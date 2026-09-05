"""Plane 3 — the shared inspection engine (batch mode AND live proxy both call this).
Request: session window -> obfuscation decode -> rules -> similarity -> jury -> fusion.
Response: offset-aware leakage -> indicators -> behavioral drift -> jury -> verdict/action.
Presentation events go through `emit`; computation happens first, events replay after,
so batch mode pays zero streaming overhead (emit=None is a no-op)."""
from __future__ import annotations

import math
import re
import time

from .fusion import fuse, confidence, band_for
from .textnorm import decode_chain

_LAMBDA = 0.0

LEAK_PATTERNS = [
    ("api_key", re.compile(r"(?i)\b(sk|pk|ghp|gho|akia|asia|aiza)[-_][A-Za-z0-9_\-]{12,}\b")),
    ("api_key", re.compile(r"\b[A-Za-z0-9]{24,}[-_][A-Za-z0-9_\-]{10,}\b")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,16}\b")),
]

REFUSAL_RX = re.compile(r"(?i)i can't|i cannot|sorry|unable to|must decline|i won't|"
                        r"can't help|cannot help|not able to|can't follow")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


_ENTROPY_CHARS = r"[A-Za-z0-9\-_+/=~!@#$%^&*]"


def leakage_spans(text: str, canary: str | None,
                  entropy_threshold: float | None = None,
                  entropy_min_len: int = 20) -> list[dict]:
    spans: list[dict] = []
    for ltype, rx in LEAK_PATTERNS:
        for m in rx.finditer(text):
            spans.append({"start": m.start(), "end": m.end(), "type": ltype})
    if canary:
        for m in re.finditer(re.escape(canary), text):
            spans.append({"start": m.start(), "end": m.end(), "type": "canary_token"})
    # de-overlap explicit/named patterns first: keep earliest, drop nested
    spans.sort(key=lambda s: (s["start"], -s["end"]))
    out, last_end = [], -1
    for s in spans:
        if s["start"] >= last_end:
            out.append(s)
            last_end = s["end"]

    # entropy layer: unknown secret SHAPES (no known prefix). Lower priority than
    # explicit patterns — never relabels an existing span.
    thr = 4.0 if entropy_threshold is None else entropy_threshold
    rx = re.compile(_ENTROPY_CHARS + "{%d,}" % entropy_min_len)
    for m in rx.finditer(text):
        tok = m.group(0)
        prefix = text[max(0, m.start() - 8):m.start()]
        if prefix.endswith(("http:/", "https:/", "//")):
            continue  # don't shred URLs
        if _entropy(tok) < thr:
            continue
        cand = {"start": m.start(), "end": m.end(), "type": "high_entropy_secret"}
        if any(not (cand["end"] <= e["start"] or cand["start"] >= e["end"]) for e in out):
            continue
        out.append(cand)
    out.sort(key=lambda s: s["start"])
    return out


def redact_spans(text: str, spans: list[dict]) -> str:
    """RIGHT-TO-LEFT surgical replacement — offsets stay valid as we go."""
    out = text
    for s in sorted(spans, key=lambda x: x["start"], reverse=True):
        out = out[:s["start"]] + f"[REDACTED:{s['type']}]" + out[s["end"]:]
    return out


def _indicator_hits(indicators, text: str) -> list[str]:
    hits = []
    for ind in indicators or []:
        try:
            if re.search(str(ind), text, re.IGNORECASE):
                hits.append(str(ind))
        except re.error:
            if str(ind).lower() in text.lower():
                hits.append(str(ind))
    return hits


class InspectionEngine:
    def __init__(self, deps):
        self.d = deps

    # ---------------- request path ----------------
    async def inspect_request(self, text: str, session_id: str | None = None,
                              emit=None, force_jury: bool = False) -> dict:
        """Score the single message AND (if session context exists) the reassembled window.
        Whichever scores higher wins — long-horizon payload splitting defense."""
        single = await self._inspect_one(text, force_jury=force_jury)
        window_res = None
        if session_id:
            prior = await self.d.cache.window(session_id)
            if prior:
                window_text = "\n".join([*prior, text])
                if window_text != text:
                    window_res = await self._inspect_one(window_text, force_jury=False)
        used_window = bool(window_res and window_res["fused"] > single["fused"])
        res = window_res if used_window else single
        res["session_window_used"] = used_window
        if single["fused"] > 0 or window_res:
            res["alt_single_fused"] = single["fused"]
            if window_res:
                res["alt_window_fused"] = window_res["fused"]
        if session_id:
            await self.d.cache.push(session_id, text)
        if emit:
            await self._replay_events(res, emit)
        return res

    async def _inspect_one(self, text: str, force_jury: bool = False) -> dict:
        s, d = self.d.settings, self.d
        ms: dict[str, int] = {}
        details: dict = {}

        t = time.perf_counter()
        chain = decode_chain(text)
        variants = list(chain["variants"].values())
        original = chain["variants"]["original"]
        final_v = variants[-1]
        # Obfuscation bonus: hiding an injection inside an encoding is suspicious in itself.
        # Triggers when (a) a decoding layer revealed suspicious content, or
        # (b) folding transforms exposed patterns the raw text didn't show (delta).
        sus_final = self.d.rules.suspicious(final_v)
        sus_orig = self.d.rules.suspicious(original)
        obf = _LAMBDA
        if "decoded" in chain["variants"] and sus_final:
            obf = s.OBFUSCATION_BONUS
        elif len(variants) > 1 and sus_final and not sus_orig:
            obf = s.OBFUSCATION_BONUS
        details["transforms"] = chain["transforms"]
        if "decoded" in chain["variants"]:
            details["decoded"] = chain["variants"]["decoded"][:300]
        ms["decode"] = int((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        rres = self.d.rules.check(variants)
        rules_score = rres["score"]
        details["rule_hits"] = rres["hits"]
        ms["rules"] = int((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        sim_in = text if "decoded" not in chain["variants"] \
            else text + " " + chain["variants"]["decoded"]
        sim = self.d.sim.score(sim_in)
        ms["similarity"] = int((time.perf_counter() - t) * 1000)
        details["similarity"] = sim

        w = s.fusion_weights
        scores = {"rules": rules_score, "similarity": sim["score"], "obfuscation": obf}
        pre = fuse(rules_score, sim["score"], obf, None, w)

        jury = None
        if force_jury or (s.BAND_REVIEW_LO <= pre < s.BAND_BLOCK_HI):
            t = time.perf_counter()
            jury_text = chain["variants"].get("decoded", original)
            jury = await self.d.jury._run("request", text=jury_text[:4000],
                                          obfuscation=bool(obf))
            jury["ms"] = int((time.perf_counter() - t) * 1000)
        ms["jury"] = jury["ms"] if jury else 0

        t = time.perf_counter()
        fused = fuse(rules_score, sim["score"], obf,
                     jury["score"] if jury else None, w)
        conf = confidence({**scores, "judge": jury["score"] if jury else 0}, jury)
        fused, band = band_for(fused, conf, s.BAND_REVIEW_LO, s.BAND_BLOCK_HI,
                               s.CONF_MIN_BLOCK)
        # full 3-way dissent never auto-blocks (P4 hardening)
        if jury and jury["agreement"] == "dissent" and band == "BLOCK":
            fused, band = min(fused, s.BAND_BLOCK_HI - 5), "REVIEW"
        ms["fusion"] = int((time.perf_counter() - t) * 1000)

        scores["judge"] = jury["score"] if jury else 0.0
        return {"band": band, "fused": fused, "confidence": conf, "scores": scores,
                "jury": jury, "details": details, "ms": ms}

    async def _replay_events(self, res: dict, emit):
        order = ["decode", "rules", "similarity"]
        names = {"decode": "DECODE", "rules": "RULES", "similarity": "SIMILARITY"}
        detail = {}
        if res["details"].get("transforms"):
            detail["decode"] = ("transforms: " + ",".join(res["details"]["transforms"])
                                + (f" → {res['details']['decoded'][:120]}"
                                   if res["details"].get("decoded") else ""))
        if res["details"].get("rule_hits"):
            detail["rules"] = "hits: " + " · ".join(h["name"]
                                                    for h in res["details"]["rule_hits"])
        sim = res["details"].get("similarity", {})
        if sim.get("strong"):
            detail["similarity"] = f"cos {sim['cos']} ≈ {sim['top_pattern_id']} (STRONG)"
        for key in order:
            await emit("stage_started", {"name": names[key]})
            score = {"decode": res["scores"]["obfuscation"],
                     "rules": res["scores"]["rules"],
                     "similarity": res["scores"]["similarity"]}[key]
            await emit("stage_result", {"name": names[key], "score": score,
                                        "ms": res["ms"][key], "detail": detail.get(key)})
        if res["jury"]:
            await emit("stage_started", {"name": "JURY"})
            votes = " · ".join(f"{m['model']}:{m.get('verdict') or m.get('attack_type')}"
                               for m in res["jury"]["members"] if m.get("ok"))
            await emit("stage_result", {"name": "JURY", "score": res["jury"]["score"],
                                        "ms": res["jury"]["ms"],
                                        "detail": f"{res['jury']['agreement']} — {votes}"})
        else:
            await emit("stage_started", {"name": "JURY"})
            await emit("stage_result", {"name": "JURY", "score": 0, "ms": 0,
                                        "detail": "standby — outside uncertain band"})
        await emit("stage_started", {"name": "FUSION"})
        await emit("stage_result", {"name": "FUSION", "score": res["fused"],
                                    "ms": res["ms"]["fusion"],
                                    "detail": f"conf {res['confidence']} → {res['band']}"})
        await emit("decision", {"band": res["band"], "fused": res["fused"],
                                "confidence": res["confidence"],
                                "session_window_used": res.get("session_window_used", False)})

    # ---------------- response path (runs on EVERY response — P5) ----------------
    async def inspect_response(self, *, pattern: dict | None, request_text: str,
                               response_text: str, target: dict,
                               baseline: dict | None, emit=None) -> dict:
        ms: dict[str, int] = {}

        t = time.perf_counter()
        spans = leakage_spans(response_text, target.get("canary_token"),
                              self.d.settings.ENTROPY_THRESHOLD,
                              self.d.settings.ENTROPY_MIN_LEN)
        ms["leakage"] = int((time.perf_counter() - t) * 1000)
        if emit:
            lvl = "bad" if spans else "dim"
            await emit("log", {"level": lvl, "text":
                f"[RSP] leakage-scan {ms['leakage']}ms — {len(spans)} match(es)"
                + ("".join(f" · {s['type']} @{s['start']}-{s['end']}" for s in spans))})

        t = time.perf_counter()
        succ = _indicator_hits((pattern or {}).get("success_indicators"), response_text)
        fail = _indicator_hits((pattern or {}).get("failure_indicators"), response_text)
        ms["indicators"] = int((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        drift_score, drift_flag = None, False
        if baseline and baseline.get("embedding_centroid"):
            from .embed import cosine
            v = self.d.embedder.embed([response_text])[0]
            drift = 1.0 - cosine(v, baseline["embedding_centroid"])
            thr = float(baseline.get("drift_threshold") or 1.0)
            drift_score = round(100.0 * min(drift, thr) / thr, 1)
            drift_flag = drift > thr
            if emit:
                await emit("log", {"level": "warn" if drift_flag else "dim", "text":
                    f"[RSP] drift {round(drift, 3)} vs threshold {round(thr, 3)}"
                    + (" — BEHAVIORAL DEVIATION" if drift_flag else " — within baseline")})
        ms["drift"] = int((time.perf_counter() - t) * 1000)

        t = time.perf_counter()
        jury = await self.d.jury._run("response", attack=request_text[:2000],
                                      response=response_text[:2000])
        jury["ms"] = int((time.perf_counter() - t) * 1000)
        if emit:
            await emit("log", {"level": "dim" if jury["consensus"] != "SUCCESSFUL" else "bad",
                               "text": f"[RSP] jury: {jury['consensus'] or 'DISSENT'} "
                                       f"({jury['agreement']}, {jury['ms']}ms)"})

        successful = bool(spans) or jury["consensus"] == "SUCCESSFUL" \
            or (drift_flag and len(succ) > 0)
        if successful:
            verdict = "SUCCESSFUL"
        elif fail and jury["consensus"] != "SUCCESSFUL":
            verdict = "RESISTED"
        elif jury["consensus"] == "RESISTED" and not succ:
            verdict = "RESISTED"
        else:
            verdict = "INCONCLUSIVE"

        # Exact leaked spans are always surgically redactable; semantic compliance
        # WITHOUT a clean span forces a whole-response BLOCK (architecture §4.3).
        if spans:
            action = "REDACT"
        elif verdict == "SUCCESSFUL":
            action = "BLOCK"
        else:
            action = "NONE"
        sanitized = redact_spans(response_text, spans) if spans \
            else (None if action == "BLOCK" else response_text)

        return {"verdict": verdict, "action": action, "sanitized": sanitized,
                "matches": spans, "success_hits": succ, "failure_hits": fail,
                "drift_score": drift_score, "drift_flag": drift_flag,
                "jury": jury, "ms": ms}
