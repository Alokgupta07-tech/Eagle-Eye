"""Batch test runner — the judged artifact. Iterates the validated corpus (seeds +
surviving mutations), drives each attack through the request gate, fires survivors at the
target, analyzes every response (P5: response path runs even when request ALLOWs),
seals every decision to the audit chain, aggregates counters."""
from __future__ import annotations

import json
import time

from . import mocktarget
from .target_client import call_target


async def run_batch(deps, run_id: str, target: dict, categories=None, limit: int | None = None,
                    progress=None) -> dict:
    store, engine, audit, s = deps.store, deps.engine, deps.audit, deps.settings
    baseline = await store.latest_baseline(target["id"])
    patterns = await store.list_patterns(statuses=("validated",), categories=categories,
                                         limit=limit)
    sys_prompt = mocktarget.system_prompt(s) if target["endpoint_url"].startswith(
        "internal://mock") else None

    for i, p in enumerate(patterns):
        t0 = time.perf_counter()
        sid = f"run-{run_id[:6]}-{i}"
        is_split = p.get("subcategory") == "payload_split"
        try:
            parts = json.loads(p["payload"])["parts"] if is_split else [p["payload"]]
        except (json.JSONDecodeError, KeyError):
            parts = [p["payload"]]

        # --- request gate (session-aware: parts accumulate in the window) ---
        req = None
        for part in parts:
            req = await engine.inspect_request(part, session_id=sid)

        verdict, action, exec_extra = None, "NONE", {}
        if req["band"] == "BLOCK":
            action = "BLOCK"
            resp_text, rres = None, None
            await store.incr_run(run_id, blocked=1)
            await store.add_alert(None, run_id, p.get("severity", "medium"),
                                  f"Blocked at request gate: {p['category']}",
                                  {"pattern_id": p["id"], "fused": req["fused"]})
        else:
            # --- fire at target ---
            resp_text = ""
            try:
                for part in parts:
                    msgs = ([{"role": "system", "content": sys_prompt}] if sys_prompt else []) \
                        + [{"role": "user", "content": part}]
                    resp_text = await call_target(target, msgs, sid, s)
            except Exception as exc:  # noqa: BLE001 - unreachable target must not kill the run
                resp_text = ""
                rres = {"verdict": "INCONCLUSIVE", "action": "NONE", "sanitized": None,
                        "matches": [], "success_hits": [], "failure_hits": [],
                        "drift_score": None, "drift_flag": False, "jury": None,
                        "ms": {}, "error": f"{exc.__class__.__name__}: {exc!s}"[:200]}
                verdict, action = "INCONCLUSIVE", "NONE"
                await store.incr_run(run_id, inconclusive=1, total=1)
                seq = await audit.seal({
                    "run_id": run_id, "session_id": sid, "mode": "batch",
                    "pattern_id": p["id"], "category": p["category"],
                    "request_payload": p["payload"][:500], "response_payload": "",
                    "layer_scores": req["scores"], "fused_score": req["fused"],
                    "confidence": req["confidence"], "band": req["band"],
                    "verdict": verdict, "action": action,
                    "error": rres["error"], "latency_ms": 0})
                await store.add_execution(
                    run_id, pattern_id=p["id"], variant_text=p["payload"][:600],
                    request_scores={"error": rres["error"]}, response_scores=None,
                    drift_score=None, jury=req.get("jury"), fused_score=req["fused"],
                    confidence=req["confidence"], band=req["band"], verdict="INCONCLUSIVE",
                    action="NONE", latency_ms=0, audit_seq=seq)
                if progress:
                    progress(i + 1, len(patterns))
                continue
            # --- response gate (ALWAYS — P5) ---
            rres = await engine.inspect_response(
                pattern=p, request_text=parts[-1], response_text=resp_text,
                target=target, baseline=baseline)
            verdict, action = rres["verdict"], rres["action"]
            c = {"RESISTED": "resisted", "SUCCESSFUL": "successful",
                 "INCONCLUSIVE": "inconclusive"}.get(verdict, "inconclusive")
            kw = {c: 1}
            if action == "REDACT":
                kw["redacted"] = 1
            await store.incr_run(run_id, **kw)
            if verdict == "SUCCESSFUL":
                await store.add_alert(None, run_id, p.get("severity", "high"),
                                      f"{p['category']} SUCCEEDED vs {target['name']}",
                                      {"pattern_id": p["id"], "action": action,
                                       "drift": rres["drift_score"]})
        await store.incr_run(run_id, total=1)

        seq = await audit.seal({
            "run_id": run_id, "session_id": sid, "mode": "batch",
            "pattern_id": p["id"], "category": p["category"],
            "request_payload": p["payload"][:500],
            "response_payload": (resp_text or "")[:500],
            "layer_scores": req["scores"], "fused_score": req["fused"],
            "confidence": req["confidence"], "band": req["band"],
            "rule_hits": [h["name"] for h in req["details"].get("rule_hits", [])],
            "session_window_used": req.get("session_window_used", False),
            "verdict": verdict, "action": action,
            "drift_score": rres["drift_score"] if rres else None,
            "jury": (rres or {}).get("jury") or req.get("jury"),
            "latency_ms": int((time.perf_counter() - t0) * 1000)})

        await store.add_execution(
            run_id, pattern_id=p["id"], variant_text=p["payload"][:600],
            request_scores={**req["scores"], "fused": req["fused"],
                            "window": req.get("session_window_used", False)},
            response_scores=({"verdict": rres["verdict"], "action": rres["action"],
                              "leaks": len(rres["matches"]),
                              "success_hits": rres["success_hits"],
                              "failure_hits": rres["failure_hits"]} if rres else None),
            drift_score=rres["drift_score"] if rres else None,
            jury=(rres or {}).get("jury") or req.get("jury"),
            fused_score=req["fused"], confidence=req["confidence"], band=req["band"],
            verdict=verdict or "BLOCKED", action=action,
            latency_ms=int((time.perf_counter() - t0) * 1000), audit_seq=seq)
        if progress:
            progress(i + 1, len(patterns))

    await store.finish_run(run_id)
    return await store.get_run(run_id)
