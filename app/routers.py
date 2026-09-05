"""All HTTP endpoints. Batch mode (judged) + live proxy (demo) share the one engine.
Every decision — both modes — is sealed to the audit chain (P6)."""
from __future__ import annotations

import asyncio
import json
import time
import uuid

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from . import mocktarget
from .deps import rate_limited, require_admin
from .report import build_report, render_markdown, render_leaderboard_markdown
from .runner import run_batch
from .target_client import call_target


class TargetIn(BaseModel):
    name: str
    endpoint_url: str
    auth_header: str | None = None
    capabilities: dict = {}


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None
    tools: list[dict] | None = None    # MCP-style tool definitions; request side
                                       # intentionally inspects message only (blind spot)


class RunIn(BaseModel):
    target_id: str | None = None
    targets: list[str] | None = None      # multi-target comparison mode
    categories: list[str] | None = None
    limit: int | None = None


class FusionWeightsIn(BaseModel):
    rules: float
    similarity: float
    obfuscation: float
    judge: float
    response: dict[str, float] | None = None   # {leakage, indicators, drift, judge}


class KBDocIn(BaseModel):
    doc_id: str | None = None
    title: str
    body: str


class FPLabelIn(BaseModel):
    audit_seq: int
    label: str          # false_positive | true_positive
    labeler: str = "operator"


def sse(ev: str, data: dict) -> str:
    return f"event: {ev}\ndata: {json.dumps(data, default=str)}\n\n"


async def _handle_chat(deps, target: dict, message: str, session_id: str, emit,
                       tools: list[dict] | None = None) -> dict:
    """Shared core for stream + non-stream proxy. Returns the final payload."""
    t0 = time.perf_counter()
    engine, store, audit, s = deps.engine, deps.store, deps.audit, deps.settings
    req = await engine.inspect_request(message, session_id=session_id, emit=emit)
    band = req["band"]
    content, action, verdict = None, "NONE", None
    rres = None

    if band == "BLOCK":
        action = "BLOCK"
        await emit("log", {"level": "bad", "text":
            f"[SYS] ⛔ BLOCKED at request gate · fused {req['fused']} (conf {req['confidence']}) "
            f"· no upstream call made"})
        content = ("⛔ BLOCKED by SENTINEL — this prompt was classified as an injection "
                   "attempt. The target model never saw it. This decision is sealed in the "
                   "audit chain.")
    else:
        if band == "REVIEW":
            await emit("log", {"level": "warn", "text":
                "[SYS] ⚠ REVIEW band — auto-dispatching (operator override logged to chain)"})
        await emit("proxied", {"target": target["name"]})
        msgs = ([{"role": "system", "content": mocktarget.system_prompt(s)}]
                if target["endpoint_url"].startswith("internal://mock") else []) \
            + [{"role": "user", "content": message}]
        resp_text = await call_target(target, msgs, session_id or "live", s, tools=tools)
        baseline = await store.latest_baseline(target["id"])
        rres = await engine.inspect_response(pattern=None, request_text=message,
                                             response_text=resp_text, target=target,
                                             baseline=baseline, emit=emit)
        verdict, action = rres["verdict"], rres["action"]
        if action == "BLOCK":
            content = ("⛔ RESPONSE BLOCKED by SENTINEL — the target complied with the "
                       "injection. The unsafe reply was intercepted; nothing was served.")
        else:
            content = rres["sanitized"]
        await emit("response_inspection", {
            "verdict": verdict, "action": action, "drift_score": rres["drift_score"],
            "risk_score": rres["risk_score"], "confidence": rres["confidence"],
            "derived_severity": rres["derived_severity"], "layers": rres["layers"],
            "matches": rres["matches"], "jury_agreement": rres["jury"]["agreement"],
            "jury_consensus": rres["jury"]["consensus"]})

    if band == "BLOCK" or verdict == "SUCCESSFUL":
        await store.add_alert(None, None, "high" if verdict == "SUCCESSFUL" else "medium",
                              f"Live {('response compromise' if verdict == 'SUCCESSFUL' else 'request block')}",
                              {"message": message[:200], "fused": req["fused"]})

    seq = await audit.seal({
        "run_id": None, "session_id": session_id, "mode": "live",
        "request_payload": message[:500], "response_payload": (content or "")[:500],
        "layer_scores": req["scores"], "fused_score": req["fused"],
        "confidence": req["confidence"], "band": band,
        "rule_hits": [h["name"] for h in req["details"].get("rule_hits", [])],
        "session_window_used": req.get("session_window_used", False),
        "verdict": verdict, "action": action,
        "drift_score": rres["drift_score"] if rres else None,
        "response_risk": (rres or {}).get("risk_score"),
        "derived_severity": (rres or {}).get("derived_severity"),
        "jury": (rres or {}).get("jury") or req.get("jury"),
        "latency_ms": int((time.perf_counter() - t0) * 1000)})

    return {"band": band, "fused": req["fused"], "confidence": req["confidence"],
            "verdict": verdict, "action": action, "content": content,
            "response_risk": (rres or {}).get("risk_score"),
            "response_confidence": (rres or {}).get("confidence"),
            "derived_severity": (rres or {}).get("derived_severity"),
            "session_window_used": req.get("session_window_used", False),
            "audit_seq": seq, "session_id": session_id}


async def leaderboard_for(deps, comparison_id: str) -> dict | None:
    """One row per target in a comparison, sorted by resistance rate (shared by the API
    and scripts/evidence_run.py)."""
    runs = await deps.store.runs_by_comparison(comparison_id)
    if not runs:
        return None
    board = []
    for run in runs:
        target = await deps.store.get_target(run["target_id"]) or {}
        rep = await build_report(deps, run["id"])
        total = max(1, run["total"])
        board.append({
            "target_id": run["target_id"], "target_name": target.get("name"),
            "run_id": run["id"], "status": run["status"], "total": run["total"],
            "resisted": run["resisted"], "compromised": run["successful"],
            "inconclusive": run["inconclusive"],
            "blocked_at_gate": run["blocked"], "redacted": run["redacted"],
            "resistance_rate": rep["summary"]["resistance_rate"] if rep else None,
            "gate_block_rate": round(run["blocked"] / total, 3),
            "jury_mode": rep["summary"].get("jury_mode") if rep else None,
            "gate_policy": rep["summary"].get("gate_policy") if rep else None,
            "top_failing_category": (rep["summary"]["top_failing_categories"][0]
                                     if rep and rep["summary"]["top_failing_categories"]
                                     else None)})
    board.sort(key=lambda b: (-(b["resistance_rate"] or 0),
                              -(b["gate_block_rate"] or 0)))
    return {"comparison_id": comparison_id, "leaderboard": board}


def build_router(settings=None) -> APIRouter:
    r = APIRouter()
    _rl = {"proxy": (settings.RATE_LIMIT_PROXY_PER_MIN if settings else 30),
           "runs":  (settings.RATE_LIMIT_RUNS_PER_MIN if settings else 6)}

    # ---------------- health ----------------
    @r.get("/healthz")
    async def healthz(request: Request):
        d = request.app.state.deps
        try:
            await d.store.query_one("SELECT 1 AS ok")
            db_ok = True
        except Exception:  # noqa: BLE001
            db_ok = False
        counts = await d.store.corpus_counts() if db_ok else {}
        return {"ok": db_ok, "backend": d.store.backend, "cache": d.cache.mode,
                "embedder": d.embedder.mode, "jury": d.jury.describe(),
                "jury_mode": d.jury.mode,
                "rules_loaded": d.rules.rule_count, "corpus": counts,
                "embeddings_indexed": len(d.sim.ids)}

    # ---------------- targets & baselines ----------------
    @r.post("/admin/targets", dependencies=[Depends(require_admin)])
    async def create_target(body: TargetIn, request: Request):
        d = request.app.state.deps
        is_mock = body.endpoint_url.startswith("internal://mock")
        caps = dict(body.capabilities)
        if body.endpoint_url.startswith("internal://mock-rag"):
            caps["RAG"] = True          # built-in RAG mock auto-declares its capability
        t = await d.store.create_target(
            body.name, body.endpoint_url, body.auth_header,
            caps,
            canary_token=d.settings.MOCK_CANARY if is_mock else None,
            seeded=is_mock)

        async def _baseline():
            from .baseline import baseline_target
            await baseline_target(d, await d.store.get_target(t["id"]))
        d.baseline_tasks[t["id"]] = asyncio.create_task(_baseline())
        return {"target": t, "baselining": "started"}

    @r.get("/admin/targets", dependencies=[Depends(require_admin)])
    async def list_targets(request: Request):
        d = request.app.state.deps
        out = []
        for t in await d.store.list_targets():
            b = await d.store.latest_baseline(t["id"])
            task = d.baseline_tasks.get(t["id"])
            out.append({**t, "baseline_version": b["version"] if b else None,
                        "baseline_status": ("running" if task and not task.done()
                                            else ("done" if b else "none"))})
        return {"targets": out}

    @r.post("/admin/targets/{target_id}/kb", dependencies=[Depends(require_admin)])
    async def kb_upsert(target_id: str, body: KBDocIn, request: Request):
        """Live-demo RAG poisoning: add/replace a KB doc of a mock-rag target, then
        ask it an innocent question and watch the RESPONSE gate catch the leak."""
        d = request.app.state.deps
        target = await d.store.get_target(target_id)
        if not target:
            return {"error": "target not found"}
        if not target["endpoint_url"].startswith("internal://mock-rag"):
            return {"error": "KB lives on the built-in internal://mock-rag targets "
                             "(in-memory, SESS-style) — external targets own their KB"}
        doc_id = mocktarget.upsert_kb(body.doc_id, body.title, body.body)
        await d.audit.seal({"type": "kb_upsert", "target_id": target_id,
                            "doc_id": doc_id, "title": body.title[:120]})
        return {"ok": True, "doc_id": doc_id,
                "docs": [{"doc_id": k, "title": v["title"]}
                         for k, v in mocktarget.KB.items()]}

    @r.post("/admin/targets/{tid}/rebaseline", dependencies=[Depends(require_admin)])
    async def rebaseline(tid: str, request: Request):
        d = request.app.state.deps
        target = await d.store.get_target(tid)
        if not target:
            return {"error": "target not found"}

        async def _baseline():
            from .baseline import baseline_target
            await baseline_target(d, await d.store.get_target(tid))
        d.baseline_tasks[tid] = asyncio.create_task(_baseline())
        return {"ok": True, "baselining": "started"}

    # ---------------- rules & feedback loop ----------------
    @r.post("/admin/reload-rules", dependencies=[Depends(require_admin)])
    async def reload_rules(request: Request):
        d = request.app.state.deps
        await d.rules.reload(d.store)
        await d.sim.reload(d.store)
        return {"status": "ok", "loaded": d.rules.rule_count,
                "embeddings_indexed": len(d.sim.ids)}

    @r.get("/admin/fusion-weights", dependencies=[Depends(require_admin)])
    async def get_fusion_weights(request: Request):
        d = request.app.state.deps
        return {"weights": d.settings.fusion_weights, "source": d.settings.FUSION_W,
                "response_weights": d.settings.response_weights,
                "response_source": d.settings.FUSION_RESPONSE_W}

    @r.post("/admin/fusion-weights", dependencies=[Depends(require_admin)])
    async def set_fusion_weights(body: FusionWeightsIn, request: Request):
        vals = {"rules": body.rules, "similarity": body.similarity,
                "obfuscation": body.obfuscation, "judge": body.judge}
        if any(v < 0 for v in vals.values()) or sum(vals.values()) <= 0:
            return {"error": "weights must be non-negative and not all zero"}
        d = request.app.state.deps
        d.settings.FUSION_W = ",".join(f"{k}:{v}" for k, v in vals.items())
        rw = None
        if body.response:
            rw = {k: float(body.response.get(k, 0.0))
                  for k in ("leakage", "indicators", "drift", "judge")}
            if any(v < 0 for v in rw.values()) or sum(rw.values()) <= 0:
                return {"error": "response weights must be non-negative and not all zero"}
            d.settings.FUSION_RESPONSE_W = ",".join(f"{k}:{v}" for k, v in rw.items())
        await d.audit.seal({"type": "fusion_weights", "weights": vals,
                            "response_weights": rw})
        return {"ok": True, "weights": d.settings.fusion_weights,
                "response_weights": d.settings.response_weights}

    @r.get("/admin/fp-queue", dependencies=[Depends(require_admin)])
    async def fp_queue(request: Request):
        return {"queue": await request.app.state.deps.store.review_queue()}

    @r.post("/admin/fp-labels", dependencies=[Depends(require_admin)])
    async def fp_label(body: FPLabelIn, request: Request):
        d = request.app.state.deps
        lid = await d.store.add_fp_label(body.audit_seq, body.label, body.labeler)
        hits: list[str] = []
        row = await d.store.query_one("SELECT payload FROM audit_log WHERE seq=?",
                                      (body.audit_seq,))
        if row:
            hits = json.loads(row["payload"]).get("rule_hits", [])
        await d.audit.seal({"type": "fp_label", "ref_seq": body.audit_seq,
                            "label": body.label, "labeler": body.labeler,
                            "rules_discounted": hits if body.label == "false_positive" else []})
        discounted = []
        if body.label == "false_positive" and hits:
            await d.store.discount_rules(hits, factor=0.9, floor=1.0)
            await d.rules.reload(d.store)
            discounted = hits
        return {"ok": True, "label_id": lid, "rules_discounted": discounted}

    # ---------------- batch runs ----------------
    async def _start_one(d, target_id, categories, limit, comparison_id=None):
        target = await d.store.get_target(target_id)
        if not target:
            return {"target_id": target_id, "error": "target not found"}
        baseline = await d.store.latest_baseline(target_id)
        run_id = await d.store.create_run(target_id, baseline["version"] if baseline else None,
                                          comparison_id=comparison_id)
        d.run_tasks[run_id] = asyncio.create_task(
            run_batch(d, run_id, target, categories=categories, limit=limit))
        return {"target_id": target_id, "target_name": target["name"], "run_id": run_id,
                "status": "running", "baseline_version": baseline["version"] if baseline else None}

    @r.post("/v1/runs", dependencies=[Depends(require_admin),
                                    Depends(rate_limited("runs", _rl["runs"]))])
    async def start_run(body: RunIn, request: Request):
        d = request.app.state.deps
        if body.targets:
            cid = uuid.uuid4().hex[:12]
            started = [await _start_one(d, tid, body.categories, body.limit, cid)
                       for tid in body.targets]
            return {"comparison_id": cid, "runs": started}
        if not body.target_id:
            return {"error": "target_id or targets required"}
        started = await _start_one(d, body.target_id, body.categories, body.limit)
        if "error" in started:
            return started
        return {"run_id": started["run_id"], "status": "running",
                "baseline_version": started["baseline_version"]}

    @r.get("/v1/runs")
    async def list_runs(request: Request):
        return {"runs": await request.app.state.deps.store.query(
            "SELECT * FROM test_runs ORDER BY started_at DESC LIMIT 20")}

    @r.get("/v1/runs/latest")
    async def latest_run(request: Request):
        return {"run": await request.app.state.deps.store.latest_run()}

    @r.get("/v1/runs/{run_id}")
    async def get_run(run_id: str, request: Request):
        return {"run": await request.app.state.deps.store.get_run(run_id)}

    @r.get("/v1/runs/{run_id}/executions")
    async def get_executions(run_id: str, request: Request):
        return {"executions": await request.app.state.deps.store.list_executions(run_id)}

    @r.get("/v1/reports/compare/{comparison_id}")
    async def compare_report(comparison_id: str, request: Request,
                             format: str = Query(default="json")):
        """Leaderboard: one row per target, side by side."""
        board = await leaderboard_for(request.app.state.deps, comparison_id)
        if not board:
            return {"error": "comparison not found"}
        if format == "md":
            return Response(render_leaderboard_markdown(board),
                            media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition":
                                     f'attachment; filename="sentinel-leaderboard-{comparison_id}.md"'})
        return board

    @r.get("/v1/reports/{run_id}")
    async def get_report(run_id: str, request: Request,
                         format: str = Query(default="json")):
        d = request.app.state.deps
        rep = await build_report(d, run_id)
        if not rep:
            return {"error": "run not found"}
        if format == "md":
            audit = await d.audit.verify(run_id=run_id)
            md = render_markdown(rep, audit)
            return Response(md, media_type="text/markdown; charset=utf-8",
                            headers={"Content-Disposition":
                                     f'attachment; filename="sentinel-report-{run_id}.md"'})
        return rep

    # ---------------- audit ----------------
    @r.get("/audit/verify")
    async def audit_verify(request: Request, run_id: str | None = Query(default=None)):
        d = request.app.state.deps
        return await d.audit.verify(run_id=run_id)

    # ---------------- live proxy ----------------
    @r.post("/v1/proxy/{target_id}/chat",
            dependencies=[Depends(rate_limited("proxy", _rl["proxy"]))])
    async def proxy_chat(target_id: str, body: ChatIn, request: Request,
                         stream: bool = Query(default=False)):
        d = request.app.state.deps
        target = await d.store.get_target(target_id)
        if not target:
            return {"error": "target not found"}
        sid = body.session_id or f"live-{int(time.time() * 1000) % 10**8}"

        if not stream:
            events: list[tuple[str, dict]] = []

            async def emit(ev, data):
                events.append((ev, data))

            final = await _handle_chat(d, target, body.message, sid, emit,
                                                        tools=body.tools)
            return {"final": final,
                    "events": [{"event": e, "data": dat} for e, dat in events]}

        q: asyncio.Queue = asyncio.Queue()

        async def emit_q(ev, data):
            await q.put((ev, data))

        async def work():
            try:
                final = await _handle_chat(d, target, body.message, sid, emit_q,
                                                          tools=body.tools)
                await q.put(("final", final))
            except Exception as exc:  # noqa: BLE001
                await q.put(("final", {"error": exc.__class__.__name__,
                                       "detail": str(exc)[:300], "content": None}))
            finally:
                await q.put(None)

        async def gen():
            task = asyncio.create_task(work())
            try:
                while True:
                    item = await q.get()
                    if item is None:
                        break
                    ev, data = item
                    yield sse(ev, data)
            finally:
                await task

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    return r
