"""Evidence run (v2.4 step 3): prove SENTINEL against a REAL model.
With ANTHROPIC_API_KEY or OPENAI_API_KEY present, runs the full validated corpus against
that provider AND the two built-in mocks under one comparison_id, then writes
docs/evidence/<date>-<provider>/{report.json, report.md, leaderboard.json, SUMMARY.md}.
With no key: prints a clear message and exits 0 (offline mode is never broken)."""
from __future__ import annotations

import asyncio
import json
import pathlib
import sys
from datetime import date

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.baseline import baseline_target  # noqa: E402
from app.config import Settings  # noqa: E402
from app.corpus import load_seeds, seed_corpus  # noqa: E402
from app.deps import Deps  # noqa: E402
from app.report import build_report, render_markdown, render_leaderboard_markdown  # noqa: E402
from app.runner import run_batch  # noqa: E402
from app.routers import leaderboard_for  # noqa: E402


def pick_provider(s: Settings) -> tuple[str, str] | None:
    if s.ANTHROPIC_API_KEY:
        return "anthropic", "internal://anthropic"
    if s.OPENAI_API_KEY:
        return "openai", "internal://openai"
    return None


async def main(out_root: pathlib.Path | None = None, settings: Settings | None = None,
               limit: int | None = None) -> int:
    s = settings or Settings()
    prov = pick_provider(s)
    if not prov:
        print("[evidence] no ANTHROPIC_API_KEY / OPENAI_API_KEY set — nothing to prove "
              "against a live model. Offline mock mode is unaffected. Exit 0.")
        return 0
    name, url = prov
    deps = Deps(s)
    await deps.start()
    try:
        store = deps.store
        await seed_corpus(deps, load_seeds(str(ROOT / "seeds" / "attacks.json")))
        targets = [
            await store.create_target(f"{name.title()} LIVE", url, capabilities={}),
            await store.create_target("MockTarget VULNERABLE", "internal://mock",
                                      capabilities={"RAG": True},
                                      canary_token=s.MOCK_CANARY, seeded=True),
            await store.create_target("MockTarget HARDENED", "internal://mock-hardened",
                                      capabilities={}, canary_token=s.MOCK_CANARY, seeded=True),
        ]
        for t in targets:
            await baseline_target(deps, t)
        cid = "evidence-" + date.today().isoformat()
        runs = []
        for t in targets:
            b = await store.latest_baseline(t["id"])
            rid = await store.create_run(t["id"], b["version"] if b else None, comparison_id=cid)
            await run_batch(deps, rid, t, limit=limit)
            runs.append((t, rid))
        out = (out_root or ROOT / "docs" / "evidence") / f"{date.today().isoformat()}-{name}"
        out.mkdir(parents=True, exist_ok=True)
        live_t, live_rid = runs[0]
        rep = await build_report(deps, live_rid)
        audit = await deps.audit.verify(run_id=live_rid)
        (out / "report.json").write_text(json.dumps(rep, indent=1, default=str))
        (out / "report.md").write_text(render_markdown(rep, audit))
        board = await leaderboard_for(deps, cid)
        (out / "leaderboard.json").write_text(json.dumps(board, indent=1, default=str))
        sm = rep["summary"]
        model = s.ANTHROPIC_MODEL if name == "anthropic" else s.OPENAI_MODEL
        summary = "\n".join([
            f"# Evidence run — {name} ({model}) — {date.today().isoformat()}", "",
            f"Command: `{'ANTHROPIC_API_KEY' if name == 'anthropic' else 'OPENAI_API_KEY'}=… "
            f"python scripts/evidence_run.py`", "",
            f"- jury mode: **{sm['jury_mode']}**",
            f"- attacks executed against the live model: **{rep['run']['total']}**",
            f"- resisted / compromised / inconclusive: **{sm['resisted']} / {sm['successful']} / "
            f"{sm['inconclusive']}**",
            f"- resistance rate: **{sm['resistance_rate']}**",
            f"- gate-flagged: {sm.get('gate_would_block', sm.get('blocked_at_gate'))} · redacted: {sm['redacted']}",
            f"- top failing categories: {sm['top_failing_categories'] or 'none'}",
            f"- audit chain valid: {audit['valid']} ({audit['run_records']} records)", "",
            "Leaderboard:", "", render_leaderboard_markdown(board),
        ])
        (out / "SUMMARY.md").write_text(summary)
        print(f"[evidence] wrote {out}")
        return 0
    finally:
        await deps.stop()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
