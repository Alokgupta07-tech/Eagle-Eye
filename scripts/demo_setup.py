"""One-command demo bootstrap:
corpus -> targets (vulnerable + hardened [+ a REAL provider target when its API key is
present]) -> baselines -> ONE comparison batch run across all targets (leaderboard).
Usage: python scripts/demo_setup.py"""
from __future__ import annotations

import asyncio
import pathlib
import sys
import uuid

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.baseline import baseline_target
from app.config import Settings
from app.corpus import load_seeds, seed_corpus
from app.deps import Deps
from app.runner import run_batch


async def main():
    deps = Deps(Settings())
    await deps.start()
    store, s = deps.store, deps.settings

    print("═══ SENTINEL demo setup ═══")
    seeds = load_seeds(str(pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json"))
    print(f"[1/5] corpus ingestion ({len(seeds)} seeds, OWASP/ATLAS tagged)…")
    stats = await seed_corpus(deps, seeds)
    print(f"      validated={stats['validated']} dead={stats['dead']} total={stats['corpus']}")

    print("[2/5] registering targets…")
    targets = [
        await store.create_target("MockTarget VULNERABLE", "internal://mock",
                                  capabilities={"RAG": True},
                                  canary_token=s.MOCK_CANARY, seeded=True),
        await store.create_target("MockTarget HARDENED", "internal://mock-hardened",
                                  capabilities={},
                                  canary_token=s.MOCK_CANARY, seeded=True),
        await store.create_target("RAG Mock VULNERABLE", "internal://mock-rag",
                                  capabilities={"RAG": True},
                                  canary_token=s.MOCK_CANARY, seeded=True),
        await store.create_target("RAG Mock HARDENED", "internal://mock-rag-hardened",
                                  capabilities={"RAG": True},
                                  canary_token=s.MOCK_CANARY, seeded=True),
    ]
    if s.ANTHROPIC_API_KEY:
        targets.append(await store.create_target("Anthropic LIVE", "internal://anthropic",
                                                 capabilities={}))
        print(f"      + Anthropic LIVE target ({s.ANTHROPIC_MODEL}) — key detected")
    elif s.OPENAI_API_KEY:
        targets.append(await store.create_target("OpenAI LIVE", "internal://openai",
                                                 capabilities={}))
        print(f"      + OpenAI LIVE target ({s.OPENAI_MODEL}) — key detected")
    else:
        print("      (no provider keys — leaderboard runs on the two built-in mocks)")
    for t in targets:
        print(f"      {t['id']}  {t['name']}")

    print(f"[3/5] behavioral baselines ({s.BASELINE_PROBES} probes/target)…")
    baselines = {}
    for t in targets:
        try:
            baselines[t["id"]] = (await baseline_target(deps, t))["version"]
        except Exception as exc:  # noqa: BLE001 - live target may be unreachable
            print(f"      baseline failed for {t['name']}: {exc.__class__.__name__}")
            baselines[t["id"]] = None
    print("      baselines locked")

    print("[4/5] COMPARISON batch run — same corpus against every target…")
    cid = uuid.uuid4().hex[:12]
    run_ids = []
    for t in targets:
        rid = await store.create_run(t["id"], baselines[t["id"]], comparison_id=cid)
        run_ids.append(rid)
        run = await run_batch(deps, rid, t)
        print(f"      {t['name']:<28} total={run['total']} resisted={run['resisted']} "
              f"compromised={run['successful']} blocked={run['blocked']} redacted={run['redacted']}")

    print("[5/5] verifying sealed audit chain…")
    v = await deps.audit.verify()
    print(f"      chain valid={v['valid']} records={v['checked']}")

    await deps.stop()
    print("\nOpen:  http://localhost:8000/                              (live cyber console)")
    print(f"Open:  http://localhost:8000/report.html?compare={cid}  (LEADERBOARD)")
    for name, rid in zip([t["name"] for t in targets], run_ids):
        print(f"Open:  http://localhost:8000/report.html?run_id={rid}  ({name})")
    print("Then:  python run.py")


if __name__ == "__main__":
    asyncio.run(main())
