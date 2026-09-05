"""Seed + mutate + adversarially validate the attack corpus into the DB.
Usage:  python scripts/seed_corpus.py [--limit N]"""
from __future__ import annotations

import asyncio
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.config import Settings
from app.corpus import load_seeds, seed_corpus
from app.deps import Deps


async def main(limit: int | None = None):
    deps = Deps(Settings())
    await deps.start()
    seeds_path = pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json"
    seeds = load_seeds(str(seeds_path), limit=limit)
    print(f"[corpus] loaded {len(seeds)} seeds; validating against canary target …")
    stats = await seed_corpus(deps, seeds)
    print(f"[corpus] seeds={stats['seeds']} variants={stats['variants']} "
          f"validated={stats['validated']} dead={stats['dead']} skipped={stats['skipped']}")
    print(f"[corpus] totals: {stats['corpus']}")
    print(f"[corpus] embeddings indexed: {len(deps.sim.ids)}")
    await deps.stop()


if __name__ == "__main__":
    limit = None
    if "--limit" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--limit") + 1])
    asyncio.run(main(limit))
