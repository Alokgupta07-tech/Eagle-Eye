"""v2.4 step 2: batch mode never scores a corpus attack against itself."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.corpus import load_seeds, seed_corpus  # noqa: E402
from app.runner import run_batch  # noqa: E402

SEEDS = str(pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json")


async def test_batch_excludes_self_and_family(deps):
    await seed_corpus(deps, load_seeds(SEEDS, limit=24))
    pats = await deps.store.list_patterns(statuses=("validated",))
    seed = next(p for p in pats if p.get("origin_kind") == "seed")
    kids = [p for p in pats if p.get("parent_id") == seed["id"]]
    assert kids, "mutations must link to their seed via parent_id"

    # live proxy semantics: no exclusion -> exact corpus text is a STRONG match
    live = deps.sim.score(seed["payload"])
    assert live["strong"] and live["top_pattern_id"] == seed["id"]

    # batch semantics: family excluded -> cannot match itself or its variants
    fam = {seed["id"], *[k["id"] for k in kids]}
    batch = deps.sim.score(seed["payload"], exclude_ids=fam)
    assert batch["top_pattern_id"] not in fam
    assert batch["score"] < 100.0
    assert batch["excluded"] == len(fam)

    target = await deps.store.create_target("m", "internal://mock",
                                            canary_token=deps.settings.MOCK_CANARY)
    run_id = await deps.store.create_run(target["id"], None)
    await run_batch(deps, run_id, target, limit=10)
    execs = await deps.store.list_executions(run_id)
    assert execs and all(e["request_scores"]["similarity"] < 100.0 for e in execs)
    assert all(e["request_scores"].get("known_corpus_match") for e in execs)


async def test_second_best_reported(deps):
    await seed_corpus(deps, load_seeds(SEEDS, limit=12))
    pats = await deps.store.list_patterns(statuses=("validated",))
    r = deps.sim.score(pats[0]["payload"])
    assert r["second_best"] and r["second_best"]["id"] != r["top_pattern_id"]
