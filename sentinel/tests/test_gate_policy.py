"""v2.4 step 7: permissive vs enforcing request-gate policy in batch mode."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.corpus import load_seeds, seed_corpus  # noqa: E402
from app.report import build_report  # noqa: E402
from app.runner import run_batch  # noqa: E402

SEEDS = str(pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json")


async def test_permissive_vs_enforcing(deps):
    await seed_corpus(deps, load_seeds(SEEDS, limit=36))
    t = await deps.store.create_target("m", "internal://mock",
                                       canary_token=deps.settings.MOCK_CANARY)
    cats = ["direct_override", "roleplay_persona", "encoded_payloads",
            "system_prompt_extraction", "data_exfiltration"]
    r1 = await deps.store.create_run(t["id"], None, gate_policy="permissive")
    await run_batch(deps, r1, t, categories=cats, enforce_request_block=False)
    r2 = await deps.store.create_run(t["id"], None, gate_policy="enforcing")
    await run_batch(deps, r2, t, categories=cats, enforce_request_block=True)
    e1 = await deps.store.list_executions(r1)
    e2 = await deps.store.list_executions(r2)
    assert len(e1) == len(e2) > 0
    # identical gate verdicts ...
    assert [e["band"] for e in e1] == [e["band"] for e in e2]
    flagged = sum(e["band"] == "BLOCK" for e in e1)
    # ... but in permissive mode every attack reached the target
    reached1 = sum(e["verdict"] in ("RESISTED", "SUCCESSFUL", "INCONCLUSIVE") for e in e1)
    reached2 = sum(e["verdict"] in ("RESISTED", "SUCCESSFUL", "INCONCLUSIVE") for e in e2)
    assert reached1 == len(e1)
    assert reached2 == len(e2) - flagged
    if flagged:
        assert any(e["verdict"] == "BLOCKED" for e in e2)
        assert not any(e["verdict"] == "BLOCKED" for e in e1)
    rep1 = await build_report(deps, r1)
    rep2 = await build_report(deps, r2)
    assert rep1["summary"]["gate_policy"].startswith("permissive")
    assert rep1["summary"]["gate_would_block"] == flagged
    assert rep1["summary"]["blocked_at_gate"] == 0
    assert rep2["summary"]["gate_policy"] == "enforcing"
    assert rep2["summary"]["blocked_at_gate"] == flagged
    assert "request gate reports" in rep1["summary"]["gate_policy_note"]
