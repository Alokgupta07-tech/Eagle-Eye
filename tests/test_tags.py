"""Step 3: OWASP LLM Top-10 / MITRE ATLAS tagging flows from seeds -> DB -> report."""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.corpus import load_seeds, seed_corpus  # noqa: E402

SEEDS = pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json"


def test_every_seed_tagged():
    seeds = json.loads(SEEDS.read_text())
    assert len(seeds) >= 60   # v2.1: 60 · v2.3 adds indirect_injection_rag + tool_poisoning
    for s in seeds:
        assert s["owasp_llm"].startswith("LLM"), s["payload"][:40]
        assert s["mitre_atlas"].startswith("AML.T"), s["payload"][:40]
        assert s.get("origin") in ("hand_authored", "adapted"), s["payload"][:40]
        assert s.get("taxonomy_source"), s["payload"][:40]
        assert "source_sha" not in s and "source_repo" not in s
    owasp = {s["owasp_llm"] for s in seeds}
    assert {"LLM01:PromptInjection", "LLM07:SystemPromptLeakage",
            "LLM02:SensitiveInformationDisclosure", "LLM06:ExcessiveAgency"} <= owasp


async def test_tags_land_in_report(deps):
    await seed_corpus(deps, load_seeds(str(SEEDS), limit=12))
    target = await deps.store.create_target("m", "internal://mock",
                                            canary_token=deps.settings.MOCK_CANARY)
    run_id = await deps.store.create_run(target["id"], None)
    from app.runner import run_batch
    await run_batch(deps, run_id, target, limit=6)
    from app.report import build_report
    rep = await build_report(deps, run_id)
    cats = rep["by_category"]
    assert cats and all("owasp_llm" in c for c in cats)
    assert all(c["owasp_llm"] for c in cats)
    assert all(p.get("owasp_llm") for p in rep["provenance"])
    assert all(p.get("origin") in ("hand_authored", "adapted") for p in rep["provenance"])
    assert not any("source_sha" in p for p in rep["provenance"])
