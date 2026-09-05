"""v2.4 step 6: Markdown report export."""
import asyncio
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.corpus import load_seeds, seed_corpus  # noqa: E402
from app.main import create_app  # noqa: E402
from app.runner import run_batch  # noqa: E402

SEEDS = str(pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json")


@pytest.fixture
async def run(deps):
    await seed_corpus(deps, load_seeds(SEEDS, limit=24))
    t = await deps.store.create_target("m", "internal://mock",
                                       canary_token=deps.settings.MOCK_CANARY)
    rid = await deps.store.create_run(t["id"], None, comparison_id="cmp1")
    await run_batch(deps, rid, t, limit=10)
    return rid


async def test_markdown_export(deps, run):
    app = create_app(deps.settings)
    app.state.deps = deps
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://t") as c:
        r = await c.get(f"/v1/reports/{run}?format=md")
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/markdown")
        assert "attachment" in r.headers["content-disposition"]
        md = r.text
        assert "## Executive summary" in md
        assert "## Top findings (ranked by observed response risk)" in md
        assert "### 1." in md and "**Remediation:**" in md
        assert "## Remediation priorities" in md and "Limitations" in md
        rep = (await c.get(f"/v1/reports/{run}")).json()
        top = rep["summary"]["top_failing_categories"]
        if top:
            fix = next(x["remediation"] for x in rep["summary"]["suggested_remediations"]
                       if x["category"] == top[0])
            assert fix[:40] in md
        # findings are sorted by response risk desc
        risks = [e.get("response_risk") or 0 for e in rep["executions"]]
        assert risks == sorted(risks, reverse=True)
        lb = await c.get("/v1/reports/compare/cmp1?format=md")
        assert lb.status_code == 200 and "leaderboard" in lb.text.lower()
