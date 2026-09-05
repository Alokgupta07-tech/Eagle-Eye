"""Step 4: multi-target comparison runs + leaderboard endpoint."""
import asyncio
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.corpus import load_seeds, seed_corpus  # noqa: E402
from app.main import create_app  # noqa: E402

SEEDS = str(pathlib.Path(__file__).resolve().parents[1] / "seeds" / "attacks.json")


@pytest.fixture
async def client(deps, admin_hdr):
    app = create_app(deps.settings)
    app.state.deps = deps
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    await seed_corpus(deps, load_seeds(SEEDS, limit=12))
    h = {"X-Sentinel-Admin-Key": deps.settings.admin_key}
    for name, url in [("vuln", "internal://mock"), ("hard", "internal://mock-hardened")]:
        await c.post("/admin/targets", json={"name": name, "endpoint_url": url}, headers=h)
    await asyncio.gather(*deps.baseline_tasks.values(), return_exceptions=True)
    targets = (await c.get("/admin/targets", headers=h)).json()["targets"]
    yield c, targets
    await c.aclose()


async def test_comparison_run_produces_sorted_leaderboard(client):
    c, targets = client
    hdr = {"X-Sentinel-Admin-Key": "test-admin-key"}
    r = await c.post("/v1/runs", json={"targets": [t["id"] for t in targets], "limit": 6},
                     headers=hdr)
    body = r.json()
    assert "comparison_id" in body and len(body["runs"]) == 2
    cid = body["comparison_id"]
    for _ in range(240):
        board = (await c.get(f"/v1/reports/compare/{cid}")).json()["leaderboard"]
        if all(b["status"] == "done" for b in board):
            break
        await asyncio.sleep(0.25)
    assert all(b["status"] == "done" for b in board)
    assert board[0]["target_name"] == "hard"        # hardened resists best -> ranked #1
    assert board[0]["resistance_rate"] == 1.0
    assert board[1]["target_name"] == "vuln"
    assert board[1]["resistance_rate"] == 0.0
    assert all(b["gate_block_rate"] >= 0 for b in board)
    per = {b["target_name"]: b for b in board}
    assert per["vuln"]["compromised"] > 0 and per["hard"]["compromised"] == 0


async def test_single_target_run_unchanged(client):
    c, targets = client
    hdr = {"X-Sentinel-Admin-Key": "test-admin-key"}
    r = await c.post("/v1/runs", json={"target_id": targets[0]["id"], "limit": 2},
                     headers=hdr)
    assert "run_id" in r.json() and "comparison_id" not in r.json()
