"""Step 1: sliding-window rate limiting on abusable surfaces (spec: small limits
+ patched clock, no real sleeps)."""
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app import deps as deps_mod  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture
async def client(deps, admin_hdr):
    deps.settings.RATE_LIMIT_PROXY_PER_MIN = 2
    deps.settings.RATE_LIMIT_RUNS_PER_MIN = 1
    app = create_app(deps.settings)
    app.state.deps = deps
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    await c.post("/admin/targets", json={"name": "m", "endpoint_url": "internal://mock"},
                 headers=admin_hdr)
    yield c, admin_hdr
    await c.aclose()


async def test_proxy_n_plus_one_returns_429_with_retry_after(client):
    c,_ = client
    tid = (await c.get("/admin/targets", headers={'X-Sentinel-Admin-Key': 'test-admin-key'})
           ).json()["targets"][0]["id"]
    body = {"message": "how do refunds work?", "session_id": "rl1"}
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 200
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 200
    r3 = await c.post(f"/v1/proxy/{tid}/chat", json=body)
    assert r3.status_code == 429
    assert r3.headers.get("Retry-After") is not None
    assert int(r3.headers["Retry-After"]) > 0


async def test_requests_succeed_again_after_window_resets(client, monkeypatch):
    c, _ = client
    hdr = {'X-Sentinel-Admin-Key': 'test-admin-key'}
    tid = (await c.get("/admin/targets", headers=hdr)).json()["targets"][0]["id"]
    body = {"message": "support hours?", "session_id": "rl2"}
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 200
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 200
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 429
    # jump the clock past the 60s window — no real sleep
    real = deps_mod._now
    monkeypatch.setattr(deps_mod, "_now", lambda: real() + 61.0)
    assert (await c.post(f"/v1/proxy/{tid}/chat", json=body)).status_code == 200


async def test_runs_bucket_limited_separately(client):
    c, _ = client
    hdr = {'X-Sentinel-Admin-Key': 'test-admin-key'}
    tid = (await c.get("/admin/targets", headers=hdr)).json()["targets"][0]["id"]
    assert "run_id" in (await c.post("/v1/runs", json={"target_id": tid, "limit": 1},
                                     headers=hdr)).json()
    r2 = await c.post("/v1/runs", json={"target_id": tid, "limit": 1}, headers=hdr)
    assert r2.status_code == 429 and "Rate-Limit" not in r2.headers
    assert r2.headers.get("Retry-After") is not None


async def test_disable_knob(deps, admin_hdr):
    deps.settings.RATE_LIMIT_ENABLED = False
    deps.settings.RATE_LIMIT_PROXY_PER_MIN = 1
    app = create_app(deps.settings)
    app.state.deps = deps
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    await c.post("/admin/targets", json={"name": "m", "endpoint_url": "internal://mock"},
                 headers=admin_hdr)
    tid = (await c.get("/admin/targets", headers=admin_hdr)).json()["targets"][0]["id"]
    for _ in range(4):
        r = await c.post(f"/v1/proxy/{tid}/chat",
                         json={"message": "hi", "session_id": "rl3"})
        assert r.status_code == 200
    await c.aclose()
