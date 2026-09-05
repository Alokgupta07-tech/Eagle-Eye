"""Step 1: control-plane auth — /admin/* and POST /v1/runs require X-Sentinel-Admin-Key.
Public surfaces (healthz, reports, live proxy chat) must stay open."""
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.main import create_app  # noqa: E402


@pytest.fixture
async def client(deps):
    app = create_app(deps.settings)
    app.state.deps = deps
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")
    yield c
    await c.aclose()


async def test_admin_routes_reject_unauthenticated(client, bad_hdr):
    for method, url in [("GET", "/admin/targets"), ("POST", "/admin/reload-rules"),
                        ("GET", "/admin/fp-queue")]:
        assert (await client.request(method, url)).status_code == 401
        assert (await client.request(method, url, headers=bad_hdr)).status_code == 401


async def test_admin_routes_accept_key(client, admin_hdr):
    r = await client.get("/admin/targets", headers=admin_hdr)
    assert r.status_code == 200
    r = await client.post("/admin/reload-rules", headers=admin_hdr)
    assert r.status_code == 200 and r.json()["loaded"] > 0


async def test_runs_creation_requires_key(client, admin_hdr):
    assert (await client.post("/v1/runs", json={"target_id": "x"})).status_code == 401
    r = await client.post("/v1/runs", json={"target_id": "x"}, headers=admin_hdr)
    assert r.status_code == 200          # target missing -> handled error, not 401
    assert r.json().get("error")


async def test_public_surfaces_stay_open(client):
    assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/v1/runs")).status_code == 200
    r = await client.post("/v1/proxy/nope/chat", json={"message": "hi"})
    assert r.status_code == 200 and r.json().get("error") == "target not found"
