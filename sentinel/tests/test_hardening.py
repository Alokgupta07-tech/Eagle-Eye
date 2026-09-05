"""v2.4 step 11: CORS default, auth masking/encryption, optional proxy key."""
import pathlib
import sys

import httpx
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.deps import Deps  # noqa: E402
from app.main import create_app  # noqa: E402
from app.secrets import mask, protect, reveal  # noqa: E402


async def _client(deps):
    app = create_app(deps.settings)
    app.state.deps = deps
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_cors_same_origin_by_default(deps):
    async with await _client(deps) as c:
        r = await c.options("/healthz", headers={"Origin": "http://evil.example",
                                                 "Access-Control-Request-Method": "GET"})
        assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


async def test_cors_opt_in(tmp_path):
    d = Deps(Settings(DATABASE_URL=f"sqlite:///{tmp_path}/c.db", CORS_ORIGINS="http://ok.example",
                      JURY_MODELS="anthropic/x", SENTINEL_ADMIN_KEY="k"))
    await d.start()
    try:
        async with await _client(d) as c:
            r = await c.options("/healthz", headers={"Origin": "http://ok.example",
                                                     "Access-Control-Request-Method": "GET"})
            assert r.headers.get("access-control-allow-origin") == "http://ok.example"
    finally:
        await d.stop()


async def test_auth_header_masked_in_api(deps, admin_hdr):
    async with await _client(deps) as c:
        r = await c.post("/admin/targets", headers=admin_hdr, json={
            "name": "ext", "endpoint_url": "https://example.invalid/v1/chat/completions",
            "auth_header": "Bearer supersecrettoken1234"})
        assert r.json()["target"]["auth_header"] == "Bearer ****1234"
        lst = (await c.get("/admin/targets", headers=admin_hdr)).json()["targets"]
        assert all("supersecret" not in (t.get("auth_header") or "") for t in lst)


def test_protect_reveal_roundtrip_or_passthrough():
    pytest.importorskip("cryptography")
    enc = protect("Bearer abc", "s3cret")
    assert enc.startswith("enc:") and reveal(enc, "s3cret") == "Bearer abc"
    assert mask(enc) == "****(encrypted)"


def test_protect_passthrough_without_secret():
    assert protect("Bearer abc", "") == "Bearer abc"
    assert reveal("Bearer abc", "") == "Bearer abc"
    assert mask("Bearer abcdefghijkl") == "Bearer ****ijkl"


async def test_proxy_key_enforced_when_set(tmp_path):
    d = Deps(Settings(DATABASE_URL=f"sqlite:///{tmp_path}/p.db", SENTINEL_PROXY_KEY="pk",
                      JURY_MODELS="anthropic/x", SENTINEL_ADMIN_KEY="k", BASELINE_PROBES=3))
    await d.start()
    try:
        t = await d.store.create_target("m", "internal://mock", canary_token=d.settings.MOCK_CANARY)
        async with await _client(d) as c:
            r = await c.post(f"/v1/proxy/{t['id']}/chat", json={"message": "hi"})
            assert r.status_code == 401
            r = await c.post(f"/v1/proxy/{t['id']}/chat", json={"message": "hi"},
                             headers={"X-Sentinel-Proxy-Key": "pk"})
            assert r.status_code == 200 and r.json()["final"]["band"] == "ALLOW"
    finally:
        await d.stop()
