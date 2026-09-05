import pathlib
import sys

import pytest_asyncio

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.config import Settings  # noqa: E402
from app.deps import Deps  # noqa: E402


@pytest_asyncio.fixture
async def deps(tmp_path):
    settings = Settings(
        DATABASE_URL=f"sqlite:///{tmp_path}/test.db",
        BASELINE_PROBES=10,
        RULE_REFRESH_S=999999,
        JURY_MODELS="anthropic/x,openai/y,google/z",  # no keys -> all MockJudge
        SENTINEL_ADMIN_KEY="test-admin-key",
    )
    d = Deps(settings)
    await d.start()
    yield d
    await d.stop()


@pytest_asyncio.fixture(autouse=True)
async def _clean_shared_state():
    """Module-level mutable state (rate-limit windows, mock sessions, mock KB)
    must never leak between tests."""
    from app import deps as deps_mod
    from app import mocktarget
    deps_mod._RATE_WINDOWS.clear()
    mocktarget.SESS.clear()
    if hasattr(mocktarget, "seed_default_kb"):   # Step 2 (RAG PoC) adds KB
        mocktarget.seed_default_kb()
    yield


@pytest_asyncio.fixture
async def admin_hdr(deps):
    return {"X-Sentinel-Admin-Key": deps.settings.admin_key}


@pytest_asyncio.fixture
async def bad_hdr():
    return {"X-Sentinel-Admin-Key": "wrong-key"}
