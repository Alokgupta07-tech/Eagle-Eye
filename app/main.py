"""SENTINEL app factory. Run:  python run.py   (or: uvicorn app.main:app --host 0.0.0.0)"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .deps import Deps
from .mocktarget import router as mock_router
from .routers import build_router


def create_app(settings=None) -> FastAPI:
    settings = settings or get_settings()
    deps = Deps(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        await deps.start()
        mode = (f"backend={deps.store.backend} cache={deps.cache.mode} "
                f"embedder={deps.embedder.mode} jury={deps.jury.describe()}")
        print(f"[sentinel] online — {mode}")
        from .secrets import available
        if not available(deps.settings.SENTINEL_SECRET):
            print("[sentinel] WARNING: target auth headers stored unencrypted — set "
                  "SENTINEL_SECRET and `pip install cryptography` to encrypt at rest")
        if deps.settings.SENTINEL_PROXY_KEY:
            print("[sentinel] proxy chat locked: X-Sentinel-Proxy-Key required")
        if not deps.settings.SENTINEL_ADMIN_KEY:
            print(f"[sentinel] ADMIN KEY (random per boot): {deps.settings.admin_key}")
            print("[sentinel] pin it via SENTINEL_ADMIN_KEY in .env — required for "
                  "/admin/* and POST /v1/runs")
        yield
        await deps.stop()

    app = FastAPI(title="SENTINEL — Prompt-Injection Security Testing Platform",
                  version="2.0", lifespan=lifespan)
    app.state.deps = deps
    origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
    if origins:   # v2.4: same-origin by default; cross-origin is an explicit opt-in
        app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"],
                           allow_headers=["*"])
    app.include_router(build_router(settings))
    app.include_router(mock_router)

    static_dir = Path(__file__).resolve().parent.parent / "static"
    if static_dir.exists():
        app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
    return app


app = create_app()
