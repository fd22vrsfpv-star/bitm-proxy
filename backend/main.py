"""BITM Proxy — FastAPI backend entry point.

Main app on port 8090, debug dashboard on port 8091.
"""

from fastapi import FastAPI, Response
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.routes import browser, sessions, devices, capture
from backend.shared import get_config
from backend.auth import APIKeyMiddleware

app = FastAPI(title="BITM Proxy", version="1.29.0")

app.add_middleware(APIKeyMiddleware)

app.include_router(browser.router, prefix="/api/browser", tags=["browser"])
app.include_router(sessions.router, prefix="/api/sessions", tags=["sessions"])
app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
app.include_router(capture.router, prefix="/api/capture", tags=["capture"])


@app.on_event("startup")
async def _prewarm_operator_browser():
    """Eager-launch the default chromium so the first :8091
    operator session lands on a warm browser instead of paying the
    ~1.0-1.5s Playwright + chromium launch cost.

    Critically: this runs as a fire-and-forget background task,
    NOT awaited inline. uvicorn's lifespan startup is awaited
    BEFORE the server binds, and run.py shares one event loop
    across :8091 / :8092 / :8000 / :8085. If the Playwright launch
    hangs (missing chromium binary, slow driver download, sandbox
    refusal) an awaited prewarm here would block ALL four servers
    from coming up. Backgrounding it means the first operator
    session pays a small additional cost if it lands before the
    warm task completes; everything else is immune.
    """
    import asyncio
    async def _bg():
        try:
            from backend import browser_warm
            from backend.shared import append_log
            try:
                await asyncio.wait_for(browser_warm.prewarm(),
                                        timeout=30.0)
            except asyncio.TimeoutError:
                append_log("warn", "browser_warm",
                           "BROWSER_WARM prewarm timed out after 30s "
                           "— sessions will fall back to per-session "
                           "launch")
        except Exception:
            # browser_warm.prewarm already logs its own failures;
            # this catch keeps the background task quiet on import
            # errors.
            pass
    asyncio.create_task(_bg())


@app.on_event("shutdown")
async def _shutdown_keepalive_pw():
    """Tear down the dedicated keep-alive Playwright browser if it
    was ever launched. No-op when the SPA fallback was never used."""
    try:
        from backend import keepalive_pw
        await keepalive_pw.shutdown_browser()
    except Exception:
        pass


@app.on_event("shutdown")
async def _shutdown_browser_warm():
    """Tear down the operator-session warm browser pool."""
    try:
        from backend import browser_warm
        await browser_warm.shutdown()
    except Exception:
        pass


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/api/config")
async def api_get_config():
    return get_config()


_FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    b'<rect width="32" height="32" rx="6" fill="#0ea5e9"/>'
    b'<path d="M7 16h12m0 0-4-4m4 4-4 4" stroke="#0a0a14" '
    b'stroke-width="3" stroke-linecap="round" stroke-linejoin="round" fill="none"/>'
    b'</svg>'
)


@app.get("/favicon.ico")
@app.get("/favicon.svg")
async def favicon():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})

# Serve built frontend (static files). Mounted under /proxy-assets/ (not the
# Vite default /assets/) so this app can coexist on an nginx vhost that
# already has a sibling SPA owning /assets/. Vite is configured to emit
# into dist/proxy-assets/ via build.assetsDir in frontend/vite.config.ts.
static_dir = Path(__file__).parent.parent / "static"
if static_dir.exists():
    _pa_dir = static_dir / "proxy-assets"
    # Fall back to the legacy /assets/ layout if an old build is deployed.
    if _pa_dir.exists():
        app.mount("/proxy-assets",
                  StaticFiles(directory=_pa_dir), name="proxy-assets")
    elif (static_dir / "assets").exists():
        app.mount("/assets",
                  StaticFiles(directory=static_dir / "assets"), name="assets")

    @app.get("/{path:path}")
    async def spa_fallback(path: str):
        file_path = static_dir / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(static_dir / "index.html")
