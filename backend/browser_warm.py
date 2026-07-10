"""Pre-warmed Chromium for `:8091` operator sessions.

`browser_session()` previously paid the full Playwright + Chromium
launch cost on every WebSocket open (~1.1 s in our measurements:
~0.5 s for `async_playwright().start()`, ~0.5 s for
`chromium.launch()`). With this module the launch happens once at
app startup (or lazily on first session) and every subsequent
session calls `browser.new_context()` on the warm process — sub-50ms
per session.

Engine cache: a single warm browser keyed by `(family, channel,
chromium_arg_set)`. The default operator path (`edge` =
chromium-with-Edge-UA, no channel, standard chromium args) is the
hot path we're optimising. Other paths (`edge-real` with
`channel='msedge'`, firefox, webkit, mobile profiles that ship
custom args) fall back to a fresh launch — those are rare enough
that adding warm copies isn't worth the extra RAM.

The browser is **not** shared with the keepalive Playwright fallback
in `backend/keepalive_pw.py` — that's a separate dedicated process
so operator sessions and keepalive refreshes don't contend.
"""

from __future__ import annotations

import asyncio
import sys
import time
from typing import Any

from backend.shared import append_log


# ── State ────────────────────────────────────────────────
_pw = None              # Single Playwright manager shared by all warm browsers
_pw_lock = asyncio.Lock()  # Serialise initial Playwright start
_browsers: dict[tuple, Any] = {}      # (family, channel, args_key) -> Browser
_browsers_lock = asyncio.Lock()       # Serialise per-key launches
_started_at: float = 0.0
_session_count: int = 0


def is_running() -> bool:
    return bool(_browsers)


def stats() -> dict:
    return {
        "running": is_running(),
        "started_at": _started_at,
        "browser_count": len(_browsers),
        "session_count": _session_count,
        "uptime_seconds": (time.time() - _started_at) if _started_at else 0,
        "engines": [
            {"family": k[0], "channel": k[1] or None}
            for k in _browsers.keys()
        ],
    }


def _args_key(args: list[str]) -> tuple:
    """Hashable signature of a launch-args list for cache keying."""
    return tuple(sorted(args or []))


async def _ensure_pw():
    """Lazy-start the shared Playwright manager."""
    global _pw, _started_at
    if _pw is not None:
        return _pw
    async with _pw_lock:
        if _pw is not None:
            return _pw
        from playwright.async_api import async_playwright
        _pw = await async_playwright().start()
        if _started_at == 0.0:
            _started_at = time.time()
            append_log("info", "browser_warm",
                       "BROWSER_WARM playwright started")
    return _pw


async def get_warm_browser(family: str = "chromium",
                            channel: str | None = None,
                            args: list[str] | None = None):
    """Return a warm browser matching `(family, channel, args)`.
    Lazy-launches per key on first request; subsequent requests for
    the same key reuse the cached browser. Returns the Browser
    object — caller calls `browser.new_context(...)` on it."""
    args = args or []
    key = (family, channel or "", _args_key(args))
    cached = _browsers.get(key)
    if cached is not None:
        try:
            # Cheap liveness probe; if the browser was killed under
            # us (e.g. SIGTERM during a long debug pause) we need to
            # relaunch it.
            if cached.is_connected():
                return cached
        except Exception:
            pass
        _browsers.pop(key, None)
    pw = await _ensure_pw()
    async with _browsers_lock:
        cached = _browsers.get(key)
        if cached is not None:
            try:
                if cached.is_connected():
                    return cached
            except Exception:
                pass
            _browsers.pop(key, None)
        launch_opts: dict = {"headless": True, "args": list(args)}
        if family == "chromium" and channel:
            launch_opts["channel"] = channel
        t0 = time.time()
        if family == "chromium":
            browser = await pw.chromium.launch(**launch_opts)
        elif family == "firefox":
            launch_opts.pop("channel", None)
            launch_opts["args"] = []
            browser = await pw.firefox.launch(**launch_opts)
        elif family == "webkit":
            launch_opts.pop("channel", None)
            launch_opts["args"] = []
            browser = await pw.webkit.launch(**launch_opts)
        else:
            browser = await pw.chromium.launch(**launch_opts)
        elapsed = int((time.time() - t0) * 1000)
        _browsers[key] = browser
        append_log("info", "browser_warm",
                   f"BROWSER_WARM launched {family}"
                   f"{('-' + channel) if channel else ''} "
                   f"in {elapsed}ms (cache size={len(_browsers)})")
        return browser


def note_session_open():
    """Called from browser_session() each time a context is grabbed
    so the dashboard status surface can show how many sessions have
    used the warm pool since startup."""
    global _session_count
    _session_count += 1


def default_chromium_args() -> list[str]:
    """The standard chromium args used by the operator-session path
    when no special flags are needed. Kept here so callers can match
    the args_key used by the warm cache without duplicating the list."""
    args = ["--disable-blink-features=AutomationControlled",
            "--disable-gpu"]
    if sys.platform == "linux":
        # `--single-process` is intentionally omitted — see
        # routes/browser.py:launch_browser for the dmesg int3 trap
        # symptom on modern Chromium.
        args += ["--no-sandbox", "--disable-dev-shm-usage",
                  "--disable-setuid-sandbox"]
    return args


async def shutdown():
    """Tear down all warm browsers + the shared Playwright manager.
    Hooked into FastAPI's app shutdown event in backend/main.py."""
    global _pw, _started_at, _session_count
    for key, browser in list(_browsers.items()):
        try:
            await browser.close()
        except Exception:
            pass
    _browsers.clear()
    if _pw is not None:
        try:
            await _pw.stop()
        except Exception:
            pass
        _pw = None
    _started_at = 0.0
    _session_count = 0
    append_log("info", "browser_warm", "BROWSER_WARM shutdown complete")


async def prewarm():
    """Eager-launch the default chromium at app startup so the first
    operator session lands on a hot browser. Called from FastAPI's
    startup event in backend/main.py. Idempotent — safe to call
    multiple times."""
    args = default_chromium_args()
    try:
        await get_warm_browser(family="chromium", channel=None,
                                args=args)
    except Exception as e:
        append_log("warn", "browser_warm",
                   f"BROWSER_WARM prewarm failed: "
                   f"{type(e).__name__}: {e} — sessions will fall "
                   f"back to per-session launch")
