"""Dedicated Playwright instance for SPA keepalive refresh.

When a site is an MSAL/OIDC SPA, cookie-replay against the root URL
returns the index.html shell — no token. Real token rotation happens
in the page via MSAL's silent-renewal flow (hidden iframe to
`/oauth2/v2.0/authorize?prompt=none` followed by a `/oauth2/v2.0/token`
POST). The only way to drive that from outside is to actually run the
SPA in a browser.

This module owns ONE long-lived headless Chromium instance, kept warm
for the lifetime of the process. Each refresh:

  1. Acquires `_pw_lock` (refreshes are serialised).
  2. Opens a fresh `BrowserContext` with the captured cookies hydrated.
  3. Hooks `page.on("response", …)` for any URL containing `/token`
     so we can intercept the silent-renewal POST when MSAL fires it.
  4. Navigates `page.goto(current_url)` and waits up to
     `keepalive_playwright_timeout_seconds` for either:
       - the /token POST to land with `access_token` in its body, or
       - a localStorage MSAL cache entry to appear with a fresh token.
  5. Closes the context (browser stays alive).
  6. Returns the new token (or None on timeout).

The dedicated browser is **separate** from `routes/browser.py:_live_pages`
(operator sessions) and from `auth_proxy._auto_sessions` (auto-launched
sessions for `:3128`) — keepalive refreshes don't touch either.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlparse

from backend.shared import append_log, get_config_value


# ── State ────────────────────────────────────────────────
_pw = None                  # Playwright manager
_browser = None             # Long-lived BrowserContext-source
_pw_lock = asyncio.Lock()   # Serialise refreshes
_launch_lock = asyncio.Lock()  # Serialise lazy-launch / relaunch
_started_at: float = 0.0
_refresh_count: int = 0


def is_running() -> bool:
    return _browser is not None


def stats() -> dict:
    return {
        "running": is_running(),
        "started_at": _started_at,
        "refresh_count": _refresh_count,
        "uptime_seconds": (time.time() - _started_at) if _started_at else 0,
    }


def _browser_alive() -> bool:
    """True when our cached browser handle still has a live chromium
    behind it. Mirrors browser_warm's is_connected() probe — without
    this the lazy-launch path can hand out a stale wrapper after the
    underlying process dies (Playwright then throws TargetClosedError
    on the first new_page() call)."""
    if _browser is None:
        return False
    try:
        return bool(_browser.is_connected())
    except Exception:
        return False


async def ensure_browser():
    """Lazy-start (or re-launch) the dedicated Chromium. Idempotent —
    safe to call repeatedly. Probes liveness on entry so a crashed /
    externally-closed browser is replaced transparently. Serialised
    via _launch_lock so concurrent refreshes don't race two
    simultaneous chromium launches."""
    global _pw, _browser, _started_at
    if _browser_alive():
        return _browser
    async with _launch_lock:
        # Re-check inside the lock — another coroutine may have
        # launched while we were waiting.
        if _browser_alive():
            return _browser
        # Drop a stale wrapper before relaunching so the new browser
        # cleanly replaces it.
        if _browser is not None:
            try:
                await _browser.close()
            except Exception:
                pass
            _browser = None
        if _pw is not None:
            # Stale Playwright manager — the chromium under it died,
            # which usually means the manager is half-gone too. Kill
            # and replace.
            try:
                await _pw.stop()
            except Exception:
                pass
            _pw = None
        from playwright.async_api import async_playwright
        _pw = await async_playwright().start()
        args = ["--disable-blink-features=AutomationControlled",
                "--disable-gpu"]
        import sys
        if sys.platform == "linux":
            args += ["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-setuid-sandbox", "--single-process"]
        _browser = await _pw.chromium.launch(headless=True, args=args)
        _started_at = time.time()
        append_log("info", "keepalive_pw",
                   f"PW_KEEPALIVE browser launched (chromium, {len(args)} args)")
        return _browser


async def shutdown_browser():
    """Tear down the dedicated browser at app shutdown."""
    global _pw, _browser, _started_at, _refresh_count
    if _browser is None:
        return
    try:
        await _browser.close()
    except Exception:
        pass
    try:
        if _pw is not None:
            await _pw.stop()
    except Exception:
        pass
    _browser = None
    _pw = None
    _started_at = 0.0
    _refresh_count = 0
    append_log("info", "keepalive_pw", "PW_KEEPALIVE browser shut down")


# ── Refresh ──────────────────────────────────────────────

def _looks_like_spa_html(body: str | None) -> bool:
    """Cheap test: is the cookie-replay response just an SPA shell?"""
    if not body:
        return False
    head = body[:600].lower()
    return ("<!doctype html" in head and
            ("<div id=\"root\"" in head
             or "<div id='root'" in head
             or "<noscript>" in head))


async def _extract_token_from_response(resp) -> str | None:
    """When a Playwright response looks like a token endpoint, parse
    the body and return access_token / id_token if present. Lazy —
    only inspect bodies of POST responses on /token-shaped URLs."""
    try:
        url = resp.url or ""
        if not any(s in url for s in (
                "/oauth2/v2.0/token", "/oauth2/token",
                "/oauth/token", "/connect/token",
                "/as/token.oauth2")):
            return None
        if 200 > (resp.status or 0) or (resp.status or 0) >= 300:
            return None
        body_text = await resp.text()
        body_obj = json.loads(body_text)
        if not isinstance(body_obj, dict):
            return None
        for k in ("access_token", "id_token", "accessToken", "idToken"):
            if body_obj.get(k):
                return body_obj[k]
    except Exception:
        return None
    return None


async def refresh_via_playwright(site_id: str, data: dict) -> dict:
    """Drive a silent token refresh in the dedicated browser.

    Args:
        site_id: credentials_store key.
        data: the credentials record (cookies, current_url, …).

    Returns:
        {
          ok: bool,
          new_token: str | None,
          source: str ("pw_token_response" / "pw_localstorage" / "pw_timeout"),
          elapsed_ms: int,
          notes: list[str],
          error?: str,
        }
    """
    global _refresh_count
    notes: list[str] = []
    cookies_list = data.get("cookies") or []
    current_url = data.get("current_url") or ""
    if not cookies_list or not current_url:
        return {"ok": False, "new_token": None, "source": "no_input",
                "elapsed_ms": 0,
                "error": "missing cookies or current_url"}

    timeout_s = max(3, int(get_config_value(
        "keepalive_playwright_timeout_seconds", 12)))
    try:
        await ensure_browser()
    except Exception as e:
        return {"ok": False, "new_token": None, "source": "launch_failed",
                "elapsed_ms": 0, "error": f"{type(e).__name__}: {e}"}

    # Cookies need a sane domain — Playwright rejects empty-domain
    # entries. Filter out anything we can't normalise.
    target_host = urlparse(current_url).hostname or ""
    pw_cookies: list[dict] = []
    for c in cookies_list:
        if not isinstance(c, dict):
            continue
        name = c.get("name") or ""
        value = c.get("value")
        if not name or value is None:
            continue
        domain = c.get("domain") or target_host
        if not domain:
            continue
        path = c.get("path") or "/"
        cookie: dict = {"name": name, "value": str(value),
                        "domain": domain, "path": path}
        # Optional flags Playwright accepts when present.
        if c.get("httpOnly") is not None:
            cookie["httpOnly"] = bool(c["httpOnly"])
        if c.get("secure") is not None:
            cookie["secure"] = bool(c["secure"])
        if c.get("sameSite"):
            ss = str(c["sameSite"]).capitalize()
            if ss in ("Strict", "Lax", "None"):
                cookie["sameSite"] = ss
        if c.get("expires"):
            try:
                cookie["expires"] = int(c["expires"])
            except Exception:
                pass
        pw_cookies.append(cookie)
    notes.append(f"hydrating {len(pw_cookies)} cookies into context")

    t0 = time.time()
    new_token: str | None = None
    source = "pw_timeout"
    error: str | None = None

    async with _pw_lock:
        try:
            from playwright.async_api import TimeoutError as PWTimeout
            # One retry: if new_context fires TargetClosedError because
            # the cached browser died between the alive-probe and the
            # call, force a relaunch and try once more. Beyond one
            # retry it's a different problem (e.g. broken cookies).
            try:
                ctx = await _browser.new_context(
                    ignore_https_errors=bool(get_config_value("ignore_ssl",
                                                                False)),
                    viewport={"width": 1280, "height": 800},
                )
            except Exception as ce:
                cls = type(ce).__name__
                if "Closed" in cls or "Connection" in cls:
                    notes.append(f"new_context dead-browser ({cls}); "
                                  f"force-relaunching chromium")
                    # Drop the stale ref and retry via ensure_browser.
                    globals()["_browser"] = None
                    await ensure_browser()
                    ctx = await _browser.new_context(
                        ignore_https_errors=bool(get_config_value("ignore_ssl",
                                                                    False)),
                        viewport={"width": 1280, "height": 800},
                    )
                else:
                    raise
            try:
                if pw_cookies:
                    await ctx.add_cookies(pw_cookies)

                # Token-response trap. Set up a Future the page handler
                # can resolve when /token responds with an access_token.
                token_future: asyncio.Future = asyncio.get_running_loop().create_future()

                async def _on_resp(resp):
                    if token_future.done():
                        return
                    tok = await _extract_token_from_response(resp)
                    if tok:
                        token_future.set_result(("pw_token_response", tok))

                try:
                    page = await ctx.new_page()
                except Exception as pe:
                    cls = type(pe).__name__
                    if "Closed" in cls or "Connection" in cls:
                        notes.append(f"new_page dead-context ({cls}); "
                                      f"recreating context")
                        # Recreate context against a fresh browser.
                        try:
                            await ctx.close()
                        except Exception:
                            pass
                        globals()["_browser"] = None
                        await ensure_browser()
                        ctx = await _browser.new_context(
                            ignore_https_errors=bool(get_config_value("ignore_ssl",
                                                                        False)),
                            viewport={"width": 1280, "height": 800},
                        )
                        if pw_cookies:
                            await ctx.add_cookies(pw_cookies)
                        page = await ctx.new_page()
                    else:
                        raise
                # Optional synthetic flow capture — hooks BEFORE
                # page.goto so the navigation request lands in the
                # keepalive_<site_id> session.
                try:
                    from backend import keepalive_flow as _kaf
                    if _kaf.is_enabled():
                        host_for_cap = (urlparse(current_url).hostname
                                         or site_id)
                        _kaf.PWCapture(site_id,
                                        host_for_cap).attach(page)
                except Exception:
                    pass
                page.on("response",
                        lambda r: asyncio.create_task(_on_resp(r)))

                _refresh_count += 1
                append_log("info", "keepalive_pw",
                           f"PW_KEEPALIVE [{site_id}] silent refresh "
                           f"start url={current_url[:120]}")

                # Navigate. We don't care about the navigation result
                # itself — we're listening for the /token response.
                try:
                    await page.goto(current_url, wait_until="commit",
                                     timeout=timeout_s * 1000)
                except Exception as ge:
                    notes.append(f"goto warn: {ge}")

                # Race: token-response future vs timeout.
                try:
                    src, tok = await asyncio.wait_for(
                        token_future, timeout=timeout_s)
                    new_token = tok
                    source = src
                    notes.append(f"caught token via {src}")
                except asyncio.TimeoutError:
                    # Final pass: scrape MSAL localStorage cache. Some
                    # SPAs minted the token before our handler attached
                    # (e.g. on a fast reload).
                    try:
                        scraped = await page.evaluate(
                            "() => { try {"
                            "for (let i=0;i<localStorage.length;i++){"
                            "const k=localStorage.key(i);"
                            "const v=localStorage.getItem(k);"
                            "if(!v)continue;"
                            "if(v.indexOf('\"access_token\"')>=0||"
                            "v.indexOf('\"id_token\"')>=0||"
                            "v.indexOf('\"secret\"')>=0){"
                            "try{const o=JSON.parse(v);"
                            "if(o.access_token)return o.access_token;"
                            "if(o.id_token)return o.id_token;"
                            "if(o.secret&&o.secret.length>40)return o.secret"
                            "}catch(e){}}}"
                            "}catch(e){} return null }")
                        if isinstance(scraped, str) and scraped:
                            new_token = scraped
                            source = "pw_localstorage"
                            notes.append("scraped from localStorage")
                    except Exception as se:
                        notes.append(f"localStorage scrape error: {se}")
            finally:
                try:
                    await ctx.close()
                except Exception:
                    pass
        except Exception as e:
            error = f"{type(e).__name__}: {e}"

    elapsed_ms = int((time.time() - t0) * 1000)

    if new_token:
        append_log("info", "keepalive_pw",
                   f"PW_KEEPALIVE [{site_id}] got new token "
                   f"len={len(new_token)} via {source} in {elapsed_ms}ms")
        return {"ok": True, "new_token": new_token, "source": source,
                "elapsed_ms": elapsed_ms, "notes": notes}
    if error:
        append_log("warn", "keepalive_pw",
                   f"PW_KEEPALIVE [{site_id}] failed in {elapsed_ms}ms: "
                   f"{error}")
        return {"ok": False, "new_token": None, "source": "error",
                "elapsed_ms": elapsed_ms, "error": error, "notes": notes}
    append_log("info", "keepalive_pw",
               f"PW_KEEPALIVE [{site_id}] no token after {elapsed_ms}ms "
               f"({timeout_s}s timeout)")
    return {"ok": False, "new_token": None, "source": "pw_timeout",
            "elapsed_ms": elapsed_ms,
            "error": "no token captured before timeout",
            "notes": notes}
