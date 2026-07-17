"""Shared state between main app and debug server.

All state changes are pushed to subscribers via asyncio Queues,
enabling fully WebSocket-driven debug dashboards.
"""

import asyncio
import json
import logging
import logging.handlers
import os
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any

# ── Event system — subscribers get all state changes ──
MAX_LOG_LINES = 10000
_log_buffer: deque[dict] = deque(maxlen=MAX_LOG_LINES)
_subscribers: list[asyncio.Queue] = []

# Lightweight metrics — surfaced via /api/metrics for perf investigations.
_bus_metrics = {
    "pushed": 0,       # total events pushed
    "fanned_out": 0,   # cumulative recipient count (pushed × subscribers)
    "dropped": 0,      # events dropped because a subscriber's queue was full
    "dead_subs": 0,    # subscribers we removed because their queue was full
}


def _push(event: dict):
    """Push an event to all subscribers. Subscribers whose queues are full
    are dropped (they're slower than we can feed them)."""
    _bus_metrics["pushed"] += 1
    dead = []
    for q in _subscribers:
        try:
            q.put_nowait(event)
            _bus_metrics["fanned_out"] += 1
        except asyncio.QueueFull:
            _bus_metrics["dropped"] += 1
            dead.append(q)
    for q in dead:
        try:
            _subscribers.remove(q)
        except ValueError:
            pass
        _bus_metrics["dead_subs"] += 1


def subscribe() -> asyncio.Queue:
    q: asyncio.Queue = asyncio.Queue(maxsize=5000)
    _subscribers.append(q)
    return q


def unsubscribe(q: asyncio.Queue):
    if q in _subscribers:
        _subscribers.remove(q)


def get_bus_metrics() -> dict:
    """Snapshot of event-bus counters + current subscriber count."""
    return {
        **_bus_metrics,
        "subscribers": len(_subscribers),
        "log_buffer_len": len(_log_buffer),
    }


# ── File logger (rotating) ──

_file_logger: logging.Logger | None = None
_file_handler: logging.handlers.RotatingFileHandler | None = None

_LOG_MAX_BYTES = 25 * 1024 * 1024   # 25 MB per file
_LOG_BACKUP_COUNT = 3                # keep last 3 rotated files (100 MB max)


def _get_log_dir() -> Path:
    from backend.paths import data_dir
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_file_logger():
    """Initialize the rotating file logger on first use."""
    global _file_logger, _file_handler
    if _file_logger is not None:
        return
    log_dir = _get_log_dir()
    log_path = log_dir / "captured.log"
    _file_logger = logging.getLogger("mitm-proxy-capture")
    _file_logger.setLevel(logging.DEBUG)
    _file_logger.propagate = False
    _file_handler = logging.handlers.RotatingFileHandler(
        str(log_path),
        maxBytes=_LOG_MAX_BYTES,
        backupCount=_LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    _file_handler.setFormatter(logging.Formatter(
        "%(asctime)s\t%(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    _file_logger.addHandler(_file_handler)


def _log_to_file(entry: dict):
    """Write a log entry to the rotating file."""
    if not _file_logger:
        return
    # Tab-separated: level, category, session_id, message
    line = json.dumps(entry, default=str, separators=(",", ":"))
    _file_logger.info(line)


def get_log_file_info() -> dict:
    """Return info about the current log file for the UI."""
    log_dir = _get_log_dir()
    log_path = log_dir / "captured.log"
    files = sorted(log_dir.glob("captured.log*"))
    total_size = sum(f.stat().st_size for f in files if f.exists())
    return {
        "enabled": _config.get("log_to_file", False),
        "path": str(log_path),
        "dir": str(log_dir),
        "file_count": len(files),
        "total_size_mb": round(total_size / (1024 * 1024), 1),
        "max_size_mb": _LOG_MAX_BYTES // (1024 * 1024),
        "max_files": _LOG_BACKUP_COUNT,
    }


# ── Per-session log files ──

_session_loggers: dict[str, logging.Logger] = {}


def _get_session_log_dir() -> Path:
    d = _get_log_dir() / "sessions"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_session_logger(session_id: str) -> logging.Logger:
    """Get or create a file logger for a specific session."""
    if session_id in _session_loggers:
        return _session_loggers[session_id]
    log_path = _get_session_log_dir() / f"{session_id}.log"
    logger = logging.getLogger(f"mitm-proxy-session-{session_id}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    handler = logging.FileHandler(str(log_path), encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s\t%(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    logger.addHandler(handler)
    _session_loggers[session_id] = logger
    return logger


def close_session_logger(session_id: str):
    """Close and remove the logger for a completed session."""
    logger = _session_loggers.pop(session_id, None)
    if logger:
        for h in logger.handlers[:]:
            h.close()
            logger.removeHandler(h)


def list_session_logs() -> list[dict]:
    """List all per-session log files with metadata."""
    log_dir = _get_session_log_dir()
    results = []
    for f in sorted(log_dir.glob("*.log")):
        stat = f.stat()
        results.append({
            "session_id": f.stem,
            "path": str(f),
            "size_bytes": stat.st_size,
            "modified": stat.st_mtime,
        })
    return results


def read_session_log(session_id: str) -> str | None:
    """Read the full log for a specific session."""
    log_path = _get_session_log_dir() / f"{session_id}.log"
    if not log_path.exists():
        return None
    return log_path.read_text(encoding="utf-8")


# ── Current JWTs file ──

_jwt_lock = asyncio.Lock()


def _atomic_write_text(path: Path, content: str) -> None:
    """Write text to path atomically via temp file + rename."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    closed = False
    try:
        os.write(fd, content.encode("utf-8"))
        os.close(fd)
        closed = True
        os.rename(tmp, str(path))
    except Exception:
        if not closed:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def _get_jwts_path() -> Path:
    from backend.paths import data_dir
    return data_dir() / "current_jwts.json"


def _is_plain_jwt(token: str) -> bool:
    """Check if a token is a plain JWT (3 dot-separated parts, typ=JWT header)."""
    import base64 as _b64
    parts = token.split(".")
    if len(parts) != 3:
        return False
    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(_b64.urlsafe_b64decode(header_b64))
        return header.get("typ") == "JWT"
    except Exception:
        return False


async def update_current_jwts(site_id: str, token_data: dict):
    """Update the current-JWTs file with the latest token for a site.

    Prefers plain JWT tokens over encrypted JWE tokens, since JWTs can be
    decoded and validated (expiry check, Graph API test).

    Uses an asyncio lock to prevent concurrent writes from clobbering each other.
    """
    async with _jwt_lock:
        jwt_path = _get_jwts_path()
        existing: dict = {}
        if jwt_path.exists():
            try:
                existing = json.loads(jwt_path.read_text(encoding="utf-8"))
            except Exception:
                existing = {}

        new_token = token_data.get("access_token") or token_data.get("token") or ""
        new_is_jwt = _is_plain_jwt(new_token)

        # Only overwrite an existing plain JWT with another plain JWT (not encrypted)
        current = existing.get(site_id, {})
        current_token = current.get("access_token", "")
        current_is_jwt = _is_plain_jwt(current_token) if current_token else False

        if current_is_jwt and not new_is_jwt:
            # Keep the existing plain JWT, don't overwrite with encrypted token
            return

        existing[site_id] = {
            "access_token": new_token,
            "refresh_token": token_data.get("refresh_token") or current.get("refresh_token") or "",
            "expires_in": token_data.get("expires_in") or token_data.get("expiresIn") or "",
            "captured_at": token_data.get("captured_at", time.time()),
            "source_url": token_data.get("source_url", ""),
        }

        _atomic_write_text(jwt_path, json.dumps(existing, indent=2, default=str))


def get_current_jwts() -> dict:
    """Read the current JWTs file."""
    jwt_path = _get_jwts_path()
    if not jwt_path.exists():
        return {}
    try:
        return json.loads(jwt_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


async def mark_jwt_expired(site_id: str):
    """Mark a JWT as expired in the current-JWTs file."""
    async with _jwt_lock:
        jwt_path = _get_jwts_path()
        if not jwt_path.exists():
            return
        try:
            existing = json.loads(jwt_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if site_id in existing:
            existing[site_id]["expired"] = True
            existing[site_id]["expired_at"] = time.time()
            _atomic_write_text(jwt_path, json.dumps(existing, indent=2, default=str))


# ── Logs ──

def append_log(level: str, category: str, message: str,
               session_id: str = ""):
    entry = {
        "type": "log",
        "ts": time.time(),
        "time": time.strftime("%H:%M:%S"),
        "level": level,
        "category": category,
        "message": message,
        "session_id": session_id,
    }
    _log_buffer.append(entry)
    _push(entry)
    # Write to rotating file if enabled
    if _config.get("log_to_file", False):
        _ensure_file_logger()
        _log_to_file(entry)
    # Write to per-session log file if session_id is present
    if session_id:
        session_logger = _get_session_logger(session_id)
        session_logger.info(json.dumps(entry, default=str, separators=(",", ":")))


def get_logs(last_n: int = 500, category: str | None = None,
             session_id: str | None = None) -> list[dict]:
    logs = list(_log_buffer)
    if category:
        logs = [l for l in logs if l["category"] == category]
    if session_id:
        logs = [l for l in logs if l.get("session_id") == session_id]
    return logs[-last_n:]


# ── Flow tracer (structured per-session req/resp capture) ──

MAX_FLOW_PER_SESSION = 2000
_session_flows: dict[str, deque] = {}
_session_flow_seq: dict[str, int] = {}


def append_flow(session_id: str, entry: dict) -> int:
    """Append a new flow entry for a session. Returns the assigned seq."""
    if not session_id:
        return -1
    buf = _session_flows.get(session_id)
    if buf is None:
        buf = deque(maxlen=MAX_FLOW_PER_SESSION)
        _session_flows[session_id] = buf
        _session_flow_seq[session_id] = 0
    seq = _session_flow_seq[session_id]
    _session_flow_seq[session_id] = seq + 1
    entry["type"] = "flow"
    entry["session_id"] = session_id
    entry["seq"] = seq
    buf.append(entry)
    _push(entry)
    return seq


def update_flow(session_id: str, req_id: str, patch: dict) -> bool:
    """Merge response fields into the in-flight entry matching req_id."""
    buf = _session_flows.get(session_id)
    if buf is None:
        return False
    for entry in reversed(buf):
        if entry.get("req_id") == req_id:
            entry.update(patch)
            _push({
                "type": "flow_update",
                "session_id": session_id,
                "seq": entry["seq"],
                "req_id": req_id,
                "patch": patch,
            })
            return True
    return False


def get_flow(session_id: str) -> list[dict]:
    buf = _session_flows.get(session_id)
    return list(buf) if buf else []


def clear_flow(session_id: str) -> None:
    if session_id in _session_flows:
        _session_flows[session_id].clear()
        _session_flow_seq[session_id] = 0


def find_flow_seq_by_req_id(session_id: str, req_id: str) -> int | None:
    buf = _session_flows.get(session_id)
    if buf is None:
        return None
    for entry in reversed(buf):
        if entry.get("req_id") == req_id:
            return entry.get("seq")
    return None


# ── Config file loading ──

def _load_config_file() -> dict[str, Any]:
    """Load config overrides from ./config/config.json and individual files.

    Reads:
      ./config/config.json          — full config dict (any keys)
      ./config/slack_keepalive.txt  — single-line webhook URL
      ./config/slack_capture.txt    — single-line webhook URL

    Also checks DATA_DIR/config/ as a fallback.
    """
    overrides: dict[str, Any] = {}

    # Search paths: ./config/, then DATA_DIR/config/
    from backend.paths import data_dir
    search_dirs = [
        Path("config"),
        Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))) / "config",
        data_dir() / "config",
    ]

    for config_dir in search_dirs:
        if not config_dir.is_dir():
            continue

        # Load full config JSON
        config_json = config_dir / "config.json"
        if config_json.exists():
            try:
                data = json.loads(config_json.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    overrides.update(data)
            except Exception as e:
                print(f"[config] Error reading {config_json}: {e}")

        # Load individual webhook files
        _file_map = {
            "slack_keepalive.txt": "slack_keepalive_webhook",
            "slack_capture.txt": "slack_capture_webhook",
            "slack_routine.txt": "slack_routine_webhook",
            "external_capture_token.txt": "external_capture_token",
        }
        for filename, config_key in _file_map.items():
            filepath = config_dir / filename
            if filepath.exists():
                try:
                    value = filepath.read_text(encoding="utf-8").strip()
                    if value:
                        overrides[config_key] = value
                except Exception as e:
                    print(f"[config] Error reading {filepath}: {e}")

    if overrides:
        print(f"[config] Loaded overrides: {list(overrides.keys())}")

    return overrides


# ── Runtime configuration ──

_config: dict[str, Any] = {
    "verbose": False,
    "ignore_ssl": True,
    "screenshot_quality": 85,
    "screenshot_interval": 0.3,
    # When the launched engine is non-Chromium (Firefox / WebKit —
    # e.g. an iPad Safari device profile), the screenshot loop falls
    # back to polling `page.screenshot()` instead of CDP screencast.
    # Each capture is a full-page paint + JPEG encode, so input-
    # driven nudges feel laggy on heavy pages. With this flag on,
    # the polling loop caps `screenshot_quality` at 55 and clamps
    # `screenshot_interval` to >= 0.5s regardless of the global
    # values, so typing into a WebKit canvas stays responsive. The
    # Chromium screencast path reads the global values unmodified.
    "screenshot_low_fidelity_non_chromium": True,
    # Device-pixel-ratio for desktop sessions. 2 = retina-style render,
    # so HiDPI operator screens get a sharp image instead of a 1x bitmap
    # being upscaled by CSS. Mobile profiles ignore this and use the
    # device's own DPR. 1 = legacy behavior, lower bandwidth.
    "screenshot_dpr": 2,
    "heartbeat_interval": 10.0,
    "goto_timeout": 15000,
    "default_login_url": "https://myapps.microsoft.com",
    # Default device profile applied to :8091 sessions when no explicit
    # `?device_id=` URL param is set. When non-empty, the proxy looks
    # the value up in the devices store (preset id, DRS credential id,
    # or a captured profile id) and applies it before the first
    # navigation — same code path as an explicit ?device_id=. Empty
    # string disables the fallback (current behaviour). The :8092
    # Configuration tab exposes this as a dropdown so the operator
    # picks a default once and subsequent :8091 users never see a
    # prompt — a missing or stale id falls through silently to "no
    # device profile" so a deleted device doesn't break new sessions.
    "default_device_id": "",
    # Default Entra ID tenant id (GUID or vanity domain). Auto-fills
    # the Captured Data → Get-AAATokenFromAzLogin snippet on every
    # site card so the operator doesn't paste it per-site. Empty
    # leaves a `<TENANT_ID>` placeholder in the snippet — copy still
    # works, the operator just edits the placeholder before running.
    "default_tenant_id": "",
    # Master gate for the Phantom Join feature (:8092 → Phantom tab).
    # Off by default. When on, the dashboard exposes a form that
    # spawns `tools/phantom_runner.py` (which drives roadtx /
    # roadrecon to register a phantom AAD device, mint a PRT, and
    # exchange it for resource tokens). High-blast-radius capability
    # — keep off when not actively running an authorized engagement.
    # The route returns 403 on every request unless this flag is set
    # AND the request carries the standard API key.
    "allow_phantom_join": False,
    # Tenant-domain allowlist for Phantom Join, checked in addition to
    # allow_phantom_join above. Empty (the default) = unrestricted, i.e.
    # today's behavior for every existing install — any domain the caller
    # supplies is accepted. Non-empty is opt-in hardening for a deployment
    # that must not be pointable at an arbitrary real org (e.g. a
    # publicly-reachable lab instance) — set via $DATA_DIR/config.json for
    # that deployment, not this committed file. Case-insensitive exact
    # match against the "domain" field the caller supplies; tenant domains
    # don't need wildcard/suffix matching the way hostnames do.
    "phantom_join_allowed_domains": [],
    "log_requests": False,
    "log_responses": False,
    "log_auth_headers": True,
    "log_set_cookies": True,
    "log_console": False,
    "auto_login_email": "",
    "browser_type": "edge",
    # Microsoft Authenticator push approval — when ON, the Playwright
    # session auto-clicks the "Approve a request on my Microsoft
    # Authenticator app" tile (`[data-value="PhoneAppNotification"]`) on
    # the MS sign-in method picker. The number-match challenge that
    # follows is already detected by site_rules and surfaced in the
    # dashboard log as `MFA NUMBER MATCH — tap **{n}** in the
    # authenticator app`. Useful for headless/remote setups where
    # cross-device passkeys can't work (BLE proximity required) but the
    # user has Authenticator app push configured for MFA.
    "prefer_push": False,
    # "full"    — full nav bar (back/forward/reload/URL input/paste/capture/close)
    # "minimal" — hide back/forward/reload/URL form; keep paste/capture/close
    # "none"    — no nav bar at all — primary window only (default)
    "browser_chrome": "none",
    "mobile_emulation": "off",  # off | phone_android | phone_ios | tablet_android | tablet_android_edge | tablet_ios | tablet_ios_edge
    "private_mode": True,
    "upstream_proxy": False,
    "upstream_proxy_host": "127.0.0.1:3128",
    "max_screenshots": 100,
    "mask_captured_input": True,
    # Blank out the [session_id] column in the All Logs view. The column is
    # still rendered as an empty placeholder so alignment stays stable when
    # toggled back on.
    "hide_session_id_in_logs": False,
    # When auth completion is detected, redirect the operator's browser
    # tab to the user's originally-requested URL (or the explicit
    # override below). The Playwright session itself stays put where
    # the IdP left it (e.g. myapps.microsoft.com) and is *kept alive*
    # past the WS disconnect so the auth proxy can keep routing
    # authenticated requests through it — see GET/DELETE
    # /api/browser/kept-alive. Off by default.
    "post_login_redirect_enabled": False,
    # Optional explicit URL the operator's browser navigates to after
    # auth completes. Empty = use the resolved target the session was
    # launched with (first URL Playwright opened).
    "post_login_redirect_url": "",
    # Independent of `post_login_redirect_enabled`: when on, navigate
    # the Playwright session itself (the headless browser) to a URL
    # after auth completes. Use when you want the captured browser
    # context to land on a specific page (an app dashboard, a console)
    # for further use, instead of staying wherever the IdP dropped it.
    # Can be combined with the operator-browser redirect above, or
    # used alone.
    "post_login_redirect_playwright_enabled": False,
    # Optional explicit URL the Playwright session navigates to after
    # auth completes. Empty = use the resolved target the session was
    # launched with.
    "post_login_redirect_playwright_url": "",
    # Operator-launch (devices tab → Launch) AUTO-MFA dead-end
    # behaviour. Default off — the dead-end parks on a "Passkey Error"
    # status. With `show_qr` on, the proxy clicks the FIDO/passkey
    # tile in the picker so MS renders its native passkey UI / cross-
    # device QR in the canvas. The QR will display, but BLE pairing
    # from a remote server can't complete; this is a diagnostic to
    # *see* where the flow stalls. Subject-link / auto-launched
    # sessions ignore this knob — they keep the existing redirect-to-
    # real-browser handoff so the subject can finish on their device.
    "mfa_dead_end_show_qr": False,
    # Independent of `show_qr`: when on, navigate the playwright
    # session to the OAuth 2.0 device authorization URL on dead-end.
    # Tests token issuance via a different OAuth grant — the operator
    # scans/types the code on their phone and an Entra app with the
    # device-code grant enabled returns a token. Not a substitute for
    # the user-facing sign-in flow. Off by default.
    "mfa_dead_end_device_code_enabled": False,
    # URL the playwright session navigates to when device_code falls
    # back. Defaults to Microsoft's well-known endpoint; override for
    # tenant-specific or custom-app URLs.
    "mfa_dead_end_device_code_url": "https://microsoft.com/devicelogin",
    # When launching a Playwright session, replay the User-Agent + client
    # hints + Accept-Language captured from the user's real browser on the
    # auth proxy (:3128). Lets Playwright present the same device signature
    # the IdP already trusts, so MFA doesn't challenge as "new device".
    "use_captured_fingerprint": False,
    # Sub-knobs: both honored only when use_captured_fingerprint is on.
    # engine: pick Playwright's firefox / webkit / chromium based on the
    # captured UA so the TLS Client Hello's JA3 matches the claimed
    # browser family. tls_proxy: route the auth-proxy's upstream leg
    # through curl_cffi with a Chrome/Firefox/Safari/Edge impersonation
    # profile so the origin sees a real-browser-shape JA3 instead of
    # stock OpenSSL.
    "fingerprint_match_engine": True,
    "fingerprint_match_tls_proxy": True,
    # Allow the auth-proxy on :3128 to serve a one-shot synthetic
    # JS-probe page when a Devices registration with `Active probe`
    # mode has stamped a pending probe for that host. The page
    # extracts timezone / screen / viewport / navigator.* signals
    # and POSTs them back via a sentinel path consumed in-proxy.
    # Off → registrations stay passive even when the operator picks
    # the active-probe mode.
    "device_probe_enabled": True,
    # Master gate for the AAD device-registration replay feature.
    # OFF by default — registration mutates state on the IdP tenant
    # (creates a real device record). When ON, the Flow Trace ⚡
    # Register button on a row carrying a DRS-scoped Bearer token
    # opens a confirmation modal; the actual POST to
    # /EnrollmentServer/device/ requires both this flag AND a
    # per-call confirm. Authorized testing only.
    "allow_drs_replay": False,
    "log_to_file": False,
    # Emit a per-session heartbeat line every heartbeat_interval seconds.
    # Useful for confirming a session is alive; noisy if not.
    "log_heartbeats": True,
    "keepalive_enabled": True,
    "keepalive_interval_minutes": 5,
    # Flow Trace per-request capture is OFF by default — it adds
    # measurable overhead to every browser session (flow append on
    # every request, response-body buffering, milestone classifier,
    # WS fanout to dashboard subscribers). Operator opts in either
    # via this global flag or per-session with `?trace=true` on the
    # :8091 URL. When off the credential-capture path still runs
    # (keepalive monitoring needs the captured Authorization headers
    # + cookies); only the heavy flow-buffer work is skipped.
    "flow_trace_enabled": False,
    # After this many consecutive failed cycles for a site, keep-alive
    # pauses it — stops hammering Graph + the cookie-replay endpoint
    # AND stops emitting recurring failure log lines / Slack alerts.
    # Operator resumes via the Debug-panel Resume button after fixing
    # the underlying capture (or accepting the loss).
    "keepalive_max_consecutive_failures": 2,
    # When ON, the keep-alive cycle emits a verbose per-site trace
    # alongside each check: token claims (aud/tid/scp/exp_in), the
    # exact Graph /me URL + status + response time, and any cookie-
    # replay round-trip (target URL, status, found-token result).
    # Default OFF — adds 3-5 lines per site per cycle.
    "keepalive_trace_enabled": False,
    # When the cookie-replay GET returns an SPA HTML shell with no
    # token (the myapps.microsoft.com / portal.azure.com / Office.com
    # pattern), fall back to driving the page in a dedicated long-
    # lived headless Chromium so MSAL's silent-renewal flow can fire
    # and we can capture the resulting /oauth2/v2.0/token response.
    # The browser is launched once, kept warm, and refreshes share
    # it via per-refresh BrowserContexts. Off by default — adds a
    # Chromium context per refresh on sites that need it.
    "keepalive_playwright_fallback_enabled": False,
    # Per-refresh timeout for the Playwright fallback. The page must
    # land + MSAL must complete its silent-renewal POST within this
    # window or the refresh is recorded as a timeout (and the
    # consecutive-failure counter ticks).
    "keepalive_playwright_timeout_seconds": 12,
    # When ON, every keep-alive cycle (httpx Graph /me + cookie-
    # replay GET) AND every Playwright silent-refresh records flow-
    # trace entries into a synthetic session keyed `keepalive_<site
    # _id>`. The Flow Trace UI / phase banners / Index decoded-JWTs
    # then work on those entries the same way they do on operator
    # sessions — useful when you want to study an auth-flow refresh
    # but missed the original capture. Default OFF — adds 2-N flow
    # entries per cycle per site.
    "keepalive_flow_capture_enabled": False,
    "enable_token_testing": True,
    "enable_slack_notifications": True,
    "autostart_playwright_from_proxy": False,
    "auto_login_wait_seconds": 10,
    "autostart_auth_proxy": True,
    "autostart_auth_proxy_port": 3128,
    # Initial log-history size sent to each new /ws/data subscriber. Smaller
    # = faster first paint + less memory churn with many clients.
    "ws_history_lines": 500,
    # Playwright worker pool. When enabled, /api/browser/session routes
    # through a pool of subprocess workers instead of running Playwright
    # in the :8091 control-plane process.
    "workers_enabled": False,
    "worker_count": 4,
    "worker_sessions_max": 5,
    "proxy_via_playwright": False,
    "slack_keepalive_webhook": "",
    "slack_capture_webhook": "",
    # Low-priority channel for routine events that don't need immediate
    # action — e.g. captures/login-starts where auto_login_email is blank
    # ("unknown user"), so the operator's main capture channel stays
    # focused on actively-tracked targets. Empty string disables routing
    # and unknown-user events fall through to the regular channel.
    "slack_routine_webhook": "",
    # POST /api/capture/external — bearer token required to enable the
    # external-ingest credential capture endpoint. Empty disables it
    # outright (endpoint returns 404). Settable via Configuration tab
    # OR config/external_capture_token.txt OR EXTERNAL_CAPTURE_TOKEN env.
    "external_capture_token": "",
    # IP/CIDR allowlist for /api/capture/external. Loopback (127.0.0.0/8,
    # ::1) is ALWAYS allowed. Add explicit egress IPs of your own tooling
    # hosts. Empty list = loopback-only.
    "external_capture_allowed_ips": [],
    # CORS allowlist for /api/capture/external. Each entry is an exact
    # origin (scheme + host + optional port — e.g.
    # https://lander.example.com), or "*" to allow any origin. Empty list
    # = no cross-origin (only same-origin POSTs from a lander hosted on
    # the proxy itself). Required for client-side landers on a separate
    # believable domain. NOTE: cross-origin lander capture also means the
    # source IP is the victim's, so external_capture_allowed_ips needs to
    # be broadened (often "0.0.0.0/0") for those deployments.
    "external_capture_cors_origins": [],
    "filter_noisy_requests": True,
    "noisy_extensions": [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
        ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".css", ".js", ".map",
        ".mp4", ".webm", ".mp3", ".ogg",
    ],
    "login_urls": [
        "https://myapps.microsoft.com",
        "https://accounts.google.com",
        "https://login.microsoftonline.com",
        "https://www.office.com",
        "https://github.com/login",
        "https://signin.aws.amazon.com",
    ],
    # RAG Scan Stack integration (burp-extension bridge API)
    "rag_enabled": False,
    "rag_api_url": "http://localhost:8000",
    "rag_api_key": "",
    "rag_engagement_id": "",
    # Ollama flow analysis
    "ollama_enabled": False,
    "ollama_url": "http://host.docker.internal:11434",
    "ollama_model": "llama3.1:8b",
    "ollama_temperature": 0.1,
    "ollama_top_p": 0.3,
    "ollama_top_k": 20,
    "ollama_num_ctx": 8192,
    "ollama_num_predict": -1,  # -1 = unlimited, model default
    "ollama_seed": 0,           # 0 = random, any int for reproducibility
    # Optional per-preset overrides. Leave empty to use the built-in defaults
    # shipped in backend/ollama_hook.py._PRESET_PROMPTS. When set, they win.
    "ollama_system_prompt_sso":          "",
    "ollama_system_prompt_saml":         "",
    "ollama_system_prompt_oidc":         "",
    "ollama_system_prompt_troubleshoot": "",
    "ollama_system_prompt": (
        "You are a web-application security analyst reviewing captured HTTP exchanges. "
        "You analyze ONLY the data shown in the user message. You MUST NOT:\n"
        "- invent URLs, headers, tokens, parameters, or values that are not in the captured data\n"
        "- speculate about parts of the flow that were not captured\n"
        "- draw on external knowledge about specific sites or APIs — use only what the capture shows\n\n"
        "Every factual claim must cite the supporting seq number(s) in the form #N. "
        "If something cannot be determined from the captured data, write "
        "\"not observable from capture\" and move on.\n\n"
        "Produce markdown with exactly these sections:\n"
        "1. **Flow summary** — 2-3 sentences identifying the auth protocol used. Only mention what is evidenced.\n"
        "2. **Key steps** — numbered list of the critical exchanges, each with its #seq number and what it accomplishes.\n"
        "3. **Credentials & tokens** — which exchanges posted credentials, which returned tokens/cookies, and how values propagate across requests. Cite seq numbers. Never emit token/cookie values.\n"
        "4. **Parameters of interest** — auth-related param names present (state, code, nonce, PKCE, CSRF, session cookies, bearer tokens). Names and seq numbers only, never values.\n"
        "5. **Notes** — anomalies observable in the data (missing PKCE where expected, credentials appearing in URLs, unusual redirect targets). Cite seq numbers. If nothing anomalous, state that.\n\n"
        "Do not add sections. Do not speculate. Do not summarize beyond the data."
    ),
}

# Snapshot of baseline defaults BEFORE any overrides. Used at save time to
# compute the diff we persist (so new defaults added in code continue to
# propagate to existing installs instead of being silently pinned by a
# stale on-disk copy).
_config_defaults = dict(_config)

# Apply overrides from config files on disk (repo ./config/ + DATA_DIR/config/)
_config.update(_load_config_file())


def _user_config_path() -> Path:
    """Per-install override file. Writes to DATA_DIR so ./config/ in the
    repo stays clean (survives git pull / image rebuild)."""
    from backend.paths import data_dir
    p = data_dir() / "config"
    p.mkdir(parents=True, exist_ok=True)
    return p / "config.json"


def _save_user_config() -> None:
    """Persist the diff of _config vs _config_defaults to the user override
    file. Atomic write via temp + os.replace so a crash mid-write can't
    corrupt the JSON."""
    diff: dict[str, Any] = {}
    for k, v in _config.items():
        if k not in _config_defaults or _config_defaults[k] != v:
            diff[k] = v
    path = _user_config_path()
    try:
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(diff, indent=2, default=str,
                                   ensure_ascii=False),
                        encoding="utf-8")
        os.replace(tmp, path)
    except Exception as e:
        append_log("warn", "config", f"Failed to persist config: {e}")


def get_config() -> dict[str, Any]:
    return dict(_config)


def update_config(updates: dict[str, Any]) -> dict[str, Any]:
    changed = {}
    for k, v in updates.items():
        if k in _config and _config[k] != v:
            _config[k] = v
            changed[k] = v
    if changed:
        append_log("info", "config", f"Config changed: {changed}")
        _push({"type": "config", "config": dict(_config)})
        _save_user_config()
    return dict(_config)


def get_config_value(key: str, default: Any = None) -> Any:
    return _config.get(key, default)


# ── Session tracking ──

_active_sessions: dict[str, dict] = {}


def register_session(session_id: str, info: dict):
    _active_sessions[session_id] = {**info, "started_at": time.time()}
    append_log("info", "session",
               f"Session started: {session_id} -> {info.get('login_url', '?')}",
               session_id=session_id)
    _push({"type": "sessions", "sessions": dict(_active_sessions)})


def update_session_info(session_id: str, updates: dict):
    """Merge field updates into an existing session's info and push to
    subscribers. Unlike register_session, does not reset started_at.
    If a non-empty `user_id` is set for the first time, also records
    `logged_in_at` as the moment the user was identified."""
    if session_id not in _active_sessions:
        return
    existing = _active_sessions[session_id]
    incoming_user = updates.get("user_id")
    if incoming_user and not existing.get("logged_in_at"):
        updates = {**updates, "logged_in_at": time.time()}
    existing.update(updates)
    _push({"type": "sessions", "sessions": dict(_active_sessions)})


def unregister_session(session_id: str):
    _active_sessions.pop(session_id, None)
    append_log("info", "session", f"Session ended: {session_id}",
               session_id=session_id)
    _push({"type": "sessions", "sessions": dict(_active_sessions)})


def get_active_sessions() -> dict[str, dict]:
    return dict(_active_sessions)


def notify_sites_changed():
    """Push a sites-changed event so debug dashboards refresh captured data."""
    _push({"type": "sites_changed"})
