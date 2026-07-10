"""Synthetic flow-trace capture for keep-alive HTTP.

When `keepalive_flow_capture_enabled` is on, every keep-alive cycle's
Graph /me + cookie-replay GET AND every Playwright silent-refresh
emits flow-trace entries into a per-site synthetic session
(`keepalive_<site_id>`) so the operator can study a refresh sequence
in the existing Flow Trace UI. Phase banners, Decoded JWTs, milestone
classifier all work on these entries because they share the same
shape as :8091 sessions.

Off by default — adds 2-N flow entries per cycle per site. When on,
the synthetic session also gets registered (`register_session`) so it
shows in the Sessions dropdown on the dashboard.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

from backend.shared import (
    append_flow, register_session, get_config_value,
)


def is_enabled() -> bool:
    return bool(get_config_value("keepalive_flow_capture_enabled", False))


def synthetic_sid(site_id: str) -> str:
    return f"keepalive_{site_id}"


# Track which synthetic sessions have been registered so we don't
# spam register_session(...) every cycle. Cleared on
# `unregister_synthetic` (e.g. credentials deletion).
_registered: set[str] = set()


def ensure_registered(site_id: str, hostname: str) -> str:
    """Idempotently register the synthetic keepalive_<site_id>
    session so it appears in the dashboard's Sessions dropdown.
    Returns the synthetic sid."""
    sid = synthetic_sid(site_id)
    if sid in _registered:
        return sid
    try:
        register_session(sid, {
            "login_url": f"keepalive://{hostname or site_id}",
            "site_id": site_id,
            "user_id": "",
            "synthetic": True,
            "source": "keepalive",
            # Treat the synthetic session as "trace on" so the Flow
            # Trace empty-state doesn't show the "trace is off" banner
            # when the user opens it.
            "trace": True,
        })
        _registered.add(sid)
    except Exception:
        pass
    return sid


def unregister_synthetic(site_id: str) -> None:
    sid = synthetic_sid(site_id)
    _registered.discard(sid)


def _classify(entry: dict) -> dict:
    """Run the auth_milestones classifier on a synthetic entry so
    LOGIN / TOKENS / SESSION pills show up in Flow Trace just like
    on operator sessions."""
    try:
        from backend import auth_milestones as _am
        tags = _am.classify(entry)
        if tags:
            entry["auth_milestones"] = tags
    except Exception:
        pass
    return entry


def append_http_round_trip(
    site_id: str, hostname: str, *,
    method: str, url: str,
    req_headers: dict | None = None,
    req_body: str | None = None,
    status: int | None = None,
    resp_headers: dict | None = None,
    resp_body: str | None = None,
    ts_req: float | None = None,
    ts_resp: float | None = None,
) -> int:
    """Append one HTTP round-trip captured by the keep-alive cycle
    (Graph /me probe, cookie-replay GET, anything else httpx-driven)
    as a flow-trace entry. Returns the assigned seq, or -1 when
    capture is off."""
    if not is_enabled():
        return -1
    sid = ensure_registered(site_id, hostname)
    entry = _classify({
        "req_id": f"ka_{int((ts_req or time.time()) * 1000)}_{id(url)}",
        "ts_req": ts_req or time.time(),
        "ts_resp": ts_resp,
        "method": (method or "GET").upper(),
        "url": url,
        "resource_type": "",
        "redirected_from_seq": None,
        "request_headers": dict(req_headers or {}),
        "request_body": req_body,
        "request_body_truncated": False,
        "status": status,
        "response_headers": dict(resp_headers or {}),
        "response_body": resp_body,
        "response_body_truncated": False,
        "_keepalive_capture": True,
    })
    return append_flow(sid, entry)


# ── Playwright per-refresh capture ─────────────────────────
# The dedicated keepalive Playwright pool runs short-lived contexts.
# Hook page.on(request/response) and accumulate flow entries while
# the page is alive. The hook is attached by keepalive_pw before
# navigation; it tears down implicitly when the context closes.

class PWCapture:
    """Captures Playwright request/response events on a single
    short-lived page during a keepalive refresh, appending them to
    the synthetic keepalive_<site_id> flow session."""

    def __init__(self, site_id: str, hostname: str):
        self.site_id = site_id
        self.hostname = hostname
        self.sid = ensure_registered(site_id, hostname)
        self._req_t0: dict[str, float] = {}

    async def on_request(self, request) -> None:
        if not is_enabled():
            return
        try:
            req_id = str(id(request))
            self._req_t0[req_id] = time.time()
            try:
                body = request.post_data
            except Exception:
                body = None
            entry = _classify({
                "req_id": req_id,
                "ts_req": self._req_t0[req_id],
                "ts_resp": None,
                "method": (request.method or "GET").upper(),
                "url": request.url,
                "resource_type": getattr(request, "resource_type", "") or "",
                "redirected_from_seq": None,
                "request_headers": dict(request.headers or {}),
                "request_body": body if isinstance(body, str) else (
                    body.decode("utf-8", "replace") if body else None),
                "request_body_truncated": False,
                "status": None,
                "response_headers": None,
                "response_body": None,
                "response_body_truncated": False,
                "_keepalive_capture": True,
                "_keepalive_phase": "pw",
            })
            append_flow(self.sid, entry)
        except Exception:
            pass

    async def on_response(self, response) -> None:
        if not is_enabled():
            return
        try:
            from backend.shared import update_flow
            req_id = str(id(response.request))
            headers = dict(response.headers or {})
            ct = (headers.get("content-type") or "").lower()
            body_text: str | None = None
            # Capture JSON / form / text bodies up to 64 KB —
            # mirrors the operator-session body-capture rules so
            # phase banners + Decoded JWTs work on token responses.
            should_capture = (
                "json" in ct or "text" in ct
                or "application/x-www-form-urlencoded" in ct
                or response.status >= 400
            )
            if should_capture:
                try:
                    import asyncio
                    raw = await asyncio.wait_for(response.body(), timeout=2.0)
                    body_text = raw[:64 * 1024].decode(
                        "utf-8", "replace") if raw else None
                except Exception:
                    pass
            patch: dict = {
                "ts_resp": time.time(),
                "status": response.status,
                "response_headers": headers,
                "response_body": body_text,
                "response_body_truncated": False,
            }
            # Re-classify with response now in hand — TOKENS / SESSION
            # / PRT live on the response side.
            try:
                from backend.shared import get_flow as _gf
                from backend import auth_milestones as _am
                req_part: dict = {}
                for fe in _gf(self.sid):
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
            except Exception:
                pass
            update_flow(self.sid, req_id, patch)
        except Exception:
            pass

    def attach(self, page) -> None:
        """Wire request + response handlers on a Playwright page.
        Caller must call this BEFORE page.goto so we don't miss
        the navigation request."""
        if not is_enabled():
            return
        try:
            import asyncio
            page.on("request",
                    lambda req: asyncio.create_task(self.on_request(req)))
            page.on("response",
                    lambda resp: asyncio.create_task(self.on_response(resp)))
        except Exception:
            pass
