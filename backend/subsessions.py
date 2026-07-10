"""Per-login sub-session records.

A sub-session is a single browser-session run that went through (or tried to
go through) login, tagged to the user identified during that run. Each one
captures the interesting events — auth headers seen in flight, cookies,
tokens, URLs visited — so an analyst can look at "what did *this specific
login* produce" independently of any prior or later login under the same
credentials.

Storage shape:
    subsessions/<sid>.json:
        {
          "id": "<sid>",
          "site_id": "...",
          "user_id": "...",
          "login_url": "...",
          "started_at": 1712345.67,
          "logged_in_at": 1712346.12,   # None until identified
          "finalized_at": null,
          "events": [
             {"at": 1712345.7, "type": "auth_header",
              "name": "Authorization: Bearer", "source": "...",
              "value_len": 412},
             ...
          ],
        }

Events never store the raw secret value — we keep only name + source + length
so the file on disk doubles as an audit trail without duplicating secrets that
already live in credentials_store.
"""
from __future__ import annotations

import time
from typing import Any

from backend.shared import append_log
from backend.store import JsonStore

_store = JsonStore("subsessions")

# In-memory mirror of active (unfinalised) sub-sessions, keyed by sid. We
# flush to disk on each append so nothing is lost on crash, but keeping the
# dict avoids re-reading the JSON file on every record.
_active: dict[str, dict[str, Any]] = {}


def _save(rec: dict[str, Any]) -> None:
    _store.put(rec["id"], rec)


def start_subsession(sid: str, site_id: str, user_id: str,
                     login_url: str = "") -> dict[str, Any]:
    """Create a sub-session record keyed by sid. Idempotent — calling twice
    just returns the existing record."""
    if sid in _active:
        # Update fields if we learnt more (user_id often arrives later than
        # the initial register_session)
        rec = _active[sid]
        changed = False
        if user_id and rec.get("user_id") != user_id:
            rec["user_id"] = user_id
            if not rec.get("logged_in_at"):
                rec["logged_in_at"] = time.time()
            changed = True
        if site_id and not rec.get("site_id"):
            rec["site_id"] = site_id
            changed = True
        if login_url and not rec.get("login_url"):
            rec["login_url"] = login_url
            changed = True
        if changed:
            _save(rec)
        return rec

    rec = {
        "id": sid,
        "site_id": site_id,
        "user_id": user_id or "",
        "login_url": login_url,
        "started_at": time.time(),
        "logged_in_at": time.time() if user_id else None,
        "finalized_at": None,
        "events": [],
    }
    _active[sid] = rec
    _save(rec)
    append_log("info", "subsession",
               f"SUBSESSION_START {sid} site={site_id} user={user_id or '(none)'}",
               session_id=sid)
    return rec


def set_user_id(sid: str, user_id: str) -> None:
    """Called when the user identity is captured mid-session."""
    rec = _active.get(sid)
    if not rec or not user_id:
        return
    if rec.get("user_id") == user_id:
        return
    rec["user_id"] = user_id
    rec["logged_in_at"] = rec.get("logged_in_at") or time.time()
    _save(rec)
    append_log("info", "subsession",
               f"SUBSESSION_USER {sid} user={user_id}", session_id=sid)


def record_event(sid: str, event_type: str, **fields: Any) -> None:
    """Append a typed event to the sub-session. Creates the record lazily if
    the sub-session wasn't started first (so a capture from before user_id
    arrives isn't lost)."""
    rec = _active.get(sid)
    if rec is None:
        # Lazy create with what we know
        rec = start_subsession(sid, fields.get("site_id", ""),
                                fields.get("user_id", ""),
                                fields.get("login_url", ""))
    evt = {"at": time.time(), "type": event_type}
    for k, v in fields.items():
        if k in ("site_id", "user_id", "login_url"):
            continue  # metadata fields, not event payload
        evt[k] = v
    rec.setdefault("events", []).append(evt)
    _save(rec)


def finalize_subsession(sid: str, summary: dict | None = None) -> None:
    """Mark the sub-session as finalized. Summary (e.g., cookie_count,
    token_count) is merged onto the record."""
    rec = _active.pop(sid, None)
    if rec is None:
        rec = _store.get(sid)
    if rec is None:
        return
    rec["finalized_at"] = time.time()
    if summary:
        rec["summary"] = {**rec.get("summary", {}), **summary}
    _save(rec)
    append_log("info", "subsession",
               f"SUBSESSION_FINALIZE {sid} events={len(rec.get('events', []))}",
               session_id=sid)


def list_subsessions(limit: int = 200) -> list[dict[str, Any]]:
    """Return all sub-session records, most recent first."""
    out: list[dict[str, Any]] = []
    for key in _store.list_keys():
        rec = _store.get(key)
        if rec:
            out.append(rec)
    out.sort(key=lambda r: r.get("started_at", 0), reverse=True)
    return out[:limit]


def get_subsession(sid: str) -> dict[str, Any] | None:
    return _active.get(sid) or _store.get(sid)


def delete_subsession(sid: str) -> bool:
    _active.pop(sid, None)
    return _store.delete(sid)


def clear_all_subsessions() -> int:
    n = _store.clear_all()
    _active.clear()
    return n
