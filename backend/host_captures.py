"""Per-hostname capture records.

Complements `backend/subsessions.py`. While a sub-session aggregates events
for *one login run* (keyed by session id), a host record aggregates events
for *one destination host* across every session that has ever touched it.

Storage:
    data/host_captures/<host>.json
        {
          "host": "login.microsoftonline.com",
          "first_seen": 1712100000.0,
          "last_seen":  1712345000.0,
          "users":  ["alice@corp", "bob@corp"],    # distinct user_ids
          "sids":   ["site_171...", "site_172..."],# distinct session ids
          "counts": {"auth_header": 23, "auto_capture": 2, ...},
          "events": [
            {"at": ..., "type": "auth_header",
             "sid": "site_171...", "user_id": "alice@corp",
             "name": "Authorization: Bearer", "value_len": 412, "source": "..."},
            ...
          ]
        }

Raw secret values are NOT stored — only name/source/length, mirroring the
subsessions store. Event rows always include `sid` and `user_id` so a host
record is useful even across sessions.

Host names are normalised (lowercased, stripped of port) before keying. Both
subdomains and parents are stored as distinct entries (so app.example.com
and example.com live separately — that's the whole point of this store).
"""
from __future__ import annotations

import re
import time
from typing import Any

from backend.shared import append_log
from backend.store import JsonStore


_store = JsonStore("host_captures")

# In-memory mirror, keyed by normalised host, for cheap incremental updates.
_cache: dict[str, dict[str, Any]] = {}

# Event-type -> counter key (for the `counts` summary).
_COUNT_KEYS = {"auth_header", "auto_capture", "manual_capture",
                "set_cookie", "bearer_token"}

# Bound on stored events per host — older entries are dropped FIFO.
_MAX_EVENTS_PER_HOST = 500

_SAFE_HOST_RE = re.compile(r"[^a-zA-Z0-9._-]+")


def _norm_host(host: str) -> str:
    if not host:
        return ""
    h = str(host).strip().lower()
    # Strip optional port (ssl handshake on 443 is the common case).
    if ":" in h:
        h = h.split(":", 1)[0]
    return h


def _storage_key(host: str) -> str:
    """JsonStore's key must be a safe filename — map dots/dashes preserved,
    everything else to underscore."""
    norm = _norm_host(host)
    return _SAFE_HOST_RE.sub("_", norm) or "_"


def _load(host: str) -> dict[str, Any]:
    norm = _norm_host(host)
    rec = _cache.get(norm)
    if rec is None:
        rec = _store.get(_storage_key(norm)) or {
            "host": norm,
            "first_seen": None,
            "last_seen": None,
            "users": [],
            "sids": [],
            "counts": {},
            "events": [],
        }
        _cache[norm] = rec
    return rec


def _save(rec: dict[str, Any]) -> None:
    _store.put(_storage_key(rec["host"]), rec)


def record_event(host: str, event_type: str, *,
                  sid: str = "", user_id: str = "",
                  **fields: Any) -> None:
    """Append a typed event under `host`. Ignored silently when host is empty."""
    norm = _norm_host(host)
    if not norm:
        return
    rec = _load(norm)
    now = time.time()
    if rec.get("first_seen") is None:
        rec["first_seen"] = now
    rec["last_seen"] = now
    if sid and sid not in rec["sids"]:
        rec["sids"].append(sid)
    if user_id and user_id not in rec["users"]:
        rec["users"].append(user_id)
    if event_type in _COUNT_KEYS:
        rec["counts"][event_type] = rec["counts"].get(event_type, 0) + 1
    evt = {"at": now, "type": event_type, "sid": sid, "user_id": user_id}
    evt.update({k: v for k, v in fields.items() if k not in ("host",)})
    rec["events"].append(evt)
    # Cap the per-host event list so a noisy flow doesn't grow unbounded.
    if len(rec["events"]) > _MAX_EVENTS_PER_HOST:
        rec["events"] = rec["events"][-_MAX_EVENTS_PER_HOST:]
    _save(rec)


def list_hosts(limit: int = 500) -> list[dict[str, Any]]:
    """Return summaries of every host captured. Most-recently-seen first.
    Each dict has host/first_seen/last_seen/users/sids/counts fields — not
    the full event list (pull that with `get_host`)."""
    out: list[dict[str, Any]] = []
    for key in _store.list_keys():
        rec = _store.get(key)
        if not rec:
            continue
        out.append({
            "host": rec.get("host", key),
            "first_seen": rec.get("first_seen"),
            "last_seen": rec.get("last_seen"),
            "users": rec.get("users", []),
            "sids": rec.get("sids", []),
            "counts": rec.get("counts", {}),
            "event_count": len(rec.get("events", [])),
        })
    out.sort(key=lambda r: r.get("last_seen") or 0, reverse=True)
    return out[:limit]


def get_host(host: str) -> dict[str, Any] | None:
    norm = _norm_host(host)
    if not norm:
        return None
    rec = _cache.get(norm) or _store.get(_storage_key(norm))
    return rec


def delete_host(host: str) -> bool:
    norm = _norm_host(host)
    _cache.pop(norm, None)
    return _store.delete(_storage_key(norm))


def clear_all() -> int:
    n = _store.clear_all()
    _cache.clear()
    append_log("info", "host_captures", f"cleared {n} host capture files")
    return n
