"""RAG Scan Stack-compatible API — exposes captured login flows as findings.

Implements the subset of the RAG API endpoints that the Burp extension
(`burp-extension/RagScanBridge.py`) calls, so users can point that extension
directly at this service with no external backend required.

Captured browser flows are converted to a single finding each
(`trace_flow_for_{hostname}`), with the full request/response sequence
embedded as evidence and the first exchange populated as `request_raw` /
`response_raw` for Burp's message viewer.

Runs on port 8000 by default (matching the Burp extension's default URL).
No auth — intended for local use. Reconfigure the port via `RAG_PORT` env var.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any

from fastapi import FastAPI, Request, Query

from backend.shared import _session_flows, append_log
from backend.rag_bridge import _build_finding, _flow_hostname
from backend.store import JsonStore


app = FastAPI(title="BITM Proxy — RAG API", version="1.0.0")


# Findings imported from external sources (Burp export, dashboard "Send to
# RAG"). Persisted via JsonStore so they survive an app/container restart —
# the built-in RAG store is otherwise in-memory only, so a restart used to
# wipe every finding. (Live captured flows in _session_flows are still
# in-memory; those become findings dynamically in _all_findings().)
_findings_store = JsonStore("rag_findings")
_IMPORT_KEY = "imported"
try:
    _imported_findings: list[dict] = _findings_store.get(_IMPORT_KEY) or []
except Exception:
    _imported_findings = []


def _all_findings() -> list[dict]:
    """Build findings from all captured session flows, plus imports.

    An explicitly-imported finding (pushed via the dashboard's 'Send to RAG')
    SUPERSEDES the auto-built finding for the same session — so a sent trace
    shows up exactly once, not duplicated alongside its auto-exposed copy.
    Without this, every 'Send to RAG' produced a second identical finding
    (and a duplicate row in the Burp queue) because the session is also
    surfaced automatically from _session_flows."""
    imported = list(_imported_findings)
    imported_sids = {f.get("session_id") for f in imported if f.get("session_id")}
    findings: list[dict] = []
    for session_id, buf in _session_flows.items():
        if session_id in imported_sids:
            continue
        entries = list(buf)
        if not entries:
            continue
        try:
            f = _build_finding(session_id, entries)
            findings.append(f)
        except Exception as e:
            append_log("warn", "rag_api",
                       f"finding build failed for {session_id}: {e}")
    findings.extend(imported)
    return findings


def _match(finding: dict, target: str, severity: str, source: str,
           engagement_id: str) -> bool:
    if target:
        # Match the target substring against the URL *and* the finding's
        # name/title/session_id (all case-insensitive). Every dashboard-test
        # trace shares the same login.microsoftonline.com URL, so a URL-only
        # filter can't separate e.g. ADO PAT from ROPC — but the title now
        # carries the tool ("🧪 ADO PAT · …"), so typing "ADO PAT" (or the
        # "adopat" session-id token) in the Burp Target field isolates it.
        t = target.lower()
        hay = " ".join(str(finding.get(k, "")) for k in
                       ("url", "name", "title", "session_id")).lower()
        if t not in hay:
            return False
    if severity and severity != "all":
        if finding.get("severity", "info") != severity:
            return False
    if source:
        # source may be comma-separated OR repeated ?source=
        wanted = [s.strip() for s in source.split(",") if s.strip()]
        if wanted and finding.get("source", "").lower() not in [w.lower() for w in wanted]:
            return False
    if engagement_id:
        if finding.get("engagement_id", "") != engagement_id:
            return False
    return True


@app.get("/health")
async def health():
    n = sum(len(buf) for buf in _session_flows.values())
    return {
        "ok": True,
        "status": "ok",
        "service": "bitm-proxy",
        "database": {"tables_found": 1, "flow_exchanges": n,
                     "active_sessions": len(_session_flows)},
    }


@app.get("/scope/names")
async def scope_names():
    # Treat each captured session's hostname as a scope name
    names = []
    for sid, buf in _session_flows.items():
        entries = list(buf)
        if not entries:
            continue
        host = _flow_hostname(entries)
        names.append({"name": host, "target_count": 1})
    return {"names": names}


@app.get("/scope")
async def scope(name: str = ""):
    targets = []
    for sid, buf in _session_flows.items():
        entries = list(buf)
        if not entries:
            continue
        host = _flow_hostname(entries)
        if name and host != name:
            continue
        targets.append({"target": host, "target_type": "hostname", "session_id": sid})
    return {"targets": targets}


@app.get("/engagements")
async def engagements():
    # Single default engagement representing this bitm-proxy instance
    return {"engagements": [
        {"id": "bitm-proxy", "name": "BITM Proxy sessions", "scope_name": ""},
    ]}


@app.get("/engagements/{eng_id}")
async def engagement_detail(eng_id: str):
    if eng_id != "bitm-proxy":
        return {"error": "not found"}
    return {"id": "bitm-proxy", "name": "BITM Proxy sessions", "scope_name": ""}


@app.get("/findings/search")
async def findings_search(
    request: Request,
    limit: int = Query(100),
    offset: int = Query(0),
    ip: str = Query(""),
    severity: str = Query(""),
    engagement_id: str = Query(""),
):
    # source may appear multiple times
    sources = ",".join(request.query_params.getlist("source"))
    all_f = _all_findings()
    filtered = [f for f in all_f
                if _match(f, ip, severity, sources, engagement_id)]
    by_severity = defaultdict(int)
    by_source = defaultdict(int)
    for f in filtered:
        by_severity[f.get("severity", "info")] += 1
        by_source[f.get("source", "unknown")] += 1
    return {
        "total": len(filtered),
        "findings": filtered[offset:offset + limit],
        "aggregations": {
            "by_severity": dict(by_severity),
            "by_source": dict(by_source),
        },
    }


@app.get("/export/findings-exchange")
async def export_findings_exchange(
    request: Request,
    limit: int = Query(500),
    target: str = Query(""),
    severity: str = Query(""),
    engagement_id: str = Query(""),
):
    sources = ",".join(request.query_params.getlist("source"))
    all_f = _all_findings()
    filtered = [f for f in all_f
                if _match(f, target, severity, sources, engagement_id)]
    return {"findings": filtered[:limit], "total": len(filtered)}


def import_findings(findings: list, source: str = "external") -> dict:
    """Core import logic — append findings to the in-memory store. Callable
    both from the HTTP handler below and directly in-process (rag_bridge's
    submit path short-circuits to this when the configured RAG URL is the
    built-in API, avoiding an HTTP round-trip to a server on the same event
    loop)."""
    imported = 0
    skipped = 0
    for f in findings:
        if not isinstance(f, dict):
            skipped += 1
            continue
        f.setdefault("source", source)
        f.setdefault("captured_at", time.time())
        sid = f.get("session_id")
        if sid:
            # Re-sending the same session updates in place rather than piling
            # up duplicate findings (each 'Send to RAG' otherwise appended a
            # fresh copy).
            _imported_findings[:] = [x for x in _imported_findings
                                     if x.get("session_id") != sid]
        _imported_findings.append(f)
        imported += 1
    if imported:
        try:
            _findings_store.put(_IMPORT_KEY, _imported_findings)
        except Exception as e:
            append_log("warn", "rag_api",
                       f"failed to persist imported findings: {e}")
    append_log("info", "rag_api",
               f"Imported {imported} findings from {source} ({skipped} skipped)")
    return {"imported": imported, "skipped": skipped,
            "total_stored": len(_imported_findings)}


@app.post("/import/findings-exchange")
async def import_findings_exchange(body: dict):
    return import_findings(body.get("findings", []),
                           body.get("source", "external"))


def clear_imported_findings() -> int:
    """Drop all imported/persisted findings (reset). Returns how many were
    cleared. Live captured flows in _session_flows are unaffected — they
    rebuild into findings on demand. Callable in-process (the dashboard's
    'Clear RAG data' button, which shares this event loop) and from the
    /findings/clear HTTP route."""
    n = len(_imported_findings)
    _imported_findings.clear()
    try:
        _findings_store.put(_IMPORT_KEY, [])
    except Exception:
        pass
    append_log("info", "rag_api", f"Cleared {n} imported findings")
    return n


@app.post("/findings/clear")
async def findings_clear():
    return {"cleared": clear_imported_findings()}


# ── Burp extension: Follow-Up Queue + tunnel nodes ──────────────────────────
# The Burp extension (burp-extension/RagScanBridge.py) polls /burp-queue for
# items to pull into Burp and /nodes for SOCKS tunnel routing. RAG Scan Stack
# implements these against its own infrastructure; here we surface the captured
# findings as the queue (so the operator can import a captured login flow into
# Burp as an issue) and return an empty node list (no tunnel infra in the
# built-in API). Without these the extension's Follow-Up Queue / Proxy tabs
# just 404 and log errors.

def _finding_to_queue_item(f: dict, idx: int) -> dict:
    ev = f.get("evidence")
    if isinstance(ev, list):
        ev = "\n".join(str(x) for x in ev)
    return {
        "id": f.get("session_id") or f.get("name") or f"finding-{idx}",
        "title": f.get("title") or f.get("name") or "finding",
        "severity": f.get("severity") or "info",
        "target": f.get("url") or "",
        "url": f.get("url") or "",
        "description": f.get("description") or "",
        "evidence": ev or "",
        "request_raw": f.get("request_raw") or "",
        "response_raw": f.get("response_raw") or "",
        "exchanges": f.get("exchanges") or [],
        "finding_source": f.get("source") or "bitm-proxy",
        "status": "pending",
    }


@app.get("/burp-queue")
async def burp_queue(status: str = "pending", limit: int = Query(500, ge=1, le=5000)):
    items = [_finding_to_queue_item(f, i)
             for i, f in enumerate(_all_findings()[:limit])]
    return {"items": items, "count": len(items)}


@app.post("/burp-queue/mark-imported")
async def burp_queue_mark_imported(body: dict):
    # No per-item imported-state tracking in the built-in API — accept and
    # ack so the extension's post-import call succeeds. Findings remain
    # queryable (re-importable) by design.
    ids = body.get("ids", []) or []
    return {"ok": True, "marked": len(ids)}


@app.get("/nodes")
async def nodes():
    # No tunnel-node / SOCKS-routing infrastructure in the built-in RAG API.
    return {"nodes": []}
