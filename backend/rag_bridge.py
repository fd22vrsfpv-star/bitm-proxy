"""RAG Scan Stack bridge — submit captured login flows as findings.

Posts a single informational finding per flow to the RAG API
(`POST /import/findings-exchange`), mirroring the schema the burp-extension
bridge (`burp-extension/RagScanBridge.py`) expects.

The finding is named `trace_flow_for_{site_id_or_hostname}` and embeds the full
sequence of request/response pairs as evidence, plus a summary of key elements
(redirect chain, auth endpoints, tokens, cookies).
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.shared import append_log, get_config_value, get_flow


def _flow_hostname(entries: list[dict]) -> str:
    for e in entries:
        url = e.get("url") or ""
        try:
            h = urlparse(url).hostname
            if h:
                return h
        except Exception:
            continue
    return "unknown"


def _summarize_entry(e: dict) -> str:
    method = e.get("method", "")
    url = (e.get("url") or "")[:200]
    status = e.get("status")
    dur = ""
    if e.get("ts_req") and e.get("ts_resp"):
        dur = f" {int((e['ts_resp'] - e['ts_req']) * 1000)}ms"
    status_str = str(status) if status is not None else "—"
    return f"#{e.get('seq')} {method} {status_str}{dur}  {url}"


def _raw_exchange(e: dict) -> tuple[str, str]:
    """Render request/response as raw HTTP-ish text blobs."""
    url = e.get("url") or ""
    method = e.get("method", "GET")
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
    except Exception:
        host, path = "unknown", "/"

    req_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for k, v in (e.get("request_headers") or {}).items():
        if k.lower() in ("host",):
            continue
        req_lines.append(f"{k}: {v}")
    req_body = e.get("request_body") or ""
    req_raw = "\r\n".join(req_lines) + "\r\n\r\n" + req_body

    status = e.get("status")
    resp_lines = [f"HTTP/1.1 {status if status is not None else 0}"]
    for k, v in (e.get("response_headers") or {}).items():
        resp_lines.append(f"{k}: {v}")
    resp_body = e.get("response_body") or ""
    resp_raw = "\r\n".join(resp_lines) + "\r\n\r\n" + resp_body
    return req_raw, resp_raw


def _key_elements(entries: list[dict]) -> dict[str, Any]:
    redirects = []
    set_cookies = []
    auth_headers = []
    tokens_seen = []
    for e in entries:
        status = e.get("status") or 0
        if 300 <= status < 400:
            loc = (e.get("response_headers") or {}).get("location") or \
                  (e.get("response_headers") or {}).get("Location")
            redirects.append({"seq": e.get("seq"), "from": e.get("url"), "to": loc})
        for k, v in (e.get("response_headers") or {}).items():
            kl = k.lower()
            if kl == "set-cookie":
                name = v.split("=", 1)[0] if "=" in v else v
                set_cookies.append({"seq": e.get("seq"), "cookie": name, "url": e.get("url")})
        for k in (e.get("request_headers") or {}):
            kl = k.lower()
            if kl in ("authorization", "x-csrf-token", "x-xsrf-token", "x-ms-token"):
                auth_headers.append({"seq": e.get("seq"), "header": k, "url": e.get("url")})
        body = e.get("response_body") or ""
        for marker in ("access_token", "id_token", "refresh_token", "session_state", "\"code\":"):
            if marker in body:
                tokens_seen.append({"seq": e.get("seq"), "kind": marker.strip('":'),
                                    "url": e.get("url")})
                break
    return {
        "redirects": redirects,
        "set_cookies": set_cookies,
        "auth_headers": auth_headers,
        "token_responses": tokens_seen,
    }


def _build_finding(session_id: str, entries: list[dict]) -> dict[str, Any]:
    host = _flow_hostname(entries)
    first = entries[0] if entries else {}
    summary_lines = [_summarize_entry(e) for e in entries]
    key = _key_elements(entries)

    description_parts = [
        f"Captured login flow for {host} (session {session_id}).",
        f"Total exchanges: {len(entries)}",
        f"Redirects: {len(key['redirects'])}",
        f"Set-Cookie responses: {len(key['set_cookies'])}",
        f"Auth headers sent: {len(key['auth_headers'])}",
        f"Token-bearing responses: {len(key['token_responses'])}",
    ]

    evidence_parts = ["=== Flow Timeline ===", *summary_lines]
    if key["redirects"]:
        evidence_parts.append("\n=== Redirects ===")
        for r in key["redirects"]:
            evidence_parts.append(f"#{r['seq']}  {r['from']}  ->  {r['to']}")
    if key["set_cookies"]:
        evidence_parts.append("\n=== Set-Cookie ===")
        for c in key["set_cookies"]:
            evidence_parts.append(f"#{c['seq']}  {c['cookie']}  from {c['url']}")
    if key["token_responses"]:
        evidence_parts.append("\n=== Token-bearing responses ===")
        for t in key["token_responses"]:
            evidence_parts.append(f"#{t['seq']}  {t['kind']}  from {t['url']}")

    evidence_parts.append("\n=== Full exchange detail (JSON) ===")
    try:
        evidence_parts.append(json.dumps(entries, default=str, indent=2)[:200_000])
    except Exception:
        pass

    # Use first entry as the request/response pair for Burp's message view
    req_raw, resp_raw = ("", "")
    if entries:
        req_raw, resp_raw = _raw_exchange(entries[0])

    return {
        "name": f"trace_flow_for_{host}",
        "title": f"trace_flow_for_{host}",
        "url": first.get("url") or f"https://{host}/",
        "severity": "info",
        "confidence": "firm",
        "source": "mitm-proxy",
        "evidence": ["\n".join(evidence_parts)],
        "description": " ".join(description_parts),
        "request_raw": req_raw,
        "response_raw": resp_raw,
        "captured_at": time.time(),
        "session_id": session_id,
        "metadata": {
            "exchange_count": len(entries),
            "key_elements": key,
        },
    }


async def submit_flow_as_finding(
    session_id: str,
    start_seq: int | None = None,
    end_seq: int | None = None,
    seqs: list[int] | None = None,
) -> dict[str, Any]:
    if not get_config_value("rag_enabled", False):
        return {"ok": False, "error": "rag_enabled is false; enable it in config"}
    entries = get_flow(session_id)
    if seqs:
        wanted = set(int(s) for s in seqs)
        entries = [e for e in entries if e.get("seq", -1) in wanted]
    else:
        if start_seq is not None:
            entries = [e for e in entries if e.get("seq", -1) >= start_seq]
        if end_seq is not None:
            entries = [e for e in entries if e.get("seq", -1) <= end_seq]
    if not entries:
        return {"ok": False, "error": f"no flow entries for session {session_id} in marker range"}

    url = (get_config_value("rag_api_url", "") or "").rstrip("/")
    key = get_config_value("rag_api_key", "") or ""
    engagement_id = get_config_value("rag_engagement_id", "") or ""
    if not url:
        return {"ok": False, "error": "rag_api_url not configured"}

    # Guard: the built-in RAG API on :8000 runs HTTP only. Auto-correct a common
    # misconfig where users leave the legacy https://localhost:8000 default.
    low = url.lower()
    if low.startswith("https://") and any(h in low for h in
        ("localhost:8000", "127.0.0.1:8000", "host.docker.internal:8000")):
        url = "http://" + url[len("https://"):]
        append_log("warn", "rag_bridge",
                   f"Switched rag_api_url scheme to http:// (built-in RAG API on :8000 is plain HTTP). "
                   f"Update Settings → Flow / RAG / Ollama to silence this.",
                   session_id=session_id)

    finding = _build_finding(session_id, entries)
    if engagement_id:
        finding["engagement_id"] = engagement_id

    payload = {"source": "mitm-proxy", "findings": [finding]}
    endpoint = f"{url}/import/findings-exchange"

    append_log("info", "rag_bridge",
               f"Submitting trace_flow_for_{_flow_hostname(entries)} ({len(entries)} exchanges) to {endpoint}",
               session_id=session_id)
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            resp = await client.post(
                endpoint,
                headers={"x-api-key": key, "Content-Type": "application/json"},
                json=payload,
            )
        ok = 200 <= resp.status_code < 300
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:500]}
        append_log("info" if ok else "warn", "rag_bridge",
                   f"RAG response {resp.status_code}: {str(data)[:200]}",
                   session_id=session_id)
        return {
            "ok": ok,
            "status": resp.status_code,
            "response": data,
            "finding_name": finding["name"],
        }
    except Exception as e:
        append_log("warn", "rag_bridge", f"RAG submit failed: {e}", session_id=session_id)
        return {"ok": False, "error": str(e)}
