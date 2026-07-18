"""Optional Ollama-based assistant for analyzing captured login flows.

Sends a compact summary of the flow (timeline + redirects + cookies + token
responses) to a local Ollama instance and returns the model's analysis as
markdown. Disabled by default; enable via `ollama_enabled=true` in config.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from backend.shared import append_log, get_config_value, get_flow


async def test_connection() -> dict[str, Any]:
    """Ping the Ollama server and check that the configured model is available."""
    base_url = (get_config_value("ollama_url", "") or "").rstrip("/")
    model = get_config_value("ollama_model", "") or ""
    if not base_url:
        return {"ok": False, "error": "ollama_url not configured"}
    try:
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            resp = await client.get(f"{base_url}/api/tags")
        if resp.status_code >= 400:
            return {"ok": False,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
        data = resp.json() or {}
        models = [m.get("name", "") for m in (data.get("models") or [])]
        model_found = any(m == model or m.startswith(model + ":") for m in models)
        return {
            "ok": True,
            "url": base_url,
            "configured_model": model,
            "model_found": model_found,
            "models": models,
        }
    except httpx.ConnectError as e:
        return {"ok": False, "error": f"Connect failed: {e}. "
                "From inside Docker use host.docker.internal instead of localhost."}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _preamble_errors(entries: list[dict], session_id: str) -> str:
    """Walk the captured flow and return a markdown summary of observable
    failures, keyed by seq. The model gets this at the top of the user
    message so it anchors on real #N → reason mappings instead of
    guessing at a 400 that isn't there."""
    from backend import site_rules as _rules
    from urllib.parse import urlparse as _urlparse
    lines: list[str] = []
    for e in entries:
        status = e.get("status")
        seq = e.get("seq")
        url = e.get("url") or ""
        host = ""
        try:
            host = _urlparse(url).hostname or ""
        except Exception:
            pass
        reasons: list[str] = []
        # HTTP-level failures are the clearest signal.
        if isinstance(status, int) and 400 <= status < 600:
            reasons.append(f"HTTP {status}")
        # Structured body error per sites.yaml rules.
        body = e.get("response_body") or ""
        if body:
            stripped = body.lstrip()
            if stripped.startswith("{") or stripped.startswith("["):
                try:
                    payload = json.loads(body[:100_000])
                except Exception:
                    payload = None
                if payload is not None and host:
                    rules, codes, _idp = _rules.response_error_rules_for(host)
                    for rule in rules:
                        um = (rule.get("url_match") or "").lower()
                        if um and um not in url.lower():
                            continue
                        code = _dig(payload, rule.get("code_path", ""))
                        if not code:
                            continue
                        msg = _dig(payload, rule.get("message_path", "")) or ""
                        meaning = codes.get(str(code)) or ""
                        parts = [f"body.{rule.get('code_path','code')}={code}"]
                        if meaning:
                            parts.append(f"({meaning})")
                        if msg:
                            parts.append(f"msg={str(msg)[:120]}")
                        reasons.append(" ".join(parts))
                        break
        if reasons:
            lines.append(f"- #{seq} {host}{url[len('https://'+host):][:120]} — "
                         + " · ".join(reasons))
    if not lines:
        return (
            "KNOWN ERRORS IN THIS CAPTURE: none — no 4xx/5xx responses and "
            "no structured error codes were found. If the user-reported "
            "problem is a failure, it is either (a) expressed in a 200 "
            "response with a non-JSON error page, (b) earlier than the "
            "captured range, or (c) a client-side script failure that the "
            "proxy cannot see. Do NOT invent a 4xx status."
        )
    return (
        "KNOWN ERRORS IN THIS CAPTURE — use these as the authoritative "
        "list of failures. Every failure you cite in your analysis MUST "
        "appear here.\n"
        + "\n".join(lines)
    )


def _dig(obj: Any, path: str) -> Any:
    if not path or obj is None:
        return None
    cur: Any = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _render_entry_full(e: dict) -> str:
    """Render one exchange with ALL headers and full bodies (as captured)."""
    out = []
    status = e.get("status")
    status_str = str(status) if status is not None else "—"
    out.append(f"=== #{e.get('seq')} {e.get('method','')} {status_str} {e.get('url','')}")
    req_h = e.get("request_headers") or {}
    if req_h:
        out.append("--- request headers ---")
        for k, v in req_h.items():
            out.append(f"{k}: {v}")
    rb = e.get("request_body") or ""
    if rb:
        trunc = " (truncated)" if e.get("request_body_truncated") else ""
        out.append(f"--- request body{trunc} ---")
        out.append(rb)
    resp_h = e.get("response_headers") or {}
    if resp_h:
        out.append("--- response headers ---")
        for k, v in resp_h.items():
            out.append(f"{k}: {v}")
    body = e.get("response_body") or ""
    if body:
        trunc = " (truncated)" if e.get("response_body_truncated") else ""
        out.append(f"--- response body{trunc} ---")
        out.append(body)
    return "\n".join(out)


def _compact_entries(entries: list[dict], char_budget: int) -> tuple[str, bool]:
    """Render the FULL flow verbatim (all headers, full bodies as captured).

    If the rendered text exceeds char_budget, progressively shrink the largest
    response bodies (newest first stays intact — prefer to preserve recent
    token/cookie exchanges) so the earlier structure remains.

    Returns (text, truncated).
    """
    parts = [_render_entry_full(e) for e in entries]
    full = "\n\n".join(parts)
    if len(full) <= char_budget:
        return full, False

    # Second pass: shrink oldest large response bodies first until within budget
    budget_remaining = char_budget
    # Start from newest, keep full size; oldest get trimmed
    kept = [None] * len(entries)
    for idx in range(len(entries) - 1, -1, -1):
        e = entries[idx]
        full_part = parts[idx]
        if len(full_part) <= budget_remaining:
            kept[idx] = full_part
            budget_remaining -= len(full_part) + 2  # +2 for "\n\n"
        else:
            # Shrink the response body in this entry
            shrunk = dict(e)
            body = shrunk.get("response_body") or ""
            if body:
                # leave at least a header-sized stub
                stub = max(400, budget_remaining - 500)
                shrunk["response_body"] = body[:stub] if stub > 0 else ""
                shrunk["response_body_truncated"] = True
            rendered = _render_entry_full(shrunk)
            if len(rendered) > budget_remaining:
                rendered = rendered[:max(200, budget_remaining)] + "\n... [truncated]"
            kept[idx] = rendered
            budget_remaining = 0
            # all earlier entries get elided
            for j in range(idx - 1, -1, -1):
                e_old = entries[j]
                kept[j] = f"=== #{e_old.get('seq')} {e_old.get('method','')} {e_old.get('status','')} {(e_old.get('url') or '')[:200]}\n[elided for budget]"
            break

    return "\n\n".join(p for p in kept if p), True


# Protocol-specific system prompts. Selected via the `preset` parameter.
# Each is calibrated for a different analyst task:
#   general      — the original broad security review (default when preset is
#                   "general" or unset)
#   sso          — recognise which flow this is (OIDC / SAML / WS-Fed /
#                   header-only) and map its stages
#   saml         — deep SAML focus: RelayState, SAMLRequest, SAMLResponse,
#                   assertion fields, signature hints
#   oidc         — OIDC/OAuth2 focus: authorize → code → token, PKCE,
#                   id_token claims, nonce, state, refresh
#   troubleshoot — given a failing trace, enumerate specific hypotheses
#                   and the exact evidence supporting each
#
# Analysts can still override any of these via config keys
# `ollama_system_prompt_<preset>`. Everything falls back to ollama_system_prompt
# when the per-preset key is empty.
# Shared header that every preset inherits. Defines the input format the
# user message uses and forbids hedging language — the model must ground
# each claim in a specific seq or explicitly say it's not observable.
_COMMON_HEADER = (
    "You analyze captured HTTP exchanges. The user message contains one or\n"
    "more exchanges in this exact format:\n"
    "\n"
    "    === #<seq> <METHOD> <STATUS> <URL>\n"
    "    --- request headers ---\n"
    "    <name>: <value>\n"
    "    --- request body ---\n"
    "    <body text, possibly truncated>\n"
    "    --- response headers ---\n"
    "    <name>: <value>\n"
    "    --- response body ---\n"
    "    <body text, possibly truncated>\n"
    "\n"
    "HARD RULES — violations invalidate the response:\n"
    "1. Cite EVERY factual claim with the seq number in the form #N. If you\n"
    "   cannot point at a specific seq, say exactly 'not observable from\n"
    "   capture' and move on.\n"
    "2. Forbidden words: 'likely', 'presumably', 'probably', 'appears to',\n"
    "   'implied', 'suggests', 'seems'. Replace each with either a\n"
    "   cited #N observation or 'not observable from capture'.\n"
    "3. Quote status codes and header values verbatim from the capture.\n"
    "   Do not invent HTTP status codes — if the '===' line says '200',\n"
    "   it is 200, not '4xx'.\n"
    "4. When the response body contains JSON, cite the specific field path\n"
    "   (e.g. #47 Result.ErrorCode='IDAPP_00008').\n"
    "5. Produce ONLY the section headers listed below, in that order. Do\n"
    "   not add a 'Summary', 'Overview', 'Recommended Next Steps', or any\n"
    "   other section unless the schema below explicitly asks for it.\n"
    "6. Output is markdown. Bold section headers with **...**. No numbered\n"
    "   preamble before the first section.\n"
    "\n"
)

_PRESET_PROMPTS = {
    "sso": _COMMON_HEADER + (
        "Schema:\n"
        "**Protocol** — one of OIDC / OAuth2 / SAML / WS-Fed / header-only /\n"
        "unclear, cited by the seq that identifies it (e.g. #3 authorize\n"
        "endpoint under /oauth2/v2.0/authorize).\n"
        "**Roles** — RP / IdP / token endpoint, one line each with the\n"
        "hostname and the representative seq.\n"
        "**Stages** — numbered list; each stage names one action, the\n"
        "seq(s) implementing it, and the HTTP status.\n"
        "**Identity assertion** — where created (seq), where consumed\n"
        "(seq), format observable (id_token / SAMLResponse / header).\n"
        "**Session binding** — each cookie or token set, with the seq that\n"
        "set it (Set-Cookie ≠ cookie used; cite both if both observed).\n"
        "**Anomalies** — one bullet per anomaly, each with a cited seq.\n"
        "If none, write 'None observable from capture'.\n"
    ),
    "saml": _COMMON_HEADER + (
        "Schema (SAML-specific):\n"
        "**Binding** — HTTP-Redirect / HTTP-POST, cite the seq carrying\n"
        "the SAMLRequest or SAMLResponse.\n"
        "**SAMLRequest** — seq, whether compressed/deflated, observable\n"
        "Issuer if present.\n"
        "**SAMLResponse** — seq, the <samlp:StatusCode> value verbatim.\n"
        "**Assertion fields** — Issuer / Audience / NotBefore /\n"
        "NotOnOrAfter / NameID / AuthnContext / <saml:Attribute>s. For\n"
        "each: either the literal value with a #N citation, or 'not\n"
        "observable from capture'.\n"
        "**RelayState** — presence + whether stable across the flow,\n"
        "cited.\n"
        "**Signature** — <ds:Signature> present in response assertion:\n"
        "yes #N / no #N / not observable from capture.\n"
        "**Anomalies** — missing audience restriction, expired\n"
        "NotOnOrAfter, drifting RelayState. Each bullet cited.\n"
    ),
    "oidc": _COMMON_HEADER + (
        "Schema (OIDC / OAuth2-specific):\n"
        "**Grant type** — authorization code / hybrid / implicit / device /\n"
        "client-credentials / not observable — with the seq whose\n"
        "response_type or grant_type parameter identifies it.\n"
        "**Authorize** — seq, client_id, redirect_uri, scope, state,\n"
        "nonce, code_challenge. Each value quoted verbatim; absent =\n"
        "'not observable from capture'.\n"
        "**Callback** — seq that returned the code/id_token. Fragment\n"
        "or query. State echoed: yes/no with both values cited.\n"
        "**Token exchange** — seq that POSTed to /token. grant_type,\n"
        "code_verifier presence (PKCE). id_token length if returned.\n"
        "**id_token claims observable** — iss / aud / sub / exp /\n"
        "nonce. Bullet each with the cited seq, no invention.\n"
        "**Refresh** — refresh_token returned: yes #N / no.\n"
        "**Session binding** — cookies set / storage artefacts,\n"
        "cited.\n"
        "**Anomalies** — missing PKCE on public client, implicit grant\n"
        "used, state mismatch, nonce absent, scope widening.\n"
    ),
    "troubleshoot": _COMMON_HEADER + (
        "This capture represents a FAILED flow. Diagnose it.\n"
        "\n"
        "Schema:\n"
        "**Outcome** — one sentence, naming the breaking seq and what it\n"
        "returned (status code + response-body error field if any). No\n"
        "hedging.\n"
        "**Last-good seq** — #N with the successful response status.\n"
        "**Breaking seq** — #N, status, URL path.\n"
        "**Evidence** — bullet each of: HTTP status, response-body error\n"
        "(specifically AADSTS*** / CyberArk Result.ErrorCode / Okta\n"
        "errorCode / OAuth error field — quote verbatim), missing cookie\n"
        "between seq A and seq B, missing header, state/nonce drift,\n"
        "redirect URL mismatch. Every bullet has a #N.\n"
        "**Hypotheses** — ordered list, most likely first. Each hypothesis\n"
        "has (a) a 1-sentence claim, (b) the specific observation supporting\n"
        "it cited by seq, (c) one observation that would rule it in or out.\n"
        "**Next check** — one concrete action the operator should take.\n"
    ),
}


def _resolve_system_prompt(preset: str) -> str:
    """Resolve the system prompt: per-preset config key → built-in default
    → legacy ollama_system_prompt → empty string."""
    preset = (preset or "general").lower()
    k = f"ollama_system_prompt_{preset}"
    override = get_config_value(k, "") or ""
    if override:
        return override
    if preset != "general" and preset in _PRESET_PROMPTS:
        return _PRESET_PROMPTS[preset]
    return get_config_value("ollama_system_prompt", "") or ""


async def analyze_flow(
    session_id: str,
    start_seq: int | None = None,
    end_seq: int | None = None,
    seqs: list[int] | None = None,
    preset: str = "general",
    on_chunk=None,
) -> dict[str, Any]:
    """Analyze a flow via Ollama. When `on_chunk` (an async callable) is
    given, generation is streamed and `on_chunk(delta_text)` is awaited for
    each batched delta so the caller can push it to the UI live; the full
    text is still returned in the result dict either way."""
    if not get_config_value("ollama_enabled", False):
        return {"ok": False, "error": "ollama_enabled is false; enable it in config"}
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

    base_url = (get_config_value("ollama_url", "") or "").rstrip("/")
    model = get_config_value("ollama_model", "llama3.1:8b") or "llama3.1:8b"
    system_prompt = _resolve_system_prompt(preset)
    temperature = float(get_config_value("ollama_temperature", 0.1))
    top_p = float(get_config_value("ollama_top_p", 0.3))
    top_k = int(get_config_value("ollama_top_k", 20))
    num_ctx = int(get_config_value("ollama_num_ctx", 8192))
    num_predict = int(get_config_value("ollama_num_predict", 512))
    keep_alive = str(get_config_value("ollama_keep_alive", "30m") or "30m")
    think = bool(get_config_value("ollama_think", False))
    seed = int(get_config_value("ollama_seed", 0))
    if not base_url:
        return {"ok": False, "error": "ollama_url not configured"}

    # Pre-scan the entries for observable failures so the model has a
    # curated #N → failure-reason list at the top of the user message. Stops
    # the model from hedging about whether a failure happened.
    error_lines = _preamble_errors(entries, session_id)

    # Budget: ~3.2 chars per token; reserve ~25% of context for prompt + response.
    char_budget = max(8000, int(num_ctx * 3.2 * 0.75))
    compact, truncated = _compact_entries(entries, char_budget)
    if error_lines:
        compact = error_lines + "\n\n" + compact
    append_log("info", "ollama",
               f"Analyzing flow session={session_id} preset={preset} "
               f"entries={len(entries)} bytes={len(compact)} "
               f"budget={char_budget} truncated={truncated} "
               f"model={model} temp={temperature} num_ctx={num_ctx}",
               session_id=session_id)

    options = {
        "temperature": temperature,
        "top_p": top_p,
        "top_k": top_k,
        "num_ctx": num_ctx,
    }
    if num_predict > 0:
        options["num_predict"] = num_predict
    if seed != 0:
        options["seed"] = seed

    # Stream so the UI shows tokens as they generate instead of blocking on
    # the full completion (the dominant "feels like a hang" factor). Deltas
    # are batched (~100ms / ~80 chars) so we don't flood the WebSocket or
    # thrash the frontend re-render on every token.
    payload = {
        "model": model,
        "stream": True,
        "keep_alive": keep_alive,
        # think=False makes reasoning models answer directly instead of
        # spending the num_predict budget on hidden chain-of-thought (which
        # can otherwise return empty content). Dropped on retry if the model
        # rejects the param.
        "think": think,
        "options": options,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": compact},
        ],
    }

    content = ""
    try:
        pending = ""
        last_flush = time.monotonic()

        async def _flush(force=False):
            nonlocal pending, last_flush
            if not on_chunk or not pending:
                return
            if force or len(pending) >= 80 or (time.monotonic() - last_flush) >= 0.10:
                try:
                    await on_chunk(pending)
                except Exception:
                    pass
                pending = ""
                last_flush = time.monotonic()

        async with httpx.AsyncClient(timeout=180, verify=False) as client:
            for attempt in (1, 2):
                content = ""
                pending = ""
                async with client.stream("POST", f"{base_url}/api/chat",
                                         json=payload) as resp:
                    if resp.status_code >= 400:
                        body = (await resp.aread())[:300].decode("utf-8", "replace")
                        # Some models don't accept the `think` param — retry once
                        # without it rather than failing the analysis.
                        if (attempt == 1 and "think" in payload
                                and "think" in body.lower()):
                            payload.pop("think", None)
                            continue
                        return {"ok": False,
                                "error": f"ollama HTTP {resp.status_code}: {body}"}
                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except Exception:
                            continue
                        delta = (obj.get("message") or {}).get("content") \
                            or obj.get("response") or ""
                        if delta:
                            content += delta
                            pending += delta
                            await _flush()
                        if obj.get("done"):
                            break
                break  # streamed successfully
        await _flush(force=True)
        append_log("info", "ollama",
                   f"Analysis complete ({len(content)} chars)",
                   session_id=session_id)
        return {"ok": True, "analysis": content, "model": model,
                "preset": preset,
                "entry_count": len(entries),
                "prompt_bytes": len(compact),
                "truncated": truncated}
    except Exception as e:
        append_log("warn", "ollama", f"Analysis failed: {e}", session_id=session_id)
        return {"ok": False, "error": str(e), "analysis": content}
