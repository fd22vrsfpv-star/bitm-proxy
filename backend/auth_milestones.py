"""Auth-flow milestone classifier for flow-trace entries.

Tags each flow row with one or more `auth_milestone` labels so the UI
can banner the key steps of a typical OAuth/OIDC login:

    LOGIN  → flowToken / username / password / MFA / KMSI exchanges
    CODE   → the IdP's redirect-back to the RP carrying ?code=…
    TOKENS → POST /token returning access_token / id_token / refresh_token
    REFRESH→ POST /token with grant_type=refresh_token (token rotation)
    PRT    → primary refresh token issuance / x-ms-PRT cookie set
    SESSION→ Set-Cookie of an IdP/RP session cookie (browser persistence)

All recognition rules live in `config/sites.yaml` under
`auth_milestones:` and are deep-merged with `$DATA_DIR/sites.yaml`
(see `backend/site_rules.py`). Regexes are compiled once per
hot-reload and cached, not per-call. Adding a custom on-prem IdP or a
SaaS-specific session-cookie prefix is a YAML edit, not a code change.

Detection is intentionally conservative — false positives flag random
transactions and dilute the banner. Multiple milestones per entry are
allowed (a single token-exchange response can be both TOKENS and PRT).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from backend import site_rules as _sr


def _host_matches(host: str) -> bool:
    """True when `host` equals or is a `.suffix` of any configured
    idp_hosts entry."""
    h = (host or "").lower()
    if not h:
        return False
    for s in _sr.auth_milestones_config()["idp_hosts"]:
        if h == s or h.endswith("." + s):
            return True
    return False


def _normalize_cookie_name(raw: str) -> str:
    if not raw:
        return ""
    return (raw.strip().split("=", 1)[0] if "=" in raw else raw).strip().lower()


def _iter_set_cookie_values(headers: dict | None) -> list[str]:
    """Set-Cookie often arrives as a single header with newline-joined
    values when the proxy collapses multiple ones, or as a single
    comma-joined string. Split conservatively."""
    if not headers:
        return []
    out: list[str] = []
    for k, v in headers.items():
        if k.lower() != "set-cookie":
            continue
        if isinstance(v, list):
            out.extend(v)
        else:
            for piece in str(v).split("\n"):
                p = piece.strip()
                if p:
                    out.append(p)
    return out


def _try_json(body: str | None) -> Any:
    if not body:
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def _try_form(body: str | None) -> dict[str, list[str]]:
    if not body:
        return {}
    try:
        return parse_qs(body, keep_blank_values=True)
    except Exception:
        return {}


def parse_ca_blocked_details(url: str) -> dict[str, str]:
    """Pull configured query/fragment params out of a Conditional-Access
    block URL into a labeled dict.

    Returns {} when the URL doesn't match any pattern in
    `globals.ca_blocked.url_match_patterns`. Param-name comparison is
    case-insensitive — the dict's keys are the canonical spellings from
    `param_keys` so the rendered output stays stable across AAD's
    casing drift (`Reason` vs `reason`).

    Shared between the live-page classifier (`routes/browser.py:_classify_challenge`)
    and the flow-row classifier (`auth_milestones.classify`) so both
    surfaces show the same parsed fields."""
    cfg = _sr.ca_blocked_config()
    patterns = cfg["url_match_patterns"]
    if not patterns or not url:
        return {}
    url_low = url.lower()
    if not any(p in url_low for p in patterns):
        return {}
    try:
        parsed = urlparse(url)
    except Exception:
        return {}
    by_lower: dict[str, str] = {}
    for source in (parsed.query, parsed.fragment):
        if not source:
            continue
        try:
            for k, vs in parse_qs(source, keep_blank_values=True).items():
                if not vs or not vs[0]:
                    continue
                by_lower.setdefault(k.lower(), vs[0])
        except Exception:
            continue
    out: dict[str, str] = {}
    for canonical in cfg["param_keys"]:
        v = by_lower.get(canonical.lower())
        if v:
            out[canonical] = v[:300]
    return out


def classify(entry: dict) -> list[dict]:
    """Return a list of milestone tags for an entry. Each tag is a dict
    `{kind, label, detail}`; an empty list means no milestone matched."""
    cfg = _sr.auth_milestones_config()
    out: list[dict] = []

    url = entry.get("url") or ""
    method = (entry.get("method") or "").upper()
    req_headers = entry.get("request_headers") or {}
    resp_headers = entry.get("response_headers") or {}
    req_body = entry.get("request_body") or ""
    resp_body = entry.get("response_body") or ""

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"

    # ── LOGIN ──────────────────────────────────────────────
    is_idp = _host_matches(host)
    not_login_re = cfg["not_login_path_re"]
    is_token_like = bool(not_login_re and not_login_re.search(path))
    login_re = cfg["login_path_re"]
    body_markers = cfg["login_body_markers"]
    if is_idp and login_re and login_re.search(path) and not is_token_like:
        out.append({"kind": "login", "label": "LOGIN",
                    "detail": f"{host}{path}"})
    elif req_body and not is_token_like and any(
            m in req_body for m in body_markers):
        out.append({"kind": "login", "label": "LOGIN",
                    "detail": "auth body marker"})
    elif resp_body and not is_token_like and any(
            m in resp_body for m in body_markers):
        out.append({"kind": "login", "label": "LOGIN",
                    "detail": "auth body marker (response)"})

    # ── CODE ──────────────────────────────────────────────
    location = ""
    for k, v in resp_headers.items():
        if k.lower() == "location":
            location = str(v or "")
            break
    if location and re.search(r"[?&#]code=[^&#]+", location):
        out.append({"kind": "code", "label": "AUTH CODE",
                    "detail": _redact_code(location)})
    elif method == "GET" and re.search(r"[?&]code=[^&]+", url) \
            and re.search(r"[?&](state|session_state|client_info)=", url):
        out.append({"kind": "code", "label": "AUTH CODE",
                    "detail": _redact_code(url)})

    # ── TOKENS / REFRESH / PRT (token endpoint) ──────────
    # Keyed on grant_type from the request body, not just the response —
    # response bodies aren't always captured (streaming, JWE wrapping,
    # body-type filter), and the grant_type is sufficient evidence on
    # its own that this is a token exchange of that flavour. Path
    # match is also softened by a body-shape fallback below: if the
    # response body has access_token / id_token, tag TOKENS even if
    # the URL didn't match (catches custom-IdP token endpoints).
    token_re = cfg["token_path_re"]
    status = entry.get("status")
    is_token_call = method == "POST" and token_re and token_re.search(path)
    # Body-shape fallback: any 2xx POST whose body contains a token
    # field anywhere — top-level, nested under a wrapper, or even
    # inside a JSON string. This catches non-canonical token endpoints
    # where the response is wrapped (`{"data": {"access_token": …}}`,
    # `{"result": "ok", "auth": {…}}`, JSONL, etc.). Conservative —
    # only fires when method is POST AND status is 2xx, so a generic
    # JSON GET that happens to return user.access_token doesn't
    # false-positive.
    success = status is None or (
        isinstance(status, int) and 200 <= status < 300)
    body_has_token_field = False
    if not is_token_call and method == "POST" and success and resp_body:
        # Quick string-level probe first — cheaper than JSON parse and
        # forgiving to whatever shape the body is in.
        if re.search(
            r'"(access_token|id_token|refresh_token)"\s*:',
            resp_body,
        ):
            body_has_token_field = True
        else:
            # Walk a parsed JSON tree for nested matches that the
            # string regex might not catch (e.g. when keys are emitted
            # without quotes by an exotic encoder).
            body_obj_probe = _try_json(resp_body)
            if isinstance(body_obj_probe, (dict, list)):
                stack = [body_obj_probe]
                while stack and not body_has_token_field:
                    cur = stack.pop()
                    if isinstance(cur, dict):
                        for k, v in cur.items():
                            if (isinstance(k, str) and k.lower() in (
                                    "access_token", "id_token",
                                    "refresh_token") and v):
                                body_has_token_field = True
                                break
                            if isinstance(v, (dict, list)):
                                stack.append(v)
                    elif isinstance(cur, list):
                        stack.extend(
                            x for x in cur if isinstance(x, (dict, list)))
        if body_has_token_field:
            is_token_call = True
    if is_token_call:
        form = _try_form(req_body)
        grant = (form.get("grant_type") or [""])[0].lower()
        scope = (form.get("scope") or [""])[0].lower()
        body_obj = _try_json(resp_body)
        issued: list[str] = []
        if isinstance(body_obj, dict):
            for k in ("access_token", "id_token", "refresh_token"):
                if body_obj.get(k):
                    issued.append(k)
        is_prt = grant in cfg["prt_grant_types"] or any(
            s in cfg["prt_scopes"] for s in scope.split())
        if isinstance(body_obj, dict):
            if str(body_obj.get("token_type", "")).lower() in cfg["prt_token_types"]:
                is_prt = True
            if body_obj.get("session_key_jwe") or body_obj.get(
                    "session_key"):
                is_prt = True
        # `success` was computed above and reused here; a 4xx is a
        # token failure, not an issuance.
        if is_prt and success:
            out.append({"kind": "prt", "label": "PRT",
                        "detail": f"grant={grant or '?'}"})
        elif grant == "refresh_token" and success:
            out.append({"kind": "refresh", "label": "REFRESH",
                        "detail": ", ".join(issued) or "tokens"})
        elif success and (issued or grant in (
                "authorization_code", "client_credentials",
                "device_code", "urn:ietf:params:oauth:grant-type:device_code",
                "password", "implicit", "")):
            out.append({"kind": "tokens", "label": "TOKENS",
                        "detail": ", ".join(issued) or f"grant={grant or '?'}"})

    # ── SESSION cookies ───────────────────────────────────
    cookie_names: list[str] = []
    session_names = cfg["session_cookie_names"]
    session_prefixes = cfg["session_cookie_prefixes"]
    prt_prefixes = cfg["prt_cookie_prefixes"]
    for sc in _iter_set_cookie_values(resp_headers):
        n = _normalize_cookie_name(sc)
        if not n:
            continue
        if n in session_names or any(n.startswith(p) for p in session_prefixes):
            cookie_names.append(n)
    if cookie_names:
        prt_cookies = [n for n in cookie_names
                       if any(n.startswith(p) for p in prt_prefixes)]
        session_cookies = [n for n in cookie_names if n not in prt_cookies]
        if prt_cookies and not any(t["kind"] == "prt" for t in out):
            out.append({"kind": "prt", "label": "PRT",
                        "detail": "Set-Cookie: " + ",".join(prt_cookies[:3])})
        if session_cookies:
            out.append({"kind": "session", "label": "SESSION",
                        "detail": "Set-Cookie: "
                                  + ",".join(session_cookies[:5])})

    # ── CA milestones (ca_blocked / ca_reprocess) ────────
    # Flow-row level CA detection — covers the cases where
    # `routes/browser.py:_classify_challenge` can't see the URL because
    # it happens in an iframe or redirect chain that never changes
    # `page.url`. Three signal sources, in order:
    #   (1) URL substring match against `blocked_url_patterns` /
    #       `reprocess_url_patterns` from `globals.ca_milestones`.
    #   (2) `Location:` response header substring match against the
    #       same patterns (catches the 302 step that sets up the
    #       redirect, before the next REQ row exists).
    #   (3) AADSTS code regex match against the response body, the
    #       URL, and the Location header. Codes are configured in
    #       `globals.ca_milestones.aadsts_codes`; the human meaning is
    #       pulled from the per-host `error_codes` map at scan time
    #       so YAML edits apply without restart.
    ca_cfg = _sr.ca_milestones_config()
    ca_kind: str | None = None
    ca_detail: str = ""
    url_low = url.lower() if url else ""

    if any(p in url_low for p in ca_cfg["blocked_url_patterns"]):
        ca_kind = "ca_blocked"
        details = parse_ca_blocked_details(url)
        if details:
            ca_detail = " · ".join(f"{k}={v}" for k, v in details.items())
        else:
            ca_detail = "user-facing block redirect"
    elif any(p in url_low for p in ca_cfg["reprocess_url_patterns"]):
        ca_kind = "ca_reprocess"
        ca_detail = "claim challenge"

    if ca_kind is None:
        location_lower = location.lower() if location else ""
        if location_lower:
            if any(p in location_lower for p in ca_cfg["blocked_url_patterns"]):
                ca_kind = "ca_blocked"
                ca_detail = "Location → CA block"
            elif any(p in location_lower
                     for p in ca_cfg["reprocess_url_patterns"]):
                ca_kind = "ca_reprocess"
                ca_detail = "Location → reprocess"

    if ca_kind is None and ca_cfg["aadsts_re"] is not None:
        for source in (resp_body, url, location):
            if not source:
                continue
            m = ca_cfg["aadsts_re"].search(source)
            if m:
                code = m.group(0).upper()
                meaning = _sr.all_error_codes().get(code, "")
                ca_kind = "ca_blocked"
                ca_detail = (f"{code} ({meaning})" if meaning else code)
                break

    if ca_kind is not None:
        out.append({
            "kind": ca_kind,
            "label": "CA-BLOCKED" if ca_kind == "ca_blocked" else "CA-REPROCESS",
            "detail": ca_detail,
        })

    # ── RP-REJECT (relying-party-side post-auth rejection) ─
    # Tags 4xx/5xx responses on relying-party callback URLs that aren't
    # on an IdP host — the shape where AAD vouched but the RP itself
    # rejected the principal (often a CA-claim-not-satisfied symptom).
    # Scoped to RP callbacks so generic 4xx noise doesn't pollute the
    # banner stream.
    rp_cfg = _sr.rp_callback_config()
    if (rp_cfg["url_patterns"]
            and isinstance(status, int)
            and 400 <= status < 600
            and not is_idp
            and url_low):
        if any(p in url_low for p in rp_cfg["url_patterns"]):
            out.append({
                "kind": "rp_reject",
                "label": "RP-REJECT",
                "detail": f"HTTP {status} from {host}{path}",
            })

    # ── MDM (Intune) milestones ──────────────────────────
    # Visibility-only: tag MDM enrollment + check-in traffic so the
    # operator can see the [MS-MDE2] / [MS-MDM] flow alongside auth
    # signals. Compliance verdict (`isCompliant`) is server-side and
    # propagates into AAD device records out-of-band — we do not
    # extract it from the SyncML body, see notes in sites.yaml. Host
    # filter narrows path matches to the Intune service domains.
    mdm_cfg = _sr.mdm_milestones_config()
    if mdm_cfg["hosts"] and url_low:
        host_in_mdm_scope = False
        for h in mdm_cfg["hosts"]:
            hh = h.lower()
            if hh.startswith("*."):
                tail = hh[2:]
                if host == tail or host.endswith("." + tail):
                    host_in_mdm_scope = True
                    break
            elif hh == host or host.endswith("." + hh) or hh in host:
                host_in_mdm_scope = True
                break
        if host_in_mdm_scope:
            path_low = path.lower()
            mdm_kind: str | None = None
            mdm_label = ""
            if any(p in path_low for p in mdm_cfg["discover_url_patterns"]):
                mdm_kind, mdm_label = "mdm_discover", "MDM-DISCOVER"
            elif any(p in path_low for p in mdm_cfg["enroll_url_patterns"]):
                mdm_kind, mdm_label = "mdm_enroll", "MDM-ENROLL"
            elif any(p in path_low for p in mdm_cfg["checkin_url_patterns"]):
                mdm_kind, mdm_label = "mdm_checkin", "MDM-CHECKIN"
            if mdm_kind:
                out.append({
                    "kind": mdm_kind,
                    "label": mdm_label,
                    "detail": f"{host}{path}",
                })

    # ── BEARER (token in use) ────────────────────────────
    # Distinct from TOKENS: TOKENS marks issuance, BEARER marks any
    # request that carries an Authorization: Bearer JWT — so the
    # operator can spot authenticated requests even when the issuance
    # happened off-flow (cached cookies, hydrated session, etc.).
    # Token value is masked in `detail` so the banner doesn't leak it.
    bearer_token = ""
    for k, v in req_headers.items():
        if k.lower() != "authorization":
            continue
        sv = str(v or "")
        m = re.match(r"^Bearer\s+([A-Za-z0-9_\-\.]+)", sv, re.IGNORECASE)
        if m:
            bearer_token = m.group(1)
            break
    if bearer_token:
        masked = (bearer_token[:12] + "…" + bearer_token[-6:]
                   if len(bearer_token) > 24 else bearer_token[:6] + "…")
        # Try to read aud/scp from the JWT payload for an at-a-glance
        # detail line. base64url decode + json parse, no signature.
        aud_scp = ""
        try:
            parts = bearer_token.split(".")
            if len(parts) >= 2 and re.fullmatch(r"[A-Za-z0-9_\-]+",
                                                  parts[1]):
                import base64
                pad = "=" * (-len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(
                    parts[1] + pad).decode("utf-8", errors="replace"))
                aud = payload.get("aud") or ""
                if isinstance(aud, list):
                    aud = ",".join(aud[:2])
                scp = payload.get("scp") or payload.get("scope") or ""
                if isinstance(scp, list):
                    scp = " ".join(scp[:3])
                bits = []
                if aud:
                    bits.append(f"aud={str(aud)[:60]}")
                if scp:
                    bits.append(f"scp={str(scp)[:60]}")
                if bits:
                    aud_scp = " · ".join(bits)
        except Exception:
            aud_scp = ""
        out.append({
            "kind": "bearer", "label": "BEARER",
            "detail": (masked + (" · " + aud_scp if aud_scp else "")),
        })

    # Deduplicate while preserving order.
    seen = set()
    deduped: list[dict] = []
    for tag in out:
        key = (tag["kind"], tag.get("label"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(tag)
    return deduped


def _redact_code(s: str) -> str:
    """Mask the authorization code in a URL/Location string so the
    milestone detail line doesn't leak the secret."""
    return re.sub(
        r"([?&#]code=)[^&#]+",
        lambda m: m.group(1) + "<redacted>",
        s,
    )[:180]
