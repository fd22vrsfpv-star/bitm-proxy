"""Load declarative site/IdP recognition rules from YAML.

Two files are merged in this order:
  1. config/sites.yaml  (repo baseline — ships with the project)
  2. $DATA_DIR/sites.yaml (per-install override — deep-merged on top)

Both files are hot-reloaded: mtime is checked on each `get_rules()` call so
edits take effect without a restart.
"""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover — loader is best-effort
    yaml = None  # type: ignore

from backend.paths import data_dir
from backend.shared import append_log


_REPO_FILE = Path(__file__).parent.parent / "config" / "sites.yaml"


def _override_file() -> Path:
    try:
        return data_dir() / "sites.yaml"
    except Exception:
        return Path(os.environ.get("DATA_DIR", "/data")) / "sites.yaml"


# ── Cache ──────────────────────────────────────────────────────────────
_cache: dict[str, Any] | None = None
_cache_mtime: tuple[float, float] = (0.0, 0.0)  # (repo_mtime, override_mtime)


def _mtime(p: Path) -> float:
    try:
        return p.stat().st_mtime
    except Exception:
        return 0.0


def _deep_merge(a: dict, b: dict) -> dict:
    """Deep-merge b into a. Lists in b REPLACE lists in a (so overrides can
    shrink the default list). Dicts are recursed. Scalars in b win."""
    out = dict(a)
    for k, v in (b or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _load_file(path: Path) -> dict[str, Any]:
    if not path.exists() or yaml is None:
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f) or {}
            return loaded if isinstance(loaded, dict) else {}
    except Exception as e:
        append_log("warn", "site_rules",
                   f"Failed to parse {path}: {e}")
        return {}


def get_rules() -> dict[str, Any]:
    """Return the merged rules dict, hot-reloading when either file changes."""
    global _cache, _cache_mtime
    override = _override_file()
    mt = (_mtime(_REPO_FILE), _mtime(override))
    if _cache is not None and mt == _cache_mtime:
        return _cache
    base = _load_file(_REPO_FILE)
    ovr = _load_file(override)
    merged = _deep_merge(base, ovr)
    _cache = merged
    _cache_mtime = mt
    if _cache_mtime != (0.0, 0.0):
        append_log("info", "site_rules",
                   f"Loaded site rules: {len(merged.get('sites', []))} sites, "
                   f"override={'yes' if mt[1] else 'no'}")
    return merged


# ── Accessors: global lists ────────────────────────────────────────────

def _globals() -> dict[str, Any]:
    return get_rules().get("globals") or {}


def ignore_headers() -> set[str]:
    return {s.lower() for s in _globals().get("ignore_headers", [])}


def auth_headers() -> set[str]:
    return {s.lower() for s in _globals().get("auth_headers", [])}


def session_keywords() -> set[str]:
    return {s.lower() for s in _globals().get("session_keywords", [])}


def capture_header_names() -> set[str]:
    return {s.lower() for s in _globals().get("capture_header_names", [])}


def capture_header_keywords() -> set[str]:
    return {s.lower() for s in _globals().get("capture_header_keywords", [])}


def mcas_domains() -> set[str]:
    return {s.lower() for s in _globals().get("mcas_domains", [])}


def mcas_noise_domains() -> set[str]:
    return {s.lower() for s in _globals().get("mcas_noise_domains", [])}


def dead_end_url_patterns() -> list[str]:
    return [s.lower() for s in _globals().get("dead_end_url_patterns", [])]


def app_install_url_patterns() -> list[str]:
    return [s.lower() for s in _globals().get("app_install_url_patterns", [])]


def noisy_hosts() -> list[str]:
    """Hosts whose requests get filtered from verbose logs (telemetry /
    analytics / CDN beacons that don't carry auth state)."""
    return [s.lower() for s in _globals().get("noisy_hosts", [])]


def body_capture_hostnames() -> list[str]:
    """Hosts whose request + response bodies the :3128 auth proxy
    records into the Flow Trace buffer. See config/sites.yaml."""
    return [s.lower() for s in _globals().get("body_capture_hostnames", [])]


def host_matches_body_capture(host: str) -> bool:
    """True if this host should have its bodies captured by :3128."""
    return _host_matches(body_capture_hostnames(), host)


def proxy_allowed_hosts() -> list[str]:
    """Hostname allowlist for the :3128 auth proxy's BITM interception.

    Empty (the default) means unrestricted — every existing install keeps
    today's behavior. Non-empty is opt-in hardening for deployments (e.g. a
    publicly-reachable lab instance) that must not intercept/decrypt traffic
    to arbitrary hosts. See config/sites.yaml globals.proxy_allowed_hosts."""
    return [s.lower() for s in _globals().get("proxy_allowed_hosts", [])]


def _host_allowed(patterns: list[str], host: str) -> bool:
    """Strict allowlist match: exact hostname, or exact subdomain suffix
    with a dot boundary. Deliberately NOT `_host_matches` (substring-based,
    built for noise-filtering heuristics) — a bare substring match would let
    "microsoft.com" also match "evil-microsoft.com.attacker.net", which is
    unacceptable for a security boundary."""
    h = (host or "").lower()
    for p in patterns:
        p = (p or "").lower().strip()
        if not p:
            continue
        if h == p or h.endswith("." + p):
            return True
    return False


def host_allowed_for_proxy(host: str) -> bool:
    """True if the :3128 proxy should BITM this host. Always True when
    proxy_allowed_hosts() is empty (unrestricted default)."""
    allowed = proxy_allowed_hosts()
    if not allowed:
        return True
    return _host_allowed(allowed, host)


# Compiled console-filter regex, cached against the merged-rules dict
# identity so a YAML hot-reload (which produces a fresh dict) triggers
# recompilation exactly once. None when no patterns are configured.
_console_filter_cache: dict[int, re.Pattern | None] = {}


def console_filter_re() -> re.Pattern | None:
    """One alternation regex matching every console-noise pattern in
    config/sites.yaml → globals.console_filter_patterns. Returns None
    when no patterns are configured."""
    rules = get_rules()
    rid = id(rules)
    cached = _console_filter_cache.get(rid)
    if rid in _console_filter_cache:
        return cached
    patterns = (rules.get("globals") or {}).get(
        "console_filter_patterns") or []
    cleaned = [p for p in patterns if p]
    if not cleaned:
        _console_filter_cache[rid] = None
        return None
    try:
        rx = re.compile(
            "|".join(f"(?:{p})" for p in cleaned),
            re.IGNORECASE,
        )
    except re.error as e:
        append_log("warn", "site_rules",
                   f"console_filter_patterns regex compile failed: {e}")
        rx = None
    # Trim cache to the latest 4 entries.
    if len(_console_filter_cache) >= 4:
        for old_key in list(_console_filter_cache.keys())[:-3]:
            _console_filter_cache.pop(old_key, None)
    _console_filter_cache[rid] = rx
    if rx is not None:
        append_log("info", "site_rules",
                   f"console_filter compiled: {len(cleaned)} pattern(s)")
    return rx


def console_should_drop(line: str) -> bool:
    """True when a console line matches any filter pattern. Cheap —
    one combined regex search against the cached compilation."""
    rx = console_filter_re()
    if rx is None or not line:
        return False
    return bool(rx.search(line))


def login_targets() -> dict[str, str]:
    return dict(get_rules().get("login_targets") or {})


# Conditional Access block detail extraction config. Cached against the
# merged-rules dict identity so a YAML hot-reload (which produces a
# fresh dict from `get_rules`) naturally invalidates the cache. The
# precomputed shape — lowercased URL-match patterns + the param_keys
# list verbatim — keeps the per-navigation parser cheap.
_ca_blocked_cache: dict[int, dict[str, Any]] = {}
_ca_milestones_cache: dict[int, dict[str, Any]] = {}
_rp_callback_cache: dict[int, dict[str, Any]] = {}
_mdm_milestones_cache: dict[int, dict[str, Any]] = {}


def ca_blocked_config() -> dict[str, Any]:
    """Return precompiled config for Conditional Access block parsing.

    Shape:
      url_match_patterns: tuple[str]   (lowercased; substring match)
      param_keys:         tuple[str]   (canonical names; case-insensitive lookup)

    Empty tuples when the YAML key is absent, in which case the parser
    returns an empty dict and no `details` are attached."""
    rules = get_rules()
    rid = id(rules)
    cached = _ca_blocked_cache.get(rid)
    if cached is not None:
        return cached
    raw = (rules.get("globals") or {}).get("ca_blocked") or {}
    cfg: dict[str, Any] = {
        "url_match_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("url_match_patterns") or [])
            if p
        ),
        "param_keys": tuple(
            k for k in (raw.get("param_keys") or []) if k
        ),
    }
    if len(_ca_blocked_cache) >= 4:
        for old_key in list(_ca_blocked_cache.keys())[:-3]:
            _ca_blocked_cache.pop(old_key, None)
    _ca_blocked_cache[rid] = cfg
    return cfg


def ca_milestones_config() -> dict[str, Any]:
    """Return precompiled config for the flow-row CA milestone classifier.

    Shape:
      blocked_url_patterns:    tuple[str]   (lowercased substrings)
      reprocess_url_patterns:  tuple[str]   (lowercased substrings)
      aadsts_codes:            tuple[str]   (uppercased; substring match)
      aadsts_re:               re.Pattern | None  (alternation of the codes)

    Empty tuples / None pattern when the YAML key is absent — the
    classifier short-circuits and emits no CA milestone in that case."""
    rules = get_rules()
    rid = id(rules)
    cached = _ca_milestones_cache.get(rid)
    if cached is not None:
        return cached
    raw = (rules.get("globals") or {}).get("ca_milestones") or {}
    codes = tuple(
        (c or "").upper() for c in (raw.get("aadsts_codes") or []) if c
    )
    cfg: dict[str, Any] = {
        "blocked_url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("blocked_url_patterns") or [])
            if p
        ),
        "reprocess_url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("reprocess_url_patterns") or [])
            if p
        ),
        "aadsts_codes": codes,
        "aadsts_re": (
            _compile_list([re.escape(c) for c in codes]) if codes else None
        ),
    }
    if len(_ca_milestones_cache) >= 4:
        for old_key in list(_ca_milestones_cache.keys())[:-3]:
            _ca_milestones_cache.pop(old_key, None)
    _ca_milestones_cache[rid] = cfg
    return cfg


def rp_callback_config() -> dict[str, Any]:
    """Return precompiled config for relying-party-callback detection.

    Shape:
      url_patterns: tuple[str]  (lowercased substrings; absolute or path)

    The classifier tags a flow row as kind=rp_reject when its URL
    matches any of these substrings AND the response status is 4xx/5xx
    AND the host is NOT one of the configured `auth_milestones.idp_hosts`."""
    rules = get_rules()
    rid = id(rules)
    cached = _rp_callback_cache.get(rid)
    if cached is not None:
        return cached
    raw = (rules.get("globals") or {}).get("rp_callbacks") or {}
    cfg: dict[str, Any] = {
        "url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("url_patterns") or [])
            if p
        ),
    }
    if len(_rp_callback_cache) >= 4:
        for old_key in list(_rp_callback_cache.keys())[:-3]:
            _rp_callback_cache.pop(old_key, None)
    _rp_callback_cache[rid] = cfg
    return cfg


def mdm_milestones_config() -> dict[str, Any]:
    """Return precompiled config for the Intune MDM milestone classifier.

    Shape:
      discover_url_patterns: tuple[str]   (lowercased path substrings)
      enroll_url_patterns:   tuple[str]
      checkin_url_patterns:  tuple[str]
      hosts:                 tuple[str]   (host filter; substring or `*.suffix`)

    Empty tuples when the YAML key is absent — the classifier short-
    circuits and emits no MDM milestone in that case. Visibility-only:
    no MDM traffic is replayed or synthesized."""
    rules = get_rules()
    rid = id(rules)
    cached = _mdm_milestones_cache.get(rid)
    if cached is not None:
        return cached
    raw = (rules.get("globals") or {}).get("mdm_milestones") or {}
    cfg: dict[str, Any] = {
        "discover_url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("discover_url_patterns") or []) if p
        ),
        "enroll_url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("enroll_url_patterns") or []) if p
        ),
        "checkin_url_patterns": tuple(
            (p or "").lower()
            for p in (raw.get("checkin_url_patterns") or []) if p
        ),
        "hosts": tuple(
            (h or "").lower() for h in (raw.get("hosts") or []) if h
        ),
    }
    if len(_mdm_milestones_cache) >= 4:
        for old_key in list(_mdm_milestones_cache.keys())[:-3]:
            _mdm_milestones_cache.pop(old_key, None)
    _mdm_milestones_cache[rid] = cfg
    return cfg


# ── Accessors: auth_milestones (declarative classifier inputs) ─────────
# Returned shape is precompiled where it makes sense — classify() runs on
# every flow row and recompiling regexes per call is wasteful. The cache
# key is the rules dict's id() so a hot-reload via get_rules() naturally
# invalidates compiled patterns (a new merged dict has a new id).

_milestones_cache: dict[int, dict[str, Any]] = {}


def _compile_list(patterns: list[str]) -> re.Pattern | None:
    """Compile a list of regex strings into one combined alternation,
    case-insensitive. Returns None when the list is empty."""
    cleaned = [p for p in (patterns or []) if p]
    if not cleaned:
        return None
    try:
        return re.compile("|".join(f"(?:{p})" for p in cleaned), re.IGNORECASE)
    except re.error as e:
        append_log("warn", "site_rules",
                   f"auth_milestones regex compile failed: {e}")
        return re.compile(r"(?!x)x")  # never matches


def auth_milestones_config() -> dict[str, Any]:
    """Return the precompiled auth-milestones config.

    The result is cached against the merged-rules dict identity so a
    YAML hot-reload (which produces a fresh dict from `get_rules`)
    triggers recompilation exactly once."""
    rules = get_rules()
    rid = id(rules)
    cached = _milestones_cache.get(rid)
    if cached is not None:
        return cached
    raw = rules.get("auth_milestones") or {}
    cfg: dict[str, Any] = {
        "idp_hosts": tuple(
            (h or "").lower() for h in (raw.get("idp_hosts") or [])),
        "login_path_re": _compile_list(raw.get("login_path_patterns") or []),
        "not_login_path_re": _compile_list(
            raw.get("not_login_path_patterns") or []),
        "login_body_markers": tuple(
            raw.get("login_body_markers") or []),
        "token_path_re": _compile_list(raw.get("token_path_patterns") or []),
        "session_cookie_names": frozenset(
            (n or "").lower() for n in (raw.get("session_cookie_names") or [])),
        "session_cookie_prefixes": tuple(
            (p or "").lower() for p in (raw.get("session_cookie_prefixes") or [])),
        "prt_cookie_prefixes": tuple(
            (p or "").lower() for p in (raw.get("prt_cookie_prefixes") or [])),
        "prt_grant_types": frozenset(
            (g or "").lower() for g in (raw.get("prt_grant_types") or [])),
        "prt_scopes": frozenset(
            (s or "").lower() for s in (raw.get("prt_scopes") or [])),
        "prt_token_types": frozenset(
            (t or "").lower() for t in (raw.get("prt_token_types") or [])),
    }
    # Trim cache to the latest 4 entries — reloads are rare but we don't
    # want unbounded growth in a long-running service.
    if len(_milestones_cache) >= 4:
        for old_key in list(_milestones_cache.keys())[:-3]:
            _milestones_cache.pop(old_key, None)
    _milestones_cache[rid] = cfg
    append_log("info", "site_rules",
               f"auth_milestones compiled: idp_hosts={len(cfg['idp_hosts'])} "
               f"login_paths={'yes' if cfg['login_path_re'] else 'no'} "
               f"token_paths={'yes' if cfg['token_path_re'] else 'no'} "
               f"session_cookies={len(cfg['session_cookie_names'])} "
               f"body_markers={len(cfg['login_body_markers'])}")
    return cfg


# ── Accessors: per-site aggregations ───────────────────────────────────

def _sites() -> list[dict[str, Any]]:
    return get_rules().get("sites") or []


def _host_matches(patterns: list[str], host: str) -> bool:
    """Does the host match any of these patterns (substring or *.suffix)?"""
    h = (host or "").lower()
    for p in patterns:
        p = (p or "").lower().strip()
        if not p:
            continue
        if p.startswith("*."):
            if h == p[2:] or h.endswith("." + p[2:]):
                return True
        elif p in h:
            return True
    return False


def login_url_patterns() -> list[str]:
    """Union of every site's `login_url_patterns`."""
    out: list[str] = []
    for site in _sites():
        out.extend(site.get("login_url_patterns", []) or [])
    return [p.lower() for p in out]


def auth_complete_url_patterns() -> list[str]:
    out: list[str] = []
    for site in _sites():
        out.extend(site.get("auth_complete_url_patterns", []) or [])
    return [p.lower() for p in out]


# ── Challenge classifier data ──────────────────────────────────────────

def sites_matching_host(host: str) -> list[dict[str, Any]]:
    return [s for s in _sites() if _host_matches(s.get("hosts", []) or [], host)]


def classify_rules(host: str) -> dict[str, Any]:
    """Return the merged challenge config for a hostname.
    Aggregates url_rules / url_regex / dom_rules / error_codes / response_errors
    across every site whose host pattern matches."""
    url_rules: list[dict[str, str]] = []
    url_regex: list[dict[str, str]] = []
    dom_rules: list[dict[str, str]] = []
    response_errors: list[dict[str, str]] = []
    error_codes: dict[str, str] = {}
    error_regex = ""
    idp = ""
    for s in sites_matching_host(host):
        if not idp:
            idp = s.get("name", "")
        ch = s.get("challenges") or {}
        url_rules.extend(ch.get("url_rules", []) or [])
        url_regex.extend(ch.get("url_regex", []) or [])
        dom_rules.extend(ch.get("dom_rules", []) or [])
        response_errors.extend(ch.get("response_errors", []) or [])
        if ch.get("error_codes"):
            error_codes.update(ch["error_codes"])
        if ch.get("error_regex"):
            error_regex = ch["error_regex"]
    return {
        "idp": idp,
        "url_rules": url_rules,
        "url_regex": url_regex,
        "dom_rules": dom_rules,
        "response_errors": response_errors,
        "error_codes": error_codes,
        "error_regex": error_regex or r"AADSTS\d{4,6}",
    }


def response_error_rules_for(host: str) -> tuple[list[dict[str, str]], dict[str, str], str]:
    """Shorthand: (rules, error_codes, idp) used by the flow scanner."""
    c = classify_rules(host)
    return c["response_errors"], c["error_codes"], c["idp"]


# AbuseAzureAPIPermissions runner — list of PowerShell function names the
# operator is allowed to invoke through the dashboard. Vendored script lives
# in tools/AbuseAzureAPIPermissions/. Recon-only by default; destructive
# (Set-/New-/Remove-/Send-) functions only land in `allowed_functions` when
# the operator has explicitly opted in via $DATA_DIR/sites.yaml. Cached
# against the merged-rules dict identity so a YAML hot-reload invalidates
# automatically.
_aaa_runner_cache: dict[int, dict[str, Any]] = {}


def aaa_runner_config() -> dict[str, Any]:
    """Return:
      allowed_functions: tuple[str]  (verb-prefixed PS function names)
      script_path:        str        (path to AbuseAzureAPIPermissions.ps1)
      pwsh:               str        (executable name; default 'pwsh')
      timeout_seconds:    int
    """
    rules = get_rules()
    rid = id(rules)
    cached = _aaa_runner_cache.get(rid)
    if cached is not None:
        return cached
    raw = rules.get("aaa_runner") or {}
    allowed = tuple(
        s.strip() for s in (raw.get("allowed_functions") or []) if s
    )
    cfg = {
        "allowed_functions": allowed,
        "script_path": str(raw.get("script_path")
                           or "tools/AbuseAzureAPIPermissions/"
                           "AbuseAzureAPIPermissions.ps1"),
        "pwsh": str(raw.get("pwsh") or "pwsh"),
        "timeout_seconds": int(raw.get("timeout_seconds") or 60),
    }
    if len(_aaa_runner_cache) >= 4:
        for old_key in list(_aaa_runner_cache.keys())[:-3]:
            _aaa_runner_cache.pop(old_key, None)
    _aaa_runner_cache[rid] = cfg
    return cfg


def all_error_codes() -> dict[str, str]:
    """Merged error-code → meaning map across every site (used as fallback
    when the current page host doesn't match any site entry)."""
    out: dict[str, str] = {}
    for s in _sites():
        for code, meaning in ((s.get("challenges") or {}).get("error_codes") or {}).items():
            out[code] = meaning
    return out


# Regex compilation cache
_regex_cache: dict[str, re.Pattern] = {}

def compile_regex(pattern: str) -> re.Pattern:
    rx = _regex_cache.get(pattern)
    if rx is None:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error:
            rx = re.compile(r"(?!x)x")  # never matches
        _regex_cache[pattern] = rx
    return rx
