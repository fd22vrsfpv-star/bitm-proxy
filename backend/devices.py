"""Device profiles — reusable bundles of fingerprint + (optional) probed
JS signals + (optional) per-host credentials, applied to fresh Playwright
sessions on launch.

Three registration modes (selectable at register time):
  - passive : snapshot of what the proxy already captured.
  - probe   : also stamp a one-shot pending probe; the next request the
              client sends through :3128 to the captured host returns a
              synthetic page that POSTs JS-only signals (timezone,
              screen, viewport, navigator.languages/platform/etc) back.
  - creds   : same as probe AND the probe page also posts back
              localStorage/sessionStorage; raw cookies + headers are
              already snapshotted by `register_from_capture` from the
              proxy's captured-session state.

A profile can also be created manually from a preset or a free-form form.
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any
from urllib.parse import urlparse

from backend.store import JsonStore
from backend.shared import append_log
from backend.ua_engine import (
    ua_to_playwright_engine, ua_to_impersonate_target,
)


devices_store = JsonStore("devices")


def _log(action: str, device_id: str = "", **fields) -> None:
    """Push a device-event entry into the shared log buffer.

    Lands on the `devices` category so the dashboard's filter and
    journalctl queries can isolate device activity. Fields are
    rendered as `k=v` pairs after the action verb. A `session_id`
    field is consumed (binds the entry to that session in the
    per-session log file) rather than rendered."""
    sid = str(fields.pop("session_id", "") or "")
    parts = [f"DEVICE_{action.upper()}"]
    if device_id:
        parts.append(f"id={device_id}")
    for k, v in fields.items():
        if v is None or v == "":
            continue
        sval = str(v)
        if len(sval) > 160:
            sval = sval[:157] + "..."
        parts.append(f"{k}={sval}")
    append_log("info", "devices", " ".join(parts), session_id=sid)

# host -> {"token","device_id","modes","sites","expires"}. Populated when a
# probe-or-creds registration happens; consumed by the synthetic probe in
# auth_proxy.py and cleared by the probe-callback REST handler.
_pending_probes: dict[str, dict] = {}
_PROBE_TTL_SECS = 1800


# ── Presets ───────────────────────────────────────────────
# Compact catalogue. Each preset's `fingerprint` keys mirror the casing
# auth_proxy._capture_request preserves so manual + captured profiles take
# the same code paths in apply_to_context_opts().

PRESETS: list[dict] = [
    {
        "id": "iphone-15-safari",
        "name": "iPhone 15 Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 390, "height": 844},
        "device_scale_factor": 3.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like "
                           "Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
                           "Gecko) Version/17.4 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "pixel-8-chrome",
        "name": "Pixel 8 Chrome",
        "engine_family": "chromium", "channel": None,
        "viewport": {"width": 412, "height": 915},
        "device_scale_factor": 2.625, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Linux; Android 14; Pixel 8) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/124.0.0.0 Mobile Safari/537.36"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Chromium";v="124", "Google Chrome";v="124", '
                          '"Not-A.Brand";v="99"'),
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        },
    },
    {
        "id": "win11-edge",
        "name": "Windows 11 Edge",
        "engine_family": "chromium", "channel": "msedge",
        "viewport": {"width": 1536, "height": 864},
        "device_scale_factor": 1.5, "is_mobile": False, "has_touch": False,
        "locale": "en-US", "timezone_id": "America/New_York",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Chromium";v="124", "Microsoft Edge";v="124", '
                          '"Not-A.Brand";v="99"'),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    },
    {
        "id": "macos-safari",
        "name": "macOS Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 1440, "height": 900},
        "device_scale_factor": 2.0, "is_mobile": False, "has_touch": False,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                           "Version/17.4 Safari/605.1.15"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "win10-chrome",
        "name": "Windows 10 Chrome",
        "engine_family": "chromium", "channel": None,
        "viewport": {"width": 1920, "height": 1080},
        "device_scale_factor": 1.0, "is_mobile": False, "has_touch": False,
        "locale": "en-US", "timezone_id": "America/Chicago",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/124.0.0.0 Safari/537.36"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Chromium";v="124", "Google Chrome";v="124", '
                          '"Not-A.Brand";v="99"'),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    },
    # ── Modern presets (late-2024 / 2025 device + browser combos) ──
    {
        "id": "iphone-16-pro-safari",
        "name": "iPhone 16 Pro Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 402, "height": 874},
        "device_scale_factor": 3.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like "
                           "Mac OS X) AppleWebKit/605.1.15 (KHTML, like "
                           "Gecko) Version/18.2 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "ipad-pro-m4-safari",
        "name": "iPad Pro M4 13\" Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 1024, "height": 1366},
        "device_scale_factor": 2.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                           "Version/18.2 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "ipad-air-m2-safari",
        "name": "iPad Air M2 11\" Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 820, "height": 1180},
        "device_scale_factor": 2.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                           "Version/18.2 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "ipad-mini-7-safari",
        "name": "iPad mini (7th gen) Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 744, "height": 1133},
        "device_scale_factor": 2.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                           "Version/18.2 Mobile/15E148 Safari/604.1"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "pixel-9-pro-chrome",
        "name": "Pixel 9 Pro Chrome (Android 15)",
        "engine_family": "chromium", "channel": None,
        "viewport": {"width": 412, "height": 915},
        "device_scale_factor": 2.625, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Mobile Safari/537.36"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Google Chrome";v="131", "Chromium";v="131", '
                          '"Not_A Brand";v="24"'),
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        },
    },
    {
        "id": "galaxy-s24-chrome",
        "name": "Galaxy S24 Chrome",
        "engine_family": "chromium", "channel": None,
        "viewport": {"width": 360, "height": 800},
        "device_scale_factor": 3.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/New_York",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Linux; Android 14; SM-S921U) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Mobile Safari/537.36"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Google Chrome";v="131", "Chromium";v="131", '
                          '"Not_A Brand";v="24"'),
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
        },
    },
    {
        "id": "macos-sequoia-safari",
        "name": "macOS Sequoia Safari",
        "engine_family": "webkit", "channel": None,
        "viewport": {"width": 1440, "height": 900},
        "device_scale_factor": 2.0, "is_mobile": False, "has_touch": False,
        "locale": "en-US", "timezone_id": "America/Los_Angeles",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                           "Version/18.2 Safari/605.1.15"),
            "Accept-Language": "en-US,en;q=0.9",
        },
    },
    {
        "id": "win11-edge-current",
        "name": "Windows 11 Edge 131",
        "engine_family": "chromium", "channel": "msedge",
        "viewport": {"width": 1920, "height": 1080},
        "device_scale_factor": 1.0, "is_mobile": False, "has_touch": False,
        "locale": "en-US", "timezone_id": "America/New_York",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Microsoft Edge";v="131", "Chromium";v="131", '
                          '"Not_A Brand";v="24"'),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    },
    {
        "id": "surface-pro-11-edge",
        "name": "Surface Pro 11 Edge (touch)",
        "engine_family": "chromium", "channel": "msedge",
        # 13" 2880x1920 native @ 2× = 1440x960 logical. has_touch
        # distinguishes it from the desktop Win11 Edge preset above —
        # AAD's CA / fingerprint heuristics treat touch-enabled Win11
        # devices as "tablet-class" for some policies.
        "viewport": {"width": 1440, "height": 960},
        "device_scale_factor": 2.0, "is_mobile": False, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/New_York",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Microsoft Edge";v="131", "Chromium";v="131", '
                          '"Not_A Brand";v="24"'),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
    },
    {
        "id": "galaxy-tab-s10-ultra-chrome",
        "name": "Galaxy Tab S10 Ultra Chrome",
        "engine_family": "chromium", "channel": None,
        # 14.6" 2960x1848 native; common Chrome reporting at DPR 2.0
        # gives a 1480x924 logical viewport. Largest Android tablet
        # surface in the preset list.
        "viewport": {"width": 1480, "height": 924},
        "device_scale_factor": 2.0, "is_mobile": True, "has_touch": True,
        "locale": "en-US", "timezone_id": "America/New_York",
        "fingerprint": {
            "User-Agent": ("Mozilla/5.0 (Linux; Android 14; SM-X926B) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/131.0.0.0 Safari/537.36"),
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": ('"Google Chrome";v="131", "Chromium";v="131", '
                          '"Not_A Brand";v="24"'),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Android"',
        },
    },
]


def list_presets() -> list[dict]:
    return [dict(p) for p in PRESETS]


def _new_id() -> str:
    return f"dev_{secrets.token_hex(4)}"


def _ua_of(fp: dict) -> str:
    for k, v in (fp or {}).items():
        if k.lower() == "user-agent":
            return v or ""
    return ""


def _derive(fp: dict) -> tuple[str, str | None, str | None]:
    """Return (engine_family, channel, impersonate_tag)."""
    ua = _ua_of(fp)
    fam, ch = ua_to_playwright_engine(ua)
    return fam, ch, ua_to_impersonate_target(ua)


def _primary_locale(fp: dict, fallback: str = "en-US") -> str:
    al = ""
    for k, v in (fp or {}).items():
        if k.lower() == "accept-language":
            al = v or ""
            break
    if not al:
        return fallback
    return (al.split(",", 1)[0].split(";")[0].strip()) or fallback


# ── Read-side ─────────────────────────────────────────────

def list_all() -> list[dict]:
    out = devices_store.list_all()
    out.sort(key=lambda d: d.get("created_at") or 0, reverse=True)
    return out


def get(device_id: str) -> dict | None:
    if not device_id:
        return None
    return devices_store.get(device_id)


def delete(device_id: str) -> bool:
    rec = devices_store.get(device_id) or {}
    name = rec.get("name") or ""
    ok = devices_store.delete(device_id)
    if ok:
        _log("delete", device_id, name=name)
    return ok


async def update(device_id: str, patch: dict) -> dict:
    def _apply(cur: dict) -> dict:
        merged = {**cur, **(patch or {})}
        merged["id"] = device_id
        # Re-derive engine/impersonate if fingerprint changed.
        if "fingerprint" in (patch or {}):
            fam, ch, imp = _derive(merged.get("fingerprint") or {})
            merged["engine_family"] = fam
            merged["channel"] = ch
            merged["impersonate_tag"] = imp
        return merged
    rec = await devices_store.update(device_id, _apply, default={})
    _log("update", device_id, name=rec.get("name", ""),
         fields=",".join(sorted((patch or {}).keys())))
    return rec


# ── Registration ──────────────────────────────────────────

def _empty_record(pid: str, name: str, source: str) -> dict:
    return {
        "id": pid,
        "name": name or "Device",
        "created_at": time.time(),
        "last_used_at": 0.0,
        "source": source,
        "modes": [],
        "fingerprint": {},
        "engine_family": "chromium",
        "channel": None,
        "impersonate_tag": None,
        "viewport": {"width": 1280, "height": 800},
        "device_scale_factor": 1.0,
        "is_mobile": False,
        "has_touch": False,
        "locale": "en-US",
        "timezone_id": "UTC",
        "probed": {},
        "credentials": {},
        "notes": "",
    }


def _apply_preset_into(rec: dict, preset_id: str) -> None:
    p = next((x for x in PRESETS if x["id"] == preset_id), None)
    if not p:
        return
    for k in ("fingerprint", "viewport", "device_scale_factor",
             "is_mobile", "has_touch", "locale", "timezone_id",
             "engine_family", "channel"):
        if k in p:
            rec[k] = (dict(p[k]) if isinstance(p[k], dict) else p[k])
    if not rec.get("name") or rec["name"] == "Device":
        rec["name"] = p.get("name") or rec["name"]
    rec["impersonate_tag"] = ua_to_impersonate_target(_ua_of(rec["fingerprint"]))


def register_manual(profile: dict) -> dict:
    """Create a profile from preset + optional overrides, or a free-form
    form. Always derives engine/channel/impersonate from the final UA so
    manual and captured paths converge."""
    profile = profile or {}
    pid = _new_id()
    name = profile.get("name") or ""
    rec = _empty_record(pid, name, "manual")
    preset_id = profile.get("preset_id")
    if preset_id:
        rec["source"] = "preset"
        _apply_preset_into(rec, preset_id)
    # Apply free-form overrides.
    if profile.get("fingerprint"):
        fp = dict(rec.get("fingerprint") or {})
        fp.update(profile["fingerprint"])
        rec["fingerprint"] = fp
    for k in ("viewport", "device_scale_factor", "is_mobile", "has_touch",
             "locale", "timezone_id", "notes"):
        if k in profile and profile[k] not in (None, ""):
            rec[k] = profile[k]
    if profile.get("name"):
        rec["name"] = profile["name"]
    fam, ch, imp = _derive(rec["fingerprint"])
    rec["engine_family"] = profile.get("engine_family") or fam
    rec["channel"] = profile.get("channel") if "channel" in profile else ch
    rec["impersonate_tag"] = profile.get("impersonate_tag") or imp
    if not rec.get("name"):
        rec["name"] = "Manual device"
    devices_store.put(pid, rec)
    _log("register_manual", pid, name=rec["name"], source=rec["source"],
         engine=rec["engine_family"], channel=rec.get("channel") or "",
         impersonate=rec.get("impersonate_tag") or "",
         ua=_ua_of(rec.get("fingerprint") or {})[:120])
    return rec


def register_from_capture(hostname: str, modes: list[str],
                          sites: list[str] | None = None,
                          name: str | None = None) -> dict:
    """Snapshot what the proxy already captured for `hostname`. If `modes`
    contains 'probe' or 'creds', also record a one-shot probe token so
    the next client request through :3128 to that host fills in `probed`
    (and, for 'creds', additionally local/sessionStorage)."""
    from backend.auth_proxy import (
        get_captured_session_state, get_captured_fingerprint,
    )

    modes = list(modes or [])
    state = get_captured_session_state(hostname) or {}
    fp = (state.get("fingerprint") or get_captured_fingerprint(hostname)
          or {})
    fam, ch, imp = _derive(fp)
    pid = _new_id()
    rec = _empty_record(pid, name or f"{hostname} device", "captured")
    rec["modes"] = modes
    rec["fingerprint"] = dict(fp)
    rec["engine_family"] = fam
    rec["channel"] = ch
    rec["impersonate_tag"] = imp
    rec["locale"] = _primary_locale(fp, "en-US")

    target_sites = [s for s in (sites or []) if s] or [hostname]
    if "creds" in modes:
        for h in target_sites:
            s = get_captured_session_state(h)
            if not s:
                continue
            rec["credentials"][h] = {
                "cookies": list(s.get("cookies") or []),
                "headers": dict(s.get("headers") or {}),
                "local_storage": {},
                "session_storage": {},
            }
    devices_store.put(pid, rec)

    cred_hosts = list(rec.get("credentials", {}).keys())
    _log("register_from_capture", pid, name=rec["name"],
         host=hostname, modes=",".join(modes) or "(none)",
         engine=rec["engine_family"], channel=rec.get("channel") or "",
         creds_hosts=",".join(cred_hosts) or "(none)",
         ua=_ua_of(fp)[:120])
    if "probe" in modes or "creds" in modes:
        token = secrets.token_urlsafe(16)
        _pending_probes[hostname] = {
            "token": token,
            "device_id": pid,
            "modes": modes,
            "sites": target_sites,
            "expires": time.time() + _PROBE_TTL_SECS,
        }
        _log("probe_pending", pid, host=hostname,
             ttl_secs=_PROBE_TTL_SECS,
             sites=",".join(target_sites))
    return rec


# ── Probe ─────────────────────────────────────────────────

def has_pending_probe(hostname: str) -> bool:
    p = _pending_probes.get(hostname)
    if not p:
        return False
    if p["expires"] < time.time():
        _pending_probes.pop(hostname, None)
        return False
    return True


def get_pending_probe(hostname: str) -> dict | None:
    p = _pending_probes.get(hostname)
    if not p or p["expires"] < time.time():
        _pending_probes.pop(hostname, None)
        return None
    return dict(p)


async def register_from_session(page, modes: list[str],
                                 name: str | None = None,
                                 sites_filter: list[str] | None = None) -> dict:
    """Snapshot a live :8091 Playwright session into a device profile.

    Reads UA + JS-derived signals (timezone, languages, screen,
    viewport, platform, hardware_concurrency, device_memory) directly
    from the page via `page.evaluate`. Reads cookies + localStorage
    via `page.context.storage_state()`. Reads sessionStorage from the
    current top-level page only — Playwright's storage_state doesn't
    export it, and visiting other origins to harvest theirs would mean
    navigating the operator's session away.

    `modes` mirrors `register_from_capture`: `passive` always means
    fingerprint + JS signals; `creds` adds cookies + storage. Probe
    isn't a separate mode here — JS signals are read live.

    `sites_filter`, when set, restricts the per-host credentials
    bundle to those hostnames.
    """
    modes = list(modes or ["passive"])
    pid = _new_id()
    rec = _empty_record(pid, name or "Session device", "captured")
    rec["modes"] = modes

    # Fingerprint + JS signals via the running page.
    fp: dict[str, str] = {}
    probed: dict[str, Any] = {}
    try:
        ua = await page.evaluate("() => navigator.userAgent")
        if ua:
            fp["User-Agent"] = ua
    except Exception:
        pass
    try:
        languages = await page.evaluate("() => navigator.languages || []")
    except Exception:
        languages = []
    if languages:
        fp["Accept-Language"] = ",".join(languages[:3]) + ";q=0.9"
        probed["languages"] = list(languages)
    try:
        # High-entropy client hints (Sec-CH-UA-*) — populated when the
        # page has called navigator.userAgentData.getHighEntropyValues
        # at any point. Many sites do.
        ua_hints = await page.evaluate(
            "async () => navigator.userAgentData ? "
            "await navigator.userAgentData.getHighEntropyValues("
            "['platform','platformVersion','architecture','bitness',"
            "'model','uaFullVersion','fullVersionList','wow64']) "
            ": null")
    except Exception:
        ua_hints = None
    if isinstance(ua_hints, dict):
        if ua_hints.get("brands") or ua_hints.get("fullVersionList"):
            try:
                lst = ua_hints.get("fullVersionList") or ua_hints.get("brands") or []
                fp["sec-ch-ua"] = ", ".join(
                    f'"{b.get("brand","")}";v="{b.get("version","")}"' for b in lst)
            except Exception:
                pass
        if ua_hints.get("mobile") is not None:
            fp["sec-ch-ua-mobile"] = "?1" if ua_hints["mobile"] else "?0"
        if ua_hints.get("platform"):
            fp["sec-ch-ua-platform"] = f'"{ua_hints["platform"]}"'
        for k_src, k_hdr in (
            ("platformVersion", "sec-ch-ua-platform-version"),
            ("architecture", "sec-ch-ua-arch"),
            ("bitness", "sec-ch-ua-bitness"),
            ("model", "sec-ch-ua-model"),
            ("uaFullVersion", "sec-ch-ua-full-version"),
            ("wow64", "sec-ch-ua-wow64"),
        ):
            v = ua_hints.get(k_src)
            if v not in (None, ""):
                fp[k_hdr] = f'"{v}"' if isinstance(v, str) else (
                    "?1" if v is True else "?0" if v is False else str(v))
    rec["fingerprint"] = fp

    fam, ch, imp = _derive(fp)
    rec["engine_family"] = fam
    rec["channel"] = ch
    rec["impersonate_tag"] = imp

    # Locale, timezone, viewport, screen, hardware.
    try:
        tz = await page.evaluate(
            "() => Intl.DateTimeFormat().resolvedOptions().timeZone")
        if tz:
            rec["timezone_id"] = tz
            probed["tz"] = tz
    except Exception:
        pass
    if languages:
        rec["locale"] = languages[0]
    try:
        vp = page.viewport_size
        if vp:
            rec["viewport"] = {"width": int(vp["width"]),
                                "height": int(vp["height"])}
    except Exception:
        pass
    try:
        screen = await page.evaluate(
            "() => ({width: screen.width, height: screen.height, "
            "colorDepth: screen.colorDepth, "
            "pixelRatio: window.devicePixelRatio || 1})")
        if isinstance(screen, dict) and screen:
            probed["screen"] = screen
            if screen.get("pixelRatio"):
                rec["device_scale_factor"] = float(screen["pixelRatio"])
    except Exception:
        pass
    try:
        plat = await page.evaluate("() => navigator.platform || ''")
        if plat:
            probed["platform"] = plat
    except Exception:
        pass
    try:
        probed["hardware_concurrency"] = await page.evaluate(
            "() => navigator.hardwareConcurrency || 0")
    except Exception:
        pass
    try:
        probed["device_memory"] = await page.evaluate(
            "() => navigator.deviceMemory || 0")
    except Exception:
        pass
    try:
        is_mobile = await page.evaluate(
            "() => (navigator.userAgentData && navigator.userAgentData.mobile) "
            "|| /Mobi|Android|iPhone/.test(navigator.userAgent)")
        rec["is_mobile"] = bool(is_mobile)
    except Exception:
        pass
    if probed:
        probed["captured_at"] = time.time()
        rec["probed"] = probed

    # Optional creds bundle.
    if "creds" in modes:
        try:
            state = await page.context.storage_state()
        except Exception:
            state = {"cookies": [], "origins": []}
        cookies = state.get("cookies") or []
        origins = state.get("origins") or []
        # Group by hostname.
        by_host: dict[str, dict] = {}

        def _bucket(h: str) -> dict:
            return by_host.setdefault(h, {
                "cookies": [], "headers": {},
                "local_storage": {}, "session_storage": {},
            })

        for c in cookies:
            host = (c.get("domain") or "").lstrip(".")
            if not host:
                continue
            if sites_filter and host not in sites_filter:
                continue
            _bucket(host)["cookies"].append(c)
        for orig in origins:
            origin = orig.get("origin") or ""
            host = urlparse(origin).hostname or ""
            if not host:
                continue
            if sites_filter and host not in sites_filter:
                continue
            kv = {item.get("name", ""): item.get("value", "")
                  for item in (orig.get("localStorage") or [])
                  if item.get("name") is not None}
            if kv:
                _bucket(host)["local_storage"][origin] = kv
        # sessionStorage from the active top-level page only.
        try:
            cur_url = page.url
            cur_host = urlparse(cur_url).hostname or ""
        except Exception:
            cur_host, cur_url = "", ""
        if cur_host and (not sites_filter or cur_host in sites_filter):
            try:
                ss = await page.evaluate(
                    "() => { const r={}; "
                    "try{for(let i=0;i<sessionStorage.length;i++){"
                    "const k=sessionStorage.key(i);r[k]=sessionStorage.getItem(k)}}"
                    "catch(e){} return r }")
                if isinstance(ss, dict) and ss:
                    _bucket(cur_host)["session_storage"][cur_url] = ss
            except Exception:
                pass
        rec["credentials"] = by_host

    devices_store.put(pid, rec)
    cred_hosts = list(rec.get("credentials", {}).keys())
    cookie_count = sum(len(b.get("cookies", []))
                        for b in rec.get("credentials", {}).values())
    _log("register_from_session", pid, name=rec["name"],
         modes=",".join(modes), engine=rec["engine_family"],
         channel=rec.get("channel") or "",
         tz=rec.get("timezone_id", ""),
         viewport=f"{rec['viewport']['width']}x{rec['viewport']['height']}",
         creds_hosts=",".join(cred_hosts) or "(none)",
         cookies=cookie_count,
         ua=_ua_of(fp)[:120])
    return rec


def consume_probe(hostname: str, token: str,
                  device_id: str = "") -> dict | None:
    p = _pending_probes.get(hostname)
    if not p or p["expires"] < time.time():
        _pending_probes.pop(hostname, None)
        return None
    if p["token"] != token:
        return None
    if device_id and p["device_id"] != device_id:
        return None
    return dict(p)


def apply_probe_result(device_id: str, probed: dict,
                       hostname: str | None = None,
                       local_storage: dict | None = None,
                       session_storage: dict | None = None) -> dict | None:
    rec = devices_store.get(device_id)
    if not rec:
        return None
    pr = dict(rec.get("probed") or {})
    if probed:
        pr.update(probed)
        pr["captured_at"] = time.time()
        rec["probed"] = pr
        if probed.get("tz"):
            rec["timezone_id"] = probed["tz"]
        if probed.get("languages"):
            try:
                rec["locale"] = probed["languages"][0] or rec["locale"]
            except Exception:
                pass
        if isinstance(probed.get("viewport"), dict):
            rec["viewport"] = probed["viewport"]
    if hostname and (local_storage or session_storage):
        bundle = (rec.setdefault("credentials", {})
                  .setdefault(hostname, {
                      "cookies": [], "headers": {},
                      "local_storage": {}, "session_storage": {},
                  }))
        if local_storage:
            bundle["local_storage"][hostname] = local_storage
        if session_storage:
            bundle["session_storage"][hostname] = session_storage
    devices_store.put(device_id, rec)
    if hostname:
        _pending_probes.pop(hostname, None)
    sl = (probed or {}).get("screen") or {}
    _log("probe_applied", device_id, host=hostname or "",
         tz=(probed or {}).get("tz") or "",
         platform=(probed or {}).get("platform") or "",
         screen=f"{sl.get('width','?')}x{sl.get('height','?')}",
         ls_keys=len(local_storage or {}),
         ss_keys=len(session_storage or {}))
    return rec


# ── Apply (Playwright launch) ─────────────────────────────

def apply_to_context_opts(profile: dict, context_opts: dict,
                           session_id: str = "") -> dict:
    """Mutate `context_opts` so a fresh `browser.new_context(**context_opts)`
    is shaped like the device. Headers + UA mirror the existing
    use_captured_fingerprint path in routes/browser.py."""
    if not profile:
        return context_opts
    fp = profile.get("fingerprint") or {}
    ua = _ua_of(fp)
    if ua:
        context_opts["user_agent"] = ua
    if profile.get("locale"):
        context_opts["locale"] = profile["locale"]
    if profile.get("timezone_id"):
        context_opts["timezone_id"] = profile["timezone_id"]
    vp = profile.get("viewport")
    if isinstance(vp, dict) and vp.get("width") and vp.get("height"):
        context_opts["viewport"] = {"width": int(vp["width"]),
                                    "height": int(vp["height"])}
    if profile.get("device_scale_factor"):
        try:
            context_opts["device_scale_factor"] = float(
                profile["device_scale_factor"])
        except Exception:
            pass
    if profile.get("is_mobile"):
        context_opts["is_mobile"] = True
    if profile.get("has_touch"):
        context_opts["has_touch"] = True
    extras: dict[str, str] = {}
    for k, v in fp.items():
        lk = k.lower()
        if lk == "user-agent":
            continue
        if lk == "accept-language" or lk.startswith("sec-ch-ua"):
            extras[k] = v
    if extras:
        merged = dict(context_opts.get("extra_http_headers") or {})
        merged.update(extras)
        context_opts["extra_http_headers"] = merged
    _log("apply_context", profile.get("id", ""),
         session_id=session_id,
         name=profile.get("name", ""),
         engine=profile.get("engine_family", ""),
         channel=profile.get("channel") or "",
         locale=context_opts.get("locale", ""),
         tz=context_opts.get("timezone_id", ""),
         viewport=(f"{context_opts['viewport']['width']}x"
                    f"{context_opts['viewport']['height']}"
                    if context_opts.get("viewport") else ""),
         hint_headers=len([k for k in (context_opts.get("extra_http_headers") or {})
                            if k.lower().startswith("sec-ch-ua")]))
    return context_opts


async def apply_post_launch(profile: dict, page,
                             session_id: str = "") -> dict:
    """Inject cookies + per-host extra headers + LS/SS into the freshly
    created page's context. Call BEFORE the first goto. Returns a
    summary dict suitable for logging."""
    summary = {"cookies": 0, "headers": 0, "ls_origins": 0, "ss_origins": 0}
    creds = (profile or {}).get("credentials") or {}
    if not creds:
        return summary
    # Merge cookies across hosts and add once.
    all_cookies: list[dict] = []
    extra_headers: dict[str, str] = {}
    for host, bundle in creds.items():
        for c in (bundle.get("cookies") or []):
            all_cookies.append(c)
        for k, v in (bundle.get("headers") or {}).items():
            extra_headers[k] = v
        for origin, kv in (bundle.get("local_storage") or {}).items():
            try:
                payload = json.dumps(kv)
                await page.context.add_init_script(
                    "(()=>{try{const _o=" + payload + ";"
                    "for(const k in _o){"
                    "try{localStorage.setItem(k,_o[k])}catch(e){}}"
                    "}catch(e){}})();")
                summary["ls_origins"] += 1
            except Exception:
                pass
        for origin, kv in (bundle.get("session_storage") or {}).items():
            try:
                payload = json.dumps(kv)
                await page.context.add_init_script(
                    "(()=>{try{const _o=" + payload + ";"
                    "for(const k in _o){"
                    "try{sessionStorage.setItem(k,_o[k])}catch(e){}}"
                    "}catch(e){}})();")
                summary["ss_origins"] += 1
            except Exception:
                pass
    if all_cookies:
        try:
            await page.context.add_cookies(all_cookies)
            summary["cookies"] = len(all_cookies)
        except Exception:
            pass
    if extra_headers:
        existing = {}
        try:
            existing = await page.context.extra_http_headers() if hasattr(
                page.context, "extra_http_headers") else {}
        except Exception:
            existing = {}
        merged = {**(existing or {}), **extra_headers}
        try:
            await page.context.set_extra_http_headers(merged)
            summary["headers"] = len(extra_headers)
        except Exception:
            pass
    _log("apply_post_launch", (profile or {}).get("id", ""),
         session_id=session_id,
         name=(profile or {}).get("name", ""),
         cookies=summary["cookies"], headers=summary["headers"],
         ls_origins=summary["ls_origins"], ss_origins=summary["ss_origins"])
    return summary
