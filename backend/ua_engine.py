"""Map a captured User-Agent to a Playwright engine family and a
curl_cffi impersonation target.

Single source of truth for the fingerprint-replay logic in
backend/routes/browser.py (Playwright launch) and backend/auth_proxy.py
(MITM upstream TLS). The classifier is deliberately regex-based and
explicit — no external UA-parser dep — because the distinctions we need
are coarse (engine family only) and Playwright only ships three engines
anyway.
"""

from __future__ import annotations

import re


# Pre-compiled regexes. Order matters: check the most-specific first
# because Chrome UAs also contain "Safari" (historical AppleWebKit
# heritage) and Edge UAs contain "Chrome".
_EDGE_RE = re.compile(r"\bEdg(?:A|iOS)?/(\d+)", re.IGNORECASE)
_FIREFOX_RE = re.compile(r"\bFirefox/(\d+)", re.IGNORECASE)
_SAFARI_ONLY_RE = re.compile(r"\bVersion/(\d+)[^ ]*\s+(?:Mobile/\S+\s+)?Safari",
                              re.IGNORECASE)
_CHROME_RE = re.compile(r"\bChrome/(\d+)", re.IGNORECASE)


def _is_firefox(ua: str) -> int | None:
    m = _FIREFOX_RE.search(ua or "")
    return int(m.group(1)) if m else None


def _is_edge(ua: str) -> int | None:
    m = _EDGE_RE.search(ua or "")
    return int(m.group(1)) if m else None


def _is_chrome(ua: str) -> int | None:
    # Excludes Edge (which also contains "Chrome/..."). Caller must check
    # _is_edge first.
    m = _CHROME_RE.search(ua or "")
    return int(m.group(1)) if m else None


def _is_safari(ua: str) -> int | None:
    # Safari proper: "Version/X" + "Safari" without "Chrome" / "Chromium" /
    # "Edg" / "Firefox". iOS apps and niche webkit browsers often ship as
    # Safari too — treat them the same.
    if not ua:
        return None
    if _is_chrome(ua) or _is_edge(ua) or _is_firefox(ua):
        return None
    m = _SAFARI_ONLY_RE.search(ua)
    return int(m.group(1)) if m else None


def ua_to_playwright_engine(ua: str) -> tuple[str, str | None]:
    """Return (engine_family, channel_or_None) for Playwright.

    engine_family is one of "chromium", "firefox", "webkit". channel is
    set to "msedge" only when the UA clearly identifies Edge — so when
    the operator picks an Edge-family device we launch the real Edge
    channel on top of Chromium, preserving the Edge TLS extensions.
    """
    if not ua:
        return ("chromium", None)
    if _is_firefox(ua):
        return ("firefox", None)
    if _is_edge(ua):
        return ("chromium", "msedge")
    if _is_safari(ua):
        return ("webkit", None)
    # Chrome, Chromium, Opera, Brave, generic Chromium forks — all
    # share the Chromium JA3 shape.
    return ("chromium", None)


# curl_cffi impersonation tags. Kept to targets present in the current
# curl_cffi release; caller handles the "target not available" error by
# falling back to the stock path.
_IMP_CHROME = [
    (124, "chrome124"), (123, "chrome123"), (120, "chrome120"),
    (119, "chrome119"), (116, "chrome116"), (110, "chrome110"),
    (107, "chrome107"), (104, "chrome104"), (101, "chrome101"),
    (100, "chrome100"), (99, "chrome99"),
]
_IMP_EDGE = [(101, "edge101"), (99, "edge99")]
_IMP_SAFARI = [(17, "safari17_0"), (16, "safari15_5"), (15, "safari15_5")]
_IMP_FIREFOX = [(133, "firefox133"), (120, "firefox120"), (117, "firefox117")]


def _closest(major: int, table: list[tuple[int, str]]) -> str:
    """Pick the curl_cffi tag whose major version is closest to `major`
    without going over — falls back to the oldest tag if `major` is too
    old for any bundled target."""
    for ver, tag in table:
        if major >= ver:
            return tag
    return table[-1][1]


def ua_to_impersonate_target(ua: str) -> str | None:
    """Map a UA to the best curl_cffi `impersonate=` tag, or None when
    the UA is not recognised."""
    if not ua:
        return None
    edge = _is_edge(ua)
    if edge is not None:
        return _closest(edge, _IMP_EDGE)
    ff = _is_firefox(ua)
    if ff is not None:
        return _closest(ff, _IMP_FIREFOX)
    if _is_safari(ua) is not None:
        return _closest(_is_safari(ua) or 17, _IMP_SAFARI)
    ch = _is_chrome(ua)
    if ch is not None:
        return _closest(ch, _IMP_CHROME)
    return None
