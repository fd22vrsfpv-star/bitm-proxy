"""Self-test suite surfaced as a Settings → Diagnostics tab.

Each check returns a record:
    {"name": str, "status": "ok" | "warn" | "fail", "message": str, "detail": str}

Checks are cheap and read-only — safe to run anytime.
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from pathlib import Path
from typing import Any

import httpx


def _ok(name: str, message: str, detail: str = "") -> dict:
    return {"name": name, "status": "ok", "message": message, "detail": detail}


def _warn(name: str, message: str, detail: str = "") -> dict:
    return {"name": name, "status": "warn", "message": message, "detail": detail}


def _fail(name: str, message: str, detail: str = "") -> dict:
    return {"name": name, "status": "fail", "message": message, "detail": detail}


def _port_listening(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


async def _http_get(url: str, timeout: float = 3.0) -> tuple[int | None, str]:
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
            resp = await client.get(url)
            return resp.status_code, resp.text[:500]
    except Exception as e:
        return None, str(e)


async def check_control_plane() -> dict:
    # If this is running, the debug server is up. Sanity-check :8092.
    status, _ = await _http_get("http://127.0.0.1:8092/health")
    if status == 200:
        return _ok("Control plane (:8092)", "debug dashboard is reachable")
    return _fail("Control plane (:8092)", f"unexpected status {status}")


async def check_main_app() -> dict:
    status, _ = await _http_get("http://127.0.0.1:8091/health")
    if status == 200:
        return _ok("Main app (:8091)", "Playwright UI server responding")
    return _fail("Main app (:8091)", f"unreachable / status {status}")


async def check_rag_api() -> dict:
    status, body = await _http_get("http://127.0.0.1:8000/health")
    if status == 200:
        return _ok("RAG API (:8000)",
                   "built-in RAG endpoint is up (Burp extension target)",
                   body[:200])
    return _warn("RAG API (:8000)",
                 "not reachable — not fatal unless you use the Burp extension",
                 str(status))


async def check_auth_proxy() -> dict:
    from backend.auth_proxy import get_auth_proxy_status
    st = get_auth_proxy_status()
    if not st.get("running"):
        return _warn(
            "Auth proxy",
            "not running — click Settings → Proxy → Start Auth Proxy",
            "Waiting for user to start the proxy is expected on first boot.")
    port = st.get("port")
    # Re-verify by actually connecting
    live = _port_listening("127.0.0.1", port) if port else False
    if not live:
        return _fail(
            "Auth proxy",
            f"status says running on :{port} but nothing accepts connections there",
            "Try clicking Stop then Start again in the Proxy tab.")
    return _ok(
        "Auth proxy",
        f"running on :{port}  bitm={st.get('bitm_enabled')}  "
        f"requests={st.get('request_count', 0)}  "
        f"injections={st.get('inject_count', 0)}",
        f"ca_cert_path={st.get('ca_cert_path')}")


async def check_go_daemon() -> dict:
    """Hybrid build: Go daemon runs reverse proxy and test proxy."""
    # Reverse proxy on :8085
    rp = _port_listening("127.0.0.1", 8085)
    tp = _port_listening("127.0.0.1", 3129)
    if rp and tp:
        return _ok("Go daemon", "reverse proxy (:8085) + test proxy (:3129) listening")
    if not rp and not tp:
        return _warn("Go daemon", "neither :8085 nor :3129 is listening",
                     "Pure-Python build is expected; hybrid should have both.")
    return _warn("Go daemon",
                 f"partial — :8085 {'UP' if rp else 'DOWN'}, :3129 {'UP' if tp else 'DOWN'}")


async def check_ca_cert() -> dict:
    from backend.paths import data_dir
    ca_path = data_dir() / "proxy_ca" / "ca.crt"
    if not ca_path.exists():
        return _warn(
            "BITM CA cert",
            "not generated yet — starts the first time the auth proxy runs",
            str(ca_path))
    try:
        size = ca_path.stat().st_size
    except Exception:
        size = 0
    return _ok("BITM CA cert", f"present at {ca_path}",
                f"{size} bytes · install as a trusted root for silent HTTPS BITM")


async def check_data_dir() -> dict:
    from backend.paths import data_dir
    d = data_dir()
    if not d.exists():
        return _fail("Data directory", f"missing: {d}")
    if not os.access(d, os.W_OK):
        return _fail("Data directory", f"not writable: {d}")
    return _ok("Data directory", f"{d}  (writable)",
                f"usage: {_dir_bytes(d):,} bytes")


def _dir_bytes(path: Path) -> int:
    total = 0
    try:
        for p in path.rglob("*"):
            try:
                if p.is_file():
                    total += p.stat().st_size
            except Exception:
                continue
    except Exception:
        pass
    return total


async def check_playwright() -> dict:
    """Playwright chromium browser binary should be present."""
    browsers_dir = Path("/root/.cache/ms-playwright")
    if not browsers_dir.exists():
        browsers_dir = Path.home() / ".cache/ms-playwright"
    if not browsers_dir.exists():
        return _warn("Playwright browsers",
                     f"cache dir not found ({browsers_dir}); first session may download",
                     "")
    entries = [p.name for p in browsers_dir.iterdir() if p.is_dir()]
    chromium = [e for e in entries if "chromium" in e.lower()]
    if not chromium:
        return _fail("Playwright browsers",
                     "no chromium binary in cache",
                     f"found: {entries}")
    return _ok("Playwright browsers",
                f"chromium present: {', '.join(chromium)}",
                f"cache: {browsers_dir}")


async def check_active_sessions() -> dict:
    from backend.shared import get_active_sessions
    sessions = get_active_sessions()
    if not sessions:
        return _warn("Active Playwright sessions",
                     "none — open http://localhost:8091/ to start one",
                     "proxy_via_playwright requires an active session")
    lines = [f"{sid} → {info.get('login_url', '?')}"
             for sid, info in sessions.items()]
    return _ok("Active Playwright sessions",
                f"{len(sessions)} active",
                "\n".join(lines))


async def check_flow_buffer() -> dict:
    from backend.shared import _session_flows
    count = sum(len(buf) for buf in _session_flows.values())
    return _ok("Flow tracer buffer",
                f"{count} entries across {len(_session_flows)} sessions",
                "cap is 2000/session")


async def check_ollama() -> dict:
    from backend.shared import get_config_value
    if not get_config_value("ollama_enabled", False):
        return _warn("Ollama", "disabled in config — skipping check")
    try:
        from backend.ollama_hook import test_connection
        result = await test_connection()
        if result.get("ok"):
            found = result.get("model_found", False)
            if found:
                return _ok("Ollama",
                           f"reachable at {result.get('url')}; "
                           f"model {result.get('configured_model')} available",
                           f"{len(result.get('models', []))} total models")
            return _warn("Ollama",
                          f"reachable but model "
                          f"'{result.get('configured_model')}' not found",
                          f"available: {', '.join(result.get('models', []))}")
        return _fail("Ollama", result.get("error", "unknown error"))
    except Exception as e:
        return _fail("Ollama", str(e))


async def check_rag_config() -> dict:
    from backend.shared import get_config_value
    if not get_config_value("rag_enabled", False):
        return _warn("RAG bridge", "disabled in config — Send to RAG inactive")
    url = (get_config_value("rag_api_url", "") or "").rstrip("/")
    if not url:
        return _fail("RAG bridge", "rag_enabled but rag_api_url is empty")
    status, body = await _http_get(f"{url}/health")
    if status == 200:
        return _ok("RAG bridge", f"reachable at {url}", body[:200])
    return _fail("RAG bridge", f"unreachable at {url}", str(status))


async def check_port_publishing() -> dict:
    """Note: this runs INSIDE the container — we can only check local sockets,
    not whether Docker -p mappings are set. We list expected ports and their
    state from the container's POV so the user can cross-check with run.sh."""
    ports = {
        8091: "main app",
        8092: "debug dashboard",
        8000: "RAG API",
        8085: "reverse proxy (Go)",
        3129: "test proxy (Go)",
    }
    proxy_ports_to_check = [3128, 3130]
    results: list[str] = []
    for p, label in ports.items():
        live = _port_listening("127.0.0.1", p)
        results.append(f"{'UP' if live else 'DOWN':>4}  :{p}  {label}")
    for p in proxy_ports_to_check:
        live = _port_listening("127.0.0.1", p)
        if live:
            results.append(f"  UP  :{p}  auth proxy (published range 3100-3199)")
    return _ok("Container ports (listening)",
                f"{sum(1 for line in results if line.strip().startswith('UP'))} "
                f"of {len(ports) + len(proxy_ports_to_check)} checked",
                "\n".join(results))


async def check_config_coherence() -> dict:
    from backend.shared import get_config_value, get_active_sessions
    issues: list[str] = []

    if get_config_value("proxy_via_playwright", False):
        if not get_active_sessions():
            issues.append(
                "proxy_via_playwright is ON but no Playwright session is active — "
                "proxy requests will fall through to direct fetch.")

    if get_config_value("ollama_enabled", False):
        if not get_config_value("ollama_url", ""):
            issues.append("ollama_enabled is ON but ollama_url is empty.")

    if get_config_value("rag_enabled", False):
        if not get_config_value("rag_api_url", ""):
            issues.append("rag_enabled is ON but rag_api_url is empty.")

    if not get_config_value("default_login_url", ""):
        issues.append(
            "default_login_url is empty — :8091 won't auto-launch a session.")

    if not issues:
        return _ok("Config coherence", "no obvious misconfigurations")
    return _warn("Config coherence",
                  f"{len(issues)} potential issue(s)",
                  "\n".join(f"• {i}" for i in issues))


async def run_all_checks() -> list[dict]:
    """Run every check concurrently and return results."""
    checks = [
        check_control_plane(),
        check_main_app(),
        check_rag_api(),
        check_auth_proxy(),
        check_go_daemon(),
        check_ca_cert(),
        check_data_dir(),
        check_playwright(),
        check_active_sessions(),
        check_flow_buffer(),
        check_ollama(),
        check_rag_config(),
        check_port_publishing(),
        check_config_coherence(),
    ]
    results = await asyncio.gather(*checks, return_exceptions=True)
    out: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            out.append(_fail("Check failed", f"{type(r).__name__}: {r}"))
        else:
            out.append(r)
    return out
