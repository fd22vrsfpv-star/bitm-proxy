"""Phantom Join — dashboard launcher for `tools/phantom_runner.py`.

WS endpoint at /api/phantom/run accepts a `start` message with
form-shaped params (username, password, domain, device_name, intune
toggle + extras, dry_run, start_phase, stop_phase, force), spawns the
runner as a subprocess under $DATA_DIR/phantom/<ts>/, and streams
stdout line-by-line back to the dashboard.

Single concurrent run is enforced via a process-wide lock — a second
`start` while one is active is rejected with `{type: "busy"}`. The WS
also accepts `{cmd: "stop"}` which sends SIGTERM (then SIGKILL after
5s) to the running subprocess.

Authorization:
  - Standard API key required (verify_ws_key on connect).
  - The `allow_phantom_join` config flag must be true. False = the
    `start` command returns `{type: "denied"}` without spawning.
  - If `phantom_join_allowed_domains` is non-empty, the requested
    `domain` must be in it (case-insensitive exact match) or the
    `start` command returns `{type: "denied"}` without spawning. Empty
    (the default) is unrestricted, matching today's behavior — this is
    opt-in hardening for deployments (e.g. a publicly-reachable lab
    instance) that must not run against an arbitrary real tenant.
  - Password is delivered to the runner via env var (PHANTOM_PASSWORD)
    so it never appears on the spawned process's argv (i.e. not
    visible to `ps`).

Output artifacts:
  - $DATA_DIR/phantom/<ts>/phantom_join_<ts>/ — the runner's own
    work_dir (logs + findings + roadrecon DB live there).
  - The findings JSON is read on subprocess exit and sent on the WS
    as `{type: "done", findings: [...], work_dir, exit_code}`.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.auth import verify_ws_key
from backend.paths import data_dir
from backend.shared import append_log, get_config_value


router = APIRouter()


# ── ANSI strip ────────────────────────────────────────────────────────
# phantom_join uses \033[91m / \033[92m / \033[93m / \033[90m for color.
# Strip before fanning out to the WS so the dashboard sees clean text.
_ANSI_RE = re.compile(rb"\x1b\[[0-9;]*m")


def _strip_ansi(b: bytes) -> str:
    try:
        return _ANSI_RE.sub(b"", b).decode("utf-8", errors="replace")
    except Exception:
        return b.decode("utf-8", errors="replace")


# ── Single-run lock + state ───────────────────────────────────────────
_run_lock = asyncio.Lock()
_active: dict = {
    "process": None,        # asyncio.subprocess.Process | None
    "work_dir": None,       # Path | None — the per-run dir (parent of phantom_join_<ts>/)
    "started_at": 0.0,
    "owner_ws": None,       # the WS that initiated the run; gets exclusive control
}


def _phantom_root() -> Path:
    d = data_dir() / "phantom"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _is_busy() -> bool:
    p = _active.get("process")
    return p is not None and p.returncode is None


def _phase_event_from_line(line: str) -> Optional[dict]:
    """Recognise the `=== PHASE N: NAME ===` header phantom_join.Logger
    emits and emit a structured event so the UI can render a phase
    progress bar without parsing the whole stream."""
    m = re.match(r"^\s*PHASE\s+(\d+):\s+(.+?)\s*$", line)
    if m:
        try:
            return {"type": "phase",
                    "num": int(m.group(1)),
                    "name": m.group(2).strip()}
        except ValueError:
            return None
    return None


def _read_findings(work_dir: Path) -> list[dict]:
    """phantom_join.Logger writes findings_<ts>.json under work_dir/logs/.
    Pick the newest one (handles re-run within same dir, though the
    runner currently never does)."""
    logs = work_dir / "logs"
    if not logs.is_dir():
        return []
    candidates = sorted(logs.glob("findings_*.json"))
    if not candidates:
        return []
    try:
        return json.loads(candidates[-1].read_text(encoding="utf-8"))
    except Exception:
        return []


def _safe_str(v) -> str:
    return str(v).strip() if v is not None else ""


async def _spawn_runner(params: dict, run_dir: Path) -> asyncio.subprocess.Process:
    """Build the env, spawn `python -m tools.phantom_runner`, return the
    Process. cwd is set to `run_dir` so phantom_join's `--output-dir`
    lands every artifact under our scoped path."""
    env = os.environ.copy()
    # Required
    env["PHANTOM_USERNAME"] = _safe_str(params.get("username"))
    env["PHANTOM_PASSWORD"] = _safe_str(params.get("password"))
    env["PHANTOM_DOMAIN"] = _safe_str(params.get("domain"))
    # Optional
    if params.get("device_name"):
        env["PHANTOM_DEVICE_NAME"] = _safe_str(params["device_name"])
    if params.get("device_type"):
        env["PHANTOM_DEVICE_TYPE"] = _safe_str(params["device_type"])
    if params.get("os_version"):
        env["PHANTOM_OS_VERSION"] = _safe_str(params["os_version"])
    if params.get("intune"):
        env["PHANTOM_INTUNE"] = "1"
    if params.get("intune_host"):
        env["PHANTOM_INTUNE_HOST"] = _safe_str(params["intune_host"])
    if params.get("hybrid_domain"):
        env["PHANTOM_HYBRID_DOMAIN"] = _safe_str(params["hybrid_domain"])
    if params.get("start_phase"):
        env["PHANTOM_START_PHASE"] = _safe_str(params["start_phase"])
    if params.get("stop_phase"):
        env["PHANTOM_STOP_PHASE"] = _safe_str(params["stop_phase"])
    if params.get("force"):
        env["PHANTOM_FORCE"] = "1"
    if params.get("dry_run"):
        env["PHANTOM_DRY_RUN"] = "1"
    env["PHANTOM_OUTPUT_DIR"] = "."
    # The runner imports tools.phantom_join — make sure the repo root
    # is on PYTHONPATH so it resolves under the spawned interpreter.
    repo_root = Path(__file__).resolve().parents[2]
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{repo_root}{os.pathsep}{existing_pp}" if existing_pp
        else str(repo_root)
    )
    # Without this, CPython block-buffers stdout by default whenever it's
    # not a tty (i.e. always, here, since it's piped to this parent) — the
    # dashboard log/phase updates would arrive in delayed chunks instead of
    # per-line, which matters most for phantom_join.py's device-code phases
    # (tools/phantom_join.py run_cmd(..., stream=True)) where the operator
    # has a 120s window to act on a line the moment it's printed.
    env["PYTHONUNBUFFERED"] = "1"

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "tools.phantom_runner",
        cwd=str(run_dir),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,  # interleave so the dashboard sees one stream
    )
    return proc


@router.websocket("/run")
async def phantom_run_ws(ws: WebSocket):
    """Bidirectional channel for one Phantom Join run.

    Wire protocol (client → server):
      {"cmd": "start", "params": {...}}
      {"cmd": "stop"}

    Server → client:
      {"type": "log",     "line": "..."}    — every output line
      {"type": "phase",   "num": N, "name": "..."}
      {"type": "started", "work_dir": "...", "pid": N}
      {"type": "done",    "exit_code": N, "findings": [...], "work_dir": "..."}
      {"type": "error",   "message": "..."}
      {"type": "denied",  "reason": "..."}  — gate failed
      {"type": "busy"}                       — another run is active
    """
    if not verify_ws_key(ws):
        await ws.close(code=4001, reason="Invalid or missing API key")
        return
    await ws.accept()

    # The first message must be a start (or a stop, if the operator
    # is reconnecting just to abort an active run).
    try:
        first = await ws.receive_json()
    except (WebSocketDisconnect, Exception):
        return

    cmd = (first or {}).get("cmd")

    if cmd == "stop":
        await _handle_stop(ws)
        return

    if cmd != "start":
        await ws.send_json({"type": "error",
                            "message": f"unknown cmd: {cmd!r}"})
        await ws.close()
        return

    if not get_config_value("allow_phantom_join", False):
        await ws.send_json({"type": "denied",
                            "reason": "allow_phantom_join is off — enable in :8092 Settings"})
        await ws.close()
        return

    if _is_busy():
        await ws.send_json({"type": "busy"})
        await ws.close()
        return

    params = (first.get("params") or {}) if isinstance(first, dict) else {}
    if not params.get("username") or not params.get("password") \
            or not params.get("domain"):
        await ws.send_json({"type": "error",
                            "message": "username, password, domain are required"})
        await ws.close()
        return

    allowed_domains = get_config_value("phantom_join_allowed_domains", [])
    if allowed_domains:
        requested_domain = _safe_str(params.get("domain")).lower()
        if requested_domain not in {d.strip().lower() for d in allowed_domains if d}:
            await ws.send_json({"type": "denied",
                                "reason": f"domain {requested_domain!r} is not in "
                                          "phantom_join_allowed_domains"})
            await ws.close()
            return

    # Acquire the lock atomically — wraps spawn so a race on two
    # concurrent `start` arrivals can't both pass the _is_busy check.
    async with _run_lock:
        if _is_busy():
            await ws.send_json({"type": "busy"})
            await ws.close()
            return
        ts = time.strftime("%Y%m%d_%H%M%S")
        run_dir = _phantom_root() / ts
        run_dir.mkdir(parents=True, exist_ok=True)
        try:
            proc = await _spawn_runner(params, run_dir)
        except FileNotFoundError as e:
            await ws.send_json({"type": "error",
                                "message": f"could not spawn runner: {e}"})
            await ws.close()
            return
        _active["process"] = proc
        _active["work_dir"] = run_dir
        _active["started_at"] = time.time()
        _active["owner_ws"] = ws

    append_log("info", "phantom",
               f"PHANTOM_JOIN_START pid={proc.pid} "
               f"user={params.get('username')} domain={params.get('domain')} "
               f"dry_run={bool(params.get('dry_run'))} "
               f"work_dir={run_dir}")

    await ws.send_json({"type": "started",
                        "work_dir": str(run_dir),
                        "pid": proc.pid})

    # Two concurrent things from here:
    #   1. read subprocess stdout, fan out line-by-line over WS
    #   2. listen for `stop` from the same WS
    reader_task = asyncio.create_task(_pipe_stdout(proc, ws))
    listener_task = asyncio.create_task(_listen_for_stop(ws, proc))

    rc = await proc.wait()
    # Cancel the listener; the reader will drain on its own.
    listener_task.cancel()
    try:
        await reader_task
    except Exception:
        pass

    findings = _read_findings(_active["work_dir"] /
                              _newest_runner_dir(_active["work_dir"]))
    append_log("info", "phantom",
               f"PHANTOM_JOIN_DONE pid={proc.pid} exit_code={rc} "
               f"findings={len(findings)}")
    try:
        await ws.send_json({"type": "done",
                            "exit_code": rc,
                            "findings": findings,
                            "work_dir": str(_active["work_dir"])})
    except Exception:
        pass

    _active["process"] = None
    _active["work_dir"] = None
    _active["owner_ws"] = None
    try:
        await ws.close()
    except Exception:
        pass


async def _handle_stop(ws: WebSocket) -> None:
    """Operator reconnected just to send `stop` — useful when the
    initiating tab crashed or was closed but the run is still running."""
    proc = _active.get("process")
    if not proc or proc.returncode is not None:
        await ws.send_json({"type": "error", "message": "no active run"})
        await ws.close()
        return
    await _terminate(proc)
    await ws.send_json({"type": "stopped"})
    await ws.close()


async def _listen_for_stop(ws: WebSocket,
                            proc: asyncio.subprocess.Process) -> None:
    """Watch the same WS for a `{cmd: "stop"}` message during the run."""
    try:
        while True:
            msg = await ws.receive_json()
            if (msg or {}).get("cmd") == "stop":
                append_log("warn", "phantom",
                           f"PHANTOM_JOIN_STOP_REQ pid={proc.pid}")
                await _terminate(proc)
                return
    except (WebSocketDisconnect, Exception):
        # Client gone — kill the run so we don't leave a phantom (heh)
        # subprocess orphaned. Operator can reconnect to start fresh.
        if proc.returncode is None:
            append_log("warn", "phantom",
                       f"PHANTOM_JOIN_WS_DROPPED — terminating pid={proc.pid}")
            await _terminate(proc)


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    """SIGTERM, then SIGKILL after 5s if it hasn't exited."""
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


async def _pipe_stdout(proc: asyncio.subprocess.Process,
                       ws: WebSocket) -> None:
    """Forward each line of subprocess stdout to the WS as
    `{type: "log", line}`, plus emit a structured `phase` event when a
    PHASE header is seen."""
    if proc.stdout is None:
        return
    while True:
        try:
            raw = await proc.stdout.readline()
        except Exception:
            break
        if not raw:
            break
        line = _strip_ansi(raw).rstrip("\n").rstrip("\r")
        try:
            await ws.send_json({"type": "log", "line": line})
        except Exception:
            return
        ev = _phase_event_from_line(line)
        if ev is not None:
            try:
                await ws.send_json(ev)
            except Exception:
                return


def _newest_runner_dir(parent: Path) -> str:
    """phantom_join creates `phantom_join_<ts>/` under our `run_dir`.
    Return its name so we can read the findings file inside.
    Returns an empty string when nothing is found (e.g. early failure
    before the runner created its own dir)."""
    if not parent.is_dir():
        return ""
    for child in sorted(parent.iterdir(), reverse=True):
        if child.is_dir() and child.name.startswith("phantom_join_"):
            return child.name
    return ""


# ── Status endpoint (HTTP) — useful for cross-tab "is something running?" ──
@router.get("/status")
async def phantom_status():
    proc = _active.get("process")
    if proc is None or proc.returncode is not None:
        return {
            "running": False,
            "allow_phantom_join": bool(get_config_value("allow_phantom_join", False)),
        }
    return {
        "running": True,
        "pid": proc.pid,
        "started_at": _active.get("started_at", 0.0),
        "work_dir": str(_active.get("work_dir") or ""),
        "allow_phantom_join": bool(get_config_value("allow_phantom_join", False)),
    }
