"""Parent-side worker-pool dispatcher.

Owns a Unix-domain listening socket, spawns N worker subprocesses, keeps
per-worker state (pid, capacity, hosted sessions, heartbeat), and routes
session commands to the least-loaded worker.

This commit ships the pool infrastructure. Session routing lands in the
next commit — `launch_session` and `send_session_cmd` are stubbed to
return NotImplemented so the control plane can call them behind the
`workers_enabled` feature flag without hitting half-working code.

Usage shape:
    dispatcher = Dispatcher(socket_path="/tmp/bitm-pool.sock")
    await dispatcher.start(worker_count=4, capacity=5)
    # … control plane runs …
    await dispatcher.stop()
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.shared import append_log
from backend.worker.rpc import send_frame, iter_frames


@dataclass
class _WorkerConn:
    worker_id: int
    proc: subprocess.Popen
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    capacity: int = 5
    sessions: set[str] = field(default_factory=set)
    last_hb: float = 0.0
    # Per-req_id futures waiting for worker reply.
    pending: dict[str, asyncio.Future] = field(default_factory=dict)


class Dispatcher:
    """Owns the worker pool. Safe to instantiate before start()."""

    def __init__(self, socket_path: str | None = None) -> None:
        if socket_path is None:
            socket_path = str(Path(tempfile.gettempdir())
                              / f"bitm-pool-{os.getpid()}.sock")
        self.socket_path = socket_path
        self.workers: dict[int, _WorkerConn] = {}
        self._server: asyncio.base_events.Server | None = None
        self._started = False
        self._worker_count = 0
        self._capacity = 5
        self._next_worker_id = 0
        # Map sid → worker_id so we know which worker owns a given session.
        self._sid_to_worker: dict[str, int] = {}
        # Channels for per-sid events streamed from workers back up to whoever
        # is proxying (the /api/browser/session WS in commit 2).
        self._sid_queues: dict[str, asyncio.Queue] = {}
        # Short-lived: holds Popen handles between spawn() and the worker's
        # first frame so _on_worker_connect can pair them by worker_id.
        self._pending_procs: dict[int, subprocess.Popen] = {}

    # ── Lifecycle ────────────────────────────────────────────────

    async def start(self, worker_count: int = 4, capacity: int = 5) -> None:
        if self._started:
            return
        self._worker_count = worker_count
        self._capacity = capacity
        # Clean stale socket from a previous crashed run.
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception:
            pass
        self._server = await asyncio.start_unix_server(
            self._on_worker_connect, path=self.socket_path)
        try:
            os.chmod(self.socket_path, 0o600)
        except Exception:
            pass
        append_log("info", "dispatcher",
                   f"worker pool listening at {self.socket_path}")
        # Spawn the configured number of workers. Each connects back to
        # _on_worker_connect below.
        for _ in range(worker_count):
            self._spawn_worker(capacity)
        self._started = True

    def _spawn_worker(self, capacity: int) -> None:
        wid = self._next_worker_id
        self._next_worker_id += 1
        cmd = [
            sys.executable, "-m", "backend.worker",
            "--socket", self.socket_path,
            "--id", str(wid),
            "--capacity", str(capacity),
        ]
        env = dict(os.environ)
        # Workers mustn't try to set up their own uvicorn signal handlers.
        env["BITM_WORKER"] = "1"
        proc = subprocess.Popen(cmd, env=env,
                                 stdout=None, stderr=None,
                                 start_new_session=False)
        append_log("info", "dispatcher",
                   f"spawned worker {wid} pid={proc.pid} capacity={capacity}")
        # Connection is established asynchronously when the worker sends
        # its "hello"; see _on_worker_connect.
        self._next_worker_id = max(self._next_worker_id, wid + 1)
        # Temporarily stash the proc object so _on_worker_connect can pair it.
        self._pending_procs[wid] = proc

    async def _on_worker_connect(self, r: asyncio.StreamReader,
                                  w: asyncio.StreamWriter) -> None:
        # First frame must be a `hello`.
        try:
            hello = await asyncio.wait_for(iter_frames(r).__anext__(),
                                            timeout=10)
        except Exception as e:
            append_log("warn", "dispatcher",
                       f"worker connected without hello ({e}); closing")
            try:
                w.close()
            except Exception:
                pass
            return
        if hello.get("type") != "hello":
            append_log("warn", "dispatcher",
                       f"expected hello, got {hello.get('type')}; closing")
            try:
                w.close()
            except Exception:
                pass
            return
        wid = int(hello.get("worker_id", -1))
        if wid < 0:
            try:
                w.close()
            except Exception:
                pass
            return
        proc = self._pending_procs.pop(wid, None)
        conn = _WorkerConn(worker_id=wid, proc=proc, reader=r, writer=w,
                           capacity=int(hello.get("capacity", self._capacity)),
                           last_hb=time.time())
        self.workers[wid] = conn
        append_log("info", "dispatcher",
                   f"worker {wid} online pid={hello.get('pid')}")
        # Start the per-worker reader loop.
        asyncio.create_task(self._worker_loop(conn))

    async def _worker_loop(self, conn: _WorkerConn) -> None:
        try:
            async for frame in iter_frames(conn.reader):
                await self._handle_worker_frame(conn, frame)
        except Exception as e:
            append_log("warn", "dispatcher",
                       f"worker {conn.worker_id} reader errored: {e}")
        finally:
            await self._on_worker_disconnect(conn)

    async def _handle_worker_frame(self, conn: _WorkerConn,
                                    frame: dict[str, Any]) -> None:
        t = frame.get("type", "")
        if t == "heartbeat":
            conn.last_hb = time.time()
            return
        # Request/reply correlation via req_id.
        req_id = frame.get("req_id")
        if req_id and req_id in conn.pending:
            fut = conn.pending.pop(req_id)
            if not fut.done():
                fut.set_result(frame)
            return
        # Per-session event: forward to whoever is awaiting this sid.
        sid = frame.get("sid") or frame.get("session_id")
        if sid and sid in self._sid_queues:
            try:
                self._sid_queues[sid].put_nowait(frame)
            except asyncio.QueueFull:
                append_log("warn", "dispatcher",
                           f"sid queue full for {sid}; dropping {t}")
            return
        # Nothing matched — log and keep going.
        append_log("debug", "dispatcher",
                   f"unrouted frame from worker {conn.worker_id}: {t}")

    async def _on_worker_disconnect(self, conn: _WorkerConn) -> None:
        append_log("warn", "dispatcher",
                   f"worker {conn.worker_id} disconnected "
                   f"(hosted {len(conn.sessions)} session(s))")
        # Signal any per-sid queues that their worker died.
        for sid in list(conn.sessions):
            if sid in self._sid_queues:
                try:
                    self._sid_queues[sid].put_nowait(
                        {"type": "worker_died", "sid": sid,
                         "worker_id": conn.worker_id})
                except Exception:
                    pass
            self._sid_to_worker.pop(sid, None)
        self.workers.pop(conn.worker_id, None)
        # Fail any in-flight RPCs.
        for fut in conn.pending.values():
            if not fut.done():
                fut.set_exception(RuntimeError("worker disconnected"))
        conn.pending.clear()
        # Respawn if the pool hasn't been told to stop.
        if self._started and conn.proc and conn.proc.returncode not in (None, 0):
            append_log("info", "dispatcher",
                       f"respawning worker to replace {conn.worker_id}")
            self._spawn_worker(self._capacity)

    async def stop(self) -> None:
        self._started = False
        for conn in list(self.workers.values()):
            try:
                await send_frame(conn.writer, {"type": "shutdown"})
            except Exception:
                pass
        for conn in list(self.workers.values()):
            try:
                conn.writer.close()
            except Exception:
                pass
            if conn.proc is not None:
                try:
                    conn.proc.wait(timeout=5)
                except Exception:
                    try:
                        conn.proc.kill()
                    except Exception:
                        pass
        self.workers.clear()
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except Exception:
            pass

    # ── Request / reply ─────────────────────────────────────────

    async def rpc(self, worker_id: int, payload: dict[str, Any],
                   timeout: float = 10.0) -> dict[str, Any]:
        """Send a command to the given worker and await its reply. Pairs on
        `req_id`. Raises asyncio.TimeoutError if the worker doesn't reply."""
        conn = self.workers.get(worker_id)
        if conn is None:
            raise RuntimeError(f"no worker {worker_id}")
        req_id = uuid.uuid4().hex
        payload = {**payload, "req_id": req_id}
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        conn.pending[req_id] = fut
        await send_frame(conn.writer, payload)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            conn.pending.pop(req_id, None)
            raise

    # ── Session management (stubs — filled in next commit) ─────

    def least_loaded_worker(self) -> int | None:
        """Return the worker_id of the worker with the most free capacity.
        None if nothing is ready."""
        best: tuple[int, int] | None = None   # (free_slots, wid)
        for wid, conn in self.workers.items():
            free = conn.capacity - len(conn.sessions)
            if free <= 0:
                continue
            if best is None or free > best[0]:
                best = (free, wid)
        return best[1] if best else None

    async def launch_session(self, sid: str, **opts: Any) -> int:
        raise NotImplementedError("launch_session ships in the next commit")

    async def send_session_cmd(self, sid: str,
                                cmd: dict[str, Any]) -> None:
        raise NotImplementedError("send_session_cmd ships in the next commit")

    # ── Introspection ───────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        return {
            "worker_count": self._worker_count,
            "capacity": self._capacity,
            "socket_path": self.socket_path,
            "workers": [
                {"worker_id": c.worker_id,
                 "pid": c.proc.pid if c.proc else None,
                 "capacity": c.capacity,
                 "sessions": list(c.sessions),
                 "last_heartbeat": c.last_hb}
                for c in self.workers.values()
            ],
        }


# Module-level singleton — set by run.py at startup when workers_enabled.
_dispatcher: Dispatcher | None = None


def get_dispatcher() -> Dispatcher | None:
    return _dispatcher


def set_dispatcher(d: Dispatcher | None) -> None:
    global _dispatcher
    _dispatcher = d
