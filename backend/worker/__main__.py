"""Worker subprocess entry point — run as `python -m backend.worker --socket PATH --id N`.

The parent (dispatcher) spawns one of these per worker slot. The worker
connects back to the parent-supplied Unix-domain socket, advertises
capacity, and then processes commands forwarded by the parent.

This is the skeleton — it accepts `ping`, `info`, and `shutdown` commands
and echoes back. Session-related commands (`launch`, `click`, `type`,
`close`) are introduced in the next commit, along with the Playwright
bridge itself. Keeping this commit scoped to infrastructure so the
existing single-process session path is untouched.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time

from backend.worker.rpc import send_frame, iter_frames


async def _run(socket_path: str, worker_id: int, cap: int) -> int:
    # Connect to the parent dispatcher.
    try:
        r, w = await asyncio.open_unix_connection(socket_path)
    except Exception as e:
        print(f"[worker-{worker_id}] connect {socket_path} failed: {e}",
              file=sys.stderr, flush=True)
        return 1

    # Announce ourselves.
    await send_frame(w, {
        "type": "hello",
        "worker_id": worker_id,
        "pid": os.getpid(),
        "capacity": cap,
        "started_at": time.time(),
    })

    stop = asyncio.Event()

    # Graceful shutdown on SIGTERM / SIGINT.
    def _sig(*_):
        stop.set()
    for s in (signal.SIGTERM, signal.SIGINT):
        try:
            asyncio.get_running_loop().add_signal_handler(s, _sig)
        except (NotImplementedError, RuntimeError):
            pass

    # Periodic heartbeat so the parent can detect a hung worker.
    async def _heartbeat():
        while not stop.is_set():
            await asyncio.sleep(5)
            await send_frame(w, {"type": "heartbeat",
                                 "worker_id": worker_id,
                                 "ts": time.time()})
    hb_task = asyncio.create_task(_heartbeat())

    try:
        async for msg in iter_frames(r):
            t = msg.get("type", "")
            if t == "ping":
                await send_frame(w, {"type": "pong",
                                     "worker_id": worker_id,
                                     "req_id": msg.get("req_id")})
            elif t == "info":
                await send_frame(w, {"type": "info_result",
                                     "worker_id": worker_id,
                                     "pid": os.getpid(),
                                     "sessions": [],   # populated in commit 2
                                     "capacity": cap,
                                     "req_id": msg.get("req_id")})
            elif t == "shutdown":
                break
            else:
                # Forward-compat: next commit adds session-scoped commands.
                await send_frame(w, {"type": "error",
                                     "req_id": msg.get("req_id"),
                                     "error": f"unknown command {t!r}"})
    except Exception as e:
        print(f"[worker-{worker_id}] loop exited: {e}",
              file=sys.stderr, flush=True)
    finally:
        hb_task.cancel()
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True,
                    help="Parent dispatcher's Unix-domain socket path")
    ap.add_argument("--id", type=int, required=True,
                    help="Worker slot id assigned by the dispatcher")
    ap.add_argument("--capacity", type=int, default=5,
                    help="Max concurrent sessions this worker will host")
    args = ap.parse_args()
    return asyncio.run(_run(args.socket, args.id, args.capacity))


if __name__ == "__main__":
    sys.exit(main())
