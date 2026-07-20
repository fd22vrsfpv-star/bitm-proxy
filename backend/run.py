"""Run both the main app and debug dashboard in a single process.

This ensures they share the same shared.py state (log buffer, config, sessions).
"""

import asyncio
import os
import sys
import uvicorn


async def main():
    host = os.environ.get("HOST", "127.0.0.1")
    main_port = int(os.environ.get("PORT", "8091"))
    debug_port = int(os.environ.get("DEBUG_PORT", "8092"))
    rag_port = int(os.environ.get("RAG_PORT", "8000"))
    rp_port = int(os.environ.get("RP_PORT", "8085"))

    # Initialize API key authentication
    from backend.auth import init_api_key
    from backend.paths import data_dir
    auth_disabled = os.environ.get("REQUIRE_API_KEY", "true").lower() in ("false", "0", "no")
    key = init_api_key()
    if not key and not auth_disabled:
        plaintext_path = data_dir() / ".api_key_plaintext"
        if plaintext_path.exists():
            key = plaintext_path.read_text().strip()
    qs = f"?api_key={key}" if key else ""
    print(f"\n{'=' * 60}", flush=True)
    if auth_disabled:
        print(f"  API key authentication DISABLED", flush=True)
    elif key:
        print(f"  API KEY: {key}", flush=True)
    print(f"  Main:    http://localhost:{main_port}/{qs}", flush=True)
    print(f"  Debug:   http://localhost:{debug_port}/{qs}", flush=True)
    print(f"  RAG API: http://localhost:{rag_port}/  (point Burp extension here)", flush=True)
    print(f"  Reverse Proxy: http://localhost:{rp_port}/  (authorized pentest use only)", flush=True)
    print(f"{'=' * 60}\n", flush=True)

    # Eagerly import every app module now so any ImportError / top-level
    # exception surfaces at the banner rather than getting swallowed by
    # asyncio.gather(return_exceptions=True) later. Previously a broken
    # import in backend.main left :8091 silently dark while :8000 came up.
    for mod_name in ("backend.main", "backend.debug_server",
                      "backend.rag_api", "backend.reverse_proxy"):
        try:
            import importlib
            importlib.import_module(mod_name)
        except Exception as e:
            import traceback
            print(f"[run] FATAL: cannot import {mod_name}: {type(e).__name__}: {e}",
                  flush=True)
            print(traceback.format_exc(), flush=True)
            print("[run] none of the Python services will bind; aborting.",
                  flush=True)
            return

    main_config = uvicorn.Config(
        "backend.main:app", host=host, port=main_port, log_level="info"
    )
    debug_config = uvicorn.Config(
        "backend.debug_server:app", host=host, port=debug_port, log_level="info"
    )
    rag_config = uvicorn.Config(
        "backend.rag_api:app", host=host, port=rag_port, log_level="info"
    )
    rp_config = uvicorn.Config(
        "backend.reverse_proxy:app", host=host, port=rp_port, log_level="info"
    )
    main_server = uvicorn.Server(main_config)
    debug_server = uvicorn.Server(debug_config)
    rag_server = uvicorn.Server(rag_config)
    rp_server = uvicorn.Server(rp_config)

    # Install signal handlers only once (from the main server)
    debug_server.install_signal_handlers = lambda: None
    rag_server.install_signal_handlers = lambda: None
    rp_server.install_signal_handlers = lambda: None

    # Watchdog — log a warning when any single callback holds the event
    # loop longer than the threshold. Helps catch sync file I/O under load.
    slow_ms = float(os.environ.get("SLOW_CALLBACK_MS", "100"))
    asyncio.get_running_loop().slow_callback_duration = slow_ms / 1000.0

    # Auto-start keep-alive if enabled
    from backend.keepalive import start_keepalive
    from backend.shared import get_config_value
    if get_config_value("keepalive_enabled", False):
        await start_keepalive()

    # Auto-start the auth proxy (BITM on :3128 by default) if enabled.
    if get_config_value("autostart_auth_proxy", True):
        try:
            from backend.auth_proxy import start_auth_proxy
            ap_port = int(get_config_value("autostart_auth_proxy_port", 3128))
            result = await start_auth_proxy(ap_port)
            print(f"[run] auth_proxy autostart: {result.get('message', result)}",
                  flush=True)
        except Exception as e:
            print(f"[run] auth_proxy autostart FAILED: {e!r}", flush=True)

    # Spin up the Playwright worker pool if enabled. When off, the existing
    # single-process session handler in routes/browser.py stays in charge.
    if get_config_value("workers_enabled", False):
        try:
            from backend.worker.dispatcher import Dispatcher, set_dispatcher
            wc = int(get_config_value("worker_count", 4))
            cap = int(get_config_value("worker_sessions_max", 5))
            d = Dispatcher()
            await d.start(worker_count=wc, capacity=cap)
            set_dispatcher(d)
            print(f"[run] worker pool: {wc} workers × {cap} sessions "
                  f"socket={d.socket_path}", flush=True)
        except Exception as e:
            print(f"[run] worker pool start FAILED: {e!r}", flush=True)

    async def _safe_serve(server, name, port):
        try:
            await server.serve()
        except (OSError, SystemExit) as e:
            print(f"[run] {name} FAILED to bind on port {port}: {e}",
                  flush=True)
            print(f"[run] {name} server stopped, other servers continue.",
                  flush=True)
        except BaseException as e:
            # Without this catch-all, an ImportError / AttributeError /
            # config-validation exception during app-module import gets
            # swallowed silently by asyncio.gather(return_exceptions=True),
            # so the user sees "8091 isn't listening" with no explanation.
            # Log the traceback so the actual cause is obvious.
            import traceback
            tb = traceback.format_exc()
            print(f"[run] {name} on port {port} CRASHED: "
                  f"{type(e).__name__}: {e}", flush=True)
            print(tb, flush=True)

    servers = [
        _safe_serve(main_server, "main", main_port),
        _safe_serve(debug_server, "debug", debug_port),
        _safe_serve(rag_server, "rag-api", rag_port),
    ]
    # When the Go daemon owns the reverse proxy, skip the Python one.
    if os.environ.get("DISABLE_PYTHON_REVPROXY", "").lower() not in ("1", "true", "yes"):
        servers.append(_safe_serve(rp_server, "reverse-proxy", rp_port))
    else:
        print("[run] Python reverse proxy disabled (DISABLE_PYTHON_REVPROXY set)",
              flush=True)

    # Restore persisted flow-trace sessions and start the debounced flusher so
    # captured flows survive a restart (see backend/shared.py flow persistence).
    from backend.shared import (load_persisted_flows, flush_flows_loop,
                                flush_dirty_flows)
    try:
        _n = load_persisted_flows()
        if _n:
            print(f"[run] restored {_n} persisted flow session(s)", flush=True)
    except Exception as _e:
        print(f"[run] flow restore failed: {_e}", flush=True)
    asyncio.create_task(flush_flows_loop())

    try:
        await asyncio.gather(*servers, return_exceptions=True)
    finally:
        # Final flush so the last <interval> seconds of flow aren't lost on exit.
        try:
            flush_dirty_flows()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
