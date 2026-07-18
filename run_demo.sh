#!/bin/bash
# Run the DEF CON RTV lab (bitm-proxy + nginx) via docker-compose.
# See docs/DEFCON-LAB-SETUP.md for the full runbook.
#
# No login gate — anyone who reaches the URL can use the lab. Safety comes
# from the proxy_allowed_hosts / phantom_join_allowed_domains allowlists
# (populate these before using --public), not authentication.
#
# Quick start (safe default — loopback only, self-signed cert):
#   ./run_demo.sh
#
# Flags:
#   --public   Bind on 0.0.0.0 instead of loopback-only. Only use this on a
#              host you intend to be publicly reachable, with a real domain
#              pointed at it and a real cert mounted (see the runbook) —
#              this is the organizer/public-instance flag, not the default
#              self-hosted path.
#   --rebuild  Force a fresh image build (docker compose up --build).
#   --logs     Tail logs from both containers after starting.
#   --stop     Stop and remove the stack (docker compose down).
#   -h|--help  Show this header.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PUBLIC=0
REBUILD=0
LOGS=0
STOP=0
for arg in "$@"; do
    case "$arg" in
        --public)  PUBLIC=1 ;;
        --rebuild) REBUILD=1 ;;
        --logs)    LOGS=1 ;;
        --stop)    STOP=1 ;;
        -h|--help)
            sed -n '2,21p' "$0"; exit 0 ;;
        *)
            echo "Unknown flag: $arg (see --help)"; exit 1 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "✗ docker not found on PATH. Install Docker Desktop (macOS/Windows) or"
    echo "  Docker Engine + the compose plugin (Linux), then re-run this script."
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "✗ Docker is installed but not running. Start Docker Desktop / the"
    echo "  docker daemon, then re-run this script."
    exit 1
fi

if [ "$STOP" = 1 ]; then
    echo "==> Stopping the lab stack"
    docker compose down
    exit 0
fi

if [ "$PUBLIC" = 1 ]; then
    echo "⚠  --public: binding on 0.0.0.0. Only do this on a host you intend"
    echo "   to be publicly reachable — see docs/DEFCON-LAB-SETUP.md before"
    echo "   using this for anything other than the organizer-run instance."
    echo "⚠  There is no login gate on this stack — anyone who reaches the URL"
    echo "   can use it. Safety comes entirely from proxy_allowed_hosts /"
    echo "   phantom_join_allowed_domains being populated before you expose this."
    export BIND_HOST=0.0.0.0
fi

BUILD_FLAG=""
[ "$REBUILD" = 1 ] && BUILD_FLAG="--build"

# ── Dashboard JS syntax check (best-effort) ──────────────────────────────────
# The whole :8092 dashboard is one inline <script> in
# backend/debug_server.py; a single syntax error there silently kills it --
# the page still 200s but nothing runs and the WebSockets never connect.
# Check it before building the image. Needs python3 + node on the host,
# which the Docker-only path doesn't otherwise require, so it's best-effort:
# skipped when they aren't present (a pure operator isn't editing the code).
if [ "$REBUILD" = 1 ] && command -v python3 >/dev/null 2>&1 && command -v node >/dev/null 2>&1; then
    echo "==> Checking dashboard JS"
    python3 "$SCRIPT_DIR/scripts/check_dashboard_js.py" || {
        echo "✗ dashboard JS check failed -- fix backend/debug_server.py before building." >&2
        exit 1
    }
fi

# Base images default to UTC; auto-detect the host's IANA zone so
# container log timestamps (docker logs, All Logs tab, phantom-log) read
# the same as this terminal. /etc/localtime bind-mounting into the
# container (docker-compose.yml) is a best-effort backstop but doesn't
# reliably resolve through Docker Desktop's file sharing on every host —
# confirmed live on macOS — so TZ is the one that actually has to work.
if [ -z "${TZ:-}" ]; then
    if [ -r /etc/timezone ]; then
        TZ="$(cat /etc/timezone)"
    elif [ -L /etc/localtime ]; then
        TZ="$(readlink /etc/localtime | sed 's#.*/zoneinfo/##')"
    fi
    export TZ
fi
[ -n "${TZ:-}" ] && echo "==> Container time zone: $TZ"

echo "==> Starting the lab stack (this can take a while the first time —"
echo "    building the app image, installing Playwright's Chromium, etc.)"
docker compose up $BUILD_FLAG -d

HOST="${BIND_HOST:-127.0.0.1}"
echo "==> Waiting for nginx to become reachable at https://$HOST/ ..."
READY=0
for _ in $(seq 1 30); do
    if curl -sk --max-time 2 "https://$HOST/" -o /dev/null; then
        READY=1
        break
    fi
    sleep 2
done

if [ "$READY" = 0 ]; then
    echo "⚠  Didn't see a response yet — it may still be starting. Check with:"
    echo "     docker compose logs -f"
else
    echo "✓  Lab is up: https://$HOST/"
fi

echo
echo "Open https://$HOST/ in your browser (click through the self-signed"
echo "cert warning if you didn't mount a real one — expected for local use)."

if [ "$READY" = 1 ]; then
    if command -v open >/dev/null 2>&1; then
        open "https://$HOST/" 2>/dev/null || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "https://$HOST/" 2>/dev/null || true
    fi
fi

if [ "$LOGS" = 1 ]; then
    echo
    echo "==> Tailing logs (Ctrl-C to stop tailing — the stack keeps running)"
    docker compose logs -f
fi
