#!/bin/bash
# Stop (and optionally remove) bitm-proxy Docker deployments — both the
# single-container `docker run` install (README) and the docker-compose
# DEF CON lab stack (docker-compose.yml / run_demo.sh). Safe to run
# regardless of which one (if either) is actually up.
#
# Flags:
#   --rm        After stopping the single container, also `docker rm -f` it
#               so the name is free.
#   --volumes   After stopping the compose lab stack, also remove its
#               volumes (docker compose down -v) — wipes captured data,
#               the CA cert, and the generated lab password/self-signed
#               cert, so the next start regenerates everything from
#               scratch. Off by default so a routine stop doesn't lose state.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CONTAINER="${CONTAINER:-bitm-proxy}"
REMOVE=0
VOLUMES=0
for arg in "$@"; do
    case "$arg" in
        --rm)      REMOVE=1 ;;
        --volumes) VOLUMES=1 ;;
        -h|--help)
            sed -n '2,14p' "$0"; exit 0 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "⚠  docker not on PATH — nothing to do."
    exit 0
fi

# ── Single-container install (docker run, per README) ────────────────────
STATE="$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || true)"
if [ -z "$STATE" ]; then
    echo "   No single container named '$CONTAINER'."
else
    if [ "$STATE" = "running" ]; then
        echo "==> Stopping container '$CONTAINER' (state=$STATE)"
        docker stop "$CONTAINER" >/dev/null
    else
        echo "   Container '$CONTAINER' is already $STATE."
    fi
    if [ "$REMOVE" = 1 ]; then
        echo "==> Removing container '$CONTAINER'"
        docker rm -f "$CONTAINER" >/dev/null
    fi
fi

# ── docker-compose DEF CON lab stack (app + nginx) ────────────────────────
if [ -f "$SCRIPT_DIR/docker-compose.yml" ]; then
    if (cd "$SCRIPT_DIR" && docker compose ps -q 2>/dev/null | grep -q .); then
        if [ "$VOLUMES" = 1 ]; then
            echo "==> Stopping the lab stack and removing its volumes (docker compose down -v)"
            echo "    Captured data, CA cert, and the lab password/self-signed cert will"
            echo "    be regenerated from scratch on the next start."
            (cd "$SCRIPT_DIR" && docker compose down -v)
        else
            echo "==> Stopping the lab stack (docker compose down)"
            (cd "$SCRIPT_DIR" && docker compose down)
        fi
    else
        echo "   Lab stack (docker compose) is not running."
    fi
fi

echo
echo "==> Current containers matching 'bitm' or 'bitm'"
docker ps -a --filter name=bitm --filter name=bitm --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -10

echo
echo "==> Port listeners on host for bitm-proxy / lab ports"
lsof -iTCP:80 -iTCP:443 -iTCP:3128 -iTCP:3129 -iTCP:8000 -iTCP:8085 -iTCP:8091 -iTCP:8092 -sTCP:LISTEN 2>/dev/null || echo "   (none)"
