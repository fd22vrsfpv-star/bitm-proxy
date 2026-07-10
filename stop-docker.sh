#!/bin/bash
# Stop (and optionally remove) the mitm-proxy Docker container.
#
# Flags:
#   --rm   After stopping, also `docker rm -f` the container so the name is free.

set -u

CONTAINER="${CONTAINER:-mitm-proxy}"
REMOVE=0
for arg in "$@"; do
    case "$arg" in
        --rm) REMOVE=1 ;;
        -h|--help)
            sed -n '2,9p' "$0"; exit 0 ;;
    esac
done

if ! command -v docker >/dev/null 2>&1; then
    echo "⚠  docker not on PATH — nothing to do."
    exit 0
fi

STATE="$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || true)"
if [ -z "$STATE" ]; then
    echo "   No container named '$CONTAINER'."
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

echo
echo "==> Current containers matching 'mitm'"
docker ps -a --filter name=mitm --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -10

echo
echo "==> Port listeners on host for mitm-proxy ports"
lsof -iTCP:3128 -iTCP:3129 -iTCP:8000 -iTCP:8085 -iTCP:8091 -iTCP:8092 -sTCP:LISTEN 2>/dev/null || echo "   (none)"
