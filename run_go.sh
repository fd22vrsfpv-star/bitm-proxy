#!/bin/bash
# Hybrid build: Python control plane + Go proxy daemon, single container.
#
# The Go binary runs the reverse, auth, and test proxies.
# Python still runs the main app, debug dashboard, RAG API, and browser
# automation — plus exposes /_internal/* endpoints the Go daemon calls.
#
# To go back to pure-Python, use ./run.sh instead.

set -e

IMAGE=mitm-proxy-hybrid
CONTAINER=mitm-proxy
VOLUME=mitm-proxy-data

docker rm -f "$CONTAINER" 2>/dev/null || true
docker build -f Dockerfile.hybrid -t "$IMAGE" .
docker run --name "$CONTAINER" \
    -p 8091:8091 -p 8092:8092 \
    -p 8000:8000 \
    -p 8085:8085 \
    -p 3100-3199:3100-3199 \
    -v "$VOLUME":/data \
    -e REQUIRE_API_KEY=false \
    -e INTERNAL_SECRET=dev-internal-secret \
    -it "$IMAGE"
