#!/bin/bash
# Stop any locally-running mitm-proxy processes (Python control plane, Go
# daemon, lingering Playwright/Chromium workers). Safe to run anytime.

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> Inspecting"
BEFORE="$(pgrep -af 'backend\.run|'"$SCRIPT_DIR"'/\.local/mitm-proxies|headless_shell|playwright.*chromium' 2>/dev/null || true)"
if [ -z "$BEFORE" ]; then
    echo "   No local mitm-proxy processes found."
else
    echo "$BEFORE"
fi

# Step 1: graceful (SIGTERM) — let asyncio + playwright clean up
pkill -TERM -f 'backend\.run' 2>/dev/null || true
pkill -TERM -f "$SCRIPT_DIR/\.local/mitm-proxies" 2>/dev/null || true
sleep 2

# Step 2: force (SIGKILL) for anything still around
pkill -KILL -f 'backend\.run' 2>/dev/null || true
pkill -KILL -f "$SCRIPT_DIR/\.local/mitm-proxies" 2>/dev/null || true
pkill -KILL -f 'headless_shell' 2>/dev/null || true
pkill -KILL -f 'playwright.*chromium' 2>/dev/null || true

echo
echo "==> Re-checking"
AFTER="$(pgrep -af 'backend\.run|'"$SCRIPT_DIR"'/\.local/mitm-proxies|headless_shell|playwright.*chromium' 2>/dev/null || true)"
if [ -z "$AFTER" ]; then
    echo "   All stopped."
else
    echo "   Still running (may be unrelated — look at the argv):"
    echo "$AFTER"
fi

echo
echo "==> Port listeners on mitm-proxy ports"
lsof -iTCP:3128 -iTCP:3129 -iTCP:8000 -iTCP:8085 -iTCP:8091 -iTCP:8092 -sTCP:LISTEN 2>/dev/null || echo "   (none)"
