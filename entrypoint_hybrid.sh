#!/bin/bash
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"

# Install runtime-mounted CA certs (same as entrypoint.sh)
if [ -d "$CERTS_DIR" ]; then
    new_certs=0
    for f in "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.pem "$CERTS_DIR"/*.cer; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        name="${base%.crt}"; name="${name%.pem}"; name="${name%.cer}"
        dest="/usr/local/share/ca-certificates/${name}.crt"
        if [ ! -f "$dest" ] || ! cmp -s "$f" "$dest"; then
            cp -v "$f" "$dest"
            new_certs=$((new_certs + 1))
        fi
    done
    if [ "$new_certs" -gt 0 ]; then
        update-ca-certificates
    fi
fi

echo "[entrypoint-hybrid] Python control plane starting on :8091 (main), :8092 (debug), :8000 (RAG)..."
python -m backend.run &
PYTHON_PID=$!

# Wait for the control plane to be reachable before starting Go
# (flowclient needs Python up to POST events)
for i in {1..30}; do
    if curl -sf "http://127.0.0.1:8092/health" >/dev/null 2>&1; then
        echo "[entrypoint-hybrid] Python control plane ready after ${i}s"
        break
    fi
    sleep 1
done

echo "[entrypoint-hybrid] Starting Go proxy daemon (reverse :8085, test :3129; Python owns :3128 auth BITM)..."
/app/bitm-proxies &
GO_PID=$!

# Forward SIGTERM/SIGINT to both
trap 'echo "[entrypoint-hybrid] stopping..."; kill -TERM $PYTHON_PID $GO_PID 2>/dev/null; wait' TERM INT

# Exit when either one exits
wait -n $PYTHON_PID $GO_PID
EXIT_CODE=$?
echo "[entrypoint-hybrid] one process exited (code $EXIT_CODE), stopping the other"
kill -TERM $PYTHON_PID $GO_PID 2>/dev/null || true
wait
exit $EXIT_CODE
