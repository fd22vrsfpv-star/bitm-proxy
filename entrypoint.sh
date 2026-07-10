#!/bin/bash
set -e

CERTS_DIR="${CERTS_DIR:-/certs}"

# Install any runtime-mounted certs not already in the trust store
if [ -d "$CERTS_DIR" ]; then
    new_certs=0
    for f in "$CERTS_DIR"/*.crt "$CERTS_DIR"/*.pem "$CERTS_DIR"/*.cer; do
        [ -f "$f" ] || continue
        base=$(basename "$f")
        # Strip all cert extensions to get the bare name, then add .crt once
        name="${base%.crt}"
        name="${name%.pem}"
        name="${name%.cer}"
        dest="/usr/local/share/ca-certificates/${name}.crt"
        if [ ! -f "$dest" ] || ! cmp -s "$f" "$dest"; then
            cp -v "$f" "$dest"
            new_certs=$((new_certs + 1))
        fi
    done
    if [ "$new_certs" -gt 0 ]; then
        echo "[entrypoint] Installing $new_certs new runtime CA cert(s)..."
        update-ca-certificates
        echo "[entrypoint] CA certificates updated"
    else
        echo "[entrypoint] No new runtime certs (build-time certs already installed)"
    fi
else
    echo "[entrypoint] No certs dir at $CERTS_DIR"
fi

echo "[entrypoint] SSL_CERT_FILE=$SSL_CERT_FILE"
echo "[entrypoint] Certs in trust store:"
ls /usr/local/share/ca-certificates/ 2>/dev/null || echo "  (none)"

echo "[entrypoint] Starting main app (:8091) + debug dashboard (:8092)..."
exec python -m backend.run
