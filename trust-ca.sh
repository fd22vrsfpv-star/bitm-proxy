#!/bin/bash
# Import the bitm-proxy BITM CA into the macOS System Keychain as a trusted
# root for SSL. Required for Chrome / curl / most native tools to accept the
# forged leaf certs the proxy mints at runtime.
#
# Safe to re-run — idempotent (overwrites an existing entry of the same name).
#
# To undo:   ./untrust-ca.sh

set -eu

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This script only applies to macOS."
    exit 1
fi

CA_PATH="${BITM_CA_PATH:-$HOME/Library/Application Support/BitmProxy/data/proxy_ca/ca.crt}"
if [ ! -f "$CA_PATH" ]; then
    echo "⚠  CA cert not found at: $CA_PATH"
    echo "   Start the proxy once (./run-local.sh) so it generates the CA, then re-run."
    exit 1
fi

echo "==> CA to trust:"
echo "   $CA_PATH"
openssl x509 -in "$CA_PATH" -noout -subject -issuer -dates -fingerprint

echo
echo "==> Installing into /Library/Keychains/System.keychain (requires sudo)"
sudo security add-trusted-cert -d -r trustRoot \
    -k /Library/Keychains/System.keychain "$CA_PATH"

echo
echo "==> Done. Verifying:"
security find-certificate -c "BITM Proxy CA" -Z /Library/Keychains/System.keychain \
    | grep -E "SHA-1|alis|keychain:"

echo
echo "Next: restart Chrome (it caches trust state) and retry the request."
