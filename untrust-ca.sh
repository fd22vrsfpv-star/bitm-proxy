#!/bin/bash
# Remove the mitm-proxy MITM CA from the macOS System Keychain. Inverse of
# ./trust-ca.sh. Safe to run even if the cert isn't installed.

set -u

if [ "$(uname -s)" != "Darwin" ]; then
    echo "This script only applies to macOS."
    exit 1
fi

if ! security find-certificate -c "MITM Proxy CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    echo "   No 'MITM Proxy CA' found in System Keychain — nothing to do."
    exit 0
fi

echo "==> Removing 'MITM Proxy CA' from /Library/Keychains/System.keychain (requires sudo)"
sudo security delete-certificate -c "MITM Proxy CA" /Library/Keychains/System.keychain

echo
echo "==> Verifying removal:"
if security find-certificate -c "MITM Proxy CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    echo "   Still present — another copy may exist. Open Keychain Access to inspect."
else
    echo "   Removed."
fi
