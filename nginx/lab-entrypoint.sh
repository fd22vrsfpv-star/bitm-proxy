#!/bin/sh
# Bootstrap entrypoint for the `nginx` compose service.
#
# Generates a self-signed cert on first run only (idempotent — skips if a
# real cert is already bind-mounted over this path for the public-instance
# deployment):
#
#   /etc/letsencrypt/live/www.rtvbitm.com/{fullchain,privkey}.pem — for the
#   loopback-default self-hosted case where Let's Encrypt isn't
#   reachable/applicable. The public instance overrides this by mounting a
#   real cert directory over /etc/letsencrypt (see docs/DEFCON-LAB-SETUP.md)
#   — this script then finds real files already in place and does nothing.
set -eu

CERT_DIR="/etc/letsencrypt/live/www.rtvbitm.com"

# The base image ships its own conf.d/default.conf (the stock "Welcome to
# nginx!" vhost), also listening on 80/443. Left in place, it competes with
# rtvbitm.conf for any request whose Host header doesn't match
# rtvbitm.conf's server_name (bare IP, curl without -H Host, a visitor
# typing the raw loopback/public IP) — rtvbitm.conf's `default_server`
# listen directives only work if there isn't a second default_server
# fighting for the same port. Idempotent: fine to remove on every start.
rm -f /etc/nginx/conf.d/default.conf

if [ ! -f "$CERT_DIR/fullchain.pem" ] || [ ! -f "$CERT_DIR/privkey.pem" ]; then
    apk add --no-cache openssl >/dev/null 2>&1 || true
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
        -keyout "$CERT_DIR/privkey.pem" \
        -out    "$CERT_DIR/fullchain.pem" \
        -subj "/CN=rtvbitm.local" \
        -addext "subjectAltName=DNS:rtvbitm.local,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
    echo "[lab-entrypoint] Generated self-signed cert at $CERT_DIR (browser will show a warning — expected for local/self-hosted use)"
fi

exec /docker-entrypoint.sh nginx -g 'daemon off;'
