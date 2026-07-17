#!/bin/bash
# Complete installer for bitm-proxy on Ubuntu (22.04+ / 24.04).
#
# What it does (idempotent — safe to re-run):
#   1. Installs apt dependencies: python3.12 + venv, nodejs 20, golang,
#      build-essential, openssl, curl, git, ca-certificates.
#   2. Installs PowerShell (pwsh) + the Az.Accounts module — needed for
#      the AAA runner endpoints (/api/aaa/run, /api/aaa/login). Both
#      installs are best-effort; the proxy still runs without them.
#   3. Creates a dedicated service user `bitm-proxy` (system user, no shell).
#   4. Syncs the project to /opt/bitm-proxy (from this repo checkout, or
#      clones $REPO_URL if run standalone).
#   5. Builds: Python venv + pip install, Playwright Chromium + Edge
#      channel, frontend via npm, Go daemon binary.
#   6. Creates /var/lib/bitm-proxy as the data directory, chown'd to the
#      service user. Certs go in /opt/bitm-proxy/certs.
#   7. Installs a hardened /etc/systemd/system/bitm-proxy.service unit.
#   8. Enables + starts the service.
#
# Usage:
#   sudo ./install-ubuntu.sh                 # install / update (full)
#   sudo ./install-ubuntu.sh --quick         # rsync source + restart service only
#                                            # (skips apt/pip/playwright/frontend/Go;
#                                            #  use after editing Python under
#                                            #  $APP_DIR — typically ./backend/**)
#   sudo ./install-ubuntu.sh --uninstall     # remove service + files (keeps data)
#   sudo ./install-ubuntu.sh --purge         # remove everything incl. data dir
#
# Environment overrides:
#   APP_DIR        (default /opt/bitm-proxy)
#   DATA_DIR       (default /var/lib/bitm-proxy)
#   SERVICE_USER   (default bitm-proxy)
#   BIND_HOST      (default 127.0.0.1 — set 0.0.0.0 to expose on LAN,
#                   but put nginx + TLS + basic-auth in front if you do)
#   REPO_URL       (default https://github.com/fd22vrsfpv-star/bitm-proxy.git,
#                   only used when script is run outside a repo checkout)
#   GO_VERSION     (default 1.22.10)

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/bitm-proxy}"
DATA_DIR="${DATA_DIR:-/var/lib/bitm-proxy}"
SERVICE_USER="${SERVICE_USER:-bitm-proxy}"
SERVICE_GROUP="${SERVICE_GROUP:-$SERVICE_USER}"
BIND_HOST="${BIND_HOST:-127.0.0.1}"
REPO_URL="${REPO_URL:-https://github.com/fd22vrsfpv-star/bitm-proxy.git}"
GO_VERSION="${GO_VERSION:-1.22.10}"
UNIT_PATH="/etc/systemd/system/bitm-proxy.service"
UNIT_NAME="bitm-proxy"

ACTION="install"
case "${1:-install}" in
    install|update) ACTION="install" ;;
    --quick|quick) ACTION="quick" ;;
    --uninstall|uninstall) ACTION="uninstall" ;;
    --purge|purge)   ACTION="purge" ;;
    -h|--help)
        sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "✗ Must be run as root. Try:  sudo $0 $*" >&2
    exit 1
fi

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m  %s\n' "$*" >&2; }
die() { printf '\033[1;31m✗\033[0m  %s\n' "$*" >&2; exit 1; }

# ── Uninstall paths ────────────────────────────────────────────────────────
if [ "$ACTION" = "uninstall" ] || [ "$ACTION" = "purge" ]; then
    log "Stopping and disabling $UNIT_NAME"
    systemctl stop "$UNIT_NAME" 2>/dev/null || true
    systemctl disable "$UNIT_NAME" 2>/dev/null || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
    if [ -d "$APP_DIR" ]; then
        log "Removing $APP_DIR"
        rm -rf "$APP_DIR"
    fi
    if [ "$ACTION" = "purge" ]; then
        if [ -d "$DATA_DIR" ]; then
            log "Purging $DATA_DIR (captured sessions, credentials, screenshots)"
            rm -rf "$DATA_DIR"
        fi
        if id -u "$SERVICE_USER" >/dev/null 2>&1; then
            log "Removing service user $SERVICE_USER"
            userdel "$SERVICE_USER" 2>/dev/null || true
        fi
    else
        log "Preserving $DATA_DIR (use --purge to remove)"
    fi
    log "Done."
    exit 0
fi

# ── Quick update (source-only sync + service restart) ─────────────────────
# For Python iteration after a full install — rsyncs the local checkout
# into $APP_DIR and restarts the service, without touching apt packages,
# the Python venv, Playwright browsers, the frontend bundle, or the Go
# binary. Use a full install if you've changed deps, frontend, or Go.
if [ "$ACTION" = "quick" ]; then
    if [ ! -d "$APP_DIR" ]; then
        die "$APP_DIR doesn't exist — run a full install first: sudo $0"
    fi
    if [ ! -f "$UNIT_PATH" ]; then
        die "$UNIT_NAME.service not installed — run a full install first: sudo $0"
    fi
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ ! -f "$SCRIPT_DIR/requirements.txt" ] || [ ! -d "$SCRIPT_DIR/backend" ]; then
        die "Run --quick from a repo checkout (need ./backend and ./requirements.txt)."
    fi
    log "Syncing $SCRIPT_DIR -> $APP_DIR (quick: skipping apt/pip/playwright/frontend/Go)"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude=.venv --exclude=.git --exclude=node_modules \
            --exclude=.local --exclude=__pycache__ \
            --exclude=.playwright-browsers \
            "$SCRIPT_DIR/" "$APP_DIR/"
    else
        cp -a "$SCRIPT_DIR/." "$APP_DIR/"
        rm -rf "$APP_DIR/.venv" "$APP_DIR/.git" "$APP_DIR/node_modules" \
               "$APP_DIR/.local" "$APP_DIR/.playwright-browsers"
    fi
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$APP_DIR"
    log "Restarting $UNIT_NAME"
    systemctl restart "$UNIT_NAME"
    sleep 2
    if systemctl is-active --quiet "$UNIT_NAME"; then
        log "Service is active. Tail logs with: journalctl -u $UNIT_NAME -f"
    else
        warn "Service did not stay up. Check:  journalctl -u $UNIT_NAME -n 80 --no-pager"
        exit 1
    fi
    exit 0
fi

# ── Preflight ──────────────────────────────────────────────────────────────
if ! grep -qiE 'ubuntu|debian' /etc/os-release 2>/dev/null; then
    warn "This installer is tested on Ubuntu 22.04 / 24.04. Other distros may need manual tweaks."
fi

# ── apt dependencies ───────────────────────────────────────────────────────
log "Installing apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git openssl build-essential jq \
    python3 python3-venv python3-pip \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 \
    libcairo2 libasound2t64 2>/dev/null \
 || apt-get install -y -qq --no-install-recommends \
    ca-certificates curl git openssl build-essential jq \
    python3 python3-venv python3-pip \
    libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libpango-1.0-0 \
    libcairo2 libasound2

# ── Python 3.12 (prefer base, fall back to deadsnakes on 22.04) ────────────
if ! command -v python3.12 >/dev/null 2>&1; then
    log "python3.12 not in base repos — adding deadsnakes PPA"
    apt-get install -y -qq --no-install-recommends software-properties-common
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends python3.12 python3.12-venv
fi
PYTHON_BIN="$(command -v python3.12 || command -v python3)"
log "Using python: $PYTHON_BIN ($("$PYTHON_BIN" --version))"

# ── Node.js 20.x (NodeSource) — only when we need to build the frontend ───
# A prebuilt static/ is checked into the repo, so production installs
# normally skip this entirely. Node is only required when static/ is
# missing AND frontend/ source exists.
SKIP_FRONTEND_BUILD=0
SRC_CHECKOUT="${SCRIPT_DIR:-$(pwd)}"
if [ -f "$SRC_CHECKOUT/static/index.html" ]; then
    SKIP_FRONTEND_BUILD=1
    log "Prebuilt static/ found in checkout — skipping Node.js install + frontend build"
fi
if [ "$SKIP_FRONTEND_BUILD" = 0 ]; then
    NODE_MAJOR="$(node --version 2>/dev/null | sed -E 's/^v([0-9]+).*/\1/' || echo 0)"
    if [ "${NODE_MAJOR:-0}" -lt 18 ]; then
        log "Installing Node.js 20 via NodeSource"
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y -qq nodejs
    fi
    log "Using node: $(node --version)  npm: $(npm --version)"
fi

# ── Go (pinned tarball under /usr/local/go) ────────────────────────────────
GO_BIN="/usr/local/go/bin/go"
NEED_GO=1
if [ -x "$GO_BIN" ] && "$GO_BIN" version 2>/dev/null | grep -q "go${GO_VERSION}"; then
    NEED_GO=0
fi
if [ "$NEED_GO" = 1 ]; then
    ARCH="$(dpkg --print-architecture)"
    case "$ARCH" in
        amd64) GO_ARCH="amd64" ;;
        arm64) GO_ARCH="arm64" ;;
        *) die "Unsupported architecture for Go install: $ARCH" ;;
    esac
    log "Installing Go $GO_VERSION ($GO_ARCH) to /usr/local/go"
    rm -rf /usr/local/go
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" \
        | tar -C /usr/local -xz
fi
ln -sf /usr/local/go/bin/go /usr/local/bin/go
log "Using go: $(go version)"

# ── AAA runner prereqs (pwsh + Az.Accounts) ───────────────────────────────
# The AbuseAzureAPIPermissions runner (`/api/aaa/run`) and the
# Get-AAATokenFromAzLogin "Run via pwsh…" button (`/api/aaa/login`)
# both shell out to pwsh. Az.Accounts is the PowerShell module that
# provides Connect-AzAccount; without it Get-AAATokenFromAzLogin fails
# at runtime. Both installs are best-effort — if they fail the proxy
# still runs and the AAA UI surfaces a clear missing-dep error path.
if ! command -v pwsh >/dev/null 2>&1; then
    log "Installing PowerShell (pwsh) — needed for /api/aaa/{run,login}"
    UBUNTU_VERSION_ID="$(. /etc/os-release && echo "$VERSION_ID")"
    if ! (
        curl -fsSL -o /tmp/packages-microsoft-prod.deb \
             "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION_ID}/packages-microsoft-prod.deb" \
        && dpkg -i /tmp/packages-microsoft-prod.deb \
        && apt-get update -qq \
        && apt-get install -y -qq --no-install-recommends powershell
    ); then
        warn "pwsh install failed — AAA runner endpoints will return 'pwsh not on PATH'."
    fi
fi

if command -v pwsh >/dev/null 2>&1; then
    if ! pwsh -NoProfile -NonInteractive -Command \
           "if (Get-Module -ListAvailable -Name Az.Accounts) { exit 0 } else { exit 1 }" \
           2>/dev/null; then
        log "Installing PowerShell Az.Accounts module (system-wide) — needed for Get-AAATokenFromAzLogin"
        if ! pwsh -NoProfile -NonInteractive -Command \
                "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
                 Install-Module Az.Accounts -Scope AllUsers -Force -AllowClobber" \
                2>&1 | tail -10; then
            warn "Az.Accounts install failed — Get-AAATokenFromAzLogin will surface install hint at runtime."
        fi
    fi
fi

# ── Service user ───────────────────────────────────────────────────────────
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating service user $SERVICE_USER"
    useradd --system --home "$DATA_DIR" --shell /usr/sbin/nologin \
            --comment "bitm-proxy service" "$SERVICE_USER"
fi

# ── Sync source into APP_DIR ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/requirements.txt" ] && [ -d "$SCRIPT_DIR/backend" ]; then
    log "Syncing repo checkout $SCRIPT_DIR -> $APP_DIR"
    mkdir -p "$APP_DIR"
    # rsync if present for speed; otherwise fall back to cp -a
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete \
            --exclude=.venv --exclude=.git --exclude=node_modules \
            --exclude=.local --exclude=__pycache__ \
            "$SCRIPT_DIR/" "$APP_DIR/"
    else
        cp -a "$SCRIPT_DIR/." "$APP_DIR/"
        rm -rf "$APP_DIR/.venv" "$APP_DIR/.git" "$APP_DIR/node_modules" \
               "$APP_DIR/.local"
    fi
else
    if [ ! -d "$APP_DIR/.git" ]; then
        log "Cloning $REPO_URL -> $APP_DIR"
        git clone "$REPO_URL" "$APP_DIR"
    else
        log "Updating existing checkout at $APP_DIR (git pull)"
        git -C "$APP_DIR" pull --ff-only
    fi
fi

# ── Python venv + deps ─────────────────────────────────────────────────────
VENV="$APP_DIR/.venv"
if [ ! -x "$VENV/bin/python" ]; then
    log "Creating Python venv at $VENV"
    "$PYTHON_BIN" -m venv "$VENV"
fi
log "Installing Python requirements"
"$VENV/bin/pip" install --upgrade pip setuptools wheel >/dev/null
"$VENV/bin/pip" install -r "$APP_DIR/requirements.txt"

# ── Playwright browsers ────────────────────────────────────────────────────
# Install Chromium + Firefox + WebKit + Edge as root so the system libs get
# installed. Browser binaries land under PLAYWRIGHT_BROWSERS_PATH; the
# systemd unit hands the same path to the service user so it can launch
# them post-drop-privs. Mirror run-local.sh's engine selection so the two
# install paths produce equivalent runtimes.
export PLAYWRIGHT_BROWSERS_PATH="$APP_DIR/.playwright-browsers"

log "Installing Playwright Chromium + Firefox + WebKit (takes a few minutes) to $PLAYWRIGHT_BROWSERS_PATH"
# All three engines let use_captured_fingerprint launch a session whose
# TLS JA3 matches the captured browser family (Firefox / WebKit as well
# as Chromium). --with-deps pulls the system libs (nss, gbm, cups,
# libwebp, libevent, etc.) for every engine.
"$VENV/bin/python" -m playwright install --with-deps chromium firefox webkit

# Microsoft Edge channel — required when browser_type is set to "edge-real".
# Skipped automatically on arm64 Linux where Microsoft doesn't ship the
# package; browser_type=edge (Chromium + Edge UA) still works without it.
log "Installing Playwright Microsoft Edge channel (required for browser_type=edge-real)"
if "$VENV/bin/python" -m playwright install --with-deps msedge 2>&1; then
    :
else
    warn "msedge install failed (common on arm64 Linux — Microsoft doesn't ship it)."
    warn "'browser_type = edge-real' will fall back. The default 'edge' (Chromium + Edge UA) works without this."
fi

# ── Frontend ───────────────────────────────────────────────────────────────
# Prefer the prebuilt static/ that ships in the repo; it was copied into
# $APP_DIR during the rsync above. Only fall back to an npm build if
# static/ is missing AND frontend/ source is available.
if [ -f "$APP_DIR/static/index.html" ]; then
    log "Using prebuilt frontend at $APP_DIR/static"
elif [ -d "$APP_DIR/frontend" ]; then
    log "No prebuilt static/ — building frontend (npm install + build)"
    (
        cd "$APP_DIR/frontend"
        npm install --no-audit --no-fund
        npm run build
    )
    rm -rf "$APP_DIR/static"
    cp -R "$APP_DIR/frontend/dist" "$APP_DIR/static"
fi

# ── Go daemon build ────────────────────────────────────────────────────────
if [ -d "$APP_DIR/go" ]; then
    log "Building Go daemon -> $APP_DIR/.local/bitm-proxies"
    mkdir -p "$APP_DIR/.local"
    (
        cd "$APP_DIR/go"
        /usr/local/go/bin/go build -o "$APP_DIR/.local/bitm-proxies" ./cmd/bitm-proxies
    )
fi

# ── Data dir + ownership ───────────────────────────────────────────────────
mkdir -p "$DATA_DIR" "$DATA_DIR/screenshots" "$APP_DIR/certs"
chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" "$APP_DIR"
chmod 750 "$DATA_DIR"
# The api_key_plaintext file must never be world-readable.
[ -f "$DATA_DIR/.api_key_plaintext" ] && chmod 600 "$DATA_DIR/.api_key_plaintext" || true

# ── systemd unit ───────────────────────────────────────────────────────────
log "Writing $UNIT_PATH"
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=BITM Proxy — remote browser login + API testing
Documentation=file://$APP_DIR/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_GROUP
WorkingDirectory=$APP_DIR
Environment=REQUIRE_API_KEY=false
Environment=PYTHONUNBUFFERED=1
Environment=HOST=$BIND_HOST
Environment=DATA_DIR=$DATA_DIR
Environment=SCREENSHOTS_DIR=$DATA_DIR/screenshots
Environment=CERTS_DIR=$APP_DIR/certs
Environment=PLAYWRIGHT_BROWSERS_PATH=$APP_DIR/.playwright-browsers
# Python control plane spawns the Go daemon child below if present.
Environment=DISABLE_PYTHON_REVPROXY=1
ExecStart=$VENV/bin/python -m backend.run
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# Hardening (Playwright needs /tmp rw + network; keep the rest clamped).
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DATA_DIR $APP_DIR/certs $APP_DIR/.playwright-browsers
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
# Bind low-numbered ports if BIND_HOST needs them later.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# ── Reload + enable + start ────────────────────────────────────────────────
log "Enabling and starting $UNIT_NAME"
systemctl daemon-reload
systemctl enable "$UNIT_NAME" >/dev/null
systemctl restart "$UNIT_NAME"

sleep 2
if systemctl is-active --quiet "$UNIT_NAME"; then
    log "Service is active."
else
    warn "Service did not stay up. Check:  journalctl -u $UNIT_NAME -n 80 --no-pager"
fi

# ── Post-install summary ───────────────────────────────────────────────────
API_KEY=""
if [ -f "$DATA_DIR/.api_key_plaintext" ]; then
    API_KEY="$(cat "$DATA_DIR/.api_key_plaintext" 2>/dev/null || true)"
fi

cat <<EOF

────────────────────────────────────────────────────────────
  BITM Proxy installed
────────────────────────────────────────────────────────────
  Service:     systemctl status $UNIT_NAME
  Logs:        journalctl -u $UNIT_NAME -f
  App dir:     $APP_DIR
  Data dir:    $DATA_DIR
  Service user: $SERVICE_USER
  Bind host:   $BIND_HOST (only loopback by default)

  URLs (on this host):
    Main:      http://$BIND_HOST:8091/
    Debug:     http://$BIND_HOST:8092/
    RAG API:   http://$BIND_HOST:8000/
    Rev proxy: http://$BIND_HOST:8085/
    Auth BITM: http://$BIND_HOST:3128/   (authorized pentest use only)

EOF
if [ -n "$API_KEY" ]; then
    echo "  API key:     $API_KEY"
    echo "               (stored at $DATA_DIR/.api_key_plaintext, chmod 600)"
fi
cat <<EOF

  Exposing to LAN?   Front with nginx + TLS + basic-auth.
                     See pages/nginx.conf.example for a template.

  Uninstall:  sudo $0 --uninstall
  Purge:      sudo $0 --purge   (removes $DATA_DIR too)
────────────────────────────────────────────────────────────
EOF
