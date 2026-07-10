#!/bin/bash
# Run the mitm-proxy stack natively on macOS / Linux (no Docker).
#
# Layout:
#   - Python control plane (main :8091, debug :8092, RAG :8000, rev-proxy :8085)
#   - Go daemon            (reverse :8085, test :3129 — auth proxy yielded to Python)
#
# Data:
#   ~/Library/Application Support/MitmProxy/{data,screenshots,certs}  (macOS)
#   $DATA_DIR / $SCREENSHOTS_DIR / $CERTS_DIR overrides env vars everywhere
#
# Flags:
#   --install-deps    Auto-yes to any setup prompts (non-interactive).
#   --no-install      Auto-no; exit if anything is missing.
#   --rebuild         Wipe venv/playwright/go/frontend caches and rebuild them.
#   -h|--help         Show this header.
#
# When run interactively with none of the above, the script prompts before
# installing anything at the host level (brew packages, etc).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

REBUILD=0
INSTALL_DEPS=-1   # -1 = ask, 0 = decline, 1 = accept
for arg in "$@"; do
    case "$arg" in
        --rebuild)      REBUILD=1 ;;
        --install-deps) INSTALL_DEPS=1 ;;
        --no-install)   INSTALL_DEPS=0 ;;
        -h|--help)
            sed -n '2,21p' "$0"; exit 0 ;;
    esac
done

# prompt_yes "Question?" <default yes|no>
# Honors --install-deps / --no-install, falls back to reading /dev/tty so
# prompts work even when the script is piped.
prompt_yes() {
    local q="$1" default="${2:-yes}" reply
    if [ "$INSTALL_DEPS" = 1 ]; then echo "$q [auto-yes]"; return 0; fi
    if [ "$INSTALL_DEPS" = 0 ]; then echo "$q [auto-no]";  return 1; fi
    if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
        echo "$q (non-interactive, no default — use --install-deps or --no-install)"
        return 1
    fi
    local suffix="[Y/n]"; [ "$default" = "no" ] && suffix="[y/N]"
    printf "%s %s " "$q" "$suffix" >&2
    if [ -r /dev/tty ]; then read -r reply < /dev/tty; else read -r reply; fi
    reply="$(printf '%s' "${reply:-}" | tr '[:upper:]' '[:lower:]')"
    if [ -z "$reply" ]; then reply="$default"; fi
    case "$reply" in
        y|yes) return 0 ;;
        *)     return 1 ;;
    esac
}

# ── Homebrew PATH on macOS ─────────────────────────────────────────────────
# Make brew-installed binaries (python3.12, node, go, etc.) visible even when
# launched from a non-login shell.
if [ "$(uname -s)" = "Darwin" ]; then
    if [ -x /opt/homebrew/bin/brew ]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [ -x /usr/local/bin/brew ]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
fi

# ── Dependency detection ───────────────────────────────────────────────────
need_brew=()
pick_python() {
    if [ -n "${PYTHON:-}" ] && "$PYTHON" -c 'import sys; assert sys.version_info >= (3, 11)' 2>/dev/null; then
        echo "$PYTHON"; return 0
    fi
    for candidate in python3.12 python3.11 python3; do
        if command -v "$candidate" >/dev/null 2>&1 \
           && "$candidate" -c 'import sys; assert sys.version_info >= (3, 11)' 2>/dev/null; then
            echo "$candidate"; return 0
        fi
    done
    return 1
}
PY="$(pick_python)" || PY=""

if [ -z "$PY" ]; then need_brew+=("python@3.12"); fi
command -v node >/dev/null 2>&1 || need_brew+=("node")
command -v go >/dev/null 2>&1   || need_brew+=("go")

if [ "${#need_brew[@]}" -gt 0 ]; then
    echo "⚠  Missing host dependencies: ${need_brew[*]}"
    if [ "$(uname -s)" = "Darwin" ]; then
        if ! command -v brew >/dev/null 2>&1; then
            echo "   Homebrew itself is not installed. Install it first:"
            echo '   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
            exit 1
        fi
        if prompt_yes "   Install them now with: brew install ${need_brew[*]} ?" yes; then
            brew install "${need_brew[@]}"
            # Re-resolve PATH + python after install
            eval "$(brew shellenv)"
            PY="$(pick_python)" || { echo "   Python 3.11+ still not found after install."; exit 1; }
        else
            echo "   Aborted. To install later:   brew install ${need_brew[*]}"
            exit 1
        fi
    else
        echo "   Install them via your OS package manager (apt / dnf / pacman), then re-run."
        exit 1
    fi
fi

# ── Preflight: make sure Docker isn't holding our ports ────────────────────
if command -v docker >/dev/null 2>&1 \
   && docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -q '3128\|3129\|8091\|8092'; then
    echo "⚠  A Docker container is holding these ports:"
    docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep -E '3128|3129|8091|8092' || true
    echo
    echo "   Stop it first:   docker stop mitm-proxy"
    exit 1
fi

# ── Preflight: reap stale backend.run / mitm-proxies from a previous run ──
# A half-killed previous instance happily holds 8091/8092/3128, and the next
# Python call then logs a bind failure we can't see (swallowed by uvicorn
# _safe_serve). Kill any lingering ones up front.
_stale_kill() {
    local pat="$1"
    local pids
    pids="$(pgrep -f "$pat" 2>/dev/null || true)"
    if [ -n "$pids" ]; then
        echo "   killing stale $pat (pids: $pids)"
        kill -TERM $pids 2>/dev/null || true
        sleep 1
        kill -KILL $pids 2>/dev/null || true
    fi
}
echo "==> Reaping any stale stack processes from a previous run"
_stale_kill 'python -m backend\.run'
_stale_kill 'python .* backend\.run'
_stale_kill "$SCRIPT_DIR/\.local/mitm-proxies"
# Give the kernel a moment to release the TCP sockets.
sleep 1

# ── Python venv ─────────────────────────────────────────────────────────────
VENV="$SCRIPT_DIR/.venv"
# Probe for a *working* venv, not just the directory — a half-built .venv from
# an interrupted prior run will otherwise silently skip setup.
if [ ! -x "$VENV/bin/python" ] || [ "$REBUILD" = 1 ]; then
    echo "==> Creating Python venv at $VENV (using $PY)"
    rm -rf "$VENV"
    "$PY" -m venv "$VENV" || {
        echo "⚠  venv creation failed. On Ubuntu you may need: sudo apt install python3-venv"
        exit 1
    }
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

REQ_STAMP="$VENV/.pip-stamp"
# Trust the stamp only if the packages are actually importable — a partial
# install can leave the stamp alone.
if ! python -c "import uvicorn, fastapi, playwright, cryptography" >/dev/null 2>&1; then
    rm -f "$REQ_STAMP"
fi
if [ ! -f "$REQ_STAMP" ] || [ "requirements.txt" -nt "$REQ_STAMP" ] || [ "$REBUILD" = 1 ]; then
    echo "==> Installing Python requirements"
    python -m pip install --upgrade pip >/dev/null
    python -m pip install -r requirements.txt
    touch "$REQ_STAMP"
fi

PW_STAMP="$VENV/.playwright-stamp"
# Detect missing Chromium install (playwright CLI doesn't report this cleanly,
# so we just check the known cache path).
PW_CACHE="${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}"
if ! ls -d "$PW_CACHE"/chromium-* >/dev/null 2>&1; then
    rm -f "$PW_STAMP"
fi
if [ ! -f "$PW_STAMP" ] || [ "$REBUILD" = 1 ]; then
    echo "==> Installing Playwright Chromium + Firefox + WebKit (takes a few minutes)"
    # All three engines let use_captured_fingerprint launch a session
    # whose TLS JA3 matches the captured browser family.
    if [ "$(uname -s)" = "Linux" ]; then
        # On Linux, pull the system libs for all three engines (nss,
        # gbm, cups, libwebp, libevent, etc.)
        python -m playwright install --with-deps chromium firefox webkit
    else
        python -m playwright install chromium firefox webkit
    fi
    touch "$PW_STAMP"
fi

# ── Playwright Microsoft Edge channel (optional) ───────────────────────────
# Required when browser_type is set to "edge-real". Skipped automatically on
# arm64 Linux where Microsoft doesn't ship the package.
MSEDGE_STAMP="$VENV/.msedge-stamp"
_edge_installed() {
    # playwright drops msedge inside the same cache as chromium;
    # `playwright install --dry-run msedge` prints an "install location"
    # line only when it's already present, but that's fragile — just look
    # for the canonical binary path it drops on Linux/macOS/Windows.
    case "$(uname -s)" in
        Linux)  [ -x /opt/microsoft/msedge/msedge ] ;;
        Darwin) [ -d "/Applications/Microsoft Edge.app" ] ;;
        *)      return 1 ;;
    esac
}
if ! _edge_installed; then rm -f "$MSEDGE_STAMP"; fi
if [ ! -f "$MSEDGE_STAMP" ] || [ "$REBUILD" = 1 ]; then
    echo "==> Installing Playwright Microsoft Edge channel (required for browser_type=edge-real)"
    if [ "$(uname -s)" = "Linux" ]; then
        if python -m playwright install --with-deps msedge 2>&1; then
            touch "$MSEDGE_STAMP"
        else
            echo "⚠  msedge install failed (common on arm64 Linux — Microsoft doesn't ship it)."
            echo "   'browser_type = edge-real' will fall back. The default 'edge' (Chromium + Edge UA) works without this."
        fi
    else
        if python -m playwright install msedge 2>&1; then
            touch "$MSEDGE_STAMP"
        else
            echo "⚠  msedge install failed. Skipping — use browser_type=edge (Chromium + Edge UA) instead."
        fi
    fi
fi

# ── Frontend build ──────────────────────────────────────────────────────────
if [ ! -d "$SCRIPT_DIR/static" ] || [ "$REBUILD" = 1 ]; then
    if [ -d "$SCRIPT_DIR/frontend" ]; then
        echo "==> Building frontend"
        (
            cd "$SCRIPT_DIR/frontend"
            if [ ! -d node_modules ] || [ "$REBUILD" = 1 ]; then
                npm install --no-audit --no-fund
            fi
            npm run build
        )
        rm -rf "$SCRIPT_DIR/static"
        cp -R "$SCRIPT_DIR/frontend/dist" "$SCRIPT_DIR/static"
    fi
fi

# ── Go daemon build ─────────────────────────────────────────────────────────
GO_BIN="$SCRIPT_DIR/.local/mitm-proxies"
mkdir -p "$SCRIPT_DIR/.local"
if [ ! -x "$GO_BIN" ] || [ "$REBUILD" = 1 ]; then
    echo "==> Building Go daemon -> $GO_BIN"
    (cd "$SCRIPT_DIR/go" && go build -o "$GO_BIN" ./cmd/mitm-proxies)
fi

# ── Runtime env ─────────────────────────────────────────────────────────────
export HOST="${HOST:-127.0.0.1}"
export REQUIRE_API_KEY="${REQUIRE_API_KEY:-false}"
export INTERNAL_SECRET="${INTERNAL_SECRET:-dev-internal-secret}"
# When the Go daemon is present, skip the Python reverse proxy (Go owns :8085).
export DISABLE_PYTHON_REVPROXY=1

# Per-platform data dirs are resolved inside backend/paths.py.
echo "==> Starting Python control plane"
python -m backend.run &
PY_PID=$!

# Wait for the debug health endpoint before starting Go
py_ready=0
for i in {1..30}; do
    if curl -sf "http://127.0.0.1:8092/health" >/dev/null 2>&1; then
        echo "   Python ready after ${i}s"
        py_ready=1
        break
    fi
    # If the process died, stop waiting.
    if ! kill -0 "$PY_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done

# Hard verification: is Python alive AND are 8091 + 8092 actually bound?
if ! kill -0 "$PY_PID" 2>/dev/null; then
    echo
    echo "⚠  Python control plane exited before startup completed." >&2
    echo "   Most common causes:" >&2
    echo "     - port 8091/8092/8000/8085 still held by a previous instance" >&2
    echo "     - syntax or import error in a recent commit — re-run with PYTHONUNBUFFERED=1" >&2
    echo "   Investigate:  ./diag.sh   (or  ss -tlnp | grep -E ':(8091|8092|8000|8085)\b')" >&2
    exit 1
fi
if [ "$py_ready" = 0 ]; then
    echo
    echo "⚠  /health never answered after 30 s — Python is running but didn't bind :8092." >&2
    echo "   Likely a port clash or an uvicorn worker exception." >&2
    echo "   Recent stderr should show it just above; if not:" >&2
    echo "     ss -tlnp | grep -E ':(8091|8092|8000|8085)\b'" >&2
    kill -TERM "$PY_PID" 2>/dev/null || true
    exit 1
fi

# Double-check every port — an individual _safe_serve failure wouldn't have
# stopped /health, but a missing :8091 WILL break the viewer.
missing=""
for port in 8091 8092 8000; do
    if ! ss -tln 2>/dev/null | awk -v p=":${port}\$" '$4 ~ p {found=1} END{exit !found}'; then
        if ! lsof -iTCP:${port} -sTCP:LISTEN -nP 2>/dev/null | grep -q .; then
            missing="$missing $port"
        fi
    fi
done
if [ -n "$missing" ]; then
    echo
    echo "⚠  Python is up but these ports did NOT bind:$missing" >&2
    echo "   Run ./diag.sh for a full breakdown." >&2
fi

echo "==> Starting Go daemon"
PYTHON_BASE_URL="http://127.0.0.1:8092" \
DISABLE_GO_AUTHPROXY=1 \
"$GO_BIN" &
GO_PID=$!

# Give Go up to 5 s to bind its ports; if it dies, say so loudly.
sleep 2
if ! kill -0 "$GO_PID" 2>/dev/null; then
    echo "⚠  Go daemon exited right after start — check its stderr above." >&2
fi

cleanup() {
    echo
    echo "==> Shutting down"
    kill -TERM "$GO_PID" 2>/dev/null || true
    kill -TERM "$PY_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup INT TERM

echo
echo "────────────────────────────────────────────────────────────"
echo "  Main:  http://127.0.0.1:8091/"
echo "  Debug: http://127.0.0.1:8092/"
echo "  Auth proxy: http://127.0.0.1:3128   (Python MITM)"
echo "  Test proxy: http://127.0.0.1:3129   (Go pass-through)"
echo "  Rev  proxy: http://127.0.0.1:8085   (Go)"
echo "────────────────────────────────────────────────────────────"
echo

# Block until either process exits. `wait -n` would be cleaner but needs bash
# 4.3+, and macOS ships with bash 3.2.
while kill -0 "$PY_PID" 2>/dev/null && kill -0 "$GO_PID" 2>/dev/null; do
    sleep 1
done
cleanup
