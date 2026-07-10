#!/usr/bin/env bash
# setup.sh — Bootstrap the Phantom Join toolkit environment
# Usage: chmod +x setup.sh && ./setup.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

info()    { echo -e "  [*] $1"; }
success() { echo -e "  ${GREEN}[+]${NC} $1"; }
warn()    { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "  ${RED}[-]${NC} $1"; }

echo ""
echo "  ╔═══════════════════════════════════════════╗"
echo "  ║  Phantom Join — Environment Setup         ║"
echo "  ╚═══════════════════════════════════════════╝"
echo ""

# Check Python version
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$(echo "$version" | cut -d. -f1)
        minor=$(echo "$version" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    fail "Python 3.10+ is required but not found"
    info "Install Python 3.10+:"
    info "  Ubuntu/Debian: sudo apt install python3.10 python3.10-venv"
    info "  macOS:         brew install python@3.12"
    exit 1
fi
success "Found $PYTHON ($($PYTHON --version 2>&1))"

# Create virtual environment
VENV_DIR=".venv"
if [ -d "$VENV_DIR" ]; then
    warn "Virtual environment already exists at $VENV_DIR"
    read -rp "  Recreate? [y/N] " choice
    if [[ "$choice" =~ ^[Yy]$ ]]; then
        rm -rf "$VENV_DIR"
        $PYTHON -m venv "$VENV_DIR"
        success "Virtual environment recreated"
    fi
else
    info "Creating virtual environment..."
    $PYTHON -m venv "$VENV_DIR"
    success "Virtual environment created at $VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"
success "Virtual environment activated"

# Upgrade pip
info "Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
info "Installing dependencies from requirements.txt..."
if pip install -r requirements.txt --quiet; then
    success "All dependencies installed"
else
    fail "Dependency installation failed"
    exit 1
fi

# Verify tools
echo ""
info "Verifying tool availability..."

TOOLS_OK=true
for tool in roadtx roadrecon; do
    if command -v "$tool" &>/dev/null; then
        version=$($tool --version 2>&1 || echo "unknown")
        success "$tool — $version"
    else
        fail "$tool not found on PATH"
        TOOLS_OK=false
    fi
done

# Summary
echo ""
echo "  ────────────────────────────────────────────"
if [ "$TOOLS_OK" = true ]; then
    success "Setup complete. Ready to run."
else
    warn "Setup complete with warnings. Some tools may need manual installation."
fi

echo ""
info "Activate the environment:"
echo "    source $VENV_DIR/bin/activate"
echo ""
info "Run a dry run to verify:"
echo "    python phantom_join.py -u test@example.com -p test -d example.com --dry-run"
echo ""
info "See README.md for full usage documentation."
echo ""
