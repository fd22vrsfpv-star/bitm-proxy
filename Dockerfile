# ── Stage 1: Build frontend ──
FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python runtime ──
FROM python:3.12-slim
LABEL maintainer="mitm-proxy"
LABEL description="MITM Proxy — Remote browser login for any site"

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

# Install Python deps + Playwright browsers (Chromium + Edge)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium \
    && (playwright install msedge || echo "msedge unavailable (likely arm64); edge-real mode disabled")

# Copy backend code
COPY backend/ ./backend/
COPY config/ ./config/

# Copy built frontend into /app/static (where main.py expects it)
COPY --from=frontend-build /build/dist/ ./static/

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
