"""API key authentication for bitm-proxy endpoints.

On first startup, generates a random 256-bit key, prints it once to stdout,
and saves the hash to DATA_DIR/.api_key_hash. Subsequent requests must include
Authorization: Bearer <key> header (HTTP) or ?api_key=<key> (WebSocket).
"""

import hashlib
import logging
import os
import secrets

from fastapi import Request, WebSocket, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware

from backend.paths import data_dir

logger = logging.getLogger("bitm-proxy.auth")

_KEY_HASH: str = ""
_SKIP_PATHS = {"/health", "/healthz", "/api/capture/external"}


def init_api_key() -> str:
    """Initialize or load the API key.

    Returns the key on first run (print it for the operator), empty string
    on subsequent runs (key already exists on disk).
    The plaintext key is always persisted to .api_key_plaintext for retrieval.

    Set REQUIRE_API_KEY=false to disable authentication entirely.
    """
    global _KEY_HASH

    if os.environ.get("REQUIRE_API_KEY", "true").lower() in ("false", "0", "no"):
        logger.info("API key authentication disabled via REQUIRE_API_KEY")
        return ""

    hash_path = data_dir() / ".api_key_hash"
    plaintext_path = data_dir() / ".api_key_plaintext"

    if hash_path.exists():
        _KEY_HASH = hash_path.read_text().strip()
        logger.info("API key loaded from %s", hash_path)
        # If plaintext was lost (e.g. old image), regenerate
        if not plaintext_path.exists():
            logger.warning("Hash exists but plaintext missing — regenerating key")
            hash_path.unlink()
        else:
            return ""

    key = secrets.token_urlsafe(32)
    _KEY_HASH = hashlib.sha256(key.encode()).hexdigest()
    hash_path.write_text(_KEY_HASH)
    os.chmod(hash_path, 0o600)
    plaintext_path.write_text(key)
    os.chmod(plaintext_path, 0o600)
    logger.info("New API key generated and saved to %s", hash_path)
    return key


def verify_key(provided: str) -> bool:
    if not _KEY_HASH:
        return True
    return hashlib.sha256(provided.encode()).hexdigest() == _KEY_HASH


def _extract_key(request: Request) -> str:
    """Extract API key from Authorization header or query param."""
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.query_params.get("api_key", "")


class APIKeyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        # CORS preflights carry no credentials by browser spec — Authorization
        # is stripped from OPTIONS, so authenticating them is non-functional
        # and would 401 every cross-origin call before it reaches the route.
        # The per-route OPTIONS handler (routes/capture.py) owns the policy
        # decision; the API key gate still applies to the actual POST.
        if request.method == "OPTIONS":
            return await call_next(request)

        token = _extract_key(request)
        if not verify_key(token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
            )

        return await call_next(request)


def verify_ws_key(websocket: WebSocket) -> bool:
    """Verify API key for WebSocket connections via query param."""
    token = websocket.query_params.get("api_key", "")
    return verify_key(token)
