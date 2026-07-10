"""Encrypted file-based storage for sessions, cookies, and captured credentials.

When CREDENTIAL_PASSPHRASE is set, all data is encrypted at rest with
AES-256-GCM. Files use .enc extension and 0o600 permissions. Writes are
atomic (write to .tmp, then rename) to prevent corruption on crash.

When CREDENTIAL_PASSPHRASE is not set, falls back to plaintext JSON — still
using atomic writes (temp + rename) to prevent corruption.
"""

import asyncio
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Callable

from backend.paths import data_dir

logger = logging.getLogger("mitm-proxy.store")

DATA_DIR = data_dir()

_PASSPHRASE: str = os.environ.get("CREDENTIAL_PASSPHRASE", "")

if not _PASSPHRASE:
    logger.warning(
        "CREDENTIAL_PASSPHRASE not set — credentials will be stored in "
        "PLAINTEXT. Set this env var before production deployment."
    )


def _encrypt_enabled() -> bool:
    return bool(_PASSPHRASE)


def _atomic_write(dest: Path, payload: bytes, dir: Path) -> None:
    """Write payload to dest atomically via temp file + rename."""
    fd, tmp = tempfile.mkstemp(dir=dir, suffix=".tmp")
    closed = False
    try:
        os.write(fd, payload)
        os.fchmod(fd, 0o600)
        os.close(fd)
        closed = True
        os.rename(tmp, dest)
    except Exception:
        if not closed:
            os.close(fd)
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


class JsonStore:
    """File-based JSON store with atomic writes and per-key locking."""

    # Class-level lock registry — one asyncio.Lock per (namespace, key) to
    # protect read-modify-write sequences across concurrent coroutines.
    _locks: dict[str, asyncio.Lock] = {}

    def __init__(self, namespace: str):
        self.namespace = namespace
        self.dir = DATA_DIR / namespace
        self.dir.mkdir(parents=True, exist_ok=True)

    def _lock_for(self, key: str) -> asyncio.Lock:
        """Get or create an asyncio.Lock for a specific key."""
        lock_id = f"{self.namespace}:{key}"
        if lock_id not in JsonStore._locks:
            JsonStore._locks[lock_id] = asyncio.Lock()
        return JsonStore._locks[lock_id]

    def _ext(self) -> str:
        return ".enc" if _encrypt_enabled() else ".json"

    def _glob(self) -> str:
        return f"*{self._ext()}"

    def path(self, key: str) -> Path:
        return self.dir / f"{key}{self._ext()}"

    def get(self, key: str) -> dict | None:
        p = self.path(key)
        if not p.exists():
            return None
        if _encrypt_enabled():
            from backend.crypto import decrypt
            blob = p.read_bytes()
            return json.loads(decrypt(blob, _PASSPHRASE))
        return json.loads(p.read_text())

    def put(self, key: str, data: Any) -> None:
        dest = self.path(key)
        payload = json.dumps(data, indent=2, default=str)
        if _encrypt_enabled():
            from backend.crypto import encrypt
            _atomic_write(dest, encrypt(payload.encode(), _PASSPHRASE), self.dir)
        else:
            _atomic_write(dest, payload.encode(), self.dir)

    async def update(self, key: str, fn: Callable[[dict], dict],
                     default: dict | None = None) -> dict:
        """Atomically read-modify-write a key under an asyncio lock.

        fn receives the current value (or default if key doesn't exist)
        and must return the new value to store. The lock ensures no
        concurrent coroutine can interleave between the read and write.
        """
        async with self._lock_for(key):
            current = self.get(key)
            if current is None:
                current = default if default is not None else {}
            updated = fn(current)
            self.put(key, updated)
            return updated

    def delete(self, key: str) -> bool:
        p = self.path(key)
        if p.exists():
            p.unlink()
            return True
        return False

    def list_all(self) -> list[dict]:
        results = []
        for f in sorted(self.dir.glob(self._glob())):
            try:
                if _encrypt_enabled():
                    from backend.crypto import decrypt
                    results.append(json.loads(decrypt(f.read_bytes(), _PASSPHRASE)))
                else:
                    results.append(json.loads(f.read_text()))
            except Exception:
                pass
        return results

    def list_keys(self) -> list[str]:
        return [f.stem for f in sorted(self.dir.glob(self._glob()))]

    def clear_all(self) -> int:
        count = 0
        for f in self.dir.glob(self._glob()):
            f.unlink()
            count += 1
        return count
