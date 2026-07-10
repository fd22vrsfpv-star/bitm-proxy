"""Cross-platform path resolution for Windows standalone, macOS local, and Docker."""

import os
import sys
from pathlib import Path


def _default_app_dir() -> Path:
    """Return the default application data directory."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        return base / "MitmProxy"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "MitmProxy"
    # Docker / Linux — use legacy paths
    return Path("/data")


def _legacy_linux_default(name: str) -> Path:
    """Absolute paths used inside the Docker image."""
    return Path(f"/{name}")


def data_dir() -> Path:
    if sys.platform == "win32":
        default = _default_app_dir() / "data"
    elif sys.platform == "darwin":
        default = _default_app_dir() / "data"
    else:
        default = _legacy_linux_default("data")
    d = Path(os.environ.get("DATA_DIR", str(default)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def screenshots_dir() -> Path:
    if sys.platform == "win32":
        default = _default_app_dir() / "screenshots"
    elif sys.platform == "darwin":
        default = _default_app_dir() / "screenshots"
    else:
        default = _legacy_linux_default("screenshots")
    d = Path(os.environ.get("SCREENSHOTS_DIR", str(default)))
    d.mkdir(parents=True, exist_ok=True)
    return d


def certs_dir() -> Path:
    if sys.platform == "win32":
        default = _default_app_dir() / "certs"
    elif sys.platform == "darwin":
        default = _default_app_dir() / "certs"
    else:
        default = _legacy_linux_default("certs")
    return Path(os.environ.get("CERTS_DIR", str(default)))


def is_docker() -> bool:
    """Detect if running inside Docker."""
    return os.path.exists("/.dockerenv") or os.environ.get("DOCKER", "") == "1"
