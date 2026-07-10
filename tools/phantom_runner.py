"""Env-var entrypoint for `phantom_join.run_chain` — invoked by the
:8092 dashboard so the operator's password never appears on a CLI
that `ps` could capture.

Reads `PHANTOM_*` env vars in lieu of CLI flags and calls
`phantom_join.run_chain(args)` directly. Output goes to stdout (which
the spawning subprocess pipes to the dashboard WS).

Required:
  PHANTOM_USERNAME      target UPN
  PHANTOM_PASSWORD      target password
  PHANTOM_DOMAIN        target tenant domain
Optional:
  PHANTOM_DEVICE_NAME   defaults to an auto-generated WKS-XXXXX style name
  PHANTOM_INTUNE        "1" / "true" to enable the Intune phases (8 + 9)
  PHANTOM_INTUNE_HOST   Intune service host (required when INTUNE=1)
  PHANTOM_HYBRID_DOMAIN on-prem domain for the hybrid bypass
  PHANTOM_START_PHASE   skip-to-phase (1..9, default 1)
  PHANTOM_STOP_PHASE    stop-after-phase (1..9, default no cap)
  PHANTOM_FORCE         "1" / "true" to continue past phase failures
  PHANTOM_DRY_RUN       "1" / "true" to log intended commands without executing
  PHANTOM_OUTPUT_DIR    base output dir (default ".")

Authorized engagements only — same gate as
`backend/routes/phantom.py:allow_phantom_join` config flag."""

from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in ("1", "true", "yes", "on")


def _autogen_device_name() -> str:
    prefixes = ("WKS", "DESKTOP", "LAPTOP", "YOURPC")
    suffix = "".join(
        random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=5)
    )
    return f"{random.choice(prefixes)}-{suffix}"


def _int_env(key: str, default: int | None = None) -> int | None:
    raw = os.environ.get(key, "")
    if not raw.strip():
        return default
    try:
        v = int(raw)
        return v if v > 0 else default
    except ValueError:
        return default


def main() -> None:
    user = os.environ.get("PHANTOM_USERNAME", "").strip()
    pwd = os.environ.get("PHANTOM_PASSWORD", "")
    domain = os.environ.get("PHANTOM_DOMAIN", "").strip()
    if not user or not pwd or not domain:
        print("phantom_runner: PHANTOM_USERNAME, PHANTOM_PASSWORD, "
              "PHANTOM_DOMAIN are all required", file=sys.stderr)
        sys.exit(2)

    args = argparse.Namespace(
        username=user,
        password=pwd,
        domain=domain,
        device_name=os.environ.get("PHANTOM_DEVICE_NAME", "").strip()
                     or _autogen_device_name(),
        intune=_truthy(os.environ.get("PHANTOM_INTUNE")),
        intune_host=os.environ.get("PHANTOM_INTUNE_HOST", "").strip(),
        hybrid_domain=os.environ.get("PHANTOM_HYBRID_DOMAIN", "").strip(),
        start_phase=_int_env("PHANTOM_START_PHASE", 1) or 1,
        stop_phase=_int_env("PHANTOM_STOP_PHASE", None),
        force=_truthy(os.environ.get("PHANTOM_FORCE")),
        dry_run=_truthy(os.environ.get("PHANTOM_DRY_RUN")),
        output_dir=os.environ.get("PHANTOM_OUTPUT_DIR", "").strip() or ".",
    )

    # Import lazily so a missing-roadtools install only errors out
    # *after* we've validated the env shape — friendlier message.
    from tools.phantom_join import run_chain
    run_chain(args)


if __name__ == "__main__":
    # Make the parent of this file importable so `from tools.phantom_join`
    # resolves when invoked as `python -m tools.phantom_runner` from any cwd.
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    main()
