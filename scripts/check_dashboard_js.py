#!/usr/bin/env python3
"""Syntax-check the inline dashboard JavaScript.

The :8092 dashboard is one giant server-rendered page: its entire
JavaScript lives in a single inline <script> inside the
`DASHBOARD_HTML` raw-string constant in backend/debug_server.py. A single
syntax error there (e.g. a bad escape in a Python-embedded JS string
closing a string early) silently kills the WHOLE script — the page loads
but nothing runs and the WebSockets never connect, so it looks like "the
dashboard won't connect" with a 200 from the server.

This extracts those <script> blocks statically (via `ast`, without
importing/running the app) and runs `node --check` on each so that class
of break is caught at build time instead of in the browser.

Exit codes: 0 = OK (or node/constant unavailable → skip, non-fatal),
            1 = a script block failed to parse.
"""
from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "backend", "debug_server.py")


def _dashboard_html() -> str | None:
    """Return the value of the DASHBOARD_HTML string constant, or None."""
    try:
        tree = ast.parse(open(SRC, encoding="utf-8").read())
    except (OSError, SyntaxError) as e:
        print(f"check_dashboard_js: cannot parse {SRC}: {e}", file=sys.stderr)
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if (isinstance(tgt, ast.Name) and tgt.id == "DASHBOARD_HTML"
                        and isinstance(node.value, ast.Constant)
                        and isinstance(node.value.value, str)):
                    return node.value.value
    return None


def main() -> int:
    if not shutil.which("node"):
        print("check_dashboard_js: node not found — skipping (non-fatal)")
        return 0
    html = _dashboard_html()
    if html is None:
        print("check_dashboard_js: DASHBOARD_HTML constant not found — skipping")
        return 0

    scripts = re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S | re.I)
    bad = 0
    checked = 0
    for i, code in enumerate(scripts, 1):
        if not code.strip():
            continue
        checked += 1
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(code)
            path = fh.name
        try:
            res = subprocess.run(["node", "--check", path],
                                 capture_output=True, text=True)
        finally:
            os.unlink(path)
        if res.returncode != 0:
            bad += 1
            print(f"✗ dashboard <script> #{i} ({len(code)} chars) has a "
                  f"syntax error:\n{res.stderr.strip()}", file=sys.stderr)

    if bad:
        print(f"✗ dashboard JS check FAILED — {bad} of {checked} block(s) "
              f"broken. The dashboard would load but not run.", file=sys.stderr)
        return 1
    print(f"✓ dashboard JS OK ({checked} inline script block(s) parsed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
