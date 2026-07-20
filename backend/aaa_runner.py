"""Run AbuseAzureAPIPermissions.ps1 functions with a captured access token.

The vendored script (`tools/AbuseAzureAPIPermissions/AbuseAzureAPIPermissions.ps1`)
exposes ~50 helpers; every one reads its bearer via `Get-AAAGraphToken`,
which simply returns `$Script:AAAtoken`. So we wrap the operator's request
into a tiny PowerShell snippet:

    . <script>
    $Script:AAAtoken = '<captured access_token>'
    <Function> <args> | ConvertTo-Json -Depth 6 -Compress

…and shell out to `pwsh`. The function name is checked against the
`aaa_runner.allowed_functions` allowlist from sites.yaml. Args come in as a
list of pre-parsed key/value pairs (or bare tokens) — we render them with
single-quote PS escaping so the operator can't break out of the wrapper.

Returns a dict with stdout / stderr / exit_code / elapsed_ms / parsed_json
(when stdout decoded as JSON) / error.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from backend import site_rules
from backend.shared import append_log, get_config_value


_FN_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,80}$")
_PARAM_NAME_RE = re.compile(r"^-?[A-Za-z][A-Za-z0-9_]{0,80}$")


def _script_path() -> Path:
    """Resolve the vendored script. Relative paths in the YAML are anchored
    to the repo root (parent of `backend/`)."""
    cfg = site_rules.aaa_runner_config()
    p = Path(cfg["script_path"])
    if not p.is_absolute():
        repo_root = Path(__file__).parent.parent
        p = repo_root / p
    return p


def is_pwsh_available() -> tuple[bool, str]:
    """(present, path-or-explanation)."""
    cfg = site_rules.aaa_runner_config()
    exe = shutil.which(cfg["pwsh"])
    if exe:
        return True, exe
    return False, (f"`{cfg['pwsh']}` not found on PATH. Install PowerShell "
                   f"(https://learn.microsoft.com/powershell/scripting/"
                   f"install/install-other-linux) and ensure `pwsh` is "
                   f"reachable from the proxy process.")


def script_present() -> tuple[bool, str]:
    p = _script_path()
    if p.exists():
        return True, str(p)
    return False, (f"AbuseAzureAPIPermissions.ps1 not found at {p}. Clone "
                   f"https://github.com/Hagrid29/AbuseAzureAPIPermissions "
                   f"into tools/ or set aaa_runner.script_path in "
                   f"sites.yaml.")


def info() -> dict[str, Any]:
    """Dashboard probe — used by the AAA button to decide whether to enable
    itself and which functions to list."""
    cfg = site_rules.aaa_runner_config()
    pwsh_ok, pwsh_msg = is_pwsh_available()
    script_ok, script_msg = script_present()
    return {
        "ready": pwsh_ok and script_ok,
        "pwsh": {"ok": pwsh_ok, "detail": pwsh_msg},
        "script": {"ok": script_ok, "detail": script_msg},
        "allowed_functions": list(cfg["allowed_functions"]),
        "timeout_seconds": cfg["timeout_seconds"],
    }


def _ps_quote(value: str) -> str:
    """Single-quote a string for PowerShell. Inside '…' the only escape
    needed is doubling embedded single quotes."""
    return "'" + value.replace("'", "''") + "'"


def _render_args(args: list[dict] | None) -> str:
    """Render the operator-supplied args as a PS argument string.

    Each entry is either:
      {"name": "UserId", "value": "alice@…"}        → -UserId 'alice@…'
      {"name": "Search"}                              → -Search
      {"value": "alice@…"}                            → 'alice@…'  (positional)

    Names are validated against PARAM_NAME_RE (alphanumeric + underscore,
    optional leading '-') and values are single-quoted, so a malicious
    operator can't break out of the wrapper.
    """
    if not args:
        return ""
    parts: list[str] = []
    for a in args:
        if not isinstance(a, dict):
            continue
        name = (a.get("name") or "").strip()
        value = a.get("value")
        if name:
            if not _PARAM_NAME_RE.match(name):
                raise ValueError(f"invalid arg name: {name!r}")
            if not name.startswith("-"):
                name = "-" + name
            parts.append(name)
        if value is not None:
            parts.append(_ps_quote(str(value)))
    return " ".join(parts)


def _pick_token(data: dict, token_index: int | None) -> tuple[str | None, str]:
    """Return (token, source-description). Prefers `tokens[i].access_token`,
    falls back to `captured_headers["access_token"].value`, then any
    Authorization-Bearer captured-header. None when nothing usable."""
    tokens = data.get("tokens") or []
    if isinstance(tokens, list) and tokens:
        idx = 0 if token_index is None else max(0,
                                                 min(token_index,
                                                     len(tokens) - 1))
        rec = tokens[idx]
        if isinstance(rec, dict):
            tok = rec.get("access_token") or rec.get("accessToken")
            if isinstance(tok, str) and tok:
                src_url = rec.get("source_url") or ""
                return tok, f"tokens[{idx}] from {src_url[:80]}"
    hdrs = data.get("captured_headers") or {}
    if isinstance(hdrs, dict):
        for key in ("access_token", "accessToken",
                    "Authorization: Bearer", "Authorization"):
            entry = hdrs.get(key)
            if isinstance(entry, dict):
                v = entry.get("value")
                if isinstance(v, str) and v:
                    if v.lower().startswith("bearer "):
                        v = v[7:]
                    return v, f"captured_headers[{key}]"
    return None, "no usable token"


async def run(site_id: str,
              data: dict,
              function: str,
              args: list[dict] | None = None,
              token_index: int | None = None) -> dict[str, Any]:
    """Invoke `<function>` from the script with the captured token.

    Returns:
        {ok, function, source, exit_code, elapsed_ms,
         stdout, stderr, parsed_json?, error?}
    """
    cfg = site_rules.aaa_runner_config()
    function = (function or "").strip()
    if not _FN_NAME_RE.match(function):
        return {"ok": False,
                "error": f"invalid function name: {function!r}"}
    allowed = set(cfg["allowed_functions"])
    if function not in allowed:
        return {"ok": False,
                "error": (f"function {function!r} not in aaa_runner."
                          f"allowed_functions — add it to "
                          f"$DATA_DIR/sites.yaml to enable.")}

    pwsh_ok, pwsh_detail = is_pwsh_available()
    if not pwsh_ok:
        return {"ok": False, "error": pwsh_detail}
    script_ok, script_detail = script_present()
    if not script_ok:
        return {"ok": False, "error": script_detail}

    token, token_source = _pick_token(data, token_index)
    if not token:
        return {"ok": False,
                "error": ("no access_token available for this credential "
                          "— capture a Graph-audience token first.")}

    try:
        rendered_args = _render_args(args)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    timeout_s = max(5, int(cfg["timeout_seconds"]))
    script_p = _script_path()
    # Build the wrapper. ConvertTo-Json with -Compress to keep stdout small;
    # we set ErrorActionPreference=Continue so partial output still streams
    # back when a command throws on a missing permission.
    # PlainText rendering: pwsh otherwise injects ANSI VT100 sequences into
    # stdout for error formatting (DEC private-mode `[?1h[?1l`, color codes),
    # which corrupts JSON parsing on the operator's side.
    wrapper = (
        "$ErrorActionPreference='Continue'\n"
        "if ($PSStyle) { $PSStyle.OutputRendering = 'PlainText' }\n"
        f". {_ps_quote(str(script_p))}\n"
        f"$Script:AAAtoken = {_ps_quote(token)}\n"
        f"try {{\n"
        f"  $r = {function} {rendered_args}\n"
        f"  if ($null -ne $r) {{ $r | ConvertTo-Json -Depth 6 -Compress }}\n"
        f"}} catch {{\n"
        f"  Write-Error $_.Exception.Message\n"
        f"  exit 1\n"
        f"}}\n"
    )

    pwsh_path = shutil.which(cfg["pwsh"]) or cfg["pwsh"]
    # `-File /dev/stdin` rather than `-Command -`: with `-Command -` pwsh
    # treats stdin as an interactive console and emits DEC private-mode
    # cursor sequences (`\e[?1h\e[?1l`) into stdout, which corrupts JSON
    # parsing on the operator's side. `-File /dev/stdin` produces clean
    # stdout. (Linux-only path; the proxy is a Linux service.)
    cmd = [pwsh_path, "-NonInteractive", "-NoProfile", "-NoLogo",
           "-File", "/dev/stdin"]
    t0 = time.time()
    append_log("info", "aaa_runner",
               f"[{site_id}] {function} args={len(args or [])} "
               f"token={token_source} timeout={timeout_s}s")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(Path(__file__).parent.parent),
            env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(wrapper.encode("utf-8")),
                timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            elapsed_ms = int((time.time() - t0) * 1000)
            append_log("warn", "aaa_runner",
                       f"[{site_id}] {function} timed out after "
                       f"{timeout_s}s")
            return {"ok": False, "function": function,
                    "source": token_source,
                    "exit_code": None, "elapsed_ms": elapsed_ms,
                    "stdout": "", "stderr": "",
                    "error": f"timed out after {timeout_s}s"}
    except FileNotFoundError as e:
        return {"ok": False,
                "error": f"failed to launch pwsh: {e}"}

    elapsed_ms = int((time.time() - t0) * 1000)
    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    exit_code = proc.returncode if proc.returncode is not None else -1

    parsed: Any = None
    if stdout.strip():
        try:
            parsed = json.loads(stdout)
        except Exception:
            parsed = None

    append_log("info" if exit_code == 0 else "warn", "aaa_runner",
               f"[{site_id}] {function} exit={exit_code} "
               f"elapsed={elapsed_ms}ms stdout={len(stdout)}b "
               f"stderr={len(stderr)}b")

    return {
        "ok": exit_code == 0,
        "function": function,
        "source": token_source,
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "stdout": stdout,
        "stderr": stderr,
        "parsed_json": parsed,
    }


# ── Get-AAATokenFromAzLogin: token-acquisition path ──
#
# Distinct from run() above. The recon functions consume a captured
# Graph token; Get-AAATokenFromAzLogin *acquires* one by calling
# Connect-AzAccount with operator-supplied user/password. The function
# itself has no return value — it stashes the token in $Script:AAAtoken
# as a side effect — so we have to emit that variable explicitly after
# the call.
#
# Az.Accounts requirement: Connect-AzAccount lives in the Az.Accounts
# PowerShell module, which is NOT bundled with pwsh. If it's missing,
# the wrapper fails with "Connect-AzAccount: The term ... is not
# recognized". We detect that pattern in stderr and rewrite the error
# so the operator sees an install hint instead of a confusing message.


_AZ_MODULE_MISSING_RE = re.compile(
    r"Connect-AzAccount.*not recognized", re.IGNORECASE | re.DOTALL)


async def persist_captured_token(site_id: str, access_token: str,
                                 source_url: str = "device-code",
                                 tenant_id: str = "") -> bool:
    """Append a captured access token to a credential record's `tokens[]` so
    it shows up in the AAA runner's Token dropdown. Shared by the
    Connect-AzAccount path and the device-code path. Returns True on success."""
    if not site_id or not access_token:
        return False
    try:
        from backend.store import JsonStore
        store = JsonStore("credentials")
        entry = {"access_token": access_token, "source_url": source_url,
                 "captured_at": int(time.time()), "tenant_id": tenant_id}

        def _append(rec: dict) -> dict:
            tokens = rec.get("tokens")
            if not isinstance(tokens, list):
                tokens = []
            tokens.append(entry)
            rec["tokens"] = tokens
            return rec

        await store.update(site_id, _append, default={"site_id": site_id})
        try:
            from backend.shared import notify_sites_changed
            notify_sites_changed()
        except Exception:
            pass
        return True
    except Exception as e:
        append_log("warn", "aaa_runner", f"[{site_id}] persist token failed: {e}")
        return False


async def acquire_token_via_az_login(
    site_id: str,
    user: str,
    password: str,
    tenant_id: str,
    service_principal: bool = True,
    persist: bool = True,
) -> dict[str, Any]:
    """Run Get-AAATokenFromAzLogin and capture $Script:AAAtoken.

    Args:
      site_id: credential record key — when persist=True the captured
        token is appended to credentials_store[site_id].tokens.
      user: -User value (UPN or app id).
      password: -Password value (plumbed via the wrapper-on-stdin path,
        not argv, so it never appears in `ps`).
      tenant_id: -TenantId value.
      service_principal: pass -ServicePrincipal when True.
      persist: append the captured token to the credential record.

    Returns:
      {ok, access_token?, persisted?, exit_code, elapsed_ms,
       stderr, error?}
    """
    cfg = site_rules.aaa_runner_config()
    user = (user or "").strip()
    tenant_id = (tenant_id or "").strip()
    if not user or not password or not tenant_id:
        return {"ok": False,
                "error": "user, password, tenant_id are all required"}

    pwsh_ok, pwsh_detail = is_pwsh_available()
    if not pwsh_ok:
        return {"ok": False, "error": pwsh_detail}
    script_ok, script_detail = script_present()
    if not script_ok:
        return {"ok": False, "error": script_detail}

    # Connect-AzAccount round-trips to login.microsoftonline.com — give
    # it more headroom than the recon-call default.
    timeout_s = max(int(cfg["timeout_seconds"]), 90)
    script_p = _script_path()
    sp_arg = "-ServicePrincipal" if service_principal else ""
    # `| Out-Null` suppresses ONLY the success-output stream (the
    # Connect-AzAccount welcome table) so the only thing on stdout is
    # our compact JSON. Earlier this used `*> $null` which also ate
    # the error stream — a bad-password failure showed up as the
    # opaque "no token captured" message instead of the real auth
    # error. Errors still reach our captured stderr.
    wrapper = (
        "$ErrorActionPreference='Continue'\n"
        "if ($PSStyle) { $PSStyle.OutputRendering = 'PlainText' }\n"
        f". {_ps_quote(str(script_p))}\n"
        f"try {{\n"
        f"  Get-AAATokenFromAzLogin -User {_ps_quote(user)} "
        f"-Password {_ps_quote(password)} "
        f"-TenantId {_ps_quote(tenant_id)} {sp_arg} "
        f"| Out-Null\n"
        f"  if ($Script:AAAtoken) {{\n"
        f"    @{{access_token=$Script:AAAtoken}} | "
        f"ConvertTo-Json -Compress\n"
        f"  }} else {{\n"
        f"    Write-Error 'no token captured — check user/password/"
        f"tenant or stderr above'\n"
        f"    exit 1\n"
        f"  }}\n"
        f"}} catch {{\n"
        f"  Write-Error $_.Exception.Message\n"
        f"  exit 1\n"
        f"}}\n"
    )

    pwsh_path = shutil.which(cfg["pwsh"]) or cfg["pwsh"]
    cmd = [pwsh_path, "-NonInteractive", "-NoProfile", "-NoLogo",
           "-File", "/dev/stdin"]
    t0 = time.time()
    # Don't log user/password — only the site_id, sp flag, and timing.
    append_log("info", "aaa_runner",
               f"[{site_id}] Get-AAATokenFromAzLogin sp={service_principal} "
               f"timeout={timeout_s}s")
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(Path(__file__).parent.parent),
            env={**os.environ, "POWERSHELL_TELEMETRY_OPTOUT": "1"},
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(wrapper.encode("utf-8")),
                timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
            return {"ok": False,
                    "error": f"timed out after {timeout_s}s "
                             f"(Connect-AzAccount round-trip)"}
    except FileNotFoundError as e:
        return {"ok": False,
                "error": f"failed to launch pwsh: {e}"}

    elapsed_ms = int((time.time() - t0) * 1000)
    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")
    exit_code = proc.returncode if proc.returncode is not None else -1

    # Friendlier surface for the most common failure mode.
    if _AZ_MODULE_MISSING_RE.search(stderr):
        append_log("warn", "aaa_runner",
                   f"[{site_id}] Get-AAATokenFromAzLogin: Az.Accounts "
                   f"module missing")
        return {
            "ok": False,
            "exit_code": exit_code,
            "elapsed_ms": elapsed_ms,
            "stderr": stderr,
            "error": ("Az.Accounts PowerShell module not installed. "
                      "Run: pwsh -Command 'Install-Module Az.Accounts "
                      "-Scope CurrentUser -Force'"),
        }

    # Non-interactive Connect-AzAccount -Credential can't satisfy an MFA /
    # interaction-required Conditional Access policy — the most common failure
    # on a hardened tenant. Redirect to the paths that actually work there.
    if re.search(r"interaction[_ ]required|multi-?factor|user interaction is "
                 r"required|AADSTS500(76|79)", stderr, re.IGNORECASE):
        append_log("warn", "aaa_runner",
                   f"[{site_id}] Get-AAATokenFromAzLogin blocked by MFA/CA")
        return {
            "ok": False, "exit_code": exit_code, "elapsed_ms": elapsed_ms,
            "stderr": stderr,
            "error": ("Conditional Access requires MFA / interactive sign-in, so "
                      "Connect-AzAccount with a username+password can't get a "
                      "token here. Use a path that works on an MFA tenant: "
                      "(1) run the AAA functions directly with a Graph token you "
                      "already captured from the BITM session or the phantom "
                      "chain — pick it in the AAA runner's Token dropdown; no az "
                      "login needed. (2) Tick 'Service principal' and pass an app "
                      "(client) ID + secret as user/password to bypass user MFA. "
                      "(3) Get a token out-of-band via device code "
                      "(roadtx/AADInternals -UseDeviceCode) and use that."),
        }

    token: str | None = None
    if exit_code == 0 and stdout.strip():
        try:
            parsed = json.loads(stdout)
            tok = parsed.get("access_token") if isinstance(parsed, dict) else None
            if isinstance(tok, str) and tok:
                token = tok
        except Exception:
            pass

    persisted = False
    if token and persist:
        persisted = await persist_captured_token(
            site_id, token, "Get-AAATokenFromAzLogin", tenant_id)

    append_log("info" if exit_code == 0 else "warn", "aaa_runner",
               f"[{site_id}] Get-AAATokenFromAzLogin exit={exit_code} "
               f"elapsed={elapsed_ms}ms token={'yes' if token else 'no'} "
               f"persisted={persisted}")

    return {
        "ok": bool(token),
        "exit_code": exit_code,
        "elapsed_ms": elapsed_ms,
        "access_token": token,
        "persisted": persisted,
        "stderr": stderr,
        "error": None if token else (stderr.strip() or "no token captured"),
    }
