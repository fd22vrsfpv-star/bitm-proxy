# DEF CON RTV Lab — Setup Runbook

Operational runbook for running `bitm-proxy` as a hands-on lab: a
publicly-reachable, self-serve version of the "Your Passkeys Won't Save You"
demo, alongside the option for visitors to self-host the same Docker image
against their own tenant. See `docs/Grapnel-passkeys-RTV.html`/`.pptx` for
the talk itself; this doc is the lab infrastructure, not the talk content.

This is a one-time event runbook, not permanent architecture — see
`ARCHITECTURE.md` / `SESSIONS.md` for that.

---

## Architecture recap

Visitors interact entirely through the browser — nginx reverse-proxies into
the app's existing hosted Playwright-session UI (`:8091`, via `/tp8091/` or
the friendlier `/start` alias) and dashboard (`:8092`, via `/dashboard/`,
including the Phantom tab, the Captured Data tab's ROPC/Graph test
buttons, and a Burp Suite extension download). Nothing is exposed on any
proxy port; the auth proxy stays internal to the `app` container and is
used automatically by the hosted session, exactly as it already runs
today. No CA cert to install, no client proxy to configure.

Two allowlists (both empty/unrestricted by default, so this is purely opt-in
hardening) make the shared public instance structurally incapable of being
pointed at anything other than the lab tenant:

- **`config/sites.yaml` → `globals.proxy_allowed_hosts`** (or, better, set
  via `$DATA_DIR/sites.yaml` so the lab's specific hostnames don't land in
  the committed repo config) — the internal auth proxy will only
  intercept/decrypt traffic to hosts on this list; everything else passes
  through untouched. Populate with:
  ```yaml
  globals:
    proxy_allowed_hosts:
      - login.microsoftonline.com
      - graph.microsoft.com
      - graph.windows.net
      - enterpriseregistration.windows.net
      - enrollment.manage.microsoft.com
      - <labtenant>.onmicrosoft.com
  ```
- **`phantom_join_allowed_domains`** in `$DATA_DIR/config/config.json` (note
  the `config/` subdir — unlike `$DATA_DIR/sites.yaml`, which has none; or set
  it via the dashboard's Configuration tab) — Phantom Join will refuse to run
  against any domain not on this list.
  ```json
  { "phantom_join_allowed_domains": ["<labtenant>.onmicrosoft.com"] }
  ```

Both are checked in code (`backend/site_rules.py:host_allowed_for_proxy`,
`backend/routes/phantom.py:phantom_run_ws`) — not just documented as a rule
for operators to remember.

A third allowlist, `external_capture_allowed_ips`, guards
`/api/capture/external` (used by the silent-fingerprint and lander demo pages
below) and is **pre-seeded for you** — `config/lab-config.json` is
bind-mounted over the app's `config/config.json` in `docker-compose.yml`,
setting it to `172.28.238.0/24` (the fixed subnet `docker-compose.yml`
assigns to `lab_net`). This exists because `backend/routes/capture.py`'s IP
check uses the raw TCP peer address, not `X-Forwarded-For` — traffic through
nginx arrives from nginx's own container address on that subnet, not
loopback, so it would 403 by default without this. Nothing to configure here
unless you change the subnet.

**There is no login gate.** nginx has no `auth_basic`, and the app's own
API-key requirement is disabled (`REQUIRE_API_KEY=false` in
`docker-compose.yml`) since there's no browser-UI path for a visitor to ever
supply that key. Anyone who reaches the URL can use the lab — the two
allowlists above are the entire safety boundary, not an authentication
layer. Populate them **before** running `--public`/`-Public`.

### Recon/capture demo pages — `/silent` and `/lander`

`pages/silent.html` (drive-by fingerprinting, no visible interaction) and
`pages/lander.html` (credential-lander template) are baked into the `app`
image's `static/` directory at build time (`Dockerfile`), reachable through
the app's existing static catch-all route the same way README.md documents
for any manually-hosted lander page. nginx exposes them at the friendly
`/silent` and `/lander` aliases (redirecting to the actual `/silent.html` /
`/lander.html` paths), linked from the landing page's "Reconnaissance &
capture demos" section.

- Both are pre-configured with `endpoint: "/api/capture/external"` (relative,
  works through nginx regardless of domain) and
  `token: "lab-demo-capture-token"` — this **must match**
  `EXTERNAL_CAPTURE_TOKEN` in `docker-compose.yml` (same default). If you
  change one, change both.
- `lander.html`'s `next_url` matches the app's own `default_login_url`
  (`https://myapps.microsoft.com/`) — after submit, the visitor's browser
  goes to the real IdP portal, same as a real engagement, so the flow looks
  unbroken. This means whatever a visitor types gets captured **and** they
  land on a real Microsoft login page afterward — the landing page has an
  explicit "don't enter real credentials" warning for exactly this reason.
- Captured demo submissions land in the same `credentials_store` as any
  other capture (encrypted at rest if `CREDENTIAL_PASSPHRASE` is set) —
  clear it as part of the reset procedure below if you don't want lab
  visitors' demo submissions (fingerprints, whatever they typed) lingering
  after the event.

---

## Lab tenant setup

1. **Provision a Microsoft 365 Developer Program "Instant Sandbox" tenant**
   (free, renewable every 90 days with active use) — a tenant dedicated to
   this event, never a real/employer tenant. Includes Entra ID P2, required
   for Conditional Access + Identity Protection.
2. **Conditional Access policy**: require phishing-resistant MFA
   (authentication strength) for the demo user(s), scoped to all cloud apps,
   **enabled** (not report-only). This is the policy gap Path A's dead-end
   and Path B's bypass both depend on.
3. **Turn off (or set report-only) any Identity Protection risk-based CA
   policies** on this tenant — otherwise the lab's own sign-in pattern (many
   visitors, conference wifi/hotspot IPs) can self-trigger a block that has
   nothing to do with the demo.
4. **Two demo accounts** (lets two visitors use the lab at once without
   colliding on one account's session state), each provisioned identically:
   - A FIDO2/WHfB credential registered (satisfies the passkey requirement;
     feeds Path A's dead-end when only passkey tiles are offered).
   - A Microsoft Authenticator push method registered (feeds Path A's
     auto-click demo).
   - Register both ahead of time via `aka.ms/mysecurityinfo` — not live.
5. **Verify the gap** once configured: `phantom_join.py --dry-run`, then a
   real phase-1-only run, confirms AADSTS53003 blocks interactive/ROPC while
   device-code to DRS still succeeds.
6. Fill in the placeholders in `pages/lab-landing.html` (`PLACEHOLDER-demo1@...`,
   `PLACEHOLDER-demo2@...`, `PLACEHOLDER-password-*`) with the real demo
   account credentials before the event.

### Known constraint — accept, don't fix

Phantom Join enforces a single process-wide run at a time
(`backend/routes/phantom.py`'s `_run_lock`; a second `start` while one is
active gets `{"type": "busy"}`). With multiple concurrent visitors, only one
Phantom Join run happens at a time — the dashboard's existing "busy" state is
the natural queue. The landing page already sets this expectation.

### Reset after the event (and after every rehearsal)

1. Delete every phantom device created during the lab from Entra admin
   center → Devices. The tool's own local "delete" only removes the local
   cert copy, not the Entra device record — the portal is the only way to
   actually remove it.
2. Revoke sessions for both demo accounts (Users → account → Revoke
   sessions), so a stale PRT/session from a rehearsal can't short-circuit
   the "blocked then bypassed" narrative on a later run.
3. Wipe `$DATA_DIR/phantom/*` run directories **and `$DATA_DIR/devices/*`**
   (the silent-capture funnel builds one device profile per visitor `cid`
   — see *Silent capture → session correlation* in `SESSIONS.md` — so these
   accumulate across the event), or just recreate the `app_data` Docker
   volume, which clears all of that plus the credentials store — including
   any `/silent` and `/lander` demo submissions from visitors — and the
   self-signed cert/htpasswd-equivalent state.
4. Re-verify AADSTS53003 still reproduces after cleanup (Entra device/policy
   deletions can have a short propagation delay).

---

## Running it

### Self-hosted (default, safe out of the box)

```bash
git clone https://github.com/fd22vrsfpv-star/bitm-proxy.git
cd bitm-proxy
./run_demo.sh          # macOS / Linux
# or, on Windows:
.\run_demo.ps1
```

`run_demo.sh`/`run_demo.ps1` wrap `docker compose up --build -d`: they check
Docker is installed and running, start the stack, poll until nginx is
reachable, and open the URL in your default browser. `--stop`/`-Stop` tears
it back down. Run with `--help`/`Get-Help .\run_demo.ps1 -Full` for all
flags. (Plain `docker compose up --build` also works if you'd rather not use
the wrapper.)

- Publishes to `https://127.0.0.1/` — loopback-only, reachable only from the
  same machine. Never accidentally exposed to a LAN or the internet.
- `nginx/lab-entrypoint.sh` generates a self-signed cert on first run if one
  isn't already mounted — click through the browser's self-signed-cert
  warning; expected, since this never leaves your machine.
- No login gate (see Architecture recap above) — the allowlists are what
  keep this safe, not a password.
- To test your own tenant instead of the lab one: configure
  `phantom_join_allowed_domains` / `proxy_allowed_hosts` for your own domain
  via the dashboard/`$DATA_DIR` config, same as below.

### Public lab instance (organizers only)

```bash
./run_demo.sh --public --rebuild
# equivalent to:
BIND_HOST=0.0.0.0 \
CREDENTIAL_PASSPHRASE='<pick one>' \
  docker compose up --build -d
```

- `--public` (or `BIND_HOST=0.0.0.0`) exposes it beyond loopback — only do
  this on a host you intend to be public, with a real domain pointed at it,
  **and only after populating both allowlists** — there is no login gate to
  fall back on. Set `CREDENTIAL_PASSPHRASE` in your environment before
  running the wrapper so it picks it up.
- Mount a real cert over the self-signed fallback: put Let's Encrypt's
  `live/www.rtvbitm.com/{fullchain,privkey}.pem` into the `nginx_certs`
  volume (or bind-mount your own cert directory over `/etc/letsencrypt` in
  a `docker-compose.override.yml`) — `lab-entrypoint.sh` only generates a
  self-signed cert when real files aren't already present.
- Populate the two allowlists (see Architecture recap above) before
  publishing the URL anywhere.
- `CREDENTIAL_PASSPHRASE` enables encryption-at-rest for captured
  sessions/cookies/credentials (`backend/crypto.py`) — set it even though
  the data is just lab-account data, matching the repo's standing
  convention for any deployment that persists captured data.

---

## Cross-platform notes (Linux / Windows / macOS)

Both the public instance and self-hosted "run it yourself" visitors could be
on any of the three — going all-Docker is most of the portability story
already (host only needs Docker; everything else runs identically inside
Linux containers regardless of host OS).

- **Windows**: use Docker Desktop with the WSL2 backend (default on current
  installs). Windows Firewall may prompt on first `docker compose up` for
  the published ports — expected, not a misconfiguration.
- **Apple Silicon (arm64) Macs**: the Dockerfile already treats the Edge
  Playwright channel as best-effort (`playwright install msedge || echo
  "msedge unavailable (likely arm64)"`) — confirmed live: Microsoft has
  never shipped an arm64 Linux Edge build at all, so this isn't a
  transient gap, it stays disabled. Chromium and Firefox both have real
  arm64 Linux builds and work normally — also confirmed live, including
  actually launching Firefox and navigating a page, not just installing
  it. Set `browser_type` to `firefox` (Configuration tab) for a genuine
  Gecko engine on arm64 instead of a Chromium UA spoof. Both base images
  (`python:3.12-slim`, `node:20-alpine`) are multi-arch.
- **Resource allocation**: Playwright/Chromium is memory-hungry. If Docker
  Desktop's memory limit is at its historical low default (as little as
  2GB on some installs), bump it to 4GB+ before running this.
- **`.gitattributes`** in the repo root forces LF line endings for
  `*.sh`/`Dockerfile*`/`docker-compose.yml`/`nginx/*` — without it, a
  Windows checkout with `core.autocrlf=true` would silently rewrite these to
  CRLF and break the `#!/bin/bash`/`#!/bin/sh` shebangs inside the Linux
  containers.

---

## Pre-show checklist

1. Lab tenant: CA policy live and enabled, Identity Protection risk
   policies off/report-only, both demo accounts have FIDO2/WHfB + push
   registered, tenant risk state clean (no unresolved risky sign-ins).
2. `proxy_allowed_hosts` and `phantom_join_allowed_domains` populated with
   the lab tenant's real hostnames/domain — not left empty.
3. `pages/lab-landing.html` placeholders replaced with the real demo
   credentials.
4. Public instance: `BIND_HOST=0.0.0.0`, real cert in place (not the
   self-signed fallback). No login gate exists — step 2 is the only thing
   standing between "public lab" and "public lab that only ever touches
   the lab tenant," confirm it's actually populated.
5. Full dry run end-to-end: Path A (push auto-click) and Path B (Phantom
   Join through phase 5) both complete successfully from a browser hitting
   the public URL, not just from the docker host directly.
6. Reset procedure (above) run once more immediately before doors open, so
   the tenant's device list starts clean.
