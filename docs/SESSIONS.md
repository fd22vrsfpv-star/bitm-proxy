# Sessions & Configuration Reference

Two parts:

- **Sessions** — every "session"-like thing the stack tracks, how it is
  keyed, where it lives in memory or on disk, and what lifecycle events
  touch it.
- **Configuration variables** — everything in `_config` with its default
  and what it actually does, grouped by settings-page subtab.

---

## Sessions — the ten kinds

### 1. Browser session (Playwright)

The primary unit of work. One remote-controlled browser with its own
context, cookies, and flow trace.

| Attribute | Value |
|---|---|
| Session ID format | `{site_id}_{unix_ts}` (e.g. `microsoft_1729560000`) |
| Created by | `GET /api/browser/session` (WebSocket) — `backend/routes/browser.py` |
| In-memory registry | `shared._active_sessions[sid]` (dashboard-visible metadata) |
| Playwright handle | `routes.browser._live_pages[sid]` (the live `Page`) |
| Persisted? | No — the session ends when the WS closes |
| Visible on | Sessions dropdown (top bar) + Sessions tab |

Key attached info (`register_session(sid, {...})`):

- `login_url` — the resolved destination URL Playwright was pointed at.
- `site_id` — derived from the URL hostname (see `site_rules.py` +
  `config/sites.yaml`).
- `user_id` — captured once the user types an email/username into the
  login page; rekeys any stored credentials.
- `started_at` — unix timestamp the session was opened.

Lifecycle: WS open → `register_session` → URL reporter loop watches
`page.url` for login / auth-complete → `_do_auto_capture` on success →
optional `post_login_redirect` → WS close → `unregister_session`.

When `post_login_redirect_enabled` is on, the operator's browser tab
navigates away (and the WS closes), but the Playwright session is
**kept alive** — strong refs to the `pw`/`browser`/`context`/`page` are
parked in `_kept_alive[sid]` and the entry stays in `_live_pages` so
`_fetch_via_playwright` (auth proxy) can keep routing authenticated
requests through it. Inspect with `GET /api/browser/kept-alive`,
tear down with `DELETE /api/browser/kept-alive/{sid}`. Otherwise
sessions live until process restart.

Related config: `browser_type`, `browser_chrome`, `mobile_emulation`,
`private_mode`, `ignore_ssl`, `goto_timeout`.

Per-session WS query params on `/api/browser/session`:
`login_url`, `target`, `login_hint`, `width`, `height`, `private`,
`device_id`, `start_url`, `trace`, `prefer_push`.

`device_id` resolution (`v1.16.0+`): when the query param is empty,
`browser_session()` falls back to the `default_device_id` config key
(set on the `:8092` Configuration tab from a dropdown of registered
device profiles). Resolution order is: explicit `?device_id=` → config
default → no profile. A stale or deleted default id falls through
silently to "no profile" so an operator who removes the configured
default doesn't break new `:8091` sessions; a `DEVICE_DEFAULT
id=… not found` line lands in the `devices` log category to flag
the silent fall-through.

`prefer_push` defaults to `false` (config key of the same name) and
auto-clicks the "Approve a request on my Microsoft Authenticator
app" tile (`[data-value="PhoneAppNotification"]`) on the MS sign-in
method picker. Use this for accounts where MFA is configured with
Authenticator app push — the user sees the number-match challenge in
the dashboard log (`MFA NUMBER MATCH — tap **N** in the
authenticator app`, surfaced by `site_rules` against
`#idRichContext_DisplaySign`) and approves on their phone. Works in
fully headless / remote-server setups, unlike phone-based passkeys.

MFA dead-end recovery: when the picker shows only passkey-class
tiles (no push or other completable method), behavior splits on
launch type:

- **Subject-link / auto-launched sessions** — fires the existing
  `post_login_redirect` WS message via `_fire_dead_end_redirect`.
  The frontend handler at `BrowserAuth.tsx` does
  `window.location.href = url` so the operator's dashboard tab
  navigates same-tab. Destination is `post_login_redirect_url` if
  set, otherwise the original target URL the session was launched
  at. The helper sets `keep_alive_after_redirect=True` and
  stashes refs in `_kept_alive` before sending the WS message —
  same as the success-path post-login redirect — so the
  destructive cleanup doesn't race the operator's navigation.
- **Operator-driven device launches** (`v1.19.0+`, Devices →
  Launch with `device_id` set) suppress the auto-redirect so the
  test session stays inspectable in the canvas. Two optional
  fallbacks then fire, both off by default and config-gated:
  - `mfa_dead_end_show_qr` clicks the FIDO/passkey tile (one of
    `FidoKey`, `Fido`, `WindowsHelloForBusiness`) so MS renders
    its native passkey UI / cross-device QR inside the page. The
    QR will display, but BLE pairing from a remote server can't
    complete; this is a *diagnostic* surface for "see where the
    flow stalls", not a working auth path.
  - `mfa_dead_end_device_code_enabled` navigates the Playwright
    session to `mfa_dead_end_device_code_url` (default
    `https://microsoft.com/devicelogin`). The operator scans /
    types the code on a phone; an Entra app with the device-code
    grant returns a token via a different OAuth path. Skipped if
    the QR click already advanced the page.
  The status message sent over WS is tailored to which fallback
  fired (or the static "Passkey Error" fallback when both are
  off / unavailable).

Idempotent via `_mfa_dead_end_fired` regardless of which branch
fires. Passkey-class tiles are detected via data-value membership
in `{Fido, FidoKey, WindowsHelloForBusiness}` — extend
`browser.py:_passkey_dvs` if MS adds new passkey variants.

Conditional Access block detail (`v1.13.0+`): when a session lands on
an `aka.ms/conditionalaccess` URL (or any URL listed under
`globals.ca_blocked.url_match_patterns` in `config/sites.yaml`),
`_classify_challenge` parses the configured query/fragment params
(`globals.ca_blocked.param_keys`) into a `details` dict that is:
(a) appended to the existing `CHALLENGE ca_blocked …` log line on the
:8092 dashboard as `key=value` pairs, and (b) attached to the
`challenge` WebSocket event under the `details` field. Param-name
match is case-insensitive — list a canonical spelling once and AAD's
casing drift (`Reason` vs `reason`) lands under it. The dedup key for
the log line includes a sorted fingerprint of `details`, so a second
CA block in the same session with different params re-logs (instead
of being suppressed as a duplicate of the first). Accessor:
`site_rules.ca_blocked_config()` — cached against the merged-rules
dict identity per the YAML hot-reload pattern.

Phantom Join (`v1.20.0+`): operator-driven AAD CA bypass via
`tools/phantom_runner.py` (env-var wrapper around vendored
`tools/phantom_join.py`). The `:8092` Phantom tab spawns the runner
as a subprocess under `$DATA_DIR/phantom/<ts>/`, streams stdout
line-by-line over `/api/phantom/run` (WebSocket), and reads the
findings JSON on completion to render a severity-coloured findings
panel. Single concurrent run enforced via `_run_lock` in
`backend/routes/phantom.py`; second `start` returns `{type:"busy"}`.
Stop button sends `{cmd:"stop"}` which SIGTERMs the subprocess (then
SIGKILL after 5 s). The `allow_phantom_join` config flag (default
**off**) gates the route — the tab itself is hidden in the dashboard
when off. Password is delivered to the runner via `PHANTOM_PASSWORD`
env var so it never appears on the spawned process's argv (i.e. not
`ps`-visible). Requires ROADtools installed on the host
(`pip install roadrecon roadtx`); the runner's first phase calls
`roadtx` and exits non-zero if not found, surfaced in the live log.

`phantom_join_allowed_domains` (default `[]`, unrestricted) is a second
gate checked in `phantom_run_ws()` right after `allow_phantom_join`: if
non-empty, the requested `domain` param must case-insensitively match an
entry or the WS returns `{type:"denied"}` before the runner spawns.
Opt-in hardening for a deployment that must not be pointable at an
arbitrary real tenant (the DEF CON RTV Lab's public instance) — every
existing single-operator install is unaffected since the default is
unrestricted.


### 2. Sub-session

A per-login record *inside* a browser session. Lets you see multiple
login attempts under the same browser context (e.g. first attempt fails,
second attempt uses a different user).

| Attribute | Value |
|---|---|
| Store | `backend/subsessions.py` → in-memory `_active[sid]`, backed by `JsonStore("subsessions")` |
| Created by | `start_subsession(sid, site_id, user_id, login_url)` on browser-session open |
| User binding | `set_user_id(sid, text)` when the dashboard captures an email/username |
| Records | `auto_capture`, `captured_input`, `mfa_number_match`, navigation events — each with a timestamp |
| Visible on | Sessions tab → per-session drill-down |
| Persisted? | Yes — `JsonStore("subsessions")` → `$DATA_DIR/subsessions/<sid>.json` (survives restart) |

### 3. Host capture

A rolling per-hostname event store that accumulates captures across
different browser sessions — useful when you log into the same IdP from
multiple users and want a hostname-scoped history.

| Attribute | Value |
|---|---|
| Store | `backend/host_captures.py` → in-memory `_cache[hostname]`, backed by `JsonStore("host_captures")` |
| Key | Hostname (e.g. `login.microsoftonline.com`) |
| Buffer | Rolling 500 events per host |
| Visible on | Captures tab |
| Persisted? | Yes — `JsonStore("host_captures")` → `$DATA_DIR/host_captures/<host>.json` (survives restart) |

### 4. Credentials store

The durable record of what was captured. Keyed by `{site_id}__{user_id}`
so multiple users per site each get their own record.

| Attribute | Value |
|---|---|
| Store | `backend/stores.py` → `credentials_store` |
| Key format | `site_id__user_id` (e.g. `microsoft__alice@example.com`) |
| On disk | `$DATA_DIR/credentials/<key>.json` (AES-256-GCM when `CREDENTIAL_PASSPHRASE` is set) |
| Contents | `cookies`, `local_storage`, `session_storage`, `tokens`, `captured_inputs`, `captured_at`, `current_url` |
| Read with | `read_creds.py` (needs passphrase if encrypted) |

### 5. Cookies store

Parallel store keyed the same way as credentials; lets the auth proxy or
a fresh session **rehydrate** a Playwright context without re-logging-in.

| Attribute | Value |
|---|---|
| Store | `cookies_store` (same module) |
| Key format | Same as credentials — `site_id__user_id` |
| On disk | `$DATA_DIR/cookies/<key>.json` |

### 6. Flow trace buffer

The timeline you see in Flow Trace. Per-browser-session ring buffer of
captured HTTP exchanges (headers, bodies up to 64 KB, status, timing).

| Attribute | Value |
|---|---|
| Store | `shared._session_flows[sid]` |
| Buffer size | 2000 exchanges per session |
| Entry fields | `seq`, `method`, `url`, `status`, `request_headers`, `request_body`, `response_headers`, `response_body`, `flag_error`, `auth_milestones`, `resource_type`, `ts_req`, `ts_resp` |
| Append / update | `append_flow(sid, entry)` / `update_flow(sid, req_id, patch)` |
| Persisted? | No — buffer dies with the session |
| Auth-flow milestones | `backend/auth_milestones.classify(entry)` runs in `_on_flow_response` (`backend/routes/browser.py`) and tags each row with one or more `{kind, label, detail}` dicts on the `auth_milestones` field. Kinds: `login` (LOGIN — IdP login pages, flowToken bodies, Okta stateHandle), `code` (AUTH CODE — `Location: …code=…` redirect-back), `tokens` / `refresh` / `prt` (TOKENS / REFRESH / PRT — `POST /token` keyed on `grant_type` + issued tokens), `session` (SESSION — `Set-Cookie: ESTSAUTH*`/`x-ms-PRT`/`SignInStateCookie`/etc.), `bearer` (BEARER — `Authorization: Bearer <jwt>` in-flight), `ca_blocked` (CA-BLOCKED — `aka.ms/conditionalaccess` URL/Location, or AADSTS5300x in body), `ca_reprocess` (CA-REPROCESS — `/common/reprocess` claim challenge), `rp_reject` (RP-REJECT — 4xx/5xx on a relying-party callback URL on a non-IdP host), `mdm_discover` / `mdm_enroll` / `mdm_checkin` (MDM-DISCOVER / MDM-ENROLL / MDM-CHECKIN — Intune enrollment + SyncML/OMA-DM check-in traffic; visibility-only, host-scoped to the Intune service domains). The Flow Trace UI renders each as a colour-coded pill next to the URL via `flowRowHtml` (`backend/debug_server.py`). All recognition rules (idp_hosts, login/token/not_login path patterns, body markers, session cookie names + prefixes, PRT prefixes / grant types / scopes / token types, CA URL patterns + AADSTS codes, RP callback URL patterns, Intune MDM endpoint patterns + host scope) live under `auth_milestones:`, `globals.ca_milestones:`, `globals.rp_callbacks:`, and `globals.mdm_milestones:` in `config/sites.yaml` and deep-merge with `$DATA_DIR/sites.yaml`; regexes are compiled once per hot-reload via `site_rules.auth_milestones_config()` / `ca_milestones_config()` / `rp_callback_config()` / `mdm_milestones_config()` and cached against the merged-rules dict identity, so YAML edits land within a second without restart. Auth codes in URL/Location strings are masked (`code=<redacted>`) before being stored on the entry's `detail`. CA URL params (Reason, Policy, client-request-id, deviceId, etc.) are extracted by the shared `parse_ca_blocked_details(url)` helper, used by both `auth_milestones.classify` and the live `_classify_challenge` path. **Intune compliance verdict (`isCompliant: true/false`) is server-side and not extracted from the SyncML body** — look at the next id_token's `deviceid` claim for what AAD ended up believing. |
| Decoded JWTs (Index tab) | The Index tab's first section is *Decoded JWTs*. `_idxScanJwts(entry)` walks each flow row and extracts JWT-shaped tokens from `Authorization: Bearer …` (req+resp), JSON body fields named `id_token` / `access_token` / `refresh_token` / `accessToken` / `idToken` / `refreshToken` / `jwt` / `sessionToken`, and Set-Cookie values. Decoder is the in-browser `_decodeJwt` (base64url + JSON, no signature verification). Detail pane shows `iss`, `aud`, `sub`, `upn`/`email`/`preferred_username`, `tid`, `oid`, `appid`, `scp`/`roles`, `amr`, plus `iat`/`nbf`/`exp` rendered as ISO + relative ("expires in 12m" / "expired 3h ago"). |

### 7. Dashboard WebSocket session

Every browser tab connected to `:8092/ws/data`. Used for live log +
flow-update fanout. Not a "session" in the Playwright sense.

| Attribute | Value |
|---|---|
| Registry | `shared._subscribers` (asyncio queues) |
| Backpressure | Drop-oldest when a client's queue fills (metric: `bus_metrics.dropped`) |
| First-paint history | `ws_history_lines` (default 500) lines replayed on connect |

### 8. Auth-proxy BITM session

A TLS tunnel held by the Python BITM proxy on `:3128`. Used for
browsers configured to proxy through us — we forge a per-host
certificate, intercept, and route through either a Playwright session
(if `proxy_via_playwright`) or direct.

| Attribute | Value |
|---|---|
| Listener | `backend/auth_proxy.py` on `autostart_auth_proxy_port` (default 3128) |
| Per-host cert cache | In-memory dict, signed by the forged CA in `$CERTS_DIR` |
| Captured state | `_captured_sessions[hostname]` — cookies, Authorization/CSRF headers, **device fingerprint** (User-Agent + Sec-CH-UA-\* + Accept-Language) |
| Registry | `_live_pages` (if proxying via Playwright) |
| Related config | `autostart_auth_proxy`, `proxy_via_playwright`, `autostart_playwright_from_proxy`, `auto_login_wait_seconds`, `use_captured_fingerprint` |

### 9. Worker-pool session (experimental)

When `workers_enabled=true`, browser sessions are routed to a pool of
subprocess workers instead of running in the `:8091` process. Still
addressed by the same session ID; the dispatcher tracks which worker
owns which session.

| Attribute | Value |
|---|---|
| Dispatcher | `backend/worker/dispatcher.py` |
| RPC | Unix-domain socket, length-prefixed msgpack |
| Pool size | `worker_count` × `worker_sessions_max` |
| Status | Infrastructure landed; session routing through the pool still gated |

### 10. Device profile

A reusable, named bundle that fresh Playwright sessions can be launched
against. Where the auth-proxy BITM session (#8) holds *what's currently
flowing through `:3128`*, a device profile is the snapshotted, persisted
form — re-applicable to any session for any target.

A profile bundles three layers:

1. **Fingerprint** — User-Agent, Accept-Language, full Sec-CH-UA-*
   client-hint set; engine family + channel + curl_cffi impersonate tag
   are derived from the UA via `backend/ua_engine.py`.
2. **Probed JS signals** (optional) — timezone, screen, viewport,
   `navigator.languages`/`platform`/`hardwareConcurrency`/`deviceMemory`.
   Captured by the active probe (see below).
3. **Per-host credentials** (optional) — cookies, Authorization /
   CSRF / X-Auth headers, localStorage, sessionStorage. Sourced from
   the auth-proxy's `_captured_sessions` at register time, plus
   localStorage/sessionStorage from the probe page.

#### Three registration modes (register from `:3128` capture)

Selectable per-registration in the dashboard's **Devices** tab → *Register from capture…*:

- **Passive** — snapshot of what `_captured_sessions[hostname]` already
  holds. No prompt to the subject's browser.
- **Active JS probe** — also stamps a one-shot `_pending_probes[host]`
  entry. The next GET that flows through `:3128` to that host gets a
  **synthetic 200 OK** page from the proxy that runs JS to read
  timezone / screen / etc, POSTs the result to a sentinel path on the
  same host (`/__bitm_probe_callback?token=…&device_id=…&host=…`,
  consumed in-proxy — never touches upstream), then meta-refreshes to
  the original URL. Single-fire; the entry clears on consume.
- **Probe + cred snapshot** — same as Active probe, plus the probe
  page also serializes `localStorage` / `sessionStorage` into the
  POST body so the device profile carries the full client-side state.

#### Register from `:8091` Playwright session

When the operator authenticates inside the canvas at `:8091` (rather
than from a separate browser proxying through `:3128`), the same
device profile can be created directly from the running Playwright
session. The nav bar in `BrowserAuth.tsx` has a **Register device**
button that posts to `POST /api/devices/from-session` with the
session id (sent to the SPA in a `session_started` WS message right
after `ws.accept()`).

`backend.devices.register_from_session(page, modes, name, sites_filter)`
reads the profile contents straight from the live page:

| Field | Source |
|---|---|
| User-Agent | `await page.evaluate("() => navigator.userAgent")` |
| Sec-CH-UA-* hints | `navigator.userAgentData.getHighEntropyValues([...])` (when supported) |
| Accept-Language | First three entries of `navigator.languages`, joined |
| timezone_id | `Intl.DateTimeFormat().resolvedOptions().timeZone` |
| viewport | `page.viewport_size` |
| screen / DPR / colorDepth | `screen.{width,height,colorDepth}` + `devicePixelRatio` |
| platform / hardware_concurrency / device_memory | `navigator.{platform,hardwareConcurrency,deviceMemory}` |
| is_mobile | `navigator.userAgentData.mobile` (or UA fallback) |
| cookies (per host) | Grouped from `page.context.storage_state().cookies` by `cookie.domain` |
| localStorage (per host, per origin) | Grouped from `page.context.storage_state().origins` |
| sessionStorage | Read live from the active top-level page only (not in `storage_state`) |

Modes for from-session:

- **Passive** (always on) — fingerprint + JS signals. There's no
  separate probe step; the session is right here, we read the values
  live and they go straight into `probed{}`.
- **+ Creds** (the "include cookies + storage" checkbox) — adds the
  per-host credentials bundle described above.

`sites_filter` (optional) restricts the per-host bundle to a list of
hostnames. Default = include every host that storage_state surfaces.

#### Manual registration

Devices tab → *Add device…* exposes:

- **Preset dropdown** (`backend/devices.py:PRESETS`): `iphone-15-safari`,
  `pixel-8-chrome`, `win11-edge`, `macos-safari`, `win10-chrome`. Each
  preset prefills UA + client hints + viewport + DPR + locale +
  timezone.
- **Advanced free-form** form: paste any UA, override Accept-Language,
  locale, timezone, viewport WxH, DPR, mobile/touch flags, engine
  family, channel, impersonate tag, notes.

Engine/channel/impersonate are always re-derived from the final UA so
manual and captured paths produce identical-shape records.

#### Launch flow

The Devices list has per-row **Launch**. The dashboard sends
`launch_with_device` over the WS; the server returns a `browser_url` of
the form `http://<host>:8091/?auto=1&device_id=<id>&url=<encoded
start>`. The dashboard `window.open()`s it.

- `frontend/src/components/BrowserAuth.tsx` reads `device_id` and
  `start_url` from the page URL and forwards both to
  `/api/browser/session`.
- `browser_session()` in `backend/routes/browser.py`:
  - prefers `device.engine_family` / `device.channel` over the
    per-host fingerprint replay logic;
  - calls `devices.apply_to_context_opts(profile, context_opts)`
    immediately before `browser.new_context(**context_opts)` (sets UA,
    locale, timezone, viewport, mobile/touch, merges Sec-CH-UA-* into
    `extra_http_headers`);
  - calls `devices.apply_post_launch(profile, page)` immediately after
    `_live_pages[sid] = page` and before the first `goto` —
    `add_cookies()`, `set_extra_http_headers()`, and
    `add_init_script()` to seed local/sessionStorage;
  - bumps `last_used_at` on the profile.

The same profile can be launched any number of times; the device's
fingerprint and bundled creds are read fresh each time, so editing the
profile (Devices tab → *Edit*) takes effect on the next Launch.

| Attribute | Value |
|---|---|
| Module | `backend/devices.py` (logic), `backend/routes/devices.py` (REST), `backend/routes/browser.py` (launch hooks), `backend/auth_proxy.py:_build_probe_response`/`_handle_probe_callback` (active probe) |
| Storage | `JsonStore("devices")` → `$DATA_DIR/devices/<id>.{json,enc}`. Encrypted at rest when `CREDENTIAL_PASSPHRASE` is set. |
| Pending-probe registry | In-memory `_pending_probes: dict[host, {token, device_id, modes, sites, expires}]`; 30-minute TTL. |
| Sentinel callback path | `/__bitm_probe_callback` — intercepted in both the plain-HTTP and HTTPS-BITM dispatch paths; consumed in-proxy, returns 204; never reaches upstream. |
| WebSocket cmds | `list_devices`, `get_device`, `register_device_from_capture`, `register_device_from_session`, `register_device_manual`, `update_device`, `delete_device`, `launch_with_device`. |
| REST routes | `GET/POST /api/devices`, `GET /api/devices/presets`, `GET/PATCH/DELETE /api/devices/{id}`, `POST /api/devices/from-capture`, `POST /api/devices/from-session`, `POST /api/devices/probe-callback`. |
| Logging | All device events land on the `devices` log category with `DEVICE_*` verbs: `DEVICE_REGISTER_MANUAL`, `DEVICE_REGISTER_FROM_CAPTURE`, `DEVICE_REGISTER_FROM_SESSION`, `DEVICE_PROBE_PENDING`, `DEVICE_PROBE_PAGE_SERVED`, `DEVICE_PROBE_APPLIED`, `DEVICE_PROBE_REJECT`, `DEVICE_PROBE_ERROR`, `DEVICE_APPLY_CONTEXT`, `DEVICE_APPLY_POST_LAUNCH`, `DEVICE_LAUNCH_REQUEST`, `DEVICE_UPDATE`, `DEVICE_DELETE`. The dashboard's All-Logs filter and `journalctl -u bitm-proxy -g DEVICE_` both isolate them. Apply-context and apply-post-launch entries also bind to the affected `session_id` so per-session log files surface them. |
| Related config | `device_probe_enabled` (default `true`) — gates the synthetic-probe interception in `auth_proxy.py`. |
| UI | Dashboard `:8092` → **Devices** tab. Per-row badges show source / engine / probed / creds×N / mobile. |

---

## Configuration variables

Every knob in `shared._config`, grouped by where it appears in the
dashboard. Defaults reflect `backend/shared.py` as of commit `e77b564`.
Overrides persist to `$DATA_DIR/config/config.json` (diff-from-defaults,
atomic write).

### Configuration (Settings → Configuration)

Generic knobs not claimed by another subtab. As of `v1.18.1+` the
pane is grouped under in-page section headers — *Identity*,
*Default device profile*, *MFA*, *Post-login redirect*, *Auth
proxy / autostart*, *Capture / Flow Trace*, *Worker pool*,
*Dashboard*, *Logs*, plus an *Other* catchall — driven by the
`CFG_SECTIONS` array in `debug_server.py`. Keys not assigned to a
section land under *Other* so newly-added defaults stay visible
without code changes. `v1.19.1+` styles section headers in sky
blue with a thin underline and indents each section's rows under
a faint left rule.

| Key | Default | Purpose |
|---|---|---|
| `default_login_url` | `https://myapps.microsoft.com` | URL opened when a session is started with no explicit target. |
| `login_urls` | 6 presets | Preset buttons in the URL picker. A broader reference list of Microsoft Entra-gated sign-in surfaces (end-user, admin, developer, auth-infrastructure) lives in `docs/microsoft_entra_login_sites.xlsx` — all authenticate through the same Entra IdP, so any is a candidate target. |
| `auto_login_email` | `""` | Email auto-filled into login pages. Also drives Slack notification routing — when blank, captures/login-starts/keepalives are tagged "unknown user" and route to `slack_routine_webhook` if set. |
| `upstream_proxy` | `false` | Route Playwright through an upstream HTTP proxy. |
| `upstream_proxy_host` | `127.0.0.1:3128` | The upstream proxy endpoint. |
| `enable_token_testing` | `true` | Enables the "test captured token" buttons (Test Graph, Test ROPC, the v1+v2 `/token` test, Create ADO PAT). |
| `default_tenant_id` | `""` | Prefills the tenant field in the ROPC / `/token` / ADO-PAT / AAA tools when set. |
| `default_ado_org` | `""` | Prefills the **ADO org** field on every Captured Data → ADO PAT panel (Settings → Azure / ADO defaults). Empty leaves it blank → auto-discover via the vssps accounts API. |
| `allow_drs_replay` | `false` | Gates the DRS-replay feature (`/api/devices/drs-analyze-token`, `/api/devices/drs-register-from-token`, `/api/devices/drs-credentials*`) — register a device directly from a captured DRS token. |
| `prefer_push` | `false` | Auto-click MS's "Approve a request on my Microsoft Authenticator app" tile (`[data-value="PhoneAppNotification"]`) on the sign-in method picker. Use when MFA is configured with Authenticator push and the operator has the phone. |
| *(TAP → password, always-on)* | — | On MS's "Enter Temporary Access Pass" screen the hosted session prefers the password option when the account still offers it (a human can complete a password in the BITM session; a TAP is an out-of-band code we don't hold). If no password option is available it leaves the TAP prompt and proceeds. No config key — a no-op unless the TAP screen renders; logged under `auth`. (1.29.0) |
| `mfa_dead_end_show_qr` | `false` | Operator-launch-only (`v1.19.0+`). On dead-end (only passkey-class tiles in the picker), click the FIDO/passkey tile so MS renders its passkey UI / cross-device QR in the canvas. Diagnostic — BLE pairing from a remote server can't complete. |
| `mfa_dead_end_device_code_enabled` | `false` | Operator-launch-only (`v1.19.0+`). On dead-end, navigate the Playwright session to `mfa_dead_end_device_code_url`. Tests token issuance via the OAuth 2.0 device-code grant. Skipped if the QR click already advanced the page. |
| `mfa_dead_end_device_code_url` | `https://microsoft.com/devicelogin` | URL the device-code fallback navigates to. Override for tenant-specific or custom-app endpoints. |
| `post_login_redirect_enabled` | `false` | After auth is detected, redirect the operator's browser tab to the destination URL. The Playwright session itself stays put. |
| `post_login_redirect_url` | `""` | Explicit destination for the operator's browser; empty = original session target. |
| `post_login_redirect_playwright_enabled` | `false` | After auth is detected, navigate the Playwright session itself (the headless browser) to the destination URL. Independent from the operator-browser redirect — combine, swap, or skip. |
| `post_login_redirect_playwright_url` | `""` | Explicit destination for the Playwright session; empty = original session target. |
| `use_captured_fingerprint` | `false` | Replay the User-Agent + Sec-CH-UA-* client hints + Accept-Language captured from the user's real browser on `:3128` when Playwright launches. Makes the IdP see the same device signature. Matches by hostname only; in-memory (`_captured_sessions`), lost on restart unless promoted to a Device profile. |
| `fingerprint_match_engine` | `true` | Sub-knob of `use_captured_fingerprint`. When the captured UA says Firefox or Safari, Playwright launches `firefox` / `webkit` instead of Chromium so the TLS JA3 matches the UA. |
| `fingerprint_match_tls_proxy` | `true` | Sub-knob of `use_captured_fingerprint`. The auth-proxy's upstream leg uses `curl_cffi` impersonation (chrome / firefox / safari / edge) so origins see a real-browser JA3 instead of OpenSSL. Websocket upgrades and >50 MB responses bypass this path. |
| `device_probe_enabled` | `true` | When a device profile is registered with **Active JS probe** (or **Probe + cred snapshot**), the auth proxy serves a one-shot synthetic page on the next GET to that host so JS signals (timezone, screen, viewport, languages, platform, optional local/sessionStorage) get persisted into the profile. Set `false` to keep registrations in passive-only mode. See *Sessions → Device profile*. |
| `autostart_playwright_from_proxy` | `false` | When a new host is seen on :3128, launch a Playwright session for it. |
| `auto_login_wait_seconds` | `10` | How long `:3128` waits for auto-launched Playwright before falling through. |
| `noisy_extensions` | common asset/media list | File extensions the flow filter drops when `filter_noisy_requests` is on. |

### Browser (Settings → Browser)

| Key | Default | Purpose |
|---|---|---|
| `browser_type` | `edge` | `edge` (Chromium + Edge UA) / `edge-real` (native msedge, no arm64 Linux build exists) / `chrome` (Chromium + Chrome UA) / `firefox` (real bundled Gecko engine via `_engine_launch()`, not a UA spoof — has a genuine arm64 Linux build, verified live). |
| `browser_chrome` | `none` | `full` / `minimal` / `none` — which nav controls the :8091 viewer shows. |
| `private_mode` | `true` | Open each Playwright session in an incognito context (no persisted cookies). |
| `mobile_emulation` | `off` | `off` / `phone_android` / `phone_ios` / `tablet_*` device emulation. |
| `ignore_ssl` | `true` | Ignore upstream cert errors (Zscaler, corp proxy, forged CAs). |
| `goto_timeout` | `15000` | `page.goto()` timeout in ms. |
| `heartbeat_interval` | `10.0` | Idle heartbeat interval from Playwright to dashboard, seconds. |
| `screenshot_interval` | `0.3` | Seconds between screenshot frames. Re-read every tick — change without restarting the session. |
| `screenshot_quality` | `85` | JPEG quality 1–100. 85 is visually clean and ~30% smaller than 100. Re-read every tick. |
| `screenshot_dpr` | `2` | Device-pixel-ratio for desktop sessions. 2 renders the page at retina resolution so HiDPI operator screens see a sharp image. Mobile profiles ignore this and use the device's own DPR. 1 = legacy (lower bandwidth, fuzzier on retina). |
| `screenshot_low_fidelity_non_chromium` | `true` | (`v1.19.2+`) Firefox / WebKit sessions take the polling `page.screenshot()` loop because they have no CDP screencast. With this flag on, the polling loop caps `screenshot_quality` at 55 and clamps `screenshot_interval` to ≥0.5s, so typing into a WebKit canvas (e.g. iPad Safari profile) stays responsive on heavy pages. Chromium uses CDP screencast and reads the global values unmodified. |
| `max_screenshots` | `100` | Frames kept per session on disk. |

### Logging (Settings → Logging)

| Key | Default | Purpose |
|---|---|---|
| `verbose` | `false` | Log at DEBUG level. |
| `log_requests` | `false` | Emit every outbound HTTP request in All Logs. |
| `log_responses` | `false` | Emit every response line. |
| `log_auth_headers` | `true` | Log `Authorization` / cookie headers. |
| `log_set_cookies` | `true` | Log each inbound `Set-Cookie`. |
| `log_console` | `false` | Pipe browser console messages to All Logs. |
| `log_heartbeats` | `true` | Emit the idle HEARTBEAT line; noisy if on. |
| `log_to_file` | `false` | Also append All Logs to `$DATA_DIR/logs/app.log`. |
| `mask_captured_input` | `true` | Show `CAPTURED_INPUT=•••` instead of the raw value. |
| `hide_session_id_in_logs` | `false` | Blank the `[session_id]` column in All Logs. |

### Slack (Settings → Slack)

| Key | Default | Purpose |
|---|---|---|
| `enable_slack_notifications` | `true` | Master toggle for Slack webhooks. |
| `slack_keepalive_webhook` | `""` | Webhook pinged on keep-alive cycles. |
| `slack_capture_webhook` | `""` | Webhook pinged on a successful auto-capture. |
| `slack_routine_webhook` | `""` | Optional low-priority channel. Capture / login-start / token / keepalive notifications are routed here when `auto_login_email` is unset (`who == "unknown user"`); failure alerts always go to the keepalive/capture channels. Falls back to the regular channels when blank. Also settable via `SLACK_ROUTINE_WEBHOOK` env or `$DATA_DIR/config/slack_routine.txt`. |

### External Capture (v1.24.0+)

`POST /api/capture/external` accepts a JSON credential bundle from
pentester-side tooling (Burp extension, separate runner) and writes it
into the same `credentials` JsonStore + Slack capture channel that the
in-band BITM auth-proxy uses. Implementation in `backend/routes/capture.py`.

Body (only `site_id` is required):
`site_id`, `user`, `source_url`, `username`, `password`, `tokens`
(list of str or `{name, value, ...}`), `cookies` (list of cookie dicts;
replaces existing — mirrors `_merge_manual_capture`), `local_storage`,
`session_storage`, `captured_inputs`, `notes`.

| Key | Default | Purpose |
|---|---|---|
| `external_capture_token` | `""` | Bearer token required on every request. Empty disables the endpoint (returns 404). Settable via Configuration tab, `EXTERNAL_CAPTURE_TOKEN` env, or `config/external_capture_token.txt`. |
| `external_capture_allowed_ips` | `[]` | List of IPs/CIDRs allowed to POST. Loopback is always allowed; remote callers must be on this list. For cross-origin lander deployments (victim browsers post directly), set to `0.0.0.0/0` since the source IP is unpredictable. **Check uses the raw TCP peer address, not `X-Forwarded-For`** — behind a reverse proxy (e.g. the DEF CON RTV Lab's nginx), the peer is the proxy's own address, not the real client's. The lab's `config/lab-config.json` pre-seeds this with `docker-compose.yml`'s fixed `lab_net` subnet (`172.28.238.0/24`) for exactly this reason. |
| `external_capture_cors_origins` | `[]` | List of exact origins allowed to POST cross-origin (e.g. `https://lander.example.com`), or `*` for any origin. Empty = same-origin only (preflights return 403). Required for client-side landers on a separate domain. |

Auth header is either `Authorization: Bearer <token>` or
`X-Capture-Token: <token>`. Token comparison is constant-time.

Files:
- `backend/routes/capture.py` — endpoint implementation.
- `pages/lander.html` — engineering-documented variant. Same wire
  behaviour as `login.html` (below), but the top-of-file comments
  spell out the deployment hazards (token visibility, CORS
  requirements, IP-allowlist semantics) so operators reading the
  repo see the full context. Use this when learning the shape.
- `pages/login.html` — deployment-ready variant. Same JSON body
  and POST flow as `lander.html`, but the visible page source is
  stripped of operator-context comments and uses short neutral
  identifiers (`S.k`, `S.e`, `ctx()`, `rs()`, `rc()`) so a target
  viewing source sees only a login form that records session
  analytics. Edit the four-field `S` block at the top
  (`g` = site_id, `k` = token, `e` = endpoint, `n` = next URL)
  before deploying.
- `pages/silent.html` — no form, no visible interaction. Captures a
  device fingerprint on page load and POSTs it silently, then
  redirects after ~500ms — drive-by recon rather than credential
  capture. Same `CONFIG` shape (`site_id`/`token`/`endpoint` +
  `redirect_url` instead of `next_url`). It also mints a **correlation
  id** (`getCid()` — reuses an incoming `?cid=`, else `crypto.randomUUID`)
  , sends it with the capture, and appends it to the redirect, whose lab
  default is `/start` (the hosted session) — turning silent recon into a
  funnel that ties the captured device to the follow-on login. See
  *Silent capture → session correlation* below. In the DEF CON RTV Lab
  both this and `lander.html` are baked into the app image's
  `static/` at build time (`Dockerfile`) and reachable via nginx's
  `/silent` and `/lander` aliases — see `docs/DEFCON-LAB-SETUP.md`.

Both files capture: form inputs + device fingerprint (UA,
Sec-CH-UA-* via `userAgentData.getHighEntropyValues`, screen,
viewport, timezone, languages, hardware concurrency, WebGL
renderer/vendor) + same-origin cookies + `localStorage` /
`sessionStorage`, POST to `/api/capture/external` with
`keepalive: true`, then redirect to the configured next URL.
Same-origin hosting (drop into `static/`) sidesteps CORS;
cross-origin hosting requires `external_capture_cors_origins` to
list the page's origin (or `*`), and `external_capture_allowed_ips`
broadened to cover the browsers that will POST.

### Silent capture → session correlation (`cid`)

A deterministic tie between a silent fingerprint capture and the
follow-on login session, so a server-side Playwright session replays the
device signature of the visitor who was fingerprinted (added in 1.27.0).
The whole chain is keyed on one correlation id (`cid`) carried through
every hop:

| Hop | What carries the `cid` |
|---|---|
| `pages/silent.html` | Mints/reuses `cid`, sends it in the `/api/capture/external` body, appends `?cid=` to the redirect (`/start` in the lab) |
| `backend/routes/capture.py` | Stores `cid` on the silent capture's credential record |
| `nginx/rtvbitm` | `location = /start` uses `return 302 /tp8091/$is_args$args` to preserve the query string |
| `frontend/src/components/BrowserAuth.tsx` | Reads `?cid=` and forwards it as `cid=` on the `/api/browser/session` WebSocket (committed bundle rebuilt into `static/`) |
| `backend/routes/browser.py` | `browser_session` `?cid=` → `_find_capture_by_cid()` → `devices.find_or_create_for_cid()` builds/reuses a device profile and applies it (only when no explicit `?device_id`/default device wins); links both records; logs `CID_LINK` |
| `backend/devices.py` | `profile_from_external_fingerprint()` converts the JS-shaped silent fingerprint (`user_agent`, `languages`, `ua_data`, `screen`, `timezone`) into a header-shaped device profile (`User-Agent` + synthesized `sec-ch-ua-*` via the shared `_apply_ua_hints()`), plus viewport/locale/timezone/DSF |

Idempotent per `cid`: a visitor who starts several sessions reuses the
one device profile (`find_or_create_for_cid` scans for an existing device
tagged with the `cid`), so there's no Devices-tab churn. The linkage is
visible both ways — the device carries `cid` + `linked_capture_key`; the
silent capture carries `linked_device_id` + `linked_session_at`; and any
credentials the session goes on to capture are stamped with the same
`cid`. Reset for the event: the per-`cid` device profiles accumulate in
`$DATA_DIR/devices/` (one per visitor) — clear them alongside the phantom
devices in the post-event wipe (`docs/DEFCON-LAB-SETUP.md`).

### Flow / RAG / Ollama (Settings → Integrations)

| Key | Default | Purpose |
|---|---|---|
| `flow_trace_enabled` | `false` | Master gate for Flow Trace capture (`backend/routes/browser.py` records request/response flow only when on). |
| `rag_enabled` | `false` | Enables "Send to RAG" button on Flow Trace. |
| `rag_api_url` | `http://localhost:8000` | External RAG Scan Stack endpoint. `submit_flow_as_finding()` (`backend/rag_bridge.py`) auto-corrects a leftover `https://` scheme back to `http://` for `localhost:8000`/`127.0.0.1:8000`/`host.docker.internal:8000`, since the built-in RAG API doesn't terminate TLS — a common misconfig carried over from `burp-extension/RagScanBridge.py`'s own historical default. |
| `rag_api_key` | `""` | Sent as `x-api-key`. |
| `rag_engagement_id` | `""` | Optional UUID to attach findings to. |
| `ollama_enabled` | `false` | Enables the "Analyze (Ollama)" button. |
| `ollama_url` | `http://host.docker.internal:11434` | Ollama HTTP endpoint. |
| `ollama_model` | `llama3.1:8b` | Model tag; anything pulled on the Ollama server. |
| `ollama_temperature` | `0.1` | Lower = more deterministic. |
| `ollama_top_p` | `0.3` | Nucleus sampling. |
| `ollama_top_k` | `20` | Restrict to top K tokens. |
| `ollama_num_ctx` | `8192` | Context window in tokens. |
| `ollama_num_predict` | `512` | Max tokens to generate. `-1` = unlimited (model stops at EOS) — the old default that, with no streaming, blocked the UI for the whole generation. |
| `ollama_keep_alive` | `30m` | How long Ollama keeps the model resident after a request (avoids the multi-second cold reload between analyses). `-1` = forever, `0` = unload immediately. |
| `ollama_think` | `false` | Thinking/reasoning models (gemma4, qwen3) emit chain-of-thought into `message.thinking`, leaving `message.content` empty until done — so with a `num_predict` cap the model can spend the whole budget reasoning and return **empty** content. `false` = answer directly (recommended for analysis). Auto-retries without the param for models that reject it. |
| `ollama_seed` | `0` | `0` = random; non-zero for reproducibility. |
| `ollama_system_prompt` | *(long default)* | General-preset system prompt. |
| `ollama_system_prompt_sso` | `""` | Override for preset=sso; empty uses bundled schema. |
| `ollama_system_prompt_saml` | `""` | Override for preset=saml. |
| `ollama_system_prompt_oidc` | `""` | Override for preset=oidc. |
| `ollama_system_prompt_troubleshoot` | `""` | Override for preset=troubleshoot. |

### Performance (Settings → Performance)

| Key | Default | Purpose |
|---|---|---|
| `ws_history_lines` | `500` | Lines replayed to each new `/ws/data` subscriber. |
| `filter_noisy_requests` | `true` | Drop `noisy_extensions` + `noisy_hosts` from the flow trace. |
| `workers_enabled` | `false` | Route browser sessions through the worker subprocess pool. |
| `worker_count` | `4` | Number of worker subprocesses. |
| `worker_sessions_max` | `5` | Max concurrent Playwright sessions per worker. |

### Keep-alive (Settings → Keep-Alive)

| Key | Default | Purpose |
|---|---|---|
| `keepalive_enabled` | `true` | Run the background keep-alive loop. |
| `keepalive_interval_minutes` | `5` | Minutes between keep-alive pings. |
| `keepalive_max_consecutive_failures` | `2` | Give up keeping a session warm after this many back-to-back failures. |
| `keepalive_trace_enabled` | `false` | Emit per-ping keepalive trace logging. |
| `keepalive_playwright_fallback_enabled` | `false` | On a stale cookie-replay, fall back to a headless Playwright refresh. |
| `keepalive_playwright_timeout_seconds` | `12` | Timeout for that Playwright fallback refresh. |
| `keepalive_flow_capture_enabled` | `false` | Record keepalive requests into the flow trace. |

### Proxy (Settings → Proxy)

| Key | Default | Purpose |
|---|---|---|
| `autostart_auth_proxy` | `true` | Auto-start the Python BITM on service boot. |
| `autostart_auth_proxy_port` | `3128` | Bind port for the auth BITM. |
| `proxy_via_playwright` | `false` | When a proxied request matches a live Playwright session, route it through that session's context instead of direct. |
| `auto_login_wait_seconds` | `10` | Proxy wait timeout for an auto-launched Playwright to become ready. |

---

## AAA runner (AbuseAzureAPIPermissions.ps1)

Vendored Hagrid29 helpers for Graph-token recon/abuse, exposed per-credential
on the Captured Credentials card via the **AAA → Run function…** button.

| Piece | Where |
|---|---|
| Vendored script | `tools/AbuseAzureAPIPermissions/AbuseAzureAPIPermissions.ps1` |
| Allowlist | `aaa_runner.allowed_functions` in `config/sites.yaml` (extend in `$DATA_DIR/sites.yaml`; remember `_deep_merge` REPLACES lists) |
| Backend | `backend/aaa_runner.py` — checks pwsh on PATH, picks the access_token from the credentials record, builds a wrapper that dot-sources the script, sets `$Script:AAAtoken`, runs the function, captures stdout/stderr |
| Endpoints | `GET /api/aaa/info` (probe), `POST /api/aaa/run` (execute), `POST /api/aaa/login` (`Get-AAATokenFromAzLogin`) |
| UI | `renderCreds()` in `backend/debug_server.py` adds the AAA panel below the Test row; `renderAaaTokenSnippet()` adds the **Run via pwsh…** button on the `Get-AAATokenFromAzLogin` snippet |

Defaults are recon-only (`Get-AAA*` / `Find-AAA*`). Destructive verbs
(`Set-/New-/Remove-/Send-`) are rejected by the backend until the operator
adds them to `allowed_functions` in their override file. Every call hits
Microsoft Graph with the captured token, so each invocation lands in the
target tenant's sign-in logs.

**Install pwsh** (Linux service host) — the runner refuses to fire when
`pwsh` is absent and `/api/aaa/info` returns `ready=false` with the install
URL. Microsoft's [PowerShell on Linux install
docs](https://learn.microsoft.com/powershell/scripting/install/install-other-linux)
cover the supported package paths.

**Install Az.Accounts** for the **Run via pwsh…** path (`/api/aaa/login`)
— `Get-AAATokenFromAzLogin` calls `Connect-AzAccount`, which lives in
the `Az.Accounts` module and is NOT bundled with pwsh. `install-ubuntu.sh`
handles both pwsh and the Az.Accounts module install automatically (best-
effort, system-wide via `Install-Module … -Scope AllUsers`). For ad-hoc
hosts where the installer hasn't run, the first failed call detects the
missing module from stderr and returns the install hint (`pwsh -Command
'Install-Module Az.Accounts -Scope CurrentUser -Force'`) instead of the
raw "term not recognized" error. Tokens captured this way are appended
to `tokens[]` on the credential record (with
`source_url=Get-AAATokenFromAzLogin`) so the existing AAA runner can use
them downstream.

**User vs service-principal login (`-ServicePrincipal`)** —
`Get-AAATokenFromAzLogin` maps to `Connect-AzAccount`, and the `-ServicePrincipal`
switch changes what `-User`/`-Password` *mean*:

| Mode | `-User` | `-Password` | Switch |
|---|---|---|---|
| **User login** (default — captured creds) | user UPN / email | user password | *(none)* |
| **Service-principal login** | app (client) ID | client secret | `-ServicePrincipal` |

Captured BITM creds are **user** email/password, so the correct command is a
plain user login with **no** `-ServicePrincipal`:

```powershell
Get-AAATokenFromAzLogin -User "victim@tenant.onmicrosoft.com" -Password "…" -TenantId "…"
```

Passing `-ServicePrincipal` with a user's email makes `Connect-AzAccount` treat
the email as an application ID and fail. The login panel's **-ServicePrincipal
(app login)** checkbox therefore defaults **off**; tick it only when you hold an
app's client ID + secret. (The copyable `Get-AAATokenFromAzLogin` snippet on the
card omits the switch for the same reason.)

**Device-code login (MFA-capable alternative, 1.35.0)** — the AAA login
panel has a **Method** selector: *Password* (Connect-AzAccount, above) or
*Device code*. Device code runs the OAuth2 device-authorization grant for a
Graph scope via `POST /api/ado-devicecode/{start,poll}` — the operator
completes sign-in (with MFA) at `microsoft.com/devicelogin` and the resulting
Graph token is stashed on the credential record via `POST /api/aaa/store-token`
(`aaa_runner.persist_captured_token`). Use this when Connect-AzAccount is
CA/MFA-blocked (`AADSTS50076` / "user interaction is required"): unlike the
password path it needs no `Az.Accounts` module and satisfies MFA.

---

## ROPC test (Resource Owner Password Credentials)

Per-credential **Test ROPC…** button on the Captured Credentials card,
alongside **Get-AAATokenFromAzLogin**. POSTs username + password straight
to `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` with
`grant_type=password` (RFC 6749 §4.3) — bypasses the interactive
authorization endpoint (and any CA policy that only evaluates that leg)
entirely, the same class of gap Path A/Path B already demonstrate.

| Piece | Where |
|---|---|
| Endpoint | `POST /api/test-ropc` (`backend/debug_server.py`) |
| UI | `renderRopcPanel()` renders the toggle + form; `ropcToggle()`/`ropcRun()` drive it |
| Pre-fill heuristic | `guessUserPass()` — factored out of the AAA snippet's own heuristic so both features guess identically from `captured_inputs` |
| Gate | `enable_token_testing` (same flag as Test Graph — this also creates a real Azure AD sign-in log entry) |

Body: `{username, password, tenant_id?, client_id?, scope?}`.
`client_id` defaults to the Microsoft Authentication Broker
(`29d9ed98-a469-4536-ade2-f981bc1d605e`, already used elsewhere in this
repo by `tools/phantom_join.py`) — a well-known public client, so ROPC
testing doesn't need its own app registration.

**`tenant_id` defaults to `organizations`, not `common`/`consumers`** —
confirmed live against the real endpoint: Microsoft rejects the password
grant over `common`/`consumers` outright with `AADSTS9001023` ("grant
type not supported over the /common or /consumers endpoints"), before it
ever evaluates the credentials. `organizations` or a specific tenant
GUID/domain is required for the request to actually reach account/CA
evaluation.

The AADSTS error code on failure is the actual finding, not just "it
didn't work" — e.g. `AADSTS50076` means CA/MFA genuinely blocked the
legacy grant (policy working as intended); a **200 with an access_token**
on an account that requires MFA for interactive sign-in means ROPC is an
uncovered bypass path. The UI reflects this: a blocked grant renders in
yellow as a (likely intended) policy hit, while a successful grant
renders in red as a warning, not a green success.

---

## Azure DevOps PAT minting (persistence)

Per-credential **Create ADO PAT…** button on the Captured Credentials
card, directly below **Test ROPC…** (added in 1.26.0). Turns captured
creds into a long-lived Azure DevOps Personal Access Token — durable
credential material that survives the victim's password reset and usually
sits outside the CA/MFA re-evaluation that gates interactive sign-in, the
same class of coverage gap as ROPC and Phantom Join.

A **Method** selector (1.33.0) picks how the ADO-audience token is acquired:
**ROPC** (default — password grant; fails on an MFA tenant), **Device code**
(interactive OAuth2 device-authorization grant — satisfies *basic* MFA, but can
still be refused by CA on the ADO resource; see the callout below), **Phantom
PRT** (exchange a `roadtx.prt` from a completed Phantom Join run for an
ADO-audience token via `roadtx prtauth`, `use_phantom_prt` →
`_ado_token_from_phantom_prt()` picks the newest `$DATA_DIR/phantom/*/*/roadtx.prt`
unless `prt_path` is given — the path that works when device-code/ROPC are
CA-blocked, since the PRT carries device claims), or **Captured token** (paste an
existing ADO-audience token). All converge on the same PAT creation.

The token must have the **Azure DevOps audience** —
`aud = 499b84ac-1321-427f-aa17-267ca6975798` (the ADO first-party resource);
a Graph token (`aud = 00000003-…` / `graph.microsoft.com`) is rejected with
401. Verify any token's `aud` with the dashboard's **Decode JWTs** button.
Where to get one: the **Device code** / **ROPC** methods here request the ADO
scope for you (easiest — prefer Device code on an MFA tenant, so the "Captured
token" field is only for a token you already hold); a captured `dev.azure.com`
BITM session; a phantom PRT exchange
(`roadtx prtauth -f roadtx.prt -r 499b84ac-1321-427f-aa17-267ca6975798`); or
`Get-AzAccessToken -ResourceUrl 499b84ac-1321-427f-aa17-267ca6975798`.

**When Device code also fails (CA on the ADO resource) — use the phantom PRT.**
Device code satisfies *basic* MFA, but it does **not** get past a Conditional
Access policy on the Azure DevOps resource that demands **authentication
strength** (phishing-resistant MFA) or a **compliant/joined device** — the ADO
token request comes back `AADSTS50076`/`AADSTS53003` even after a clean
device-code sign-in. This is the same coverage boundary the demo rides:
device-code only walks past CA when the *target* resource is uncovered (DRS is;
ADO usually isn't). The way through is the **Phantom Join** chain — its PRT
carries device claims that satisfy device-based CA, so exchange the PRT for an
ADO-audience token
(`roadtx prtauth -f roadtx.prt -r 499b84ac-1321-427f-aa17-267ca6975798`) and
paste it into the **Captured token** method. `/api/ado-devicecode/poll` now
detects these CA codes and returns that guidance inline.

| Piece | Where |
|---|---|
| Endpoint | `POST /api/create-ado-pat` (accepts `username`/`password`, or `access_token`) |
| List orgs | `POST /api/ado-orgs` (1.45.0) — discovery-only: acquires an ADO token by the selected method (`_acquire_ado_token()`) then returns `organizations[]` via `_discover_ado_orgs()` (the vssps profile + accounts APIs), **without** minting a PAT. The **☰ List ADO orgs** button reuses the same method dispatch as Create; each result has a **Use** button that fills the ADO org field. `create-ado-pat` now shares these two helpers for its token + org-discovery steps. |
| Device-code | `POST /api/ado-devicecode/start` + `POST /api/ado-devicecode/poll` — start returns the `user_code`/`verification_uri`; the panel polls on the server interval, then feeds the token into create-ado-pat. Uses the Azure CLI public client (pre-consented for the ADO resource). |
| UI | `renderAdoPatPanel()` + `adoPatMethodChange()`/`adoPatGo()`/`_adoPatCreate()`/`adoPatDeviceCode()`; `adoOrgsGo()`/`_adoOrgsList()` for the org listing |
| Shared token step (ROPC) | `_ropc_grant()` — same helper `/api/test-ropc` uses, so a blocked grant surfaces the AADSTS code identically |
| nginx | `location = /api/create-ado-pat`, `location = /api/ado-orgs`, and `location /api/ado-devicecode/` in `nginx/rtvbitm` (dashboard-exclusive `:8092` routes — see the CLAUDE.md rule) |
| Gate | `enable_token_testing` (creates a real AAD sign-in log entry **and** a real, listable PAT in the target org) |

Body: `{username?, password?, tenant_id?, access_token?, client_id?,
organization?, display_name?, scope?, valid_days?, all_orgs?}`.

The chain (all confirmed live against the real endpoints):

1. **AAD token for the ADO resource** (`499b84ac-1321-427f-aa17-267ca6975798`)
   — either a caller-supplied `access_token`, or a ROPC grant of
   username+password. `client_id` defaults to the **Azure CLI public
   client** (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`), *not* the Auth
   Broker client the Graph ROPC uses — confirmed live: the Auth Broker
   client does not carry Azure DevOps delegated permission, the Azure CLI
   client does.
2. **Org discovery** (when `organization` is blank) — `GET`
   `app.vssps.visualstudio.com/_apis/profile/profiles/me` then
   `/_apis/accounts?memberId=…`. Returns the full org list, uses the first.
3. **PAT create** — `POST vssps.dev.azure.com/{org}/_apis/tokens/pats`
   with `{displayName, scope, validTo, allOrgs}`. `scope: app_token` =
   full access; `all_orgs: true` = valid against every org the identity
   can reach; `valid_days` defaults to 90.

The vssps hosts intermittently take >15s on the TLS handshake from inside
Docker Desktop's NAT (confirmed live — a 15s cap surfaced as a spurious
"discovery failed"), so the two ADO calls use a 30s timeout while the
Microsoft login endpoint stays at 15s. A blocked ROPC grant returns the
`aadsts_code` as the finding (same shape as the ROPC panel); a minted PAT
returns the token plus its `authorizationId` for revocation. **Cleanup:**
revoke from Azure DevOps → User settings → Personal access tokens, or
`DELETE .../_apis/tokens/pats?authorizationId=…`.

---

## Docs tab — Test Attacks playbook

The **Docs** tab (`:8092`) has two subtabs: **Reference** (the original
single-page reference this section lives in spirit alongside) and
**Test Attacks**, added in 1.25.0 — a step-by-step playbook covering every
attack/demo the tool drives, written against the actual dashboard controls
(tab names, button labels, field ids) so it works as a live runbook, not
just a feature list.

| Piece | Where |
|---|---|
| UI | `renderDocs()` in `backend/debug_server.py` — subtab bar toggles `#docs-pane-reference`/`#docs-pane-attacks` via `switchDocsPane()` |
| Content | Static HTML, no new backend route — each attack is an `.attack-card` block with a goal line and numbered steps |
| Card titles | Each card's `<h3>` title is a link to where the attack lives in the dashboard — `docsGoTab('creds'|'phantom'|'auth-proxy'|'keepalive-log')` for `:8092` tabs, or a `target="_blank"` link to `:8091`/the demo page for browser-driven ones (1.26.0) |

Covers (11 cards): push notification auto-click (Path A), passkey dead-end
detection, silent drive-by fingerprinting, Phantom Join device-code CA
bypass (Path B), the ROPC test above, the ADO PAT minting above (all four
acquisition methods — ROPC / device-code / Phantom PRT / captured token —
plus **☰ List ADO orgs**), Graph API recon via the **Graph:** dropdown,
Graph-permission abuse via the **AAA** runner, credential injection via the
auth proxy, token keepalive/persistence, and the lander credential-capture
page. Each entry names the real tab/button/field to click, not a paraphrase,
and its title links straight to that tab — update this list (and the title
link target) alongside any change to those controls' labels or ids.

---

## Environment variables

These live in the service environment (set by `install-ubuntu.sh` or
`run-local.sh`), not in `_config`.

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind host for `:8091` / `:8092` / `:8000` / `:8085`. Installer threads `BIND_HOST` into this. |
| `PORT` | `8091` | Main-app port override. |
| `DEBUG_PORT` | `8092` | Debug-dashboard port override. |
| `RAG_PORT` | `8000` | RAG API port override. |
| `RP_PORT` | `8085` | Reverse-proxy port override. |
| `DATA_DIR` | `/var/lib/bitm-proxy` (installer) / platform-specific otherwise | Captures, credentials, screenshots, api_key_plaintext. |
| `SCREENSHOTS_DIR` | `$DATA_DIR/screenshots` | Per-session screenshot output. |
| `CERTS_DIR` | `$APP_DIR/certs` | Forged-CA store + user-supplied custom CA bundles. |
| `PLAYWRIGHT_BROWSERS_PATH` | `$APP_DIR/.playwright-browsers` (installer) | Where Chromium/Edge binaries live. |
| `REQUIRE_API_KEY` | `true` | When `false`, the dashboard skips API-key auth. |
| `INTERNAL_SECRET` | `dev-internal-secret` | Shared secret gating the Go↔Python internal-auth handshake. **Not** randomized — the same literal is hardcoded in `run-local.sh`, `run_go.sh`, `Dockerfile.hybrid`, and as `debug_server.py`'s fallback. Override via env if you want a non-default value. |
| `CREDENTIAL_PASSPHRASE` | unset | If set, `credentials_store` + `cookies_store` are AES-256-GCM-encrypted. |
| `DISABLE_PYTHON_REVPROXY` | unset | `1` to skip binding the Python reverse proxy (Go daemon owns `:8085`). |
| `DISABLE_GO_AUTHPROXY` | unset | `1` to skip the Go BITM; Python `:3128` keeps auth BITM duties. |
| `SLOW_CALLBACK_MS` | `100` | Threshold for the event-loop slow-callback watchdog. |
| `PYTHONUNBUFFERED` | `1` in the systemd unit | Flush stdout/stderr immediately so journald sees live output. |

---

## Data-directory layout

```
$DATA_DIR/
├── config/
│   └── config.json              # diff-from-defaults override, atomic-written
├── credentials/<key>.json       # per-(site,user) — encrypted if passphrase set
├── cookies/<key>.json           # parallel to credentials
├── devices/<dev_id>.json        # device profiles (#10) — encrypted if passphrase set
├── subsessions/<sid>.json       # per-browser-session sub-session events (#2)
├── host_captures/<host>.json    # rolling per-hostname event store (#3)
├── flows/<sid>.json             # persisted flow-trace sessions (debounced flush)
├── rag_findings/imported.json   # persisted RAG findings (Send to RAG / Burp import)
├── screenshots/<sid>/*.jpg      # per-session frame captures
├── logs/                        # only populated when log_to_file = true
├── .api_key_plaintext           # mode 0600 — printed by run.py on boot
└── sites.yaml                   # optional user-local override of config/sites.yaml
```

---

## Relationship diagram

```
                       ┌─────────────────────────────────┐
                       │  dashboard /ws/data subscribers │
                       │   (session 7)                   │
                       └───────────────┬─────────────────┘
                                       │ fan-out
                                       ▼
   config defaults ─► shared._config ─► update_config ─► atomic diff write
                                        │                $DATA_DIR/config/config.json
                                        ▼
   ┌────────── browser_session WS (session 1) ──────────┐
   │  sid = {site_id}_{ts}                              │
   │    ├─► _active_sessions[sid]  (registry / UI)      │
   │    ├─► _live_pages[sid]       (Playwright handle)  │
   │    ├─► _session_flows[sid]    (flow trace, #6)     │
   │    ├─► subsessions[sid]       (#2)                 │
   │    └─► _do_auto_capture ─► credentials_store (#4)  │
   │                            ─► cookies_store    (#5)│
   │                            ─► host_captures   (#3) │
   └────────────────────────────────────────────────────┘
                      ▲
                      │ optional rehydrate / autolaunch
                      │
   ┌───── auth_proxy :3128 (session 8) ─────┐
   │  forged-CA TLS + per-host routing      │
   │   └─► _live_pages (when proxy_via_playwright) │
   └─────────────────────────────────────────┘
                      ▲
                      │ subprocess RPC (when workers_enabled)
                      │
   ┌───── worker pool (session 9) ─────────┐
   │  dispatcher.py + worker/__main__.py    │
   └─────────────────────────────────────────┘
```
