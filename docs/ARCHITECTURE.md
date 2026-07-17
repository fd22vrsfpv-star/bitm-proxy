# MITM Proxy — Architecture

What this repo is: a forging-CA MITM proxy + a Playwright-driven remote
browser + a debug dashboard, glued together so an operator can capture
auth state from a real subject's browser, replay it on the server, and
launch fresh authenticated Playwright sessions.

For per-feature mechanics (every session type, every config variable,
the data layout, the relationship diagram) read **`SESSIONS.md`** —
that file is the canonical reference and stays in sync with the code.
For the deepest dive into how the on-the-wire MITM works (TLS forging,
upstream impersonation, fingerprint replay, the device probe), read
**`PROXY_DEEP_DIVE.md`**.

This document is the high-level component map.

---

## Surfaces

| Port | Purpose | Module |
|---|---|---|
| **3128** | Forging-CA MITM proxy. Browsers/tools point here. CONNECT tunnels are MITM'd against a generated CA so HTTPS traffic is observable; HTTP/1.1 only on the upstream leg (`curl_cffi` impersonation forces it). | `backend/auth_proxy.py` |
| **8091** | Operator browser. Serves the React SPA (`frontend/dist/proxy-assets/` → `static/proxy-assets/`); renders a Playwright session as a JPEG canvas via WebSocket. Click/scroll/keystroke roundtrip. | `backend/main.py` + `backend/routes/browser.py` |
| **8092** | Debug dashboard. Single-page Python-rendered HTML with two WebSockets (`/ws/control` for commands, `/ws/data` for log/flow streaming). Runs the auth proxy on demand, shows captures, drives flow analysis, hosts the Devices tab. | `backend/debug_server.py` |
| **8000** | RAG API. Implements the RAG Scan Stack-compatible findings surface (`/health`, `/scope*`, `/engagements*`, `/findings/search`, `/export`, `/import`) that `burp-extension/RagScanBridge.py` calls, so that extension works against this built-in API with no external RAG Scan Stack backend. Captured flows become findings via `backend/rag_bridge.py`. Disabled if `RAG_PORT` isn't bound. | `backend/rag_api.py`, `backend/rag_bridge.py` |
| **8085** | Reverse proxy. Browse `http://localhost:8085/_r/<host>/<path>` (or use the form on `/`) to fetch a target URL through this proxy with logging — handy for replays from a single-tab debugging stance. | `backend/reverse_proxy.py` |
| **3129** | Test proxy (Go). Pass-through HTTP/HTTPS proxy without MITM, used to A/B against `:3128` when diagnosing. | `go/cmd/mitm-proxies` |

`backend/run.py` is the process entry point. `:8091`, `:8092`, `:8000`,
`:8085` are separate uvicorn instances inside the same Python process.
`:3128` is an asyncio TCP listener inside `:8091`'s loop, auto-started
when `autostart_auth_proxy=true`. `:3129` is a separate Go binary
launched as a child process.

---

## Deployment topologies

The core app above is topology-agnostic — everything so far describes
`backend/run.py`'s single process, regardless of how it's launched.
Three ways to launch it:

1. **`run-local.sh`** — native, all ports on `127.0.0.1` directly.
2. **`docker rm -f mitm-proxy && docker build ...`** — single container,
   `:8091`/`:8092` published directly. Same topology as native, just
   containerized.
3. **`docker-compose.yml`** (the DEF CON RTV Lab) — a genuinely different
   topology: nginx sits in front, terminating TLS and reverse-proxying into
   the app over an internal compose network (`app` isn't published to the
   host at all except `:8092`, hardcoded to loopback for operator console
   access). Visitors never touch `:3128` or install a CA cert — they drive
   the hosted Playwright session at `:8091` through nginx's `/tp8091/`
   mount instead. Two extra files exist only for this topology:
   `nginx/rtvbitm` (the vhost config — dashboard-exclusive routes like
   `/api/aaa/`, `/api/phantom/`, `/ws/` need explicit location blocks,
   since `:8091`'s own SPA catch-all route would otherwise silently
   swallow them) and `config/lab-config.json` (pre-seeds
   `external_capture_allowed_ips` with the compose network's fixed
   subnet, since `backend/routes/capture.py`'s IP check uses the raw TCP
   peer address and would otherwise see nginx's container IP, not
   loopback). Full runbook: `docs/DEFCON-LAB-SETUP.md`.

---

## Backend layout

```
backend/
├── run.py            # Process entry — boots :8091, :8092, :3128
├── main.py           # FastAPI app on :8091 (operator browser SPA)
├── debug_server.py   # FastAPI app on :8092 (dashboard, WS control + data)
├── auth_proxy.py     # MITM TCP listener on :3128 — forges CA, MITMs HTTPS,
│                     #   captures fingerprints, impersonates upstream TLS via
│                     #   curl_cffi, intercepts the device-probe sentinel path
├── ua_engine.py      # UA → Playwright engine family + curl_cffi impersonate tag
├── shared.py         # Shared config (atomic JSON write), session registry,
│                     #   log buffer, flow trace, WS pub/sub
├── store.py          # JsonStore — atomic JSON files, optional AES-256-GCM
│                     #   when CREDENTIAL_PASSPHRASE is set
├── crypto.py         # AES-256-GCM helpers used by store.py
├── auth.py           # APIKeyMiddleware + verify_ws_key
├── paths.py          # Resolves DATA_DIR, certs_dir, screenshots_dir per OS
├── site_rules.py     # config/sites.yaml → login_targets() + redaction rules
├── subsessions.py    # Per-Playwright-session sub-session events
├── host_captures.py  # Rolling per-hostname event store (keepalive view)
├── keepalive.py      # Background "do something so the cookie stays warm" loop
├── ollama_hook.py    # Local LLM endpoint for flow analysis
├── rag_api.py        # Send a flow window to a configured RAG endpoint
├── rag_bridge.py     # Helper used by rag_api
├── reverse_proxy.py  # nginx-style reverse proxy primitive (used by debug)
├── diagnostics.py    # /api/diagnostics health checks
├── service.py        # Windows/Linux service install helpers (re-exec target)
├── devices.py        # Device profiles store + presets + register/probe/apply
├── routes/
│   ├── browser.py    # Operator session WS (/api/browser/session) + creds REST
│   ├── sessions.py   # Saved-session CRUD (/api/sessions)
│   ├── devices.py    # Device profile REST (/api/devices)
│   ├── capture.py    # External credential ingest (/api/capture/external)
│   └── phantom.py    # Phantom Join launcher WS (/api/phantom/run) — :8092 only
└── worker/           # Subprocess worker pool (gated, experimental)
```

### Why one store, many namespaces

`JsonStore("name")` is a one-stop atomic-write JSON dir under
`$DATA_DIR/<name>/`. The same primitive backs **all** persistent state:
`credentials`, `cookies`, `sessions` (saved targets), and `devices` (the
new profiles). When `CREDENTIAL_PASSPHRASE` is set, every namespace is
encrypted with AES-256-GCM transparently — no code branch in callers.

### Sites file

`config/sites.yaml` ships with the repo and defines login-target
aliases (`target=msft` → real URL) plus redaction rules for the flow
trace. `$DATA_DIR/sites.yaml` is deep-merged on top so per-install
customisations don't get clobbered on upgrade.

`globals.proxy_allowed_hosts` (empty/unrestricted by default) is a hostname
allowlist for `:3128`'s MITM interception, checked via
`site_rules.host_allowed_for_proxy()` before `_handle_connect()`/
`_handle_http()` decide whether to forge a cert or just tunnel bytes
untouched. Opt-in hardening for deployments that must not be usable to
intercept arbitrary hosts — see the DEF CON RTV Lab section below, where
it's the load-bearing safety control for a publicly-reachable instance.

---

## Frontend layout

```
frontend/
├── package.json           # @1.1.0 — React 18, TS, Vite 5, Tailwind 3
├── vite.config.ts         # build.assetsDir = "proxy-assets"
└── src/
    ├── main.tsx           # React entry (QueryClient)
    ├── App.tsx            # Top-level layout
    ├── index.css          # Tailwind + dark theme tokens
    ├── pages/
    │   └── MitmProxy.tsx  # Reads ?url=, ?private, ?device_id from
    │                       # location.search → mounts <BrowserAuth>
    ├── components/
    │   └── BrowserAuth.tsx# Canvas + WebSocket to /api/browser/session.
    │                       # Forwards login_url / private / device_id /
    │                       # start_url query params to the WS so the
    │                       # backend can launch with a saved profile.
    ├── api/
    │   ├── client.ts      # apiFetch + wsUrl with API key handling
    │   └── mitmProxy.ts   # Typed wrappers for the operator-browser app
    └── lib/utils.ts
```

The dashboard at `:8092` is **not** part of this React app — it's
HTML/JS rendered server-side by `debug_server.py`. The React app is
specifically the operator browser surface (`:8091`).

Build: `npm run build` in `frontend/`, then `cp -R frontend/dist
static/`. `run-local.sh --rebuild` does this for you. The committed
`static/` directory means production installs don't need Node.

---

## Public surface

### `:8091` — operator browser

| | Path | Purpose |
|---|---|---|
| WS | `/api/browser/session` | The session WS. Query: `login_url`, `target`, `login_hint`, `width`, `height`, `private`, `device_id`, `start_url`. |
| GET | `/api/browser/credentials`, `/credentials/{site_id}` | List / fetch captures. |
| DEL | `/api/browser/credentials/{site_id}` | Delete a capture. |
| GET | `/api/browser/sites` | Per-host capture summary feed. |
| POST | `/api/browser/test/decode/{site_id}` | Decode any JWTs in a capture. |
| POST | `/api/browser/test/token/{site_id}` | Replay an `Authorization: Bearer …` against an arbitrary URL. |
| POST | `/api/browser/test/cookies/{site_id}` | Replay captured cookies against a URL. |
| GET | `/api/browser/certs` | Forged-CA cert metadata. |
| GET | `/api/sessions`, etc | Saved-target CRUD (sites the dashboard's URL picker offers). |
| GET/POST/PATCH/DELETE | `/api/devices/...` | Device profile CRUD + `/presets`, `/from-capture`, `/probe-callback`. |
| GET | `/api/config` | Flat config snapshot. |

### `:8092` — debug dashboard

| | Path | Purpose |
|---|---|---|
| GET | `/` | The dashboard HTML (rendered by `debug_server.py`). |
| WS | `/ws/control` | Bidirectional command channel. Every dashboard action sends a `{cmd}` message. |
| WS | `/ws/data` | Pushes log entries + flow trace updates. |
| GET | `/api/metrics`, `/api/config`, `/api/sessions`, `/api/headers/...`, etc. | Read endpoints for the dashboard. |
| POST | `/api/test-graph`, `/api/test-ropc` | Per-credential test actions: replay a token against MS Graph `/me`, or perform a ROPC `grant_type=password` request straight to the tenant's `/token` endpoint. Both gated by `enable_token_testing`. |
| POST | `/api/create-ado-pat` | Mints a long-lived Azure DevOps PAT from captured creds: ROPC → ADO-resource token → org discovery → PAT Lifecycle API. Shares `_ropc_grant()` with `/api/test-ropc`; gated by `enable_token_testing`. |
| GET | `/api/rag/burp-extension/download` | Streams `burp-extension/RagScanBridge.py` as a download. |

The dashboard re-mounts the same `browser_routes` and `devices_routes`
under itself so workflows that target `:8092` (the operator can prefer
one origin) keep working.

### `:3128` — MITM proxy

Configure your browser/tool to use `http://127.0.0.1:3128` as its HTTP
+ HTTPS proxy. After installing the forged CA from
`$DATA_DIR/proxy_ca/ca.crt` into your trust store, HTTPS sites stop
warning. See `trust-ca.sh` / `untrust-ca.sh` for the macOS/Linux flow
and `PROXY_DEEP_DIVE.md` for what actually happens on the wire.

---

## Core flows

### A. Capture → Replay → Launch

```
subject's browser ─► :3128 ──► auth_proxy._capture_request
                                  ├─ stash cookies, Authorization, CSRF
                                  ├─ stash User-Agent + Sec-CH-UA-* fingerprint
                                  └─ (when use_captured_fingerprint) curl_cffi
                                     forges JA3 on the upstream leg

operator           ─► :8092 ──► dashboard / Captured Data tab
operator clicks    ─► /ws/control {cmd:'hydrate_session', session_id, hostname}
                                  └─ injects cookies + Sec-CH-UA-* into the live
                                     :8091 Playwright session
```

### B. Device profile (the v1.1 feature)

```
register-from-capture ─► backend.devices.register_from_capture(host, modes, sites)
                          ├─ snapshot fingerprint + (if 'creds') cookies/headers
                          └─ if 'probe'/'creds': stamp _pending_probes[host]

next GET on host    ─► auth_proxy._handle_http / _mitm_connect
                          └─ serves a synthetic 200 with JS that POSTs
                             tz/screen/viewport/languages/platform back to
                             /__mitm_probe_callback (intercepted in-proxy,
                             never reaches upstream); meta-refresh to original

probe callback      ─► backend.devices.apply_probe_result(...)
                          └─ promotes tz/locale/viewport into the profile
                             stores LS/SS bundles when 'creds' was selected

operator clicks Launch
                    ─► /?auto=1&device_id=<id>&url=<start>  (port 8091)
                    ─► BrowserAuth.tsx forwards device_id + start_url to WS
                    ─► routes/browser.py:browser_session loads device,
                       prefers device.engine_family/channel, calls
                       devices.apply_to_context_opts() before new_context,
                       calls devices.apply_post_launch() before goto.
```

### C. Flow trace

Every request/response observed in either the proxy or the operator
session is appended to `_session_flows[sid]` with seq numbers,
redaction applied per `sites.yaml`. The dashboard's Flow Trace tab
streams updates over `/ws/data`. RAG/Ollama analysis pulls a slice of
that buffer and asks an LLM for an explanation.

---

## Versioning

`backend/main.py`, `backend/debug_server.py`, and
`frontend/package.json` track the same `MAJOR.MINOR.PATCH`. Bump
`MINOR` for user-visible features (dashboard tabs, new endpoints, new
proxy behaviours), `PATCH` for fixes.

Current: **1.1.0** — adds the Devices tab.

---

## Key design decisions

1. **Forging-CA MITM, not a Chromium extension or Playwright `route()` shim.** A real proxy on `:3128` works for *anything* that speaks HTTP — browsers, mobile apps via Wi-Fi proxy, curl, any tool — without modifying the subject. The forged CA is a one-time trust-store install; from then on the subject sees normal HTTPS.
2. **Atomic JSON over a database.** Operators run this in pentest VMs / labs / containers; "no DB to install or upgrade" is a feature. `JsonStore` uses temp-file-plus-rename so no half-written files survive a crash.
3. **Server-side log + flow buffer, not browser-side localStorage.** The dashboard reconnects mean nothing if the buffer lived in the tab. `shared._logs` and `_session_flows` are owned by the backend; WS subscribers receive history then live tail.
4. **Single Python process, multiple uvicorn instances.** `:8091` and `:8092` share `_live_pages`, `_captured_sessions`, `shared._logs` directly via in-process dicts — no IPC. `:3128` is a TCP listener inside the same loop. Saves a serialisation tax that doesn't buy anything in this footprint.
5. **`curl_cffi` for upstream impersonation.** When `use_captured_fingerprint` is on and the subject's UA is identifiable, the proxy's upstream leg uses curl_cffi's `impersonate=` so the *origin* sees a real-browser-shaped TLS Client Hello (JA3/JA4) instead of OpenSSL's. Combined with the captured `Sec-CH-UA-*` headers the IdP sees a coherent device. WebSocket upgrades and >50 MB bodies bypass this path.
6. **Devices = persistent named hydrate.** `hydrate_session` was already great for "make this live session look like that capture." Devices generalise it: snapshot once, launch many times, edit in the Devices tab. Same primitives — `add_cookies`, `set_extra_http_headers`, `add_init_script` — packaged as a reusable record.
7. **`browser_type` picks identity, not just engine.** `edge`/`chrome` both launch bundled Chromium with a spoofed UA (no real Edge/Chrome install needed); `edge-real` launches the actual `msedge` channel binary; `firefox` launches Playwright's real bundled Firefox engine (genuine Gecko, not a UA spoof) via the same generic `_engine_launch()` dispatcher fingerprint-matching already used (`backend/routes/browser.py`). Edge has no arm64 Linux build at all and `edge-real` silently disables there; Firefox does have one and works — verified live on arm64, not assumed from docs.
