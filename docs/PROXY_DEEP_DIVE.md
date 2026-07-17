# Proxy Deep Dive — `:3128` MITM, Fingerprint Replay, Device Probe

This is the on-the-wire view of `backend/auth_proxy.py`. For the
high-level component map see `ARCHITECTURE.md`; for every config knob
and per-feature mechanic see `SESSIONS.md`.

The proxy on `:3128` does five things in one hot path:

1. Terminate the subject's CONNECT tunnel, MITM HTTPS with a forged
   per-host cert.
2. Snapshot what flows through (cookies, Authorization, CSRF,
   User-Agent, Sec-CH-UA-*, Accept-Language) into
   `_captured_sessions[hostname]`.
3. Optionally inject saved credentials into matching outbound requests.
4. Optionally route the upstream leg through `curl_cffi` so the
   *origin* sees a real-browser TLS fingerprint (JA3/JA4) and matching
   client hints — instead of Python OpenSSL's signature.
5. Optionally serve a synthetic "device probe" page (single-fire) to
   capture JS-only signals into a Device profile.

All five behaviours are gated by config; everything else is plain
HTTP/1.1 forwarding.

---

## Where the proxy sits

```
   subject's browser ─► :3128 (asyncio TCP)
                          │
                          ├─ CONNECT host:443 → forge cert(host) → MITM
                          │       │
                          │       └─ TLS-decrypted request stream  ── _capture_request
                          │                                         ── inject saved creds
                          │                                         ── (optional) probe page
                          │                                         └─► upstream
                          │
                          └─ plain HTTP request ── same as above, plain
                                                  └─► upstream
```

`_handle_client` reads one line, dispatches:

- `CONNECT host:port HTTP/1.1` → `_handle_connect`. If we have no cert
  (or the user disabled MITM for this host) → `_plain_tunnel` (just
  splice). Otherwise → `_mitm_connect`.
- `GET|POST|... <abs-url> HTTP/1.1` → `_handle_http`. Plain HTTP path.

Both entry points check `site_rules.host_allowed_for_proxy(hostname)`
first — an opt-in hostname allowlist (`globals.proxy_allowed_hosts` in
`config/sites.yaml`, empty/unrestricted by default). When non-empty and
the host isn't on it, `_handle_connect` forces `_plain_tunnel` (the exact
same passthrough path used when there's no CA at all — no new plumbing),
and `_handle_http` uses a dedicated byte-faithful passthrough
(`_plain_http_passthrough`) that skips `_capture_request` and injection
entirely, not just the cert forging. Matching is exact-hostname or
exact-subdomain-suffix with a dot boundary
(`site_rules._host_allowed`) — deliberately **not** the same
substring/`"*.suffix"` matcher `noisy_hosts`/`body_capture_hostnames`
use, since `"microsoft.com"` as a loose substring pattern would also
match `evil-microsoft.com.attacker.net`, which is unacceptable for a
security boundary rather than a noise-filtering heuristic. This is the
load-bearing safety control for the DEF CON RTV Lab
(`docs/DEFCON-LAB-SETUP.md`) — with no client-side CA/proxy config
required to use the hosted session, this allowlist is what actually
stops the shared instance from intercepting an arbitrary real site a
visitor navigates the session to.

---

## Forging the CA + per-host certs

```
backend/auth_proxy.py
├── _ensure_ca()          # load or generate ca.key + ca.crt under
│                         #   $DATA_DIR/proxy_ca/. RSA-2048, valid 10y,
│                         #   BasicConstraints CA + KeyUsage cert_sign.
├── _make_host_cert(host) # leaf cert signed by the CA, SAN: DNSName(host),
│                         #   1y validity, fresh RSA-2048 key.
└── _make_ssl_context(host)  # SSLContext seeded with the leaf cert + key
                             #   from temp files (the ssl module wants paths).
```

`trust-ca.sh` walks the operator through trusting `proxy_ca/ca.crt` on
macOS / Linux / Windows. After that, the subject's browser sees normal
HTTPS — same green padlock, same HSTS behaviour.

`_mitm_connect` writes `HTTP/1.1 200 Connection established`, then
wraps the socket with `_make_ssl_context(hostname)` and reads the
plaintext HTTP/1.1 request out of the TLS stream.

There is no JA3 forging on the *server* side of the MITM — the
subject's TLS handshake terminates at our forged cert. Subject-facing
TLS uses Python's default cipher list. JA3 forging applies only to the
**upstream** leg (see "Upstream impersonation" below).

---

## Capturing state: `_captured_sessions`

Every dispatched request is fed to `_capture_request(hostname,
headers, url)` in both the plain-HTTP and HTTPS paths. It accumulates
into `_captured_sessions[hostname]`:

| Field | Source | Used by |
|---|---|---|
| `cookies` | `Cookie:` header from the subject's request, plus `Set-Cookie:` from the response (parsed into Playwright shape). | `hydrate_session`, device profile cred snapshot |
| `headers` | `Authorization`, plus any header whose lowercased name contains `csrf`, `xsrf`, `x-ms-token`, `x-auth`. | `hydrate_session` extra_http_headers, device cred bundle |
| `fingerprint` | `User-Agent`, `Accept-Language`, full `Sec-CH-UA-*` set. | Playwright `user_agent` + `extra_http_headers`, `curl_cffi` impersonate target, device profile snapshot |
| `last_url` | The full request URL most recently seen for the host. | `hydrate_session` (navigate=True) and the device probe redirect target |
| `captured_at` | `time.time()` on every update. | UI ordering |

Scope is per-hostname so the operator can pick a specific capture in
the dashboard. The fingerprint, however, doesn't really vary by
destination — `get_captured_fingerprint(host)` falls back to the most
recent global fingerprint if a per-host one isn't on file.

`list_captured_hostnames()` is what feeds the "Captures" dropdown on
the dashboard.

---

## Injection: saved creds for matching hosts

When `_get_credentials_for_host(hostname)` returns a record from
`credentials_store`, the proxy:

```
_build_cookie_header(creds, hostname)        →  appended to Cookie: header
_build_auth_headers(creds)                   →  Authorization, CSRF, etc.
                                                (don't overwrite if the
                                                subject already set them)
```

Logged as `HTTP <method> <host><path> INJECT<- cookies(N), Authorization, ...`
or `MITM_INJECT ...` for the HTTPS path.

This is how the operator can pre-seed a session: stash creds via the
Captured Data tab, then any tool pointed at `:3128` for that host is
auto-authenticated without the operator's tool knowing anything about
auth.

---

## Upstream impersonation: `curl_cffi`

By default the proxy reaches upstream with a vanilla
`asyncio.open_connection` + a stock SSL context. The Client Hello that
goes out has Python OpenSSL's JA3 — easy to fingerprint as "definitely
not a browser." For OAuth IdPs that profile clients (Microsoft Entra,
Okta, Auth0) that's a giveaway and can trigger step-up MFA / device
challenges that you wouldn't see from a real browser.

When **all** of these are true:

- `use_captured_fingerprint` (config) is `true`,
- `fingerprint_match_tls_proxy` (config) is `true`,
- the request isn't a WebSocket upgrade,
- the captured UA classifies into a `curl_cffi` impersonate target
  (`ua_to_impersonate_target` in `backend/ua_engine.py`),
- the `(host, target)` pair isn't on the 5-minute skip list,

…then `_pick_impersonate_target(host, headers)` returns a tag like
`chrome124` / `edge101` / `firefox133` / `safari17_0` and the request
is dispatched through `_upstream_fetch_impersonate`:

```python
async with AsyncSession(impersonate=target,
                        http_version=CurlHttpVersion.V1_1,
                        timeout=30,
                        verify=not get_config_value("ignore_ssl", False)) as s:
    r = await s.request(method, url, headers=send_headers,
                        data=body or None, stream=True,
                        allow_redirects=False)
```

Critical bits:

- `http_version=CurlHttpVersion.V1_1` is forced (`v1.19.4+`).
  Earlier code passed the float `1.1`, which `curl_cffi >=0.10`
  rejects with `TypeError: an integer is required` — every
  IMPERSONATE fetch failed and the host got skip-listed for 5
  minutes, before falling all the way back to the stock leg. The
  enum is the supported API. h2 framing translation back to the
  MITM client is out of scope; `curl_cffi`'s impersonate profiles
  ship h1 shapes that match what real browsers do for the same
  endpoints.
- `allow_redirects=False` — we re-frame the response and let the
  subject's browser follow redirects itself, so cookie jars and state
  on its side remain authoritative.
- The response body is streamed back to the subject's connection as
  HTTP/1.1 chunked; `Content-Encoding` and `Transfer-Encoding` from
  `curl_cffi`'s decoded output are stripped (it already
  decoded/decompressed).
- Bodies over `_IMPERSONATE_MAX_BODY` (50 MB) abort the stream — this
  path is for auth flows, not bulk download.
- On any `curl_cffi` exception the `(host, target)` is skip-listed for
  300s so one broken origin doesn't repeatedly stall the proxy.

What the *origin* sees:

| Layer | Without impersonate | With impersonate |
|---|---|---|
| TLS Client Hello | OpenSSL JA3, no GREASE, alphabetical extensions | Real browser JA3 — Chrome/Edge/Firefox/Safari |
| ALPN | h2,http/1.1 | h2,http/1.1 (forced down to h1 by `http_version`) |
| User-Agent | (whatever the subject sent) | Same — passed through `send_headers` |
| Sec-CH-UA-* | (whatever the subject sent) | Same — passed through |
| Accept ordering | Browser's (subject) | Browser's (subject) — `curl_cffi` doesn't override custom headers |

So combined with the **Sec-CH-UA-*** header capture in
`_capture_request`, the origin gets a request that matches a real
browser end-to-end — TLS fingerprint, hint headers, accept ordering.

Logged as `IMPERSONATE host=… target=… -> 200 (N bytes)`.

### Failure handling

`_upstream_fetch_impersonate` returns `True` when it owns the response
end-to-end (headers already on the wire). The HTTP/HTTPS dispatchers
fall back to the stock raw-socket path *only* when it returns `False`,
which means the curl request itself failed before any bytes hit the
client. Once we've started writing chunked body, there's no rewind.

### Idle preconnect handling

Modern Chromium aggressively opens *speculative* TLS preconnects
to hosts it expects to need (DNS warmed, socket primed) and
frequently doesn't reuse them. The proxy's TLS server-side
handshake succeeds, then the request-line read hits the 10s
`asyncio.wait_for` and raises `TimeoutError`. As of `v1.19.5`,
the MITM connection handler catches `asyncio.TimeoutError`
specifically and logs a single-line `MITM idle preconnect
closed for <host>` entry at the `debug` level, instead of a
multi-line traceback at `warn`. The catch-all
`except Exception` still warns on real errors.

---

## The device probe (active JS signal capture)

Background: Sec-CH-UA-* gives us a ton of device info, but a few
high-value signals are JS-only — `Intl.DateTimeFormat().resolvedOptions().timeZone`,
`screen.{width,height,colorDepth,pixelRatio}`, `innerWidth/innerHeight`,
`navigator.languages/platform/hardwareConcurrency/deviceMemory`. A real
device profile wants those.

The proxy can't query JS through HTTP headers, so it briefly serves a
synthetic page when the operator opts in.

### Wiring

```
backend/devices.py
└── register_from_capture(host, modes=[...passive,probe,creds],
                          sites=[...], name=None)
       └── if 'probe' or 'creds' in modes:
              _pending_probes[host] = {token, device_id, modes,
                                       sites, expires=now+1800}

backend/auth_proxy.py
├── _build_probe_response(host, original_url, token, device_id,
│                         want_storage)
│       returns a synthetic HTTP/1.1 200 OK with a tiny HTML page that:
│         1. fetches `//<host>/__mitm_probe_callback?token=…&device_id=…&host=…`
│            with JSON body { tz, languages, platform, screen, viewport,
│                             hardware_concurrency, device_memory,
│                             [local_storage, session_storage] }
│         2. then `location.replace(original_url)`
│
├── _is_probe_callback(path)
│       True for "/__mitm_probe_callback" — the in-proxy sentinel.
│
├── _handle_probe_callback(reader, writer, host, path, headers)
│       reads JSON body, calls backend.devices.consume_probe + apply_probe_result,
│       returns 204 No Content (or 400 on token mismatch).
│       *never reaches upstream*.
│
└── _handle_http and _mitm_connect both:
        - on POST to /__mitm_probe_callback → call _handle_probe_callback, return.
        - on GET while _pending_probes[host] is set and device_probe_enabled is on
          → write _build_probe_response, return.
```

Why intercept inside the proxy rather than POSTing to `:8092`:

- The subject's browser is the one running the JS. It already has the
  `:3128` proxy configured; making it talk to a different origin
  (`:8092`) would hit CORS and may not even be reachable from the
  subject's network.
- Routing the callback through the proxy keeps everything HTTP-level
  on a single connection the subject already trusts.
- The `/__mitm_probe_callback` path is processed **without contacting
  upstream** so the origin never sees the sentinel request.

### Single-fire semantics

`_pending_probes[host]` is consumed by `consume_probe()` on the first
matching callback (or by `apply_probe_result(host=…)`). After consume
the host is back to normal: subsequent GETs flow through unchanged.
TTL is 30 minutes; a stale entry is ignored.

`device_probe_enabled` (default `true`) gates the synthetic-page write
in both dispatchers — set to `false` to keep registrations passive.

---

## Per-request flow on a single GET

The full path of one request through `:3128`, with everything turned
on, looks like:

```
1. accept TCP from subject
2. read request line + headers
3. CONNECT host:443? → wrap_socket with _make_ssl_context(host)
                       (forged leaf cert + key, signed by ca.key)
4. read inner HTTP/1.1 request from the TLS stream
5. _capture_request(host, headers, url):
       updates _captured_sessions[host]:
         cookies / headers / fingerprint / last_url / captured_at
6. probe-callback POST? → _handle_probe_callback, return 204.
7. pending probe + GET? → write _build_probe_response, return.
8. _get_credentials_for_host(host):
       inject Cookie + Authorization headers from credentials_store
9. _pick_impersonate_target(host, headers):
       if matches → _upstream_fetch_impersonate (curl_cffi)
                    streams response back as chunked HTTP/1.1
       else        → asyncio.open_connection upstream, splice
10. capture Set-Cookie and any auth-y headers from the response
11. close
```

`HTTP/1.1` is enforced everywhere the proxy participates: the MITM
side is a manual line-based parser, the curl_cffi side forces
`http_version=1.1`. Browsers negotiate h2 only on the segments where
the proxy isn't in the middle (impossible here).

---

## What's *not* in scope

| | Why |
|---|---|
| HTTP/2 on the MITM client side | Manual h1 parser; h2 framing translation is meaningfully more code. Most auth flows are h1/h2 indistinguishable at the URL/cookie level so the cost/benefit is bad. |
| WebSocket forwarding through curl_cffi | `curl_cffi` doesn't speak WS upgrades cleanly; we detect `Upgrade: websocket` and bypass impersonation. The plain raw-socket path forwards WS without intervention. |
| Bodies over 50 MB on the impersonate path | Auth flows don't ship bulk media. Bypassing keeps memory bounded and avoids edge cases in `curl_cffi`'s streaming decode. |
| TLS fingerprint forging on the *subject* side of the MITM | The forged cert is enough. The subject already trusts our CA; matching their TLS is unnecessary and would be hard since each subject browser has its own JA3. |

---

## Comparison: this proxy vs adjacent approaches

| Approach | Subject-transparent? | Captures upstream JA3? | Captures cookies? | Captures bodies? | One-time install? |
|---|---|---|---|---|---|
| **This repo's `:3128`** | Yes (after CA trust) | Yes (subject UA → curl_cffi target) | Yes | Yes (with redaction) | CA cert install |
| mitmproxy / Charles | Yes (after CA trust) | No (OpenSSL stack) | Yes | Yes | CA cert install |
| Burp Suite | Yes (after CA trust) | No | Yes | Yes | CA cert install |
| Browser extension | Partial (CSP blocks some) | No | Partial | Partial | Per-browser install |
| Playwright `page.route()` (older approach) | No (only inside the operator's Playwright) | No | Within Playwright only | Within Playwright only | None |

The `curl_cffi` upstream leg is what differentiates this proxy from
mitmproxy/Burp for fingerprint-sensitive auth work.
