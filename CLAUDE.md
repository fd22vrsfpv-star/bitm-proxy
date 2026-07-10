# CLAUDE.md — guardrails for changes in this repo

These conventions are non-obvious from the code alone and have already
caused regressions when ignored. Read before adding heuristics, hooks,
or new surfaces.

## YAML-driven classification, not hardcoded Python

**Rule:** Site / IdP / auth-flow recognition rules go in
`config/sites.yaml` (deep-merged with `$DATA_DIR/sites.yaml`), not in
Python lists or compiled-in regexes.

**Why:** Operators add new IdPs (custom on-prem ADFS, internal
PingFederate, org-specific session-cookie names) at runtime in the
field. A rebuild is unavailable on the install host; a YAML edit is.
Hot-reload is already wired in `backend/site_rules.py:get_rules` —
mtime-checked on every call — so edits land within a second.

**How to apply it for new heuristics:**

1. Add a top-level (or `globals:` / per-site) block to
   `config/sites.yaml` describing the rule lists.
2. Add a typed accessor in `backend/site_rules.py`. If the rule needs
   compiled regexes or large sets, **cache the compiled form against
   the merged-rules dict identity** so a YAML hot-reload (which
   produces a fresh dict from `get_rules`) naturally invalidates the
   cache. Pattern:
   ```python
   _foo_cache: dict[int, dict[str, Any]] = {}
   def foo_config():
       rules = get_rules()
       cached = _foo_cache.get(id(rules))
       if cached is not None:
           return cached
       cfg = {"pattern": _compile_list(rules.get("foo", {}).get("patterns", []))}
       _foo_cache[id(rules)] = cfg
       return cfg
   ```
3. Read from the accessor in the consumer module — never re-compile per
   request, never inline the rule list.

**Existing examples:** `auth_milestones_config()`, `classify_rules(host)`,
`response_error_rules_for(host)` in `backend/site_rules.py`.
`backend/auth_milestones.py` is the canonical consumer pattern.

**Counter-examples to avoid:** any module-level `_FOO_RE = re.compile(...)`
or `_FOO_HOSTS = (...)` that classifies request/response data. If you
catch yourself writing one, lift it to YAML before merging.

## Lists in override files REPLACE, not extend

`backend/site_rules._deep_merge`: dicts recurse, **lists replace**. To
extend a defaults list from `$DATA_DIR/sites.yaml`, copy the defaults
plus your additions. Document this when you add a new YAML key.

## Versioning is in three places, kept in lockstep

`backend/main.py`, `backend/debug_server.py`, and
`frontend/package.json`. Bump `MINOR` for user-visible features (new
tab, new endpoint, new proxy behaviour), `PATCH` for fixes. ARCHITECTURE.md
documents this convention; SESSIONS.md is the per-feature reference and
must stay in sync.

## Frontend bundle is committed

`static/proxy-assets/` is the deployed bundle (production installs
don't run Node). After editing `frontend/src/**`, run
`npm run build && rm -rf static && cp -R frontend/dist static`.
`run-local.sh --rebuild` does this for you.

## No DB — atomic JSON only

`backend/store.py:JsonStore("name")` is the only persistence primitive.
Don't introduce sqlite, redis, etc. Atomic-write-and-rename is a hard
requirement; reads must tolerate the temp file.

## Encryption-at-rest is transparent

When `CREDENTIAL_PASSPHRASE` is set, every `JsonStore` namespace
encrypts via `backend/crypto.py`. New code that persists captured data
must use `JsonStore`, not `Path.write_text` or sqlite, so encryption
applies automatically.

## Logging categories are stable

`auth_proxy`, `browser`, `devices`, `flow`, `keepalive`, `site_rules`,
`devtools`, etc. The dashboard filters and `journalctl -u mitm-proxy -g`
greps depend on these. Pick an existing category for new log entries
unless you're adding a real new subsystem; if so, document it in
SESSIONS.md.

## Cross-origin endpoints are per-route, not global

**Rule:** Don't add `fastapi.middleware.cors.CORSMiddleware` to either
app. If a single route needs cross-origin reachability, write a
per-route `OPTIONS` handler and attach CORS headers to **both** the
success and error responses in the matching `POST`/`GET`.

**Why:** Global `CORSMiddleware` opens every `/api/*` path to the
configured origins. The dashboard API surface is large and most routes
are intentionally same-origin only. Per-route handlers cap the blast
radius to the one endpoint that actually needs it.

**How to apply it for a new cross-origin endpoint:**

1. Add a `list[str]` config key in `backend/shared.py` (default `[]` =
   same-origin only). Allow `"*"` as a wildcard sentinel.
2. Write a small helper that returns the CORS header dict by matching
   `request.headers.get("origin")` against the config. Empty `Origin`
   or no match → return `{}`.
3. `@router.options(path)` returns `Response(204, headers=cors)` when
   the dict is non-empty, `HTTPException(403)` otherwise.
4. The success handler injects `response: Response` and copies the
   dict onto `response.headers` before returning.
5. **Every `raise HTTPException(...)` in the route must pass
   `headers=cors`.** Without this the browser swallows the authentic
   `401`/`400` as a generic CORS failure and debugging gets miserable.

**Existing example:** `backend/routes/capture.py` (`_cors_headers`,
`external_capture_preflight`, all error raises in `external_capture`).

## APIKeyMiddleware skips OPTIONS — keep it that way

**Rule:** `backend/auth.py:APIKeyMiddleware.dispatch` short-circuits
when `request.method == "OPTIONS"`. Preserve this when touching the
file.

**Why:** CORS preflights are anonymous by browser spec —
`Authorization` is stripped from `OPTIONS`. Authenticating them is
non-functional and would `401` every cross-origin call before it
reaches the route handler. The per-route `OPTIONS` handlers (see
above) own the policy decision; the API key still gates the actual
`POST` that follows.

If you add another global middleware that performs auth, give it the
same `OPTIONS` short-circuit.
