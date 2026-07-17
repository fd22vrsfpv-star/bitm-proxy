# Adding & Troubleshooting Auth-Flow Milestones

A working manual for the operator who needs the Flow Trace banners
(LOGIN → AUTH CODE → TOKENS → SESSION → PRT) to light up on a new IdP,
a custom on-prem auth, or a relying party that doesn't match the
default rules.

The classifier and its YAML config:

| Layer | File |
|---|---|
| Classifier code | `backend/auth_milestones.py` |
| Recognition rules (YAML) | `config/sites.yaml` → `auth_milestones:` block |
| Per-install override (deep-merged) | `$DATA_DIR/sites.yaml` (same shape) |
| YAML loader / regex cache | `backend/site_rules.py:auth_milestones_config()` |
| Wiring on flow rows | `backend/routes/browser.py:_on_flow_request` + `_on_flow_response` |
| UI render | `backend/debug_server.py:flowRowHtml` (`.flow-ms-badge.{kind}`) |

For the end-to-end mechanism see `SESSIONS.md` → *Flow trace buffer* and
*Sessions → Device profile*. The operational philosophy ("rules go in
YAML, not code") is in `CLAUDE.md`.

---

## 0 · Confirm the classifier is alive

Before chasing rule bugs, verify the wiring is doing anything.

1. Open the dashboard at `:8092` → **Flow Trace** tab.
2. Select an active session.
3. Click **Reclassify milestones** in the toolbar.

A blue diagnostic banner appears immediately above the timeline:

```
Reclassify result   tagged 12 / 87 rows
[LOGIN ×4] [TOKENS ×1] [SESSION ×2] [CODE ×1]
req_body=12 resp_body=8 token_paths=2 idp_hosts=15
YAML loaded (19 idp_hosts, 35 session cookies)
[N token-path rows did NOT tag — click to inspect ▾]
```

(If the YAML didn't load you'll see a red `YAML problem — idp_hosts=0,
login_re=NO, token_re=NO` line instead.)

The same line is also:

- **printed to stdout** with a `[FLOW]` prefix — visible via
  `journalctl -u bitm-proxy -f` or `docker logs -f bitm-proxy` or the
  console of `run-local.sh`. Grep with
  `journalctl -u bitm-proxy -g "FLOW.*reclassify"`.
- **written to the in-memory log buffer** under category `flow` —
  visible on the dashboard's *All Logs* tab when the Service dropdown
  is set to `flow`.

What each field means:

| Field | If zero / NO → likely cause |
|---|---|
| `tagged` | Rows the classifier matched (`auth_milestones` field set) |
| Per-kind pills (LOGIN/TOKENS/…) | Breakdown of what was tagged |
| `req_body` / `resp_body` | Rows that even had a body to inspect |
| `token_paths` | Rows whose URL path matched `token_path_patterns` |
| `idp_hosts` | Rows whose hostname matched `idp_hosts` |
| `yaml_idp_host_count` | Number of hosts the YAML loaded — **0 means YAML not parsed** |
| `yaml_token_re` / `yaml_login_re` | `ok` if the combined regex compiled — **NO means a malformed entry in `*_path_patterns`** |
| `yaml_session_cookie_count` | Length of the merged `session_cookie_names` list |

If `yaml_idp_host_count` is `0`, the YAML didn't load — check
`config/sites.yaml` for syntax errors with `python -c "import yaml;
yaml.safe_load(open('config/sites.yaml'))"`. If a regex flag is `NO`,
look for a recent entry in the corresponding `*_patterns` list that's
malformed — the loader logs the failure on the `site_rules` category.

If `tagged > 0` but the kind you expected is missing, you have a rule
gap — go to *§3 Identifying the milestone shape* below.

If `tagged == 0` despite `req_body > 0`: the proxy likely needs a
restart to pick up the classifier code. The flow buffer is in-memory
and entries captured before the classifier shipped don't carry the
field; **Reclassify** retro-tags them on demand, but only with the
classifier code that the running process has.

When a token-endpoint row didn't tag, the banner has an expandable
**N token-path rows did NOT tag** section listing up to 3 sample rows
with their request/response bodies so you can read why on the spot.
The same samples are also written to stdout / `flow` category logs:

```
reclassify untagged token-path #54 POST https://login.foo.com/oauth2/token
   -> 200 req='grant_type=client_credentials&...' resp=''
```

That tells you: path matched, status was good, but `grant_type` wasn't
in the recognised list (or `resp_body` was empty AND grant_type was
missing). The fix is in YAML, not in code.

---

## 1 · Capture a representative session

You need raw data to read off the milestone shapes for a new flow.

1. Set the operator's browser at `:8091` to use the target's login URL
   (or, when authenticating from a separate machine, point its proxy
   at `:3128` and trust the CA from `$DATA_DIR/proxy_ca/ca.crt`).
2. On the **Flow Trace** tab, click **Mark start** just before you
   begin the login.
3. Authenticate end-to-end (username, password, MFA, KMSI/consent,
   landing). Don't click around afterward — keep the buffer focused.
4. Click **Mark login complete** at the landing page.
5. Click **Export Flow** in the toolbar — writes the full flow
   (request + response headers + bodies up to 64 KB per body) to
   `$DATA_DIR/debug/<session_id>-<ts>.json`. The exact path is shown
   in the dashboard's status line; tail the JSON to verify.

The exported file is the source of truth for everything below. It
contains entries with this shape (`shared.append_flow`):

```jsonc
{
  "seq": 12, "method": "POST", "url": "https://idp.example.com/login",
  "status": 200, "request_headers": {...}, "request_body": "…",
  "response_headers": {...}, "response_body": "…",
  "ts_req": …, "ts_resp": …, "auth_milestones": [{...}]?
}
```

Tip: if the flow is too noisy to read, set the session's marker range
and click **Export Flow** again — markers are honoured and only
relevant rows go to disk.

---

## 2 · Map the steps to milestones

Walk the exported JSON in order and decide which kind each interesting
row should be:

| Kind | What you're looking for |
|---|---|
| `login` | The IdP-rendered username/password/MFA/KMSI/consent steps. Multi-step IdPs have several. |
| `code`  | The single redirect that hands an `?code=…` back to the relying party. |
| `tokens` | The first POST to the RP's token endpoint with `grant_type=authorization_code` (or `client_credentials`, `device_code`, etc). Issues access/id/refresh tokens. |
| `refresh` | A later POST to the same endpoint with `grant_type=refresh_token`. |
| `prt` | AAD-only: an extra POST to the token endpoint with `grant_type=srv_challenge` *or* a Set-Cookie carrying `x-ms-PRT`. |
| `session` | Set-Cookie of the IdP's session cookie (`ESTSAUTH*`, `MSPAuth`, `idsrvAuth`, etc) — the artifact that keeps the browser logged in. |

For each row that *should* be a milestone but isn't tagged, identify
which of these matched / didn't:

### LOGIN

The classifier tags LOGIN when **either**:

- the URL host matches `idp_hosts` AND the path matches a
  `login_path_patterns` regex AND the path is *not* a
  `not_login_path_patterns` match (i.e. not `/token`, `/userinfo`,
  `/.well-known`, `/jwks`, `/keys`); **or**
- the request or response body contains any string from
  `login_body_markers`. This is the fallback for unknown IdPs.

If a real LOGIN row is missing, run `urlparse` on it and ask:

```
$ python3 -c "from urllib.parse import urlparse; \
   p = urlparse('https://idp.example.com/auth/realms/main/login-actions/authenticate'); \
   print(p.hostname, p.path)"
idp.example.com /auth/realms/main/login-actions/authenticate
```

If `idp.example.com` isn't in `idp_hosts`, add it (or its closest
parent suffix, e.g. `example.com`). If the path is exotic
(`/auth/realms/main/login-actions/authenticate` for Keycloak), add a
specific regex to `login_path_patterns`.

### AUTH CODE

Tagged when the response has a `Location:` header containing
`?code=` / `&code=` / `#code=` and that URL also carries `state=` or
`session_state=` or `client_info=` (the AAD/OIDC convention).

If your IdP uses non-standard query keys, the simplest fix is to add
the response header itself to the `Location:` regex — but the current
regex is hardcoded in `auth_milestones.py:classify` (one of the few
places where YAML doesn't reach yet). Open an issue / patch if you
need to.

### TOKENS / REFRESH / PRT

Tagged when **all** of these hold:

1. `method == "POST"`
2. URL path matches `token_path_patterns`
3. Status is 2xx (`status is None` is also accepted for in-flight rows
   that haven't received a response yet)

Then the body / grant chooses the kind:

- `grant_type=refresh_token` → REFRESH
- `grant_type=srv_challenge` *or* `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` *or* a scope containing `aza`/`openid_aza` *or* a response with `token_type=pop|bearer-prt` *or* `session_key_jwe`/`session_key` field → PRT
- otherwise (authorization_code / client_credentials / device_code /
  password / implicit / unspecified) → TOKENS

If your IdP's token endpoint lives at a non-standard path
(`/api/auth/oauth/token`, `/sts/issue`), add a regex to
`token_path_patterns`.

### SESSION cookies

Tagged when the response has `Set-Cookie:` whose name (lowercased) is
in `session_cookie_names` *or* starts with any prefix in
`session_cookie_prefixes`.

PRT is also tagged here when the cookie name starts with any prefix in
`prt_cookie_prefixes` (currently `x-ms-`).

To find candidate cookie names in your exported flow, grep:

```
$ jq -r '.entries[].response_headers["set-cookie"] // empty' flow.json |
   awk -F'=' '{print tolower($1)}' | sort -u
```

Anything that survives the IdP login (long expiry, `HttpOnly`,
`Secure`) is a candidate.

---

## 3 · Edit the YAML

Two files matter:

| Where | When to edit |
|---|---|
| `config/sites.yaml` (in repo) | Defaults that ship to every install. PR-worthy. |
| `$DATA_DIR/sites.yaml` (per-install) | Local additions you don't want to upstream. |

The two are deep-merged on every read by `backend/site_rules.get_rules`
— mtime-checked, so a save lands within ~1s without restart. **Lists
in the override file REPLACE, not extend** (`backend/site_rules._deep_merge`).
If you need to add to a default list, copy the whole list into the
override and add to it.

### Example: a new on-prem Keycloak

You captured a flow against `https://sso.corp.local/auth/realms/main/...`
and saw:

- LOGIN steps at `/auth/realms/main/protocol/openid-connect/auth` and
  `/auth/realms/main/login-actions/authenticate`
- AUTH CODE redirect from `/auth/realms/main/protocol/openid-connect/auth`
- TOKENS POST to `/auth/realms/main/protocol/openid-connect/token`
- SESSION cookies `KC_RESTART`, `AUTH_SESSION_ID`, `KEYCLOAK_IDENTITY`

Add to `$DATA_DIR/sites.yaml`:

```yaml
auth_milestones:
  # Lists REPLACE under deep-merge, so re-state the defaults you
  # still want plus your additions. The smallest delta is to start
  # from the package defaults (cat config/sites.yaml) and append.
  idp_hosts:
    # … paste defaults here …
    - sso.corp.local

  login_path_patterns:
    # … paste defaults here …
    - "(?:^|/)auth/realms/[^/]+/login-actions(?:/|\\?|$)"
    - "(?:^|/)auth/realms/[^/]+/protocol/openid-connect/auth(?:/|\\?|$)"

  token_path_patterns:
    # … paste defaults here …
    - "(?:^|/)auth/realms/[^/]+/protocol/openid-connect/token(?:/|\\?|$)"

  session_cookie_names:
    # … paste defaults here …
    - kc_restart
    - auth_session_id
    - keycloak_identity
    - keycloak_session
```

Save. Within ~1 second the next request through the proxy will be
classified with the new rules. Click **Reclassify milestones** to
back-fill rows already in the buffer.

### Regex syntax notes

- All patterns are `re.IGNORECASE`-compiled in
  `site_rules._compile_list`.
- Patterns are joined with `|` into one combined alternation, so each
  must be self-contained (no shared anchors across entries).
- YAML uses double-quoted strings for backslashes —
  `"\\?"` in YAML is the regex `\?`. Single-quoted YAML strings don't
  process escapes, so `'\\?'` is two characters in the regex (`\\?`).
  When in doubt, use double quotes.
- The combined regex is searched, not matched-from-start. Anchor with
  `(?:^|/)` and end with `(?:/|\?|$)` to avoid matching inside a
  longer path component.

### Body markers (the LOGIN fallback)

`login_body_markers` is a substring list, not regex. Keep entries
distinctive — `"username"` matches every form post on the internet
and will over-tag. Prefer markers that only appear on login pages:
`"flowToken"`, `"canary"`, `"stateHandle"`, `"j_spring_security_check"`.

---

## 4 · Validate the addition

Three quick checks:

```bash
# 1. YAML parses
python3 -c "import yaml; yaml.safe_load(open('$DATA_DIR/sites.yaml'))" && echo OK

# 2. Regexes compile (the classifier emits one info line on first
#    access; just look for "auth_milestones compiled: …" in the logs)
journalctl -u bitm-proxy -n 50 -g "auth_milestones compiled"

# 3. Reclassify the captured session and check the kinds histogram
#    appears with non-zero counts for the kinds you expected.
```

In the dashboard:

1. **Flow Trace** → pick the session you exported earlier.
2. **Reclassify milestones**.
3. **All Logs** filter to `flow` → confirm `kinds={'login': N, 'tokens': 1, …}`
   matches your expectation.
4. Scroll Flow Trace — pills are now coloured next to the URL.
5. **Index** tab → expand *Decoded JWTs*; an OIDC-issuing IdP should
   surface `iss` / `aud` / `sub` / `scp` from the captured `id_token`
   / `access_token`.

---

## 5 · Common gotchas

- **Lists replace under deep-merge.** Override files must re-state the
  full list. See `backend/site_rules._deep_merge`.
- **Hot reload is mtime-driven.** A `touch` on the YAML invalidates
  the cache. The classifier uses `id(rules_dict)` as the cache key,
  so a fresh dict from `get_rules` triggers exactly one recompile.
- **`session_cookie_prefixes` is greedy.** Adding `"app"` would tag
  any cookie whose name starts with `app`. Prefer specific prefixes
  (`appsession-`, `app_auth_`).
- **`login_body_markers` is a substring match.** No regex, no
  word-boundary. Generic words (`token`, `password`, `email`) will
  over-tag — pick distinctive IdP-specific markers.
- **`not_login_path_patterns` short-circuits LOGIN.** If you add a
  path here it cannot be tagged LOGIN even via the body-marker
  fallback. Only put non-login endpoints (`/token`, `/userinfo`,
  `/.well-known`, `/jwks`, `/keys`) here.
- **AUTH CODE detection is hardcoded.** The `code=` regex and the
  state/session_state guard live in `auth_milestones.py:classify`,
  not YAML. Open an issue / patch if your IdP uses a different
  parameter name.
- **TOKENS skips 4xx.** Failed token exchanges (invalid_grant,
  expired auth code) don't tag, by design — they're errors, surfaced
  by the existing red error badge instead.
- **Body capture has a 64KB cap.** Larger bodies are truncated by
  `_flow_trim_body`. Tokens are tiny so this rarely affects
  classification, but if your IdP wraps tokens in a giant JWE you
  may need to bump `MAX_FLOW_BODY` in `routes/browser.py` (rare).
- **Restart the proxy after editing `auth_milestones.py`.** YAML
  hot-reloads; Python module changes do not.

---

## 6 · Adding a brand-new milestone kind

If the existing five kinds don't cover what you need (e.g. you want a
"DEVICE_REGISTER" kind for AAD device-registration flows), the work
is in three places:

1. `backend/auth_milestones.py:classify` — emit the new tag from a
   new heuristic (read its inputs from
   `site_rules.auth_milestones_config()` so it's YAML-driven).
2. `config/sites.yaml` — add the rule lists under
   `auth_milestones:` and accessor support in
   `backend/site_rules.py:auth_milestones_config`.
3. `backend/debug_server.py` — add CSS for `.flow-ms-badge.<kind>`
   (the existing block has six entries; copy one and pick a colour).

Don't forget to update `SESSIONS.md` and bump the `MINOR` version
across `backend/main.py`, `backend/debug_server.py`, and
`frontend/package.json` (per `CLAUDE.md`).
