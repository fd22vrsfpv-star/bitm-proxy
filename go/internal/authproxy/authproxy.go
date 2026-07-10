// Package authproxy is the credential-injecting forward proxy.
//
// For plain HTTP, it injects captured Cookie / Authorization / CSRF headers
// from the Python credentials store (via pyclient).
// For HTTPS it does CONNECT tunneling. Full TLS MITM with dynamic cert
// generation is not yet implemented in the Go port — use the Python
// auth_proxy.py for HTTPS injection if you need it.
package authproxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mitm-proxy/go/internal/flowclient"
	"github.com/mitm-proxy/go/internal/pyclient"
)

type Server struct {
	flow *flowclient.Client
	py   *pyclient.Client
	log  *slog.Logger
}

func New(flow *flowclient.Client, py *pyclient.Client) *Server {
	return &Server{
		flow: flow, py: py,
		log: slog.Default().With("component", "authproxy"),
	}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			s.handleConnect(w, r)
			return
		}
		s.handleHTTP(w, r)
	})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	// Plain tunnel; no MITM in Go port v1.
	s.flow.Log("info", "auth_proxy",
		"TUNNEL "+r.Host+" (no MITM in Go port)", "")

	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hij.Hijack()
	if err != nil {
		dest.Close()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { io.Copy(dest, client); dest.Close() }()
	go func() { io.Copy(client, dest); client.Close() }()
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	target, err := url.Parse(r.RequestURI)
	if err != nil || target.Host == "" {
		http.Error(w, "invalid proxy request", http.StatusBadRequest)
		return
	}
	hostname := target.Hostname()
	creds, _ := s.py.CredentialsForHost(hostname)
	injected := []string{}

	// Look up best (most recent) credentials
	var best *pyclient.Credential
	for i := range creds {
		if best == nil || creds[i].CapturedAt > best.CapturedAt {
			best = &creds[i]
		}
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL = target

	if best != nil {
		if cookieHeader := buildCookieHeader(best, hostname); cookieHeader != "" {
			existing := outReq.Header.Get("Cookie")
			if existing != "" {
				outReq.Header.Set("Cookie", existing+"; "+cookieHeader)
			} else {
				outReq.Header.Set("Cookie", cookieHeader)
			}
			injected = append(injected, "cookies")
		}
		for name, val := range buildAuthHeaders(best) {
			if outReq.Header.Get(name) == "" {
				outReq.Header.Set(name, val)
				injected = append(injected, name)
			}
		}
	}

	if len(injected) > 0 {
		s.flow.Log("info", "auth_proxy",
			fmt.Sprintf("INJECT %s %s%s <- %s",
				r.Method, hostname, target.Path, strings.Join(injected, ",")),
			"")
	} else {
		s.flow.Log("debug", "auth_proxy",
			fmt.Sprintf("PASS %s %s%s", r.Method, hostname, target.Path), "")
	}

	tr := &http.Transport{}
	resp, err := tr.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func buildCookieHeader(c *pyclient.Credential, hostname string) string {
	seen := map[string]bool{}
	parts := []string{}
	for _, ck := range c.Cookies {
		name, _ := ck["name"].(string)
		val, _ := ck["value"].(string)
		domain, _ := ck["domain"].(string)
		domain = strings.TrimPrefix(domain, ".")
		if name == "" || val == "" {
			continue
		}
		if domain != "" && !strings.HasSuffix(hostname, domain) {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		parts = append(parts, name+"="+val)
	}
	return strings.Join(parts, "; ")
}

func buildAuthHeaders(c *pyclient.Credential) map[string]string {
	out := map[string]string{}
	// Authorization: Bearer
	for _, k := range []string{"Authorization: Bearer", "access_token", "accessToken"} {
		if info, ok := c.CapturedHeaders[k]; ok {
			if val, _ := info["value"].(string); val != "" {
				out["Authorization"] = "Bearer " + val
				break
			}
		}
	}
	for name, info := range c.CapturedHeaders {
		l := strings.ToLower(name)
		if strings.HasPrefix(l, "cookie:") {
			continue
		}
		if name == "Authorization: Bearer" || name == "access_token" || name == "accessToken" {
			continue
		}
		if strings.Contains(l, "csrf") || strings.Contains(l, "xsrf") ||
			strings.Contains(l, "x-ms-token") || strings.Contains(l, "x-auth") {
			if val, _ := info["value"].(string); val != "" {
				out[name] = val
			}
		}
	}
	return out
}
