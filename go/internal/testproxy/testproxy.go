// Package testproxy is a simple forward proxy — CONNECT tunnels for HTTPS,
// plain proxy for HTTP. No interception, used to verify proxy wiring.
package testproxy

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mitm-proxy/go/internal/flowclient"
)

type Server struct {
	flow *flowclient.Client
	log  *slog.Logger
}

func New(flow *flowclient.Client) *Server {
	return &Server{flow: flow, log: slog.Default().With("component", "testproxy")}
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			s.flow.Log("info", "test_proxy",
				"PASSTHROUGH CONNECT "+r.Host+
					" — tunneled as-is, no MITM, no capture, no injection",
				"testproxy")
			s.handleConnect(w, r)
			return
		}
		s.flow.Log("info", "test_proxy",
			"PASSTHROUGH "+r.Method+" "+r.URL.String()+
				" — forwarded as-is, no MITM, no capture, no injection",
			"testproxy")
		s.handleHTTP(w, r)
	})
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		dest.Close()
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		dest.Close()
		return
	}
	client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go func() { io.Copy(dest, client); dest.Close() }()
	go func() { io.Copy(client, dest); client.Close() }()
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Plain-HTTP forward proxy: rewrite URL, forward.
	tr := &http.Transport{}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
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
