// Command mitm-proxies runs the Go-ported proxy services in a single binary.
//
// Services:
//   - reverse proxy on RP_PORT  (default 8085)
//   - auth proxy    on AUTH_PORT (default 3128)
//   - test proxy    on TEST_PORT (default 3129)
//
// All services push flow events to the Python control plane at PYTHON_BASE_URL
// via flowclient. The RAG API (:8000) stays in Python because it reads the
// authoritative flow buffer.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mitm-proxy/go/internal/authproxy"
	"github.com/mitm-proxy/go/internal/flowclient"
	"github.com/mitm-proxy/go/internal/pyclient"
	"github.com/mitm-proxy/go/internal/revproxy"
	"github.com/mitm-proxy/go/internal/testproxy"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
	log := slog.Default().With("component", "main")

	host := envOr("HOST", "0.0.0.0")
	rpPort := envInt("RP_PORT", 8085)
	authPort := envInt("AUTH_PROXY_PORT", 3128)
	testPort := envInt("TEST_PROXY_PORT", 3129)
	disableAuth := envBool("DISABLE_GO_AUTHPROXY")

	flow := flowclient.FromEnv()
	flow.Start(4)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		flow.Stop(ctx)
	}()
	py := pyclient.FromEnv()

	rpSrv := &http.Server{
		Addr:    host + ":" + strconv.Itoa(rpPort),
		Handler: revproxy.New(flow).Handler(),
	}
	testSrv := &http.Server{
		Addr:    host + ":" + strconv.Itoa(testPort),
		Handler: testproxy.New(flow).Handler(),
	}
	var authSrv *http.Server
	if !disableAuth {
		authSrv = &http.Server{
			Addr:    host + ":" + strconv.Itoa(authPort),
			Handler: authproxy.New(flow, py).Handler(),
		}
	}

	logArgs := []any{
		"reverse_proxy", rpSrv.Addr,
		"test_proxy", testSrv.Addr,
		"python_base", envOr("PYTHON_BASE_URL", "http://127.0.0.1:8092"),
	}
	if authSrv != nil {
		logArgs = append(logArgs, "auth_proxy", authSrv.Addr)
	} else {
		logArgs = append(logArgs,
			"auth_proxy", "disabled (DISABLE_GO_AUTHPROXY) — start Python auth_proxy from dashboard for full MITM")
	}
	log.Info("starting Go proxy services", logArgs...)

	errCh := make(chan error, 3)
	go func() { errCh <- rpSrv.ListenAndServe() }()
	go func() { errCh <- testSrv.ListenAndServe() }()
	if authSrv != nil {
		go func() { errCh <- authSrv.ListenAndServe() }()
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		log.Info("shutting down", "signal", sig)
	case err := <-errCh:
		log.Error("server error", "err", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = rpSrv.Shutdown(ctx)
	_ = testSrv.Shutdown(ctx)
	if authSrv != nil {
		_ = authSrv.Shutdown(ctx)
	}
}
