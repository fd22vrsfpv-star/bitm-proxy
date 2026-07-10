// Package config resolves runtime config for the Go proxies.
//
// The Python control plane owns the canonical config (in backend/shared.py's
// in-memory _config dict). Go services pull it via HTTP on startup and refresh
// periodically.
package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

// Config mirrors the subset of Python's _config that Go services need.
type Config struct {
	IgnoreSSL          bool `json:"ignore_ssl"`
	LogRequests        bool `json:"log_requests"`
	LogResponses       bool `json:"log_responses"`
	MaskCapturedInput  bool `json:"mask_captured_input"`

	// Ports (informational; daemon binds from env/flags, not these)
	AuthProxyPort int `json:"auth_proxy_port,omitempty"`
}

// Resolver refreshes config from the Python control plane.
type Resolver struct {
	url       string
	mu        sync.RWMutex
	current   Config
	lastFetch time.Time
}

func NewResolver(pythonBase string) *Resolver {
	return &Resolver{url: pythonBase + "/api/config"}
}

func (r *Resolver) Refresh() error {
	req, err := http.NewRequest("GET", r.url, nil)
	if err != nil {
		return err
	}
	// Control plane accepts no-auth on /api/config if REQUIRE_API_KEY=false,
	// otherwise add the key from env.
	if k := os.Getenv("INTERNAL_API_KEY"); k != "" {
		req.Header.Set("Authorization", "Bearer "+k)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("config fetch HTTP %d", resp.StatusCode)
	}
	var c Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return err
	}
	r.mu.Lock()
	r.current = c
	r.lastFetch = time.Now()
	r.mu.Unlock()
	return nil
}

func (r *Resolver) Get() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// AutoRefresh polls the control plane every interval. Safe to run in a goroutine.
func (r *Resolver) AutoRefresh(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		_ = r.Refresh()
	}
}
