// Package pyclient lets Go services query the Python control plane for
// state it owns — mainly captured credentials used by the auth proxy.
package pyclient

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"time"
)

type Credential struct {
	Tokens           []map[string]any            `json:"tokens"`
	CapturedHeaders  map[string]map[string]any   `json:"captured_headers"`
	Cookies          []map[string]any            `json:"cookies"`
	CurrentURL       string                      `json:"current_url"`
	CapturedAt       float64                     `json:"captured_at"`
	CredKey          string                      `json:"_cred_key"`
}

type Client struct {
	base    string
	secret  string
	http    *http.Client
}

func New(base, secret string) *Client {
	return &Client{
		base:   base,
		secret: secret,
		http:   &http.Client{Timeout: 5 * time.Second},
	}
}

// CredentialsForHost fetches all credentials from Python whose domain matches hostname.
func (c *Client) CredentialsForHost(hostname string) ([]Credential, error) {
	req, err := http.NewRequest("GET", c.base+"/_internal/creds?host="+hostname, nil)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("X-Internal-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, nil // no creds, not an error
	}
	var out struct {
		Credentials []Credential `json:"credentials"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Credentials, nil
}

// StoreCapturedHeader sends a captured header back to Python so it lands in
// the credentials_store alongside browser-session captures.
func (c *Client) StoreCapturedHeader(siteID, name, value, sourceURL string) error {
	body := map[string]any{
		"site_id":    siteID,
		"name":       name,
		"value":      value,
		"source_url": sourceURL,
	}
	data, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", c.base+"/_internal/captured_header", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("X-Internal-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func FromEnv() *Client {
	base := os.Getenv("PYTHON_BASE_URL")
	if base == "" {
		base = "http://127.0.0.1:8092"
	}
	secret := os.Getenv("INTERNAL_SECRET")
	if secret == "" {
		secret = "dev-internal-secret"
	}
	return New(base, secret)
}
