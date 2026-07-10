// Package flowclient pushes flow tracer entries to the Python control plane.
//
// The Python debug server owns the canonical flow buffer (deque per session).
// Go services POST structured flow events to /_internal/flow and the control
// plane appends them via shared.append_flow. Non-blocking via a buffered
// channel + worker goroutines; drops events under backpressure rather than
// slowing down proxy forwarding.
package flowclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Entry mirrors the Python flow entry schema.
type Entry struct {
	Type                   string            `json:"type"`
	SessionID              string            `json:"session_id"`
	ReqID                  string            `json:"req_id"`
	TsReq                  float64           `json:"ts_req"`
	TsResp                 *float64          `json:"ts_resp"`
	Method                 string            `json:"method"`
	URL                    string            `json:"url"`
	ResourceType           string            `json:"resource_type"`
	RedirectedFromSeq      *int              `json:"redirected_from_seq"`
	RequestHeaders         map[string]string `json:"request_headers"`
	RequestBody            *string           `json:"request_body"`
	RequestBodyTruncated   bool              `json:"request_body_truncated"`
	Status                 *int              `json:"status"`
	ResponseHeaders        map[string]string `json:"response_headers"`
	ResponseBody           *string           `json:"response_body"`
	ResponseBodyTruncated  bool              `json:"response_body_truncated"`
}

// Update carries a partial flow update keyed by req_id (for response fields).
type Update struct {
	SessionID             string            `json:"session_id"`
	ReqID                 string            `json:"req_id"`
	TsResp                *float64          `json:"ts_resp"`
	Status                *int              `json:"status"`
	ResponseHeaders       map[string]string `json:"response_headers,omitempty"`
	ResponseBody          *string           `json:"response_body,omitempty"`
	ResponseBodyTruncated bool              `json:"response_body_truncated"`
}

// Log is a freeform log line forwarded to Python's append_log.
type Log struct {
	Level     string `json:"level"`
	Category  string `json:"category"`
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
}

type job struct {
	kind string // "flow", "update", "log"
	body any
}

// Client is a buffered, async forwarder to the Python control plane.
type Client struct {
	base       string
	secret     string
	http       *http.Client
	jobs       chan job
	wg         sync.WaitGroup
	dropped    uint64
	droppedMu  sync.Mutex
	log        *slog.Logger
}

// New constructs a Client; call Start to begin the worker goroutine.
func New(base string, secret string, bufSize int) *Client {
	if bufSize <= 0 {
		bufSize = 2048
	}
	return &Client{
		base:   base,
		secret: secret,
		http: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:    20,
				IdleConnTimeout: 60 * time.Second,
			},
		},
		jobs: make(chan job, bufSize),
		log:  slog.Default().With("component", "flowclient"),
	}
}

func (c *Client) Start(workers int) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		c.wg.Add(1)
		go c.worker()
	}
}

func (c *Client) Stop(ctx context.Context) {
	close(c.jobs)
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// AppendFlow queues a new flow entry. Non-blocking; drops silently under pressure.
func (c *Client) AppendFlow(e Entry) {
	e.Type = "flow"
	c.offer(job{kind: "flow", body: e})
}

func (c *Client) UpdateFlow(u Update) {
	c.offer(job{kind: "update", body: u})
}

func (c *Client) Log(level, category, message, sessionID string) {
	c.offer(job{kind: "log", body: Log{
		Level: level, Category: category, Message: message, SessionID: sessionID,
	}})
}

func (c *Client) offer(j job) {
	select {
	case c.jobs <- j:
	default:
		c.droppedMu.Lock()
		c.dropped++
		n := c.dropped
		c.droppedMu.Unlock()
		if n%1000 == 1 {
			c.log.Warn("dropped flow event under backpressure", "total_dropped", n)
		}
	}
}

func (c *Client) worker() {
	defer c.wg.Done()
	for j := range c.jobs {
		c.send(j)
	}
}

func (c *Client) send(j job) {
	path := map[string]string{
		"flow":   "/_internal/flow",
		"update": "/_internal/flow_update",
		"log":    "/_internal/log",
	}[j.kind]
	if path == "" {
		return
	}
	buf, err := json.Marshal(j.body)
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", c.base+path, bytes.NewReader(buf))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if c.secret != "" {
		req.Header.Set("X-Internal-Secret", c.secret)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()
}

// FromEnv constructs a client using PYTHON_BASE_URL and INTERNAL_SECRET env vars.
func FromEnv() *Client {
	base := os.Getenv("PYTHON_BASE_URL")
	if base == "" {
		base = "http://127.0.0.1:8092"
	}
	secret := os.Getenv("INTERNAL_SECRET")
	if secret == "" {
		secret = "dev-internal-secret"
	}
	return New(base, secret, 4096)
}

// Ptr is a convenience for the optional fields above.
func Ptr[T any](v T) *T { return &v }

// ErrDropped is returned (informationally) when backpressure drops events.
var ErrDropped = fmt.Errorf("event dropped under backpressure")
