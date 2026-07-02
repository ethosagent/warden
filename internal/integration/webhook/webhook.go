// Package webhook is the reference outbound integration: it implements
// integration.Integration + integration.Alerter, POSTing each routed Alert as
// JSON to a configured URL. It self-registers under the type key "webhook".
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/integration"
)

// defaultHTTPTimeout bounds a single POST at the client level (the router also
// applies its own per-attempt context timeout).
const defaultHTTPTimeout = 10 * time.Second

// Webhook delivers Alerts to an HTTP(S) endpoint.
type Webhook struct {
	mu     sync.Mutex
	client *http.Client
	url    string // full endpoint (may embed a token) — NEVER logged
	host   string // host only, safe to log
}

// Type is the stable registry key.
func (w *Webhook) Type() string { return "webhook" }

type webhookConfig struct {
	URL string `json:"url"`
}

// Start decodes the config, expands ${ENV} in the URL, validates it is a
// non-empty http(s) URL, and prepares an HTTP client.
func (w *Webhook) Start(_ context.Context, _ integration.System, cfg integration.Config) error {
	var c webhookConfig
	if err := cfg.Decode(&c); err != nil {
		return fmt.Errorf("webhook %q: decode config: %w", cfg.Name, err)
	}
	// Secrets follow Warden's existing ${ENV} convention: the URL may be
	// "${WEBHOOK_URL}" and is resolved from the environment at Start.
	raw := expandEnv(c.URL)
	if raw == "" {
		return fmt.Errorf("webhook %q: url is required (set config.url, e.g. \"${WEBHOOK_URL}\")", cfg.Name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("webhook %q: invalid url: %w", cfg.Name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("webhook %q: url scheme must be http or https", cfg.Name)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook %q: url missing host", cfg.Name)
	}

	w.mu.Lock()
	w.url = raw
	w.host = u.Host
	w.client = &http.Client{Timeout: defaultHTTPTimeout}
	w.mu.Unlock()
	return nil
}

// alertPayload is the JSON body POSTed per Alert. Alert.ID is included so the
// receiver can dedupe (delivery is at-least-once ⇒ idempotent on ID).
type alertPayload struct {
	ID        string              `json:"id"`
	DedupKey  string              `json:"dedupKey"`
	Category  string              `json:"category"`
	Severity  string              `json:"severity"`
	Subject   integration.Subject `json:"subject"`
	Summary   string              `json:"summary"`
	Evidence  string              `json:"evidence"`
	Status    string              `json:"status"`
	Count     int                 `json:"count"`
	FirstSeen time.Time           `json:"firstSeen"`
	LastSeen  time.Time           `json:"lastSeen"`
}

// Alert POSTs a as JSON. A non-2xx response (or transport error) returns an
// error so the router retries and eventually dead-letters. The URL is never
// logged or included in errors — only its host (it may embed a token).
func (w *Webhook) Alert(ctx context.Context, a integration.Alert) error {
	w.mu.Lock()
	client := w.client
	endpoint := w.url
	host := w.host
	w.mu.Unlock()
	if client == nil {
		return fmt.Errorf("webhook: Alert called before Start")
	}

	body, err := json.Marshal(alertPayload{
		ID:        a.ID,
		DedupKey:  a.DedupKey,
		Category:  a.Category,
		Severity:  a.Severity.String(),
		Subject:   a.Subject,
		Summary:   a.Summary,
		Evidence:  string(a.Evidence),
		Status:    string(a.Status),
		Count:     a.Count,
		FirstSeen: a.FirstSeen,
		LastSeen:  a.LastSeen,
	})
	if err != nil {
		return fmt.Errorf("webhook: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request for host %s: %w", host, err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: POST to %s failed: %w", host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("webhook: POST to %s returned status %d", host, resp.StatusCode)
	}
	return nil
}

// Stop is idempotent: it drops the client and closes idle connections.
func (w *Webhook) Stop(_ context.Context) error {
	w.mu.Lock()
	client := w.client
	w.client = nil
	w.mu.Unlock()
	if client != nil {
		client.CloseIdleConnections()
	}
	return nil
}

// expandEnv resolves ${VAR}/$VAR references from the process environment,
// following Warden's existing ${ENV} secret-reference convention.
func expandEnv(s string) string { return os.Expand(s, os.Getenv) }

func init() {
	integration.Register("webhook", func() integration.Integration { return &Webhook{} })
}
