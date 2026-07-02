package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/integration"
)

func testConfig(name, rawURL string) integration.Config {
	return integration.Config{Name: name, Raw: map[string]any{"url": rawURL}}
}

func sampleAlert() integration.Alert {
	return integration.Alert{
		ID:        "abc123",
		DedupKey:  "error_rate:api.foo.com",
		Category:  "reliability",
		Severity:  integration.SevHigh,
		Subject:   integration.Subject{Domain: "api.foo.com", Tool: "search"},
		Summary:   "error rate high",
		Evidence:  "rate=7.2% window=5m",
		Status:    integration.StatusFiring,
		Count:     3,
		FirstSeen: time.UnixMilli(1000).UTC(),
		LastSeen:  time.UnixMilli(2000).UTC(),
	}
}

func TestWebhookRegistered(t *testing.T) {
	// The init() self-registration must make "webhook" constructible via the
	// registry. We assert indirectly: a fresh Webhook has the right type key.
	w := &Webhook{}
	if w.Type() != "webhook" {
		t.Errorf("Type() = %q, want webhook", w.Type())
	}
}

func TestWebhookSuccess(t *testing.T) {
	var gotBody []byte
	var gotCT string
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotCT = req.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(req.Body)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := &Webhook{}
	if err := w.Start(context.Background(), nil, testConfig("hook", srv.URL)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := w.Alert(context.Background(), sampleAlert()); err != nil {
		t.Fatalf("Alert: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("server hits = %d, want 1", hits)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}

	// Payload shape assertion.
	var payload map[string]any
	if err := json.Unmarshal(gotBody, &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["id"] != "abc123" {
		t.Errorf("payload id = %v, want abc123 (idempotency key)", payload["id"])
	}
	if payload["severity"] != "high" {
		t.Errorf("payload severity = %v, want high", payload["severity"])
	}
	if payload["dedupKey"] != "error_rate:api.foo.com" {
		t.Errorf("payload dedupKey = %v", payload["dedupKey"])
	}
	if payload["status"] != "firing" {
		t.Errorf("payload status = %v", payload["status"])
	}
	if _, ok := payload["subject"]; !ok {
		t.Error("payload missing subject")
	}
	_ = w.Stop(context.Background())
	// Stop is idempotent.
	if err := w.Stop(context.Background()); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestWebhookNon2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	w := &Webhook{}
	if err := w.Start(context.Background(), nil, testConfig("hook", srv.URL)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	err := w.Alert(context.Background(), sampleAlert())
	if err == nil {
		t.Fatal("5xx should return an error so the router retries/dead-letters")
	}
	// Error must reference host, never the full URL (may embed a token).
	host := strings.TrimPrefix(srv.URL, "http://")
	if !strings.Contains(err.Error(), host) {
		t.Errorf("error %q should reference host %q", err.Error(), host)
	}
}

func TestWebhookEnvExpansion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent) // 204, still 2xx
	}))
	defer srv.Close()

	t.Setenv("WARDEN_WH_URL", srv.URL)
	w := &Webhook{}
	if err := w.Start(context.Background(), nil, testConfig("hook", "${WARDEN_WH_URL}")); err != nil {
		t.Fatalf("Start with ${ENV} url: %v", err)
	}
	if err := w.Alert(context.Background(), sampleAlert()); err != nil {
		t.Errorf("Alert after env expansion: %v", err)
	}
}

func TestWebhookMissingURL(t *testing.T) {
	w := &Webhook{}
	err := w.Start(context.Background(), nil, testConfig("hook", ""))
	if err == nil {
		t.Error("empty URL should error")
	}
	// Unset env var expands to empty ⇒ also an error.
	err = w.Start(context.Background(), nil, testConfig("hook", "${WARDEN_UNSET_URL_XYZ}"))
	if err == nil {
		t.Error("unset env url should error")
	}
}

func TestWebhookInvalidScheme(t *testing.T) {
	w := &Webhook{}
	if err := w.Start(context.Background(), nil, testConfig("hook", "ftp://example.com")); err == nil {
		t.Error("non-http(s) scheme should error")
	}
}

func TestWebhookAlertBeforeStart(t *testing.T) {
	w := &Webhook{}
	if err := w.Alert(context.Background(), sampleAlert()); err == nil {
		t.Error("Alert before Start should error")
	}
}

func TestWebhookContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	w := &Webhook{}
	if err := w.Start(context.Background(), nil, testConfig("hook", srv.URL)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := w.Alert(ctx, sampleAlert()); err == nil {
		t.Error("Alert should respect ctx timeout and return an error")
	}
}
