package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// --- fakes ---

type fakeDataSource struct {
	events []analytics.Event
}

func (f *fakeDataSource) GetEvents(filter analytics.EventFilter) ([]analytics.Event, error) {
	var out []analytics.Event
	for i := len(f.events) - 1; i >= 0; i-- {
		e := f.events[i]
		if filter.Domain != "" && e.Domain != filter.Domain {
			continue
		}
		if filter.Decision != "" && e.Decision != filter.Decision {
			continue
		}
		if !filter.Since.IsZero() && e.Timestamp.Before(filter.Since) {
			continue
		}
		out = append(out, e)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

type fakeSecretProvider struct {
	values map[string]string
	err    error
}

func (f *fakeSecretProvider) GetSecret(placeholder string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	v, ok := f.values[placeholder]
	if !ok {
		return "", fmt.Errorf("unknown placeholder")
	}
	return v, nil
}

func (f *fakeSecretProvider) RefreshSecrets() error { return nil }

// --- helpers ---

func newTestServer(ds DataSource, pol config.Policy, sp secrets.SecretProvider) http.Handler {
	return NewServer(ds, pol, sp).Handler()
}

func doGet(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// --- tests ---

func TestTrafficEndpoint(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Timestamp: now, Domain: "api.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://api.example.com/v1", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(time.Second), Domain: "evil.com", Port: 443, Protocol: "https", Method: "POST", URL: "https://evil.com/hack", Decision: "deny", ResponseStatus: 403},
			{Timestamp: now.Add(2 * time.Second), Domain: "api.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://api.example.com/v2", Decision: "allow", ResponseStatus: 200},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	t.Run("all events", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/traffic")
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var events []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(events) != 3 {
			t.Fatalf("expected 3 events, got %d", len(events))
		}
	})

	t.Run("filter by domain", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/traffic?domain=evil.com")
		var events []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("expected 1 event, got %d", len(events))
		}
		if events[0]["Domain"] != "evil.com" {
			t.Fatalf("expected domain evil.com, got %v", events[0]["Domain"])
		}
	})

	t.Run("limit", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/traffic?limit=2")
		var events []map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &events); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("expected 2 events, got %d", len(events))
		}
	})
}

func TestPolicyEndpoint(t *testing.T) {
	pol := config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.example.com", Port: 443},
			{Domain: "cdn.example.com"},
		},
		Denylist: []config.DenylistEntry{
			{Domain: "evil.com"},
		},
		Secrets: []config.SecretMapping{
			{Placeholder: "secret_1", EnvVar: "SECRET_1"},
		},
	}
	handler := newTestServer(&fakeDataSource{}, pol, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/policy")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Must have allowlist and denylist
	if _, ok := resp["allowlist"]; !ok {
		t.Fatal("missing allowlist in response")
	}
	if _, ok := resp["denylist"]; !ok {
		t.Fatal("missing denylist in response")
	}

	// Must NOT contain secrets
	body := rr.Body.String()
	if strings.Contains(body, "Secrets") || strings.Contains(body, "SECRET_1") || strings.Contains(body, "secret_1") {
		t.Fatal("policy response must not contain secret information")
	}

	// Check allowlist count
	var allowlist []map[string]any
	if err := json.Unmarshal(resp["allowlist"], &allowlist); err != nil {
		t.Fatalf("unmarshal allowlist: %v", err)
	}
	if len(allowlist) != 2 {
		t.Fatalf("expected 2 allowlist entries, got %d", len(allowlist))
	}

	// Check denylist count
	var denylist []map[string]any
	if err := json.Unmarshal(resp["denylist"], &denylist); err != nil {
		t.Fatalf("unmarshal denylist: %v", err)
	}
	if len(denylist) != 1 {
		t.Fatalf("expected 1 denylist entry, got %d", len(denylist))
	}
}

func TestSecretsEndpoint(t *testing.T) {
	pol := config.Policy{
		Secrets: []config.SecretMapping{
			{Placeholder: "openai_key", EnvVar: "OPENAI_API_KEY"},
			{Placeholder: "bad_key", EnvVar: "MISSING_VAR"},
		},
	}
	sp := &fakeSecretProvider{
		values: map[string]string{
			"openai_key": "sk-test-1234567890abcdef",
		},
	}
	handler := newTestServer(&fakeDataSource{}, pol, sp)

	rr := doGet(t, handler, "/dashboard/api/secrets")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var entries []secretEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &entries); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// First entry: successful
	first := entries[0]
	if first.Placeholder != "openai_key" {
		t.Fatalf("expected placeholder openai_key, got %s", first.Placeholder)
	}
	if first.Ref == nil {
		t.Fatal("expected ref to be non-nil for openai_key")
	}
	if first.Ref.SHA256 == "" {
		t.Fatal("expected non-empty sha256")
	}
	ref := secrets.Ref("sk-test-1234567890abcdef")
	if first.Ref.SHA256 != ref.SHA256 {
		t.Fatalf("sha256 mismatch: got %s, want %s", first.Ref.SHA256, ref.SHA256)
	}
	if first.Ref.Last4 != "cdef" {
		t.Fatalf("expected last4 'cdef', got %s", first.Ref.Last4)
	}
	if first.Ref.Length != len("sk-test-1234567890abcdef") {
		t.Fatalf("expected length %d, got %d", len("sk-test-1234567890abcdef"), first.Ref.Length)
	}

	// Must NOT contain the raw value
	body := rr.Body.String()
	if strings.Contains(body, "sk-test-1234567890abcdef") {
		t.Fatal("response must not contain raw secret value")
	}

	// Second entry: error
	second := entries[1]
	if second.Placeholder != "bad_key" {
		t.Fatalf("expected placeholder bad_key, got %s", second.Placeholder)
	}
	if second.Ref != nil {
		t.Fatal("expected ref to be nil for failing secret")
	}
	if second.Error == "" {
		t.Fatal("expected error message for failing secret")
	}
}

func TestBlockedEndpoint(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Timestamp: now, Domain: "evil.com", Decision: "deny"},
			{Timestamp: now.Add(time.Minute), Domain: "evil.com", Decision: "deny"},
			{Timestamp: now.Add(2 * time.Minute), Domain: "evil.com", Decision: "deny"},
			{Timestamp: now, Domain: "bad.org", Decision: "deny"},
			{Timestamp: now.Add(time.Hour), Domain: "bad.org", Decision: "deny"},
			{Timestamp: now, Domain: "api.example.com", Decision: "allow"},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/blocked")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var groups []blockedGroup
	if err := json.Unmarshal(rr.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(groups))
	}

	// evil.com should be first (3 > 2)
	if groups[0].Domain != "evil.com" {
		t.Fatalf("expected first group to be evil.com, got %s", groups[0].Domain)
	}
	if groups[0].Count != 3 {
		t.Fatalf("expected count 3 for evil.com, got %d", groups[0].Count)
	}
	if groups[1].Domain != "bad.org" {
		t.Fatalf("expected second group to be bad.org, got %s", groups[1].Domain)
	}
	if groups[1].Count != 2 {
		t.Fatalf("expected count 2 for bad.org, got %d", groups[1].Count)
	}

	// Verify first/last seen
	if groups[0].FirstSeen != now.Format(time.RFC3339) {
		t.Fatalf("expected first_seen %s, got %s", now.Format(time.RFC3339), groups[0].FirstSeen)
	}
	if groups[0].LastSeen != now.Add(2*time.Minute).Format(time.RFC3339) {
		t.Fatalf("expected last_seen %s, got %s", now.Add(2*time.Minute).Format(time.RFC3339), groups[0].LastSeen)
	}
}

func TestStatsEndpoint(t *testing.T) {
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Domain: "a.com", Decision: "allow"},
			{Domain: "a.com", Decision: "allow"},
			{Domain: "b.com", Decision: "deny"},
			{Domain: "c.com", Decision: "allow"},
			{Domain: "c.com", Decision: "deny"},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var stats statsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &stats); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if stats.Total != 5 {
		t.Fatalf("expected total 5, got %d", stats.Total)
	}
	if stats.AllowCount != 3 {
		t.Fatalf("expected allow_count 3, got %d", stats.AllowCount)
	}
	if stats.DenyCount != 2 {
		t.Fatalf("expected deny_count 2, got %d", stats.DenyCount)
	}
	if len(stats.TopDestinations) != 3 {
		t.Fatalf("expected 3 top destinations, got %d", len(stats.TopDestinations))
	}
	// a.com and c.com both have 2, should sort alphabetically
	if stats.TopDestinations[0].Domain != "a.com" {
		t.Fatalf("expected first destination a.com, got %s", stats.TopDestinations[0].Domain)
	}
	if stats.TopDestinations[0].Count != 2 {
		t.Fatalf("expected count 2, got %d", stats.TopDestinations[0].Count)
	}
}

func TestHTMLServes(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html content type, got %s", ct)
	}
	if !strings.Contains(rr.Body.String(), "Warden Dashboard") {
		t.Fatal("expected body to contain 'Warden Dashboard'")
	}
}

func TestMethodNotAllowed(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	endpoints := []string{
		"/dashboard/api/traffic",
		"/dashboard/api/policy",
		"/dashboard/api/secrets",
		"/dashboard/api/blocked",
		"/dashboard/api/stats",
		"/dashboard/",
	}
	for _, ep := range endpoints {
		t.Run("POST "+ep, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, ep, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Fatalf("expected 405 for POST %s, got %d", ep, rr.Code)
			}
		})
	}
}
