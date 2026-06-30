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
	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
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
		if filter.Protocol != "" && e.Protocol != filter.Protocol {
			continue
		}
		if filter.Tool != "" && e.Tool != filter.Tool {
			continue
		}
		if filter.ProxyID != "" && e.ProxyID != filter.ProxyID {
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

func TestEndpointsEndpoint(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			// foo: hit 3 times; latest at now+2m is a deny/403.
			{Timestamp: now, Domain: "api.example.com", Method: "POST", URL: "https://api.example.com/foo", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(time.Minute), Domain: "api.example.com", Method: "POST", URL: "https://api.example.com/foo", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(2 * time.Minute), Domain: "api.example.com", Method: "POST", URL: "https://api.example.com/foo", Decision: "deny", ResponseStatus: 403},
			// bar: hit once, but most recently (now+1h) -> sorts first by lastSeen.
			{Timestamp: now.Add(time.Hour), Domain: "api.example.com", Method: "GET", URL: "https://api.example.com/bar", Decision: "allow", ResponseStatus: 200},
			// Same URL as foo but different method -> distinct group.
			{Timestamp: now, Domain: "api.example.com", Method: "GET", URL: "https://api.example.com/foo", Decision: "allow", ResponseStatus: 200},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	t.Run("aggregation and sort", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints")
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		// 3 distinct (method,url) groups: POST /foo, GET /bar, GET /foo.
		if resp.Total != 3 {
			t.Fatalf("expected total 3, got %d", resp.Total)
		}
		if resp.Page != 1 || resp.PageSize != 50 || resp.TotalPages != 1 {
			t.Fatalf("unexpected pagination: %+v", resp)
		}
		if len(resp.Items) != 3 {
			t.Fatalf("expected 3 items, got %d", len(resp.Items))
		}
		// GET /bar has the latest lastSeen -> first.
		first := resp.Items[0]
		if first.Method != "GET" || first.URL != "https://api.example.com/bar" {
			t.Fatalf("expected GET /bar first, got %s %s", first.Method, first.URL)
		}
		// Find POST /foo and verify aggregation.
		var foo *endpointGroup
		for i := range resp.Items {
			if resp.Items[i].Method == "POST" && resp.Items[i].URL == "https://api.example.com/foo" {
				foo = &resp.Items[i]
			}
		}
		if foo == nil {
			t.Fatal("POST /foo group not found")
		}
		if foo.Count != 3 {
			t.Fatalf("expected count 3 for POST /foo, got %d", foo.Count)
		}
		if foo.FirstSeen != now.Format(time.RFC3339) {
			t.Fatalf("expected firstSeen %s, got %s", now.Format(time.RFC3339), foo.FirstSeen)
		}
		if foo.LastSeen != now.Add(2*time.Minute).Format(time.RFC3339) {
			t.Fatalf("expected lastSeen %s, got %s", now.Add(2*time.Minute).Format(time.RFC3339), foo.LastSeen)
		}
		if foo.LastDecision != "deny" {
			t.Fatalf("expected lastDecision deny, got %s", foo.LastDecision)
		}
		if foo.LastStatus != 403 {
			t.Fatalf("expected lastStatus 403, got %d", foo.LastStatus)
		}
	})

	t.Run("pagination slicing", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?page=2&pageSize=2")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Total != 3 || resp.TotalPages != 2 {
			t.Fatalf("expected total 3 / totalPages 2, got %d / %d", resp.Total, resp.TotalPages)
		}
		if resp.Page != 2 || resp.PageSize != 2 {
			t.Fatalf("expected page 2 size 2, got %d / %d", resp.Page, resp.PageSize)
		}
		// Page 2 of size 2 over 3 items -> 1 item.
		if len(resp.Items) != 1 {
			t.Fatalf("expected 1 item on page 2, got %d", len(resp.Items))
		}
	})

	t.Run("page out of range yields empty slice", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?page=99&pageSize=50")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(resp.Items) != 0 {
			t.Fatalf("expected 0 items for out-of-range page, got %d", len(resp.Items))
		}
	})

	t.Run("bad params fall back to defaults", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?page=abc&pageSize=-5")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Page != 1 {
			t.Fatalf("expected default page 1, got %d", resp.Page)
		}
		if resp.PageSize != 50 {
			t.Fatalf("expected default pageSize 50, got %d", resp.PageSize)
		}
	})

	t.Run("pageSize clamps to 200", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?pageSize=9999")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.PageSize != 200 {
			t.Fatalf("expected pageSize clamped to 200, got %d", resp.PageSize)
		}
	})

	t.Run("empty data", func(t *testing.T) {
		emptyHandler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
		rr := doGet(t, emptyHandler, "/dashboard/api/endpoints")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Total != 0 || resp.TotalPages != 0 {
			t.Fatalf("expected total 0 / totalPages 0, got %d / %d", resp.Total, resp.TotalPages)
		}
		if len(resp.Items) != 0 {
			t.Fatalf("expected 0 items, got %d", len(resp.Items))
		}
	})
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

func TestHTMLHasFavicon(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `rel="icon"`) {
		t.Fatal("expected dashboard HTML to declare a favicon (rel=\"icon\")")
	}
	if !strings.Contains(body, "image/svg+xml") {
		t.Fatal("expected favicon to be an inline SVG (image/svg+xml data URI)")
	}
}

func TestEndpointsDomainFilter(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Timestamp: now, Domain: "a.com", Method: "GET", URL: "https://a.com/x", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(time.Minute), Domain: "a.com", Method: "POST", URL: "https://a.com/y", Decision: "allow", ResponseStatus: 201},
			{Timestamp: now.Add(2 * time.Minute), Domain: "b.com", Method: "GET", URL: "https://b.com/z", Decision: "deny", ResponseStatus: 403},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/endpoints?domain=a.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp endpointsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 2 {
		t.Fatalf("expected 2 endpoints for a.com, got %d", resp.Total)
	}
	for _, it := range resp.Items {
		if it.Domain != "a.com" {
			t.Fatalf("expected only a.com endpoints, got %s", it.Domain)
		}
	}

	// Without the filter, all 3 distinct endpoints appear.
	rr = doGet(t, handler, "/dashboard/api/endpoints")
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Total != 3 {
		t.Fatalf("expected 3 endpoints unfiltered, got %d", resp.Total)
	}
}

func TestAnalyticsEndpoint(t *testing.T) {
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{
		events: []analytics.Event{
			{Timestamp: now, Domain: "api.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://api.example.com/v1", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(time.Second), Domain: "api.example.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://api.example.com/v1", Decision: "allow", ResponseStatus: 304},
			{Timestamp: now.Add(2 * time.Second), Domain: "api.example.com", Port: 443, Protocol: "https", Method: "POST", URL: "https://api.example.com/write", Decision: "allow", ResponseStatus: 201, SecretRef: "openai_secret_001"},
			{Timestamp: now.Add(3 * time.Second), Domain: "evil.com", Port: 443, Protocol: "https", Method: "POST", URL: "https://evil.com/exfil", Decision: "deny", ResponseStatus: 403, JudgeReason: "blocked: exfiltration attempt"},
			{Timestamp: now.Add(4 * time.Second), Domain: "broken.io", Port: 80, Protocol: "http", Method: "GET", URL: "http://broken.io/x", Decision: "allow", ResponseStatus: 503},
			{Timestamp: now.Add(5 * time.Second), Domain: "evil.com", Port: 443, Protocol: "https", Method: "GET", URL: "https://evil.com/probe", Decision: "deny", ResponseStatus: 0, JudgeReason: "blocked: known-bad domain"},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/analytics")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp analyticsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if resp.GeneratedAt == "" {
		t.Fatal("expected generatedAt to be set")
	}
	// Totals.
	if resp.Totals.Requests != 6 {
		t.Fatalf("expected 6 requests, got %d", resp.Totals.Requests)
	}
	if resp.Totals.Allowed != 4 || resp.Totals.Denied != 2 {
		t.Fatalf("expected allowed 4 / denied 2, got %d / %d", resp.Totals.Allowed, resp.Totals.Denied)
	}
	if resp.Totals.UniqueDomains != 3 {
		t.Fatalf("expected 3 unique domains, got %d", resp.Totals.UniqueDomains)
	}
	// 5 distinct (method,url) endpoints.
	if resp.Totals.UniqueEndpoints != 5 {
		t.Fatalf("expected 5 unique endpoints, got %d", resp.Totals.UniqueEndpoints)
	}
	// Writes = distinct non-GET endpoints: POST /write and POST /exfil = 2.
	if resp.Totals.Writes != 2 {
		t.Fatalf("expected 2 write endpoints, got %d", resp.Totals.Writes)
	}

	// Status classes: 200 -> 2xx, 304 -> 3xx, 201 -> 2xx, 403 -> 4xx, 503 -> 5xx, 0 -> other.
	if resp.StatusClasses.C2xx != 2 {
		t.Fatalf("expected 2 2xx, got %d", resp.StatusClasses.C2xx)
	}
	if resp.StatusClasses.C3xx != 1 {
		t.Fatalf("expected 1 3xx, got %d", resp.StatusClasses.C3xx)
	}
	if resp.StatusClasses.C4xx != 1 {
		t.Fatalf("expected 1 4xx, got %d", resp.StatusClasses.C4xx)
	}
	if resp.StatusClasses.C5xx != 1 {
		t.Fatalf("expected 1 5xx, got %d", resp.StatusClasses.C5xx)
	}
	if resp.StatusClasses.Other != 1 {
		t.Fatalf("expected 1 other, got %d", resp.StatusClasses.Other)
	}

	// Methods sorted by count desc: GET(4) before POST(2).
	if len(resp.Methods) != 2 || resp.Methods[0].Method != "GET" || resp.Methods[0].Count != 4 {
		t.Fatalf("unexpected methods: %+v", resp.Methods)
	}
	if resp.Methods[1].Method != "POST" || resp.Methods[1].Count != 2 {
		t.Fatalf("unexpected POST method entry: %+v", resp.Methods)
	}

	// Protocols sorted: https(5) before http(1).
	if len(resp.Protocols) != 2 || resp.Protocols[0].Protocol != "https" || resp.Protocols[0].Count != 5 {
		t.Fatalf("unexpected protocols: %+v", resp.Protocols)
	}

	// Timeline: events span 5s -> single bucket fallback OR 30 buckets; tally must equal totals.
	var tlAllow, tlDeny int
	for _, b := range resp.Timeline {
		tlAllow += b.Allow
		tlDeny += b.Deny
	}
	if tlAllow != 4 || tlDeny != 2 {
		t.Fatalf("timeline tally mismatch: allow %d deny %d", tlAllow, tlDeny)
	}
	if len(resp.Timeline) == 0 {
		t.Fatal("expected at least one timeline bucket")
	}

	// Hourly is 24 entries with correct hour indices.
	if len(resp.Hourly) != 24 {
		t.Fatalf("expected 24 hourly entries, got %d", len(resp.Hourly))
	}
	for i, h := range resp.Hourly {
		if h.Hour != i {
			t.Fatalf("hourly[%d].Hour = %d, want %d", i, h.Hour, i)
		}
	}
	var hourlyTotal int
	for _, h := range resp.Hourly {
		hourlyTotal += h.Count
	}
	if hourlyTotal != 6 {
		t.Fatalf("expected hourly total 6, got %d", hourlyTotal)
	}

	// Top domains: api.example.com has 3 events, 2 endpoints, 3 allowed.
	var apiDom *topDomain
	for i := range resp.TopDomains {
		if resp.TopDomains[i].Domain == "api.example.com" {
			apiDom = &resp.TopDomains[i]
		}
	}
	if apiDom == nil {
		t.Fatal("api.example.com missing from topDomains")
	}
	if apiDom.Count != 3 || apiDom.Endpoints != 2 || apiDom.Allowed != 3 || apiDom.Denied != 0 {
		t.Fatalf("unexpected api.example.com agg: %+v", *apiDom)
	}

	// Secrets: one ref injected once, to api.example.com only; no raw value present.
	if len(resp.Secrets) != 1 {
		t.Fatalf("expected 1 secret usage, got %d", len(resp.Secrets))
	}
	if resp.Secrets[0].Ref != "openai_secret_001" || resp.Secrets[0].Count != 1 {
		t.Fatalf("unexpected secret usage: %+v", resp.Secrets[0])
	}
	if len(resp.Secrets[0].Domains) != 1 || resp.Secrets[0].Domains[0] != "api.example.com" {
		t.Fatalf("unexpected secret domains: %+v", resp.Secrets[0].Domains)
	}

	// Judge: only the two non-empty reasons, most-recent first.
	if len(resp.Judge) != 2 {
		t.Fatalf("expected 2 judge entries, got %d", len(resp.Judge))
	}
	if resp.Judge[0].Time < resp.Judge[1].Time {
		t.Fatalf("judge entries not most-recent-first: %+v", resp.Judge)
	}
	for _, j := range resp.Judge {
		if j.Reason == "" {
			t.Fatal("judge entry with empty reason leaked in")
		}
	}

	// Writes: non-GET endpoints only.
	if len(resp.Writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(resp.Writes))
	}
	for _, wEntry := range resp.Writes {
		if wEntry.Method == "GET" || wEntry.Method == "HEAD" {
			t.Fatalf("write entry has read method: %+v", wEntry)
		}
	}

	// Blocked grouped by domain: only evil.com (2 denies).
	if len(resp.Blocked) != 1 || resp.Blocked[0].Domain != "evil.com" || resp.Blocked[0].Count != 2 {
		t.Fatalf("unexpected blocked: %+v", resp.Blocked)
	}
}

func TestAnalyticsJudgeCap(t *testing.T) {
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	var evs []analytics.Event
	for i := 0; i < 25; i++ {
		evs = append(evs, analytics.Event{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			Domain:    "x.com", Method: "GET", URL: "https://x.com/p", Decision: "deny",
			JudgeReason: fmt.Sprintf("reason %d", i),
		})
	}
	ds := &fakeDataSource{events: evs}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/analytics")
	var resp analyticsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Judge) != 20 {
		t.Fatalf("expected judge capped at 20, got %d", len(resp.Judge))
	}
	// Most recent (reason 24) must be first.
	if resp.Judge[0].Reason != "reason 24" {
		t.Fatalf("expected newest judge first, got %q", resp.Judge[0].Reason)
	}
}

func TestAnalyticsEmpty(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	rr := doGet(t, handler, "/dashboard/api/analytics")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// Arrays must be [] not null in the raw JSON.
	body := rr.Body.String()
	for _, field := range []string{`"methods":[]`, `"protocols":[]`, `"timeline":[]`, `"topDomains":[]`,
		`"topEndpoints":[]`, `"blocked":[]`, `"secrets":[]`, `"judge":[]`, `"writes":[]`} {
		if !strings.Contains(body, field) {
			t.Fatalf("expected %s in empty response, body: %s", field, body)
		}
	}
	var resp analyticsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Totals.Requests != 0 {
		t.Fatalf("expected 0 requests, got %d", resp.Totals.Requests)
	}
	if len(resp.Hourly) != 24 {
		t.Fatalf("expected 24 hourly entries even when empty, got %d", len(resp.Hourly))
	}
}

func TestAnalyticsMethodNotAllowed(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/analytics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestAnalyticsRangeFilter(t *testing.T) {
	now := time.Now()
	ds := &fakeDataSource{
		events: []analytics.Event{
			// Old events (~48h ago): excluded by any finite window we test.
			{Timestamp: now.Add(-48 * time.Hour), Domain: "old.example.com", Protocol: "https", Method: "GET", URL: "https://old.example.com/a", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(-47 * time.Hour), Domain: "old.example.com", Protocol: "https", Method: "POST", URL: "https://old.example.com/b", Decision: "deny", ResponseStatus: 403},
			// Recent events (~1m ago): inside a 1h window.
			{Timestamp: now.Add(-1 * time.Minute), Domain: "recent.example.com", Protocol: "https", Method: "GET", URL: "https://recent.example.com/x", Decision: "allow", ResponseStatus: 200},
			{Timestamp: now.Add(-2 * time.Minute), Domain: "recent.example.com", Protocol: "https", Method: "GET", URL: "https://recent.example.com/y", Decision: "deny", ResponseStatus: 403},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	get := func(t *testing.T, path string) analyticsResponse {
		t.Helper()
		rr := doGet(t, handler, path)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		var resp analyticsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return resp
	}

	t.Run("finite range excludes old events", func(t *testing.T) {
		resp := get(t, "/dashboard/api/analytics?range=1h")
		if resp.Totals.Requests != 2 {
			t.Fatalf("expected 2 in-window requests, got %d", resp.Totals.Requests)
		}
		for _, d := range resp.TopDomains {
			if d.Domain == "old.example.com" {
				t.Fatalf("old.example.com should be filtered out of topDomains: %+v", resp.TopDomains)
			}
		}
		// Timeline buckets across the fixed window: up to 30, tally == in-window count.
		if len(resp.Timeline) > 30 {
			t.Fatalf("expected at most 30 timeline buckets, got %d", len(resp.Timeline))
		}
		var allow, deny int
		for _, b := range resp.Timeline {
			allow += b.Allow
			deny += b.Deny
		}
		if allow+deny != resp.Totals.Requests {
			t.Fatalf("timeline tally %d != in-window requests %d", allow+deny, resp.Totals.Requests)
		}
	})

	t.Run("range=all includes everything", func(t *testing.T) {
		resp := get(t, "/dashboard/api/analytics?range=all")
		if resp.Totals.Requests != 4 {
			t.Fatalf("expected 4 requests for range=all, got %d", resp.Totals.Requests)
		}
	})

	t.Run("missing range includes everything", func(t *testing.T) {
		resp := get(t, "/dashboard/api/analytics")
		if resp.Totals.Requests != 4 {
			t.Fatalf("expected 4 requests with no range, got %d", resp.Totals.Requests)
		}
	})

	t.Run("bogus range behaves like all", func(t *testing.T) {
		resp := get(t, "/dashboard/api/analytics?range=bogus")
		if resp.Totals.Requests != 4 {
			t.Fatalf("expected 4 requests for bogus range, got %d", resp.Totals.Requests)
		}
	})
}

func TestEndpointsRangeFilter(t *testing.T) {
	now := time.Now()
	ds := &fakeDataSource{
		events: []analytics.Event{
			// Old endpoint group (~48h ago).
			{Timestamp: now.Add(-48 * time.Hour), Domain: "a.com", Method: "GET", URL: "https://a.com/old", Decision: "allow", ResponseStatus: 200},
			// Recent endpoint group (~1m ago).
			{Timestamp: now.Add(-1 * time.Minute), Domain: "a.com", Method: "GET", URL: "https://a.com/new", Decision: "allow", ResponseStatus: 200},
		},
	}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	t.Run("finite range excludes old endpoint", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?range=1h")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Total != 1 {
			t.Fatalf("expected 1 endpoint group in 1h window, got %d", resp.Total)
		}
		for _, it := range resp.Items {
			if it.URL == "https://a.com/old" {
				t.Fatalf("old endpoint should be filtered out: %+v", resp.Items)
			}
		}
	})

	t.Run("range=all includes both", func(t *testing.T) {
		rr := doGet(t, handler, "/dashboard/api/endpoints?range=all")
		var resp endpointsResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Total != 2 {
			t.Fatalf("expected 2 endpoint groups for range=all, got %d", resp.Total)
		}
	})
}

func TestMethodNotAllowed(t *testing.T) {
	handler := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	endpoints := []string{
		"/dashboard/api/traffic",
		"/dashboard/api/policy",
		"/dashboard/api/secrets",
		"/dashboard/api/blocked",
		"/dashboard/api/endpoints",
		"/dashboard/api/stats",
		"/dashboard/api/analytics",
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

// fakeMCPProvider is a content-free stand-in for the MCP gateway view.
type fakeMCPProvider struct {
	inv  []gateway.InventoryItem
	snap map[string]mcp.ToolProfileView
}

func (f *fakeMCPProvider) Inventory() []gateway.InventoryItem             { return f.inv }
func (f *fakeMCPProvider) SchemaSnapshot() map[string]mcp.ToolProfileView { return f.snap }

func mcpKey(tool string, dir mcp.Direction) string {
	return tool + "\x00" + string(dir)
}

func TestMCPEndpoint(t *testing.T) {
	now := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Protocol: "mcp", Tool: "read_file", Decision: "allow"},
		{Timestamp: now.Add(time.Second), Protocol: "mcp", Tool: "read_file", Decision: "allow"},
		{Timestamp: now.Add(2 * time.Second), Protocol: "mcp", Tool: "read_file", Decision: "allow"},
		{Timestamp: now.Add(3 * time.Second), Protocol: "mcp", Tool: "exec_cmd", Decision: "deny", Reason: "mcp_tool_denied"},
		{Timestamp: now.Add(4 * time.Second), Protocol: "mcp", Tool: "exec_cmd", Decision: "deny", Reason: "mcp_tool_denied"},
		// A non-mcp event must be ignored by the mcp view.
		{Timestamp: now, Protocol: "https", Method: "GET", Decision: "allow"},
	}}

	prov := &fakeMCPProvider{
		inv: []gateway.InventoryItem{
			{Name: "read_file", HasDescription: true, InputSchemaHash: "h1", FirstSeen: now, LastSeen: now},
			{Name: "exec_cmd", HasDescription: true, InputSchemaHash: "h2", FirstSeen: now, LastSeen: now},
			{Name: "upload", HasDescription: false, InputSchemaHash: "h3", FirstSeen: now, LastSeen: now},
		},
		snap: map[string]mcp.ToolProfileView{
			mcpKey("read_file", mcp.DirRequest): {Fields: map[string]mcp.FieldProfileView{
				"params.path": {Types: []string{"string"}, SeenCount: 3},
			}},
			mcpKey("read_file", mcp.DirResponse): {Fields: map[string]mcp.FieldProfileView{
				"result.email": {Types: []string{"string"}, SeenCount: 3, Sensitivity: []string{"pii"}},
			}},
		},
	}

	srv := NewServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetMCPProvider(prov)
	handler := srv.Handler()

	rr := doGet(t, handler, "/dashboard/api/mcp")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp mcpResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected enabled=true")
	}

	byTool := map[string]mcpToolView{}
	for _, v := range resp.Tools {
		byTool[v.Tool] = v
	}

	rf, ok := byTool["read_file"]
	if !ok {
		t.Fatalf("read_file missing")
	}
	if rf.Calls != 3 || rf.Allowed != 3 || rf.Denied != 0 {
		t.Fatalf("read_file want calls=3 allowed=3 denied=0, got %d/%d/%d", rf.Calls, rf.Allowed, rf.Denied)
	}
	if !rf.Present {
		t.Fatalf("read_file should be present in inventory")
	}
	resField, ok := rf.ResponseSchema["result.email"]
	if !ok {
		t.Fatalf("read_file responseSchema missing result.email: %+v", rf.ResponseSchema)
	}
	if len(resField.Sensitivity) != 1 || resField.Sensitivity[0] != "pii" {
		t.Fatalf("result.email sensitivity want [pii], got %v", resField.Sensitivity)
	}
	if !containsStr(rf.Sensitive, "pii") {
		t.Fatalf("read_file tool-level sensitive should include pii, got %v", rf.Sensitive)
	}
	if _, ok := rf.RequestSchema["params.path"]; !ok {
		t.Fatalf("read_file requestSchema missing params.path: %+v", rf.RequestSchema)
	}

	ec, ok := byTool["exec_cmd"]
	if !ok {
		t.Fatalf("exec_cmd missing")
	}
	if ec.Denied != 2 {
		t.Fatalf("exec_cmd want denied=2, got %d", ec.Denied)
	}
	if !containsStr(ec.Findings, "mcp_tool_denied") {
		t.Fatalf("exec_cmd findings want mcp_tool_denied, got %v", ec.Findings)
	}

	up, ok := byTool["upload"]
	if !ok {
		t.Fatalf("upload (present-but-uncalled) missing")
	}
	if up.Calls != 0 || !up.Present {
		t.Fatalf("upload want present, calls=0; got present=%v calls=%d", up.Present, up.Calls)
	}
}

func TestMCPEndpointNilProvider(t *testing.T) {
	ds := &fakeDataSource{}
	handler := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	rr := doGet(t, handler, "/dashboard/api/mcp")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp mcpResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Enabled {
		t.Fatalf("expected enabled=false with nil provider")
	}
	if len(resp.Tools) != 0 {
		t.Fatalf("expected 0 tools with nil provider and no events, got %d", len(resp.Tools))
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
