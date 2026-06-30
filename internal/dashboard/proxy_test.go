package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func doGetJSON(t *testing.T, h http.Handler, path string, into any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d", path, rec.Code)
	}
	if err := json.NewDecoder(rec.Body).Decode(into); err != nil {
		t.Fatalf("%s: decode: %v", path, err)
	}
}

// TestAnalyticsProxyBreakdownAndFilter covers the fleet per-worker view: the
// proxies breakdown lists every worker, and ?proxy= narrows the rest of the
// dashboard to one worker while the selector still lists all of them.
func TestAnalyticsProxyBreakdownAndFilter(t *testing.T) {
	now := time.Now()
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: now, Domain: "a.com", Decision: "allow", Protocol: "https", ProxyID: "worker-1"},
		{Timestamp: now, Domain: "b.com", Decision: "deny", Protocol: "https", ProxyID: "worker-1"},
		{Timestamp: now, Domain: "c.com", Decision: "allow", Protocol: "https", ProxyID: "worker-2"},
	}}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	var full analyticsResponse
	doGetJSON(t, h, "/dashboard/api/analytics", &full)
	if len(full.Proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(full.Proxies))
	}
	if full.Proxies[0].ProxyID != "worker-1" || full.Proxies[0].Count != 2 {
		t.Errorf("top proxy = %+v, want worker-1 count 2", full.Proxies[0])
	}
	if full.Totals.Requests != 3 {
		t.Errorf("fleet requests = %d, want 3", full.Totals.Requests)
	}

	var filtered analyticsResponse
	doGetJSON(t, h, "/dashboard/api/analytics?proxy=worker-1", &filtered)
	if filtered.SelectedProxy != "worker-1" {
		t.Errorf("selectedProxy = %q, want worker-1", filtered.SelectedProxy)
	}
	if filtered.Totals.Requests != 2 {
		t.Errorf("worker-1 requests = %d, want 2", filtered.Totals.Requests)
	}
	if len(filtered.Proxies) != 2 {
		t.Errorf("selector should still list all workers, got %d", len(filtered.Proxies))
	}
}

// TestSingleNodeHasNoProxies verifies a worker dashboard (no proxy ids) reports
// an empty proxies list, so the UI hides the selector.
func TestSingleNodeHasNoProxies(t *testing.T) {
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: time.Now(), Domain: "a.com", Decision: "allow", Protocol: "https"},
	}}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	var resp analyticsResponse
	doGetJSON(t, h, "/dashboard/api/analytics", &resp)
	if len(resp.Proxies) != 0 {
		t.Fatalf("single-node proxies = %d, want 0", len(resp.Proxies))
	}
}

// TestLivePolicyPanel verifies the policy panel reflects the live policy
// provider (hot-reloaded), not the static startup snapshot.
func TestLivePolicyPanel(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "static.example.com"}},
	}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetLivePolicy(func() config.Policy {
		return config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "live.example.com"}}}
	})

	var pol policyResponse
	doGetJSON(t, srv.Handler(), "/dashboard/api/policy", &pol)
	if len(pol.Allowlist) != 1 || pol.Allowlist[0].Domain != "live.example.com" {
		t.Fatalf("policy panel = %+v, want live.example.com (live, not static snapshot)", pol.Allowlist)
	}
}
