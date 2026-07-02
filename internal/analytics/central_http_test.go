package analytics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/mcp"
	"github.com/ethosagent/warden/internal/mcp/gateway"
)

// TestCentralIngestRoundTrip sends a batch from the worker-side HTTPRemoteStore
// to the aggregator-side IngestHandler and verifies the full event (including
// the new cost/compliance fields) and the proxy id survive the hop.
func TestCentralIngestRoundTrip(t *testing.T) {
	cs := NewCentralStore(0)
	srv := httptest.NewServer(NewIngestHandler(cs, "secret"))
	defer srv.Close()

	rs, err := NewHTTPRemoteStore(srv.URL, "secret", "proxy-1", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	in := []Event{{
		Domain: "api.openai.com", Port: 443, Protocol: "https",
		Method: "POST", Decision: "allow", ResponseStatus: 200,
		CostUSD: 0.0123, Provider: "openai",
		Compliance: []string{"mitre:T1071", "owasp:LLM06"},
	}}
	if err := rs.SendBatch(in); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}

	got, err := cs.GetAggregatedEvents(AggregatedFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("stored %d events, want 1", len(got))
	}
	e := got[0]
	if e.ProxyID != "proxy-1" {
		t.Errorf("ProxyID = %q, want proxy-1", e.ProxyID)
	}
	if e.Provider != "openai" || e.CostUSD != 0.0123 {
		t.Errorf("cost fields lost: provider=%q cost=%v", e.Provider, e.CostUSD)
	}
	if len(e.Compliance) != 2 || e.Compliance[0] != "mitre:T1071" {
		t.Errorf("compliance lost: %v", e.Compliance)
	}
}

// TestIngestOnEvents verifies SetOnEvents receives the posted events + proxy id,
// and that ServeHTTP is nil-safe when no onEvents callback is registered.
func TestIngestOnEvents(t *testing.T) {
	cs := NewCentralStore(0)
	h := NewIngestHandler(cs, "")
	var gotProxy string
	var gotEvents []Event
	h.SetOnEvents(func(proxyID string, events []Event) {
		gotProxy = proxyID
		gotEvents = events
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-9", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	in := []Event{
		{Domain: "evil.example.com", Decision: "block", Method: "POST"},
		{Domain: "api.openai.com", Decision: "allow"},
	}
	if err := rs.SendBatch(in); err != nil {
		t.Fatalf("SendBatch: %v", err)
	}
	if gotProxy != "proxy-9" {
		t.Errorf("onEvents proxyID = %q, want proxy-9", gotProxy)
	}
	if len(gotEvents) != 2 || gotEvents[0].Domain != "evil.example.com" {
		t.Fatalf("onEvents events = %+v, want the 2 posted events", gotEvents)
	}
}

func TestIngestOnEventsNilSafe(t *testing.T) {
	// No SetOnEvents call: a POST must still succeed (204), not panic on a nil fn.
	cs := NewCentralStore(0)
	srv := httptest.NewServer(NewIngestHandler(cs, ""))
	defer srv.Close()
	rs, err := NewHTTPRemoteStore(srv.URL, "", "p", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.SendBatch([]Event{{Domain: "x.com", Decision: "allow"}}); err != nil {
		t.Fatalf("SendBatch with no onEvents should succeed: %v", err)
	}
}

// TestIngestMCPSnapshot round-trips an MCP snapshot worker→CP and verifies it
// routes to the onMCP callback with the sender's proxy id (value-free schema).
func TestIngestMCPSnapshot(t *testing.T) {
	cs := NewCentralStore(0)
	h := NewIngestHandler(cs, "")
	var gotProxy string
	var gotSnap MCPSnapshot
	h.SetOnMCP(func(p string, s MCPSnapshot) { gotProxy, gotSnap = p, s })

	srv := httptest.NewServer(h)
	defer srv.Close()
	rs, err := NewHTTPRemoteStore(srv.URL, "", "worker-1", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	snap := MCPSnapshot{
		Inventory: []gateway.InventoryItem{{Name: "read_file", HasDescription: true}},
		Schema: map[string]mcp.ToolProfileView{
			"read_file\x00request": {Fields: map[string]mcp.FieldProfileView{
				"path": {Types: []string{"string"}, SeenCount: 3},
			}},
		},
	}
	if err := rs.SendMCP(snap); err != nil {
		t.Fatal(err)
	}
	if gotProxy != "worker-1" {
		t.Errorf("proxy = %q, want worker-1", gotProxy)
	}
	if len(gotSnap.Inventory) != 1 || gotSnap.Inventory[0].Name != "read_file" {
		t.Errorf("inventory not forwarded: %+v", gotSnap.Inventory)
	}
	if _, ok := gotSnap.Schema["read_file\x00request"]; !ok {
		t.Errorf("schema not forwarded: %+v", gotSnap.Schema)
	}
}

// TestIngestBareArrayBackCompat verifies the ingest endpoint still accepts a bare
// JSON array of events (pre-envelope wire format).
func TestIngestBareArrayBackCompat(t *testing.T) {
	cs := NewCentralStore(0)
	srv := httptest.NewServer(NewIngestHandler(cs, ""))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL,
		strings.NewReader(`[{"Domain":"a.com","Decision":"allow"}]`))
	req.Header.Set(ProxyIDHeader, "legacy")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("bare array status = %d, want 204", resp.StatusCode)
	}
	got, _ := cs.GetEvents(EventFilter{})
	if len(got) != 1 || got[0].Domain != "a.com" {
		t.Fatalf("bare array not ingested: %+v", got)
	}
}

// TestCentralStoreProxyFilter verifies GetEvents populates ProxyID on read and
// honors the ProxyID filter (the per-worker slicing the fleet dashboard needs).
func TestCentralStoreProxyFilter(t *testing.T) {
	cs := NewCentralStore(0)
	_ = cs.StoreAggregatedEvent(AggregatedEvent{Event: Event{Domain: "a.com", Decision: "allow"}, ProxyID: "w1"})
	_ = cs.StoreAggregatedEvent(AggregatedEvent{Event: Event{Domain: "b.com", Decision: "allow"}, ProxyID: "w2"})

	all, err := cs.GetEvents(EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("all = %d, want 2", len(all))
	}
	for _, e := range all {
		if e.ProxyID == "" {
			t.Error("GetEvents did not surface ProxyID on read")
		}
	}

	w1, err := cs.GetEvents(EventFilter{ProxyID: "w1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(w1) != 1 || w1[0].Domain != "a.com" || w1[0].ProxyID != "w1" {
		t.Fatalf("proxy filter failed: %+v", w1)
	}
}

// TestCentralIngestRejectsBadToken verifies the ingest endpoint enforces its
// bearer token (SendBatch surfaces the non-2xx as an error so the worker retries).
func TestCentralIngestRejectsBadToken(t *testing.T) {
	cs := NewCentralStore(0)
	srv := httptest.NewServer(NewIngestHandler(cs, "secret"))
	defer srv.Close()

	rs, err := NewHTTPRemoteStore(srv.URL, "wrong-token", "", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.SendBatch([]Event{{Domain: "x.com", Decision: "allow"}}); err == nil {
		t.Fatal("expected error from unauthorized ingest, got nil")
	}
	if got, _ := cs.GetEvents(EventFilter{}); len(got) != 0 {
		t.Fatalf("rejected batch should not be stored, got %d", len(got))
	}
}

// TestIngestOnIngestHook verifies the aggregator's per-batch callback fires with
// the sender's proxy id and batch size (the control plane uses it to track workers).
func TestIngestOnIngestHook(t *testing.T) {
	cs := NewCentralStore(0)
	h := NewIngestHandler(cs, "")
	var gotProxy string
	var gotN int
	h.SetOnIngest(func(p string, n int) { gotProxy, gotN = p, n })

	srv := httptest.NewServer(h)
	defer srv.Close()
	rs, err := NewHTTPRemoteStore(srv.URL, "", "worker-x", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.SendBatch([]Event{{Domain: "a.com"}, {Domain: "b.com"}}); err != nil {
		t.Fatal(err)
	}
	if gotProxy != "worker-x" || gotN != 2 {
		t.Fatalf("onIngest got (%q, %d), want (worker-x, 2)", gotProxy, gotN)
	}
}

// TestSQLiteCostComplianceRoundTrip ensures the new columns persist and decode.
func TestSQLiteCostComplianceRoundTrip(t *testing.T) {
	s, err := NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()

	in := Event{
		Domain: "api.openai.com", Port: 443, Protocol: "https",
		Method: "POST", URL: "https://api.openai.com/v1/chat", Decision: "allow",
		ResponseStatus: 200, CostUSD: 0.0123, Provider: "openai",
		Compliance: []string{"mitre:T1071", "owasp:LLM06"},
	}
	if err := s.StoreEvent(in); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	if got[0].CostUSD != 0.0123 || got[0].Provider != "openai" {
		t.Errorf("cost/provider lost: %+v", got[0])
	}
	if len(got[0].Compliance) != 2 || got[0].Compliance[1] != "owasp:LLM06" {
		t.Errorf("compliance lost: %v", got[0].Compliance)
	}
}
