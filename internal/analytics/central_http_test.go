package analytics

import (
	"net/http/httptest"
	"testing"
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
