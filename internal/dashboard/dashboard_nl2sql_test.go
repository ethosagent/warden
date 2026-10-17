package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

// fakeSQLGen is a scripted SQLGenerator: it returns out/err verbatim and records
// the prompt it was handed so a test can assert the schema was included.
type fakeSQLGen struct {
	out       string
	err       error
	gotPrompt string
	callCount int
}

func (f *fakeSQLGen) Evaluate(prompt string) (string, error) {
	f.gotPrompt = prompt
	f.callCount++
	return f.out, f.err
}

// nl2sqlServer builds a dashboard backed by a real in-memory fleet SQLite store
// (so queryEngine is non-nil) and, unless gen is nil, the given fake generator.
func nl2sqlServer(t *testing.T, gen SQLGenerator) *Server {
	t.Helper()
	store, err := analytics.NewFleetSQLiteStore(":memory:", 0, 0)
	if err != nil {
		t.Fatalf("new fleet store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.StoreAggregatedEvent(analytics.AggregatedEvent{
		Event:   analytics.Event{Timestamp: time.Now(), Domain: "api.example.com", Decision: "allow"},
		ProxyID: "worker-1",
	}); err != nil {
		t.Fatalf("store event: %v", err)
	}
	srv := NewServer(store, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetQueryEngine(store)
	if gen != nil {
		srv.SetSQLGenerator(gen)
	}
	return srv
}

// (a) nil generator → 409 llm_not_configured.
func TestQueryGenerate_NotConfigured(t *testing.T) {
	h := nl2sqlServer(t, nil).Handler()
	rr := doPost(t, h, "/dashboard/api/query/generate", `{"question":"top domains"}`)
	if rr.Code != http.StatusConflict {
		t.Fatalf("want 409, got %d (%s)", rr.Code, rr.Body.String())
	}
	var d map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d["error"] != "llm_not_configured" {
		t.Fatalf("error = %q, want llm_not_configured", d["error"])
	}
	if d["message"] == "" {
		t.Fatalf("expected a human message")
	}
}

// (b) fake returning a fenced SELECT → 200 with the cleaned SELECT, and the prompt
// carried the real schema.
func TestQueryGenerate_FencedSelect(t *testing.T) {
	gen := &fakeSQLGen{out: "```sql\nSELECT domain, count(*) AS n FROM events GROUP BY domain\n```"}
	h := nl2sqlServer(t, gen).Handler()
	rr := doPost(t, h, "/dashboard/api/query/generate", `{"question":"top domains"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var d map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := "SELECT domain, count(*) AS n FROM events GROUP BY domain"
	if d["sql"] != want {
		t.Fatalf("sql = %q, want %q", d["sql"], want)
	}
	// The prompt must be grounded on the real schema (the events table).
	if gen.callCount != 1 {
		t.Fatalf("Evaluate called %d times, want 1", gen.callCount)
	}
	if !strings.Contains(gen.gotPrompt, "events") {
		t.Fatalf("prompt missing schema table \"events\": %q", gen.gotPrompt)
	}
}

// (c) fake returning a mutating statement → 422 not_readonly.
func TestQueryGenerate_NotReadOnly(t *testing.T) {
	gen := &fakeSQLGen{out: "DELETE FROM events"}
	h := nl2sqlServer(t, gen).Handler()
	rr := doPost(t, h, "/dashboard/api/query/generate", `{"question":"delete everything"}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("want 422, got %d (%s)", rr.Code, rr.Body.String())
	}
	var d map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["error"] != "not_readonly" {
		t.Fatalf("error = %q, want not_readonly", d["error"])
	}
}

// (d) non-POST → 405.
func TestQueryGenerate_MethodNotAllowed(t *testing.T) {
	h := nl2sqlServer(t, &fakeSQLGen{out: "SELECT 1"}).Handler()
	if rr := doGet(t, h, "/dashboard/api/query/generate"); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", rr.Code)
	}
}

// (e) nil queryEngine → 404 (mirrors handleQuerySchema); checked before the
// generator so a node without a query builder is uniformly unavailable.
func TestQueryGenerate_NoQueryEngine(t *testing.T) {
	// A server with a generator but no query engine still 404s.
	srv := NewServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetSQLGenerator(&fakeSQLGen{out: "SELECT 1"})
	rr := doPost(t, srv.Handler(), "/dashboard/api/query/generate", `{"question":"x"}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// (g) WORKER wiring: with the LOCAL SQLite store as the query engine (what
// worker.go wires) plus a generator, generate reaches the LLM path and the
// prompt is grounded on the LOCAL schema (data_classes present, proxy_id not).
func TestQueryGenerate_LocalStoreEngine(t *testing.T) {
	store, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("new local store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(store, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetQueryEngine(store)
	gen := &fakeSQLGen{out: "SELECT domain FROM events"}
	srv.SetSQLGenerator(gen)

	rr := doPost(t, srv.Handler(), "/dashboard/api/query/generate", `{"question":"which domains"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(gen.gotPrompt, "data_classes") {
		t.Fatalf("prompt missing local column data_classes: %q", gen.gotPrompt)
	}
	if strings.Contains(gen.gotPrompt, "proxy_id") {
		t.Fatalf("prompt contains fleet-only column proxy_id: %q", gen.gotPrompt)
	}
}

// (f) blank question → 400.
func TestQueryGenerate_BlankQuestion(t *testing.T) {
	h := nl2sqlServer(t, &fakeSQLGen{out: "SELECT 1"}).Handler()
	rr := doPost(t, h, "/dashboard/api/query/generate", `{"question":"   "}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d (%s)", rr.Code, rr.Body.String())
	}
}

// A failing generator surfaces a bounded 502 llm_error.
func TestQueryGenerate_LLMError(t *testing.T) {
	gen := &fakeSQLGen{err: errFake}
	h := nl2sqlServer(t, gen).Handler()
	rr := doPost(t, h, "/dashboard/api/query/generate", `{"question":"top domains"}`)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("want 502, got %d (%s)", rr.Code, rr.Body.String())
	}
	var d map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &d)
	if d["error"] != "llm_error" {
		t.Fatalf("error = %q, want llm_error", d["error"])
	}
}

// extractReadOnlySQL unit coverage: fences, trailing semicolon, a rejected second
// statement, WITH prefix, and embedded write keywords.
func TestExtractReadOnlySQL(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		wantOK bool
		want   string
	}{
		{"plain select", "SELECT 1", true, "SELECT 1"},
		{"fenced sql", "```sql\nSELECT a FROM events\n```", true, "SELECT a FROM events"},
		{"fenced bare", "```\nSELECT a FROM events\n```", true, "SELECT a FROM events"},
		{"trailing semicolon", "SELECT a FROM events;", true, "SELECT a FROM events"},
		{"with cte", "WITH t AS (SELECT 1) SELECT * FROM t", true, "WITH t AS (SELECT 1) SELECT * FROM t"},
		{"second statement", "SELECT 1; DROP TABLE events", false, ""},
		{"delete", "DELETE FROM events", false, ""},
		{"embedded update", "SELECT * FROM events WHERE x=1; UPDATE events SET x=2", false, ""},
		{"not a select", "explain the schema", false, ""},
		{"empty", "   ", false, ""},
		{"column named created_at is fine", "SELECT created_at FROM events", true, "SELECT created_at FROM events"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := extractReadOnlySQL(c.in)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v (got %q)", ok, c.wantOK, got)
			}
			if ok && got != c.want {
				t.Fatalf("sql = %q, want %q", got, c.want)
			}
		})
	}
}

// errFake is a static error for the LLM-failure path.
var errFake = errStr("boom")

type errStr string

func (e errStr) Error() string { return string(e) }
