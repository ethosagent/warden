package dashboard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func doPost(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// queryTestServer builds a dashboard whose query engine is a real in-memory
// fleet SQLite store seeded with one event.
func queryTestServer(t *testing.T) http.Handler {
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
	srv.SetQueryEngine(store)
	return srv.Handler()
}

// TestQueryEndpoints_Unavailable: with no query engine (default), both query
// endpoints report 404 (Query Builder unavailable).
func TestQueryEndpoints_Unavailable(t *testing.T) {
	h := newTestServer(&fakeDataSource{}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	if rr := doGet(t, h, "/dashboard/api/query/schema"); rr.Code != http.StatusNotFound {
		t.Fatalf("schema: want 404 without engine, got %d", rr.Code)
	}
	if rr := doPost(t, h, "/dashboard/api/query", `{"sql":"SELECT 1"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("query: want 404 without engine, got %d", rr.Code)
	}
}

// TestQuerySchemaEndpoint: the schema endpoint reports the sqlite dialect and the
// events table.
func TestQuerySchemaEndpoint(t *testing.T) {
	h := queryTestServer(t)
	rr := doGet(t, h, "/dashboard/api/query/schema")
	if rr.Code != http.StatusOK {
		t.Fatalf("schema: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var got analytics.SchemaInfo
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode schema: %v", err)
	}
	if got.Dialect != "sqlite" {
		t.Fatalf("dialect = %q, want sqlite", got.Dialect)
	}
	found := false
	for _, tb := range got.Tables {
		if tb.Name == "events" && len(tb.Columns) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema missing events table with columns: %+v", got.Tables)
	}
}

// TestQueryEndpoint_SelectAndReject: a read-only SELECT returns rows; a mutating
// statement is rejected with 400 (the read-only sandbox).
func TestQueryEndpoint_SelectAndReject(t *testing.T) {
	h := queryTestServer(t)

	rr := doPost(t, h, "/dashboard/api/query", `{"sql":"SELECT domain, decision FROM events","maxRows":10}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("select: want 200, got %d (%s)", rr.Code, rr.Body.String())
	}
	var res analytics.QueryResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(res.Columns) != 2 || len(res.Rows) != 1 {
		t.Fatalf("unexpected result: cols=%v rows=%v", res.Columns, res.Rows)
	}

	// A mutating statement must be rejected (client error) — the read-only guard.
	rr = doPost(t, h, "/dashboard/api/query", `{"sql":"DELETE FROM events"}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("delete: want 400 (rejected), got %d (%s)", rr.Code, rr.Body.String())
	}
}
