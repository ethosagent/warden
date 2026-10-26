package dashboard

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

func userEvents() []analytics.Event {
	now := time.Now().UTC()
	return []analytics.Event{
		{Timestamp: now, Domain: "a.example", Method: "GET", Decision: "allow", Protocol: "https", UserSub: "sub-alice", UserEmail: "alice@corp"},
		{Timestamp: now.Add(time.Second), Domain: "b.example", Method: "GET", Decision: "deny", Protocol: "https", UserSub: "sub-alice", UserEmail: "alice@corp"},
		{Timestamp: now.Add(2 * time.Second), Domain: "c.example", Method: "POST", Decision: "allow", Protocol: "https", UserSub: "sub-bob", UserEmail: "bob@corp"},
	}
}

// userDataSources returns the worker (local SQLite) and CP (fleet SQLite) data
// sources, each seeded with userEvents.
func userDataSources(t *testing.T) map[string]DataSource {
	t.Helper()
	local, err := analytics.NewSQLiteStore(":memory:", 0)
	if err != nil {
		t.Fatalf("local store: %v", err)
	}
	t.Cleanup(func() { _ = local.Close() })
	fleet, err := analytics.NewFleetSQLiteStore(":memory:", 0, 0)
	if err != nil {
		t.Fatalf("fleet store: %v", err)
	}
	t.Cleanup(func() { _ = fleet.Close() })
	for _, e := range userEvents() {
		if err := local.StoreEvent(e); err != nil {
			t.Fatal(err)
		}
		if err := fleet.StoreAggregatedEvent(analytics.AggregatedEvent{Event: e, ProxyID: "w1"}); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]DataSource{"worker": local, "cp": fleet}
}

func trafficDomains(t *testing.T, h http.Handler, query string) []string {
	t.Helper()
	rr := doGet(t, h, "/dashboard/api/traffic"+query)
	if rr.Code != http.StatusOK {
		t.Fatalf("traffic%s: status %d (%s)", query, rr.Code, rr.Body.String())
	}
	var evs []analytics.Event
	if err := json.Unmarshal(rr.Body.Bytes(), &evs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Domain)
	}
	return out
}

func TestTrafficUserFilter(t *testing.T) {
	for name, ds := range userDataSources(t) {
		t.Run(name, func(t *testing.T) {
			h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
			byEmail := trafficDomains(t, h, "?user=Alice@Corp")
			bySub := trafficDomains(t, h, "?user=sub-alice")
			padded := trafficDomains(t, h, "?user="+url.QueryEscape("  alice@corp  "))
			want := []string{"b.example", "a.example"} // newest first
			for label, got := range map[string][]string{"email": byEmail, "sub": bySub, "trimmed": padded} {
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Errorf("%s: got %v, want %v", label, got, want)
				}
			}
			if got := trafficDomains(t, h, "?user=nobody"); len(got) != 0 {
				t.Errorf("unknown user: got %v, want none", got)
			}
			// Without ?user the full set comes back, and an empty or blank
			// value behaves exactly like no parameter.
			if got := trafficDomains(t, h, ""); len(got) != 3 {
				t.Errorf("no user: got %v, want 3 events", got)
			}
			if got := trafficDomains(t, h, "?user=%20"); len(got) != 3 {
				t.Errorf("blank user: got %v, want 3 events", got)
			}
		})
	}
}

func analyticsTotal(t *testing.T, h http.Handler, query string) (int, []byte) {
	t.Helper()
	rr := doGet(t, h, "/dashboard/api/analytics"+query)
	if rr.Code != http.StatusOK {
		t.Fatalf("analytics%s: status %d (%s)", query, rr.Code, rr.Body.String())
	}
	var resp struct {
		Totals struct {
			Total int `json:"requests"`
		} `json:"totals"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp.Totals.Total, rr.Body.Bytes()
}

func TestAnalyticsUserCacheKey(t *testing.T) {
	ds := &fakeDataSource{events: []analytics.Event{
		{Timestamp: time.Now(), Domain: "a.example", Decision: "allow", UserEmail: "alice"},
		{Timestamp: time.Now(), Domain: "a.example", Decision: "allow", UserEmail: "alice"},
		{Timestamp: time.Now(), Domain: "b.example", Decision: "allow", UserEmail: "bob"},
	}}
	h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})

	// Same range, same instant (cache is hot): only the user differs.
	if n, _ := analyticsTotal(t, h, "?range=24h&user=alice"); n != 2 {
		t.Fatalf("alice total = %d, want 2", n)
	}
	if n, _ := analyticsTotal(t, h, "?range=24h&user=bob"); n != 1 {
		t.Fatalf("bob total = %d (served alice's cached figures?), want 1", n)
	}
	if n, _ := analyticsTotal(t, h, "?range=24h"); n != 3 {
		t.Fatalf("unfiltered total = %d, want 3", n)
	}
	// Surrounding whitespace normalizes to the same key and the same figures.
	if n, _ := analyticsTotal(t, h, "?range=24h&user=%20alice%20"); n != 2 {
		t.Fatalf("padded alice total = %d, want 2", n)
	}
}

// A blank user param must produce the byte-identical body of no param.
func TestAnalyticsNoUserUnchanged(t *testing.T) {
	ds := &fakeDataSource{events: userEvents()}
	a := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	b := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	_, withParam := analyticsTotal(t, a, "?range=24h&user=")
	_, without := analyticsTotal(t, b, "?range=24h")
	// generatedAt differs only if the clock ticked between calls.
	strip := func(b []byte) string {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		delete(m, "generatedAt")
		out, _ := json.Marshal(m)
		return string(out)
	}
	if strip(withParam) != strip(without) {
		t.Fatalf("blank user changed the analytics body")
	}
}

func TestUserParamBound(t *testing.T) {
	h := newTestServer(&fakeDataSource{events: userEvents()}, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
	for _, path := range []string{"/dashboard/api/traffic", "/dashboard/api/analytics"} {
		ok := doGet(t, h, path+"?user="+strings.Repeat("a", 320))
		if ok.Code != http.StatusOK {
			t.Errorf("%s: 320 chars: status %d, want 200", path, ok.Code)
		}
		long := doGet(t, h, path+"?user="+strings.Repeat("a", 321))
		if long.Code != http.StatusBadRequest {
			t.Errorf("%s: 321 chars: status %d, want 400", path, long.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(long.Body.Bytes(), &body); err != nil || body["error"] == "" {
			t.Errorf("%s: 400 body = %q, want {\"error\":...}", path, long.Body.String())
		}
		// Whitespace is trimmed before the bound applies.
		padded := doGet(t, h, path+"?user="+strings.Repeat("a", 320)+strings.Repeat("%20", 10))
		if padded.Code != http.StatusOK {
			t.Errorf("%s: padded 320 chars: status %d, want 200", path, padded.Code)
		}
	}
}

func TestTrafficUserFilterInjectionIsLiteral(t *testing.T) {
	for name, ds := range userDataSources(t) {
		h := newTestServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
		if got := trafficDomains(t, h, "?user="+url.QueryEscape("x' OR '1'='1")); len(got) != 0 {
			t.Errorf("%s: injection matched %v, want none", name, got)
		}
	}
}

func TestQueryBuilderUserColumns(t *testing.T) {
	for name, ds := range userDataSources(t) {
		t.Run(name, func(t *testing.T) {
			srv := NewServer(ds, config.Policy{}, &fakeSecretProvider{values: map[string]string{}})
			srv.SetWriteGuard(AllowUngatedWritesForTests)
			srv.SetQueryEngine(ds.(analytics.AnalyticsQuery))
			h := srv.Handler()

			rr := doGet(t, h, "/dashboard/api/query/schema")
			if rr.Code != http.StatusOK {
				t.Fatalf("schema: status %d", rr.Code)
			}
			var schema analytics.SchemaInfo
			if err := json.Unmarshal(rr.Body.Bytes(), &schema); err != nil {
				t.Fatal(err)
			}
			cols := map[string]bool{}
			for _, tb := range schema.Tables {
				for _, c := range tb.Columns {
					cols[c.Name] = true
				}
			}
			if !cols["user_sub"] || !cols["user_email"] {
				t.Errorf("schema lacks user columns: %v", cols)
			}

			rr = doPost(t, h, "/dashboard/api/query", `{"sql":"SELECT user_sub, count(*) FROM events GROUP BY user_sub","maxRows":10}`)
			if rr.Code != http.StatusOK {
				t.Fatalf("query: status %d (%s)", rr.Code, rr.Body.String())
			}
			var res analytics.QueryResult
			if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
				t.Fatal(err)
			}
			if len(res.Rows) != 2 {
				t.Errorf("rows = %v, want 2 groups (alice, bob)", res.Rows)
			}
		})
	}
}
