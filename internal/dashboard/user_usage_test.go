package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

var usageNow = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

type usageBody struct {
	Window string `json:"window"`
	From   string `json:"from"`
	To     string `json:"to"`
	Users  []struct {
		Sub          string           `json:"sub"`
		Email        string           `json:"email"`
		Requests     int64            `json:"requests"`
		Denies       map[string]int64 `json:"denies"`
		CostUSD      float64          `json:"costUSD"`
		TodayCostUSD float64          `json:"todayCostUSD"`
		TopAgents    []struct {
			AgentID  string  `json:"agentID"`
			Requests int64   `json:"requests"`
			CostUSD  float64 `json:"costUSD"`
		} `json:"topAgents"`
		LimitRule   string  `json:"limitRule"`
		CapUSD      float64 `json:"capUSD"`
		AtLimit     bool    `json:"atLimit"`
		CostBlocked bool    `json:"costBlocked"`
	} `json:"users"`
	Unattributed struct {
		Requests int64   `json:"requests"`
		CostUSD  float64 `json:"costUSD"`
	} `json:"unattributed"`
	CostBlocks *CostBlockStatus `json:"costBlocks"`
}

// usageEnv is a dashboard over a real local SQLiteStore (the standalone
// worker's UserUsageQuerier) holding the ticket's fixture: alice 5 allow and
// 2 user_rate_limited denies ($1.25) under rule eng, bob 1 allow, 3 anonymous.
type usageEnv struct {
	t     *testing.T
	store *analytics.SQLiteStore
	srv   *Server
	h     http.Handler
}

func newUsageEnv(t *testing.T, pol config.Policy) *usageEnv {
	t.Helper()
	store, err := analytics.NewSQLiteStore("file:"+filepath.Join(t.TempDir(), "warden.db"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	srv := NewServer(store, pol, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	clock := usageNow
	srv.now = func() time.Time { return clock }
	e := &usageEnv{t: t, store: store, srv: srv, h: srv.Handler()}
	var evs []analytics.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, analytics.Event{Timestamp: usageNow.Add(-time.Hour), Domain: "api.openai.com", Decision: "allow",
			UserSub: "alice", UserEmail: "alice@corp.example", AgentID: "a1", LimitRule: "eng", CostUSD: 0.25})
	}
	for i := 0; i < 2; i++ {
		evs = append(evs, analytics.Event{Timestamp: usageNow.Add(-time.Hour), Domain: "api.openai.com", Decision: "deny",
			Reason: "user_rate_limited", UserSub: "alice", UserEmail: "alice@corp.example", AgentID: "a1", LimitRule: "eng"})
	}
	evs = append(evs, analytics.Event{Timestamp: usageNow.Add(-time.Hour), Domain: "api.openai.com", Decision: "allow",
		UserSub: "bob", UserEmail: "bob@corp.example", AgentID: "a2"})
	for i := 0; i < 3; i++ {
		evs = append(evs, analytics.Event{Timestamp: usageNow.Add(-time.Hour), Domain: "api.openai.com", Decision: "allow",
			AgentID: "a1", LimitRule: analytics.AnonymousLimitRule})
	}
	if err := store.StoreEventsBatch(evs); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *usageEnv) get(query string) (*httptest.ResponseRecorder, usageBody) {
	e.t.Helper()
	rr := doGet(e.t, e.h, "/dashboard/api/usage/users"+query)
	var b usageBody
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			e.t.Fatalf("decode %s: %v", rr.Body.String(), err)
		}
	}
	return rr, b
}

func TestUserUsage_Totals(t *testing.T) {
	e := newUsageEnv(t, config.Policy{})
	rr, b := e.get("?window=7d")
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	if b.Window != "7d" || len(b.Users) != 2 {
		t.Fatalf("body = %s", rr.Body.String())
	}
	a := b.Users[0]
	if a.Sub != "alice" || a.Email != "alice@corp.example" || a.Requests != 7 || a.CostUSD != 1.25 ||
		len(a.Denies) != 1 || a.Denies["user_rate_limited"] != 2 || a.LimitRule != "eng" {
		t.Errorf("alice = %+v", a)
	}
	if len(a.TopAgents) != 1 || a.TopAgents[0].AgentID != "a1" || a.TopAgents[0].Requests != 7 {
		t.Errorf("alice agents = %+v", a.TopAgents)
	}
	if b.Users[1].Sub != "bob" || b.Users[1].Requests != 1 {
		t.Errorf("bob = %+v", b.Users[1])
	}
	if b.Unattributed.Requests != 3 {
		t.Errorf("unattributed = %+v", b.Unattributed)
	}
	if b.CostBlocks != nil {
		t.Errorf("costBlocks present without a status source: %+v", b.CostBlocks)
	}
	// Defaults are 7d and cost.
	if _, d := e.get(""); d.Window != "7d" || len(d.Users) != 2 {
		t.Errorf("default query = %+v", d)
	}
}

func TestUserUsage_InvalidParams(t *testing.T) {
	e := newUsageEnv(t, config.Policy{})
	for q, want := range map[string]string{
		"?window=1y":  "invalid_window",
		"?window=24H": "invalid_window",
		"?sort=name":  "invalid_sort",
		"?limit=0":    "invalid_limit",
		"?limit=501":  "invalid_limit",
		"?limit=abc":  "invalid_limit",
	} {
		rr, _ := e.get(q)
		if rr.Code != http.StatusBadRequest || strings.TrimSpace(rr.Body.String()) != `{"error":"`+want+`"}` {
			t.Errorf("%s = %d %s, want 400 %s", q, rr.Code, rr.Body.String(), want)
		}
	}
	for _, q := range []string{"?window=24h", "?window=30d&sort=requests&limit=500", "?limit=1"} {
		if rr, _ := e.get(q); rr.Code != http.StatusOK {
			t.Errorf("%s = %d %s, want 200", q, rr.Code, rr.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/usage/users", nil)
	rr := httptest.NewRecorder()
	e.h.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rr.Code)
	}
}

func TestUserUsage_AtLimitAndCostBlocked(t *testing.T) {
	pol := config.Policy{
		UserLimits: []config.UserLimit{{Name: "eng", DailyCostUSD: 1.0}},
		CostBlockedUsers: []config.CostBlockedUser{
			{Sub: "bob", Rule: "eng", Day: "2026-11-27"},
			{Sub: "alice", Rule: "eng", Day: "2026-11-26"}, // yesterday: ignored
		},
	}
	e := newUsageEnv(t, pol)
	_, b := e.get("")
	a, bob := b.Users[0], b.Users[1]
	if a.CapUSD != 1.0 || a.TodayCostUSD != 1.25 || !a.AtLimit {
		t.Errorf("alice = %+v, want cap 1 today 1.25 atLimit", a)
	}
	if a.CostBlocked {
		t.Error("a block from a past day must not count")
	}
	if !bob.CostBlocked || bob.AtLimit || bob.CapUSD != 0 {
		t.Errorf("bob = %+v, want costBlocked only", bob)
	}

	// Under the cap: no badge.
	pol.UserLimits[0].DailyCostUSD = 5
	e2 := newUsageEnv(t, pol)
	if _, b2 := e2.get(""); b2.Users[0].AtLimit {
		t.Errorf("alice under a $5 cap is atLimit: %+v", b2.Users[0])
	}
	// The served policy (SetUsagePolicy) wins over the startup one.
	e2.srv.SetUsagePolicy(func() config.Policy {
		return config.Policy{DefaultUserLimit: &config.UserLimit{DailyCostUSD: 2}}
	})
	e2.srv.userUsageCache = newRespCache()
	if _, b3 := e2.get(""); b3.Users[0].CapUSD != 0 {
		t.Errorf("rule eng no longer served, cap = %v", b3.Users[0].CapUSD)
	}
}

func TestUserUsage_SortLimitAndCache(t *testing.T) {
	e := newUsageEnv(t, config.Policy{})
	// bob has fewer requests and no cost: cost order alice, bob; request order the same. Give bob more requests.
	var more []analytics.Event
	for i := 0; i < 10; i++ {
		more = append(more, analytics.Event{Timestamp: usageNow.Add(-time.Hour), Domain: "d", Decision: "allow", UserSub: "bob", AgentID: "a2"})
	}
	if err := e.store.StoreEventsBatch(more); err != nil {
		t.Fatal(err)
	}
	if _, b := e.get("?sort=cost"); b.Users[0].Sub != "alice" {
		t.Errorf("sort=cost first = %s", b.Users[0].Sub)
	}
	_, b := e.get("?sort=requests&limit=1")
	if len(b.Users) != 1 || b.Users[0].Sub != "bob" || b.Users[0].Requests != 11 {
		t.Errorf("sort=requests limit=1 = %+v", b.Users)
	}

	// Cached 30s per (window, sort, limit); a fresh key and an expired entry recompute.
	if err := e.store.StoreEvent(analytics.Event{Timestamp: usageNow, Domain: "d", Decision: "allow", UserSub: "carol"}); err != nil {
		t.Fatal(err)
	}
	if _, c := e.get("?sort=requests&limit=1"); len(c.Users) != 1 || c.Users[0].Sub != "bob" {
		t.Errorf("cached read changed: %+v", c.Users)
	}
	if _, c := e.get("?sort=cost&limit=50"); len(c.Users) != 3 {
		t.Errorf("fresh key must see carol: %+v", c.Users)
	}
	adv := usageNow.Add(31 * time.Second)
	e.srv.now = func() time.Time { return adv }
	if _, c := e.get("?sort=cost"); len(c.Users) != 3 {
		t.Errorf("expired entry must recompute: %+v", c.Users)
	}
}

func TestUserUsage_CostBlockStatus(t *testing.T) {
	e := newUsageEnv(t, config.Policy{})
	e.srv.SetCostBlockStatus(func() CostBlockStatus { return CostBlockStatus{Enabled: false, Truncated: 3, RecomputeErrors: 2} })
	_, b := e.get("")
	if b.CostBlocks == nil || b.CostBlocks.Enabled || b.CostBlocks.Truncated != 3 || b.CostBlocks.RecomputeErrors != 2 {
		t.Errorf("costBlocks = %+v", b.CostBlocks)
	}
}

func TestUserUsage_Unavailable(t *testing.T) {
	h := newTestServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	rr := doGet(t, h, "/dashboard/api/usage/users")
	if rr.Code != http.StatusNotFound {
		t.Errorf("a data source with no usage query = %d, want 404", rr.Code)
	}
}

// An email holding markup crosses the wire as JSON-escaped text and the view
// builds every cell with textContent.
func TestUserUsage_EscapesEmail(t *testing.T) {
	e := newUsageEnv(t, config.Policy{})
	evil := `<script>alert(1)</script>@x.example`
	if err := e.store.StoreEvent(analytics.Event{Timestamp: usageNow, Domain: "d", Decision: "allow", UserSub: "mallory", UserEmail: evil}); err != nil {
		t.Fatal(err)
	}
	rr, b := e.get("")
	if strings.Contains(rr.Body.String(), "<script>") {
		t.Errorf("raw markup in the response: %s", rr.Body.String())
	}
	found := false
	for _, u := range b.Users {
		found = found || u.Email == evil
	}
	if !found {
		t.Errorf("email did not round trip: %s", rr.Body.String())
	}

	page := doGet(t, e.h, "/dashboard/").Body.String()
	start := strings.Index(page, "function renderUsage(")
	end := strings.Index(page, "async function loadUsage(")
	if start < 0 || end < start {
		t.Fatal("renderUsage not found in the served dashboard")
	}
	fn := page[start:end]
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML"} {
		if strings.Contains(fn, bad) {
			t.Errorf("renderUsage uses %s", bad)
		}
	}
	if !strings.Contains(fn, "textContent") || !strings.Contains(fn, "drillToUser") {
		t.Error("renderUsage must use textContent and offer the drill-down")
	}
}

// The fleet JSON carries noUserLimits and the served dashboard renders the
// "do not enforce user limits" warning from it.
func TestUserUsage_FleetWarning(t *testing.T) {
	srv := NewServer(&fakeDataSource{}, config.Policy{}, emptyProvider())
	srv.SetWriteGuard(AllowUngatedWritesForTests)
	srv.SetWorkers(func() []WorkerView {
		return []WorkerView{{ProxyID: "old", NoUserLimits: true}, {ProxyID: "new"}}
	})
	var rows []map[string]any
	rr := doGet(t, srv.Handler(), "/dashboard/api/workers")
	if err := json.Unmarshal(rr.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0]["noUserLimits"] != true || rows[1]["noUserLimits"] != false {
		t.Fatalf("fleet JSON = %s", rr.Body.String())
	}
	page := doGet(t, srv.Handler(), "/dashboard/").Body.String()
	for _, want := range []string{`id="fleet-userlimits-banner"`, "w.online&&w.noUserLimits", "do not enforce user limits", `data-page="usage"`, "/dashboard/api/usage/users"} {
		if !strings.Contains(page, want) {
			t.Errorf("served dashboard lacks %q", want)
		}
	}
}
