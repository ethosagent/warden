package analytics

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// usageDayT is a fixed UTC instant used as "today" by the rollup tests.
var usageDayT = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

// usageStores returns a fresh FleetSQLiteStore and CentralStore, both with the
// rollup clock pinned to now, so every rollup behaviour is checked on both.
func usageStores(t *testing.T, maxEvents int, now time.Time) map[string]interface {
	FleetStore
	UserUsageQuerier
} {
	t.Helper()
	fs := newFleetStore(t, 0, maxEvents)
	fs.now = func() time.Time { return now }
	cs := NewCentralStore(maxEvents)
	cs.now = func() time.Time { return now }
	return map[string]interface {
		FleetStore
		UserUsageQuerier
	}{"sqlite": fs, "memory": cs}
}

func usageEvent(uid, sub, agent, rule string, ts time.Time, cost float64) Event {
	return Event{
		UID: uid, Timestamp: ts, Domain: "api.openai.com", Decision: "allow",
		UserSub: sub, UserEmail: sub + "@corp.example", AgentID: agent, LimitRule: rule, CostUSD: cost,
	}
}

func postIngest(t *testing.T, url string, events []Event) {
	t.Helper()
	body, err := json.Marshal(ingestEnvelope{Events: events})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set(ProxyIDHeader, "proxy-a")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("ingest status %d", resp.StatusCode)
	}
}

func usageAll(t *testing.T, q UserUsageQuerier) []UserUsage {
	t.Helper()
	got, err := q.UsageByUser(context.Background(), usageDayT.AddDate(0, 0, -40), usageDayT, 0)
	if err != nil {
		t.Fatalf("UsageByUser: %v", err)
	}
	return got
}

// An event synced from a worker with AgentID claude-code reads back with that
// agent (both the outer and the embedded field) and its limit rule from
// GetAggregatedEvents and GetEvents, on both fleet stores. A marshalled
// AggregatedEvent carries the agent once, under "agent_id".
func TestIngest_CarriesAgentID(t *testing.T) {
	for name, fleet := range usageStores(t, 0, time.Now()) {
		t.Run(name, func(t *testing.T) {
			local := newTestStore(t, 0)
			ev := attributedEvent()
			ev.AgentID, ev.LimitRule = "claude-code", "eng-llm"
			if err := local.StoreEvent(ev); err != nil {
				t.Fatal(err)
			}
			srv := newIngestServer(t, NewIngestHandler(fleet, StaticTokenAuthorizer("")))
			rs, err := NewHTTPRemoteStore(srv.URL, "", "proxy-1", srv.Client())
			if err != nil {
				t.Fatal(err)
			}
			if err := NewSyncWorker(local, rs, "proxy-1", 5, 100, time.Hour).SyncOnce(); err != nil {
				t.Fatalf("SyncOnce: %v", err)
			}
			agg, err := fleet.(interface {
				GetAggregatedEvents(AggregatedFilter) ([]AggregatedEvent, error)
			}).GetAggregatedEvents(AggregatedFilter{AgentID: "claude-code"})
			if err != nil || len(agg) != 1 {
				t.Fatalf("GetAggregatedEvents by agent: %d events, err %v", len(agg), err)
			}
			a := agg[0]
			if a.AgentID != "claude-code" || a.Event.AgentID != "claude-code" || a.LimitRule != "eng-llm" || a.ProxyID != "proxy-1" {
				t.Fatalf("aggregated event: outer agent %q, event agent %q, rule %q, proxy %q",
					a.AgentID, a.Event.AgentID, a.LimitRule, a.ProxyID)
			}
			evs, err := fleet.GetEvents(EventFilter{})
			if err != nil || len(evs) != 1 || evs[0].AgentID != "claude-code" || evs[0].LimitRule != "eng-llm" {
				t.Fatalf("GetEvents: %+v err %v", evs, err)
			}
			b, err := json.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(b), `"agent_id":"claude-code"`) != 1 || strings.Contains(string(b), `"AgentID"`) {
				t.Errorf("aggregated JSON must carry the agent once as agent_id: %s", b)
			}
		})
	}
}

// A caller that sets only the outer AggregatedEvent.AgentID (pre-#291 tests and
// tools) still stores and reads that agent on both fields.
func TestAggregatedEvent_OuterAgentIDStillStored(t *testing.T) {
	for name, s := range usageStores(t, 0, time.Now()) {
		t.Run(name, func(t *testing.T) {
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: Event{Timestamp: time.Now(), Domain: "x"}, AgentID: "outer"}); err != nil {
				t.Fatal(err)
			}
			evs, err := s.GetEvents(EventFilter{})
			if err != nil || len(evs) != 1 || evs[0].AgentID != "outer" {
				t.Fatalf("GetEvents: %+v %v", evs, err)
			}
		})
	}
}

// Ingesting the same batch twice (a retry after a lost ack) leaves the rollup's
// requests, denies and cost unchanged, on both fleet stores.
func TestUserUsageDaily_Dedup(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			srv := newIngestServer(t, NewIngestHandler(s, StaticTokenAuthorizer("")))
			deny := usageEvent("u3", "alice", "claude-code", "eng-llm", usageDayT, 0)
			deny.Decision, deny.Reason = "deny", "user_cost_limited"
			batch := []Event{
				usageEvent("u1", "alice", "claude-code", "eng-llm", usageDayT, 0.25),
				usageEvent("u2", "alice", "claude-code", "eng-llm", usageDayT, 0.5),
				deny,
			}
			postIngest(t, srv.URL, batch)
			first := usageAll(t, s)
			postIngest(t, srv.URL, batch)
			second := usageAll(t, s)
			if len(first) != 1 || first[0].Requests != 3 || first[0].CostUSD != 0.75 ||
				!reflect.DeepEqual(first[0].Denies, map[string]int64{"user_cost_limited": 1}) {
				t.Fatalf("first ingest: %+v", first)
			}
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("retried batch changed the rollup:\n first %+v\nsecond %+v", first, second)
			}
		})
	}
}

// After every event row is pruned by maxEvents, UsageByUser returns the same
// totals: the rollup has its own retention.
func TestUserUsageDaily_SurvivesEventsPrune(t *testing.T) {
	for name, s := range usageStores(t, 2, usageDayT) {
		t.Run(name, func(t *testing.T) {
			for i := range 6 {
				uid := "a" + strconv.Itoa(i)
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent(uid, "alice", "agent-1", "eng-llm", usageDayT, 0.25)}); err != nil {
					t.Fatal(err)
				}
			}
			before := usageAll(t, s)
			// Two unattributed events push the remaining attributed rows out.
			for i := range 2 {
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: Event{UID: "x" + strconv.Itoa(i), Timestamp: usageDayT, Domain: "x"}}); err != nil {
					t.Fatal(err)
				}
			}
			if evs, _ := s.GetEvents(EventFilter{User: "alice"}); len(evs) != 0 {
				t.Fatalf("alice events still stored: %d", len(evs))
			}
			after := usageAll(t, s)
			if len(before) != 1 || before[0].Requests != 6 || before[0].CostUSD != 1.5 || !reflect.DeepEqual(before, after) {
				t.Fatalf("totals changed by events prune:\nbefore %+v\n after %+v", before, after)
			}
		})
	}
}

// Rollup rows older than UsageRetentionDays UTC days are pruned once the clock
// passes them, whatever the events retention; the 35th day back is kept. A
// late event for a day already past the horizon is not counted.
func TestUserUsageDaily_PrunedAfter35Days(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			now := usageDayT.AddDate(0, 0, -1)
			setNow := func(ts time.Time) {
				now = ts
				switch st := s.(type) {
				case *FleetSQLiteStore:
					st.now = func() time.Time { return now }
				case *CentralStore:
					st.now = func() time.Time { return now }
				}
			}
			setNow(now)
			kept := usageDayT.AddDate(0, 0, -(UsageRetentionDays - 1))
			dropped := kept.AddDate(0, 0, -1)
			for i, ts := range []time.Time{kept, dropped} {
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent("p"+strconv.Itoa(i), "bob", "a", "r", ts, 1)}); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := s.UsageByUser(context.Background(), dropped, dropped, 0); err != nil || len(got) != 1 {
				t.Fatalf("day %s inside the horizon yesterday: %+v %v", UsageDay(dropped), got, err)
			}
			setNow(usageDayT)
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent("p8", "carol", "a", "r", usageDayT, 1)}); err != nil {
				t.Fatal(err)
			}
			// A late event for the pruned day is not counted.
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent("p9", "dave", "a", "r", dropped, 1)}); err != nil {
				t.Fatal(err)
			}
			got, err := s.UsageByUser(context.Background(), dropped, dropped, 0)
			if err != nil || len(got) != 0 {
				t.Fatalf("day %s should be pruned: %+v %v", UsageDay(dropped), got, err)
			}
			got, err = s.UsageByUser(context.Background(), kept, kept, 0)
			if err != nil || len(got) != 1 || got[0].Sub != "bob" || got[0].Requests != 1 {
				t.Fatalf("day %s should be kept: %+v %v", UsageDay(kept), got, err)
			}
		})
	}
}

// UsageByUser orders by cost, splits by agent and rule, keeps the latest
// email, appends one anonymous row outside the limit, keys days in UTC and
// skips unattributed events that no anonymous rule applied to. Both stores
// return identical results.
func TestUsageByUser(t *testing.T) {
	results := map[string][]UserUsage{}
	for name, s := range usageStores(t, 0, usageDayT) {
		yesterday := usageDayT.AddDate(0, 0, -1)
		// 23:30 at UTC-5 on the 19th is 04:30 UTC on the 20th: today.
		lateLocal := time.Date(2026, 11, 19, 23, 30, 0, 0, time.FixedZone("EST", -5*3600))
		evs := []Event{
			usageEvent("1", "alice", "claude-code", "eng-llm", usageDayT, 1),
			usageEvent("2", "alice", "cursor", "eng-llm", usageDayT, 0.5),
			usageEvent("3", "alice", "cursor", "", yesterday, 0.25),
			usageEvent("4", "bob", "claude-code", "eng-llm", lateLocal, 2),
			usageEvent("5", "carol", "claude-code", "eng-llm", usageDayT, 0.125),
			{UID: "6", Timestamp: usageDayT, Domain: "x", AgentID: "claude-code", LimitRule: AnonymousLimitRule, CostUSD: 0.5},
			{UID: "7", Timestamp: usageDayT, Domain: "x", AgentID: "claude-code", CostUSD: 9}, // unattributed, no rule
		}
		evs[2].UserEmail = "old@corp.example"
		for _, e := range evs {
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.UsageByUser(context.Background(), yesterday, usageDayT, 2)
		if err != nil {
			t.Fatal(err)
		}
		results[name] = got
		today, err := s.UsageByUser(context.Background(), usageDayT, usageDayT, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(today) != 4 || today[0].Sub != "bob" {
			t.Errorf("%s: bob's late-local event must land on the UTC day: %+v", name, today)
		}
	}
	want := []UserUsage{
		{
			Sub: "bob", Email: "bob@corp.example", Requests: 1, CostUSD: 2, Denies: map[string]int64{},
			Agents: []AgentUsage{{AgentID: "claude-code", Requests: 1, CostUSD: 2}},
			Rules:  []RuleUsage{{Rule: "eng-llm", Requests: 1, CostUSD: 2}},
		},
		{
			Sub: "alice", Email: "alice@corp.example", Requests: 3, CostUSD: 1.75, Denies: map[string]int64{},
			Agents: []AgentUsage{{AgentID: "claude-code", Requests: 1, CostUSD: 1}, {AgentID: "cursor", Requests: 2, CostUSD: 0.75}},
			Rules:  []RuleUsage{{Rule: "eng-llm", Requests: 2, CostUSD: 1.5}, {Rule: "", Requests: 1, CostUSD: 0.25}},
		},
		{
			Sub: "", Requests: 1, CostUSD: 0.5, Denies: map[string]int64{},
			Agents: []AgentUsage{{AgentID: "claude-code", Requests: 1, CostUSD: 0.5}},
			Rules:  []RuleUsage{{Rule: AnonymousLimitRule, Requests: 1, CostUSD: 0.5}},
		},
	}
	for name, got := range results {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s UsageByUser:\n got %+v\nwant %+v", name, got, want)
		}
	}
}

// TodayCostByRule sums one UTC day per (sub, rule) across agents, leaving out
// anonymous and rule-less rows and other days.
func TestTodayCostByRule(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			evs := []Event{
				usageEvent("1", "alice", "claude-code", "eng-llm", usageDayT, 1),
				usageEvent("2", "alice", "cursor", "eng-llm", usageDayT, 0.5),
				usageEvent("3", "alice", "cursor", "ops", usageDayT, 0.25),
				usageEvent("4", "alice", "cursor", "", usageDayT, 4),
				usageEvent("5", "alice", "cursor", "eng-llm", usageDayT.AddDate(0, 0, -1), 8),
				{UID: "6", Timestamp: usageDayT, AgentID: "a", LimitRule: AnonymousLimitRule, CostUSD: 3},
				usageEvent("7", "bob", "cursor", "eng-llm", usageDayT, 0.125),
			}
			for _, e := range evs {
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.TodayCostByRule(context.Background(), UsageDay(usageDayT))
			if err != nil {
				t.Fatal(err)
			}
			want := []UserRuleCost{{"alice", "eng-llm", 1.5}, {"alice", "ops", 0.25}, {"bob", "eng-llm", 0.125}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
			got, err = s.TodayCostByRule(context.Background(), "2001-01-01")
			if err != nil || got == nil || len(got) != 0 {
				t.Fatalf("empty day: %+v %v", got, err)
			}
		})
	}
}

// Deny reasons are bounded per row: empty becomes "unspecified", over-long and
// past-the-cap reasons are counted as "other". Negative costs add nothing.
func TestUserUsageDaily_DenyReasonsBounded(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			store := func(uid, reason string, cost float64) {
				e := usageEvent(uid, "alice", "a", "r", usageDayT, cost)
				e.Decision, e.Reason = "deny", reason
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
					t.Fatal(err)
				}
			}
			store("e", "", -5)
			store("l", strings.Repeat("x", maxDenyReasonLen+1), 0)
			for i := range maxDenyReasons + 5 {
				store("r"+strconv.Itoa(i), "reason_"+strconv.Itoa(i), 0)
			}
			got := usageAll(t, s)
			if len(got) != 1 {
				t.Fatalf("users: %+v", got)
			}
			d := got[0].Denies
			if len(d) > maxDenyReasons+1 || d[denyReasonUnspecified] != 1 || d[denyReasonOther] < 1 {
				t.Fatalf("denies not bounded: %d keys %v", len(d), d)
			}
			var total int64
			for _, n := range d {
				total += n
			}
			if total != int64(maxDenyReasons+7) || got[0].CostUSD != 0 {
				t.Fatalf("total denies %d cost %v", total, got[0].CostUSD)
			}
		})
	}
}

// The rollup holds identifiers and counters only: no URL, secret reference,
// judge reason or header text from the event reaches it.
func TestUserUsageDaily_NoSecretMaterial(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	s.now = func() time.Time { return usageDayT }
	e := usageEvent("1", "alice", "a", "r", usageDayT, 1)
	e.URL = "https://api.openai.com/v1?key=sk-live-SECRETVALUE"
	e.SecretRef, e.JudgeReason, e.Tool = "{{SECRETREF}}", "judged-SECRETJUDGE", "tool-SECRETTOOL"
	e.Decision, e.Reason = "deny", "rate_limited"
	if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
		t.Fatal(err)
	}
	var dump string
	err := s.db.QueryRow(`SELECT group_concat(day||'|'||sub||'|'||agent_id||'|'||limit_rule||'|'||email||'|'||requests||'|'||denies_json||'|'||cost_usd, ';') FROM user_usage_daily`).Scan(&dump)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(dump, "alice") {
		t.Fatalf("rollup row missing: %q", dump)
	}
	for _, bad := range []string{"SECRET", "sk-live", "http"} {
		if strings.Contains(dump, bad) {
			t.Errorf("rollup carries %q: %q", bad, dump)
		}
	}
}

// createPreLimitRuleFleetDB writes a fleet DB as it was after W-P1-VRFY-06 and
// W-P2-WBND-08 (user columns) but before limit_rule and the rollup.
func createPreLimitRuleFleetDB(t *testing.T, path string) {
	t.Helper()
	createLegacyFleetDB(t, path)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	for _, c := range fleetColumnMigrations {
		if c.name == "limit_rule" {
			continue
		}
		if _, err := db.Exec(c.ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO events (event_uid, proxy_id, agent_id, ts, domain, decision, user_sub, cost_usd)
        VALUES ('u2', 'proxy-a', 'old-agent', 6000, 'api.openai.com', 'allow', 'alice', 0.5)`); err != nil {
		t.Fatal(err)
	}
}

// An old fleet DB (both the original schema and one with the user columns)
// opens with limit_rule and user_usage_daily added and no data loss; old rows
// read with an empty limit rule, and a second open changes nothing.
func TestFleetMigrate_LimitRule(t *testing.T) {
	for name, create := range map[string]func(*testing.T, string){
		"original":     createLegacyFleetDB,
		"user-columns": createPreLimitRuleFleetDB,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "fleet.db")
			create(t, path)
			s, err := NewFleetSQLiteStore(path, 0, 0)
			if err != nil {
				t.Fatalf("open old DB: %v", err)
			}
			if ok, err := s.columnPresent("limit_rule"); err != nil || !ok {
				t.Fatalf("limit_rule not added: %v %v", ok, err)
			}
			evs, err := s.GetEvents(EventFilter{})
			if err != nil || len(evs) == 0 {
				t.Fatalf("old rows lost: %v %v", evs, err)
			}
			for _, e := range evs {
				if e.LimitRule != "" {
					t.Errorf("old row has limit rule %q", e.LimitRule)
				}
				if e.UserSub == "alice" && e.AgentID != "old-agent" {
					t.Errorf("old agent_id lost: %+v", e)
				}
			}
			ev := usageEvent("new", "alice", "claude-code", "eng-llm", time.Now(), 1)
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: ev}); err != nil {
				t.Fatalf("store after migrate: %v", err)
			}
			if got := usageAll2(t, s); len(got) != 1 || got[0].Requests != 1 {
				t.Fatalf("rollup after migrate: %+v", got)
			}
			before := fleetShape(t, s.db)
			_ = s.Close()
			s2, err := NewFleetSQLiteStore(path, 0, 0)
			if err != nil {
				t.Fatalf("second open must be a no-op: %v", err)
			}
			defer func() { _ = s2.Close() }()
			if after := fleetShape(t, s2.db); after != before {
				t.Errorf("second open changed the schema or rows:\nbefore %s\n after %s", before, after)
			}
		})
	}
}

func usageAll2(t *testing.T, q UserUsageQuerier) []UserUsage {
	t.Helper()
	now := time.Now()
	got, err := q.UsageByUser(context.Background(), now.AddDate(0, 0, -1), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// fleetShape summarises the schema SQL and the row counts of both tables.
func fleetShape(t *testing.T, db *sql.DB) string {
	t.Helper()
	var schema string
	if err := db.QueryRow(`SELECT group_concat(name||':'||coalesce(sql,''), '\n') FROM (SELECT name, sql FROM sqlite_master ORDER BY name)`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	var events, usage int
	if err := db.QueryRow(`SELECT (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM user_usage_daily)`).Scan(&events, &usage); err != nil {
		t.Fatal(err)
	}
	return schema + "\nrows " + strconv.Itoa(events) + "/" + strconv.Itoa(usage)
}

// Every rollup statement plans as a primary-key search on day, with no full
// scan of user_usage_daily, both on a fresh DB (no statistics) and after
// ANALYZE over a skewed fixture, so the plan does not hang on a no-stats
// tie-break.
func TestUsageQueryPlans(t *testing.T) {
	s := newFleetStore(t, 0, 0)
	s.now = func() time.Time { return usageDayT }
	day := UsageDay(usageDayT)
	plans := []struct {
		name, sql, want string
		args            []any
	}{
		{"UsageByUser", usageByUserSQL, "USING PRIMARY KEY (day>? AND day<?)", []any{day, day, day, day, 10}},
		{"anonymous", usageAnonymousSQL, "USING PRIMARY KEY (day>? AND day<?)", []any{day, day}},
		{"TodayCostByRule", todayCostByRuleSQL, "USING PRIMARY KEY (day=?", []any{day}},
		{"prune", usagePruneSQL, "USING PRIMARY KEY (day<?)", []any{day}},
		{"denies", usageDeniesSQL, "USING PRIMARY KEY (day=? AND sub=? AND agent_id=? AND limit_rule=?)", []any{day, "a", "b", "c"}},
	}
	check := func(stage string) {
		for _, p := range plans {
			rows, err := s.db.Query("EXPLAIN QUERY PLAN "+p.sql, p.args...)
			if err != nil {
				t.Fatalf("%s %s: %v", stage, p.name, err)
			}
			var lines []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				lines = append(lines, detail)
			}
			_ = rows.Close()
			seen := 0
			for _, l := range lines {
				if !strings.Contains(l, "user_usage_daily") {
					continue
				}
				seen++
				if !strings.HasPrefix(l, "SEARCH user_usage_daily ") || !strings.Contains(l, p.want) {
					t.Errorf("%s %s: plan line %q, want SEARCH ... %s (plan %q)", stage, p.name, l, p.want, lines)
				}
			}
			if seen == 0 {
				t.Errorf("%s %s: no plan line for user_usage_daily: %q", stage, p.name, lines)
			}
		}
	}
	check("no-stats")
	// Skew: many rows on one day for few users, so ANALYZE statistics would
	// favour a scan if one were available.
	for i := range 300 {
		ev := usageEvent("q"+strconv.Itoa(i), "u"+strconv.Itoa(i%3), "a"+strconv.Itoa(i%7), "r", usageDayT, 0.01)
		if err := s.StoreAggregatedEvent(AggregatedEvent{Event: ev}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	check("analyzed")
}
