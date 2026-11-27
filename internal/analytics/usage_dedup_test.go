package analytics

import (
	"context"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// syncFrom stores n attributed events for sub in a local store and syncs them
// to url as proxyID through the real SyncWorker and HTTP ingest path.
func syncFrom(t *testing.T, local *SQLiteStore, url, proxyID, sub string, n int) {
	t.Helper()
	for range n {
		if err := local.StoreEvent(usageEvent("", sub, "agent-1", "eng-llm", time.Now(), 0.25)); err != nil {
			t.Fatal(err)
		}
	}
	rs, err := NewHTTPRemoteStore(url, "", proxyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewSyncWorker(local, rs, proxyID, 100, 1000, time.Hour).SyncOnce(); err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}
}

func openLocal(t *testing.T, path string) *SQLiteStore {
	t.Helper()
	s, err := NewSQLiteStore("file:"+path, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func requestsFor(t *testing.T, q UserUsageQuerier, sub string) int64 {
	t.Helper()
	now := time.Now()
	got, err := q.UsageByUser(context.Background(), now.AddDate(0, 0, -1), now, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range got {
		if u.Sub == sub {
			return u.Requests
		}
	}
	return 0
}

// A worker whose local database is recreated (same proxy id, rowids restart
// at 1) sends events the control plane stores and counts, because the new
// database has a new UID epoch.
func TestFleetDedup_LocalDBResetCounted(t *testing.T) {
	for name, fleet := range usageStores(t, 0, time.Now()) {
		t.Run(name, func(t *testing.T) {
			srv := newIngestServer(t, NewIngestHandler(fleet, StaticTokenAuthorizer("")))
			dir := t.TempDir()
			syncFrom(t, openLocal(t, filepath.Join(dir, "a.db")), srv.URL, "worker-1", "alice", 3)
			syncFrom(t, openLocal(t, filepath.Join(dir, "b.db")), srv.URL, "worker-1", "alice", 3)
			if got := requestsFor(t, fleet, "alice"); got != 6 {
				t.Fatalf("requests after a local DB reset = %d, want 6", got)
			}
		})
	}
}

// Two proxies sending identical worker UIDs are both counted, and a worker
// authenticated as A that sends B's future UIDs first cannot suppress B's
// events: dedup is scoped to the authorized proxy id. The same proxy resending
// its batch is still deduped.
func TestFleetDedup_ScopedToAuthorizedProxy(t *testing.T) {
	for name, fleet := range usageStores(t, 0, time.Now()) {
		t.Run(name, func(t *testing.T) {
			// The authorizer, not the body, names the proxy: the bearer token
			// maps to the id.
			auth := func(r *http.Request) (string, int) {
				return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), 0
			}
			srv := newIngestServer(t, NewIngestHandler(fleet, auth))
			batch := []Event{
				usageEvent("uid-1", "bob", "agent-1", "eng-llm", time.Now(), 0.25),
				usageEvent("uid-2", "bob", "agent-1", "eng-llm", time.Now(), 0.25),
			}
			post := func(proxy string) {
				rs, err := NewHTTPRemoteStore(srv.URL, proxy, "", nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := rs.SendBatch(batch); err != nil {
					t.Fatal(err)
				}
			}
			post("worker-a") // A pre-sends B's UIDs
			post("worker-b")
			post("worker-b") // B's retry: deduped
			if got := requestsFor(t, fleet, "bob"); got != 4 {
				t.Fatalf("requests = %d, want 4 (2 from A, 2 from B, B's retry dropped)", got)
			}
			evs, err := fleet.GetEvents(EventFilter{ProxyID: "worker-b"})
			if err != nil || len(evs) != 2 {
				t.Fatalf("worker-b events: %d %v", len(evs), err)
			}
		})
	}
}

// An upgraded fleet DB whose old rows hold raw worker UIDs opens and dedups
// correctly for batches sent after the upgrade.
func TestFleetDedup_UpgradedDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.db")
	createLegacyFleetDB(t, path) // holds a row with raw event_uid 'u1' from proxy-a
	s, err := NewFleetSQLiteStore(path, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	ev := AggregatedEvent{Event: usageEvent("u1", "carol", "a", "r", time.Now(), 1), ProxyID: "proxy-a"}
	for range 2 {
		if err := s.StoreAggregatedEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := s.GetEvents(EventFilter{})
	if err != nil || len(evs) != 2 {
		t.Fatalf("events = %d (want the legacy row plus one new), err %v", len(evs), err)
	}
	if got := requestsFor(t, s, "carol"); got != 1 {
		t.Fatalf("requests = %d, want 1", got)
	}
}

// Each local database gets one random UID epoch, kept across reopens; a new
// database gets a different one, and a database from before the epoch gains
// one on first open.
func TestUIDEpoch_PerDatabase(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.db")
	s1 := openLocal(t, a)
	e1 := s1.uidEpoch
	_ = s1.Close()
	if len(e1) != 32 {
		t.Fatalf("epoch %q, want 32 hex chars", e1)
	}
	if e2 := openLocal(t, a).uidEpoch; e2 != e1 {
		t.Fatalf("epoch changed on reopen: %q -> %q", e1, e2)
	}
	if e3 := openLocal(t, filepath.Join(dir, "b.db")).uidEpoch; e3 == e1 {
		t.Fatal("two databases share an epoch")
	}
	legacy := filepath.Join(dir, "legacy.db")
	createLegacyEventsDB(t, "file:"+legacy)
	if e := openLocal(t, legacy).uidEpoch; len(e) != 32 {
		t.Fatalf("legacy DB epoch %q", e)
	}
}

// A future-dated event counts toward the CP's today, never a later day.
func TestUserUsageDaily_FutureClampedToToday(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent("f", "alice", "a", "r", usageDayT.AddDate(0, 0, 3), 1)}); err != nil {
				t.Fatal(err)
			}
			got, err := s.TodayCostByRule(context.Background(), UsageDay(usageDayT))
			if err != nil || len(got) != 1 || got[0].CostUSD != 1 {
				t.Fatalf("today: %+v %v", got, err)
			}
			if got, _ := s.TodayCostByRule(context.Background(), UsageDay(usageDayT.AddDate(0, 0, 3))); len(got) != 0 {
				t.Fatalf("future day has rows: %+v", got)
			}
		})
	}
}

// Rule names outside the rule-name charset map to usageRuleInvalid (which no
// configured rule can be named); oversized sub, email and agent are cut to
// their caps without splitting a rune.
func TestUserUsageDaily_IdentifiersBounded(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			long := strings.Repeat("é", maxUsageSubLen) // 2 bytes each
			e := usageEvent("1", long, strings.Repeat("a", 500), "bad rule<script>", usageDayT, 1)
			e.UserEmail = strings.Repeat("m", 1000)
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
				t.Fatal(err)
			}
			e2 := usageEvent("2", "bob", "a", strings.Repeat("r", 65), usageDayT, 1)
			if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e2}); err != nil {
				t.Fatal(err)
			}
			got := usageAll(t, s)
			if len(got) != 2 {
				t.Fatalf("users: %+v", got)
			}
			for _, u := range got {
				if len(u.Sub) > maxUsageSubLen || (u.Sub != "bob" && !strings.HasPrefix(long, u.Sub)) || len(u.Email) > maxUsageEmailLen ||
					len(u.Agents) != 1 || len(u.Agents[0].AgentID) > maxUsageAgentLen ||
					len(u.Rules) != 1 || u.Rules[0].Rule != usageRuleInvalid {
					t.Errorf("unbounded row: sub %d bytes, email %d, agents %+v, rules %+v", len(u.Sub), len(u.Email), u.Agents, u.Rules)
				}
			}
		})
	}
}

// At its row cap the in-memory rollup refuses new keys and counts them, while
// existing rows keep counting.
func TestCentralStore_UsageRowCap(t *testing.T) {
	c := NewCentralStore(0)
	c.now = func() time.Time { return usageDayT }
	c.usage.maxRows = 2
	for i, sub := range []string{"a", "b", "c", "a"} {
		if err := c.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent(string(rune('0'+i)), sub, "x", "r", usageDayT, 1)}); err != nil {
			t.Fatal(err)
		}
	}
	got := usageAll(t, c)
	if len(got) != 2 || got[0].Sub != "a" || got[0].Requests != 2 || c.UsageRowsRefused() != 1 {
		t.Fatalf("rows %+v refused %d", got, c.UsageRowsRefused())
	}
}

// captureFleet records what the ingest handler hands the store.
type captureFleet struct {
	FleetStore
	got []AggregatedEvent
}

func (c *captureFleet) StoreAggregatedEvent(e AggregatedEvent) error {
	c.got = append(c.got, e)
	return nil
}

// The ingest handler sets the outer AggregatedEvent.AgentID from the event and
// ProxyID from the authorizer (a body ProxyID is ignored).
func TestIngest_SetsOuterAgentID(t *testing.T) {
	fake := &captureFleet{}
	auth := func(*http.Request) (string, int) { return "authorized-proxy", 0 }
	srv := newIngestServer(t, NewIngestHandler(fake, auth))
	ev := usageEvent("u", "alice", "claude-code", "eng-llm", time.Now(), 0)
	ev.ProxyID = "body-proxy"
	postIngest(t, srv.URL, []Event{ev})
	if len(fake.got) != 1 {
		t.Fatalf("stored %d events", len(fake.got))
	}
	if g := fake.got[0]; g.AgentID != "claude-code" || g.ProxyID != "authorized-proxy" {
		t.Fatalf("outer AgentID %q ProxyID %q", g.AgentID, g.ProxyID)
	}
}

// Rule names use the agent-id charset PUL-01 enforces (agentid.ValidID): a
// valid name with ':' keeps its name and shows in TodayCostByRule, so its
// spend can be published; an invalid one maps to usageRuleInvalid.
func TestUserUsageDaily_RuleNameCharset(t *testing.T) {
	for name, s := range usageStores(t, 0, usageDayT) {
		t.Run(name, func(t *testing.T) {
			for i, rule := range []string{"eng:llm", "-leading-dash", "eng.llm_v2-x"} {
				e := usageEvent("c"+string(rune('0'+i)), "alice", "a", rule, usageDayT, 1)
				if err := s.StoreAggregatedEvent(AggregatedEvent{Event: e}); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.TodayCostByRule(context.Background(), UsageDay(usageDayT))
			if err != nil {
				t.Fatal(err)
			}
			want := []UserRuleCost{{"alice", usageRuleInvalid, 1}, {"alice", "eng.llm_v2-x", 1}, {"alice", "eng:llm", 1}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v want %+v", got, want)
			}
		})
	}
}

// FleetConfig.Now drives the rollup's day clamp: with the store clock on a
// later day than the real one, an event stamped on that day books to it
// instead of being clamped back to the real today.
func TestNewFleetStore_NowDrivesDayClamp(t *testing.T) {
	fake := time.Now().UTC().AddDate(0, 0, 1) // tomorrow: after the real today
	for _, provider := range []string{"memory", "sqlite"} {
		t.Run(provider, func(t *testing.T) {
			fs, err := NewFleetStore(FleetConfig{Provider: provider, SQLitePath: t.TempDir() + "/f.db", Now: func() time.Time { return fake }})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = fs.Close() }()
			if err := fs.StoreAggregatedEvent(AggregatedEvent{Event: usageEvent("n", "alice", "a", "r", fake, 1)}); err != nil {
				t.Fatal(err)
			}
			got, err := fs.(UserUsageQuerier).TodayCostByRule(context.Background(), UsageDay(fake))
			if err != nil || len(got) != 1 || got[0].CostUSD != 1 {
				t.Fatalf("fake-day rows: %+v %v", got, err)
			}
		})
	}
}
