package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// ucEnv is a versioned control plane over a persistent fleet store, with a
// fake clock pinned to the real current instant (the rollup clamps
// future-dated events to the store's own today, so events must not be in the
// real future).
type ucEnv struct {
	s         *Server
	fleet     *analytics.FleetSQLiteStore
	fleetPath string
	db        *cpstate.DB
	clk       *clocktest.Fake
	logs      *syncBuf
	fk        *fakeBundleKeys
}

type ucOpts struct {
	bundles   string // "" = off
	db        *cpstate.DB
	fleetPath string
	clk       *clocktest.Fake
	fk        *fakeBundleKeys
	policy    string
	// wrap, when set, wraps the fleet store the Server is built over.
	wrap func(*analytics.FleetSQLiteStore) analytics.FleetStore
	// backoff, when set, replaces the startup retry waits.
	backoff []time.Duration
}

func newUserCostEnv(t *testing.T, o ucOpts) *ucEnv {
	t.Helper()
	if o.db == nil {
		o.db = openPolicyState(t)
	}
	if o.fleetPath == "" {
		o.fleetPath = filepath.Join(t.TempDir(), "warden-fleet.db")
	}
	if o.clk == nil {
		o.clk = clocktest.NewFake(time.Now().UTC())
	}
	if o.policy == "" {
		o.policy = writePolicyFile(t, "api.openai.com")
	}
	fleet, err := analytics.NewFleetSQLiteStore(o.fleetPath, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fleet.Close() })
	logs := &syncBuf{}
	var store analytics.FleetStore = fleet
	if o.wrap != nil {
		store = o.wrap(fleet)
	}
	cfg := Config{
		PolicyPath: o.policy, State: o.db, PolicyStore: PolicyStoreVersioned,
		Store: store, Clock: o.clk, Logger: slog.New(slog.NewJSONHandler(logs, nil)),
		userCostStartupBackoff: o.backoff,
	}
	if o.bundles != "" {
		if o.fk == nil {
			o.fk = newFakeBundleKeys(t)
		}
		cfg.Bundles = BundlesConfig{Mode: o.bundles}
		cfg.bundleKeys = o.fk
	}
	s := New(cfg)
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.bundles != "" {
		if err := s.policy.startBundles(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if s.userCost == nil {
		t.Fatal("aggregator not built over the sqlite fleet store")
	}
	return &ucEnv{s: s, fleet: fleet, fleetPath: o.fleetPath, db: o.db, clk: o.clk, logs: logs, fk: o.fk}
}

// engLLM is the rule of the acceptance: dailyCostUSD 0.01.
func engLLM(cost float64) config.UserLimit {
	return config.UserLimit{Name: "eng-llm", Match: config.UserLimitMatch{Groups: []string{"eng"}, Domains: []string{"api.openai.com"}}, RateLimit: "60/minute", DailyCostUSD: cost}
}

// setRules makes the head version carry rules (stored directly: the
// not-yet-enforced config guard stands between the loader and a rule).
func (e *ucEnv) setRules(t *testing.T, rules []config.UserLimit, def *config.UserLimit) {
	t.Helper()
	head := mustHead(t, e.s.versions)
	doc := baseDoc(t, e.s)
	doc.UserLimits, doc.DefaultUserLimit = rules, def
	if _, _, err := e.s.versions.Create(context.Background(), doc, testAuthor, "rules", SourcePolicy, head); err != nil {
		t.Fatal(err)
	}
}

var ucSeq atomic.Int64

// spend stores one allowed event from worker proxy for sub under rule.
func (e *ucEnv) spend(t *testing.T, proxy, sub, rule string, cost float64) {
	t.Helper()
	ev := analytics.Event{
		UID: fmt.Sprintf("uc-%d", ucSeq.Add(1)), Timestamp: e.clk.Now(), Domain: "api.openai.com", Decision: "allow",
		UserSub: sub, AgentID: "agent-a", LimitRule: rule, CostUSD: cost,
	}
	if err := e.fleet.StoreAggregatedEvent(analytics.AggregatedEvent{Event: ev, ProxyID: proxy}); err != nil {
		t.Fatal(err)
	}
}

func (e *ucEnv) recompute() { e.s.userCost.recompute(context.Background()) }

// served returns the costBlockedUsers of one GET /policy and its ETag.
func (e *ucEnv) served(t *testing.T) ([]config.CostBlockedUser, string, []byte) {
	t.Helper()
	body, etag := servePolicyOnce(t, e.s.policy)
	var w struct {
		CostBlockedUsers []config.CostBlockedUser `json:"costBlockedUsers"`
	}
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	return w.CostBlockedUsers, etag, body
}

func (e *ucEnv) today() string { return analytics.UsageDay(e.clk.Now()) }

func publishReasons(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.versions.PublishLog(context.Background(), 0, 500)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Reason
	}
	return out
}

func countReason(reasons []string, want string) int {
	n := 0
	for _, r := range reasons {
		if r == want {
			n++
		}
	}
	return n
}

// TestUserCostAggregator_TwoWorkersOverCap: alice spends $0.006 through worker
// A and $0.006 through worker B under eng-llm (cap $0.01): one run puts her,
// and only her, in /policy. Anonymous spend, unknown and invalid rule names
// and a user under the cap are never published.
func TestUserCostAggregator_TwoWorkersOverCap(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.006)
	e.spend(t, "worker-b", "alice", "eng-llm", 0.006)
	e.spend(t, "worker-a", "bob", "eng-llm", 0.006)              // under the cap
	e.spend(t, "worker-a", "carol", "ghost", 5)                  // a rule the policy does not have
	e.spend(t, "worker-a", "dave", "bad rule!", 5)               // rolled up as "!invalid"
	e.spend(t, "worker-a", "", config.UserLimitNameAnonymous, 5) // anonymous spend

	if got, _, _ := e.served(t); got != nil {
		t.Fatalf("before the first run /policy carries %v", got)
	}
	e.recompute()
	got, _, _ := e.served(t)
	want := []config.CostBlockedUser{{Sub: "alice", Rule: "eng-llm", Day: e.today()}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("costBlockedUsers = %v, want %v", got, want)
	}
	if n := e.s.userCost.BlockedUsers(); n != 1 {
		t.Errorf("blocked gauge = %d, want 1", n)
	}
	if strings.Contains(e.logs.String(), "alice") {
		t.Errorf("a log line names a sub:\n%s", e.logs.String())
	}
}

// TestUserCostAggregator_PublishLogAndETag: a change appends exactly one
// publish-log row with reason user_cost and moves the ETag; an unchanged list
// on the next run changes neither.
func TestUserCostAggregator_PublishLogAndETag(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.recompute() // nobody over: no change
	_, etag0, _ := e.served(t)
	rows0 := publishReasons(t, e.s)

	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	_, etag1, _ := e.served(t)
	rows1 := publishReasons(t, e.s)
	if etag1 == etag0 {
		t.Fatal("the ETag did not change with the list")
	}
	if len(rows1) != len(rows0)+1 || rows1[len(rows1)-1] != userCostOverlayName {
		t.Fatalf("publish log %v -> %v, want one more row with reason %s", rows0, rows1, userCostOverlayName)
	}
	if e.s.versions == nil || mustHead(t, e.s.versions) != 2 {
		t.Fatal("the list created a policy version")
	}

	e.spend(t, "worker-b", "alice", "eng-llm", 0.02) // more spend, same list
	e.recompute()
	_, etag2, _ := e.served(t)
	if etag2 != etag1 {
		t.Errorf("unchanged list moved the ETag %s -> %s", etag1, etag2)
	}
	if rows2 := publishReasons(t, e.s); len(rows2) != len(rows1) {
		t.Errorf("unchanged list wrote publish rows: %v -> %v", rows1, rows2)
	}
	// The stored head doc never holds the list.
	v, err := e.s.versions.Get(context.Background(), mustHead(t, e.s.versions))
	if err != nil || len(v.Doc.CostBlockedUsers) != 0 {
		t.Fatalf("head doc = %+v, %v; want no costBlockedUsers", v.Doc.CostBlockedUsers, err)
	}
}

// TestUserCostAggregator_BundleSeqIncreases: with --bundles=offer a list
// change is signed under a higher seq.
func TestUserCostAggregator_BundleSeqIncreases(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{bundles: BundlesOffer})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.recompute()
	before := e.s.policy.bundleHeadSeq()
	if before == 0 {
		t.Fatal("no bundle signed")
	}
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	after := e.s.policy.bundleHeadSeq()
	if after <= before {
		t.Fatalf("bundle seq %d -> %d, want an increase", before, after)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("Accept", BundleMediaType)
	e.s.policy.ServePolicy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bundle GET = %d", rec.Code)
	}
	b := btPayload(t, rec.Body.Bytes())
	if !strings.Contains(string(b.Policy), `"costBlockedUsers":[{"sub":"alice","rule":"eng-llm"`) {
		t.Errorf("signed policy lacks the cost block: %s", b.Policy)
	}
	// The same list again signs nothing new.
	e.recompute()
	if got := e.s.policy.bundleHeadSeq(); got != after {
		t.Errorf("unchanged list moved the bundle seq %d -> %d", after, got)
	}
}

// TestUserCostAggregator_MidnightServesEmpty: once the fake clock passes
// 00:00 UTC, yesterday's entries are not served even before a run, and the
// next run serves an empty list.
func TestUserCostAggregator_MidnightServesEmpty(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	if got, _, _ := e.served(t); len(got) != 1 {
		t.Fatalf("before midnight = %v, want alice", got)
	}
	e.clk.Advance(untilNextUTCDay(e.clk.Now()) + time.Second)
	e.s.policy.Refresh() // the reload ticker, no run
	if got, _, body := e.served(t); got != nil || strings.Contains(string(body), "costBlockedUsers") {
		t.Fatalf("after midnight, before a run = %s, want no costBlockedUsers", body)
	}
	e.recompute()
	if got, _, _ := e.served(t); got != nil {
		t.Fatalf("after midnight = %v, want empty", got)
	}
	if n := e.s.userCost.BlockedUsers(); n != 0 {
		t.Errorf("blocked gauge = %d, want 0", n)
	}
}

// failingUsage fails TodayCostByRule while fail is set.
type failingUsage struct {
	analytics.UserUsageQuerier
	fail  atomic.Bool
	calls atomic.Int64
}

func (f *failingUsage) TodayCostByRule(ctx context.Context, day string) ([]analytics.UserRuleCost, error) {
	f.calls.Add(1)
	if f.fail.Load() {
		return nil, errors.New("database is locked")
	}
	return f.UserUsageQuerier.TodayCostByRule(ctx, day)
}

// TestUserCostAggregator_StoreErrorKeepsList: a failing query keeps the
// previous list and ETag, counts the error and logs one ERROR without subs.
func TestUserCostAggregator_StoreErrorKeepsList(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	fq := &failingUsage{UserUsageQuerier: e.fleet}
	e.s.userCost.q = fq
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	list0, etag0, _ := e.served(t)
	rows0 := publishReasons(t, e.s)

	fq.fail.Store(true)
	e.spend(t, "worker-a", "bob", "eng-llm", 0.02)
	e.recompute()
	e.s.policy.Refresh()
	list1, etag1, _ := e.served(t)
	if fmt.Sprint(list1) != fmt.Sprint(list0) || etag1 != etag0 {
		t.Fatalf("after a store error = %v %s, want the previous %v %s", list1, etag1, list0, etag0)
	}
	if rows := publishReasons(t, e.s); len(rows) != len(rows0) {
		t.Errorf("a failed run wrote publish rows: %v -> %v", rows0, rows)
	}
	if n := e.s.userCost.RecomputeErrors(); n != 1 {
		t.Errorf("recompute errors = %d, want 1", n)
	}
	logs := e.logs.String()
	if strings.Count(logs, userCostRecomputeFailedMsg) != 1 || !strings.Contains(logs, `"level":"ERROR"`) {
		t.Errorf("want one ERROR %s:\n%s", userCostRecomputeFailedMsg, logs)
	}
	if strings.Contains(logs, "alice") || strings.Contains(logs, "bob") {
		t.Errorf("a log line names a sub:\n%s", logs)
	}
	fq.fail.Store(false)
	e.recompute()
	if got, _, _ := e.served(t); len(got) != 2 {
		t.Errorf("after recovery = %v, want alice and bob", got)
	}
}

// TestUserCostAggregator_RestartRebuildsBeforeFirstPoll: a new control plane
// over the same state and fleet DB has the list from its first load: New
// rebuilds it synchronously, with no loop running (Start is never called). A
// worker holding the pre-restart ETag gets 304: the restarted CP serves the
// same bytes, list included.
func TestUserCostAggregator_RestartRebuildsBeforeFirstPoll(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.006)
	e.spend(t, "worker-b", "alice", "eng-llm", 0.006)
	e.recompute()
	list, preETag, _ := e.served(t)
	if len(list) != 1 {
		t.Fatalf("before restart = %v, want alice", list)
	}
	if err := e.fleet.Close(); err != nil {
		t.Fatal(err)
	}

	e2 := newUserCostEnv(t, ucOpts{db: e.db, fleetPath: e.fleetPath, clk: e.clk})
	wire, etag, ok, _ := e2.s.policy.snapshot()
	if !ok || fmt.Sprint(wire.CostBlockedUsers) != fmt.Sprint(list) || `"`+etag+`"` != preETag {
		t.Fatalf("after restart, before any loop = %v %q (ok %v), want %v %s", wire.CostBlockedUsers, etag, ok, list, preETag)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("If-None-Match", preETag)
	e2.s.policy.ServePolicy(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("first poll with the pre-restart ETag = %d %s, want 304", rec.Code, rec.Body.String())
	}
}

// failingFleet is a FleetSQLiteStore whose TodayCostByRule fails while fail
// is set.
type failingFleet struct {
	*analytics.FleetSQLiteStore
	fail atomic.Bool
}

func (f *failingFleet) TodayCostByRule(ctx context.Context, day string) ([]analytics.UserRuleCost, error) {
	if f.fail.Load() {
		return nil, errors.New("disk I/O error")
	}
	return f.FleetSQLiteStore.TodayCostByRule(ctx, day)
}

// failingEnv restarts e's control plane over the same state and fleet DB with
// a rollup query that fails until the returned store's fail is cleared.
func failingEnv(t *testing.T, e *ucEnv, o ucOpts) (*ucEnv, *failingFleet) {
	t.Helper()
	var ff *failingFleet
	o.db, o.fleetPath = e.db, e.fleetPath
	if o.clk == nil {
		o.clk = e.clk
	}
	o.wrap = func(s *analytics.FleetSQLiteStore) analytics.FleetStore {
		ff = &failingFleet{FleetSQLiteStore: s}
		ff.fail.Store(true)
		return ff
	}
	return newUserCostEnv(t, o), ff
}

// TestUserCostAggregator_RestartWithFailingRollupServesPersisted: a restart
// whose rollup query fails starts (snapshot loaded, as Run requires in
// versioned mode) and serves the persisted last good list with 200; policy
// changes keep reaching workers meanwhile; once the query recovers the live
// list replaces the seed.
func TestUserCostAggregator_RestartWithFailingRollupServesPersisted(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	if err := e.fleet.Close(); err != nil {
		t.Fatal(err)
	}

	e2, ff := failingEnv(t, e, ucOpts{})
	if _, _, ok, _ := e2.s.policy.snapshot(); !ok {
		t.Fatal("the restarted versioned CP has no loaded policy: Run would refuse to start")
	}
	list, _, _ := e2.served(t)
	if len(list) != 1 || list[0].Sub != "alice" {
		t.Fatalf("after a restart with a failing rollup = %v, want the persisted alice", list)
	}
	if e2.s.userCost.RecomputeErrors() == 0 {
		t.Error("the failing startup attempt was not counted")
	}

	// A deny entry saved while the rollup fails is delivered, list intact.
	head := mustHead(t, e2.s.versions)
	doc := baseDoc(t, e2.s)
	doc.Denylist = append(doc.Denylist, config.DenylistEntry{Domain: "new-deny.example.com"})
	if _, _, err := e2.s.versions.Create(context.Background(), doc, testAuthor, "deny", SourcePolicy, head); err != nil {
		t.Fatalf("Create while the rollup fails = %v", err)
	}
	list, _, body := e2.served(t)
	if !strings.Contains(string(body), "new-deny.example.com") || len(list) != 1 {
		t.Fatalf("after a deny save = %s, want the new entry and alice", body)
	}

	// Recovery: a live run replaces the seed (bob is now over too).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e2.s.Start(ctx)
	e2.spend(t, "worker-b", "bob", "eng-llm", 0.02)
	ff.fail.Store(false)
	e2.recompute()
	if list, _, _ := e2.served(t); len(list) != 2 {
		t.Fatalf("after recovery = %v, want alice and bob", list)
	}
}

// TestUserCostAggregator_PersistedYesterdayServesNothing: a persisted list
// from an earlier UTC day is not served after a restart, even while the
// rollup fails.
func TestUserCostAggregator_PersistedYesterdayServesNothing(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	if err := e.fleet.Close(); err != nil {
		t.Fatal(err)
	}
	clk := clocktest.NewFake(e.clk.Now().Add(untilNextUTCDay(e.clk.Now()) + time.Hour))
	e2, _ := failingEnv(t, e, ucOpts{clk: clk})
	if list, _, body := e2.served(t); list != nil || strings.Contains(string(body), "costBlockedUsers") {
		t.Fatalf("a day later = %s, want no costBlockedUsers", body)
	}
}

// TestUserCostAggregator_CorruptPersistedRow: an unreadable persisted row
// means "unknown", not "empty": with the rollup also failing the load is held
// (never a cost-capped wire without the list); with a working rollup the
// live list is served.
func TestUserCostAggregator_CorruptPersistedRow(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	if _, err := e.db.SQL().Exec(`UPDATE user_cost_blocks SET list_json = '{not json'`); err != nil {
		t.Fatal(err)
	}
	if err := e.fleet.Close(); err != nil {
		t.Fatal(err)
	}

	e2, _ := failingEnv(t, e, ucOpts{backoff: []time.Duration{time.Millisecond}})
	if _, _, ok, _ := e2.s.policy.snapshot(); ok {
		t.Fatal("corrupt row and failing rollup: a policy was loaded")
	}
	rec := httptest.NewRecorder()
	e2.s.policy.ServePolicy(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("corrupt row and failing rollup: /policy = 200 %s, want it held", rec.Body.String())
	}
	if !strings.Contains(e2.logs.String(), "user_cost_load_failed") {
		t.Errorf("the corrupt row was not logged:\n%s", e2.logs.String())
	}
	if err := e2.fleet.Close(); err != nil {
		t.Fatal(err)
	}

	e3 := newUserCostEnv(t, ucOpts{db: e.db, fleetPath: e.fleetPath, clk: e.clk, backoff: []time.Duration{time.Millisecond}})
	if list, _, _ := e3.served(t); len(list) != 1 || list[0].Sub != "alice" {
		t.Fatalf("corrupt row and working rollup = %v, want the live alice", list)
	}
}

// TestUserCostAggregator_PersistWriteFailure: a failed write of the
// persisted list is counted and logged; the new list is still served.
func TestUserCostAggregator_PersistWriteFailure(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil)
	if _, err := e.db.SQL().Exec("DROP TABLE user_cost_blocks"); err != nil {
		t.Fatal(err)
	}
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.recompute()
	if list, _, _ := e.served(t); len(list) != 1 {
		t.Fatalf("served %v, want alice despite the write failure", list)
	}
	if n := e.s.userCost.PersistErrors(); n != 1 {
		t.Errorf("persist errors = %d, want 1", n)
	}
	// The table is back: the next run repairs the row although the list did
	// not change.
	if _, err := e.db.SQL().Exec(userCostMigration0001); err != nil {
		t.Fatal(err)
	}
	e.recompute()
	st := &userCostStore{db: e.db.SQL(), now: e.clk.Now}
	day, list, ok, err := st.load(context.Background())
	if err != nil || !ok || day != e.today() || len(list) != 1 || list[0].entry.Sub != "alice" {
		t.Fatalf("persisted row after the repair run = %q %v %v %v, want today's alice", day, list, ok, err)
	}
	if n := e.s.userCost.PersistErrors(); n != 1 {
		t.Errorf("persist errors after the repair = %d, want still 1", n)
	}
	e.recompute() // clean now: no further write needed, none fails
	if n := e.s.userCost.PersistErrors(); n != 1 {
		t.Errorf("persist errors = %d after a clean run, want 1", n)
	}
	if !strings.Contains(e.logs.String(), userCostPersistFailedMsg) || strings.Contains(e.logs.String(), "alice") {
		t.Errorf("want %s logged without subs:\n%s", userCostPersistFailedMsg, e.logs.String())
	}
}

// TestUserCostAggregator_NoStateFailsClosed: without a state DB there is no
// persisted list, so a failing rollup at startup holds /policy (never a
// cost-capped wire without the list) until the loop's retry succeeds.
func TestUserCostAggregator_NoStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n  userLimits:\n    - name: eng-llm\n      match: {groups: [eng]}\n      dailyCostUSD: 0.01\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fleet, err := analytics.NewFleetSQLiteStore(filepath.Join(t.TempDir(), "fleet.db"), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fleet.Close() })
	clk := clocktest.NewFake(time.Now().UTC())
	ev := analytics.Event{UID: "ns-1", Timestamp: clk.Now(), Domain: "api.openai.com", Decision: "allow", UserSub: "alice", LimitRule: "eng-llm", CostUSD: 0.02}
	if err := fleet.StoreAggregatedEvent(analytics.AggregatedEvent{Event: ev, ProxyID: "w"}); err != nil {
		t.Fatal(err)
	}
	ff := &failingFleet{FleetSQLiteStore: fleet}
	ff.fail.Store(true)
	s := New(Config{PolicyPath: path, Store: ff, Clock: clk, Logger: testJSONLogger(nil), userCostStartupBackoff: []time.Duration{time.Millisecond}})
	serve := func() (int, string) {
		rec := httptest.NewRecorder()
		s.policy.ServePolicy(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := serve(); code == http.StatusOK {
		t.Fatalf("without state and a failing rollup /policy = 200 %s, want it held", body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.Start(ctx)
	ff.fail.Store(false)
	btEventually(t, "the retry serves the list", func() bool {
		if code, body := serve(); code == http.StatusOK && !strings.Contains(body, `"sub":"alice"`) {
			t.Fatalf("served a cost-capped policy without the list: %s", body)
		}
		clk.Advance(time.Second)
		code, body := serve()
		return code == http.StatusOK && strings.Contains(body, `"sub":"alice"`)
	})
}

// TestUserCostAggregator_RuleChanges: removing the cap drops its entries at
// once (no run needed); a default rule's cap is looked up under "default"; a
// raised cap is applied by the run the cap change asks for.
func TestUserCostAggregator_RuleChanges(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, &config.UserLimit{Name: "default", DailyCostUSD: 1})
	e.spend(t, "worker-a", "alice", "eng-llm", 0.02)
	e.spend(t, "worker-a", "erin", "default", 2)
	e.recompute()
	if got, _, _ := e.served(t); len(got) != 2 || got[0].Sub != "alice" || got[1].Rule != "default" {
		t.Fatalf("list = %v, want alice/eng-llm and erin/default", got)
	}
	// The cap change leaves a pending recompute request.
	select {
	case <-e.s.userCost.kick:
	default:
	}
	e.setRules(t, []config.UserLimit{engLLM(0)}, &config.UserLimit{Name: "default", DailyCostUSD: 1})
	if got, _, _ := e.served(t); len(got) != 1 || got[0].Sub != "erin" {
		t.Fatalf("after removing eng-llm's cap = %v, want erin only", got)
	}
	select {
	case <-e.s.userCost.kick:
	default:
		t.Fatal("a cap change did not ask for a recompute")
	}
	e.setRules(t, []config.UserLimit{engLLM(0)}, &config.UserLimit{Name: "default", DailyCostUSD: 10})
	e.recompute()
	if got, _, _ := e.served(t); got != nil {
		t.Fatalf("after raising the default cap = %v, want empty", got)
	}
}

// TestUserCostAggregator_Loop: notifications are debounced to one run per
// 30s, and a run happens at UTC midnight with no ingest.
func TestUserCostAggregator_Loop(t *testing.T) {
	start := time.Date(2030, 1, 2, 23, 58, 0, 0, time.UTC)
	clk := clocktest.NewFake(start)
	fq := &countingUsage{}
	a := newUserCostAggregator(fq, clk, slog.New(slog.NewJSONHandler(&syncBuf{}, nil)))
	a.served = func() (policyWire, bool) { return policyWire{UserLimits: []config.UserLimit{engLLM(1)}}, true }
	a.refresh = func() {}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	a.onEvents("w", []analytics.Event{{UserSub: "alice", LimitRule: "eng-llm"}})
	btEventually(t, "the first run", func() bool { return fq.calls.Load() == 1 })
	// Anonymous or unruled traffic schedules nothing.
	a.onEvents("w", []analytics.Event{{LimitRule: "anonymous"}, {UserSub: "bob"}})
	select {
	case <-a.kick:
		t.Fatal("unattributed traffic scheduled a run")
	default:
	}
	a.onEvents("w", []analytics.Event{{UserSub: "alice", LimitRule: "eng-llm"}})
	a.onEvents("w", []analytics.Event{{UserSub: "alice", LimitRule: "eng-llm"}})
	// The loop waits on the debounce timer; nothing runs before 30s pass.
	btEventually(t, "the debounce timer", func() bool { return clk.PendingTimers() == 1 })
	clk.Advance(userCostDebounce - time.Second)
	if n := fq.calls.Load(); n != 1 {
		t.Fatalf("%d runs before the debounce passed, want 1", n)
	}
	btEventually(t, "the debounced run", func() bool { clk.Advance(time.Second); return fq.calls.Load() == 2 })
	// The second notification above coalesces into at most one more run 30s
	// later; with no further traffic the next run is midnight's, on the new day.
	btEventually(t, "the midnight run", func() bool {
		clk.Advance(10 * time.Second)
		day, _ := fq.lastDay.Load().(string)
		return day == "2030-01-03"
	})
	if n := fq.calls.Load(); n > 4 {
		t.Errorf("%d runs in two minutes, want at most 4 (debounced)", n)
	}
}

type countingUsage struct {
	analytics.UserUsageQuerier
	calls   atomic.Int64
	lastDay atomic.Value
}

func (c *countingUsage) TodayCostByRule(_ context.Context, day string) ([]analytics.UserRuleCost, error) {
	c.lastDay.Store(day)
	c.calls.Add(1)
	return nil, nil
}

// TestUserCostAggregator_Limits: the list is capped at MaxCostBlockedUsers,
// keeps the largest spenders, and is cut so the served body stays under the
// worker's MaxPolicyBytes; rows that would fail ValidateCostBlockedUsers are
// skipped one by one, never failing the list.
func TestUserCostAggregator_Limits(t *testing.T) {
	a := newUserCostAggregator(nil, clocktest.NewFake(time.Now()), slog.New(slog.NewJSONHandler(&syncBuf{}, nil)))
	day := analytics.UsageDay(a.clock.Now())
	caps := map[string]float64{"eng-llm": 1}

	var rows []analytics.UserRuleCost
	for i := range config.MaxCostBlockedUsers + 10 {
		rows = append(rows, analytics.UserRuleCost{Sub: fmt.Sprintf("u%05d", i), Rule: "eng-llm", CostUSD: 1 + float64(i)})
	}
	rows = append(rows,
		analytics.UserRuleCost{Sub: "bad\x01sub", Rule: "eng-llm", CostUSD: 1e9},
		analytics.UserRuleCost{Sub: "   ", Rule: "eng-llm", CostUSD: 1e9},
		analytics.UserRuleCost{Sub: strings.Repeat("x", 256), Rule: "eng-llm", CostUSD: 1e9},
	)
	got, cut := a.buildBlocks(rows, caps, day)
	if len(got) != config.MaxCostBlockedUsers || cut != 10 {
		t.Fatalf("%d entries, %d cut; want %d and 10", len(got), cut, config.MaxCostBlockedUsers)
	}
	if len(got) != config.MaxCostBlockedUsers {
		t.Fatalf("%d entries, want %d", len(got), config.MaxCostBlockedUsers)
	}
	if got[0].entry.Sub != fmt.Sprintf("u%05d", config.MaxCostBlockedUsers+9) || got[len(got)-1].entry.Sub != "u00010" {
		t.Errorf("kept %s..%s, want the largest spenders", got[0].entry.Sub, got[len(got)-1].entry.Sub)
	}

	// Long subs: 5000 entries of 255 bytes are far over 1 MiB.
	rows = rows[:0]
	for i := range config.MaxCostBlockedUsers {
		rows = append(rows, analytics.UserRuleCost{Sub: fmt.Sprintf("%05d", i) + strings.Repeat("s", 250), Rule: "eng-llm", CostUSD: 2})
	}
	a.blocks, _ = a.buildBlocks(rows, caps, day)
	a.computed = true
	w := policyWire{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}, UserLimits: []config.UserLimit{engLLM(1)}}
	fp, err := a.apply(context.Background(), &w)
	if err != nil || fp == "" {
		t.Fatalf("apply = %q, %v", fp, err)
	}
	// A candidate evaluation (servedETag) moves no gauge; a served load does.
	if a.Truncated() != 0 {
		t.Fatalf("apply alone set the truncated gauge to %d", a.Truncated())
	}
	a.observeServed(w)
	b, _ := json.Marshal(projectScoped(w))
	if len(b) > config.MaxPolicyBytes || len(w.CostBlockedUsers) == 0 || len(w.CostBlockedUsers) >= config.MaxCostBlockedUsers {
		t.Fatalf("served %d entries in %d bytes; want a cut list under %d bytes", len(w.CostBlockedUsers), len(b), config.MaxPolicyBytes)
	}
	if err := config.ValidateCostBlockedUsers(w.CostBlockedUsers); err != nil {
		t.Fatal(err)
	}
	if got := a.Truncated(); got != int64(config.MaxCostBlockedUsers-len(w.CostBlockedUsers)) {
		t.Errorf("truncated gauge = %d, want %d", got, config.MaxCostBlockedUsers-len(w.CostBlockedUsers))
	}
	for i := 1; i < len(w.CostBlockedUsers); i++ {
		if !lessCostBlocked(w.CostBlockedUsers[i-1], w.CostBlockedUsers[i]) {
			t.Fatalf("served list not sorted at %d", i)
		}
	}
}

// TestUserCostAggregator_MemoryProviderOff: with the in-memory fleet store
// no aggregator runs, nothing reaches the wire, and one WARN says why.
func TestUserCostAggregator_MemoryProviderOff(t *testing.T) {
	logs := &syncBuf{}
	s := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), State: openPolicyState(t), PolicyStore: PolicyStoreVersioned,
		Logger: slog.New(slog.NewJSONHandler(logs, nil)),
	})
	if err := s.importInitialVersion(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.userCost != nil {
		t.Fatal("aggregator built over the memory store")
	}
	if strings.Contains(logs.String(), "fleet cost blocks are off") {
		t.Fatal("warned with no cost rule served")
	}
	e := &ucEnv{s: s}
	e.setRules(t, []config.UserLimit{engLLM(0.01)}, nil) // as an import would: only the reload sees it
	if n := strings.Count(logs.String(), "fleet cost blocks are off"); n != 1 {
		t.Fatalf("after the reload that served a cap: %d WARN lines, want 1:\n%s", n, logs.String())
	}
	s.policy.Refresh()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s.Start(ctx)
	if body, _ := servePolicyOnce(t, s.policy); strings.Contains(string(body), "costBlockedUsers") {
		t.Fatalf("memory provider served cost blocks: %s", body)
	}
	if n := strings.Count(logs.String(), "fleet cost blocks are off"); n != 1 {
		t.Fatalf("%d WARN lines, want 1:\n%s", n, logs.String())
	}
}

// TestUserCostAggregator_IngestHookSchedules: a batch posted to
// /central/ingest asks the aggregator for a run.
func TestUserCostAggregator_IngestHookSchedules(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	h := e.s.Handler()
	select {
	case <-e.s.userCost.kick:
	default:
	}
	body, _ := json.Marshal(map[string]any{"events": []analytics.Event{{
		UID: "ingest-1", Timestamp: e.clk.Now(), Domain: "api.openai.com", Decision: "allow",
		UserSub: "alice", LimitRule: "eng-llm", CostUSD: 0.5,
	}}})
	req := httptest.NewRequest(http.MethodPost, "/central/ingest", bytes.NewReader(body))
	req.Header.Set(analytics.ProxyIDHeader, "worker-a")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ingest = %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-e.s.userCost.kick:
	default:
		t.Fatal("ingest did not schedule a recompute")
	}
}

// With no dailyCostUSD rule the aggregator over a sqlite fleet store with
// spend in it queries nothing and /policy is the golden body.
func TestPolicyWire_UserLimitsAbsentUnchangedWithFleetStore(t *testing.T) {
	e := newUserCostEnv(t, ucOpts{})
	fq := &failingUsage{UserUsageQuerier: e.fleet}
	e.s.userCost.q = fq
	e.spend(t, "worker-a", "alice", "eng-llm", 5)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.s.Start(ctx)
	e.recompute()
	body, _ := servePolicyOnce(t, e.s.policy)
	const golden = `{"allowlist":[{"domain":"api.openai.com","port":0}],"denylist":[{"domain":"evil.example.com","port":0}]}`
	if string(body) != golden+"\n" {
		t.Fatalf("body = %q, want the golden %q", body, golden)
	}
	if n := fq.calls.Load(); n != 0 {
		t.Errorf("%d rollup queries with no cost rule, want 0", n)
	}
	if reasons := publishReasons(t, e.s); countReason(reasons, userCostOverlayName) != 0 {
		t.Errorf("publish log has user_cost rows with no cost rule: %v", reasons)
	}
}
