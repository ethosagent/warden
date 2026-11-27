package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
)

// Fleet cost blocks (W-P3-PUL-08). A worker's own cost ledger lets a user
// spend a rule's dailyCostUSD once on every worker; the control plane closes
// that gap. The userCostAggregator recomputes today's (UTC) spend per (sub,
// rule) from the fleet rollup (W-P3-PUL-07), and the user_cost overlay serves
// the users at or over their rule's cap as policyWire.costBlockedUsers. The
// list is computed state: it is never stored in a policy version, so a
// rollback can neither restore nor clear it, and the overlay name is the
// publish-log reason of the ETag change it causes, so signed bundles move to
// a new seq instead of reading as equivocation.
//
// Nothing here runs unless the served policy has a rule with dailyCostUSD and
// the fleet store is persistent (sqlite); with the memory provider the
// aggregator stays off, no overlay is registered and one WARN says so. With no cost rule nothing is
// queried and nothing is added to the wire, so /policy is byte-identical.

const (
	// userCostOverlayName is the overlay name, its fingerprint key and the
	// policy_publish_log reason of a change it makes.
	userCostOverlayName = "user_cost"
	// userCostDebounce bounds recomputes after ingest to one per 30s.
	userCostDebounce = 30 * time.Second
	// userCostWireMargin is the headroom kept under config.MaxPolicyBytes when
	// the overlay sizes the list against the rest of the served body.
	userCostWireMargin = 64 << 10
	// userCostRecomputeFailedMsg is the ERROR logged when a recompute's query
	// fails; the previous list is kept.
	userCostRecomputeFailedMsg = "user_cost_recompute_failed"
	// userCostRetry is how often the loop retries while no recompute has
	// succeeded since start.
	userCostRetry = 5 * time.Second
)

// defaultUserCostStartupBackoff are the waits between the startup attempts
// New makes before the first policy load when there is no persisted list (no
// --state-dir). Read only; Config.userCostStartupBackoff overrides it.
var defaultUserCostStartupBackoff = []time.Duration{100 * time.Millisecond, 300 * time.Millisecond, time.Second}

// userCostPersistFailedMsg is the ERROR logged when the last good list cannot
// be written to the state DB; the in-memory list is still served.
const userCostPersistFailedMsg = "user_cost_persist_failed"

// errUserCostPending fails the user_cost overlay, and so the whole policy
// load, while a cost cap is served and the list is unknown: no recompute has
// succeeded since start and there is no persisted last good list. That
// happens only without a state DB (no --state-dir); with one, the persisted
// list is the start state. The policy server then keeps its last-known-good
// wire (or answers /policy with an error before the first load), so workers
// keep their cached list instead of a cost-capped policy without it.
var errUserCostPending = errors.New("fleet cost blocks not computed yet since start")

// costBlock is one served entry plus what the aggregator needs to rank and
// size it.
type costBlock struct {
	entry config.CostBlockedUser
	cost  float64
	// size is the entry's JSON length plus one separating comma.
	size int
}

// userCostAggregator owns the last good cost block list. The list it holds
// is immutable once stored (replaced whole), so the overlay reads it without
// copying.
type userCostAggregator struct {
	q        analytics.UserUsageQuerier
	clock    clock.Clock
	logger   *slog.Logger
	debounce time.Duration
	// served returns the policy currently served and whether one has loaded;
	// each rule's dailyCostUSD is looked up by name in it. base is the policy
	// before overlays, used until the first load (the startup recompute runs
	// before it).
	served func() (policyWire, bool)
	base   func(ctx context.Context) (policyWire, error)
	retry  time.Duration
	// startupBackoff are the waits between prime's attempts.
	startupBackoff []time.Duration
	// persist is the last good list in the state DB; nil without one.
	persist *userCostStore
	// refresh is the policy server's Refresh: it re-runs the overlays, appends
	// the publish-log row and wakes long-poll waiters.
	refresh func()

	kick chan struct{}

	mu sync.Mutex
	// blocks is in priority order (cost desc, then sub, then rule), so a size
	// cut keeps the largest spenders. Nil when no one is over a cap.
	blocks []costBlock
	// capsFP is the fingerprint of the caps blocks were computed with; the
	// overlay kicks a recompute when the served caps differ from it.
	capsFP  string
	lastRun time.Time
	// computed is set by the first recompute that succeeds; until then the
	// overlay fails any load that serves a cost cap (errUserCostPending).
	computed bool
	// trimWarned is set once the overlay has logged a size cut of the current
	// list, so the 3s reload does not repeat it.
	trimWarned bool

	// recomputeErrors is warden_cp_cost_recompute_errors_total and blocked is
	// the warden_cp_cost_blocked_users gauge; in memory only, for W-P5-RETN-06
	// to export.
	recomputeErrors atomic.Int64
	blocked         atomic.Int64
	// countCut and sizeCut are the entries left out of the current list by
	// the MaxCostBlockedUsers cap and by the policy size limit; Truncated is
	// their sum (in memory, for W-P5-RETN-06 to export).
	countCut atomic.Int64
	sizeCut  atomic.Int64
	// persistErrors counts failed writes of the persisted list.
	persistErrors atomic.Int64
}

// newUserCostAggregator builds the aggregator over q. served and refresh are
// set by the caller before the first recompute.
func newUserCostAggregator(q analytics.UserUsageQuerier, clk clock.Clock, logger *slog.Logger) *userCostAggregator {
	return &userCostAggregator{
		q: q, clock: clk, logger: logger, debounce: userCostDebounce, retry: userCostRetry,
		startupBackoff: defaultUserCostStartupBackoff,
		kick:           make(chan struct{}, 1),
	}
}

// RecomputeErrors is the in-memory warden_cp_cost_recompute_errors_total.
func (a *userCostAggregator) RecomputeErrors() int64 { return a.recomputeErrors.Load() }

// BlockedUsers is the in-memory warden_cp_cost_blocked_users gauge: the size
// of the list the last good recompute built.
func (a *userCostAggregator) BlockedUsers() int64 { return a.blocked.Load() }

// Truncated is the in-memory warden_cp_cost_blocked_users_truncated gauge:
// over-cap users left out of the served list by the entry cap or the policy
// size limit.
func (a *userCostAggregator) Truncated() int64 { return a.countCut.Load() + a.sizeCut.Load() }

// PersistErrors counts failed writes of the persisted last good list.
func (a *userCostAggregator) PersistErrors() int64 { return a.persistErrors.Load() }

// isComputed reports whether a recompute has succeeded since start.
func (a *userCostAggregator) isComputed() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.computed
}

// notify asks the run loop for a recompute; it never blocks.
func (a *userCostAggregator) notify() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// onEvents is the ingest hook: a batch carrying attributed, rule-tagged
// traffic schedules a (debounced) recompute. Anonymous or unruled traffic
// cannot change the list, so it schedules nothing.
func (a *userCostAggregator) onEvents(_ string, events []analytics.Event) {
	for i := range events {
		if events[i].UserSub != "" && events[i].LimitRule != "" {
			a.notify()
			return
		}
	}
}

// run recomputes after each notify (at most once per debounce) and at each
// UTC midnight, until ctx is done. While no recompute has succeeded since
// start it also retries every a.retry.
func (a *userCostAggregator) run(ctx context.Context) {
	for {
		midnight := a.clock.NewTimer(untilNextUTCDay(a.clock.Now()))
		var retryC <-chan time.Time
		var retryT interface{ Stop() bool }
		if !a.isComputed() {
			rt := a.clock.NewTimer(a.retry)
			retryC, retryT = rt.C(), rt
		}
		stop := func() {
			midnight.Stop()
			if retryT != nil {
				retryT.Stop()
			}
		}
		select {
		case <-ctx.Done():
			stop()
			return
		case <-midnight.C():
			stop()
		case <-retryC:
			stop()
		case <-a.kick:
			stop()
			if !a.waitDebounce(ctx) {
				return
			}
		}
		a.recompute(ctx)
	}
}

// prime is the startup recompute New runs before the first policy load:
// up to len(backoff)+1 attempts with the given waits between them. It
// reports whether one succeeded; if none did, the overlay fails the load
// (errUserCostPending) and the loop keeps retrying once started.
func (a *userCostAggregator) prime(ctx context.Context) bool {
	backoff := a.startupBackoff
	for i := 0; ; i++ {
		a.recomputeOnce(ctx, false)
		if a.isComputed() {
			return true
		}
		if i >= len(backoff) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff[i]):
		}
	}
}

// waitDebounce sleeps until debounce has passed since the last recompute. It
// returns false when ctx ends first.
func (a *userCostAggregator) waitDebounce(ctx context.Context) bool {
	a.mu.Lock()
	wait := a.lastRun.Add(a.debounce).Sub(a.clock.Now())
	a.mu.Unlock()
	if wait <= 0 {
		return true
	}
	t := a.clock.NewTimer(wait)
	select {
	case <-ctx.Done():
		t.Stop()
		return false
	case <-t.C():
		return true
	}
}

// untilNextUTCDay is the time from now to the next 00:00 UTC.
func untilNextUTCDay(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	return next.Sub(u)
}

// recompute rebuilds the list from today's rollup and, when it changed,
// refreshes the policy server (one publish-log row, a new ETag and bundle
// seq, long-poll waiters woken). A query error keeps the previous list and
// ETag. With no cost rule served nothing is queried and the list is empty.
func (a *userCostAggregator) recompute(ctx context.Context) { a.recomputeOnce(ctx, true) }

// recomputeOnce is recompute; refresh false skips the policy Refresh (the
// startup attempt, which runs before the first load).
func (a *userCostAggregator) recomputeOnce(ctx context.Context, refresh bool) {
	now := a.clock.Now()
	day := analytics.UsageDay(now)
	var caps map[string]float64
	if w, ok := a.served(); ok {
		caps = costCapsOf(w)
	} else if a.base != nil {
		w, err := a.base(ctx)
		if err != nil {
			// No policy to read caps from: nothing can be computed yet.
			a.recomputeErrors.Add(1)
			a.logger.Error(userCostRecomputeFailedMsg, "error", boundedErr(err))
			return
		}
		caps = costCapsOf(w)
	}
	var next []costBlock
	cut := 0
	if len(caps) > 0 {
		rows, err := a.q.TodayCostByRule(ctx, day)
		if err != nil {
			a.recomputeErrors.Add(1)
			a.mu.Lock()
			a.lastRun = now
			a.mu.Unlock()
			// The error comes from the store (no sub or email in it); counts
			// and the bounded error text only.
			a.logger.Error(userCostRecomputeFailedMsg, "error", boundedErr(err))
			return
		}
		next, cut = a.buildBlocks(rows, caps, day)
	}
	a.mu.Lock()
	// The first success after start always refreshes: it clears the pending
	// state the overlay failed loads with.
	changed := !a.computed || !sameCostBlocks(a.blocks, next)
	a.blocks, a.capsFP, a.lastRun, a.computed = next, capsFingerprint(caps), now, true
	if changed {
		a.trimWarned = false
	}
	a.mu.Unlock()
	a.blocked.Store(int64(len(next)))
	a.countCut.Store(int64(cut))
	if !changed {
		return
	}
	if cut > 0 {
		a.logger.Warn("user cost blocks: list cut to the limit", "dropped", cut, "limit", config.MaxCostBlockedUsers)
	}
	// Persist before the refresh serves it, so a restart starts from the list
	// workers last saw. A failed write is counted; the list is still served.
	if a.persist != nil {
		if err := a.persist.save(ctx, day, next); err != nil {
			a.persistErrors.Add(1)
			a.logger.Error(userCostPersistFailedMsg, "error", boundedErr(err))
		}
	}
	a.logger.Info("user cost blocks updated", "blocked", len(next), "day", day)
	if refresh {
		a.refresh()
	}
}

// buildBlocks turns the rollup's (sub, rule, cost) rows into the users at or
// over their rule's cap on day. Anonymous spend, unknown or removed rule
// names (the rollup's "!invalid" among them) and rows that would not pass
// config.ValidateCostBlockedUsers are skipped, never mapped onto a rule. The
// result is in priority order and capped at config.MaxCostBlockedUsers; cut
// is how many over-cap users the cap left out.
func (a *userCostAggregator) buildBlocks(rows []analytics.UserRuleCost, caps map[string]float64, day string) (blocks []costBlock, cut int) {
	var out []costBlock
	skipped := 0
	seen := make(map[config.CostBlockedUser]struct{})
	for _, r := range rows {
		if r.Sub == "" || r.Rule == config.UserLimitNameAnonymous {
			continue
		}
		limit, ok := caps[r.Rule]
		if !ok || math.IsNaN(r.CostUSD) || r.CostUSD < limit {
			continue
		}
		e := config.CostBlockedUser{Sub: r.Sub, Rule: r.Rule, Day: day}
		if config.ValidateCostBlockedUsers([]config.CostBlockedUser{e}) != nil {
			skipped++
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		b, err := json.Marshal(e)
		if err != nil {
			skipped++
			continue
		}
		out = append(out, costBlock{entry: e, cost: r.CostUSD, size: len(b) + 1})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].cost != out[j].cost {
			return out[i].cost > out[j].cost
		}
		return lessCostBlocked(out[i].entry, out[j].entry)
	})
	if skipped > 0 {
		a.logger.Warn("user cost blocks: rollup rows skipped", "skipped", skipped)
	}
	if len(out) > config.MaxCostBlockedUsers {
		cut = len(out) - config.MaxCostBlockedUsers
		out = out[:config.MaxCostBlockedUsers]
	}
	return out, cut
}

// apply is the user_cost overlay. It serves the entries of the last good list
// whose day is today and whose rule is still served with a dailyCostUSD, so
// a removed rule or a passed midnight drops its entries at once, without a
// recompute. The list is cut, largest spenders kept, so the whole served body
// stays under the worker's config.MaxPolicyBytes. A change of the served caps
// asks for a recompute.
func (a *userCostAggregator) apply(_ context.Context, w *policyWire) (string, error) {
	caps := costCapsOf(*w)
	fp := capsFingerprint(caps)
	a.mu.Lock()
	blocks, stale, computed := a.blocks, fp != a.capsFP, a.computed
	a.mu.Unlock()
	if stale {
		a.notify()
	}
	if len(caps) == 0 {
		return "", nil
	}
	if !computed {
		return "", errUserCostPending
	}
	if len(blocks) == 0 {
		return "", nil
	}
	today := analytics.UsageDay(a.clock.Now())
	keep := make([]costBlock, 0, len(blocks))
	for _, b := range blocks {
		if b.entry.Day == today && caps[b.entry.Rule] > 0 {
			keep = append(keep, b)
		}
	}
	if len(keep) == 0 {
		return "", nil
	}
	keep, err := fitBody(*w, keep)
	if err != nil {
		return "", err
	}
	list := make([]config.CostBlockedUser, len(keep))
	for i, b := range keep {
		list[i] = b.entry
	}
	sort.Slice(list, func(i, j int) bool { return lessCostBlocked(list[i], list[j]) })
	if err := config.ValidateCostBlockedUsers(list); err != nil {
		return "", err
	}
	w.CostBlockedUsers = list
	return costBlocksFingerprint(list), nil
}

// fitBody returns the longest prefix of keep whose entries fit next to the
// rest of w in config.MaxPolicyBytes less the margin. An encoding error fails
// the load (never an empty list). It has no side effects: it also runs for
// candidate docs (servedETag) that are never served.
func fitBody(w policyWire, keep []costBlock) ([]costBlock, error) {
	total := 0
	for _, b := range keep {
		total += b.size
	}
	b, err := json.Marshal(projectScoped(w))
	if err != nil {
		return nil, err
	}
	// The key, its quotes, the brackets and the comma before it.
	budget := config.MaxPolicyBytes - userCostWireMargin - len(b) - len(`,"costBlockedUsers":[]`)
	if total <= budget {
		return keep, nil
	}
	n, used := 0, 0
	for n < len(keep) && used+keep[n].size <= budget {
		used += keep[n].size
		n++
	}
	return keep[:n], nil
}

// observeServed runs after every load the policy server actually serves
// (never for a candidate doc): it sets the size-cut gauge from what reached
// the wire and logs the size cut once per list.
func (a *userCostAggregator) observeServed(w policyWire) {
	caps := costCapsOf(w)
	today := analytics.UsageDay(a.clock.Now())
	a.mu.Lock()
	eligible := 0
	if len(caps) > 0 {
		for _, b := range a.blocks {
			if b.entry.Day == today && caps[b.entry.Rule] > 0 {
				eligible++
			}
		}
	}
	cut := max(eligible-len(w.CostBlockedUsers), 0)
	warn := cut > 0 && !a.trimWarned
	if warn {
		a.trimWarned = true
	}
	a.mu.Unlock()
	a.sizeCut.Store(int64(cut))
	if warn {
		a.logger.Warn("user cost blocks: list cut to fit the policy size limit", "blocked", eligible, "served", len(w.CostBlockedUsers))
	}
}

// seed installs the persisted last good list as the start state, before the
// first load: entries for today are served until a live recompute replaces
// them; a row from an earlier day (or no row) starts empty. Either way the
// list counts as known, so no load waits on the rollup. A read error is
// logged and starts empty as well.
func (a *userCostAggregator) seed(ctx context.Context) {
	day, list, ok, err := a.persist.load(ctx)
	today := analytics.UsageDay(a.clock.Now())
	switch {
	case err != nil:
		a.logger.Error("user_cost_load_failed", "error", boundedErr(err))
		list = nil
	case !ok || day != today:
		list = nil
	}
	a.mu.Lock()
	a.blocks, a.computed = list, true
	a.mu.Unlock()
	a.blocked.Store(int64(len(list)))
	a.logger.Info("user cost blocks loaded", "source", "persisted", "blocked", len(list))
}

// costCapsOf maps each served rule with a dailyCostUSD to its cap: userLimits
// by name and defaultUserLimit under its reserved name. anonymousLimit is left
// out: anonymous spend is never published (it is capped by each worker's own
// ledger).
func costCapsOf(w policyWire) map[string]float64 {
	var caps map[string]float64
	add := func(name string, c float64) {
		if c <= 0 || name == "" || name == config.UserLimitNameAnonymous {
			return
		}
		if caps == nil {
			caps = make(map[string]float64)
		}
		caps[name] = c
	}
	for _, l := range w.UserLimits {
		add(l.Name, l.DailyCostUSD)
	}
	if l := w.DefaultUserLimit; l != nil {
		add(config.UserLimitNameDefault, l.DailyCostUSD)
	}
	return caps
}

// capsFingerprint is a stable string of caps ("" when there are none).
func capsFingerprint(caps map[string]float64) string {
	if len(caps) == 0 {
		return ""
	}
	names := make([]string, 0, len(caps))
	for n := range caps {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString(n)
		sb.WriteByte('=')
		sb.WriteString(strconv.FormatFloat(caps[n], 'g', -1, 64))
		sb.WriteByte(';')
	}
	return sb.String()
}

// costBlocksFingerprint is a short hash of the served list: it names a change
// in the publish log without putting a sub in it.
func costBlocksFingerprint(list []config.CostBlockedUser) string {
	b, _ := json.Marshal(list)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}

func lessCostBlocked(a, b config.CostBlockedUser) bool {
	if a.Sub != b.Sub {
		return a.Sub < b.Sub
	}
	if a.Rule != b.Rule {
		return a.Rule < b.Rule
	}
	return a.Day < b.Day
}

// sameCostBlocks reports whether a and b hold the same entries, ignoring
// order and cost: only a change of who is blocked moves the ETag.
func sameCostBlocks(a, b []costBlock) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[config.CostBlockedUser]struct{}, len(a))
	for _, x := range a {
		set[x.entry] = struct{}{}
	}
	for _, x := range b {
		if _, ok := set[x.entry]; !ok {
			return false
		}
	}
	return true
}

// warnUserCostOff logs, once per process, that fleet cost blocks are off
// because the fleet store is the in-memory one, when caps has a cost cap the
// control plane would publish (anonymousLimit's is per worker anyway). It
// runs at Start and on a save that adds a cap.
func (s *Server) warnUserCostOff(caps map[string]float64) {
	if s.userCost != nil {
		return
	}
	fleetCap := false
	for name, c := range caps {
		fleetCap = fleetCap || (c > 0 && name != config.UserLimitNameAnonymous)
	}
	if !fleetCap {
		return
	}
	s.userCostOffWarn.Do(func() {
		s.cfg.Logger.Warn("control plane: fleet cost blocks are off with the memory analytics provider; dailyCostUSD is enforced per worker only (use the sqlite analytics provider)")
	})
}

// initUserCost builds the aggregator and registers the user_cost overlay when
// the fleet store has the persistent rollup; with the memory provider nothing
// is registered (warnUserCostOff says so once a cap is served). It must run
// after the other overlays, so the size check sees the rest of the body.
func (s *Server) initUserCost() {
	q, ok := s.central.(analytics.UserUsageQuerier)
	if _, mem := s.central.(*analytics.CentralStore); mem || !ok {
		// Every successful load checks for a cap, so one served later (an
		// import, an external edit) is warned about too.
		s.policy.onLoaded = func(w policyWire) { s.warnUserCostOff(wireCostCaps(w)) }
		return
	}
	a := newUserCostAggregator(q, s.cfg.Clock, s.cfg.Logger)
	a.served = func() (policyWire, bool) {
		w, _, ok, _ := s.policy.snapshot()
		return w, ok
	}
	a.base = s.policy.loadBase
	a.refresh = s.policy.Refresh
	if err := s.policy.addOverlay(wireOverlay{name: userCostOverlayName, apply: a.apply}); err != nil {
		s.cfg.Logger.Error("control plane: user_cost overlay not registered", "error", err)
		return
	}
	s.policy.onLoaded = a.observeServed
	s.userCost = a
	ctx := context.Background()
	if s.cfg.State != nil {
		// The persisted last good list is the start state; one live attempt
		// then refreshes it, and the loop keeps it current.
		a.persist = &userCostStore{db: s.cfg.State.SQL(), now: s.cfg.Clock.Now}
		a.seed(ctx)
		a.startupBackoff = nil
		a.prime(ctx)
		return
	}
	if b := s.cfg.userCostStartupBackoff; b != nil {
		a.startupBackoff = b
	}
	// No state DB: rebuild the list before the first load, so a restart
	// serves it from the first /policy; with a failing rollup the load fails
	// closed (errUserCostPending) until a retry succeeds.
	if !a.prime(ctx) {
		s.cfg.Logger.Error("control plane: fleet cost blocks could not be rebuilt at startup and no --state-dir holds the last list; /policy is held at last-known-good while a dailyCostUSD rule is served, retrying")
	}
}

// startUserCost starts the recompute loop. New already rebuilt the list
// (prime); if that failed, one more attempt runs here before Start returns
// and the loop retries every userCostRetry until one succeeds.
func (s *Server) startUserCost(ctx context.Context) {
	if s.userCost == nil {
		if w, _, ok, _ := s.policy.snapshot(); ok {
			s.warnUserCostOff(wireCostCaps(w))
		}
		return
	}
	if !s.userCost.isComputed() {
		s.userCost.recompute(ctx)
	}
	go s.userCost.run(ctx)
}
