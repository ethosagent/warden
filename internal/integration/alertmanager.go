package integration

import (
	"log/slog"
	"time"
)

// alertStore is the store surface the AlertManager needs: upsert on the producer
// path (Ingest) and list for the resolve sweep (ResolveStale). Declaring it as an
// interface (satisfied by *Store) lets tests inject a fake to assert the
// persist-before-deliver ordering without a real database.
type alertStore interface {
	UpsertAlert(a Alert) error
	ListAlerts(limit int) ([]Alert, error)
}

// DefaultResolveTTL is the silence window after which a FIRING alert with no
// re-fire is auto-resolved. Detectors re-fire every tick while a condition holds
// (which bumps LastSeen), so a LastSeen older than this TTL means the condition
// has cleared. On the AlertManager, a zero resolveTTL selects this default; a
// NEGATIVE resolveTTL disables auto-resolve entirely.
const DefaultResolveTTL = 15 * time.Minute

// alertDeliverer is the router dependency AlertManager needs (satisfied by
// *Router). Deliver never blocks — it enqueues and returns.
type alertDeliverer interface {
	Deliver(a Alert)
}

// AlertManager dedups Findings into stateful Alerts, persists each to the store
// FIRST (system-of-record), then hands it to the router for fan-out. In M1
// dedup is trivial (1 finding → 1 upsert); the store's ON CONFLICT provides
// Count and severity escalation naturally on re-fire.
type AlertManager struct {
	store  alertStore
	router alertDeliverer
	logger *slog.Logger
	now    func() time.Time
	// resolveTTL is the silence window after which a firing alert auto-resolves
	// (see ResolveStale). 0 selects DefaultResolveTTL; a negative value disables
	// the resolve sweep. Set once at construction (Manager.NewManager); read only
	// by the tick-driven ResolveStale, so no lock is needed.
	resolveTTL time.Duration
}

// NewAlertManager wires an AlertManager over a concrete Store and Router. A nil
// logger defaults to slog.Default().
func NewAlertManager(store *Store, router *Router, logger *slog.Logger) *AlertManager {
	if logger == nil {
		logger = slog.Default()
	}
	return &AlertManager{store: store, router: router, logger: logger, now: time.Now}
}

// Ingest turns a Finding into an Alert, persists it, then delivers it. It is on
// the producer path and MUST NOT block or panic: a store or router error is
// logged and swallowed (fail-open), matching Warden's "scanning bugs never
// break egress" invariant.
func (am *AlertManager) Ingest(f Finding) {
	defer func() {
		if r := recover(); r != nil {
			am.logger.Error("integration: alertmanager ingest panic (recovered)", "recover", r)
		}
	}()

	ts := f.Ts
	if ts.IsZero() {
		ts = am.now()
	}

	a := Alert{
		ID:       alertID(f.DedupKey),
		DedupKey: f.DedupKey,
		Category: f.Category,
		Severity: f.Severity,
		Subject:  f.Subject,
		// Bound Summary/Evidence at construction — the egress-hygiene guarantee.
		Summary:  boundedSummary(f.Summary),
		Evidence: boundEvidence(f.Evidence),
		// TODO(M1-resolve): a resolve TTL that flips Status to StatusResolved
		// after a quiet period since LastSeen is out of scope for this phase;
		// Status stays firing. The type already carries the lifecycle fields so
		// adding the TTL later needs no migration.
		Status:    StatusFiring,
		Count:     1,
		FirstSeen: ts,
		LastSeen:  ts,
	}

	// Persist FIRST: the store is the system-of-record and its ON CONFLICT
	// escalation gives Count/severity merge on re-fire. A persist error is
	// logged but does NOT suppress delivery — delivery does not depend on the
	// row existing, and a notification is more valuable than none (fail-open).
	if err := am.store.UpsertAlert(a); err != nil {
		am.logger.Error("integration: persist alert failed (delivering best-effort)", "id", a.ID, "err", err)
	}

	// THEN hand to the router. Deliver enqueues and returns immediately.
	am.router.Deliver(a)
}

// ResolveStale flips every FIRING alert whose LastSeen is older than the resolve
// TTL to StatusResolved and upserts it, reusing the store's ON CONFLICT path (no
// new table). It is LEVEL-TRIGGERED off LastSeen: a detector re-fires each tick
// while its condition holds (bumping LastSeen), so a TTL of silence since LastSeen
// is the natural "cleared" signal. It NEVER touches the "new finding → firing"
// path — only the resolve transition. The pipeline tick calls it once per tick, so
// it runs wherever the pipeline runs (control plane in fleet, worker in local-only).
//
// Fail-open: a store error, or a panic, is logged and swallowed so a bad sweep can
// never break the tick loop or proxying. Returns the number of alerts resolved.
// resolveTTL == 0 uses DefaultResolveTTL; resolveTTL < 0 disables the sweep.
//
// The reused UpsertAlert bumps count by 1 on the resolving write (its ON CONFLICT
// increments count); LastSeen is preserved (the row keeps its last re-fire time).
// The +1 is a benign artifact of reusing the single upsert path rather than adding
// a bespoke resolve statement — a resolved alert is skipped on subsequent sweeps.
func (am *AlertManager) ResolveStale(now time.Time) (resolved int) {
	defer func() {
		if r := recover(); r != nil {
			am.logger.Error("integration: alertmanager resolve sweep panic (recovered)", "recover", r)
		}
	}()

	ttl := am.resolveTTL
	if ttl < 0 {
		return 0 // auto-resolve disabled
	}
	if ttl == 0 {
		ttl = DefaultResolveTTL
	}

	alerts, err := am.store.ListAlerts(0)
	if err != nil {
		am.logger.Error("integration: resolve sweep list failed", "err", err)
		return 0
	}
	cutoff := now.Add(-ttl)
	for _, a := range alerts {
		if a.Status != StatusFiring {
			continue
		}
		if a.LastSeen.After(cutoff) {
			continue // still fresh — re-fired within the TTL
		}
		a.Status = StatusResolved
		if err := am.store.UpsertAlert(a); err != nil {
			am.logger.Error("integration: resolve upsert failed", "id", a.ID, "err", err)
			continue
		}
		resolved++
	}
	return resolved
}
