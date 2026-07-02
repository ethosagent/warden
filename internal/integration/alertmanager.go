package integration

import (
	"log/slog"
	"time"
)

// alertUpserter is the store dependency AlertManager needs. Declaring it as an
// interface (satisfied by *Store) lets tests inject a fake to assert the
// persist-before-deliver ordering without a real database.
type alertUpserter interface {
	UpsertAlert(a Alert) error
}

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
	store  alertUpserter
	router alertDeliverer
	logger *slog.Logger
	now    func() time.Time
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
