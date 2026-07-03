package integration

import (
	"testing"
	"time"
)

// TestResolveStaleFlipsStaleLeavesFresh drives the P4 resolve sweep against a real
// Store: a firing alert whose LastSeen is older than the TTL is flipped to
// resolved, while a freshly re-fired alert stays firing. It reuses the store's
// ON CONFLICT upsert (no new table), so it also proves LastSeen is preserved.
func TestResolveStaleFlipsStaleLeavesFresh(t *testing.T) {
	s := newTestStore(t)
	now := time.UnixMilli(10_000_000)
	ttl := 15 * time.Minute

	stale := sampleAlert("stale", "error_rate:stale.example.com", SevHigh, now.Add(-20*time.Minute))
	fresh := sampleAlert("fresh", "error_rate:fresh.example.com", SevHigh, now.Add(-1*time.Minute))
	if err := s.UpsertAlert(stale); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	if err := s.UpsertAlert(fresh); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}

	am := &AlertManager{store: s, logger: quietLogger(), now: time.Now, resolveTTL: ttl}
	if got := am.ResolveStale(now); got != 1 {
		t.Fatalf("ResolveStale resolved %d, want 1", got)
	}

	staleRow, _, err := s.GetAlert("stale")
	if err != nil {
		t.Fatalf("get stale: %v", err)
	}
	if staleRow.Status != StatusResolved {
		t.Errorf("stale alert status = %q, want resolved", staleRow.Status)
	}
	if !staleRow.LastSeen.Equal(stale.LastSeen) {
		t.Errorf("resolve must preserve LastSeen: got %v want %v", staleRow.LastSeen, stale.LastSeen)
	}

	freshRow, _, err := s.GetAlert("fresh")
	if err != nil {
		t.Fatalf("get fresh: %v", err)
	}
	if freshRow.Status != StatusFiring {
		t.Errorf("fresh alert status = %q, want firing", freshRow.Status)
	}

	// Idempotent: a resolved alert is skipped on the next sweep (no double count).
	if got := am.ResolveStale(now); got != 0 {
		t.Errorf("second sweep resolved %d, want 0 (resolved rows skipped)", got)
	}
}

// TestResolveStaleDisabledAndDefault covers the TTL knob edges: a negative TTL
// disables the sweep, and a zero TTL selects DefaultResolveTTL.
func TestResolveStaleDisabledAndDefault(t *testing.T) {
	s := newTestStore(t)
	now := time.UnixMilli(10_000_000)
	old := sampleAlert("old", "error_rate:old.example.com", SevHigh, now.Add(-24*time.Hour))
	if err := s.UpsertAlert(old); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Negative TTL: never resolve.
	amOff := &AlertManager{store: s, logger: quietLogger(), now: time.Now, resolveTTL: -1}
	if got := amOff.ResolveStale(now); got != 0 {
		t.Fatalf("disabled sweep resolved %d, want 0", got)
	}
	row, _, _ := s.GetAlert("old")
	if row.Status != StatusFiring {
		t.Fatalf("disabled sweep should not touch alerts; status=%q", row.Status)
	}

	// Zero TTL: DefaultResolveTTL applies; a 24h-stale alert resolves.
	amDefault := &AlertManager{store: s, logger: quietLogger(), now: time.Now, resolveTTL: 0}
	if got := amDefault.ResolveStale(now); got != 1 {
		t.Fatalf("default-TTL sweep resolved %d, want 1", got)
	}
}
