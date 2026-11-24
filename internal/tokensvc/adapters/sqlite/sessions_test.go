package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
)

var policy = tokensvc.SessionPolicy{Idle: 12 * time.Hour, Absolute: 7 * 24 * time.Hour}

func newSessions(t *testing.T) (*sqlite.Sessions, *cpstate.DB) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), sqlite.SessionMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.NewSessions(db), db
}

func TestSessionsTouch(t *testing.T) {
	ctx := context.Background()
	s, _ := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := tokensvc.SessionKey{IdPIss: "https://idp", Sub: "u1", AgentID: "a1"}

	first, err := s.Touch(ctx, key, t0.Add(-time.Minute), t0, policy, "wts_1")
	if err != nil || first != "wts_1" {
		t.Fatalf("first = %q, %v", first, err)
	}
	// Reuse within the idle window keeps the sid and moves last_used_at.
	for _, at := range []time.Duration{time.Hour, 12 * time.Hour, 23 * time.Hour} {
		got, err := s.Touch(ctx, key, t0, t0.Add(at), policy, "wts_other")
		if err != nil || got != "wts_1" {
			t.Fatalf("at %s: sid = %q, %v", at, got, err)
		}
	}
	// Idle for 12h+1s: a new session; the old one is gone, not revoked.
	got, err := s.Touch(ctx, key, t0, t0.Add(23*time.Hour+12*time.Hour+time.Second), policy, "wts_2")
	if err != nil || got != "wts_2" {
		t.Fatalf("after idle: %q, %v", got, err)
	}
	// Another key is independent.
	other, err := s.Touch(ctx, tokensvc.SessionKey{IdPIss: "https://idp", Sub: "u1", AgentID: "a2"}, t0, t0, policy, "wts_3")
	if err != nil || other != "wts_3" {
		t.Fatalf("other agent: %q, %v", other, err)
	}
}

func TestSessionsAbsoluteLifetime(t *testing.T) {
	ctx := context.Background()
	s, _ := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := tokensvc.SessionKey{IdPIss: "i", Sub: "u", AgentID: "a"}
	if _, err := s.Touch(ctx, key, t0, t0, policy, "wts_1"); err != nil {
		t.Fatal(err)
	}
	// Used every 6h, so never idle, until the 7d cap.
	at := t0
	for at.Before(t0.Add(7 * 24 * time.Hour)) {
		at = at.Add(6 * time.Hour)
		if at.After(t0.Add(7 * 24 * time.Hour)) {
			break
		}
		got, err := s.Touch(ctx, key, at, at, policy, "wts_x")
		if err != nil || got != "wts_1" {
			t.Fatalf("at %s: %q, %v", at.Sub(t0), got, err)
		}
	}
	got, err := s.Touch(ctx, key, at, t0.Add(7*24*time.Hour+time.Second), policy, "wts_2")
	if err != nil || got != "wts_2" {
		t.Fatalf("after absolute lifetime: %q, %v", got, err)
	}
}

func TestSessionsRevoke(t *testing.T) {
	ctx := context.Background()
	s, db := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := tokensvc.SessionKey{IdPIss: "i", Sub: "u", AgentID: "a"}
	if _, err := s.Touch(ctx, key, t0, t0, policy, "wts_1"); err != nil {
		t.Fatal(err)
	}
	if found, err := s.Revoke(ctx, "wts_missing", t0); err != nil || found {
		t.Fatalf("Revoke(unknown) = %v, %v", found, err)
	}
	revokedAt := t0.Add(time.Hour)
	if found, err := s.Revoke(ctx, "wts_1", revokedAt); err != nil || !found {
		t.Fatalf("Revoke = %v, %v", found, err)
	}
	// Revoking again keeps the first revoked_at and still reports found.
	if found, err := s.Revoke(ctx, "wts_1", revokedAt.Add(time.Hour)); err != nil || !found {
		t.Fatalf("second Revoke = %v, %v", found, err)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM token_sessions WHERE sid='wts_1' AND revoked_at = ?`, revokedAt.Unix()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("revoked row = %d, %v (the row must stay, with its first revoked_at)", n, err)
	}

	now := revokedAt.Add(time.Minute)
	// Issued at or before the revoke: refused.
	for _, issued := range []time.Time{t0, revokedAt.Add(-time.Second), revokedAt} {
		if _, err := s.Touch(ctx, key, issued, now, policy, "wts_2"); !errors.Is(err, tokensvc.ErrSessionRevoked) {
			t.Fatalf("issued %s: err = %v, want ErrSessionRevoked", issued.Sub(t0), err)
		}
	}
	// Issued after: a new session.
	got, err := s.Touch(ctx, key, revokedAt.Add(time.Second), now, policy, "wts_2")
	if err != nil || got != "wts_2" {
		t.Fatalf("new sign-in: %q, %v", got, err)
	}
	// And that session is the live one for later exchanges, whatever their iat.
	got, err = s.Touch(ctx, key, t0, now.Add(time.Minute), policy, "wts_3")
	if err != nil || got != "wts_2" {
		t.Fatalf("reuse: %q, %v", got, err)
	}
}

func TestSessionsRevokeAll(t *testing.T) {
	ctx := context.Background()
	s, _ := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i, k := range []tokensvc.SessionKey{
		{IdPIss: "i", Sub: "u1", AgentID: "a1"}, {IdPIss: "i", Sub: "u2", AgentID: "a1"},
		{IdPIss: "i", Sub: "u1", AgentID: "a2"}, {IdPIss: "j", Sub: "u1", AgentID: "a1"},
	} {
		if _, err := s.Touch(ctx, k, t0, t0, policy, fmt.Sprintf("wts_%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RevokeAll(ctx, tokensvc.SessionFilter{}, t0); err == nil {
		t.Fatal("empty filter accepted")
	}
	at := t0.Add(time.Minute)
	for _, tc := range []struct {
		f    tokensvc.SessionFilter
		want int64
	}{
		{tokensvc.SessionFilter{AgentID: "a2"}, 1},
		{tokensvc.SessionFilter{AgentID: "a2"}, 0}, // already revoked
		{tokensvc.SessionFilter{Sub: "u2"}, 1},
		{tokensvc.SessionFilter{IdPIss: "i", Sub: "u1"}, 1},
		{tokensvc.SessionFilter{IdPIss: "j"}, 1},
	} {
		if n, err := s.RevokeAll(ctx, tc.f, at); err != nil || n != tc.want {
			t.Fatalf("RevokeAll(%+v) = %d, %v, want %d", tc.f, n, err, tc.want)
		}
	}
}

func TestSessionsPurge(t *testing.T) {
	ctx := context.Background()
	s, _ := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		k := tokensvc.SessionKey{IdPIss: "i", Sub: fmt.Sprintf("u%d", i), AgentID: "a"}
		if _, err := s.Touch(ctx, k, t0, t0, policy, fmt.Sprintf("wts_%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	// u1 is used later; u2 is revoked later: both survive a purge at t0+1h.
	if _, err := s.Touch(ctx, tokensvc.SessionKey{IdPIss: "i", Sub: "u1", AgentID: "a"}, t0, t0.Add(2*time.Hour), policy, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Revoke(ctx, "wts_2", t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Purge(ctx, t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v, want 1 (wts_0)", n, err)
	}
	if n, err := s.Purge(ctx, t0.Add(3*time.Hour)); err != nil || n != 2 {
		t.Fatalf("second Purge = %d, %v, want 2", n, err)
	}
}

func TestSessionsConcurrentTouchOneSession(t *testing.T) {
	ctx := context.Background()
	s, _ := newSessions(t)
	t0 := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	key := tokensvc.SessionKey{IdPIss: "i", Sub: "u", AgentID: "a"}
	var wg sync.WaitGroup
	sids := make(chan string, 30)
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sid, err := s.Touch(ctx, key, t0, t0, policy, fmt.Sprintf("wts_%d", i))
			if err != nil {
				t.Error(err)
				return
			}
			sids <- sid
		}()
	}
	wg.Wait()
	close(sids)
	seen := map[string]bool{}
	for sid := range sids {
		seen[sid] = true
	}
	if len(seen) != 1 {
		t.Fatalf("%d sessions for one key", len(seen))
	}
}

func TestSessionsStoreErrors(t *testing.T) {
	ctx := context.Background()
	s, db := newSessions(t)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.Touch(ctx, tokensvc.SessionKey{}, now, now, policy, "x"); err == nil {
		t.Error("Touch on a closed db")
	}
	if _, err := s.Revoke(ctx, "x", now); err == nil {
		t.Error("Revoke on a closed db")
	}
	if _, err := s.RevokeAll(ctx, tokensvc.SessionFilter{Sub: "u"}, now); err == nil {
		t.Error("RevokeAll on a closed db")
	}
	if _, err := s.Purge(ctx, now); err == nil {
		t.Error("Purge on a closed db")
	}
}
