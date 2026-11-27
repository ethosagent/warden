package oauthbroker_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/adapters/sqlite"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
)

func newSQLiteStore(t *testing.T, clk *clocktest.Fake) *sqlite.Store {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"),
		cpstate.Enable(sqlite.Migrations(), sqlite.EnabledMigrationIDs()...))
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.New(db, sqlite.Options{Clock: clk})
}

// TestPendingExpiry: a pending past expires_at reads as expired before any
// sweep; after Sweep its stored status is expired and a Subscribe channel for
// it is closed within 1s.
func TestPendingExpiry(t *testing.T) {
	clk := clocktest.NewFake(oauthbrokertest.Start)
	s := newSQLiteStore(t, clk)
	ctx := context.Background()
	p, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google", "drive.readonly"), 15*time.Minute)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	ch, cancel := s.Subscribe(p.ID)
	defer cancel()

	clk.Advance(15 * time.Minute)
	got, err := s.GetPending(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetPending: %v", err)
	}
	if got.Status != oauthbroker.StatusExpired {
		t.Fatalf("status before sweep = %s, want expired", got.Status)
	}
	select {
	case <-ch:
		t.Fatal("waiter woke before the sweep")
	default:
	}

	res, err := s.Sweep(ctx, clk.Now())
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.PendingsExpired != 1 {
		t.Fatalf("Sweep expired %d pendings, want 1", res.PendingsExpired)
	}
	if st := oauthbrokertest.Received(t, ch); st != oauthbroker.StatusExpired {
		t.Fatalf("waiter got %q, want expired", st)
	}
	got, err = s.GetPending(ctx, p.ID)
	if err != nil || got.Status != oauthbroker.StatusExpired || got.CompletedAt.IsZero() {
		t.Fatalf("stored pending after sweep = %+v, %v", got, err)
	}
	// The stored status is now expired, so a CompletePending loses.
	if err := s.CompletePending(ctx, p.ID, oauthbroker.StatusGranted, ""); err == nil {
		t.Fatal("CompletePending on an expired pending succeeded")
	}
}

// TestAttemptNeverPrintsVerifier: String, GoString, %+v and slog output carry
// at most 8 characters of the state hash and never the verifier.
func TestAttemptNeverPrintsVerifier(t *testing.T) {
	a := oauthbrokertest.NewAttempt("alice", "google", "pend-1", 1)
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("attempt", "attempt", a)
	for _, out := range []string{a.String(), fmt.Sprintf("%v", a), fmt.Sprintf("%+v", a), fmt.Sprintf("%#v", a), buf.String()} {
		if strings.Contains(out, a.Verifier) || strings.Contains(out, a.StateHash) || strings.Contains(out, a.BrowserHash) {
			t.Errorf("output leaks the verifier or a full hash: %s", out)
		}
		if !strings.Contains(out, a.StateHash[:8]) {
			t.Errorf("output lacks the short state hash: %s", out)
		}
	}
	if got := oauthbroker.ShortHash("abc"); got != "abc" {
		t.Errorf("ShortHash(short) = %q", got)
	}
}

func TestCanonicalScopes(t *testing.T) {
	got := oauthbroker.CanonicalScopes([]string{"repo", "", "read:user", "repo"})
	if !slices.Equal(got, []string{"read:user", "repo"}) {
		t.Fatalf("CanonicalScopes = %v", got)
	}
	if got := oauthbroker.CanonicalScopes(nil); got == nil || len(got) != 0 {
		t.Fatalf("CanonicalScopes(nil) = %#v, want empty non-nil", got)
	}
}

func TestHashes(t *testing.T) {
	// SHA-256("abc"), FIPS 180-2 appendix B.1.
	const abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := oauthbroker.HashState("abc"); got != abc {
		t.Fatalf("HashState = %s", got)
	}
	if got := oauthbroker.HashBrowserBinding("abc"); got != abc {
		t.Fatalf("HashBrowserBinding = %s", got)
	}
}

func TestStatusTerminal(t *testing.T) {
	for st, want := range map[oauthbroker.PendingStatus]bool{
		oauthbroker.StatusPending: false, oauthbroker.StatusGranted: true,
		oauthbroker.StatusDenied: true, oauthbroker.StatusExpired: true, "other": false,
	} {
		if st.Terminal() != want {
			t.Errorf("%q.Terminal() = %v", st, !want)
		}
	}
}

func TestValidateBounds(t *testing.T) {
	long := strings.Repeat("x", 600)
	p := oauthbrokertest.NewPending("alice", "google")
	p.AgentID = long
	if err := oauthbroker.ValidatePending(p, time.Minute); err == nil {
		t.Error("over-long agent_id accepted")
	}
	p = oauthbrokertest.NewPending("alice", "google")
	p.Scopes = make([]string, 65)
	for i := range p.Scopes {
		p.Scopes[i] = fmt.Sprintf("s%d", i)
	}
	if err := oauthbroker.ValidatePending(p, time.Minute); err == nil {
		t.Error("65 scopes accepted")
	}
	p = oauthbrokertest.NewPending("alice", "google")
	p.Request.Host = strings.Repeat("h", 3000)
	if err := oauthbroker.ValidatePending(p, time.Minute); err == nil {
		t.Error("over-long request_host accepted")
	}
	a := oauthbrokertest.NewAttempt("alice", "google", long, 1)
	if err := oauthbroker.ValidateAttempt(a); err == nil {
		t.Error("over-long pending_id accepted")
	}
	a = oauthbrokertest.NewAttempt("alice", "google", "", 1)
	a.Verifier = strings.Repeat("v", 129)
	if err := oauthbroker.ValidateAttempt(a); err == nil {
		t.Error("129-character verifier accepted")
	}
	if err := oauthbroker.ValidateAccount([]string{"a"}, oauthbroker.Account{Login: long}); err == nil {
		t.Error("over-long account login accepted")
	}
	if err := oauthbroker.ValidateGrantRef(oauthbroker.GrantRef{UserKey: "u", Iss: "i", Sub: long, Provider: "p"}); err == nil {
		t.Error("over-long sub accepted")
	}
}
