package sqlite

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/oauthbrokertest"
)

func openDB(t *testing.T) *cpstate.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(context.Background(), path, cpstate.Enable(Migrations(), EnabledMigrationIDs()...))
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestGrantStoreConformance(t *testing.T) {
	oauthbrokertest.Run(t, func(t *testing.T, clk *clocktest.Fake, limits oauthbroker.Limits) oauthbroker.GrantStore {
		return New(openDB(t), Options{Clock: clk, Limits: limits})
	})
}

// TestGrantStoreConformanceSchema pins the three tables' columns (exactly the
// designed set, none named for a token, secret or value) and the index that
// serves the open-pending cap.
func TestGrantStoreConformanceSchema(t *testing.T) {
	db := openDB(t)
	want := map[string][]string{
		"pending_authorizations": {"id", "iss", "sub", "user_key", "agent_id", "provider", "scopes_json", "message",
			"request_method", "request_host", "request_path", "mcp_tool", "status", "reason", "created_at", "expires_at", "completed_at"},
		"connect_attempts": {"state_hash", "pending_id", "iss", "sub", "user_key", "provider", "scopes_json", "verifier",
			"browser_hash", "created_at", "expires_at"},
		"oauth_grants": {"user_key", "iss", "sub", "provider", "grant_id", "prev_grant_id", "state", "scopes_json", "provider_account_id",
			"provider_account_login", "granted_at", "updated_at", "last_used_at", "revoked_at", "last_refresh_at", "last_refresh_status"},
	}
	for table, cols := range want {
		rows, err := db.SQL().Query(`SELECT name, type FROM pragma_table_info(?)`, table)
		if err != nil {
			t.Fatalf("table_info(%s): %v", table, err)
		}
		var got []string
		for rows.Next() {
			var name, typ string
			if err := rows.Scan(&name, &typ); err != nil {
				t.Fatal(err)
			}
			if oauthbrokertest.NamesValue(name) || oauthbrokertest.NamesValue(typ) {
				t.Errorf("%s.%s (%s) names a token, secret or value", table, name, typ)
			}
			if typ == "BLOB" {
				t.Errorf("%s.%s is a BLOB; no column holds opaque bytes", table, name)
			}
			got = append(got, name)
		}
		_ = rows.Close()
		if !slices.Equal(got, cols) {
			t.Errorf("%s columns = %v\nwant %v", table, got, cols)
		}
	}
	var idx []string
	rows, err := db.SQL().Query(`SELECT name FROM pragma_index_info('pending_authorizations_user_open') ORDER BY seqno`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		idx = append(idx, c)
	}
	_ = rows.Close()
	if want := []string{"user_key", "status", "expires_at"}; !slices.Equal(idx, want) {
		t.Errorf("open-pending cap index = %v, want %v", idx, want)
	}
}

// TestMigrationsOptional: the broker migrations are known but not applied
// unless enabled, so a CP without consent.providers creates no table.
func TestMigrationsOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(context.Background(), path, Migrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	var n int
	if err := db.SQL().QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table'
AND name IN ('pending_authorizations','connect_attempts','oauth_grants')`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(db.Applied()) != 0 {
		t.Fatalf("disabled broker created %d tables, applied %v", n, db.Applied())
	}
	_ = db.Close()
	db, err = cpstate.Open(context.Background(), path, cpstate.Enable(Migrations(), EnabledMigrationIDs()...))
	if err != nil {
		t.Fatalf("cpstate.Open (enabled): %v", err)
	}
	defer func() { _ = db.Close() }()
	if got := db.Applied(); !slices.Equal(got, EnabledMigrationIDs()) {
		t.Fatalf("applied = %v, want %v", got, EnabledMigrationIDs())
	}
}

// TestStatusCheckConstraints: the CHECK constraints reject a status or state
// the domain does not define, whatever writes the row.
func TestStatusCheckConstraints(t *testing.T) {
	db := openDB(t)
	if _, err := db.SQL().Exec(`INSERT INTO pending_authorizations (id, iss, sub, user_key, provider, scopes_json, status, created_at, expires_at)
VALUES ('x', 'i', 's', 'u', 'p', '[]', 'approved', 0, 1)`); err == nil {
		t.Error("pending status 'approved' was accepted")
	}
	if _, err := db.SQL().Exec(`INSERT INTO oauth_grants (user_key, iss, sub, provider, grant_id, state, scopes_json, granted_at, updated_at)
VALUES ('u', 'i', 's', 'p', 'g', 'paused', '[]', 0, 0)`); err == nil {
		t.Error("grant state 'paused' was accepted")
	}
}

// TestPendingStoredStatusLazy: GetPending reports expired while the stored row
// still says pending, until Sweep writes it.
func TestPendingStoredStatusLazy(t *testing.T) {
	clk := clocktest.NewFake(oauthbrokertest.Start)
	db := openDB(t)
	s := New(db, Options{Clock: clk})
	ctx := context.Background()
	p, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	stored := func() string {
		var st string
		if err := db.SQL().QueryRow(`SELECT status FROM pending_authorizations WHERE id = ?`, p.ID).Scan(&st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if got, _ := s.GetPending(ctx, p.ID); got.Status != oauthbroker.StatusExpired || stored() != "pending" {
		t.Fatalf("before sweep: read %s, stored %s", got.Status, stored())
	}
	if _, err := s.Sweep(ctx, clk.Now()); err != nil {
		t.Fatal(err)
	}
	if stored() != "expired" {
		t.Fatalf("after sweep stored status = %s", stored())
	}
}

// TestBrokenRandom: a failing entropy source is an error, never a weak id.
func TestBrokenRandom(t *testing.T) {
	s := New(openDB(t), Options{Clock: clocktest.NewFake(oauthbrokertest.Start), Rand: bytes.NewReader(nil)})
	ctx := context.Background()
	if _, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute); err == nil {
		t.Error("CreatePending with no entropy succeeded")
	}
	if _, err := s.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: "u", Iss: "i", Sub: "s", Provider: "google"}); err == nil {
		t.Error("BeginGrant with no entropy succeeded")
	}
}

// TestIDCollisionRetries: a repeated random id retries with a fresh one, and a
// source that only repeats gives up with an error.
func TestIDCollisionRetries(t *testing.T) {
	same := bytes.Repeat([]byte{7}, idBytes)
	fresh := bytes.Repeat([]byte{9}, idBytes)
	s := New(openDB(t), Options{Clock: clocktest.NewFake(oauthbrokertest.Start),
		Rand: bytes.NewReader(slices.Concat(same, same, fresh, same, same, same, same, same))})
	ctx := context.Background()
	a, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute)
	if err != nil {
		t.Fatalf("collision did not retry: %v", err)
	}
	if a.ID == b.ID {
		t.Fatal("ids repeat")
	}
	if _, err := s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute); err == nil || errors.Is(err, oauthbroker.ErrTooMany) {
		t.Fatalf("only-colliding source: err = %v, want a broken-random error", err)
	}
}

// TestStoreErrorsWrapped: a closed database surfaces as a wrapped error from
// every method, never as ErrNotFound.
func TestStoreErrorsWrapped(t *testing.T) {
	db := openDB(t)
	s := New(db, Options{Clock: clocktest.NewFake(oauthbrokertest.Start)})
	_ = db.Close()
	ctx := context.Background()
	uk := "u"
	errs := map[string]error{}
	_, errs["CreatePending"] = s.CreatePending(ctx, oauthbrokertest.NewPending("alice", "google"), time.Minute)
	_, errs["GetPending"] = s.GetPending(ctx, "x")
	errs["CompletePending"] = s.CompletePending(ctx, "x", oauthbroker.StatusDenied, "")
	_, errs["CreateAttempt"] = s.CreateAttempt(ctx, oauthbrokertest.NewAttempt("alice", "google", "", 1))
	_, errs["ConsumeAttempt"] = s.ConsumeAttempt(ctx, oauthbroker.HashState("s"))
	_, errs["BeginGrant"] = s.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: uk, Iss: "i", Sub: "s", Provider: "p"})
	_, errs["ActivateGrant"] = s.ActivateGrant(ctx, "g", nil, oauthbroker.Account{})
	_, errs["MarkReconsentRequired"] = s.MarkReconsentRequired(ctx, uk, "p", "g")
	_, errs["RestoreGrant"] = s.RestoreGrant(ctx, uk, "p", "g", "h")
	_, errs["RevokeGrant"] = s.RevokeGrant(ctx, uk, "p", "")
	_, errs["GetGrant"] = s.GetGrant(ctx, uk, "p")
	_, errs["ListGrants"] = s.ListGrants(ctx, uk, true)
	errs["TouchLastUsed"] = s.TouchLastUsed(ctx, uk, "p", time.Now())
	_, errs["Sweep"] = s.Sweep(ctx, time.Now())
	for name, err := range errs {
		if err == nil || errors.Is(err, oauthbroker.ErrNotFound) {
			t.Errorf("%s on a closed DB: err = %v, want a wrapped store error", name, err)
		}
	}
	ch, cancel := s.Subscribe("x")
	defer cancel()
	select {
	case <-ch:
		t.Error("Subscribe on a read error closed the channel; the waiter must stay registered")
	default:
	}
}

// TestTouchThrottleBounded: the in-memory throttle never grows past its cap.
func TestTouchThrottleBounded(t *testing.T) {
	s := New(openDB(t), Options{Clock: clocktest.NewFake(oauthbrokertest.Start)})
	at := oauthbrokertest.Start
	for i := range maxTouchEntries + 10 {
		s.rememberTouch(string(rune(i))+"k", at)
	}
	if n := len(s.touched); n > maxTouchEntries {
		t.Fatalf("throttle holds %d entries, cap %d", n, maxTouchEntries)
	}
	s.rememberTouch("late", at.Add(2*oauthbroker.TouchInterval))
	if _, ok := s.touched["late"]; !ok {
		t.Fatal("newest entry dropped")
	}
}

// TestDefaultLimits: a store built without Limits enforces the documented caps.
func TestDefaultLimits(t *testing.T) {
	s := New(openDB(t), Options{})
	want := oauthbroker.Limits{MaxOpenPendingsPerUser: 20, MaxOpenAttemptsPerUser: 20, MaxLiveAttempts: 10000}
	if s.limits != want {
		t.Fatalf("limits = %+v, want %+v", s.limits, want)
	}
	if got := (oauthbroker.Limits{MaxLiveAttempts: 5}).WithDefaults(); got.MaxLiveAttempts != 5 || got.MaxOpenPendingsPerUser != 20 {
		t.Fatalf("WithDefaults = %+v", got)
	}
}

// TestRecordRefresh: the refresh bookkeeping columns (oauthbroker/0004) are set
// only on the row that still holds the grant id, accept only the closed status
// words, and are read back through GetGrant.
func TestRecordRefresh(t *testing.T) {
	ctx := context.Background()
	clk := clocktest.NewFake(oauthbrokertest.Start)
	s := New(openDB(t), Options{Clock: clk})
	g, err := s.BeginGrant(ctx, oauthbroker.GrantRef{UserKey: "u1", Iss: "https://idp.example.test", Sub: "s", Provider: "google"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ActivateGrant(ctx, g.GrantID, []string{"a"}, oauthbroker.Account{}); err != nil {
		t.Fatal(err)
	}
	at := clk.Now().Add(time.Minute)
	if err := s.RecordRefresh(ctx, "u1", "google", g.GrantID, oauthbroker.RefreshStatusWritebackFailed, at); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGrant(ctx, "u1", "google")
	if err != nil {
		t.Fatal(err)
	}
	if got.LastRefreshStatus != oauthbroker.RefreshStatusWritebackFailed || !got.LastRefreshAt.Equal(at) {
		t.Fatalf("last refresh = %v %q", got.LastRefreshAt, got.LastRefreshStatus)
	}
	if err := s.RecordRefresh(ctx, "u1", "google", "other-grant", oauthbroker.RefreshStatusOK, at); !errors.Is(err, oauthbroker.ErrNotFound) {
		t.Fatalf("a stale grant id stamped the row: %v", err)
	}
	if err := s.RecordRefresh(ctx, "u1", "google", g.GrantID, "free text", at); !errors.Is(err, oauthbroker.ErrInvalid) {
		t.Fatalf("an unknown status was accepted: %v", err)
	}
	var _ oauthbroker.RefreshRecorder = s
}
