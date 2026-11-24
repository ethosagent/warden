package sqlite_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	agentsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
)

const issuer = "https://cp.example.test"

type fixture struct {
	t      *testing.T
	path   string
	db     *cpstate.DB
	agents *agentsqlite.Store
	replay *sqlite.Store
	clk    *clocktest.Fake
	v      *tokensvc.AssertionVerifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	migs := append(agentsqlite.Migrations(), sqlite.Migrations()...)
	db, err := cpstate.Open(context.Background(), path, migs)
	if err != nil {
		t.Fatalf("open cpstate: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	f := &fixture{t: t, path: path, db: db, agents: agentsqlite.New(db), replay: sqlite.New(db),
		clk: clocktest.NewFake(time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC))}
	f.v = &tokensvc.AssertionVerifier{Agents: f.agents, Replay: f.replay, Issuer: issuer, Now: f.clk.Now}
	return f
}

func (f *fixture) register(id string, disabled bool) *signer.LocalSigner {
	f.t.Helper()
	ctx := context.Background()
	s, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		f.t.Fatal(err)
	}
	jwk, _ := keys.PublicJWK(s.Public(), keys.AlgEdDSA)
	doc, _ := json.Marshal(jwk)
	a, err := f.agents.Create(ctx, agentreg.Agent{ID: id, AllowedGroups: []string{"eng"}, Keys: []agentreg.Key{{JWK: doc}}}, "admin:test")
	if err != nil {
		f.t.Fatal(err)
	}
	if disabled {
		if _, err := f.agents.SetStatus(ctx, id, agentreg.StatusDisabled, a.Revision, "admin:test"); err != nil {
			f.t.Fatal(err)
		}
	}
	return s
}

func (f *fixture) assertion(s keys.Signer, id, jti string) string {
	f.t.Helper()
	now := f.clk.Now()
	raw, err := keys.SignCompact(context.Background(), s, keys.Header{}, map[string]any{
		"iss": id, "sub": id, "aud": issuer, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": jti,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *fixture) rows() int {
	f.t.Helper()
	var n int
	if err := f.db.SQL().QueryRow(`SELECT COUNT(*) FROM token_assertion_jti`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func TestMigrationRegistered(t *testing.T) {
	f := newFixture(t)
	found := false
	for _, id := range f.db.Applied() {
		found = found || id == sqlite.MigrationID
	}
	if !found {
		t.Fatalf("applied migrations %v lack %s", f.db.Applied(), sqlite.MigrationID)
	}
}

func TestStore_ConsumeIsAtomic(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	exp := f.clk.Now().Add(time.Minute)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := f.replay.Consume(ctx, "a1", "hash", exp)
			if err != nil {
				t.Error(err)
			}
			if ok {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d winners, want 1", wins.Load())
	}
	if ok, err := f.replay.Consume(ctx, "a2", "hash", exp); err != nil || !ok {
		t.Fatalf("same hash, other agent: %v %v", ok, err)
	}
}

func TestStore_ErrorsDoNotLeakValues(t *testing.T) {
	f := newFixture(t)
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := f.replay.Consume(context.Background(), "a1", "secret-hash", time.Now())
	if err == nil {
		t.Fatal("want an error on a closed database")
	}
	if bytes.Contains([]byte(err.Error()), []byte("secret-hash")) {
		t.Fatalf("error leaks the hash: %v", err)
	}
}

func TestAssertionReplay(t *testing.T) {
	f := newFixture(t)
	s := f.register("agent-1", false)
	raw := f.assertion(s, "agent-1", "jti-1")
	var ok, replays atomic.Int64
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.v.VerifyClientAssertion(context.Background(), raw)
			var te *tokensvc.Error
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &te) && te.Reason == tokensvc.ReasonReplay:
				replays.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 || replays.Load() != 49 {
		t.Fatalf("successes %d, replays %d", ok.Load(), replays.Load())
	}
	if _, err := f.v.VerifyClientAssertion(context.Background(), raw); err == nil {
		t.Fatal("sequential reuse must fail")
	}
	if f.rows() != 1 {
		t.Fatalf("rows = %d, want 1", f.rows())
	}
}

func TestAssertionNoRowForDisabledOrUnknown(t *testing.T) {
	f := newFixture(t)
	off := f.register("agent-off", true)
	stranger, _ := signer.GenerateLocal(keys.AlgEdDSA)
	ctx := context.Background()
	_, err := f.v.VerifyClientAssertion(ctx, f.assertion(off, "agent-off", "jti-off"))
	var te *tokensvc.Error
	if !errors.As(err, &te) || te.Reason != tokensvc.ReasonAgentDisabled {
		t.Fatalf("disabled: %v", err)
	}
	_, err = f.v.VerifyClientAssertion(ctx, f.assertion(stranger, "ghost", "jti-ghost"))
	if !errors.As(err, &te) || te.Reason != tokensvc.ReasonAgentUnknown {
		t.Fatalf("unknown: %v", err)
	}
	if f.rows() != 0 {
		t.Fatalf("rows = %d, want 0", f.rows())
	}
}

func TestAssertionJTIPurge(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	s := f.register("agent-1", false)
	const jti = "very-secret-jti-value-0001"
	if _, err := f.v.VerifyClientAssertion(ctx, f.assertion(s, "agent-1", jti)); err != nil {
		t.Fatal(err)
	}
	if f.rows() != 1 {
		t.Fatalf("rows = %d, want 1", f.rows())
	}

	// exp is now+60s and the row lives until exp+60s.
	f.clk.Advance(2 * time.Minute)
	if n, err := f.replay.Purge(ctx, f.clk.Now()); err != nil || n != 0 {
		t.Fatalf("at exp+60s the row must stay: purged %d, %v", n, err)
	}
	f.clk.Advance(time.Second)
	n, err := f.replay.Purge(ctx, f.clk.Now())
	if err != nil || n != 1 {
		t.Fatalf("past exp+60s: purged %d, %v", n, err)
	}
	if f.rows() != 0 {
		t.Fatalf("rows = %d, want 0", f.rows())
	}

	// The database file (and its WAL) never held the raw jti, only its hash.
	if _, err := f.v.VerifyClientAssertion(ctx, f.assertion(s, "agent-1", jti)); err != nil {
		t.Fatalf("after the purge the jti is new again: %v", err)
	}
	for _, name := range []string{f.path, f.path + "-wal"} {
		b, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(jti)) {
			t.Fatalf("%s contains the raw jti", filepath.Base(name))
		}
	}
}
