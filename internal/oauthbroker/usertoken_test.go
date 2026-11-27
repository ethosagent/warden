package oauthbroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

const (
	utUser     = "0123456789abcdef0123456789abcdef"
	utProvider = "prov"
	utAccess0  = "ut-access-0-SECRET"
	utRefresh0 = "ut-refresh-0-SECRET"
	utSecret   = "ut-client-secret-SECRET"
)

var utStart = time.Unix(1_800_000_000, 0)

// utClock is a settable clock.
type utClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *utClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *utClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// utRecords is an in-memory GrantRecords with versioned compare-and-swap
// semantics and injectable failures.
type utRecords struct {
	mu      sync.Mutex
	rec     TokenRecord
	exists  bool
	version int64
	loadErr error
	putErr  error
	puts    int // StoreRotated calls, including failed ones
	writes  int // successful writes
	readVer []GrantVersion
}

func (r *utRecords) LoadGrant(_ context.Context, _, _ string) (TokenRecord, GrantVersion, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loadErr != nil {
		return TokenRecord{}, GrantVersion{}, r.loadErr
	}
	if !r.exists {
		return TokenRecord{}, GrantVersion{}, ErrGrantMissing
	}
	return r.rec, GrantVersion{N: r.version, Versioned: true, GrantID: r.rec.GrantID}, nil
}

func (r *utRecords) StoreRotated(_ context.Context, _, _ string, rec TokenRecord, read GrantVersion) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts++
	r.readVer = append(r.readVer, read)
	if r.putErr != nil {
		return r.putErr
	}
	if !r.exists || r.rec.GrantID != read.GrantID || r.version != read.N {
		return ErrGrantChanged
	}
	r.rec, r.version = rec, r.version+1
	r.writes++
	return nil
}

func (r *utRecords) snapshot() (TokenRecord, bool, int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rec, r.exists, r.puts, r.writes
}

func (r *utRecords) del() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exists = false
}

// utGrants is the metadata port: GetGrant, MarkReconsentRequired and
// RecordRefresh are real; every other method panics (the engine must not call
// it).
type utGrants struct {
	GrantStore
	mu       sync.Mutex
	grant    Grant
	missing  bool
	getErr   error
	reconsts int
	stamps   []string
}

func (g *utGrants) GetGrant(context.Context, string, string) (Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.getErr != nil {
		return Grant{}, g.getErr
	}
	if g.missing {
		return Grant{}, ErrNotFound
	}
	return g.grant, nil
}

func (g *utGrants) MarkReconsentRequired(_ context.Context, _, _, grantID string) (Grant, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.grant.GrantID != grantID {
		return Grant{}, ErrGrantState
	}
	g.grant.State = GrantReconsentRequired
	g.reconsts++
	return g.grant, nil
}

func (g *utGrants) RecordRefresh(_ context.Context, _, _, _, status string, _ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stamps = append(g.stamps, status)
	return nil
}

func (g *utGrants) state() GrantState { g.mu.Lock(); defer g.mu.Unlock(); return g.grant.State }
func (g *utGrants) lastStamp() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.stamps) == 0 {
		return ""
	}
	return g.stamps[len(g.stamps)-1]
}

type utMetrics struct {
	mu        sync.Mutex
	counts    map[string]int
	writeFail int
}

func (m *utMetrics) RecordCPUserTokenRefresh(provider, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.counts == nil {
		m.counts = map[string]int{}
	}
	m.counts[provider+"/"+outcome]++
}
func (m *utMetrics) RecordCPUserTokenWritebackFailure() { m.mu.Lock(); m.writeFail++; m.mu.Unlock() }
func (m *utMetrics) count(k string) int                 { m.mu.Lock(); defer m.mu.Unlock(); return m.counts[k] }

type utAlerter struct {
	mu   sync.Mutex
	keys []string
}

func (a *utAlerter) WritebackFailed(userKey, provider string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys = append(a.keys, userKey+"/"+provider)
}

// utEnv wires an Engine to a fake provider token endpoint.
type utEnv struct {
	e       *Engine
	clk     *utClock
	recs    *utRecords
	grants  *utGrants
	metrics *utMetrics
	alerter *utAlerter
	logs    *bytes.Buffer
	srv     *httptest.Server
	hits    atomic.Int32
	reply   atomic.Value // func(w http.ResponseWriter, n int)
	slept   []time.Duration
	smu     sync.Mutex
}

func rotating(n int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"access_token":"ut-access-%d-SECRET","refresh_token":"ut-refresh-%d-SECRET","expires_in":3600,"scope":"a b"}`, n, n)
}

func newUTEnv(t *testing.T, typ string) *utEnv {
	t.Helper()
	env := &utEnv{clk: &utClock{t: utStart}, recs: &utRecords{}, metrics: &utMetrics{}, alerter: &utAlerter{}, logs: &bytes.Buffer{}}
	env.reply.Store(func(w http.ResponseWriter, n int) { rotating(n, w) })
	env.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(env.hits.Add(1))
		env.reply.Load().(func(http.ResponseWriter, int))(w, n)
	}))
	t.Cleanup(env.srv.Close)
	cfg := config.OAuthProviderConfig{ID: utProvider, Type: typ, ClientID: "cid", ClientSecretEnv: "SEC", TokenURL: env.srv.URL + "/token", AllowedScopes: []string{"a", "b", "c"}}
	if typ == config.OAuthProviderGitHubApp {
		cfg.AllowedScopes = nil
	}
	logger := slog.New(slog.NewJSONHandler(env.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg, err := NewRegistry([]config.OAuthProviderConfig{cfg}, Options{
		LookupEnv: func(string) (string, bool) { return utSecret, true },
		Now:       env.clk.Now, HTTPClient: testPoster{}, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.grants = &utGrants{grant: Grant{UserKey: utUser, Provider: utProvider, GrantID: "g1", State: GrantActive, Scopes: []string{"a", "b"}}}
	env.recs.rec = TokenRecord{V: 1, GrantID: "g1", Provider: utProvider, ClientID: "cid", TokenType: "Bearer",
		AccessToken: utAccess0, RefreshToken: utRefresh0, Scope: "a b",
		Expiry: utStart.Unix() - 10, ObtainedAt: utStart.Unix() - 3610}
	env.recs.exists, env.recs.version = true, 1
	e, err := NewEngine(EngineConfig{
		Registry: reg, Grants: env.grants, Records: env.recs, Locks: NewGrantLocks(),
		Metrics: env.metrics, Alerter: env.alerter, Now: env.clk.Now, Logger: logger,
		Sleep: func(_ context.Context, d time.Duration) {
			env.smu.Lock()
			env.slept = append(env.slept, d)
			env.smu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	env.e = e
	return env
}

func (u *utEnv) token(t *testing.T, force bool, staleRef string, need ...string) (Minted, error) {
	t.Helper()
	return u.e.Token(context.Background(), utUser, utProvider, need, force, staleRef)
}

func (u *utEnv) mustToken(t *testing.T, force bool, staleRef string) Minted {
	t.Helper()
	m, err := u.token(t, force, staleRef, "a")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return m
}

func (u *utEnv) assertClean(t *testing.T) {
	t.Helper()
	for _, s := range []string{utAccess0, utRefresh0, utSecret, "ut-access-1-SECRET", "ut-refresh-1-SECRET", "ut-access-2-SECRET", "ut-refresh-2-SECRET", "SENSITIVE-DESCRIPTION"} {
		if strings.Contains(u.logs.String(), s) {
			t.Errorf("log leaks %q", s)
		}
	}
}

func TestEngineSingleflight(t *testing.T) {
	env := newUTEnv(t, "google")
	release := make(chan struct{})
	env.e.testHook = func(string, string) { <-release }
	const n = 100
	var wg sync.WaitGroup
	toks := make([]Minted, n)
	errs := make([]error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], errs[i] = env.token(t, false, "", "a")
		}()
	}
	// Let every caller reach the flight, then release the one refresh.
	deadline := time.Now().Add(5 * time.Second)
	for env.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if toks[i].AccessToken != toks[0].AccessToken || toks[i].Ref != toks[0].Ref {
			t.Fatalf("caller %d got a different token", i)
		}
	}
	if got := env.hits.Load(); got != 1 {
		t.Fatalf("provider refreshes = %d, want exactly 1", got)
	}
	env.assertClean(t)
}

func TestEngineRotatedRefreshTokenIsWrittenOnceBeforeReturn(t *testing.T) {
	env := newUTEnv(t, "google")
	m := env.mustToken(t, false, "")
	rec, _, puts, writes := env.recs.snapshot()
	if puts != 1 || writes != 1 {
		t.Fatalf("puts=%d writes=%d, want exactly one write", puts, writes)
	}
	if rec.RefreshToken != "ut-refresh-1-SECRET" || rec.AccessToken != m.AccessToken {
		t.Fatalf("stored record not the rotated one")
	}
	if env.grants.lastStamp() != RefreshStatusOK {
		t.Fatalf("last_refresh_status = %q", env.grants.lastStamp())
	}
	// Served again from the cache: no second refresh, no write.
	env.mustToken(t, false, "")
	if env.hits.Load() != 1 {
		t.Fatalf("cache hit refreshed again")
	}
	if env.metrics.count(utProvider+"/refreshed") != 1 || env.metrics.count(utProvider+"/cache") != 1 {
		t.Fatalf("counts = %v", env.metrics.counts)
	}
	env.assertClean(t)
}

func TestEngineResponseWithoutRefreshTokenWritesNothing(t *testing.T) {
	env := newUTEnv(t, "google")
	env.reply.Store(func(w http.ResponseWriter, n int) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"ut-access-%d-SECRET","expires_in":3600}`, n)
	})
	m := env.mustToken(t, false, "")
	rec, _, puts, _ := env.recs.snapshot()
	if puts != 0 {
		t.Fatalf("puts = %d, want 0", puts)
	}
	if rec.RefreshToken != utRefresh0 {
		t.Fatalf("stored refresh token changed")
	}
	// The in-memory record keeps the stored refresh token.
	env.clk.Add(2 * time.Hour)
	m2 := env.mustToken(t, false, "")
	if m2.Ref == m.Ref || env.hits.Load() != 2 {
		t.Fatalf("expected a second refresh after expiry")
	}
	if r, _, puts, _ := env.recs.snapshot(); puts != 0 || r.RefreshToken != utRefresh0 {
		t.Fatalf("second refresh wrote")
	}
}

func TestEngineStoredTokenWithTimeLeftIsReused(t *testing.T) {
	env := newUTEnv(t, "google")
	env.recs.rec.Expiry = utStart.Unix() + 61
	m := env.mustToken(t, false, "")
	if m.AccessToken != utAccess0 || env.hits.Load() != 0 {
		t.Fatalf("stored token with 61s left was not reused")
	}
	if m.ExpiresIn != 61 {
		t.Fatalf("ExpiresIn = %d, want 61", m.ExpiresIn)
	}
	env.clk.Add(2 * time.Second) // 59s left: refresh
	m = env.mustToken(t, false, "")
	if m.AccessToken == utAccess0 || env.hits.Load() != 1 {
		t.Fatalf("token with under 60s left was not refreshed")
	}
}

func TestEngineInvalidGrantMarksReconsentKeepsRow(t *testing.T) {
	env := newUTEnv(t, "google")
	env.reply.Store(func(w http.ResponseWriter, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_grant","error_description":"SENSITIVE-DESCRIPTION"}`)
	})
	_, err := env.token(t, false, "", "a")
	if !errors.Is(err, ErrReconsentRequired) {
		t.Fatalf("err = %v, want ErrReconsentRequired", err)
	}
	if env.grants.state() != GrantReconsentRequired || env.grants.lastStamp() != RefreshStatusInvalidGrant {
		t.Fatalf("state=%s stamp=%s", env.grants.state(), env.grants.lastStamp())
	}
	if _, exists, _, _ := env.recs.snapshot(); !exists {
		t.Fatalf("the stored record was deleted")
	}
	// A second call answers from the row without another provider call.
	before := env.hits.Load()
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrReconsentRequired) || env.hits.Load() != before {
		t.Fatalf("second call: err=%v hits=%d", err, env.hits.Load())
	}
	if env.metrics.count(utProvider+"/reconsent_required") != 2 {
		t.Fatalf("counts = %v", env.metrics.counts)
	}
	env.assertClean(t)
}

func TestEngineOutagesAreUnavailableNotReconsent(t *testing.T) {
	cases := map[string]func(*utEnv){
		"provider 503": func(env *utEnv) {
			env.reply.Store(func(w http.ResponseWriter, _ int) { w.WriteHeader(503) })
		},
		"provider invalid_client": func(env *utEnv) {
			env.reply.Store(func(w http.ResponseWriter, _ int) {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"invalid_client"}`)
			})
		},
		"store read 500": func(env *utEnv) { env.recs.loadErr = errors.New("store 500") },
		"grant row read": func(env *utEnv) { env.grants.getErr = errors.New("db locked") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			env := newUTEnv(t, "google")
			setup(env)
			_, err := env.token(t, false, "", "a")
			if !errors.Is(err, ErrTokenUnavailable) {
				t.Fatalf("err = %v, want ErrTokenUnavailable", err)
			}
			if errors.Is(err, ErrGrantMissing) || errors.Is(err, ErrReconsentRequired) {
				t.Fatalf("outage classified as a grant problem: %v", err)
			}
			if env.grants.state() != GrantActive {
				t.Fatalf("state = %s, want active", env.grants.state())
			}
			env.assertClean(t)
		})
	}
}

func TestEngineGrantMissingAndScopes(t *testing.T) {
	env := newUTEnv(t, "google")
	env.recs.exists = false
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrGrantMissing) {
		t.Fatalf("no record: err = %v", err)
	}
	env = newUTEnv(t, "google")
	env.grants.missing = true
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrGrantMissing) {
		t.Fatalf("no row: err = %v", err)
	}
	env = newUTEnv(t, "google")
	env.grants.grant.State = GrantRevoked
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrGrantMissing) {
		t.Fatalf("revoked: err = %v", err)
	}
	env = newUTEnv(t, "google")
	if _, err := env.token(t, false, "", "a", "c"); !errors.Is(err, ErrScopeInsufficient) {
		t.Fatalf("missing scope: err = %v", err)
	}
	// The same cached token still serves a caller whose scopes it covers.
	if _, err := env.token(t, false, "", "a", "b"); err != nil {
		t.Fatalf("covered scopes: %v", err)
	}
}

func TestEngineConnectingWithPrevGrantIsUnavailable(t *testing.T) {
	env := newUTEnv(t, "google")
	env.grants.grant.State, env.grants.grant.PrevGrantID = GrantConnecting, "g1"
	env.grants.grant.GrantID = "g2"
	_, err := env.token(t, false, "", "a")
	if !errors.Is(err, ErrTokenUnavailable) || errors.Is(err, ErrGrantMissing) {
		t.Fatalf("err = %v, want ErrTokenUnavailable", err)
	}
	if env.hits.Load() != 0 {
		t.Fatalf("a mid-reconnect grant triggered a refresh")
	}
}

func TestEngineRecordOfAnotherGrantIsNeverServed(t *testing.T) {
	env := newUTEnv(t, "google")
	env.recs.rec.GrantID = "other"
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrTokenUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestEngineRevokeRace(t *testing.T) {
	env := newUTEnv(t, "google")
	entered, release := make(chan struct{}), make(chan struct{})
	env.e.testHook = func(string, string) { close(entered); <-release }

	tokErr := make(chan error, 1)
	go func() { _, err := env.token(t, false, "", "a"); tokErr <- err }()
	<-entered

	revokeDone := make(chan error, 1)
	go func() {
		revokeDone <- env.e.WithGrantLock(utUser, utProvider, func() error {
			env.recs.del()
			env.grants.mu.Lock()
			env.grants.grant.State = GrantRevoked
			env.grants.mu.Unlock()
			return nil
		})
	}()
	select {
	case <-revokeDone:
		t.Fatal("revoke ran while the refresh held the grant lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-tokErr; err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := <-revokeDone; err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, exists, _, _ := env.recs.snapshot(); exists {
		t.Fatal("the record was restored by the refresh")
	}
	// Nothing is served from a dropped cache afterwards.
	if _, err := env.token(t, false, "", "a"); !errors.Is(err, ErrGrantMissing) {
		t.Fatalf("after revoke: err = %v, want ErrGrantMissing", err)
	}
}

func TestEngineReconnectDuringRefreshDropsRotatedToken(t *testing.T) {
	env := newUTEnv(t, "google")
	env.e.testHook = func(string, string) {
		// A reconnect that bypassed the lock (defence in depth): a new grant.
		env.recs.mu.Lock()
		env.recs.rec.GrantID, env.recs.rec.AccessToken, env.recs.rec.RefreshToken = "g2", "ut-access-new-SECRET", "ut-refresh-new-SECRET"
		env.recs.rec.Expiry = utStart.Unix() + 3600
		env.recs.version++
		env.recs.mu.Unlock()
		env.grants.mu.Lock()
		env.grants.grant.GrantID = "g2"
		env.grants.mu.Unlock()
	}
	m, err := env.token(t, false, "", "a")
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if m.AccessToken != "ut-access-new-SECRET" {
		t.Fatalf("served %q, want the reconnected grant's token", m.AccessToken)
	}
	rec, _, _, writes := env.recs.snapshot()
	if writes != 0 || rec.GrantID != "g2" || rec.RefreshToken != "ut-refresh-new-SECRET" {
		t.Fatalf("the rotated token overwrote the new grant: writes=%d rec=%v", writes, rec)
	}
}

func TestEngineEpochChangeDuringRefreshDropsRotatedToken(t *testing.T) {
	env := newUTEnv(t, "google")
	ep := &utEpochs{}
	env.e.epochs = ep
	env.e.testHook = func(string, string) { ep.set(5) }
	_, err := env.token(t, false, "", "a")
	// The second pass re-reads at the new epoch and refreshes again.
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if _, _, _, writes := env.recs.snapshot(); writes != 1 {
		t.Fatalf("writes = %d: the first rotated token must be dropped, the second written", writes)
	}
	if env.hits.Load() != 2 {
		t.Fatalf("refreshes = %d, want 2", env.hits.Load())
	}
}

type utEpochs struct {
	mu sync.Mutex
	n  int64
}

func (u *utEpochs) GrantEpoch(context.Context, string) (int64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.n, nil
}
func (u *utEpochs) set(n int64) { u.mu.Lock(); u.n = n; u.mu.Unlock() }

func TestEngineForceRefresh(t *testing.T) {
	env := newUTEnv(t, "google")
	first := env.mustToken(t, false, "")
	if env.hits.Load() != 1 {
		t.Fatalf("hits = %d", env.hits.Load())
	}
	// A stale ref that is not the current token's: the current token, no refresh.
	m := env.mustToken(t, true, "not-the-current-ref")
	if m.Ref != first.Ref || env.hits.Load() != 1 {
		t.Fatalf("a force with a stale ref that no longer matches refreshed")
	}
	// The matching ref: one refresh.
	second := env.mustToken(t, true, first.Ref)
	if second.Ref == first.Ref || env.hits.Load() != 2 {
		t.Fatalf("a matching force did not refresh (hits=%d)", env.hits.Load())
	}
	// Two forces with the same stale ref: the second sees a different current ref.
	again := env.mustToken(t, true, first.Ref)
	if again.Ref != second.Ref || env.hits.Load() != 2 {
		t.Fatalf("the repeated force refreshed again")
	}
	// A new stale ref within 30s: rate limited, the current token is returned.
	limited := env.mustToken(t, true, second.Ref)
	if limited.Ref != second.Ref || env.hits.Load() != 2 {
		t.Fatalf("force inside the 30s window refreshed (hits=%d)", env.hits.Load())
	}
	env.clk.Add(31 * time.Second)
	third := env.mustToken(t, true, second.Ref)
	if third.Ref == second.Ref || env.hits.Load() != 3 {
		t.Fatalf("force after the window did not refresh (hits=%d)", env.hits.Load())
	}
	env.assertClean(t)
}

func TestEngineGitHubOAuthAppRecordIsUsedAsStored(t *testing.T) {
	env := newUTEnv(t, "githubApp")
	env.recs.rec.Expiry, env.recs.rec.RefreshToken = 0, ""
	m := env.mustToken(t, false, "")
	if m.AccessToken != utAccess0 || m.ExpiresIn <= 0 || env.hits.Load() != 0 {
		t.Fatalf("non-expiring record not used as stored: %v hits=%d", m, env.hits.Load())
	}
	env.clk.Add(24 * 365 * time.Hour)
	if m2 := env.mustToken(t, false, ""); m2.AccessToken != utAccess0 {
		t.Fatalf("non-expiring record changed")
	}
	// A forced refresh (the upstream rejected the token) needs a re-consent.
	_, err := env.token(t, true, m.Ref, "a")
	if !errors.Is(err, ErrReconsentRequired) {
		t.Fatalf("force on a non-refreshable record: err = %v", err)
	}
	if env.grants.state() != GrantReconsentRequired || env.hits.Load() != 0 {
		t.Fatalf("state = %s hits = %d", env.grants.state(), env.hits.Load())
	}
}

func TestRefreshWriteBackFailure(t *testing.T) {
	env := newUTEnv(t, "google")
	env.recs.putErr = errors.New("store down")
	_, err := env.token(t, false, "", "a")
	if !errors.Is(err, ErrTokenUnavailable) {
		t.Fatalf("err = %v, want ErrTokenUnavailable (the rotation is not durable)", err)
	}
	_, _, puts, writes := env.recs.snapshot()
	if puts != 4 || writes != 0 {
		t.Fatalf("StoreRotated calls = %d (want the first try plus 3 retries), writes = %d", puts, writes)
	}
	env.smu.Lock()
	slept := append([]time.Duration(nil), env.slept...)
	env.smu.Unlock()
	if len(slept) != 3 || slept[0] != 100*time.Millisecond || slept[1] != 400*time.Millisecond || slept[2] != 1600*time.Millisecond {
		t.Fatalf("backoff = %v", slept)
	}
	// Every retry used the version of the one read.
	env.recs.mu.Lock()
	for i, v := range env.recs.readVer {
		if v != env.recs.readVer[0] {
			t.Fatalf("retry %d used a different read version %v", i, v)
		}
	}
	env.recs.mu.Unlock()
	env.metrics.mu.Lock()
	wf := env.metrics.writeFail
	env.metrics.mu.Unlock()
	env.alerter.mu.Lock()
	keys := append([]string(nil), env.alerter.keys...)
	env.alerter.mu.Unlock()
	if wf != 1 || len(keys) != 1 || keys[0] != utUser+"/"+utProvider {
		t.Fatalf("counter=%d findings=%v, want one of each", wf, keys)
	}
	if env.grants.lastStamp() != RefreshStatusWritebackFailed {
		t.Fatalf("last_refresh_status = %q", env.grants.lastStamp())
	}
	if env.grants.state() != GrantActive {
		t.Fatalf("state = %s", env.grants.state())
	}

	// The store recovers: the next call writes the in-memory rotated token
	// (before serving anything) without another provider call.
	env.recs.mu.Lock()
	env.recs.putErr = nil
	env.recs.mu.Unlock()
	hits := env.hits.Load()
	m, err := env.token(t, false, "", "a")
	if err != nil {
		t.Fatalf("after recovery: %v", err)
	}
	rec, _, _, writes := env.recs.snapshot()
	if writes != 1 || rec.RefreshToken != "ut-refresh-1-SECRET" || rec.AccessToken != m.AccessToken {
		t.Fatalf("the in-memory rotated token was not written: writes=%d", writes)
	}
	if env.hits.Load() != hits {
		t.Fatalf("recovery refreshed again")
	}
	env.assertClean(t)
}

func TestEngineWritebackConflictDropsRotatedToken(t *testing.T) {
	env := newUTEnv(t, "google")
	env.recs.putErr = ErrGrantChanged
	m, err := env.token(t, false, "", "a")
	// The grant "changed" on every attempt: two passes, then unavailable; the
	// rotated token is never written plainly and never retried as a transient.
	if err == nil {
		t.Fatalf("served %v despite a conflicting write", m)
	}
	if _, _, puts, writes := env.recs.snapshot(); writes != 0 || puts != 2 {
		t.Fatalf("puts=%d writes=%d", puts, writes)
	}
}

func TestEngineNilCollaboratorsAreRejected(t *testing.T) {
	if _, err := NewEngine(EngineConfig{}); err == nil {
		t.Fatal("NewEngine accepted an empty config")
	}
}

func TestEngineMintedNeverPrintsToken(t *testing.T) {
	m := Minted{AccessToken: "SECRET-TOKEN", Ref: "r"}
	for _, s := range []string{m.String(), m.GoString(), fmt.Sprintf("%v %+v %#v", m, m, m)} {
		if strings.Contains(s, "SECRET-TOKEN") {
			t.Fatalf("Minted prints its token: %s", s)
		}
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "m", m)
	if strings.Contains(buf.String(), "SECRET-TOKEN") {
		t.Fatalf("Minted logs its token")
	}
}
