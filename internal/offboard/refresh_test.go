package offboard_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/offboard"
	"github.com/ethosagent/warden/internal/offboard/adapters/oidcrefresh"
	"github.com/ethosagent/warden/internal/portal"
	idplinksqlite "github.com/ethosagent/warden/internal/portal/adapters/sqlite"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// The refresh job end to end against the Dex-shaped issuer fake: the real
// oidcrefresh client, the real ID-token verifier pinned to warden-portal, and
// the real portal.LinkStore over idp_links and an in-memory consent.store.

const (
	clientID     = "warden-portal"
	clientSecret = "portal-client-secret"
	lifetime     = 720 * time.Hour
)

var epoch = time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// findings records published Findings.
type findings struct {
	mu sync.Mutex
	fs []offboard.Finding
}

func (f *findings) PublishFinding(x offboard.Finding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fs = append(f.fs, x)
}

func (f *findings) rule(id string) []offboard.Finding {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []offboard.Finding
	for _, x := range f.fs {
		if x.RuleID == id {
			out = append(out, x)
		}
	}
	return out
}

func (f *findings) all() []offboard.Finding {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]offboard.Finding(nil), f.fs...)
}

// countingSecrets is consent.store counting Puts, with an optional Put failure.
type countingSecrets struct {
	*fakes.MemorySecretStore
	puts    atomic.Int64
	failPut atomic.Bool
}

// errPutEcho is an error whose text echoes the value, as a careless backend's might.
type errPutEcho struct{ v string }

func (e errPutEcho) Error() string { return "put failed for " + e.v }

func (c *countingSecrets) Put(ctx context.Context, key, value string) error {
	c.puts.Add(1)
	if c.failPut.Load() {
		return errPutEcho{v: value}
	}
	return c.MemorySecretStore.Put(ctx, key, value)
}

// spyLinks records the job's Rotate results.
type spyLinks struct {
	*portal.LinkStore
	mu      sync.Mutex
	rotates []error
	// before, when set, runs once before the first Rotate.
	before func()
}

func (s *spyLinks) Rotate(ctx context.Context, iss, sub string, gen int64, tok string) (portal.IdPLink, error) {
	s.mu.Lock()
	hook := s.before
	s.before = nil
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	l, err := s.LinkStore.Rotate(ctx, iss, sub, gen, tok)
	s.mu.Lock()
	s.rotates = append(s.rotates, err)
	s.mu.Unlock()
	return l, err
}

func (s *spyLinks) rotateErrs() []error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]error(nil), s.rotates...)
}

type rig struct {
	t       *testing.T
	clk     *clocktest.Fake
	idp     *fakes.OIDCIssuer
	mem     *countingSecrets
	links   *portal.LinkStore
	spy     *spyLinks
	job     *offboard.Job
	pub     *findings
	logs    *syncBuf
	metrics *offboard.Metrics
}

type rigOpts struct {
	maxFailures int
	leader      offboard.Leader
	interval    time.Duration
}

func newRig(t *testing.T, o rigOpts) *rig {
	t.Helper()
	clk := clocktest.NewFake(epoch)
	idp := fakes.NewOIDCIssuer(t, fakes.WithIssuerClock(clk.Now))
	idp.RegisterClient(clientID, clientSecret)
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), idplinksqlite.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	logs := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mem := &countingSecrets{MemorySecretStore: fakes.NewMemorySecretStore()}
	links, err := portal.NewLinkStore(portal.LinkStoreConfig{
		Repo: idplinksqlite.New(db), Secrets: mem,
		Keys: portal.LinkKeys{
			UserKey: secrets.UserKey, SecretKey: secrets.IdPLinkKey,
			Ref: func(tok string) string { return secrets.Ref(tok).String() },
		},
		RefreshLifetime: lifetime, Now: clk.Now, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	httpc, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: idp.Issuer(), InternalIssuerURL: idp.URL()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := oidcrefresh.New(oidcrefresh.Config{
		HTTP: httpc, ClientID: clientID, ClientSecret: clientSecret,
		TokenURL: func() (string, bool) { return idp.Issuer() + "/token", true },
	})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oidc.NewIDTokenVerifier(oidc.IDTokenConfig{Issuer: idp.Issuer(), ClientID: clientID, InternalIssuerURL: idp.URL(), Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if o.maxFailures == 0 {
		o.maxFailures = 3
	}
	if o.interval == 0 {
		o.interval = time.Hour
	}
	spy := &spyLinks{LinkStore: links}
	pub := &findings{}
	m := offboard.NewMetrics()
	job, err := offboard.NewJob(offboard.JobConfig{
		Links: spy, Client: client, Verifier: verifier, Now: clk.Now, After: clk.After, Leader: o.leader,
		Findings: pub, Metrics: m, Logger: logger, Mode: "observe",
		Interval: o.interval, Concurrency: 4, RequestTimeout: 5 * time.Second,
		MaxFailures: o.maxFailures, ReauthWarning: 72 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, clk: clk, idp: idp, mem: mem, links: links, spy: spy, job: job, pub: pub, logs: logs, metrics: m}
}

// login links sub with token, as a portal login does, and starts the chain at
// the IdP.
func (r *rig) login(sub, token string) {
	r.t.Helper()
	if err := r.links.StoreLink(context.Background(), portal.Link{Iss: r.idp.Issuer(), Sub: sub, Email: sub + "@example.com", RefreshToken: token}); err != nil {
		r.t.Fatal(err)
	}
	r.idp.AddRefreshChain(token, sub, sub+"@example.com", clientID)
}

func (r *rig) row(sub string) portal.IdPLink {
	r.t.Helper()
	l, err := r.links.Get(context.Background(), r.idp.Issuer(), sub)
	if err != nil {
		r.t.Fatal(err)
	}
	return l
}

// stored is the value at idp/<userKey> in consent.store.
func (r *rig) stored(sub string) string {
	r.t.Helper()
	uk, err := secrets.UserKey(r.idp.Issuer(), sub)
	if err != nil {
		r.t.Fatal(err)
	}
	v, _ := r.mem.Value("idp/" + uk)
	return v
}

func (r *rig) runOnce() offboard.RunStats {
	r.t.Helper()
	st, err := r.job.RunOnce(context.Background())
	if err != nil {
		r.t.Fatalf("RunOnce: %v", err)
	}
	return st
}

func (r *rig) noSecretInLogs(values ...string) {
	r.t.Helper()
	logs := r.logs.String()
	for _, v := range values {
		if v != "" && strings.Contains(logs, v) {
			r.t.Fatalf("the logs hold %q", v)
		}
	}
}

func TestRefreshJob_Rotation(t *testing.T) {
	r := newRig(t, rigOpts{})
	const first = "rt-dana-login-token-000001"
	r.login("dana", first)
	before := r.row("dana")
	st := r.runOnce()
	if st.OK != 1 || st.Checked != 1 {
		t.Fatalf("stats = %+v, want one ok", st)
	}
	got := r.stored("dana")
	if got == first || got == "" || !r.idp.LiveRefreshToken(got) || r.idp.LiveRefreshToken(first) {
		t.Fatalf("consent.store holds %q: want the rotated, live token", got)
	}
	after := r.row("dana")
	if after.Generation != before.Generation+1 || after.RefreshRef != secrets.Ref(got).String() {
		t.Fatalf("row = gen %d ref %q; want gen %d and the new token's Reference", after.Generation, after.RefreshRef, before.Generation+1)
	}
	if after.State != portal.LinkActive || !after.LastOKAt.Equal(r.clk.Now().UTC().Truncate(time.Millisecond)) ||
		after.RotationPendingRef != "" || after.ConsecutiveFailures != 0 || !after.EmailVerified ||
		after.LastRefreshStatus != portal.RefreshStatusRotated || !after.RelinkDueAt.Equal(before.RelinkDueAt) {
		t.Fatalf("row after rotation = %+v", after)
	}
	// The chain keeps going: the next run refreshes with the rotated token.
	r.clk.Advance(time.Hour)
	if st := r.runOnce(); st.OK != 1 {
		t.Fatalf("second run = %+v", st)
	}
	if again := r.row("dana"); again.Generation != after.Generation+1 || r.stored("dana") == got {
		t.Fatalf("second rotation: gen %d stored-changed=%v", again.Generation, r.stored("dana") != got)
	}
	if r.metrics.Refresh("ok") != 2 || r.metrics.LastRun() == 0 {
		t.Fatalf("metrics ok=%d lastRun=%v", r.metrics.Refresh("ok"), r.metrics.LastRun())
	}
	logs := r.logs.String()
	for _, want := range []string{`"msg":"offboarding_job_run"`, `"checked":1`, `"ok":1`, `"transient":0`, `"expired":0`, `"token_lost":0`, `"duration_ms":`} {
		if !strings.Contains(logs, want) {
			t.Errorf("run log line lacks %s", want)
		}
	}
	r.noSecretInLogs(first, got)
	if len(r.pub.all()) != 0 {
		t.Fatalf("findings = %+v, want none", r.pub.all())
	}
}

// An IdP that does not rotate: the token stays, only the state is written.
func TestRefreshJob_RotationNotIssued(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.idp.SetRefreshRotation(false)
	r.login("dana", "rt-dana-static-token-0001")
	before := r.row("dana")
	if st := r.runOnce(); st.OK != 1 {
		t.Fatalf("stats = %+v", st)
	}
	after := r.row("dana")
	if after.Generation != before.Generation || r.stored("dana") != "rt-dana-static-token-0001" || after.LastOKAt.IsZero() || after.LastRefreshStatus != "refreshed" {
		t.Fatalf("row = %+v", after)
	}
}

func TestRefreshJob_RotateFailsTokenLost(t *testing.T) {
	r := newRig(t, rigOpts{})
	const first = "rt-dana-login-token-000002"
	r.login("dana", first)
	before := r.row("dana")
	putsBefore := r.mem.puts.Load()
	r.mem.failPut.Store(true)
	st := r.runOnce()
	if st.TokenLost != 1 {
		t.Fatalf("stats = %+v, want token_lost", st)
	}
	if n := r.mem.puts.Load() - putsBefore; n != 3 {
		t.Fatalf("Put attempts = %d, want 3", n)
	}
	errs := r.spy.rotateErrs()
	if len(errs) != 3 {
		t.Fatalf("Rotate calls = %d, want 3", len(errs))
	}
	for _, err := range errs {
		if !errors.Is(err, portal.ErrLinkSecretStore) {
			t.Fatalf("Rotate error = %v, want ErrLinkSecretStore", err)
		}
	}
	after := r.row("dana")
	if after.State != portal.LinkTokenLost || after.LastErrorCode != "rotate_failed" || after.RotationPendingRef != "" || after.Generation != before.Generation {
		t.Fatalf("row = %+v", after)
	}
	if r.stored("dana") != first {
		t.Fatal("the stored token changed although every Put failed")
	}
	// The token the IdP rotated to was held only in memory and lost.
	if r.idp.LiveRefreshToken(first) {
		t.Fatal("the IdP did not rotate the token")
	}
	rotated := r.idp.LastIssuedRefreshToken()
	// (The login's own idp_link_stored line names the first token's
	// Reference; nothing names the lost one.)
	r.noSecretInLogs(first, rotated, secrets.Ref(rotated).String())
	if !strings.Contains(r.logs.String(), `"msg":"offboarding_rotate_failed"`) || !strings.Contains(r.logs.String(), offboard.SubHash("dana")) {
		t.Fatal("no offboarding_rotate_failed line with the sub hash")
	}
	if strings.Contains(r.logs.String(), `"dana"`) {
		t.Fatal("a log line names the raw sub")
	}
	if fs := r.pub.rule(offboard.RuleReauthRequired); len(fs) != 1 || fs[0].Sub != "dana" {
		t.Fatalf("reauth findings = %+v, want one", fs)
	}
	// token_lost is terminal until a login: the next run makes no IdP call.
	calls := r.idp.RefreshRequests()
	if st := r.runOnce(); st.Skipped != 1 || r.idp.RefreshRequests() != calls {
		t.Fatalf("next run = %+v, calls %d -> %d", st, calls, r.idp.RefreshRequests())
	}
	// A login resets the link to active.
	r.mem.failPut.Store(false)
	r.login("dana", "rt-dana-relogin-token-0003")
	if l := r.row("dana"); l.State != portal.LinkActive || l.LastErrorCode != "" || l.ConsecutiveFailures != 0 {
		t.Fatalf("after a re-login = %+v", l)
	}
}

func TestRefreshJob_ReloginRace(t *testing.T) {
	const relogin = "rt-dana-relogin-token-000005"
	relogIn := func(t *testing.T, r *rig) {
		if err := r.links.StoreLink(context.Background(), portal.Link{Iss: r.idp.Issuer(), Sub: "dana", Email: "dana@example.com", RefreshToken: relogin}); err != nil {
			t.Error(err)
		}
	}
	check := func(t *testing.T, r *rig, puts int64) {
		t.Helper()
		if n := r.mem.puts.Load(); n != puts {
			t.Fatalf("Puts after the login = %d, want none", n-puts)
		}
		if got := r.stored("dana"); got != relogin {
			t.Fatalf("stored = %q, want the re-login token", got)
		}
		if l := r.row("dana"); l.State != portal.LinkActive || l.RefreshRef != secrets.Ref(relogin).String() || l.RotationPendingRef != "" || l.LastErrorCode != "" {
			t.Fatalf("row = %+v", l)
		}
	}
	t.Run("Rotate loses to a login just before it", func(t *testing.T) {
		r := newRig(t, rigOpts{})
		r.login("dana", "rt-dana-login-token-000004")
		var puts int64
		r.spy.before = func() {
			relogIn(t, r)
			puts = r.mem.puts.Load()
		}
		st := r.runOnce()
		if st.Stale != 1 || st.TokenLost != 0 {
			t.Fatalf("stats = %+v, want stale", st)
		}
		if errs := r.spy.rotateErrs(); len(errs) != 1 || !errors.Is(errs[0], portal.ErrStaleGeneration) {
			t.Fatalf("Rotate = %v, want one ErrStaleGeneration (no retry)", errs)
		}
		check(t, r, puts)
	})
	t.Run("a login during the refresh call", func(t *testing.T) {
		// The IdP still honours the presented token; the pending-rotation
		// write already sees the newer generation, so nothing is written.
		r := newRig(t, rigOpts{})
		r.login("dana", "rt-dana-login-token-000004")
		var puts int64
		r.idp.OnRefresh(func(string) {
			relogIn(t, r)
			puts = r.mem.puts.Load()
		})
		st := r.runOnce()
		if st.Stale != 1 || st.TokenLost != 0 {
			t.Fatalf("stats = %+v, want stale", st)
		}
		check(t, r, puts)
	})
	t.Run("the login invalidates the presented chain", func(t *testing.T) {
		// Dex keeps only the newest chain: the in-flight refresh is refused
		// as claimed, and that verdict about the old token is dropped.
		r := newRig(t, rigOpts{})
		r.login("dana", "rt-dana-login-token-000006")
		r.idp.OnRefresh(func(string) {
			r.idp.OnRefresh(nil)
			r.login("dana", "rt-dana-relogin-token-000007")
		})
		st := r.runOnce()
		if st.Stale != 1 || st.TokenLost != 0 {
			t.Fatalf("stats = %+v, want stale (never token_lost)", st)
		}
		if l := r.row("dana"); l.State != portal.LinkActive || l.LastErrorCode != "" {
			t.Fatalf("row = %+v", l)
		}
		if len(r.pub.all()) != 0 {
			t.Fatalf("findings = %+v", r.pub.all())
		}
	})
}

func TestRefreshJob_TransientFindings(t *testing.T) {
	t.Run("one user failing while others succeed", func(t *testing.T) {
		r := newRig(t, rigOpts{maxFailures: 3})
		for _, s := range []string{"ana", "ben", "cy"} {
			r.login(s, "rt-"+s+"-login-token-000010")
		}
		r.idp.SetRefreshFailure("ben", fakes.RefreshUnavailable)
		for run := 1; run <= 3; run++ {
			st := r.runOnce()
			if st.OK != 2 || st.Transient != 1 {
				t.Fatalf("run %d = %+v", run, st)
			}
			want := 0
			if run == 3 {
				want = 1
			}
			if fs := r.pub.rule(offboard.RuleRefreshFailing); len(fs) != want {
				t.Fatalf("run %d: idp_refresh_failing = %d, want %d", run, len(fs), want)
			}
			r.clk.Advance(time.Hour)
		}
		fs := r.pub.rule(offboard.RuleRefreshFailing)
		if fs[0].Sub != "ben" || fs[0].DedupKey != offboard.RuleRefreshFailing+":"+offboard.SubHash("ben") || fs[0].Evidence != "consecutive_failures=3" {
			t.Fatalf("finding = %+v", fs[0])
		}
		if l := r.row("ben"); l.ConsecutiveFailures != 3 || l.LastErrorCode != "http_503" || l.State != portal.LinkActive {
			t.Fatalf("ben = %+v", l)
		}
		if len(r.pub.rule(offboard.RuleRefreshUnavailable)) != 0 {
			t.Fatal("idp_refresh_unavailable published for one failing user")
		}
		// A success resets the count.
		r.idp.SetRefreshFailure("ben", fakes.RefreshFailure{})
		r.runOnce()
		if l := r.row("ben"); l.ConsecutiveFailures != 0 || l.LastErrorCode != "" {
			t.Fatalf("ben after a success = %+v", l)
		}
	})
	t.Run("every user failing", func(t *testing.T) {
		r := newRig(t, rigOpts{maxFailures: 1})
		for _, s := range []string{"ana", "ben", "cy"} {
			r.login(s, "rt-"+s+"-login-token-000011")
		}
		r.idp.SetTokenStatus(503)
		st := r.runOnce()
		if st.Transient != 3 {
			t.Fatalf("stats = %+v", st)
		}
		if fs := r.pub.rule(offboard.RuleRefreshUnavailable); len(fs) != 1 || fs[0].Sub != "" || fs[0].Evidence != "transient=3 attempted=3" {
			t.Fatalf("idp_refresh_unavailable = %+v, want one", fs)
		}
		if fs := r.pub.rule(offboard.RuleRefreshFailing); len(fs) != 0 {
			t.Fatalf("per-user findings = %+v, want none", fs)
		}
		if st.Issuers[r.idp.Issuer()].Transient != 3 {
			t.Fatalf("issuer stats = %+v", st.Issuers)
		}
	})
}

func TestRefreshJob_Lifetime(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.login("dana", "rt-dana-login-token-000020")
	due := r.row("dana").RelinkDueAt
	// 70h before relink_due_at, inside the 72h warning.
	r.clk.Set(due.Add(-70 * time.Hour))
	if st := r.runOnce(); st.OK != 1 {
		t.Fatalf("stats = %+v", st)
	}
	if l := r.row("dana"); l.State != portal.LinkExpiring {
		t.Fatalf("state = %q, want expiring", l.State)
	}
	fs := r.pub.rule(offboard.RuleReauthRequired)
	if len(fs) != 1 || fs[0].Sub != "dana" || fs[0].Evidence != "link_state=expiring" || fs[0].Severity != offboard.SeverityMedium {
		t.Fatalf("findings = %+v, want one offboarding_reauth_required", fs)
	}
	// Still expiring on the next run: no second Finding.
	r.clk.Advance(time.Hour)
	r.runOnce()
	if n := len(r.pub.rule(offboard.RuleReauthRequired)); n != 1 {
		t.Fatalf("findings after a second run = %d, want 1", n)
	}
	// Past relink_due_at: no refresh call, reauth_required.
	r.clk.Set(due.Add(time.Minute))
	calls := r.idp.RefreshRequests()
	st := r.runOnce()
	if st.Expired != 1 || r.idp.RefreshRequests() != calls {
		t.Fatalf("stats = %+v, refresh calls %d -> %d", st, calls, r.idp.RefreshRequests())
	}
	if l := r.row("dana"); l.State != portal.LinkReauthRequired || l.LastErrorCode != "relink_due" {
		t.Fatalf("row = %+v", l)
	}
	if n := len(r.pub.rule(offboard.RuleReauthRequired)); n != 2 {
		t.Fatalf("findings = %d, want a second one for reauth_required", n)
	}
	// A login starts a new chain and resets the state.
	r.login("dana", "rt-dana-relogin-token-000021")
	if l := r.row("dana"); l.State != portal.LinkActive || !l.RelinkDueAt.After(due) {
		t.Fatalf("after a re-login = %+v", l)
	}
}

func TestRefreshJob_Classification(t *testing.T) {
	cases := []struct {
		name      string
		fail      fakes.RefreshFailure
		mint      []fakes.MintOption
		wantState string
		wantCode  string
		wantName  string
	}{
		{"expired", fakes.RefreshExpired, nil, portal.LinkReauthRequired, "refresh_expired", "expired"},
		{"claimed", fakes.RefreshClaimed, nil, portal.LinkTokenLost, "refresh_invalid", "token_lost"},
		{"invalid_grant", fakes.RefreshFailure{Status: 400, Error: "invalid_grant"}, nil, portal.LinkTokenLost, "refresh_invalid", "token_lost"},
		{"upstream refused", fakes.RefreshUpstreamRefused, nil, portal.LinkActive, "upstream_refused", "upstream_refused"},
		{"429", fakes.RefreshFailure{Status: 429}, nil, portal.LinkActive, "http_429", "transient"},
		{"500 server_error", fakes.RefreshFailure{Status: 500, Error: "server_error"}, nil, portal.LinkActive, "http_500", "transient"},
		{"unknown 400", fakes.RefreshFailure{Status: 400, Error: "invalid_scope"}, nil, portal.LinkActive, "http_400", "transient"},
		{"sub mismatch", fakes.RefreshFailure{}, []fakes.MintOption{fakes.WithSub("mallory")}, portal.LinkSuspect, "sub_mismatch", "suspect"},
		{"wrong audience", fakes.RefreshFailure{}, []fakes.MintOption{fakes.WithAud("warden-console"), fakes.WithAZP("warden-console")}, portal.LinkSuspect, "id_token_invalid", "suspect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, rigOpts{})
			const tok = "rt-dana-login-token-000030"
			r.login("dana", tok)
			r.idp.SetRefreshFailure("dana", tc.fail)
			if tc.mint != nil {
				r.idp.SetRefreshMint("dana", tc.mint...)
			}
			r.runOnce()
			l := r.row("dana")
			if l.State != tc.wantState || l.LastErrorCode != tc.wantCode || r.metrics.Refresh(tc.wantName) != 1 {
				t.Fatalf("state %q code %q outcomes %v; want %q %q %s", l.State, l.LastErrorCode, r.metrics.Outcomes(), tc.wantState, tc.wantCode, tc.wantName)
			}
			if tc.wantState == portal.LinkSuspect && r.stored("dana") != tok {
				t.Fatal("a suspect refresh wrote its token")
			}
			r.noSecretInLogs(tok)
		})
	}
}

func TestRefreshJob_ConfigErrorPauses(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.login("ana", "rt-ana-login-token-000040")
	r.login("ben", "rt-ben-login-token-000040")
	r.idp.RegisterClient(clientID, "rotated-elsewhere")
	st, err := r.job.RunOnce(context.Background())
	if err != nil || st.ConfigError == 0 {
		t.Fatalf("RunOnce = %+v, %v", st, err)
	}
	fs := r.pub.rule(offboard.RuleConfigError)
	if len(fs) != 1 || fs[0].Severity != offboard.SeverityCritical {
		t.Fatalf("config findings = %+v, want one critical", fs)
	}
	if !r.job.Paused() {
		t.Fatal("the job is not paused")
	}
	calls := r.idp.RefreshRequests()
	if _, err := r.job.RunOnce(context.Background()); !errors.Is(err, offboard.ErrPaused) || r.idp.RefreshRequests() != calls {
		t.Fatalf("paused RunOnce = %v (calls %d -> %d)", err, calls, r.idp.RefreshRequests())
	}
	for _, s := range []string{"ana", "ben"} {
		if l := r.row(s); l.State != portal.LinkActive || l.LastErrorCode != "" {
			t.Fatalf("%s = %+v: a config error is no verdict on the user", s, l)
		}
	}
	r.idp.RegisterClient(clientID, clientSecret)
	r.job.Resume()
	if st := r.runOnce(); st.OK != 2 {
		t.Fatalf("after Resume = %+v", st)
	}
}

func TestRefreshJob_InconsistentSnapshot(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.login("dana", "rt-dana-login-token-000050")
	uk, _ := secrets.UserKey(r.idp.Issuer(), "dana")
	// A write behind the control plane's back: the row's Reference no
	// longer names the stored token.
	if err := r.mem.MemorySecretStore.Put(context.Background(), "idp/"+uk, "rt-someone-else-000051"); err != nil {
		t.Fatal(err)
	}
	before := r.row("dana")
	st := r.runOnce()
	if st.Inconsistent != 1 || r.idp.RefreshRequests() != 0 {
		t.Fatalf("stats = %+v, refresh calls %d", st, r.idp.RefreshRequests())
	}
	if after := r.row("dana"); !reflect.DeepEqual(after, before) {
		t.Fatalf("row changed: %+v", after)
	}
}

func TestRefreshJob_OffboardedSkipped(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.login("dana", "rt-dana-login-token-000060")
	l := r.row("dana")
	st := l.RefreshState()
	st.State = portal.LinkOffboarded
	if err := r.links.SetState(context.Background(), l.Iss, l.Sub, l.Generation, st); err != nil {
		t.Fatal(err)
	}
	if s := r.runOnce(); s.Skipped != 1 || s.Checked != 0 || r.idp.RefreshRequests() != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

type notLeader struct{}

func (notLeader) IsLeader(context.Context) bool { return false }

// TestRefreshJob_Start drives the scheduled loop on the fake clock: nothing
// before the first-run delay, then one refresh per link inside the run, and a
// non-leader never refreshes.
func TestRefreshJob_Start(t *testing.T) {
	r := newRig(t, rigOpts{interval: 5 * time.Minute})
	for _, s := range []string{"ana", "ben", "cy"} {
		r.login(s, "rt-"+s+"-login-token-000070")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.job.Start(ctx)
	waitTimers(t, r.clk, 1)
	r.clk.Advance(59 * time.Second)
	if n := r.idp.RefreshRequests(); n != 0 {
		t.Fatalf("refreshes before the first-run delay = %d", n)
	}
	pollAdvance(t, r.clk, func() bool { return r.metrics.LastRun() != 0 })
	if n := r.idp.RefreshRequests(); n != 3 {
		t.Fatalf("refreshes in the first run = %d, want 3", n)
	}
	// The next run comes one interval after the first started.
	pollAdvance(t, r.clk, func() bool { return r.idp.RefreshRequests() == 6 })

	nl := newRig(t, rigOpts{interval: 5 * time.Minute, leader: notLeader{}})
	nl.login("ana", "rt-ana-login-token-000071")
	nctx, ncancel := context.WithCancel(context.Background())
	defer ncancel()
	nl.job.Start(nctx)
	waitTimers(t, nl.clk, 1)
	for range 30 {
		nl.clk.Advance(time.Minute)
		waitTimers(t, nl.clk, 1)
	}
	if n := nl.idp.RefreshRequests(); n != 0 {
		t.Fatalf("a non-leader refreshed %d times", n)
	}
}

// waitTimers waits (real time) until the fake clock has n timers armed.
func waitTimers(t *testing.T, clk *clocktest.Fake, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for clk.PendingTimers() < n {
		if time.Now().After(deadline) {
			t.Fatalf("pending timers = %d, want %d", clk.PendingTimers(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// pollAdvance advances the fake clock in small steps until cond holds.
func pollAdvance(t *testing.T, clk *clocktest.Fake, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never held")
		}
		clk.Advance(5 * time.Second)
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRefreshJob_NoOffboarderSeam: observe mode cannot offboard because the
// job has no seam that could: no field or method of the job or its config
// names offboarding.
func TestRefreshJob_NoOffboarderSeam(t *testing.T) {
	for _, typ := range []reflect.Type{reflect.TypeOf(offboard.JobConfig{}), reflect.TypeOf(&offboard.Job{})} {
		if typ.Kind() == reflect.Struct {
			for i := range typ.NumField() {
				if strings.Contains(strings.ToLower(typ.Field(i).Name), "offboard") {
					t.Errorf("%s has field %s", typ, typ.Field(i).Name)
				}
			}
		}
		for i := range typ.NumMethod() {
			if strings.Contains(strings.ToLower(typ.Method(i).Name), "offboard") {
				t.Errorf("%s has method %s", typ, typ.Method(i).Name)
			}
		}
	}
}
