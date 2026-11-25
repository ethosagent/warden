package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/secrets"
	tokensvcsqlite "github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
)

const keyOwnerIss = "https://idp.example"

// keyEnv is a control plane in oidc mode with API keys on: a real sqlite key
// store and Index (never Run: the fake clock stays inside the staleness
// ceiling), a fake admin audit recorder, and sessions created in-process.
type keyEnv struct {
	t      *testing.T
	srv    *Server
	h      http.Handler
	clk    *clocktest.Fake
	store  *sqlitestore.SQLiteStore
	ix     *apikeys.Index
	rec    *fakeRecorder
	logs   *syncBuf
	policy string
	db     *cpstate.DB
	reg    *apikeys.Registry
	minted int
}

type keyEnvOpts struct {
	roles      config.ConsoleRoles
	db         *cpstate.DB
	policy     string
	ratePerKey int
	noAudit    bool
	versioned  bool
}

func openKeysDB(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"),
		cpstate.Enable(StateMigrations(), sqlitestore.MigrationID, tokensvcsqlite.SessionsMigrationID))
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newKeyEnv(t *testing.T, o keyEnvOpts) *keyEnv {
	t.Helper()
	if o.roles.Admin == nil {
		o.roles = defaultRoles()
	}
	if o.db == nil {
		o.db = openKeysDB(t)
	}
	if o.policy == "" {
		o.policy = writePolicyFile(t, "api.openai.com")
	}
	if o.ratePerKey == 0 {
		o.ratePerKey = config.DefaultAPIKeysRatePerKey
	}
	logger, logs := testLogger()
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	reg := newAPIKeyRegistry()
	store, err := sqlitestore.New(o.db, sqlitestore.Options{Registry: reg, Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	ix, err := apikeys.NewIndex(context.Background(), store, apikeys.IndexOptions{Now: clk.Now, After: clk.After, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	cc := authzConsole(o.roles)
	cc.APIKeys = config.ConsoleAPIKeys{
		Enabled: true, DefaultTTL: config.DefaultAPIKeyTTL, MaxTTL: config.DefaultAPIKeyMaxTTL,
		MaxPerOwner: config.DefaultAPIKeysMaxPerOwner, RatePerKey: o.ratePerKey,
	}
	cfg := Config{
		PolicyPath: o.policy, Token: dashTestToken, State: o.db, Console: cc, Logger: logger, Clock: clk,
		APIKeyIndex: ix, APIKeyStore: store, APIKeyRegistry: reg, SecretStore: secrets.NewEchoStore(),
	}
	if o.versioned {
		cfg.PolicyStore = PolicyStoreVersioned
	}
	srv := New(cfg)
	if o.versioned {
		if err := srv.importInitialVersion(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if srv.apiKeys == nil {
		t.Fatal("API keys enabled with an index and sessions must build the authenticator")
	}
	srv.sessions = NewSessionStore(o.db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
	srv.sessionReader = srv.sessions
	rec := &fakeRecorder{}
	if !o.noAudit {
		srv.enableAdminAudit(rec, rec.probe, fakeMAC)
	}
	// The token service mounts the token session routes, so the ScopeNone
	// sweep covers them too.
	srv.EnableTokens(&fakeExchanger{}, testTokenIssuer, TokenEdge{Sessions: tokensvcsqlite.NewSessions(o.db)})
	return &keyEnv{t: t, srv: srv, h: srv.Handler(), clk: clk, store: store, ix: ix, rec: rec, logs: logs,
		policy: o.policy, db: o.db, reg: reg}
}

// mint creates a key for owner sub in group with scopes and returns its plaintext
// and id.
func (e *keyEnv) mint(sub, group string, scopes ...apikeys.Scope) (string, string) {
	e.t.Helper()
	e.minted++
	tok, k, err := e.store.Create(context.Background(), apikeys.CreateParams{
		Name: fmt.Sprintf("key-%d", e.minted), OwnerIss: keyOwnerIss, OwnerSub: sub,
		OwnerEmail: sub + "@example.com", OwnerGroups: []string{group}, Scopes: scopes,
		TTL: 24 * time.Hour, MaxTTL: config.DefaultAPIKeyMaxTTL, MaxActive: 25,
	})
	if err != nil {
		e.t.Fatalf("mint: %v", err)
	}
	return tok, k.ID
}

func (e *keyEnv) allScopes() []apikeys.Scope { return e.reg.Registered() }

// do sends a request bearing token ("" for none).
func (e *keyEnv) do(token, method, path, body string) *httptest.ResponseRecorder {
	return e.doReq(token, method, path, body, nil)
}

func (e *keyEnv) doReq(token, method, path, body string, mut func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:4242"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if mut != nil {
		mut(req)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *keyEnv) policyBytes() string {
	b, err := os.ReadFile(e.policy)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s = %d %s, want %d", what, rec.Code, strings.TrimSpace(rec.Body.String()), want)
	}
}

func TestAPIKeyScopes(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, _ := e.mint("alice", groupEditor, "policy:read")
	before := e.policyBytes()

	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "GET policy with policy:read")
	rec := e.do(tok, http.MethodPost, "/dashboard/api/policy", policyBody)
	wantStatus(t, rec, http.StatusForbidden, "POST policy with policy:read")
	if got := strings.TrimSpace(rec.Body.String()); got != `{"error":"insufficient_scope","need":"policy:write"}` {
		t.Errorf("POST policy body = %s", got)
	}
	if after := e.policyBytes(); after != before {
		t.Errorf("policy file changed by a refused key:\n%s", after)
	}

	// The same editor's policy:write key writes.
	wtok, _ := e.mint("alice", groupEditor, "policy:write")
	wantStatus(t, e.do(wtok, http.MethodPost, "/dashboard/api/policy", policyBody), http.StatusOK, "POST policy with policy:write")
	// policy:write does not imply policy:read.
	rec = e.do(wtok, http.MethodGet, "/dashboard/api/policy", "")
	wantStatus(t, rec, http.StatusForbidden, "GET policy with policy:write only")
	if !strings.Contains(rec.Body.String(), `"need":"policy:read"`) {
		t.Errorf("body = %s, want need policy:read", rec.Body.String())
	}
	if c := e.srv.APIKeyAuthCounts(); c[APIKeyOutcomeInsufficientScope] < 2 || c[APIKeyOutcomeOK] < 2 {
		t.Errorf("counts = %v", c)
	}
}

// TestAPIKeyScopeMatrix: for every keyable table row, a key holding exactly that
// row's scope (owner admin) is let through authz, and a key holding every
// other scope is refused with insufficient_scope.
func TestAPIKeyScopeMatrix(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{noAudit: true, ratePerKey: 10000})
	ids := 0
	toks := map[apikeys.Scope]string{}
	others := map[apikeys.Scope]string{}
	for _, s := range e.allScopes() {
		ids++
		toks[s], _ = e.mint(fmt.Sprintf("admin%d", ids), groupAdmin, s)
		var rest []apikeys.Scope
		for _, o := range e.allScopes() {
			if o != s {
				rest = append(rest, o)
			}
		}
		others[s], _ = e.mint(fmt.Sprintf("other%d", ids), groupAdmin, rest...)
	}
	for k, row := range authzTable() {
		if row.Scope == apikeys.ScopeNone || row.Scope == apikeys.ScopeSelf {
			continue
		}
		path := strings.NewReplacer("{v}", "1", "{id}", "x").Replace(k.Path)
		name := k.Method + " " + path
		rec := e.do(toks[row.Scope], k.Method, path, "{}")
		if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "insufficient_scope") || rec.Code == http.StatusUnauthorized {
			t.Errorf("%s with %s = %d %s, want it past authz", name, row.Scope, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		rec = e.do(others[row.Scope], k.Method, path, "{}")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"need":"`+string(row.Scope)+`"`) {
			t.Errorf("%s without %s = %d %s, want 403 insufficient_scope", name, row.Scope, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}

// TestAPIKeyRejectedOutsideAdminAPI: a valid key holding every scope is refused
// on the worker routes and the human-session routes, and on every ScopeNone row.
func TestAPIKeyRejectedOutsideAdminAPI(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{ratePerKey: 10000})
	tok, _ := e.mint("root", groupAdmin, e.allScopes()...)
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/policy", http.StatusUnauthorized},
		{http.MethodPost, "/control/heartbeat", http.StatusUnauthorized},
		{http.MethodPost, "/central/ingest", http.StatusUnauthorized},
		{http.MethodGet, "/dashboard/", http.StatusUnauthorized},
		{http.MethodGet, "/auth/me", http.StatusUnauthorized},
		{http.MethodGet, "/central/secrets", http.StatusForbidden},
		{http.MethodPost, "/central/secrets", http.StatusForbidden},
		{http.MethodDelete, "/central/secrets/k", http.StatusForbidden},
		{http.MethodPost, "/dashboard/api/secretstore", http.StatusForbidden},
		{http.MethodPost, "/dashboard/api/settings", http.StatusForbidden},
		{http.MethodPost, "/dashboard/api/worker-tokens", http.StatusForbidden},
		{http.MethodPost, "/dashboard/api/query/generate", http.StatusForbidden},
		{http.MethodGet, "/dashboard/api/sessions", http.StatusForbidden},
		{http.MethodPost, "/dashboard/api/backup", http.StatusForbidden},
		{http.MethodGet, "/dashboard/api/brand-new", http.StatusForbidden},
	} {
		rec := e.do(tok, c.method, c.path, "{}")
		wantStatus(t, rec, c.want, c.method+" "+c.path)
		if c.want == http.StatusUnauthorized && rec.Header().Get("WWW-Authenticate") == "" && !strings.HasPrefix(c.path, "/policy") {
			t.Errorf("%s %s: 401 without WWW-Authenticate", c.method, c.path)
		}
	}
	// Every ScopeNone dashboard row refuses a key holding every scope.
	for k, row := range authzTable() {
		if row.Scope != apikeys.ScopeNone || !strings.HasPrefix(k.Path, "/dashboard/api/") {
			continue
		}
		path := strings.NewReplacer("{v}", "1", "{id}", "x").Replace(k.Path)
		rec := e.do(tok, k.Method, path, "{}")
		if row.SessionOnly { // key creation answers a key session_required
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"session_required"`) {
				t.Errorf("%s %s = %d %s, want 403 session_required", k.Method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
			}
			continue
		}
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"need":"none"`) {
			t.Errorf("%s %s = %d %s, want 403 insufficient_scope need none", k.Method, path, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
	}
}

// TestWorkerAuthRejectsAPIKeyEverywhere: a wak_ bearer is a 401 on the worker
// routes in every mode, before any comparison with the shared token.
func TestWorkerAuthRejectsAPIKeyEverywhere(t *testing.T) {
	for name, tok := range map[string]string{"open": "", "shared token": "legacy-secret"} {
		t.Run(name, func(t *testing.T) {
			srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: tok})
			h := srv.Handler()
			for _, c := range []struct{ method, path string }{
				{http.MethodGet, "/policy"}, {http.MethodPost, "/control/heartbeat"}, {http.MethodPost, "/central/ingest"},
			} {
				// A well-formed key, a truncated one and just the prefix: all 401.
				for _, bearer := range []string{"wak_" + strings.Repeat("0", 16) + "_" + strings.Repeat("a", 52), "wak_short", "wak_"} {
					req := httptest.NewRequest(c.method, c.path, strings.NewReader("{}"))
					req.Header.Set("Authorization", "Bearer "+bearer)
					rec := httptest.NewRecorder()
					h.ServeHTTP(rec, req)
					if rec.Code != http.StatusUnauthorized {
						t.Errorf("%s %s with %q = %d, want 401", c.method, c.path, bearer, rec.Code)
					}
				}
			}
		})
	}
	// The shared token itself still works, so the refusal is about the prefix.
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: "legacy-secret"})
	req := httptest.NewRequest(http.MethodGet, "/policy", nil)
	req.Header.Set("Authorization", "Bearer legacy-secret")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("shared token on /policy = %d, want 200", rec.Code)
	}
}

func TestAPIKeyOwnerDowngrade(t *testing.T) {
	db := openKeysDB(t)
	policy := writePolicyFile(t, "api.openai.com")
	e := newKeyEnv(t, keyEnvOpts{db: db, policy: policy})
	tok, _ := e.mint("alice", groupEditor, "policy:write", "policy:read")
	wantStatus(t, e.do(tok, http.MethodPost, "/dashboard/api/policy", policyBody), http.StatusOK, "POST policy as editor")

	// "Restart" the control plane on the same database with the owner's group
	// now mapped to viewer. The key keeps its scopes and its group snapshot.
	e2 := newKeyEnv(t, keyEnvOpts{db: db, policy: policy, roles: config.ConsoleRoles{
		Viewer: []string{groupViewer, groupEditor}, Admin: []string{groupAdmin},
	}})
	before := e2.policyBytes()
	rec := e2.do(tok, http.MethodPost, "/dashboard/api/policy", policyBody)
	wantStatus(t, rec, http.StatusForbidden, "POST policy after the downgrade")
	if !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Errorf("body = %s, want insufficient_scope", rec.Body.String())
	}
	if e2.policyBytes() != before {
		t.Error("policy changed by a downgraded owner's key")
	}
	wantStatus(t, e2.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "GET policy (viewer still covers policy:read)")

	// A group that maps to no role at all loses everything.
	e3 := newKeyEnv(t, keyEnvOpts{db: db, policy: policy, roles: config.ConsoleRoles{Admin: []string{groupAdmin}}})
	wantStatus(t, e3.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusForbidden, "GET policy with no role")
}

func TestAPIKeyAmbiguousCredentials(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, _ := e.mint("alice", groupEditor, "policy:read")
	raw, _, err := e.srv.sessions.Create(context.Background(), SessionInput{
		Iss: keyOwnerIss, Sub: "alice", Email: "alice@example.com", Groups: []string{groupEditor}, AuthMethod: "oidc"})
	if err != nil {
		t.Fatal(err)
	}
	withCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: raw}) }

	// Cookie plus a good key, and cookie plus a bad key: 400 either way, never a
	// session fallback.
	bad := strings.Replace(tok, "_", "_x", 1)[:len(tok)]
	for name, bearer := range map[string]string{"valid key": tok, "bad key": bad, "bare prefix": "wak_"} {
		rec := e.doReq(bearer, http.MethodGet, "/dashboard/api/policy", "", withCookie)
		wantStatus(t, rec, http.StatusBadRequest, "cookie + "+name)
		if !strings.Contains(rec.Body.String(), "ambiguous_credentials") {
			t.Errorf("cookie + %s body = %s", name, rec.Body.String())
		}
	}
	// The cookie alone still works.
	wantStatus(t, e.doReq("", http.MethodGet, "/dashboard/api/policy", "", withCookie), http.StatusOK, "cookie alone")

	// A key in the query string is refused wherever it appears.
	for _, q := range []string{"?api_key=" + tok, "?access_token=" + tok + "&x=1", "?" + tok + "=1"} {
		rec := e.do(tok, http.MethodGet, "/dashboard/api/policy"+q, "")
		wantStatus(t, rec, http.StatusBadRequest, "key in query "+q[:12])
		rec = e.do("", http.MethodGet, "/dashboard/api/policy"+q, "")
		wantStatus(t, rec, http.StatusBadRequest, "key in query without a header")
	}
	if strings.Contains(e.logs.String(), tok) {
		t.Error("the token reached the log")
	}

	// A bearer that is not a key is ignored exactly as before: no session, so 401.
	rec := e.do("some-other-bearer", http.MethodGet, "/dashboard/api/policy", "")
	wantStatus(t, rec, http.StatusUnauthorized, "non-key bearer")
	if rec.Header().Get("WWW-Authenticate") != "" {
		t.Error("a non-key bearer got the key authenticator's challenge")
	}
	// A non-key bearer next to a cookie is not ambiguous.
	wantStatus(t, e.doReq("some-other-bearer", http.MethodGet, "/dashboard/api/policy", "", withCookie), http.StatusOK, "cookie + non-key bearer")
	// Key requests skip CSRF and Origin: a cookieless write with a foreign Origin works.
	wtok, _ := e.mint("alice", groupEditor, "policy:write")
	wantStatus(t, e.doReq(wtok, http.MethodPost, "/dashboard/api/policy", policyBody, func(r *http.Request) {
		r.Header.Set("Origin", "https://evil.example")
	}), http.StatusOK, "key write without CSRF header")
}

func TestAPIKeyFailuresAreUniform(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, id := e.mint("alice", groupEditor, "policy:read")
	revoked, rid := e.mint("alice", groupEditor, "traffic:read")
	expired, _ := e.mint("alice", groupEditor, "audit:read")
	if err := e.store.Revoke(context.Background(), rid, "test"); err != nil {
		t.Fatal(err)
	}
	// Change the first secret character to a different base32 one: always a
	// well-formed key with the right id and a wrong secret. (Overwriting the
	// tail with "aa" was a no-op for the 1 in 64 keys that already end in "aa",
	// since the last character is always 'a' or 'q'.)
	sec := len("wak_") + 16 + 1
	sub := byte('a')
	if tok[sec] == 'a' {
		sub = 'b'
	}
	wrong := tok[:sec] + string(sub) + tok[sec+1:]
	if wrong == tok {
		t.Fatal("the bad-secret key equals the real one")
	}
	unknown := "wak_" + strings.Repeat("f", 16) + tok[len("wak_")+16:]
	cases := map[string]string{"malformed": "wak_nope", "unknown": unknown, "bad_secret": wrong, "revoked": revoked}
	var first string
	for name, bearer := range cases {
		rec := e.do(bearer, http.MethodGet, "/dashboard/api/policy", "")
		wantStatus(t, rec, http.StatusUnauthorized, name)
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s: WWW-Authenticate = %q", name, rec.Header().Get("WWW-Authenticate"))
		}
		body := rec.Body.String()
		if first == "" {
			first = body
		}
		if body != first || !strings.Contains(body, `"unauthorized"`) {
			t.Errorf("%s: body %q differs from %q", name, body, first)
		}
	}
	e.clk.Advance(25 * time.Hour)
	_ = expired // expired at this point; the Index checks expiry against the clock
	// Without Run nothing refreshes the Index; do what a poll would so the
	// staleness ceiling is not what refuses the key.
	if err := e.ix.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := e.do(tok, http.MethodGet, "/dashboard/api/policy", "")
	wantStatus(t, rec, http.StatusUnauthorized, "expired")
	if rec.Body.String() != first {
		t.Errorf("expired body %q differs", rec.Body.String())
	}
	c := e.srv.APIKeyAuthCounts()
	for _, o := range []string{APIKeyOutcomeMalformed, APIKeyOutcomeUnknown, APIKeyOutcomeBadSecret, APIKeyOutcomeRevoked, APIKeyOutcomeExpired} {
		if c[o] != 1 {
			t.Errorf("counter %s = %d, want 1 (all: %v)", o, c[o], c)
		}
	}
	// The rejection line carries the parsed id (not the secret) and the reason.
	logs := e.logs.String()
	if !strings.Contains(logs, "apikey_auth_rejected") || !strings.Contains(logs, "client_ip=192.0.2.10") {
		t.Errorf("rejection not logged:\n%s", logs)
	}
	if strings.Contains(logs, tok) || strings.Contains(logs, wrong) || strings.Contains(logs, revoked) {
		t.Error("a token reached the log")
	}
	_ = id
}

func TestAPIKeyRejectionLogRateLimited(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	for range 20 {
		e.do("wak_nope", http.MethodGet, "/dashboard/api/policy", "")
	}
	if n := strings.Count(e.logs.String(), "apikey_auth_rejected"); n != 1 {
		t.Errorf("%d rejection lines for 20 requests from one address, want 1", n)
	}
	if c := e.srv.APIKeyAuthCounts()[APIKeyOutcomeMalformed]; c != 20 {
		t.Errorf("malformed counter = %d, want 20 (every rejection counts)", c)
	}
	e.clk.Advance(2 * apiKeyRejectLogEvery)
	e.do("wak_nope", http.MethodGet, "/dashboard/api/policy", "")
	if n := strings.Count(e.logs.String(), "apikey_auth_rejected"); n != 2 {
		t.Errorf("%d rejection lines after the interval, want 2", n)
	}
}

func TestAPIKeyRateLimit(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{ratePerKey: 2, noAudit: true})
	a, _ := e.mint("alice", groupEditor, "policy:read")
	b, _ := e.mint("bob", groupEditor, "policy:read")
	// Burst is 2x the rate: four requests pass, the fifth does not.
	for i := range 4 {
		wantStatus(t, e.do(a, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, fmt.Sprintf("request %d", i+1))
	}
	rec := e.do(a, http.MethodGet, "/dashboard/api/policy", "")
	wantStatus(t, rec, http.StatusTooManyRequests, "request over the burst")
	if rec.Header().Get("Retry-After") == "" || !strings.Contains(rec.Body.String(), "rate_limited") {
		t.Errorf("429 = %v %s", rec.Header(), rec.Body.String())
	}
	// Another key has its own bucket.
	wantStatus(t, e.do(b, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "other key")
	// The bucket refills at ratePerKey per second.
	e.clk.Advance(time.Second)
	wantStatus(t, e.do(a, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "after 1s")
	wantStatus(t, e.do(a, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "after 1s (2nd)")
	wantStatus(t, e.do(a, http.MethodGet, "/dashboard/api/policy", ""), http.StatusTooManyRequests, "after 1s (3rd)")
	if c := e.srv.APIKeyAuthCounts()[APIKeyOutcomeRateLimited]; c != 2 {
		t.Errorf("rate_limited counter = %d, want 2", c)
	}
	// A failing key never creates a bucket (no unbounded growth from garbage).
	for i := range 50 {
		e.do(fmt.Sprintf("wak_%016x_%s", i, strings.Repeat("a", 52)), http.MethodGet, "/dashboard/api/policy", "")
	}
	e.srv.apiKeys.limiter.mu.Lock()
	n := len(e.srv.apiKeys.limiter.buckets)
	e.srv.apiKeys.limiter.mu.Unlock()
	if n != 2 {
		t.Errorf("limiter holds %d buckets, want 2 (only valid keys)", n)
	}
}

func TestAPIKeyAdminAudit(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, id := e.mint("alice", groupEditor, "policy:write", "policy:read")
	ro, roID := e.mint("alice", groupEditor, "policy:read")
	revoked, rid := e.mint("alice", groupEditor, "policy:write")

	wantStatus(t, e.do(tok, http.MethodPost, "/dashboard/api/policy", policyBody), http.StatusOK, "key write")
	rows := e.rec.inputs()
	if len(rows) != 1 {
		t.Fatalf("%d rows after one key write, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.AuthMethod != adminaudit.AuthMethodAPIKey || r.Actor.Sub != "alice" || r.Actor.Email != "alice@example.com" ||
		r.ActorRole != "editor" || r.Action != "policy.write" || r.Outcome != adminaudit.OutcomeOK ||
		r.Details[adminaudit.DetailAPIKeyID] != id || r.ClientIP != "192.0.2.10" {
		t.Errorf("row = %+v", r)
	}

	// A scope denial by a valid key is chained as denied, under the owner.
	wantStatus(t, e.do(ro, http.MethodPost, "/dashboard/api/policy", policyBody), http.StatusForbidden, "scope denial")
	rows = e.rec.inputs()
	if len(rows) != 2 || rows[1].Outcome != adminaudit.OutcomeDenied || rows[1].AuthMethod != adminaudit.AuthMethodAPIKey ||
		rows[1].Actor.Sub != "alice" || rows[1].Details[adminaudit.DetailAPIKeyID] != roID {
		t.Fatalf("denial rows = %+v", rows)
	}
	// Reads are not audited.
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "read")
	if got := len(e.rec.inputs()); got != 2 {
		t.Errorf("%d rows after a read, want 2", got)
	}

	// Invalid and revoked keys write no row.
	if err := e.store.Revoke(context.Background(), rid, "test"); err != nil {
		t.Fatal(err)
	}
	for _, bearer := range []string{revoked, "wak_nope", strings.Replace(tok, "_", "_z", 1)[:len(tok)]} {
		wantStatus(t, e.do(bearer, http.MethodPost, "/dashboard/api/policy", policyBody), http.StatusUnauthorized, "invalid key write")
	}
	if got := len(e.rec.inputs()); got != 2 {
		t.Errorf("%d rows after invalid keys, want 2", got)
	}

	// Neither the tokens nor their hashes are in any row or log line.
	var all strings.Builder
	for _, in := range e.rec.inputs() {
		fmt.Fprintf(&all, "%+v\n", in)
	}
	all.WriteString(e.logs.String())
	for _, tk := range []string{tok, ro, revoked} {
		if strings.Contains(all.String(), tk) {
			t.Error("a token is in a row or a log line")
		}
		for _, h := range secretHashes(t, tk) {
			if strings.Contains(all.String(), h) {
				t.Error("a token hash is in a row or a log line")
			}
		}
	}
}

// secretHashes returns the hex and base32 forms of sha256(secret) for a token.
func secretHashes(t *testing.T, tok string) []string {
	t.Helper()
	enc := base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
	secret, err := enc.DecodeString(tok[len(apikeys.Prefix)+17:])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(secret)
	return []string{hex.EncodeToString(sum[:]), strings.ToUpper(hex.EncodeToString(sum[:])), enc.EncodeToString(sum[:])}
}

// TestAPIKeyRevokedThroughStoreIsRefused: an in-process revoke applies at once,
// with no poll.
func TestAPIKeyRevokedThroughStoreIsRefused(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, id := e.mint("alice", groupEditor, "policy:read")
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "before revoke")
	if err := e.store.Revoke(context.Background(), id, "admin"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusUnauthorized, "after revoke")
	if n, err := e.store.RevokeByOwner(context.Background(), keyOwnerIss, "alice", "admin"); err != nil || n != 0 {
		t.Errorf("RevokeByOwner = %d, %v", n, err)
	}
}

// TestAPIKeyLastUsed: a request marks the key used in memory without any
// database write; Flush persists it.
func TestAPIKeyLastUsed(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, id := e.mint("alice", groupEditor, "policy:read")
	e.clk.Advance(10 * time.Second) // inside the Index's staleness ceiling
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "read")
	k, err := e.store.Get(context.Background(), id)
	if err != nil || !k.LastUsedAt.IsZero() {
		t.Fatalf("last_used_at written before a flush: %v %v", k.LastUsedAt, err)
	}
	if err := e.ix.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	k, _ = e.store.Get(context.Background(), id)
	if k.LastUsedAt.IsZero() || k.LastUsedIP != "192.0.2.10" {
		t.Errorf("after flush: used %v from %q", k.LastUsedAt, k.LastUsedIP)
	}
}

// TestAPIKeysDisabledChangesNothing: with console.apiKeys off no authenticator
// is built, a wak_ bearer is just an unrecognised bearer on the human routes,
// and the worker routes still refuse it.
func TestAPIKeysDisabledChangesNothing(t *testing.T) {
	e := newAuthzEnvOn(t, openSessionDB(t), writePolicyFile(t, "api.openai.com"), defaultRoles())
	if e.srv.apiKeys != nil || e.srv.apiKeyCounts != nil || len(e.srv.APIKeyAuthCounts()) != 0 {
		t.Fatal("API key state built with the feature off")
	}
	key := "wak_" + strings.Repeat("0", 16) + "_" + strings.Repeat("a", 52)
	for _, p := range []string{"/dashboard/api/policy", "/dashboard/api/policy?k=" + key} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("GET %s = %d %v, want the plain unauthenticated 401", p, rec.Code, rec.Header())
		}
	}
	// And the api_keys table is not created without the migration enabled.
	var n int
	_ = e.srv.cfg.State.SQL().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name='api_keys'`).Scan(&n)
	if n != 0 {
		t.Error("api_keys table created with the feature off")
	}
}

func TestStateMigrationsForAPIKeys(t *testing.T) {
	has := func(migs []cpstate.Migration, id string) (present, optional bool) {
		for _, m := range migs {
			if m.ID == id {
				return true, m.Optional
			}
		}
		return false, false
	}
	off := stateMigrationsFor(config.KeysConfig{}, config.ConsoleConfig{}, config.TokenServiceConfig{})
	if p, opt := has(off, sqlitestore.MigrationID); !p || !opt {
		t.Errorf("disabled: present=%v optional=%v, want the ID known and optional", p, opt)
	}
	on := stateMigrationsFor(config.KeysConfig{}, config.ConsoleConfig{APIKeys: config.ConsoleAPIKeys{Enabled: true}}, config.TokenServiceConfig{})
	if p, opt := has(on, sqlitestore.MigrationID); !p || opt {
		t.Errorf("enabled: present=%v optional=%v, want it applied", p, opt)
	}
	if p, _ := has(StateMigrations(), sqlitestore.MigrationID); !p {
		t.Error("StateMigrations must carry the ID so the offline CLIs' downgrade guard knows it")
	}
}

func BenchmarkAPIKeyMiddleware(b *testing.B) {
	logger, _ := testLogger()
	db, err := cpstate.Open(context.Background(), filepath.Join(b.TempDir(), "warden-cp.db"),
		cpstate.Enable(StateMigrations(), sqlitestore.MigrationID))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	store, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry(), Clock: clk})
	if err != nil {
		b.Fatal(err)
	}
	tok, _, err := store.Create(context.Background(), apikeys.CreateParams{
		Name: "bench", OwnerIss: keyOwnerIss, OwnerSub: "alice", OwnerGroups: []string{groupEditor},
		Scopes: []apikeys.Scope{"policy:read"}, TTL: 24 * time.Hour, MaxTTL: config.DefaultAPIKeyMaxTTL, MaxActive: 5,
	})
	if err != nil {
		b.Fatal(err)
	}
	ix, err := apikeys.NewIndex(context.Background(), store, apikeys.IndexOptions{Now: clk.Now, After: clk.After, Logger: logger})
	if err != nil {
		b.Fatal(err)
	}
	cc := authzConsole(defaultRoles())
	cc.APIKeys = config.ConsoleAPIKeys{Enabled: true, RatePerKey: config.MaxAPIKeysRatePerKey}
	a := newAPIKeyAuth(ix, cc, "warden_console", clk, logger, newAPIKeyCounters())
	h := a.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/policy", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.RemoteAddr = "192.0.2.10:4242"
	rec := httptest.NewRecorder()
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		h.ServeHTTP(rec, req)
		clk.Advance(time.Millisecond) // keep the token bucket from running dry
	}
}

const apiKeysRunBlock = oidcStartBlock + "  apiKeys:\n    enabled: true\n"

// TestRunStartsAPIKeyIndex: with console.apiKeys.enabled, Run builds the store
// and runs the Index for the control plane's whole life. A key created through a
// second handle (the offline CLI path) is picked up by the poll, a revoke made
// the same way is refused within a poll, and the last-use value is flushed when
// Run returns, before the state DB closes.
func TestRunStartsAPIKeyIndex(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy+apiKeysRunBlock)
	t.Setenv("WARDEN_CONSOLE_SECRET", "x-client-secret")
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))

	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- Run(ctx, &lockedBuffer{}, Params{
			ConfigPath: cfg, StateDir: state, ListenAddr: "127.0.0.1:0", AnalyticsProvider: "memory",
			Clock: clk, OnReady: func(a string) { ready <- a },
		})
	}()
	var addr string
	select {
	case addr = <-ready:
	case err := <-errCh:
		t.Fatalf("Run returned before serving: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnReady")
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("Run after cancel = %v, want nil", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for Run to return")
		}
	}
	defer stop()

	// The second handle, as the offline CLI opens the database.
	db, err := cpstate.Open(context.Background(), filepath.Join(state, "warden-cp.db"), cpstate.Enable(StateMigrations(), sqlitestore.MigrationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	store, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry(), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	tok, k, err := store.Create(context.Background(), apikeys.CreateParams{
		Name: "ci", OwnerIss: keyOwnerIss, OwnerSub: "alice", OwnerGroups: []string{"warden-admins"},
		Scopes: []apikeys.Scope{"policy:read"}, TTL: 24 * time.Hour, MaxTTL: config.DefaultAPIKeyMaxTTL, MaxActive: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	get := func() (int, string) {
		req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/dashboard/api/policy", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
	}
	// Condition-driven: Run's poll loop reacts on its own goroutine.
	poll := func(desc string, want int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if got, _ := get(); got == want {
				return
			}
			// Each iteration is a real HTTP round trip, which gives Run's goroutine
			// the time to react; no sleep, the condition is the wait.
			clk.Advance(apiKeyPollForTest)
		}
		t.Fatalf("timed out waiting for %s", desc)
	}
	poll("Run's Index to load a key created by another handle", http.StatusOK)

	if err := store.Revoke(context.Background(), k.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	poll("Run's Index to refuse a key revoked by another handle", http.StatusUnauthorized)
	if _, www := get(); www != "Bearer" {
		t.Errorf("revoked key challenge = %q, want the key authenticator's Bearer", www)
	}
}

const apiKeyPollForTest = apikeys.DefaultPollInterval

// TestRunAPIKeysNeedStateDir: enabled without --state-dir stops startup and
// names the setting; enabled outside oidc is refused by the config loader.
func TestRunAPIKeysNeedStateDir(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	writeFileT(t, cfg, basePolicy+apiKeysRunBlock)
	t.Setenv("WARDEN_CONSOLE_SECRET", "x-client-secret")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), &lockedBuffer{}, Params{ConfigPath: cfg, Listener: ln, AnalyticsProvider: "memory"})
	if err == nil || !strings.Contains(err.Error(), "console.apiKeys.enabled") {
		t.Fatalf("Run without --state-dir = %v, want an error naming console.apiKeys.enabled", err)
	}

	writeFileT(t, cfg, basePolicy+"console:\n  apiKeys:\n    enabled: true\n")
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), &lockedBuffer{}, Params{ConfigPath: cfg, Listener: ln2, StateDir: filepath.Join(dir, "s"), AnalyticsProvider: "memory"})
	if err == nil || !strings.Contains(err.Error(), "console.apiKeys.enabled") {
		t.Fatalf("Run with auth none = %v, want an error naming console.apiKeys.enabled", err)
	}
}

// TestStartAPIKeysStopFlushes: stop waits for Index.Run and its final flush.
func TestStartAPIKeysStopFlushes(t *testing.T) {
	db := openKeysDB(t)
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	logger, _ := testLogger()
	store, err := sqlitestore.New(db, sqlitestore.Options{Registry: newAPIKeyRegistry(), Clock: clk})
	if err != nil {
		t.Fatal(err)
	}
	_, k, err := store.Create(context.Background(), apikeys.CreateParams{
		Name: "ci", OwnerIss: keyOwnerIss, OwnerSub: "alice", OwnerGroups: []string{"g"},
		Scopes: []apikeys.Scope{"policy:read"}, TTL: 24 * time.Hour, MaxTTL: config.DefaultAPIKeyMaxTTL, MaxActive: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	reg := newAPIKeyRegistry()
	st, ix, stop, err := startAPIKeys(context.Background(), db, reg, clk, logger)
	if err != nil || st == nil {
		t.Fatalf("startAPIKeys = %v, %v", st, err)
	}
	ix.MarkUsed(k.ID, clk.Now(), "192.0.2.1")
	stop()
	got, err := store.Get(context.Background(), k.ID)
	if err != nil || got.LastUsedIP != "192.0.2.1" {
		t.Fatalf("after stop: %+v %v, want the last use flushed", got, err)
	}
	if _, _, _, err := startAPIKeys(context.Background(), nil, reg, clk, logger); err == nil || !strings.Contains(err.Error(), "--state-dir") {
		t.Errorf("startAPIKeys without a state db = %v, want an error naming --state-dir", err)
	}
}

// TestAPIKeyBlockedOwner: blocking a key's owner refuses the key at once, on
// reads and writes, with the policy untouched; the refusal is a counted
// insufficient_scope and a chained denied row. Unblocking restores it.
func TestAPIKeyBlockedOwner(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	tok, _ := e.mint("alice", groupEditor, "policy:read", "policy:write")
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "before the block")
	if e.srv.blocks == nil || !e.srv.blocks.Ready() {
		t.Fatal("the block list must be loaded")
	}
	id, err := e.srv.blocks.Add(context.Background(), BlockEntry{Sub: "alice"}, "cli:test")
	if err != nil {
		t.Fatal(err)
	}
	before := e.policyBytes()
	rows := len(e.rec.inputs())
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusForbidden, "GET policy, owner blocked")
	rec := e.do(tok, http.MethodPost, "/dashboard/api/policy", policyBody)
	wantStatus(t, rec, http.StatusForbidden, "POST policy, owner blocked")
	if !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Errorf("body = %s", rec.Body.String())
	}
	if e.policyBytes() != before {
		t.Error("policy changed by a blocked owner's key")
	}
	got := e.rec.inputs()
	if len(got) != rows+1 || got[rows].Outcome != adminaudit.OutcomeDenied || got[rows].AuthMethod != adminaudit.AuthMethodAPIKey {
		t.Errorf("rows = %+v, want one new denied apikey row", got[rows:])
	}
	if c := e.srv.APIKeyAuthCounts()[APIKeyOutcomeInsufficientScope]; c != 2 {
		t.Errorf("insufficient_scope = %d, want 2", c)
	}
	// Blocked by email alone as well.
	if err := e.srv.blocks.Remove(context.Background(), id, "cli:test"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusOK, "after the unblock")
	if _, err := e.srv.blocks.Add(context.Background(), BlockEntry{Email: "ALICE@example.com"}, "cli:test"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do(tok, http.MethodGet, "/dashboard/api/policy", ""), http.StatusForbidden, "owner blocked by email")
}

// TestAPIKeyAuthorsUnderOwner: a key-made policy version is authored by the
// owner with kind apikey, and a key-made block list entry is created_by
// oidc:<owner>; the owner's own key cannot block the owner (isSelf).
func TestAPIKeyAuthorsUnderOwner(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{versioned: true})
	tok, _ := e.mint("alice", groupAdmin, "policy:write")
	rec := e.doReq(tok, http.MethodPost, "/dashboard/api/policy", policyBody, func(r *http.Request) { r.Header.Set("If-Match", `"v1"`) })
	wantStatus(t, rec, http.StatusOK, "versioned key write")
	v := headVersion(t, e.srv)
	if v.Version != 2 || v.Author.Sub != "alice" || v.Author.Kind != AuthorKindAPIKey || v.Author.Email != "alice@example.com" {
		t.Errorf("head = v%d by %+v, want v2 by alice, kind apikey", v.Version, v.Author)
	}

	rec = e.do(tok, http.MethodPost, blockAPIPath, `{"sub":"someone-else","email":"x@corp.com"}`)
	wantStatus(t, rec, http.StatusCreated, "key block add")
	var created blockPostResp
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.CreatedBy != "oidc:alice" {
		t.Errorf("created_by = %q (%v), want oidc:alice", created.CreatedBy, err)
	}
	// isSelf (the guard against lifting one's own block) sees the owner, not the
	// key's "apikey:<id>" subject.
	ctx := WithPrincipal(context.Background(), keyPrincipal(apikeys.Key{ID: "k1", OwnerIss: keyOwnerIss, OwnerSub: "alice", OwnerEmail: "alice@example.com"}))
	if !isSelf(ctx, BlockEntry{Sub: "alice"}) || !isSelf(ctx, BlockEntry{Email: "ALICE@example.com"}) {
		t.Error("isSelf does not recognise the key's owner")
	}
	if isSelf(ctx, BlockEntry{Sub: "apikey:k1"}) || isSelf(ctx, BlockEntry{Sub: "someone-else"}) {
		t.Error("isSelf matched something that is not the owner")
	}
}

// TestAPIKeyHeaderRobustness: a key is recognised however the header is
// spelled, and several Authorization values are refused.
func TestAPIKeyHeaderRobustness(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{ratePerKey: 10000})
	tok, _ := e.mint("alice", groupEditor, "policy:read")
	for name, hdr := range map[string]string{
		"lowercase scheme": "bearer " + tok, "mixed scheme": "BeArEr " + tok, "extra spaces": "Bearer   " + tok + "  ",
	} {
		rec := e.doReq("", http.MethodGet, "/dashboard/api/policy", "", func(r *http.Request) { r.Header.Set("Authorization", hdr) })
		wantStatus(t, rec, http.StatusOK, name)
	}
	rec := e.doReq("", http.MethodGet, "/dashboard/api/policy", "", func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+tok)
		r.Header.Add("Authorization", "Bearer other")
	})
	wantStatus(t, rec, http.StatusBadRequest, "two Authorization values")
	rec = e.doReq("", http.MethodGet, "/dashboard/api/policy", "", func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer other")
		r.Header.Add("Authorization", "Bearer "+tok)
	})
	wantStatus(t, rec, http.StatusBadRequest, "a key in the second value")

	// The worker routes refuse a key in any Authorization value or spelling.
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	h := srv.Handler()
	for name, vals := range map[string][]string{
		"lowercase":    {"bearer " + tok},
		"padded":       {"Bearer    " + tok},
		"second value": {"Bearer other", "Bearer " + tok},
		"first value":  {"Bearer " + tok, "Bearer other"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/policy", nil)
		for _, v := range vals {
			req.Header.Add("Authorization", v)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("/policy with %s = %d, want 401", name, rr.Code)
		}
	}
}

// TestAPIKeySelfScopeKeepsRole: a ScopeSelf row still needs the owner's role.
func TestAPIKeySelfScopeKeepsRole(t *testing.T) {
	p := Principal{Kind: PrincipalAPIKey}
	row := authzRow{MinRole: config.RoleEditor, Scope: apikeys.ScopeSelf}
	if ok, _ := keyAuthorized(p, row, config.RoleViewer); ok {
		t.Error("a viewer-owned key passed an editor ScopeSelf row")
	}
	if ok, _ := keyAuthorized(p, row, config.RoleEditor); !ok {
		t.Error("an editor-owned key was refused a ScopeSelf row")
	}
}

// TestStartAPIKeysRunOutlivesParent: Index.Run is stopped only by stop(), not
// by cancelling the context it was started with, so last-use marks from
// requests still in flight at shutdown reach the final flush.
func TestStartAPIKeysRunOutlivesParent(t *testing.T) {
	db := openKeysDB(t)
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))
	logger, _ := testLogger()
	ctx, cancel := context.WithCancel(context.Background())
	st, ix, stop, err := startAPIKeys(ctx, db, newAPIKeyRegistry(), clk, logger)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	base := ix.Polls()
	deadline := time.Now().Add(10 * time.Second)
	for ix.Polls() <= base {
		if time.Now().After(deadline) {
			t.Fatal("Run stopped polling when its parent context was cancelled")
		}
		clk.Advance(apikeys.DefaultPollInterval)
		runtime.Gosched()
	}
	_, k, err := st.Create(context.Background(), apikeys.CreateParams{
		Name: "late", OwnerIss: keyOwnerIss, OwnerSub: "alice", OwnerGroups: []string{"g"},
		Scopes: []apikeys.Scope{"policy:read"}, TTL: 24 * time.Hour, MaxTTL: config.DefaultAPIKeyMaxTTL, MaxActive: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	ix.MarkUsed(k.ID, clk.Now(), "192.0.2.9")
	stop()
	if got, err := st.Get(context.Background(), k.ID); err != nil || got.LastUsedIP != "192.0.2.9" {
		t.Fatalf("after stop: %+v %v, want the in-flight use flushed", got, err)
	}
}
