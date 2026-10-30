package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/metastore"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/test/fakes"
)

// countingKeyStore counts every call into the private key store.
type countingKeyStore struct {
	keys.PrivateKeyStore
	n atomic.Int64
}

func (c *countingKeyStore) Put(ctx context.Context, p, k string, b []byte) error {
	c.n.Add(1)
	return c.PrivateKeyStore.Put(ctx, p, k, b)
}

func (c *countingKeyStore) Get(ctx context.Context, p, k string) ([]byte, error) {
	c.n.Add(1)
	return c.PrivateKeyStore.Get(ctx, p, k)
}

func (c *countingKeyStore) Delete(ctx context.Context, p, k string) error {
	c.n.Add(1)
	return c.PrivateKeyStore.Delete(ctx, p, k)
}

func (c *countingKeyStore) List(ctx context.Context, p string) ([]string, error) {
	c.n.Add(1)
	return c.PrivateKeyStore.List(ctx, p)
}

// countingKeyMeta counts every call into the signing_keys metadata store.
type countingKeyMeta struct {
	keys.MetaStore
	n atomic.Int64
}

func (c *countingKeyMeta) List(ctx context.Context) ([]keys.Record, error) {
	c.n.Add(1)
	return c.MetaStore.List(ctx)
}

func (c *countingKeyMeta) Insert(ctx context.Context, r keys.Record) error {
	c.n.Add(1)
	return c.MetaStore.Insert(ctx, r)
}

func (c *countingKeyMeta) InsertIfEmpty(ctx context.Context, p string, r []keys.Record) (bool, error) {
	c.n.Add(1)
	return c.MetaStore.InsertIfEmpty(ctx, p, r)
}

func (c *countingKeyMeta) UpdateState(ctx context.Context, kid string, from, to keys.State, at time.Time) (bool, error) {
	c.n.Add(1)
	return c.MetaStore.UpdateState(ctx, kid, from, to, at)
}

func (c *countingKeyMeta) Promote(ctx context.Context, purpose, oldKID string, oldTo keys.State, nextKID string, at time.Time) (bool, error) {
	c.n.Add(1)
	return c.MetaStore.Promote(ctx, purpose, oldKID, oldTo, nextKID, at)
}

func (c *countingKeyMeta) DataVersion(ctx context.Context) (int64, error) {
	c.n.Add(1)
	return c.MetaStore.DataVersion(ctx)
}

// stubKeys is a KeysSource whose every call succeeds; it lets a test reach the
// rotate route without a key manager.
type stubKeys struct{}

func (stubKeys) Keys(context.Context) dashboard.KeysResponse { return dashboard.KeysResponse{} }

func (stubKeys) Rotate(context.Context, dashboard.KeyRotateRequest) error { return nil }

// keysEnv is a control plane with a real key manager on a fake clock, driven
// through Server.Handler.
type keysEnv struct {
	srv   *Server
	h     http.Handler
	mgr   *keys.Manager
	clk   *clocktest.Fake
	rec   *fakeRecorder
	fs    *fakes.FakeKeyStore
	store *countingKeyStore
	meta  *countingKeyMeta
}

type keysEnvOpts struct {
	oidc     bool // console.auth oidc (default none)
	strict   bool // --require-worker-tokens
	disabled bool // keys.enabled false: no manager
	down     bool // the key store is down at startup
	noAudit  bool
}

func newKeysEnv(t *testing.T, o keysEnvOpts) *keysEnv {
	t.Helper()
	logger, _ := testLogger()
	kc, err := config.KeysConfig{Enabled: true}.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	db, err := cpstate.Open(context.Background(), t.TempDir()+"/warden-cp.db", stateMigrationsFor(kc))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	clk := clocktest.NewFake(time.Unix(1_800_000_000, 0))

	cfg := detectionEditorConfig(t)
	cfg.State, cfg.Logger, cfg.Clock, cfg.Token = db, logger, clk, dashTestToken
	cfg.RequireWorkerTokens = o.strict
	if o.oidc {
		cfg.Console = authzConsole(defaultRoles())
	}
	e := &keysEnv{clk: clk, rec: &fakeRecorder{}, fs: fakes.NewFakeKeyStore()}
	e.store = &countingKeyStore{PrivateKeyStore: e.fs}
	e.meta = &countingKeyMeta{MetaStore: metastore.New(db)}
	if !o.disabled {
		mc := keys.ManagerConfig{
			Store: e.store, Meta: e.meta, Codec: signer.Codec{}, Backend: "fake",
			Algs: map[string]string{keys.PurposeToken: keys.AlgEdDSA, keys.PurposeBundle: keys.AlgEdDSA},
			Timings: map[string]keys.Timing{
				keys.PurposeToken:  {Interval: 720 * time.Hour, Prepublish: time.Hour, Overlap: 48 * time.Hour},
				keys.PurposeBundle: {Prepublish: time.Hour, Overlap: 48 * time.Hour},
			},
			Now:    clk.Now,
			Wait:   func(ctx context.Context, d time.Duration) bool { return waitOn(ctx, clk, d) },
			Logger: logger,
		}
		if !o.noAudit {
			mc.Audit = keysAudit{rec: e.rec}
		}
		e.mgr, err = keys.NewManager(mc)
		if err != nil {
			t.Fatal(err)
		}
		if o.down {
			e.fs.SetDown(errors.New("store down"))
		}
		e.mgr.Init(context.Background())
		e.fs.SetDown(nil)
		cfg.Keys = e.mgr
	}
	e.srv = New(cfg)
	t.Cleanup(func() {
		if e.srv.integrationsStore != nil {
			_ = e.srv.integrationsStore.Close()
		}
	})
	if e.srv.sessions != nil {
		e.srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, newFakeClock().Now)
		e.srv.sessionReader = e.srv.sessions
	}
	if !o.noAudit {
		e.srv.enableAdminAudit(e.rec, e.rec.probe, fakeMAC)
	}
	e.h = e.srv.Handler()
	return e
}

func (e *keysEnv) session(t *testing.T, group string) string {
	t.Helper()
	in := testSessionInput()
	in.Groups = []string{group}
	raw, _, err := e.srv.sessions.Create(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// do sends a request; rawID is a session ("" none), carrying its CSRF token on
// writes.
func (e *keysEnv) do(rawID, method, target, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if rawID != "" {
		req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: rawID})
		if method != http.MethodGet {
			req.Header.Set(CSRFHeader, CSRFToken(rawID))
		}
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *keysEnv) jwks(hdr ...string) *httptest.ResponseRecorder {
	return e.do("", http.MethodGet, jwksPath, "", hdr...)
}

// jwksKids returns the kids of a 200 JWKS response, failing if any member is
// not a public key the verifier library accepts.
func jwksKids(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("JWKS = %d %s, want 200", rec.Code, rec.Body)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, raw := range doc.Keys {
		var members map[string]json.RawMessage
		if err := json.Unmarshal(raw, &members); err != nil {
			t.Fatal(err)
		}
		for m := range members {
			switch m {
			case "kty", "crv", "x", "y", "kid", "alg", "use":
			default:
				t.Errorf("JWKS member %q is not a public JWK member", m)
			}
		}
		if _, ok := members["d"]; ok {
			t.Fatal("JWKS carries a private parameter d")
		}
		jwk, err := keys.ParseJWK(raw)
		if err != nil {
			t.Fatalf("ParseJWK: %v", err)
		}
		kids = append(kids, jwk.Kid)
	}
	return kids
}

func TestJWKSEndpoint(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    keysEnvOpts
	}{
		{"oidc", keysEnvOpts{oidc: true}},
		{"strict worker tokens", keysEnvOpts{oidc: true, strict: true}},
		{"console none strict", keysEnvOpts{strict: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newKeysEnv(t, tc.o)
			rec := e.jwks()
			kids := jwksKids(t, rec)
			if len(kids) != 2 {
				t.Fatalf("JWKS has %d keys, want active and next: %v", len(kids), kids)
			}
			h := rec.Header()
			if got := h.Get("Content-Type"); got != "application/jwk-set+json" {
				t.Errorf("Content-Type = %q", got)
			}
			if got := h.Get("Cache-Control"); got != "public, max-age=300" {
				t.Errorf("Cache-Control = %q", got)
			}
			etag := h.Get("ETag")
			if len(etag) < 3 || etag[0] != '"' || etag[len(etag)-1] != '"' {
				t.Errorf("ETag = %q, want a quoted value", etag)
			}
			for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
				if got := e.do("", m, jwksPath, "{}"); got.Code != http.StatusMethodNotAllowed {
					t.Errorf("%s = %d, want 405", m, got.Code)
				}
			}
			head := e.do("", http.MethodHead, jwksPath, "")
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("ETag") != etag {
				t.Errorf("HEAD = %d body %d etag %q", head.Code, head.Body.Len(), head.Header().Get("ETag"))
			}
		})
	}
}

func TestJWKSConditionalAndRotation(t *testing.T) {
	e := newKeysEnv(t, keysEnvOpts{oidc: true})
	first := e.jwks()
	etag := first.Header().Get("ETag")
	for _, inm := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
		got := e.jwks("If-None-Match", inm)
		if got.Code != http.StatusNotModified || got.Body.Len() != 0 {
			t.Errorf("If-None-Match %q = %d body %d, want 304 empty", inm, got.Code, got.Body.Len())
		}
		if got.Header().Get("ETag") != etag {
			t.Errorf("304 carries ETag %q, want %q", got.Header().Get("ETag"), etag)
		}
	}
	if got := e.jwks("If-None-Match", `"stale"`); got.Code != http.StatusOK {
		t.Errorf("non-matching If-None-Match = %d, want 200", got.Code)
	}

	// A rotation moves the set: the old next becomes active, a fresh next is
	// published, and the old active stays inside its overlap.
	before := jwksKids(t, first)
	e.clk.Advance(2 * time.Hour)
	if err := e.mgr.Rotate(context.Background(), keys.PurposeToken, keys.RotateOpts{}); err != nil {
		t.Fatal(err)
	}
	after := e.jwks("If-None-Match", etag)
	if after.Code != http.StatusOK {
		t.Fatalf("after rotation = %d, want 200 with a new ETag", after.Code)
	}
	if after.Header().Get("ETag") == etag {
		t.Error("ETag did not change after a rotation")
	}
	kids := jwksKids(t, after)
	if len(kids) != 3 {
		t.Fatalf("after rotation %d keys, want next, active and the retired one: %v", len(kids), kids)
	}
	seen := map[string]bool{}
	for _, k := range before {
		seen[k] = true
	}
	var fresh int
	for _, k := range kids {
		if !seen[k] {
			fresh++
		}
	}
	if fresh != 1 {
		t.Errorf("%d new kids after rotation, want exactly the fresh next key: before %v after %v", fresh, before, kids)
	}

	// The overlap ends with no version change: the retired key leaves the set
	// on the next request after the window.
	e.clk.Advance(49 * time.Hour)
	gone := e.jwks()
	if len(jwksKids(t, gone)) != 2 {
		t.Errorf("retired key still published past its overlap: %s", gone.Body)
	}
	if gone.Header().Get("ETag") == after.Header().Get("ETag") {
		t.Error("ETag unchanged after the overlap ended")
	}
}

func TestJWKSDisabled(t *testing.T) {
	e := newKeysEnv(t, keysEnvOpts{oidc: true, disabled: true})
	admin := e.session(t, groupAdmin)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, jwksPath},
		{http.MethodPost, jwksPath},
		{http.MethodGet, "/dashboard/api/keys"},
		{http.MethodPost, "/dashboard/api/keys/rotate"},
	} {
		if got := e.do(admin, c.method, c.path, `{"purpose":"token"}`); got.Code != http.StatusNotFound {
			t.Errorf("%s %s with keys disabled = %d, want 404", c.method, c.path, got.Code)
		}
	}
	if got := e.do("", http.MethodGet, readyzPath, ""); got.Code != http.StatusOK {
		t.Errorf("/readyz with keys disabled = %d, want 200", got.Code)
	}
}

func TestJWKSUnavailableAndReadyz(t *testing.T) {
	e := newKeysEnv(t, keysEnvOpts{oidc: true, down: true})
	got := e.jwks()
	if got.Code != http.StatusServiceUnavailable || strings.TrimSpace(got.Body.String()) != `{"error":"signing_unavailable"}` {
		t.Errorf("JWKS without keys = %d %q, want 503 signing_unavailable", got.Code, got.Body)
	}
	if got.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("503 Cache-Control = %q, want no-store", got.Header().Get("Cache-Control"))
	}
	ready := e.do("", http.MethodGet, readyzPath, "")
	if ready.Code != http.StatusServiceUnavailable || strings.TrimSpace(ready.Body.String()) != `{"keys":"no_active_key"}` {
		t.Errorf("/readyz = %d %q, want 503 no_active_key", ready.Code, ready.Body)
	}
	if h := e.do("", http.MethodGet, "/healthz", ""); h.Code != http.StatusOK || h.Body.String() != "ok\n" {
		t.Errorf("/healthz = %d %q, want 200 ok", h.Code, h.Body)
	}
	if m := e.do("", http.MethodPost, readyzPath, ""); m.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /readyz = %d, want 405", m.Code)
	}

	// The store comes back and the load retry succeeds: both flip.
	if err := e.mgr.LoadKeySet(context.Background(), keys.PurposeToken); err != nil {
		t.Fatalf("LoadKeySet: %v", err)
	}
	if err := e.mgr.LoadKeySet(context.Background(), keys.PurposeBundle); err != nil {
		t.Fatalf("LoadKeySet: %v", err)
	}
}

// TestJWKSNoIO: once loaded, serving the JWKS touches neither the key store
// nor the database, however many verifiers fetch at once.
func TestJWKSNoIO(t *testing.T) {
	e := newKeysEnv(t, keysEnvOpts{oidc: true, strict: true})
	storeBefore, metaBefore := e.store.n.Load(), e.meta.n.Load()
	if storeBefore == 0 || metaBefore == 0 {
		t.Fatalf("setup did no I/O (store %d, meta %d): the counters are not wired", storeBefore, metaBefore)
	}
	var wg sync.WaitGroup
	var bad atomic.Int64
	for range 1000 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, jwksPath, nil)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !bytes.Contains(rec.Body.Bytes(), []byte(`"keys"`)) {
				bad.Add(1)
			}
			rd := httptest.NewRecorder()
			e.h.ServeHTTP(rd, httptest.NewRequest(http.MethodGet, readyzPath, nil))
			if rd.Code != http.StatusOK {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 {
		t.Errorf("%d requests failed", bad.Load())
	}
	if got := e.store.n.Load(); got != storeBefore {
		t.Errorf("key store calls grew from %d to %d during 1000 JWKS fetches", storeBefore, got)
	}
	if got := e.meta.n.Load(); got != metaBefore {
		t.Errorf("signing_keys calls grew from %d to %d during 1000 JWKS fetches", metaBefore, got)
	}
}

func TestEtagMatches(t *testing.T) {
	const tag = `"abc"`
	for _, c := range []struct {
		header string
		want   bool
	}{
		{"", false}, {tag, true}, {"W/" + tag, true}, {`"x","abc"`, true},
		{`"x", "abc"`, true}, {"*", true}, {`"abcd"`, false}, {`abc`, false},
	} {
		if got := etagMatches(c.header, tag); got != c.want {
			t.Errorf("etagMatches(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

// keyActions returns the actions of the recorded admin rows.
func keyActions(rec *fakeRecorder) []adminaudit.Input {
	var out []adminaudit.Input
	for _, in := range rec.inputs() {
		if in.Action == "keys.rotate_requested" {
			out = append(out, in)
		}
	}
	return out
}

func TestKeysAdminAPI(t *testing.T) {
	const listPath, rotatePath = "/dashboard/api/keys", "/dashboard/api/keys/rotate"
	e := newKeysEnv(t, keysEnvOpts{oidc: true})
	viewer, editor, admin := e.session(t, groupViewer), e.session(t, groupEditor), e.session(t, groupAdmin)

	for _, s := range []struct{ name, raw string }{{"viewer", viewer}, {"editor", editor}} {
		if got := e.do(s.raw, http.MethodGet, listPath, ""); got.Code != http.StatusForbidden {
			t.Errorf("%s GET keys = %d, want 403", s.name, got.Code)
		}
		if got := e.do(s.raw, http.MethodPost, rotatePath, `{"purpose":"token"}`); got.Code != http.StatusForbidden {
			t.Errorf("%s POST rotate = %d, want 403", s.name, got.Code)
		}
	}
	if got := e.do("", http.MethodGet, listPath, ""); got.Code != http.StatusUnauthorized {
		t.Errorf("anonymous GET keys = %d, want 401", got.Code)
	}
	// Authenticated refusals are recorded as denied; nothing was rotated.
	for _, in := range keyActions(e.rec) {
		if in.Outcome != adminaudit.OutcomeDenied {
			t.Fatalf("a refused rotate wrote a %s row", in.Outcome)
		}
	}

	list := e.do(admin, http.MethodGet, listPath, "")
	if list.Code != http.StatusOK {
		t.Fatalf("admin GET keys = %d %s", list.Code, list.Body)
	}
	for _, banned := range []string{`"d"`, "PRIVATE", "private", `"pem"`} {
		if strings.Contains(list.Body.String(), banned) {
			t.Errorf("key list contains %s", banned)
		}
	}
	var resp struct {
		Keys []struct {
			KID, Purpose, Alg, State, Backend string
			PublicJWK                         map[string]string `json:"publicJwk"`
		} `json:"keys"`
		Purposes []struct {
			Purpose string
			Loaded  bool
		} `json:"purposes"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Keys) != 4 || len(resp.Purposes) != 2 {
		t.Fatalf("list = %d keys %d purposes, want an active and a next key per purpose: %s", len(resp.Keys), len(resp.Purposes), list.Body)
	}
	for _, k := range resp.Keys {
		if k.KID == "" || k.PublicJWK["kid"] != k.KID || k.PublicJWK["x"] == "" || k.Backend != "fake" {
			t.Errorf("incomplete key view: %+v", k)
		}
		if _, ok := k.PublicJWK["d"]; ok {
			t.Error("public JWK has d")
		}
	}
	for _, p := range resp.Purposes {
		if !p.Loaded {
			t.Errorf("purpose %s not loaded", p.Purpose)
		}
	}

	// The next key has not been published for its prepublish window: refused,
	// and a refused rotation is a conflict, not a server error.
	if got := e.do(admin, http.MethodPost, rotatePath, `{"purpose":"token"}`); got.Code != http.StatusConflict {
		t.Errorf("early rotate = %d %s, want 409", got.Code, got.Body)
	}

	e.clk.Advance(2 * time.Hour)
	e.rec.reset()
	rot := e.do(admin, http.MethodPost, rotatePath, `{"purpose":"token"}`)
	if rot.Code != http.StatusOK {
		t.Fatalf("rotate = %d %s", rot.Code, rot.Body)
	}
	rows := keyActions(e.rec)
	if len(rows) != 1 {
		t.Fatalf("rotate wrote %d admin rows, want 1: %+v", len(rows), e.rec.inputs())
	}
	row := rows[0]
	if row.Outcome != adminaudit.OutcomeOK || row.Target != "keys" || row.TargetRef != "keys:token" ||
		row.Actor.Sub != "u1" || row.AuthMethod != adminaudit.AuthMethodOIDC || row.HTTPStatus != http.StatusOK {
		t.Errorf("admin row = %+v", row)
	}
	if row.BeforeHash == "" || row.BeforeHash == row.AfterHash {
		t.Errorf("rotation did not move the state hash: %q -> %q", row.BeforeHash, row.AfterHash)
	}
	var sawActivated bool
	for _, in := range e.rec.inputs() {
		if in.Action == keys.ActionActivated && in.Actor.Sub == "u1" {
			sawActivated = true
		}
	}
	if !sawActivated {
		t.Error("the manager's keys.activated row does not name the console actor")
	}

	// Bundle rotation is staged through the CLI; nothing is rotated.
	e.rec.reset()
	b := e.do(admin, http.MethodPost, rotatePath, `{"purpose":"bundle","confirmPinned":true}`)
	if b.Code != http.StatusConflict || !strings.Contains(b.Body.String(), `"use_cli"`) {
		t.Errorf("bundle rotate = %d %s, want 409 use_cli", b.Code, b.Body)
	}
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"unknown purpose", `{"purpose":"ca"}`, http.StatusBadRequest},
		{"empty", `{}`, http.StatusBadRequest},
		{"unknown field", `{"purpose":"token","force":true}`, http.StatusBadRequest},
		{"trailing data", `{"purpose":"token"}{}`, http.StatusBadRequest},
		{"not json", `nope`, http.StatusBadRequest},
		{"oversized", `{"purpose":"` + strings.Repeat("a", 4096) + `"}`, http.StatusRequestEntityTooLarge},
	} {
		if got := e.do(admin, http.MethodPost, rotatePath, c.body); got.Code != c.want {
			t.Errorf("%s = %d %s, want %d", c.name, got.Code, got.Body, c.want)
		}
	}
	if got := e.do(admin, http.MethodGet, rotatePath, ""); got.Code != http.StatusForbidden {
		t.Errorf("GET rotate = %d, want 403 (no authz row)", got.Code)
	}
	if got := e.do(admin, http.MethodPost, listPath, "{}"); got.Code != http.StatusForbidden {
		t.Errorf("POST keys = %d, want 403 (no authz row)", got.Code)
	}
	// A session write without its CSRF token is refused before the handler.
	req := httptest.NewRequest(http.MethodPost, rotatePath, strings.NewReader(`{"purpose":"token"}`))
	req.AddCookie(&http.Cookie{Name: e.srv.sessionCookie.Name, Value: admin})
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("rotate without CSRF = %d, want 403", rec.Code)
	}

	// Emergency rotation revokes the old key.
	e.clk.Advance(0)
	em := e.do(admin, http.MethodPost, rotatePath, `{"purpose":"token","emergency":true}`)
	if em.Code != http.StatusOK {
		t.Fatalf("emergency rotate = %d %s", em.Code, em.Body)
	}
	if !strings.Contains(em.Body.String(), `"revoked"`) {
		t.Errorf("emergency rotation left no revoked key: %s", em.Body)
	}
}

// TestKeysAdminConsoleNone: without sign-in there is nobody to attribute a
// rotation to, so the console refuses and points at the CLI.
func TestKeysAdminConsoleNone(t *testing.T) {
	e := newKeysEnv(t, keysEnvOpts{noAudit: true})
	got := e.do("", http.MethodPost, "/dashboard/api/keys/rotate", `{"purpose":"token"}`, "Authorization", "Bearer "+dashTestToken)
	if got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "use_cli") {
		t.Errorf("rotate in console.auth none = %d %s, want 403 use_cli", got.Code, got.Body)
	}
	e.clk.Advance(2 * time.Hour)
	if kids := jwksKids(t, e.jwks()); len(kids) != 2 {
		t.Errorf("a refused rotation changed the JWKS: %v", kids)
	}
}
