package controlplane

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

const testRedirectHTTPS = "https://cp.example/auth/callback"

// fakeClock is the control-plane clock of the session tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_800_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func openSessionDB(t *testing.T) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newTestStore(t *testing.T, clk *fakeClock) (*SessionStore, *cpstate.DB) {
	t.Helper()
	db := openSessionDB(t)
	return NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, clk.Now), db
}

func testSessionInput() SessionInput {
	return SessionInput{Iss: "https://idp.example", Sub: "u1", Email: "u1@example.com", Groups: []string{"warden-admins"}, AuthMethod: "oidc"}
}

func testCookie(t *testing.T) SessionCookie {
	t.Helper()
	c, err := NewSessionCookie(testRedirectHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// principalProbe answers 200 with the principal's sub, or 204 when there is none.
func principalProbe() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFrom(r.Context())
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(p.Sub))
	})
}

func probe(h http.Handler, c SessionCookie, rawID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/workers", nil)
	req.AddCookie(&http.Cookie{Name: c.Name, Value: rawID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSessionExpiry(t *testing.T) {
	t.Run("idle", func(t *testing.T) {
		clk := newFakeClock()
		store, _ := newTestStore(t, clk)
		cookie := testCookie(t)
		h := withSession(principalProbe(), store, cookie, slog.Default())
		raw, _, err := store.Create(context.Background(), testSessionInput())
		if err != nil {
			t.Fatal(err)
		}
		clk.Advance(59 * time.Minute)
		if rec := probe(h, cookie, raw); rec.Code != http.StatusOK {
			t.Fatalf("at 59m: %d, want a Principal", rec.Code)
		}
		// The 59m request touched last_seen_at, so idle counts from there.
		clk.Advance(61 * time.Minute)
		if rec := probe(h, cookie, raw); rec.Code != http.StatusNoContent {
			t.Fatalf("1h01m idle: %d, want no Principal", rec.Code)
		}
		// The expired row is gone for good.
		if _, ok, _ := store.Lookup(context.Background(), raw); ok {
			t.Fatal("expired session still resolves")
		}
	})
	t.Run("idle from creation", func(t *testing.T) {
		clk := newFakeClock()
		store, _ := newTestStore(t, clk)
		cookie := testCookie(t)
		h := withSession(principalProbe(), store, cookie, slog.Default())
		raw, _, _ := store.Create(context.Background(), testSessionInput())
		clk.Advance(time.Hour + time.Minute)
		if rec := probe(h, cookie, raw); rec.Code != http.StatusNoContent {
			t.Fatalf("1h01m idle: %d, want no Principal", rec.Code)
		}
	})
	t.Run("absolute", func(t *testing.T) {
		clk := newFakeClock()
		store, _ := newTestStore(t, clk)
		cookie := testCookie(t)
		h := withSession(principalProbe(), store, cookie, slog.Default())
		raw, _, _ := store.Create(context.Background(), testSessionInput())
		// Steady activity every 30 minutes keeps the session idle-fresh.
		for elapsed := 30 * time.Minute; elapsed <= 12*time.Hour; elapsed += 30 * time.Minute {
			clk.Advance(30 * time.Minute)
			want := http.StatusOK
			if elapsed == 12*time.Hour {
				want = http.StatusNoContent // exactly at the absolute limit
			}
			if rec := probe(h, cookie, raw); rec.Code != want {
				t.Fatalf("at %s: %d, want %d", elapsed, rec.Code, want)
			}
		}
		raw2, _, _ := store.Create(context.Background(), testSessionInput())
		for range 24 {
			clk.Advance(30 * time.Minute)
			probe(h, cookie, raw2)
		}
		clk.Advance(time.Minute)
		if rec := probe(h, cookie, raw2); rec.Code != http.StatusNoContent {
			t.Fatalf("12h01m: %d, want no Principal", rec.Code)
		}
	})
	t.Run("unknown and empty id", func(t *testing.T) {
		store, _ := newTestStore(t, newFakeClock())
		for _, id := range []string{"", "nope"} {
			if _, ok, err := store.Lookup(context.Background(), id); ok || err != nil {
				t.Fatalf("Lookup(%q) = %v, %v", id, ok, err)
			}
		}
	})
	t.Run("sweep", func(t *testing.T) {
		clk := newFakeClock()
		store, _ := newTestStore(t, clk)
		ctx := context.Background()
		old, _, _ := store.Create(ctx, testSessionInput())
		clk.Advance(30 * time.Minute)
		fresh, _, _ := store.Create(ctx, testSessionInput())
		clk.Advance(40 * time.Minute) // old is 70m idle, fresh 40m
		n, err := store.SweepExpired(ctx)
		if err != nil || n != 1 {
			t.Fatalf("SweepExpired = %d, %v; want 1", n, err)
		}
		if _, ok, _ := store.Lookup(ctx, old); ok {
			t.Fatal("swept session resolves")
		}
		if _, ok, _ := store.Lookup(ctx, fresh); !ok {
			t.Fatal("fresh session was swept")
		}
	})
}

func TestSessionCSRF(t *testing.T) {
	policy := writePolicyFile(t, "api.openai.com")
	before, err := os.ReadFile(policy)
	if err != nil {
		t.Fatal(err)
	}
	db := openSessionDB(t)
	cc := config.ConsoleConfig{
		Auth:    config.ConsoleAuthOIDC,
		OIDC:    config.ConsoleOIDC{RedirectURL: testRedirectHTTPS},
		Roles:   config.ConsoleRoles{Admin: []string{"warden-admins"}},
		Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
	}
	srv := New(Config{PolicyPath: policy, Token: dashTestToken, State: db, Console: cc})
	if srv.sessions == nil {
		t.Fatal("oidc mode with a state db must enable sessions")
	}
	h := srv.Handler()
	raw, _, err := srv.sessions.Create(context.Background(), testSessionInput())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"allowlist":[{"domain":"evil.example.com"}],"denylist":[]}`
	send := func(method, csrf, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/dashboard/api/policy", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: srv.sessionCookie.Name, Value: raw})
		req.Header.Set("Authorization", "Bearer "+dashTestToken) // the bearer would let the write through
		if csrf != "" {
			req.Header.Set(CSRFHeader, csrf)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	good := CSRFToken(raw)
	cases := []struct{ name, method, csrf, origin string }{
		{"PUT no token", http.MethodPut, "", ""},
		{"POST no token", http.MethodPost, "", ""},
		{"wrong token", http.MethodPut, "deadbeef", ""},
		{"token of another session", http.MethodPut, CSRFToken(raw + "x"), ""},
		{"foreign origin", http.MethodPut, good, "https://evil.example"},
		{"null origin", http.MethodPut, good, "null"},
		{"scheme-downgraded origin", http.MethodPut, good, "http://cp.example"},
	}
	for _, tc := range cases {
		rec := send(tc.method, tc.csrf, tc.origin)
		if rec.Code != http.StatusForbidden || strings.TrimSpace(rec.Body.String()) != `{"error":"csrf"}` {
			t.Errorf("%s: %d %q, want 403 {\"error\":\"csrf\"}", tc.name, rec.Code, rec.Body.String())
		}
	}
	after, _ := os.ReadFile(policy)
	if !bytes.Equal(before, after) {
		t.Fatal("policy file changed by a refused request")
	}
	if rec := send(http.MethodPut, good, "https://cp.example"); rec.Code != http.StatusOK {
		t.Fatalf("valid token + own origin: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if rec := send(http.MethodPut, good, ""); rec.Code != http.StatusOK {
		t.Fatalf("valid token, no Origin: %d, want 200", rec.Code)
	}
	// Reads need no token; a request with no session is not CSRF-checked here.
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/policy", nil)
	req.AddCookie(&http.Cookie{Name: srv.sessionCookie.Name, Value: raw})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with session: %d", rec.Code)
	}
	// In oidc mode the shared bearer no longer opens a dashboard write (W-P1-SSO-05).
	if rec := dashWrite(t, h, http.MethodPut, "/dashboard/api/policy", "Bearer "+dashTestToken); rec.Code != http.StatusUnauthorized {
		t.Fatalf("sessionless bearer write: %d, want 401", rec.Code)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	clk := newFakeClock()
	store, _ := newTestStore(t, clk)
	cookie := testCookie(t)
	// A plain-HTTP test server: Secure must not depend on r.TLS.
	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _, err := store.Create(r.Context(), testSessionInput())
		if err != nil {
			http.Error(w, "x", http.StatusInternalServerError)
			return
		}
		http.SetCookie(w, cookie.New(raw, 12*time.Hour))
	})
	srv := httptest.NewServer(login)
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	sc := resp.Header.Get("Set-Cookie")
	if !strings.HasPrefix(sc, "__Host-warden_console=") {
		t.Fatalf("Set-Cookie = %q, want the __Host- cookie", sc)
	}
	for _, attr := range []string{"Secure", "HttpOnly", "SameSite=Lax", "Path=/", "Max-Age=43200"} {
		if !strings.Contains(sc, attr) {
			t.Errorf("Set-Cookie %q lacks %s", sc, attr)
		}
	}
	if strings.Contains(strings.ToLower(sc), "domain") {
		t.Errorf("Set-Cookie %q must not carry Domain", sc)
	}

	t.Run("http loopback", func(t *testing.T) {
		c, err := NewSessionCookie("http://localhost:8081/auth/callback")
		if err != nil {
			t.Fatal(err)
		}
		got := c.New("id", time.Hour)
		if got.Name != "warden_console" || got.Secure || !got.HttpOnly || got.SameSite != http.SameSiteLaxMode {
			t.Fatalf("loopback cookie = %+v", got)
		}
	})
	t.Run("rejected redirects", func(t *testing.T) {
		for _, u := range []string{"http://cp.example/auth/callback", "ftp://localhost/x", "/auth/callback", ""} {
			if _, err := NewSessionCookie(u); err == nil {
				t.Errorf("NewSessionCookie(%q) succeeded", u)
			}
		}
	})
	t.Run("clear", func(t *testing.T) {
		got := cookie.Clear()
		if got.MaxAge >= 0 || got.Value != "" || !got.Secure {
			t.Fatalf("Clear = %+v", got)
		}
	})
}

func TestSessionTouchOncePerMinute(t *testing.T) {
	clk := newFakeClock()
	store, _ := newTestStore(t, clk)
	cookie := testCookie(t)
	h := withSession(principalProbe(), store, cookie, slog.Default())
	ctx := context.Background()
	raw, created, _ := store.Create(ctx, testSessionInput())

	// Inside the first minute nothing is written.
	clk.Advance(30 * time.Second)
	probe(h, cookie, raw)
	s, _, _ := store.Lookup(ctx, raw)
	if !s.LastSeenAt.Equal(created.LastSeenAt) {
		t.Fatalf("last_seen_at moved within a minute: %v -> %v", created.LastSeenAt, s.LastSeenAt)
	}

	// Ten requests inside one minute after the interval: exactly one write.
	clk.Advance(31 * time.Second)
	writeAt := clk.Now()
	for i := 0; i < 10; i++ {
		if rec := probe(h, cookie, raw); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
		clk.Advance(5 * time.Second)
	}
	s, _, _ = store.Lookup(ctx, raw)
	if !s.LastSeenAt.Equal(writeAt) {
		t.Fatalf("last_seen_at = %v, want the first request's %v (one write)", s.LastSeenAt, writeAt)
	}
	// Touch directly reports whether it wrote.
	if wrote, _ := store.Touch(ctx, raw); wrote {
		t.Fatal("Touch wrote inside the interval")
	}
	clk.Advance(time.Minute)
	if wrote, err := store.Touch(ctx, raw); !wrote || err != nil {
		t.Fatalf("Touch after the interval = %v, %v; want a write", wrote, err)
	}
}

func TestSessionStoresHashOnly(t *testing.T) {
	clk := newFakeClock()
	store, db := newTestStore(t, clk)
	ctx := context.Background()
	raw, sess, err := store.Create(ctx, testSessionInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 43 { // 32 bytes, unpadded base64url
		t.Fatalf("raw id %q is %d chars, want 43", raw, len(raw))
	}
	if sess.IDHash != hashID(raw) || sess.IDHash == raw || len(sess.IDHash) != 64 {
		t.Fatalf("IDHash = %q", sess.IDHash)
	}
	var stored string
	rows, err := db.SQL().Query(`SELECT id_hash || '|' || iss || '|' || sub || '|' || email || '|' || groups_json || '|' || auth_method FROM sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		n++
		if err := rows.Scan(&stored); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stored, raw) {
			t.Fatal("sessions row contains the raw id")
		}
		if !strings.HasPrefix(stored, hashID(raw)+"|") {
			t.Fatalf("row %q does not start with sha256(id)", stored)
		}
	}
	if n != 1 {
		t.Fatalf("%d rows, want 1", n)
	}
	// Every Create mints a fresh id.
	raw2, _, _ := store.Create(ctx, testSessionInput())
	if raw2 == raw {
		t.Fatal("Create reused an id")
	}
	// The CSRF token is derived, differs per session and is not the id.
	if CSRFToken(raw) == CSRFToken(raw2) || CSRFToken(raw) == raw {
		t.Fatal("CSRFToken is not a stable per-session value")
	}
}

func TestSessionStoreCRUD(t *testing.T) {
	clk := newFakeClock()
	store, _ := newTestStore(t, clk)
	ctx := context.Background()
	a, _, _ := store.Create(ctx, testSessionInput())
	in2 := testSessionInput()
	in2.Sub, in2.Groups = "u2", nil
	clk.Advance(time.Second)
	b, _, _ := store.Create(ctx, in2)

	got, ok, err := store.Lookup(ctx, b)
	if err != nil || !ok || got.Sub != "u2" || got.Groups == nil || len(got.Groups) != 0 {
		t.Fatalf("Lookup b = %+v %v %v", got, ok, err)
	}
	got, _, _ = store.Lookup(ctx, a)
	if len(got.Groups) != 1 || got.Groups[0] != "warden-admins" || got.Email != "u1@example.com" || got.AuthMethod != "oidc" {
		t.Fatalf("Lookup a = %+v", got)
	}
	list, err := store.List(ctx)
	if err != nil || len(list) != 2 || list[0].Sub != "u2" {
		t.Fatalf("List = %+v, %v; want newest first", list, err)
	}
	if err := store.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.Lookup(ctx, a); ok {
		t.Fatal("deleted session resolves")
	}
	c, _, _ := store.Create(ctx, in2)
	n, err := store.DeleteBySub(ctx, "u2")
	if err != nil || n != 2 {
		t.Fatalf("DeleteBySub = %d, %v; want 2", n, err)
	}
	for _, id := range []string{b, c} {
		if _, ok, _ := store.Lookup(ctx, id); ok {
			t.Fatal("session survives DeleteBySub")
		}
	}
	if err := store.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete of a missing session: %v", err)
	}
	d, _, _ := store.Create(ctx, in2)
	if ok, err := store.DeleteByHash(ctx, hashID(d)); err != nil || !ok {
		t.Fatalf("DeleteByHash = %v, %v; want true", ok, err)
	}
	if _, ok, _ := store.Lookup(ctx, d); ok {
		t.Fatal("session survives DeleteByHash")
	}
	if ok, err := store.DeleteByHash(ctx, hashID(d)); err != nil || ok {
		t.Fatalf("DeleteByHash of a missing session = %v, %v; want false", ok, err)
	}
}

func TestSessionPrincipal(t *testing.T) {
	clk := newFakeClock()
	store, _ := newTestStore(t, clk)
	cookie := testCookie(t)
	var got Principal
	h := withSession(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, _ = PrincipalFrom(r.Context())
	}), store, cookie, slog.Default())
	raw, _, _ := store.Create(context.Background(), testSessionInput())
	probe(h, cookie, raw)
	want := Principal{Kind: PrincipalSession, Iss: "https://idp.example", Sub: "u1", Email: "u1@example.com", Groups: []string{"warden-admins"}, AuthMethod: "oidc"}
	if got.Kind != want.Kind || got.Iss != want.Iss || got.Sub != want.Sub || got.Email != want.Email ||
		got.AuthMethod != want.AuthMethod || len(got.Groups) != 1 || got.Groups[0] != "warden-admins" {
		t.Fatalf("Principal = %+v, want %+v", got, want)
	}
	if _, ok := PrincipalFrom(context.Background()); ok {
		t.Fatal("empty context has a Principal")
	}
}

// TestSessionLogsNoSecrets checks the CSRF refusal log carries at most the
// 8-char id-hash prefix, never the cookie value or the expected token.
func TestSessionLogsNoSecrets(t *testing.T) {
	clk := newFakeClock()
	store, _ := newTestStore(t, clk)
	cookie := testCookie(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	h := withSession(principalProbe(), store, cookie, logger)
	raw, sess, _ := store.Create(context.Background(), testSessionInput())
	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", nil)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: raw})
	req.Header.Set(CSRFHeader, "guess-value")
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	if !strings.Contains(out, sess.IDHash[:8]) {
		t.Fatalf("log lacks the id-hash prefix: %s", out)
	}
	for _, secret := range []string{raw, CSRFToken(raw), "guess-value", sess.IDHash} {
		if strings.Contains(out, secret) {
			t.Fatalf("log leaks %q: %s", secret, out)
		}
	}
}

func TestSessionsDisabledOutsideOIDC(t *testing.T) {
	db := openSessionDB(t)
	for name, cfg := range map[string]Config{
		"none":          {State: db},
		"oidc no state": {Console: config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS}}},
	} {
		srv := New(Config{PolicyPath: writePolicyFile(t, "a.example"), State: cfg.State, Console: cfg.Console})
		if srv.sessions != nil {
			t.Errorf("%s: sessions enabled", name)
		}
	}
	// Without sessions a stray session cookie changes nothing.
	srv := New(Config{PolicyPath: writePolicyFile(t, "a.example"), Token: dashTestToken, State: db})
	req := httptest.NewRequest(http.MethodPut, "/dashboard/api/policy", strings.NewReader(`{"allowlist":[{"domain":"a.example"}],"denylist":[]}`))
	req.AddCookie(&http.Cookie{Name: "__Host-warden_console", Value: "x"})
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("none mode write = %d, want 200", rec.Code)
	}
}

func TestSessionSweeperRuns(t *testing.T) {
	db := openSessionDB(t)
	clk := newFakeClock()
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "a.example"), State: db,
		Console: config.ConsoleConfig{
			Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS},
			Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
		},
	})
	srv.sessions = NewSessionStore(db.SQL(), time.Hour, 12*time.Hour, clk.Now)
	ctx, cancel := context.WithCancel(context.Background())
	if _, _, err := srv.sessions.Create(ctx, testSessionInput()); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Hour)
	done := make(chan struct{})
	go func() { srv.sweepSessions(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := db.SQL().QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sweeper did not remove the expired session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

// countingReader is a fake session store that counts every call.
type countingReader struct {
	mu    sync.Mutex
	calls int
}

func (c *countingReader) hit() { c.mu.Lock(); c.calls++; c.mu.Unlock() }
func (c *countingReader) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *countingReader) Lookup(context.Context, string) (Session, bool, error) {
	c.hit()
	return Session{}, false, nil
}

func (c *countingReader) Touch(context.Context, string) (bool, error) { c.hit(); return false, nil }
func (c *countingReader) Now() time.Time                              { return time.Now() }

func TestSessionNotOnWorkerRoutes(t *testing.T) {
	db := openSessionDB(t)
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"), Token: dashTestToken, State: db,
		Console: config.ConsoleConfig{
			Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: testRedirectHTTPS},
			Session: config.ConsoleSession{Idle: time.Hour, Absolute: 12 * time.Hour},
		},
	})
	fake := &countingReader{}
	srv.sessionReader = fake
	h := srv.Handler()
	send := func(method, path string) {
		req := httptest.NewRequest(method, path, strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: srv.sessionCookie.Name, Value: "some-session-id"})
		req.Header.Set("Authorization", "Bearer "+dashTestToken)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/policy"},
		{http.MethodPost, "/control/heartbeat"},
		{http.MethodPost, "/central/ingest"},
		{http.MethodGet, "/healthz"},
	} {
		send(r.method, r.path)
		if n := fake.count(); n != 0 {
			t.Fatalf("%s %s queried the session store %d times", r.method, r.path, n)
		}
	}
	send(http.MethodGet, "/dashboard/api/workers")
	if fake.count() == 0 {
		t.Fatal("a dashboard request must reach the session store")
	}
}

func TestSessionLookupFailureHasNoPrincipal(t *testing.T) {
	clk := newFakeClock()
	store, db := newTestStore(t, clk)
	cookie := testCookie(t)
	raw, _, _ := store.Create(context.Background(), testSessionInput())
	var buf bytes.Buffer
	h := withSession(principalProbe(), store, cookie, slog.New(slog.NewTextHandler(&buf, nil)))
	_ = db.Close() // every later query fails
	if rec := probe(h, cookie, raw); rec.Code != http.StatusNoContent {
		t.Fatalf("store failure: %d, want pass-through without a Principal", rec.Code)
	}
	if !strings.Contains(buf.String(), "lookup failed") || strings.Contains(buf.String(), raw) {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestSessionsDisabledOnBadRedirect(t *testing.T) {
	srv := New(Config{
		PolicyPath: writePolicyFile(t, "a.example"), State: openSessionDB(t),
		Console: config.ConsoleConfig{Auth: config.ConsoleAuthOIDC, OIDC: config.ConsoleOIDC{RedirectURL: "ftp://x/y"}},
	})
	if srv.sessions != nil || srv.sessionReader != nil {
		t.Fatal("sessions enabled for an unusable redirect URL")
	}
}

func TestSessionOriginNormalized(t *testing.T) {
	for in, want := range map[string]string{
		"https://CP.example:443/auth/callback":  "https://cp.example",
		"https://cp.example:8443/auth/callback": "https://cp.example:8443",
		"http://localhost:80/auth/callback":     "http://localhost",
		"http://[::1]:8081/auth/callback":       "http://[::1]:8081",
	} {
		c, err := NewSessionCookie(in)
		if err != nil || c.origin != want {
			t.Errorf("NewSessionCookie(%q).origin = %q, %v; want %q", in, c.origin, err, want)
		}
	}
}

// failingTouch resolves every session but fails to record activity.
type failingTouch struct{}

func (*failingTouch) Lookup(context.Context, string) (Session, bool, error) {
	return Session{Sub: "u1", IDHash: "0123456789abcdef", LastSeenAt: time.Unix(0, 0)}, true, nil
}
func (*failingTouch) Touch(context.Context, string) (bool, error) {
	return false, context.DeadlineExceeded
}

func TestSessionTouchFailureStillServes(t *testing.T) {
	var buf bytes.Buffer
	h := withSession(principalProbe(), &failingTouch{}, testCookie(t), slog.New(slog.NewTextHandler(&buf, nil)))
	rec := probe(h, testCookie(t), "raw-secret-id")
	if rec.Code != http.StatusOK || rec.Body.String() != "u1" {
		t.Fatalf("touch failure: %d %q, want the request served with its Principal", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), "01234567") || strings.Contains(buf.String(), "raw-secret-id") {
		t.Fatalf("log = %q", buf.String())
	}
}

func (*failingTouch) Now() time.Time { return time.Now() }
