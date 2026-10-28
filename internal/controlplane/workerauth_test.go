package controlplane

import (
	"context"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/secrets"
)

const waLegacy = "legacy-shared-token"

type waEnv struct {
	*wtEnv
	srv  *Server
	h    http.Handler
	logs *syncBuf
}

// newWA builds a control plane over a real worker token store. legacy is the
// shared Config.Token ("" = open mode).
func newWA(t *testing.T, legacy string, withSecrets bool) *waEnv {
	t.Helper()
	e := newWT(t)
	logs := &syncBuf{}
	cfg := Config{
		PolicyPath:   writePolicyFile(t, "api.openai.com"),
		Token:        legacy,
		WorkerTokens: e.store,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
		Clock:        e.clk,
		Store:        analytics.NewCentralStore(100),
	}
	if withSecrets {
		cfg.SecretStore = secrets.NewEchoStore()
	}
	srv := New(cfg)
	return &waEnv{wtEnv: e, srv: srv, h: srv.Handler(), logs: logs}
}

// call sends a request to one of the three worker routes (or any route).
func (e *waEnv) call(method, path, bearer, proxyID, remote string) *httptest.ResponseRecorder {
	body := ""
	switch path {
	case "/central/ingest":
		body = `{"events":[{"type":"allow","host":"api.openai.com"}]}`
	case "/control/heartbeat":
		body = `{"policyETag":"x"}`
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	if proxyID != "" {
		r.Header.Set(analytics.ProxyIDHeader, proxyID)
	}
	if remote != "" {
		r.RemoteAddr = remote
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	return rec
}

type waRoute struct {
	method, path string
	ok           int
}

var waRoutes = []waRoute{
	{http.MethodGet, "/policy", http.StatusOK},
	{http.MethodPost, "/control/heartbeat", http.StatusNoContent},
	{http.MethodPost, "/central/ingest", http.StatusNoContent},
}

func (e *waEnv) workerIDs() []string {
	var ids []string
	for _, v := range e.srv.registry.Views() {
		ids = append(ids, v.ProxyID)
	}
	return ids
}

func TestWorkerAuthBinding(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, _ := e.create(t, "a", "worker-1")
	for _, rt := range waRoutes {
		rec := e.call(rt.method, rt.path, a, "worker-2", "")
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "proxy id mismatch") {
			t.Errorf("%s with header worker-2 = %d %q, want 403 proxy id mismatch", rt.path, rec.Code, rec.Body.String())
		}
	}
	if ids := e.workerIDs(); len(ids) != 0 {
		t.Fatalf("a mismatched request registered workers %v", ids)
	}
	for _, rt := range waRoutes {
		if rec := e.call(rt.method, rt.path, a, "", ""); rec.Code != rt.ok {
			t.Errorf("%s without header = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
	if ids := e.workerIDs(); len(ids) != 1 || ids[0] != "worker-1" {
		t.Fatalf("registry = %v, want [worker-1]", ids)
	}
	// An equal header is accepted.
	if rec := e.call(http.MethodGet, "/policy", a, "worker-1", ""); rec.Code != http.StatusOK {
		t.Errorf("matching header = %d, want 200", rec.Code)
	}
}

func TestWorkerAuthExactBinding(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, _ := e.create(t, "a", "worker-1")
	for _, hdr := range []string{"worker-10", "worker-1-a", "worker-", "Worker-1", "worker-1 "} {
		for _, rt := range waRoutes {
			rec := e.call(rt.method, rt.path, a, hdr, "")
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "proxy id mismatch") {
				t.Errorf("%s header %q = %d %q, want 403 proxy id mismatch", rt.path, hdr, rec.Code, rec.Body.String())
			}
		}
	}
	// A second header value that differs is a mismatch too.
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	r.Header.Set("Authorization", "Bearer "+a)
	r.Header.Add(analytics.ProxyIDHeader, "worker-1")
	r.Header.Add(analytics.ProxyIDHeader, "worker-2")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("duplicate header values = %d, want 403", rec.Code)
	}
}

func TestWorkerAuthRevoked(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, ta := e.create(t, "a", "worker-1")
	b, _ := e.create(t, "b", "worker-2")
	for _, rt := range waRoutes {
		if rec := e.call(rt.method, rt.path, a, "", ""); rec.Code != rt.ok {
			t.Fatalf("%s before revoke = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
	if err := e.store.Revoke(context.Background(), ta.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, rt := range waRoutes {
		rec := e.call(rt.method, rt.path, a, "", "")
		if rec.Code != http.StatusUnauthorized || strings.TrimSpace(rec.Body.String()) != "unauthorized" {
			t.Errorf("%s after revoke = %d %q, want 401 unauthorized", rt.path, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
			t.Errorf("%s WWW-Authenticate = %q, want Bearer", rt.path, got)
		}
		if rec := e.call(rt.method, rt.path, b, "", ""); rec.Code != rt.ok {
			t.Errorf("%s token B = %d, want %d", rt.path, rec.Code, rt.ok)
		}
	}
}

func TestWorkerAuthSameBodyForEveryReason(t *testing.T) {
	e := newWA(t, waLegacy, false)
	e.create(t, "a", "worker-1")
	exp, _, _ := e.store.Create(context.Background(), CreateOpts{Name: "e", ProxyID: "worker-3", Actor: "x", ExpiresAt: e.clk.Now().Add(time.Minute)})
	e.clk.Advance(time.Hour)
	unknown, _ := generateWorkerToken()
	for name, bearer := range map[string]string{
		"missing": "", "malformed": "wwt_short", "unknown": unknown, "legacy-wrong": "nope", "expired": exp,
	} {
		rec := e.call(http.MethodGet, "/policy", bearer, "", "")
		if rec.Code != 401 || rec.Body.String() != "unauthorized\n" || rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s = %d %q %q", name, rec.Code, rec.Body.String(), rec.Header().Get("WWW-Authenticate"))
		}
	}
}

func TestWorkerAuthRejectedOnHumanRoutes(t *testing.T) {
	for name, legacy := range map[string]string{"mixed": waLegacy, "open": ""} {
		t.Run(name, func(t *testing.T) {
			e := newWA(t, legacy, true)
			a, _ := e.create(t, "a", "worker-1")
			for _, c := range []struct{ method, path string }{
				{http.MethodPost, "/central/secrets"},
				{http.MethodGet, "/central/secrets"},
				{http.MethodDelete, "/central/secrets/k1"},
				{http.MethodGet, "/central/secrets/k1"},
			} {
				rec := e.call(c.method, c.path, a, "", "")
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s %s with a worker token = %d, want 401", c.method, c.path, rec.Code)
				}
			}
		})
	}
}

func TestWorkerTokenNeverSatisfiesWriteGuard(t *testing.T) {
	for name, legacy := range map[string]string{"mixed": waLegacy, "open": ""} {
		t.Run(name, func(t *testing.T) {
			e := newWA(t, legacy, false)
			a, _ := e.create(t, "a", "worker-1")
			if st, _ := e.srv.dashboardWriteGuard()(bearerReq(a)); st == 0 {
				t.Fatal("write guard accepted a worker token")
			}
			before, _ := os.ReadFile(e.srv.cfg.PolicyPath)
			r := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", strings.NewReader(`{"allowlist":[{"domain":"evil.example.com"}]}`))
			r.Header.Set("Authorization", "Bearer "+a)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, r)
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Errorf("dashboard write with a worker token = %d, want 401/403", rec.Code)
			}
			after, _ := os.ReadFile(e.srv.cfg.PolicyPath)
			if string(before) != string(after) {
				t.Error("a worker token changed the policy file")
			}
		})
	}
}

func bearerReq(tok string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/dashboard/api/policy", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestWorkerAuthIngestProxyID(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, _ := e.create(t, "a", "worker-1")
	var gotID string
	var gotN int
	body := `{"events":[{"type":"allow","host":"api.openai.com"}],"mcp":{"inventory":[],"schema":{}}}`
	r := httptest.NewRequest(http.MethodPost, "/central/ingest", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+a)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("ingest = %d", rec.Code)
	}
	evs, err := e.srv.central.GetEvents(analytics.EventFilter{})
	if err != nil || len(evs) != 1 {
		t.Fatalf("events = %v, %v", evs, err)
	}
	gotID = evs[0].ProxyID // set by the store from AggregatedEvent.ProxyID
	if gotID != "worker-1" {
		t.Fatalf("stored ProxyID = %q, want worker-1", gotID)
	}
	for _, v := range e.srv.registry.Views() {
		gotN += int(v.EventsForwarded)
		if v.ProxyID != "worker-1" {
			t.Errorf("registry has %q, want only worker-1", v.ProxyID)
		}
	}
	if gotN != 1 {
		t.Errorf("registry events = %d, want 1", gotN)
	}
	if inv, _ := e.srv.mcp.For("worker-1"); inv == nil {
		t.Error("mcp snapshot not stored under worker-1")
	}
}

func TestWorkerAuthModes(t *testing.T) {
	t.Run("mixed", func(t *testing.T) {
		e := newWA(t, waLegacy, false)
		if rec := e.call(http.MethodGet, "/policy", "", "w1", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("anonymous in mixed = %d, want 401", rec.Code)
		}
		for i := 0; i < 2; i++ {
			if rec := e.call(http.MethodGet, "/policy", waLegacy, "w1", ""); rec.Code != http.StatusOK {
				t.Errorf("legacy in mixed = %d, want 200", rec.Code)
			}
		}
		if got := e.srv.workerAuth.LegacyRequests("w1"); got != 2 {
			t.Errorf("legacy count = %d, want 2", got)
		}
		if got := e.srv.workerAuth.Count(KindLegacy, "ok"); got != 2 {
			t.Errorf("legacy ok counter = %d, want 2", got)
		}
		if !strings.Contains(e.logs.String(), "auth_mode=mixed") {
			t.Errorf("mode not logged: %s", e.logs.String())
		}
	})
	t.Run("open", func(t *testing.T) {
		e := newWA(t, "", false)
		for i := 0; i < 3; i++ {
			if rec := e.call(http.MethodGet, "/policy", "", "w1", ""); rec.Code != http.StatusOK {
				t.Errorf("anonymous in open = %d, want 200", rec.Code)
			}
		}
		if got := e.srv.workerAuth.Count(KindNone, "ok"); got != 3 {
			t.Errorf("none ok counter = %d, want 3", got)
		}
		if ids := e.workerIDs(); len(ids) != 1 || ids[0] != "w1" {
			t.Errorf("registry = %v, want [w1] from the header", ids)
		}
		if n := strings.Count(e.logs.String(), "level=WARN msg=\"worker auth is open"); n != 1 {
			t.Errorf("open-mode warning logged %d times, want 1:\n%s", n, e.logs.String())
		}
		if !strings.Contains(e.logs.String(), "auth_mode=open") {
			t.Error("mode not logged")
		}
		// A worker token is still validated in open mode, never waved through.
		if rec := e.call(http.MethodGet, "/policy", "wwt_bogus", "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("bogus wwt_ in open = %d, want 401", rec.Code)
		}
	})
}

func TestWorkerAuthTokenNeverFallsBackToLegacy(t *testing.T) {
	// A legacy token that itself looks like a worker token still never matches
	// through the legacy compare.
	e := newWT(t)
	legacy, _ := generateWorkerToken()
	srv := New(Config{PolicyPath: writePolicyFile(t, "x.com"), Token: legacy, WorkerTokens: e.store, Logger: slog.New(slog.DiscardHandler)})
	r := httptest.NewRequest(http.MethodGet, "/policy", nil)
	r.Header.Set("Authorization", "Bearer "+legacy)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wwt_-shaped legacy token = %d, want 401", rec.Code)
	}
}

func TestWorkerAuthRejectionLog(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, ta := e.create(t, "a", "worker-1")
	secretHdr := "Bearer " + a
	count := func(reason string) int {
		return strings.Count(e.logs.String(), "msg=\"worker auth rejected\" reason="+reason)
	}
	for i := 0; i < 5; i++ {
		e.call(http.MethodGet, "/policy", "", "", "10.0.0.1:1000"+string(rune('0'+i)))
	}
	if n := count("missing"); n != 1 {
		t.Fatalf("missing logged %d times for one address, want 1:\n%s", n, e.logs.String())
	}
	e.call(http.MethodGet, "/policy", "", "", "10.0.0.2:5")
	if n := count("missing"); n != 2 {
		t.Fatalf("a second address should log: %d", n)
	}
	e.call(http.MethodGet, "/policy", "nope", "", "10.0.0.1:5")
	if n := count("bad_token"); n != 1 {
		t.Fatalf("a different reason should log: %d", n)
	}
	e.clk.Advance(61 * time.Second)
	e.call(http.MethodGet, "/policy", "", "", "10.0.0.1:7")
	if n := count("missing"); n != 3 {
		t.Fatalf("after a minute the reason logs again: %d", n)
	}
	if err := e.store.Revoke(context.Background(), ta.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	e.call(http.MethodGet, "/policy", a, "", "10.0.0.9:1")
	if !strings.Contains(e.logs.String(), "reason=revoked token_id="+ta.ID) {
		t.Errorf("revoked rejection lacks the token id:\n%s", e.logs.String())
	}
	out := e.logs.String()
	h := hashToken(a)
	for _, bad := range []string{a, secretHdr, hex.EncodeToString(h[:]), waLegacy, "nope"} {
		if strings.Contains(out, bad) {
			t.Errorf("log contains a credential or header value (%d bytes)", len(bad))
		}
	}
}

func TestWorkerAuthCountersAndMarkUsed(t *testing.T) {
	e := newWA(t, waLegacy, false)
	a, ta := e.create(t, "a", "worker-1")
	e.call(http.MethodGet, "/policy", a, "", "")
	e.call(http.MethodGet, "/policy", a, "other", "")
	e.call(http.MethodGet, "/policy", "", "", "")
	wa := e.srv.workerAuth
	if wa.Count(KindToken, "ok") != 1 || wa.Count(KindToken, "forbidden") != 1 || wa.Count(KindNone, "unauthorized") != 1 {
		t.Errorf("counters wrong: ok=%d forbidden=%d anon=%d", wa.Count(KindToken, "ok"), wa.Count(KindToken, "forbidden"), wa.Count(KindNone, "unauthorized"))
	}
	if err := e.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	list, _ := e.store.List(context.Background())
	if len(list) != 1 || list[0].ID != ta.ID || list[0].LastUsedAt.IsZero() {
		t.Errorf("MarkUsed not recorded: %+v", list)
	}
}

func TestWorkerAuthLegacyCounterCapped(t *testing.T) {
	e := newWA(t, waLegacy, false)
	for i := 0; i < maxLegacyIDs+5; i++ {
		e.srv.workerAuth.countLegacy("id-" + string(rune('a'+i%26)) + strings.Repeat("x", i/26) + "-" + hex.EncodeToString([]byte{byte(i), byte(i >> 8)}))
	}
	if n := e.srv.workerAuth.legacyIDs(); n > maxLegacyIDs {
		t.Fatalf("legacy ids = %d, want <= %d", n, maxLegacyIDs)
	}
}
