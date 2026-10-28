package controlplane

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
)

// newWAOn builds a control plane in open mode over e's token store.
func newWAOn(t *testing.T, legacy string, e *wtEnv) *waEnv {
	t.Helper()
	logs := &syncBuf{}
	srv := New(Config{
		PolicyPath:   writePolicyFile(t, "api.openai.com"),
		Token:        legacy,
		WorkerTokens: e.store,
		Logger:       slog.New(slog.NewTextHandler(logs, nil)),
		Clock:        e.clk,
		Store:        analytics.NewCentralStore(100),
	})
	return &waEnv{wtEnv: e, srv: srv, h: srv.Handler(), logs: logs}
}

// lpHold sends GET /policy?wait=30s for bearer in the background and returns
// the channel its response arrives on.
func (e *waEnv) lpHold(bearer, etag string) <-chan *httptest.ResponseRecorder {
	out := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodGet, "/policy?wait=30s", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("If-None-Match", `"`+etag+`"`)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, r)
		out <- rec
	}()
	return out
}

// lpEtag fetches the current policy ETag with a plain request.
func (e *waEnv) lpEtag(t *testing.T, bearer string) string {
	t.Helper()
	rec := e.call(http.MethodGet, "/policy", bearer, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d", rec.Code)
	}
	return strings.Trim(rec.Header().Get("ETag"), `"`)
}

// lpParked waits until n requests of token id are parked.
func (e *waEnv) lpParked(t *testing.T, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		a := e.srv.workerAuth
		a.cancelMu.Lock()
		got := 0
		if c := a.cancels[id]; c != nil {
			got = c.waiters
		}
		a.cancelMu.Unlock()
		if got == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("token %s: %d waiters never parked", id, n)
}

func lpWait(t *testing.T, ch <-chan *httptest.ResponseRecorder, within time.Duration) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case rec := <-ch:
		return rec
	case <-time.After(within):
		t.Fatalf("held /policy request did not return within %s", within)
		return nil
	}
}

func lpChangePolicy(t *testing.T, e *waEnv, domain string) {
	t.Helper()
	body := "policy:\n  allowlist:\n    - domain: " + domain + "\n  denylist:\n    - domain: evil.example.com\n"
	if err := os.WriteFile(e.srv.cfg.PolicyPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	e.srv.policy.Refresh()
}

func TestLongPollRevokeCancels(t *testing.T) {
	e := newWA(t, "", false)
	ptA, tokA := e.create(t, "a", "proxy-a")
	ptB, tokB := e.create(t, "b", "proxy-b")
	etag := e.lpEtag(t, ptA)
	heldA, heldB := e.lpHold(ptA, etag), e.lpHold(ptB, etag)
	e.lpParked(t, tokA.ID, 1)
	e.lpParked(t, tokB.ID, 1)

	start := time.Now()
	if err := e.store.Revoke(context.Background(), tokA.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	rec := lpWait(t, heldA, time.Second)
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" || strings.TrimSpace(rec.Body.String()) != "unauthorized" {
		t.Fatalf("revoked wait = %d %q", rec.Code, rec.Body.String())
	}
	t.Logf("cancelled in %s", time.Since(start))
	select {
	case <-heldB:
		t.Fatal("a revoke of A returned B's held request")
	case <-time.After(100 * time.Millisecond):
	}
	e.lpParked(t, tokA.ID, 0)
	lpChangePolicy(t, e, "api.example.com")
	if rec := lpWait(t, heldB, 2*time.Second); rec.Code != http.StatusOK {
		t.Fatalf("B after change = %d", rec.Code)
	}
}

func TestLongPollRevokeFromOtherProcess(t *testing.T) {
	e := newWT(t)
	// The CP's store runs its real-clock poll loop on the file; the "CLI"
	// is a second store on the same file.
	db, cpStore, _ := openWT(t, e.path, clock.Real(), StoreOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go cpStore.Run(ctx)
	_, cliStore, _ := openWT(t, e.path, clock.Real(), StoreOptions{})
	we := newWAOn(t, "", &wtEnv{path: e.path, clk: e.clk, store: cpStore, db: db, logs: e.logs})
	pt, tok, err := cliStore.Create(ctx, CreateOpts{Name: "a", ProxyID: "proxy-a", Actor: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	// The CP learns of the new token at its next data_version poll.
	deadline := time.Now().Add(5 * time.Second)
	for we.call(http.MethodGet, "/policy", pt, "", "").Code != http.StatusOK {
		if time.Now().After(deadline) {
			t.Fatal("CP never loaded the token created by the other store")
		}
		time.Sleep(50 * time.Millisecond)
	}
	etag := we.lpEtag(t, pt)
	held := we.lpHold(pt, etag)
	we.lpParked(t, tok.ID, 1)
	if err := cliStore.Revoke(ctx, tok.ID, "cli"); err != nil {
		t.Fatal(err)
	}
	if rec := lpWait(t, held, 3*time.Second); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked by other store = %d", rec.Code)
	}
}

// Expiry has no revoke hook, so these exercise the re-authentication on the
// timeout and policy-change paths.
func TestLongPollRevokedNever304(t *testing.T) {
	e := newWA(t, "", false)
	pt, tok, err := e.store.Create(context.Background(), CreateOpts{
		Name: "a", ProxyID: "proxy-a", Actor: "admin", ExpiresAt: e.clk.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	etag := e.lpEtag(t, pt)
	r := httptest.NewRequest(http.MethodGet, "/policy?wait=1s", nil)
	r.Header.Set("Authorization", "Bearer "+pt)
	r.Header.Set("If-None-Match", `"`+etag+`"`)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { e.h.ServeHTTP(rec, r); close(done) }()
	e.lpParked(t, tok.ID, 1)
	e.clk.Advance(2 * time.Hour)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("wait never timed out")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired token whose wait timed out = %d, want 401", rec.Code)
	}
	// A live token still gets its 304.
	pt2, _ := e.create(t, "b", "proxy-b")
	r = httptest.NewRequest(http.MethodGet, "/policy?wait=1s", nil)
	r.Header.Set("Authorization", "Bearer "+pt2)
	r.Header.Set("If-None-Match", `"`+etag+`"`)
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotModified {
		t.Fatalf("live token wait timeout = %d, want 304", rec.Code)
	}
}

func TestLongPollRevokedNeverGetsNewPolicy(t *testing.T) {
	e := newWA(t, "", false)
	pt, tok, err := e.store.Create(context.Background(), CreateOpts{
		Name: "a", ProxyID: "proxy-a", Actor: "admin", ExpiresAt: e.clk.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	etag := e.lpEtag(t, pt)
	held := e.lpHold(pt, etag)
	e.lpParked(t, tok.ID, 1)
	e.clk.Advance(2 * time.Hour) // invalid between the change and the response
	lpChangePolicy(t, e, "api.example.com")
	rec := lpWait(t, held, 2*time.Second)
	if rec.Code != http.StatusUnauthorized || strings.Contains(rec.Body.String(), "api.example.com") {
		t.Fatalf("got %d %q, want 401 without the new policy", rec.Code, rec.Body.String())
	}
}

func TestLongPollWakeNoDBIO(t *testing.T) {
	e := newWA(t, "", false)
	ptA, tokA := e.create(t, "a", "proxy-a")
	ptB, tokB := e.create(t, "b", "proxy-b")
	etag := e.lpEtag(t, ptA)
	const nB, nA = 500, 5
	var heldA, heldB []<-chan *httptest.ResponseRecorder
	for range nA {
		heldA = append(heldA, e.lpHold(ptA, etag))
	}
	for range nB {
		heldB = append(heldB, e.lpHold(ptB, etag))
	}
	e.lpParked(t, tokA.ID, nA)
	e.lpParked(t, tokB.ID, nB)
	if err := e.store.Revoke(context.Background(), tokA.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	for _, h := range heldA {
		if rec := lpWait(t, h, time.Second); rec.Code != http.StatusUnauthorized {
			t.Fatalf("A waiter = %d", rec.Code)
		}
	}

	// The state DB has one connection. Holding it means any query issued while
	// B's waiters wake would block (and count as a wait).
	conn, err := e.db.SQL().Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	before := e.db.SQL().Stats().WaitCount
	lpChangePolicy(t, e, "api.example.com")
	var wg sync.WaitGroup
	for _, h := range heldB {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rec := lpWait(t, h, 5*time.Second); rec.Code != http.StatusOK {
				t.Errorf("B waiter = %d", rec.Code)
			}
		}()
	}
	wg.Wait()
	if got := e.db.SQL().Stats().WaitCount - before; got != 0 {
		t.Fatalf("waking %d waiters waited on the DB %d times", nB, got)
	}
}

func TestLongPollLegacyAndNoneNotCancelled(t *testing.T) {
	e := newWA(t, waLegacy, false)
	_, tokA := e.create(t, "a", "proxy-a")
	etag := e.lpEtag(t, waLegacy)
	held := e.lpHold(waLegacy, etag)
	time.Sleep(50 * time.Millisecond)
	if err := e.store.Revoke(context.Background(), tokA.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-held:
		t.Fatal("a token revoke returned a shared-token long-poll")
	case <-time.After(200 * time.Millisecond):
	}
	if n := len(e.srv.workerAuth.cancels); n != 0 {
		t.Fatalf("legacy waiter registered %d cancel entries", n)
	}
	lpChangePolicy(t, e, "api.example.com")
	if rec := lpWait(t, held, 2*time.Second); rec.Code != http.StatusOK {
		t.Fatalf("legacy waiter = %d", rec.Code)
	}
}
