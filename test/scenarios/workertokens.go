package scenarios

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// Per-worker token authentication (W-P1-WTOK-02): a token bound to one proxy id
// authenticates /policy, /control/heartbeat and /central/ingest, the bound id
// (not the self-reported header) is what the control plane records, a revoke
// made out of process takes effect on the next poll, and a worker token opens
// no human route. The workers themselves keep the shared token throughout.

func workerTokenOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerTokens()}
}

// wtokRoute is one worker-plane request.
type wtokRoute struct {
	method, path, body string
	ok                 int
}

func wtokRoutes(t *testing.T) []wtokRoute {
	t.Helper()
	ev, err := json.Marshal(map[string]any{"events": []analytics.Event{{
		Timestamp: time.Now().UTC(), Domain: "d.example.com", Port: 443, Protocol: "https",
		Method: "GET", URL: "https://d.example.com/", Decision: "allow",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	return []wtokRoute{
		{http.MethodGet, "/policy", "", http.StatusOK},
		{http.MethodPost, "/control/heartbeat", `{"policyETag":"x"}`, http.StatusNoContent},
		{http.MethodPost, "/central/ingest", string(ev), http.StatusNoContent},
	}
}

// mintWorkerToken creates a token the way an out-of-process writer does (a
// second store on the control plane's state db, with every migration) and
// returns its plaintext and id. The plaintext is never printed.
func mintWorkerToken(t *testing.T, h *harness.H, name, proxyID string) (plaintext, id string) {
	t.Helper()
	ctx := context.Background()
	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	st, err := controlplane.NewWorkerTokenStore(db, controlplane.StoreOptions{Clock: h.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	pt, tok, err := st.Create(ctx, controlplane.CreateOpts{Name: name, ProxyID: proxyID, Actor: "scenario"})
	if err != nil {
		t.Fatalf("create worker token %s: %v", name, err)
	}
	return pt, tok.ID
}

func revokeWorkerToken(t *testing.T, h *harness.H, id string) {
	t.Helper()
	ctx := context.Background()
	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	st, err := controlplane.NewWorkerTokenStore(db, controlplane.StoreOptions{Clock: h.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Revoke(ctx, id, "scenario"); err != nil {
		t.Fatalf("revoke %s: %v", id, err)
	}
}

func cpProxies(t *testing.T, h *harness.H) map[string]int {
	t.Helper()
	var resp struct {
		Proxies []struct {
			ProxyID string `json:"proxyID"`
			Count   int    `json:"count"`
		} `json:"proxies"`
	}
	if err := h.CP().GetJSON("/dashboard/api/analytics?range=24h", &resp); err != nil {
		t.Fatalf("cp analytics: %v", err)
	}
	out := map[string]int{}
	for _, p := range resp.Proxies {
		out[p.ProxyID] = p.Count
	}
	return out
}

func workerTokenAuth(t *testing.T, h *harness.H) {
	cp := h.CP()
	routes := wtokRoutes(t)
	a, aID := mintWorkerToken(t, h, "tok-a", "tok-worker-a")
	b, _ := mintWorkerToken(t, h, "tok-b", "tok-worker-b")

	// The running control plane picks the new tokens up on its next poll (the
	// token store runs on the harness clock): advance it until A authenticates.
	h.Eventually("the control plane to load the new tokens", func() bool {
		h.Clock().Advance(3 * time.Second)
		return cp.DoWorker(http.MethodGet, "/policy", a, "", "").Status == http.StatusOK
	})

	// Binding: a header naming another worker is refused on every route, with
	// the same text, and the refusal registers nothing.
	for _, rt := range routes {
		for _, hdr := range []string{"tok-worker-b", "tok-worker-a-2"} {
			got := cp.DoWorker(rt.method, rt.path, a, hdr, rt.body)
			if got.Status != http.StatusForbidden || !strings.Contains(got.Body, "proxy id mismatch") {
				t.Errorf("%s with header %q = %d %q, want 403 proxy id mismatch", rt.path, hdr, got.Status, got.Body)
			}
		}
	}
	// Without the header every route accepts the token and the control plane
	// records the id the token is bound to.
	for _, rt := range routes {
		if got := cp.DoWorker(rt.method, rt.path, a, "", rt.body); got.Status != rt.ok {
			t.Errorf("%s with token A = %d, want %d", rt.path, got.Status, rt.ok)
		}
	}
	ws, err := cp.Workers()
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, w := range ws {
		if w.ProxyID == "tok-worker-b" || w.ProxyID == "tok-worker-a-2" {
			t.Errorf("the registry lists %q from a refused request", w.ProxyID)
		}
		seen = seen || w.ProxyID == "tok-worker-a"
	}
	if !seen {
		t.Errorf("the registry does not list tok-worker-a: %+v", ws)
	}
	if got := cpProxies(t, h)["tok-worker-a"]; got != 1 {
		t.Errorf("ingested events stored under tok-worker-a = %d, want 1", got)
	}

	// A worker token opens no human route and cannot write the dashboard.
	if got := cp.DoWorker(http.MethodPost, "/dashboard/api/policy", a, "", `{"allowlist":[{"domain":"evil.example.com"}]}`); got.Status != http.StatusUnauthorized {
		t.Errorf("dashboard write with a worker token = %d, want 401", got.Status)
	}

	// Revoke A out of process. B (another worker) keeps working; A is refused
	// with the one generic body on every route.
	revokeWorkerToken(t, h, aID)
	h.Eventually("the revoke to reach the control plane", func() bool {
		h.Clock().Advance(3 * time.Second)
		return cp.DoWorker(http.MethodGet, "/policy", a, "", "").Status == http.StatusUnauthorized
	})
	for _, rt := range routes {
		got := cp.DoWorker(rt.method, rt.path, a, "", rt.body)
		if got.Status != http.StatusUnauthorized || strings.TrimSpace(got.Body) != "unauthorized" || got.Header.Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("%s with revoked A = %d %q, want 401 unauthorized", rt.path, got.Status, got.Body)
		}
		if got := cp.DoWorker(rt.method, rt.path, b, "", rt.body); got.Status != rt.ok {
			t.Errorf("%s with token B = %d, want %d", rt.path, got.Status, rt.ok)
		}
	}

	// The shared token still authenticates (mixed mode): the harness workers
	// run on it, and an unauthenticated caller is refused.
	if got := cp.DoWorker(http.MethodGet, "/policy", "", "", ""); got.Status != http.StatusUnauthorized {
		t.Errorf("anonymous /policy = %d, want 401", got.Status)
	}
	h.Eventually("the shared-token workers to stay registered", func() bool {
		ws, err := cp.Workers()
		if err != nil {
			return false
		}
		for _, w := range ws {
			if w.ProxyID == "worker-1" {
				return true
			}
		}
		return false
	})
	// Neither token value reaches the control plane's logs.
	logs := h.Logs()
	for name, tok := range map[string]string{"A": a, "B": b} {
		if strings.Contains(logs, tok) {
			t.Errorf("worker token %s appears in the logs", name)
		}
	}
}

// workerTokenLongPollRevoke (W-P1-WTOK-09): two tokens each hold a
// GET /policy?wait=30s. Revoking A out of process (the CLI case) returns A's
// held request with 401 at the next reload, never a policy response; B's stays
// parked and still receives the next policy change.
func workerTokenLongPollRevoke(t *testing.T, h *harness.H) {
	cp := h.CP()
	a, aID := mintWorkerToken(t, h, "lp-a", "lp-worker-a")
	b, _ := mintWorkerToken(t, h, "lp-b", "lp-worker-b")
	h.Eventually("the control plane to load the new tokens", func() bool {
		h.Clock().Advance(3 * time.Second)
		return cp.DoWorker(http.MethodGet, "/policy", a, "", "").Status == http.StatusOK &&
			cp.DoWorker(http.MethodGet, "/policy", b, "", "").Status == http.StatusOK
	})
	first := cp.DoWorker(http.MethodGet, "/policy", b, "", "")
	etag := first.Header.Get("ETag")
	if etag == "" {
		t.Fatal("GET /policy returned no ETag")
	}
	hold := func(tok string) <-chan harness.RawResponse {
		return cp.HoldWorker(http.MethodGet, "/policy?wait=30s", tok, http.Header{"If-None-Match": {etag}})
	}
	heldA, heldB := hold(a), hold(b)
	time.Sleep(200 * time.Millisecond) // let both park; the assertions below hold either way

	revokeWorkerToken(t, h, aID)
	var gotA harness.RawResponse
	h.Eventually("A's held request to be cancelled by the revoke", func() bool {
		h.Clock().Advance(3 * time.Second)
		select {
		case gotA = <-heldA:
			return true
		default:
			return false
		}
	})
	if gotA.Status != http.StatusUnauthorized || strings.TrimSpace(gotA.Body) != "unauthorized" {
		t.Errorf("held request of revoked A = %d %q, want 401 unauthorized", gotA.Status, gotA.Body)
	}
	select {
	case got := <-heldB:
		t.Fatalf("B's held request returned %d when only A was revoked", got.Status)
	default:
	}

	// A policy change still reaches B.
	body := `{"allowlist":[{"domain":"lp-changed.example.com"}],"denylist":[]}`
	if code, resp, err := cp.Do(http.MethodPut, "/dashboard/api/policy", cp.Token(), []byte(body)); err != nil || code != http.StatusOK {
		t.Fatalf("PUT /dashboard/api/policy = %d %s %v", code, resp, err)
	}
	h.Eventually("B's held request to receive the changed policy", func() bool {
		select {
		case got := <-heldB:
			return got.Status == http.StatusOK && strings.Contains(got.Body, "lp-changed.example.com")
		default:
			return false
		}
	})
	if strings.Contains(h.Logs(), a) || strings.Contains(h.Logs(), b) {
		t.Error("a worker token appears in the logs")
	}
}
