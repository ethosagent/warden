package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestAPIKeysDoneWhen drives the done-when sentence of the scoped API keys
// feature (docs/roadmap/features/api-keys.md, W-P2-APIK-07) over HTTP with a
// fake clock and an in-process OIDC session: an editor creates a read-only
// key, the key reads policy but cannot write it, cannot reach a worker route or
// the secrets API, stops working the moment it is revoked, a second key stops
// at its expiry, and a restarted control plane on the same state database
// still refuses both and still accepts a third, live key.
func TestAPIKeysDoneWhen(t *testing.T) {
	const policyPath = "/dashboard/api/policy"
	e := newKeyEnv(t, keyEnvOpts{})
	editor := e.session("eve", groupEditor, "oidc")

	// 1. An editor creates a policy:read key; the plaintext is returned once.
	rec, ci := e.create(editor, `{"name":"ci","scopes":["policy:read"],"expiresIn":"720h"}`)
	wantStatus(t, rec, http.StatusCreated, "create ci key")
	if ci.Key == "" || ci.ID == "" {
		t.Fatalf("create body = %s", rec.Body.String())
	}

	// 2. The key reads policy (200) ...
	wantStatus(t, e.do(ci.Key, http.MethodGet, policyPath, ""), http.StatusOK, "read policy with the key")

	// 3. ... but a write is 403 insufficient_scope naming the scope it lacks,
	// and the policy file is untouched.
	before := e.policyBytes()
	rec = e.do(ci.Key, http.MethodPost, policyPath, "allow: []\n")
	wantStatus(t, rec, http.StatusForbidden, "write policy with a read-only key")
	if !strings.Contains(rec.Body.String(), `"insufficient_scope"`) || !strings.Contains(rec.Body.String(), `"policy:write"`) {
		t.Errorf("write 403 body = %s, want insufficient_scope need policy:write", rec.Body.String())
	}
	if e.policyBytes() != before {
		t.Error("a refused write changed the policy file")
	}

	// 4. A worker route refuses a key outright (401), and the secrets API is
	// never keyable (403).
	for _, rt := range []struct{ method, path string }{
		{http.MethodGet, "/policy"}, {http.MethodPost, "/control/heartbeat"}, {http.MethodPost, "/central/ingest"},
	} {
		wantStatus(t, e.do(ci.Key, rt.method, rt.path, "{}"), http.StatusUnauthorized, "key on worker route "+rt.path)
	}
	wantStatus(t, e.do(ci.Key, http.MethodGet, "/central/secrets", ""), http.StatusForbidden, "key on /central/secrets")

	// 5. Revoking the key by its owner takes effect on the next request.
	wantStatus(t, e.as(editor, http.MethodDelete, keysPath+"/"+ci.ID, ""), http.StatusNoContent, "revoke")
	rec = e.do(ci.Key, http.MethodGet, policyPath, "")
	wantStatus(t, rec, http.StatusUnauthorized, "revoked key")
	if rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want Bearer", rec.Header().Get("WWW-Authenticate"))
	}

	// 6. A second key works until its expiry and not after. The index is
	// refreshed after the clock jump the way its poll loop would, so the 401
	// comes from expiry and not from the staleness ceiling.
	_, short := e.create(editor, `{"name":"short","scopes":["policy:read"],"expiresIn":"2h"}`)
	_, live := e.create(editor, `{"name":"live","scopes":["policy:read"],"expiresIn":"720h"}`)
	wantStatus(t, e.do(short.Key, http.MethodGet, policyPath, ""), http.StatusOK, "short key before expiry")
	e.clk.Advance(3 * time.Hour)
	if err := e.ix.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.do(short.Key, http.MethodGet, policyPath, ""), http.StatusUnauthorized, "short key after expiry")
	wantStatus(t, e.do(live.Key, http.MethodGet, policyPath, ""), http.StatusOK, "live key after the jump")

	// 7. Restart: a new Server, store and index over the same state database
	// and policy file, at the same instant. Revocation and expiry persist and
	// the live key still works; a new process reads the keys from disk only.
	r := newKeyEnv(t, keyEnvOpts{db: e.db, policy: e.policy})
	r.clk.Set(e.clk.Now())
	if err := r.ix.Rebuild(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, r.do(ci.Key, http.MethodGet, policyPath, ""), http.StatusUnauthorized, "revoked key after restart")
	wantStatus(t, r.do(short.Key, http.MethodGet, policyPath, ""), http.StatusUnauthorized, "expired key after restart")
	wantStatus(t, r.do(live.Key, http.MethodGet, policyPath, ""), http.StatusOK, "live key after restart")
	wantStatus(t, r.do(live.Key, http.MethodPost, policyPath, "allow: []\n"), http.StatusForbidden, "live key write after restart")
	wantStatus(t, r.do(live.Key, http.MethodGet, "/policy", ""), http.StatusUnauthorized, "live key on /policy after restart")
}
