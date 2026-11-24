package scenarios

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// Scoped API keys on the control plane (W-P2-APIK-02): wak_ keys authenticate
// /dashboard/api/* behind console.apiKeys, each route names the scope it needs,
// and a key revoked out of process (the offline CLI) is refused by the running
// control plane within one 2s poll of its Index. Keys are minted and revoked
// through a second handle on the state database, never through the control
// plane's own store, so the running Index only learns of them by polling.

const (
	apiKeyScenarioOwner = "scenario-owner"
	apiKeyPoll          = 2 * time.Second
)

func apiKeyOpts() []harness.Option {
	return []harness.Option{harness.WithAPIKeys(), harness.WithAdminAudit()}
}

// apiKeyOfflineStore opens the second handle: the Store only, no Index and no
// Run, as an offline CLI does.
func apiKeyOfflineStore(t *testing.T, h *harness.H) *sqlitestore.SQLiteStore {
	t.Helper()
	db, err := cpstate.Open(context.Background(), h.ControlPlaneStateDB(),
		cpstate.Enable(controlplane.StateMigrations(), sqlitestore.MigrationID))
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st, err := sqlitestore.New(db, sqlitestore.Options{Registry: apikeys.NewP2Registry(), Clock: h.Clock()})
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func mintAPIKey(t *testing.T, st *sqlitestore.SQLiteStore, name string, scopes ...apikeys.Scope) (token, id string) {
	t.Helper()
	tok, k, err := st.Create(context.Background(), apikeys.CreateParams{
		Name: name, OwnerIss: "https://idp.scenario", OwnerSub: apiKeyScenarioOwner, OwnerEmail: "owner@example.com",
		OwnerGroups: []string{harness.ConsoleAdminGroup}, Scopes: scopes,
		TTL: 24 * time.Hour, MaxTTL: 8760 * time.Hour, MaxActive: 25,
	})
	if err != nil {
		t.Fatalf("mint %s: %v", name, err)
	}
	return tok, k.ID
}

// keyStatus sends one request with a key and returns the status.
func keyStatus(t *testing.T, h *harness.H, token, method, path, body string) (int, string) {
	t.Helper()
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	resp, err := h.CP().SendBearer(token, method, path, nil, b)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp.Status, string(resp.Body)
}

// pollUntil drives the control plane's fake clock one poll interval at a time
// until cond holds: the Index's Run loop reacts on its own goroutine, so a
// fixed Advance followed by a read would race it.
func pollUntil(h *harness.H, desc string, cond func() bool) {
	h.Eventually(desc, func() bool {
		if cond() {
			return true
		}
		h.Clock().Advance(apiKeyPoll)
		return false
	})
}

// apiKeyOfflineRevoke: a key created and then revoked through a second store
// handle is picked up and then refused by the running control plane, which
// proves Index.Run runs for the control plane's life. The refusal is the
// uniform 401, and a refused key writes no admin audit row.
func apiKeyOfflineRevoke(t *testing.T, h *harness.H) {
	st := apiKeyOfflineStore(t, h)
	key, id := mintAPIKey(t, st, "ci", "policy:read", "policy:write")

	// Created behind the control plane's back: unknown until the next poll.
	pollUntil(h, "the control plane to load the new key", func() bool {
		status, _ := keyStatus(t, h, key, http.MethodGet, "/dashboard/api/policy", "")
		return status == http.StatusOK
	})

	if err := st.Revoke(context.Background(), id, "scenario-cli"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rows := len(h.AdminAuditRows())
	pollUntil(h, "the control plane to refuse the revoked key", func() bool {
		status, _ := keyStatus(t, h, key, http.MethodGet, "/dashboard/api/policy", "")
		return status == http.StatusUnauthorized
	})
	resp, err := h.CP().SendBearer(key, http.MethodPost, "/dashboard/api/policy", nil, []byte(`{"allowlist":[],"denylist":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" ||
		!strings.Contains(string(resp.Body), `"unauthorized"`) {
		t.Fatalf("revoked key write = %d %v %s, want the uniform 401", resp.Status, resp.Header, resp.Body)
	}
	if got := len(h.AdminAuditRows()); got != rows {
		t.Fatalf("admin_audit has %d rows after a refused key, want %d", got, rows)
	}
	if strings.Contains(h.Logs(), key) {
		t.Fatal("the API key is in the control plane's logs")
	}
}

// apiKeyScopes: a policy:read key reads the policy and is refused a write with
// insufficient_scope, the refusal is a chained denied row under the owner with
// the key id, and a key holding every scope is still refused on the worker
// routes (401).
func apiKeyScopes(t *testing.T, h *harness.H) {
	st := apiKeyOfflineStore(t, h)
	ro, roID := mintAPIKey(t, st, "readonly", "policy:read")
	all, _ := mintAPIKey(t, st, "everything", apikeys.NewP2Registry().Registered()...)

	pollUntil(h, "the control plane to load the new keys", func() bool {
		a, _ := keyStatus(t, h, ro, http.MethodGet, "/dashboard/api/policy", "")
		b, _ := keyStatus(t, h, all, http.MethodGet, "/dashboard/api/policy", "")
		return a == http.StatusOK && b == http.StatusOK
	})

	before := len(h.AdminAuditRows())
	status, body := keyStatus(t, h, ro, http.MethodPost, "/dashboard/api/policy", `{"allowlist":[],"denylist":[]}`)
	if status != http.StatusForbidden || !strings.Contains(body, `"insufficient_scope"`) || !strings.Contains(body, `"need":"policy:write"`) {
		t.Fatalf("POST policy with a read key = %d %s, want 403 insufficient_scope need policy:write", status, body)
	}
	rows := h.AdminAuditRows()
	if len(rows) != before+1 {
		t.Fatalf("admin_audit has %d rows, want one new denied row", len(rows))
	}
	r := rows[len(rows)-1]
	if r.AuthMethod != adminaudit.AuthMethodAPIKey || r.Outcome != adminaudit.OutcomeDenied || r.Sub != apiKeyScenarioOwner ||
		r.Action != "policy.write" || !strings.Contains(r.Details, `"api_key_id":"`+roID+`"`) {
		t.Fatalf("audit row = %+v, want a denied apikey row for the owner naming key %s", r, roID)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/policy"},
		{http.MethodPost, "/control/heartbeat"},
		{http.MethodPost, "/central/ingest"},
		{http.MethodGet, "/dashboard/"},
	} {
		if status, _ := keyStatus(t, h, all, c.method, c.path, "{}"); status != http.StatusUnauthorized {
			t.Errorf("%s %s with a key = %d, want 401", c.method, c.path, status)
		}
	}
	if status, _ := keyStatus(t, h, all, http.MethodPost, "/dashboard/api/worker-tokens", `{}`); status != http.StatusForbidden {
		t.Errorf("POST worker-tokens with every scope = %d, want 403", status)
	}
}
