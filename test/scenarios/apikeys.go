package scenarios

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/apikeys/adapters/sqlitestore"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/fakes"
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

	// Let Index.Run re-arm its poll timer after the load above: the count of
	// pending timers on the control plane's clock is unchanged across a short
	// real-time gap.
	prev := -1
	h.Eventually("the control plane's timers to settle", func() bool {
		n := h.Clock().PendingTimers()
		settled := n == prev
		prev = n
		time.Sleep(20 * time.Millisecond)
		return settled
	})
	if err := st.Revoke(context.Background(), id, "scenario-cli"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rows := len(h.AdminAuditRows())
	// One poll interval is enough: a single Advance, then wait for the refusal
	// without moving the clock again.
	before := h.APIKeyAuthCounts()
	h.Clock().Advance(apiKeyPoll)
	h.Eventually("the control plane to refuse the revoked key within one poll", func() bool {
		status, _ := keyStatus(t, h, key, http.MethodGet, "/dashboard/api/policy", "")
		return status == http.StatusUnauthorized
	})
	after := h.APIKeyAuthCounts()
	if after["revoked"] <= before["revoked"] || after["index_stale"] != before["index_stale"] {
		t.Fatalf("counters before %v after %v: want revoked up and index_stale unchanged", before, after)
	}
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

// apiKeyCLIRevoke (W-P2-APIK-05): `warden control-plane api-key revoke` run in a
// second process, here controlplane.RunAPIKeyRevoke on the live state dir, is
// refused by the running control plane within one 2s poll of its Index. The CLI
// uses the Store only (no Index, no Run), appends exactly one admin_audit row
// with auth_method cli, and list shows the key without its secret.
func apiKeyCLIRevoke(t *testing.T, h *harness.H) {
	ctx := context.Background()
	st := apiKeyOfflineStore(t, h)
	key, id := mintAPIKey(t, st, "ci", "policy:read")
	other, otherID := mintAPIKey(t, st, "other", "policy:read")
	stateDir := h.AdminAuditStateDir()

	pollUntil(h, "the control plane to load the new keys", func() bool {
		a, _ := keyStatus(t, h, key, http.MethodGet, "/dashboard/api/policy", "")
		b, _ := keyStatus(t, h, other, http.MethodGet, "/dashboard/api/policy", "")
		return a == http.StatusOK && b == http.StatusOK
	})
	listed, err := controlplane.ListAPIKeysOffline(ctx, stateDir)
	if err != nil || len(listed) != 2 {
		t.Fatalf("offline list = %v, %v; want the two keys", listed, err)
	}
	for _, k := range listed {
		if all := k.String() + k.OwnerEmail; strings.Contains(all, key) || strings.Contains(all, "wak_") {
			t.Fatalf("offline list shows key material: %s", all)
		}
	}

	// Let Index.Run re-arm its poll timer before the revoke (see apiKeyOfflineRevoke).
	prev := -1
	h.Eventually("the control plane's timers to settle", func() bool {
		n := h.Clock().PendingTimers()
		settled := n == prev
		prev = n
		time.Sleep(20 * time.Millisecond)
		return settled
	})
	rows := len(h.AdminAuditRows())
	res, err := controlplane.RunAPIKeyRevoke(ctx, stateDir, "", controlplane.APIKeyRevokeTarget{ID: id}, nil)
	if err != nil || len(res.Revoked) != 1 || res.Revoked[0] != id || !res.Audited {
		t.Fatalf("RunAPIKeyRevoke = %+v, %v", res, err)
	}
	h.Clock().Advance(apiKeyPoll)
	h.Eventually("the control plane to refuse the CLI-revoked key within one poll", func() bool {
		status, _ := keyStatus(t, h, key, http.MethodGet, "/dashboard/api/policy", "")
		return status == http.StatusUnauthorized
	})
	if status, _ := keyStatus(t, h, other, http.MethodGet, "/dashboard/api/policy", ""); status != http.StatusOK {
		t.Fatalf("an untouched key = %d, want 200", status)
	}

	all := h.AdminAuditRows()
	if len(all) != rows+1 {
		t.Fatalf("admin_audit has %d rows, want one new row for the revoke", len(all))
	}
	r := all[len(all)-1]
	if r.AuthMethod != adminaudit.AuthMethodCLI || r.Action != "api_key.revoke" || r.Target != "api_keys" || r.TargetRef != "api_key:"+id {
		t.Fatalf("audit row = %+v, want a cli api_key.revoke row for %s", r, id)
	}
	if k, err := st.Get(ctx, id); err != nil || !strings.HasPrefix(k.RevokedBy, "cli:") {
		t.Fatalf("revoked_by = %q, %v; want cli:<os user>", k.RevokedBy, err)
	}
	if k, _ := st.Get(ctx, otherID); !k.RevokedAt.IsZero() {
		t.Fatal("the CLI revoked a key it was not asked to")
	}
	if strings.Contains(h.Logs(), key) || strings.Contains(r.Details, key) {
		t.Fatal("the API key is in the logs or the audit row")
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

// apiKeyManagement is the management API end to end (W-P2-APIK-03): a console
// admin creates a key (the plaintext is in the 201 only), the key reads the
// policy, introspects itself on /self, is refused a write, and is listed
// without its secret. The admin revokes it and the key's very next request is
// refused, with no clock advance and no poll. Create and revoke are admin audit
// rows that never carry the key.
func apiKeyManagement(t *testing.T, h *harness.H) {
	admin, csrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	hdr := http.Header{controlplane.CSRFHeader: {csrf}, "Content-Type": {"application/json"}}
	do := func(method, path, body string) (*http.Response, string) {
		t.Helper()
		var rb []byte
		if body != "" {
			rb = []byte(body)
		}
		resp, err := admin.DoBody(method, path, hdr, rb)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return resp, string(data)
	}

	// Create: 201, the key once, never cached.
	resp, body := do(http.MethodPost, "/dashboard/api/api-keys", `{"name":"ci","scopes":["policy:read"],"expiresIn":"24h"}`)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("POST api-keys = %d, Cache-Control %q, want 201 no-store", resp.StatusCode, resp.Header.Get("Cache-Control"))
	}
	var made struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(body), &made); err != nil || !apikeys.LooksLikeKey(made.Key) || made.ID == "" {
		t.Fatalf("201 body has no key and id (err %v)", err)
	}

	// Use: the key reads, introspects itself and is refused a write.
	if status, _ := keyStatus(t, h, made.Key, http.MethodGet, "/dashboard/api/policy", ""); status != http.StatusOK {
		t.Fatalf("GET policy with the new key = %d, want 200", status)
	}
	status, self := keyStatus(t, h, made.Key, http.MethodGet, "/dashboard/api/api-keys/self", "")
	if status != http.StatusOK || !strings.Contains(self, `"id":"`+made.ID+`"`) || !strings.Contains(self, `"scopes":["policy:read"]`) {
		t.Fatalf("GET /self = %d %s, want the key's id and scopes", status, self)
	}
	if status, body := keyStatus(t, h, made.Key, http.MethodPost, "/dashboard/api/policy", `{"allowlist":[],"denylist":[]}`); status != http.StatusForbidden || !strings.Contains(body, "insufficient_scope") {
		t.Fatalf("POST policy with a read key = %d %s, want 403 insufficient_scope", status, body)
	}
	if status, body := keyStatus(t, h, made.Key, http.MethodPost, "/dashboard/api/api-keys", `{"name":"x","scopes":["policy:read"]}`); status != http.StatusForbidden || !strings.Contains(body, "session_required") {
		t.Fatalf("a key minting a key = %d %s, want 403 session_required", status, body)
	}

	// List: the admin sees the key, with no secret in it.
	if resp, list := do(http.MethodGet, "/dashboard/api/api-keys", ""); resp.StatusCode != http.StatusOK ||
		!strings.Contains(list, made.ID) || strings.Contains(list, made.Key) || strings.Contains(list, "secret") {
		t.Fatalf("GET api-keys = %d %s", resp.StatusCode, list)
	}

	// Revoke: 204, and the key's next request is refused at once.
	if resp, _ := do(http.MethodDelete, "/dashboard/api/api-keys/"+made.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE api-keys/{id} = %d, want 204", resp.StatusCode)
	}
	for _, path := range []string{"/dashboard/api/policy", "/dashboard/api/api-keys/self"} {
		if status, _ := keyStatus(t, h, made.Key, http.MethodGet, path, ""); status != http.StatusUnauthorized {
			t.Errorf("GET %s with the revoked key = %d, want 401", path, status)
		}
	}
	if resp, _ := do(http.MethodDelete, "/dashboard/api/api-keys/"+made.ID, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("a repeated revoke = %d, want 204", resp.StatusCode)
	}

	// Audit: one ok create row and one ok revoke row (the repeat wrote none), neither
	// carrying the key.
	var create, revoke int
	for _, r := range h.AdminAuditRows() {
		if r.Outcome != adminaudit.OutcomeOK {
			continue // the refused key-minted create is a denied row, by design
		}
		switch r.Action {
		case "api_key.create":
			create++
			if r.TargetRef != "api_key:"+made.ID || r.Target != "api_keys" || r.AuthMethod != adminaudit.AuthMethodOIDC {
				t.Errorf("create row = %+v", r)
			}
		case "api_key.revoke":
			revoke++
			if r.TargetRef != "api_key:"+made.ID || r.Outcome != adminaudit.OutcomeOK {
				t.Errorf("revoke row = %+v", r)
			}
		}
		if strings.Contains(r.Details, made.Key) || strings.Contains(r.TargetRef, made.Key) {
			t.Errorf("audit row %d carries the key", r.Seq)
		}
	}
	if create != 1 || revoke != 1 {
		t.Fatalf("audit has %d create and %d revoke rows, want 1 and 1", create, revoke)
	}
	if strings.Contains(h.Logs(), made.Key) {
		t.Fatal("the API key is in the control plane's logs")
	}
}
