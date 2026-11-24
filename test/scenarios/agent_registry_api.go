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
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/agentreg/agentregtest"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The agent registry admin API (W-P2-AREG-02): an admin registers, edits,
// disables and enables agents from the console; viewers and editors read but
// cannot write; every write is exactly one admin audit row naming agent:<id>
// that carries no key coordinates; a missing or stale If-Match is 428 or 409;
// a write by another process (the offline CLI) shows up in the API; without
// console sign-in the API is read-only; without a state dir it is 503; a
// worker's dashboard does not serve it.

const agentsPathScn = "/dashboard/api/agents"

func agentRegistryAPIOpts() []harness.Option {
	return []harness.Option{harness.WithConsoleOIDC(), harness.WithAdminAudit()}
}

type agentScnView struct {
	ID            string   `json:"id"`
	Revision      int64    `json:"revision"`
	Status        string   `json:"status"`
	OwnerSub      string   `json:"ownerSub"`
	CreatedBy     string   `json:"createdBy"`
	AllowedGroups []string `json:"allowedGroups"`
	Keys          []struct {
		KID string `json:"kid"`
		Alg string `json:"alg"`
		JKT string `json:"jkt"`
		JWK struct {
			X string `json:"x"`
		} `json:"jwk"`
	} `json:"keys"`
}

func agentRegistryAPI(t *testing.T, h *harness.H) {
	admin, acsrf := consoleLogin(t, h, fakes.Valid("ada", "ada@example.com", harness.ConsoleAdminGroup))
	viewer, vcsrf := consoleLogin(t, h, fakes.Valid("vera", "vera@example.com", harness.ConsoleViewerGroup))
	do := func(b *harness.Browser, csrf, method, target, body string, hdr ...string) (*http.Response, string) {
		t.Helper()
		hd := http.Header{"Content-Type": {"application/json"}}
		if method != http.MethodGet {
			hd.Set(controlplane.CSRFHeader, csrf)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			hd.Set(hdr[i], hdr[i+1])
		}
		var payload []byte
		if body != "" {
			payload = []byte(body)
		}
		resp, err := b.DoBody(method, target, hd, payload)
		if err != nil {
			t.Fatalf("%s %s: %v", method, target, err)
		}
		defer func() { _ = resp.Body.Close() }()
		out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatalf("read %s %s: %v", method, target, err)
		}
		return resp, string(out)
	}
	agentRows := func() []harness.AdminAuditRow {
		var out []harness.AdminAuditRow
		for _, r := range h.AdminAuditRows() {
			if strings.HasPrefix(r.Action, "agent.") {
				out = append(out, r)
			}
		}
		return out
	}

	key1, key2 := agentregtest.Ed25519JWK(t, "scn-key-1"), agentregtest.Ed25519JWK(t, "scn-key-2")
	create := `{"id":"claude-code","displayName":"Claude Code","keys":[` + string(key1) + `],"allowedGroups":["warden-agents"]}`
	update := `{"displayName":"Claude Code","keys":[` + string(key1) + `,` + string(key2) + `],"allowedGroups":["warden-agents","eng"]}`

	// A viewer reads and cannot write; the refusals are denied rows.
	for _, c := range []struct{ method, target string }{
		{http.MethodPost, agentsPathScn}, {http.MethodPut, agentsPathScn + "/claude-code"},
	} {
		resp, body := do(viewer, vcsrf, c.method, c.target, create, "If-Match", `"r1"`)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, `"role_required"`) {
			t.Fatalf("viewer %s %s = %d %s, want 403 role_required", c.method, c.target, resp.StatusCode, body)
		}
	}
	if resp, body := do(viewer, vcsrf, http.MethodGet, agentsPathScn, ""); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, `{"agents":[]`) {
		t.Fatalf("viewer GET = %d %s, want an empty list", resp.StatusCode, body)
	}
	if rows := agentRows(); len(rows) != 2 || rows[0].Outcome != adminaudit.OutcomeDenied || rows[1].Outcome != adminaudit.OutcomeDenied {
		t.Fatalf("agent rows after the viewer's writes = %+v, want two denied", rows)
	}

	// A write without the CSRF header is refused and recorded as denied.
	resp, err := admin.DoBody(http.MethodPost, agentsPathScn, http.Header{"Content-Type": {"application/json"}}, []byte(create))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if rows := agentRows(); resp.StatusCode != http.StatusForbidden || len(rows) != 3 || rows[2].Outcome != adminaudit.OutcomeDenied || rows[2].Action != "agent.create" {
		t.Fatalf("POST without CSRF = %d, rows %+v, want 403 and a denied agent.create row", resp.StatusCode, rows)
	}
	denied := len(agentRows())

	// Create.
	resp, body := do(admin, acsrf, http.MethodPost, agentsPathScn, create)
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("ETag") != `"r1"` || resp.Header.Get("Location") != agentsPathScn+"/claude-code" {
		t.Fatalf("create = %d %s, ETag %q Location %q", resp.StatusCode, body, resp.Header.Get("ETag"), resp.Header.Get("Location"))
	}
	var created agentScnView
	decodeInto(t, "create", body, &created)
	if created.ID != "claude-code" || created.Revision != 1 || created.Status != "active" || created.OwnerSub != "ada" || created.CreatedBy != "oidc:ada" ||
		len(created.Keys) != 1 || created.Keys[0].Alg != "EdDSA" || created.Keys[0].KID != created.Keys[0].JKT {
		t.Fatalf("created view = %+v", created)
	}
	coordinate := created.Keys[0].JWK.X

	// Validation names its field; a duplicate id and a shared key are 409.
	resp, body = do(admin, acsrf, http.MethodPost, agentsPathScn, `{"id":"p384","keys":[{"kty":"EC","crv":"P-384","x":"AAAA","y":"AAAA"}],"allowedGroups":["g"]}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"error":"invalid_agent"`) || !strings.Contains(body, `"field":"keys[0].crv"`) {
		t.Fatalf("P-384 create = %d %s, want 400 invalid_agent keys[0].crv", resp.StatusCode, body)
	}
	if resp, body := do(admin, acsrf, http.MethodPost, agentsPathScn, create); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate id = %d %s, want 409", resp.StatusCode, body)
	}
	shared := `{"id":"other","keys":[` + string(key1) + `],"allowedGroups":["g"]}`
	if resp, body := do(admin, acsrf, http.MethodPost, agentsPathScn, shared); resp.StatusCode != http.StatusConflict {
		t.Fatalf("shared key = %d %s, want 409", resp.StatusCode, body)
	}

	// If-Match: missing is 428, stale is 409, current is 200 and rotates.
	if resp, body := do(admin, acsrf, http.MethodPut, agentsPathScn+"/claude-code", update); resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("PUT without If-Match = %d %s, want 428", resp.StatusCode, body)
	}
	resp, body = do(admin, acsrf, http.MethodPut, agentsPathScn+"/claude-code", update, "If-Match", `"r9"`)
	if resp.StatusCode != http.StatusConflict || strings.TrimSpace(body) != `{"error":"agent_conflict"}` {
		t.Fatalf("stale PUT = %d %s, want 409 agent_conflict", resp.StatusCode, body)
	}
	resp, body = do(admin, acsrf, http.MethodPut, agentsPathScn+"/claude-code", update, "If-Match", `"r1"`)
	var updated agentScnView
	decodeInto(t, "update", body, &updated)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"r2"` || updated.Revision != 2 || len(updated.Keys) != 2 || updated.OwnerSub != "ada" || len(updated.AllowedGroups) != 2 {
		t.Fatalf("update = %d %s", resp.StatusCode, body)
	}

	// Disable and enable.
	resp, body = do(admin, acsrf, http.MethodPost, agentsPathScn+"/claude-code/disable", "", "If-Match", `"r2"`)
	var off agentScnView
	decodeInto(t, "disable", body, &off)
	if resp.StatusCode != http.StatusOK || off.Status != "disabled" || off.Revision != 3 {
		t.Fatalf("disable = %d %s", resp.StatusCode, body)
	}
	if resp, body := do(admin, acsrf, http.MethodPost, agentsPathScn+"/claude-code/enable", ""); resp.StatusCode != http.StatusPreconditionRequired {
		t.Fatalf("enable without If-Match = %d %s, want 428", resp.StatusCode, body)
	}
	resp, body = do(admin, acsrf, http.MethodPost, agentsPathScn+"/claude-code/enable", "", "If-Match", `"r3"`)
	var on agentScnView
	decodeInto(t, "enable", body, &on)
	if resp.StatusCode != http.StatusOK || on.Status != "active" || on.Revision != 4 {
		t.Fatalf("enable = %d %s", resp.StatusCode, body)
	}
	if resp, body := do(admin, acsrf, http.MethodDelete, agentsPathScn+"/claude-code", ""); resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		t.Fatalf("DELETE = %d %s, want a refusal", resp.StatusCode, body)
	}

	// Reads: the viewer sees the agent and its public key.
	resp, body = do(viewer, vcsrf, http.MethodGet, agentsPathScn+"/claude-code", "")
	var got agentScnView
	decodeInto(t, "get", body, &got)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"r4"` || got.Revision != 4 {
		t.Fatalf("GET = %d %s ETag %q", resp.StatusCode, body, resp.Header.Get("ETag"))
	}
	if resp, _ := do(viewer, vcsrf, http.MethodGet, agentsPathScn+"/ghost", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET of an unknown agent = %d, want 404", resp.StatusCode)
	}

	// Exactly one ok row per successful write (create, update, disable, enable),
	// each naming the agent, none carrying a key coordinate.
	var ok []harness.AdminAuditRow
	for _, r := range agentRows()[denied:] {
		if r.Outcome == adminaudit.OutcomeOK {
			ok = append(ok, r)
		}
	}
	wantActions := []string{"agent.create", "agent.update", "agent.disable", "agent.enable"}
	if len(ok) != len(wantActions) {
		t.Fatalf("ok agent rows = %+v, want %v", ok, wantActions)
	}
	for i, r := range ok {
		if r.Action != wantActions[i] || r.Target != "agents" || r.TargetRef != "agent:claude-code" || r.Sub != "ada" || r.ActorRole != "admin" || r.BeforeHash == r.AfterHash {
			t.Errorf("row %d = %+v, want %s on agent:claude-code by ada", i, r, wantActions[i])
		}
	}
	for _, r := range h.AdminAuditRows() {
		var d map[string]string
		if r.Details != "" {
			decodeInto(t, "details", r.Details, &d)
		}
		if _, hasX := d["x"]; hasX || strings.Contains(r.Details, coordinate) || strings.Contains(r.Details, `"y"`) {
			t.Errorf("row %d (%s) details carry key material: %s", r.Seq, r.Action, r.Details)
		}
	}
	if strings.Contains(h.Logs(), coordinate) {
		t.Error("a log line carries a key coordinate")
	}

	// A write by another process (the offline CLI) shows up through the API
	// once the control plane's watch sees the database change.
	ctx := context.Background()
	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := agentregsqlite.New(db, agentregsqlite.WithClock(h.Clock())).Create(ctx, agentreg.Agent{
		ID: "from-cli", Keys: []agentreg.Key{{JWK: agentregtest.Ed25519JWK(t, "scn-key-cli")}}, AllowedGroups: []string{"eng"},
	}, "cli:scenario"); err != nil {
		t.Fatalf("offline create: %v", err)
	}
	h.Eventually("the API to show the agent an offline writer registered", func() bool {
		h.Clock().Advance(3 * time.Second)
		resp, body := do(viewer, vcsrf, http.MethodGet, agentsPathScn+"/from-cli", "")
		return resp.StatusCode == http.StatusOK && strings.Contains(body, `"createdBy":"cli:scenario"`)
	})
	var list struct {
		Agents []agentScnView `json:"agents"`
	}
	_, body = do(viewer, vcsrf, http.MethodGet, agentsPathScn, "")
	decodeInto(t, "list", body, &list)
	if len(list.Agents) != 2 || list.Agents[0].ID != "claude-code" || list.Agents[1].ID != "from-cli" {
		t.Errorf("list = %s, want claude-code and from-cli ordered by id", body)
	}
}

// agentRegistryUseCLIOpts: console.auth none with a state dir.
func agentRegistryUseCLIOpts() []harness.Option {
	return []harness.Option{harness.WithWorkerTokens()}
}

// agentRegistryUseCLI: without console sign-in there is nobody to attribute a
// key or group change to, so writes answer 403 use_cli even for the bearer the
// dashboard accepts, and reads still work.
func agentRegistryUseCLI(t *testing.T, h *harness.H) {
	cp := h.CP()
	body := []byte(`{"id":"a1","keys":[` + string(agentregtest.Ed25519JWK(t, "scn-none")) + `],"allowedGroups":["g"]}`)
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, agentsPathScn},
		{http.MethodPut, agentsPathScn + "/a1"},
		{http.MethodPost, agentsPathScn + "/a1/disable"},
		{http.MethodPost, agentsPathScn + "/a1/enable"},
	} {
		code, resp, err := cp.Do(c.method, c.path, cp.Token(), body)
		if err != nil || code != http.StatusForbidden || !strings.Contains(resp, `"use_cli"`) {
			t.Errorf("%s %s = %d %q, %v; want 403 use_cli", c.method, c.path, code, resp, err)
		}
	}
	var list struct {
		Agents []json.RawMessage `json:"agents"`
	}
	if err := cp.GetJSON(agentsPathScn, &list); err != nil || len(list.Agents) != 0 {
		t.Errorf("GET %s = %v, %v; want an empty list", agentsPathScn, list, err)
	}
}

// agentRegistryNoState: a control plane with no state dir has no registry, so
// every route is 503 state_dir_required; the worker's own dashboard never
// serves the routes (404).
func agentRegistryNoState(t *testing.T, h *harness.H) {
	cp := h.CP()
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, agentsPathScn},
		{http.MethodGet, agentsPathScn + "/a1"},
		{http.MethodPost, agentsPathScn},
		{http.MethodPut, agentsPathScn + "/a1"},
		{http.MethodPost, agentsPathScn + "/a1/disable"},
	} {
		code, resp, err := cp.Do(c.method, c.path, cp.Token(), []byte(`{}`))
		if err != nil || code != http.StatusServiceUnavailable || !strings.Contains(resp, "state_dir_required") {
			t.Errorf("%s %s = %d %q, %v; want 503 state_dir_required", c.method, c.path, code, resp, err)
		}
	}
	for _, path := range []string{agentsPathScn, agentsPathScn + "/a1"} {
		if code, _ := adminDo(t, h, http.MethodGet, path); code != http.StatusNotFound {
			t.Errorf("worker dashboard GET %s = %d, want 404", path, code)
		}
	}
}
