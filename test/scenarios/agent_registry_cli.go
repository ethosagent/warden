package scenarios

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// Offline agent registry CLI (W-P2-AREG-06). The `warden control-plane agent`
// commands are flag parsing over controlplane.RunAgent*, so the scenario calls
// those with the control plane running on the same state dir. There is no
// registry read path in the control plane until the admin API and the policy
// wire land (W-P2-AREG-02 and -04), so what a running control plane would
// serve is proven at the store level: a second handle on the live database,
// running the store's data_version Watch on the harness clock, sees each CLI
// write within the policy reload interval. In-process only (CP state dir).

func agentRegistryCLIOpts() []harness.Option { return []harness.Option{harness.WithAdminAudit()} }

func agentRegistryCLI(t *testing.T, h *harness.H) {
	ctx := context.Background()
	stateDir := h.AdminAuditStateDir()

	db, err := cpstate.Open(ctx, filepath.Join(stateDir, adminaudit.StateDBFileName), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the live state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	reader := agentregsqlite.New(db, agentregsqlite.WithClock(h.Clock()))
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go reader.Watch(watchCtx, 0)

	if got, err := reader.List(ctx); err != nil || len(got) != 0 {
		t.Fatalf("registry before the CLI = %v, %v; want empty", got, err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := keys.PublicJWK(pub, keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(j)
	file := filepath.Join(t.TempDir(), "pub.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := controlplane.ReadAgentJWKFiles([]string{file})
	if err != nil {
		t.Fatalf("ReadAgentJWKFiles: %v", err)
	}

	// register
	if _, err := controlplane.RunAgentRegister(ctx, stateDir, "", agentreg.Agent{
		ID: "claude-code", Keys: loaded, AllowedGroups: []string{"warden-agents"},
	}, nil); err != nil {
		t.Fatalf("register: %v", err)
	}
	seen := func(want agentreg.Status, rev int64) func() bool {
		return func() bool {
			h.Clock().Advance(agentregsqlite.DataVersionInterval)
			a, err := reader.Get(ctx, "claude-code")
			return err == nil && a.Status == want && a.Revision == rev
		}
	}
	h.Eventually("a running control plane's store sees the registered agent", seen(agentreg.StatusActive, 1))

	// disable
	if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", "claude-code", agentreg.StatusDisabled, 1, nil); err != nil {
		t.Fatalf("disable: %v", err)
	}
	h.Eventually("a running control plane's store sees the disable", seen(agentreg.StatusDisabled, 2))

	// a stale revision is refused and changes nothing
	if _, err := controlplane.RunAgentSetStatus(ctx, stateDir, "", "claude-code", agentreg.StatusActive, 1, nil); err == nil {
		t.Fatal("enable with a stale revision succeeded")
	}

	// two cli audit rows, no key material
	var rows []harness.AdminAuditRow
	for _, r := range h.AdminAuditRows() {
		if r.Target == "agents" {
			rows = append(rows, r)
		}
	}
	if len(rows) != 2 || rows[0].Action != "agent.create" || rows[1].Action != "agent.disable" {
		t.Fatalf("agent audit rows = %+v, want agent.create then agent.disable", rows)
	}
	for _, r := range rows {
		if r.AuthMethod != adminaudit.AuthMethodCLI || r.TargetRef != "agent:claude-code" || r.Outcome != adminaudit.OutcomeOK {
			t.Errorf("audit row = %+v", r)
		}
		if strings.Contains(r.Details, j.X) {
			t.Errorf("audit details carry a key coordinate: %s", r.Details)
		}
	}
	if !strings.Contains(rows[1].Details, `"status_to":"disabled"`) {
		t.Errorf("disable details = %s", rows[1].Details)
	}
}
