package controlplane

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
)

type failingAuditRecorder struct{ calls int }

func (f *failingAuditRecorder) Record(context.Context, adminaudit.Input) (adminaudit.Entry, error) {
	f.calls++
	return adminaudit.Entry{}, errors.New("audit store unavailable")
}

func agentKey(t *testing.T) agentreg.Key {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	j, err := keys.PublicJWK(pub, keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(j)
	return agentreg.Key{JWK: raw}
}

func failingAgentCLI(t *testing.T) (*agentCLI, *failingAuditRecorder) {
	t.Helper()
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), adminaudit.StateDBFileName), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	rec := &failingAuditRecorder{}
	return &agentCLI{rec: rec, store: agentregsqlite.New(db), closeAll: func() {}}, rec
}

// TestAgentCLIUnauditedWriteIsUndone: when the audit append fails, register
// leaves the agent disabled, update restores the previous fields and keys,
// and a status change is flipped back; each reports the failure.
func TestAgentCLIUnauditedWriteIsUndone(t *testing.T) {
	ctx := context.Background()
	h, rec := failingAgentCLI(t)

	if _, err := h.register(ctx, agentreg.Agent{ID: "a1", Keys: []agentreg.Key{agentKey(t)}, AllowedGroups: []string{"g1"}}); err == nil {
		t.Fatal("register with a failing audit succeeded")
	}
	a, err := h.store.Get(ctx, "a1")
	if err != nil || a.Status != agentreg.StatusDisabled || a.Revision != 2 {
		t.Fatalf("after failed register: %+v %v; want disabled revision 2", a, err)
	}

	// Seed an active agent directly, then fail updates and status changes.
	k1 := agentKey(t)
	seed, err := h.store.Create(ctx, agentreg.Agent{ID: "a2", DisplayName: "one", Keys: []agentreg.Key{k1}, AllowedGroups: []string{"g1"}}, "cli:test")
	if err != nil {
		t.Fatal(err)
	}
	name := "two"
	if _, err := h.update(ctx, "a2", seed.Revision, AgentChange{DisplayName: &name, SetGroups: true, Groups: []string{"g9"}, Keys: []agentreg.Key{agentKey(t)}}); err == nil {
		t.Fatal("update with a failing audit succeeded")
	}
	got, _ := h.store.Get(ctx, "a2")
	if got.DisplayName != "one" || len(got.AllowedGroups) != 1 || got.AllowedGroups[0] != "g1" ||
		len(got.Keys) != 1 || got.Keys[0].JKT != seed.Keys[0].JKT || got.Revision != seed.Revision+2 {
		t.Fatalf("after failed update: %+v, want the seed fields", got)
	}

	if _, err := h.setStatus(ctx, "a2", agentreg.StatusDisabled, got.Revision); err == nil {
		t.Fatal("disable with a failing audit succeeded")
	}
	got2, _ := h.store.Get(ctx, "a2")
	if got2.Status != agentreg.StatusActive || got2.Revision != got.Revision+2 {
		t.Fatalf("after failed disable: %+v, want active", got2)
	}
	if rec.calls != 3 {
		t.Errorf("recorder calls = %d, want 3", rec.calls)
	}
}

// racingRecorder fails the audit append after a concurrent writer bumped the
// agent's revision, so the undo hits a stale revision.
type racingRecorder struct {
	store *agentregsqlite.Store
	id    string
}

func (r *racingRecorder) Record(ctx context.Context, _ adminaudit.Input) (adminaudit.Entry, error) {
	a, _ := r.store.Get(ctx, r.id)
	_, _ = r.store.SetStatus(ctx, r.id, agentreg.StatusActive, a.Revision, "cli:other")
	return adminaudit.Entry{}, errors.New("audit store unavailable")
}

// TestAgentCLIUndoFailureReportsBoth: an undo that cannot apply is reported
// together with the audit failure.
func TestAgentCLIUndoFailureReportsBoth(t *testing.T) {
	h, _ := failingAgentCLI(t)
	h.rec = &racingRecorder{store: h.store, id: "a1"}
	_, err := h.register(context.Background(), agentreg.Agent{ID: "a1", Keys: []agentreg.Key{agentKey(t)}, AllowedGroups: []string{"g1"}})
	if err == nil || !errors.Is(err, agentreg.ErrConflict) || !strings.Contains(err.Error(), "audit store unavailable") {
		t.Fatalf("err = %v, want both the audit failure and the conflict", err)
	}
}
