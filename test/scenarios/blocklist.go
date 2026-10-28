package scenarios

import (
	"context"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// The block-list store scenario (W-P1-BLOCK-03): a block written through
// BlockStore by another process (standing in for the offline CLI) reaches the
// policy the control plane serves workers within its reload tick, carries only
// the sub and email (never the reason), and leaves with the entry when it is
// removed. The list rides the serve-time overlay, so the versioned policy store
// never holds it. Worker enforcement is W-P1-BLOCK-02's scenario.

func blockListOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// blockReason must never show up in the served policy or in any log line.
const blockReason = "reason-text-for-block-store-scenario"

func blockListServed(t *testing.T, h *harness.H) {
	ctx := context.Background()
	db, err := cpstate.Open(ctx, h.ControlPlaneStateDB(), controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	store := controlplane.NewBlockStore(db, controlplane.BlockStoreOptions{})

	served := func() []config.BlockedUser {
		var p struct {
			BlockedUsers []config.BlockedUser `json:"blockedUsers"`
		}
		if err := h.CP().GetJSON("/policy", &p); err != nil {
			t.Fatalf("GET /policy: %v", err)
		}
		return p.BlockedUsers
	}
	if got := served(); len(got) != 0 {
		t.Fatalf("a fresh control plane serves blockedUsers %+v, want none", got)
	}

	id, err := store.Add(ctx, controlplane.BlockEntry{Email: "Alice@Corp.com", Reason: blockReason}, "cli:harness")
	if err != nil {
		t.Fatalf("BlockStore.Add: %v", err)
	}
	h.Eventually("the control plane serves the block", func() bool {
		got := served()
		return len(got) == 1 && got[0] == config.BlockedUser{Email: "alice@corp.com"}
	})

	if err := store.Remove(ctx, id, "cli:harness"); err != nil {
		t.Fatalf("BlockStore.Remove: %v", err)
	}
	h.Eventually("the control plane stops serving the block", func() bool { return len(served()) == 0 })

	if logs := h.Logs(); strings.Contains(logs, blockReason) || strings.Contains(logs, "alice@corp.com") {
		t.Error("a log line carries a block-list value")
	}
}
