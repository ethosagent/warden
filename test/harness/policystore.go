package harness

import (
	"path/filepath"

	"github.com/ethosagent/warden/internal/controlplane"
)

// WithVersionedPolicyStore boots the control plane with
// --policy-store=versioned and a state dir, so /policy serves the head of the
// versioned policy store (the YAML while the store is empty). In-process only.
func WithVersionedPolicyStore() Option {
	return func(h *H) { h.versionedPolicy = true }
}

// applyPolicyStore sets the control-plane params WithVersionedPolicyStore asks
// for. The state dir is the one WithConsoleOIDC uses, so the two combine.
func (h *H) applyPolicyStore(p *controlplane.Params) {
	if !h.versionedPolicy {
		return
	}
	p.StateDir = filepath.Join(h.root, "cp-state")
	p.PolicyStore = controlplane.PolicyStoreVersioned
}

// ControlPlaneStateDB is the path of the control plane's state database, for a
// scenario that plays an out-of-process writer (the CLI). It needs
// WithVersionedPolicyStore, WithConsoleOIDC or WithWorkerTokens.
func (h *H) ControlPlaneStateDB() string {
	h.tb.Helper()
	if !h.versionedPolicy && !h.wantConsole && !h.wantWorkerTokens {
		h.tb.Fatal("harness: ControlPlaneStateDB needs WithVersionedPolicyStore, WithConsoleOIDC or WithWorkerTokens")
	}
	return filepath.Join(h.root, "cp-state", "warden-cp.db")
}

// WithWorkerTokens boots the control plane with a state dir, so it builds the
// per-worker token store (W-P1-WTOK-02) on the harness's fake clock. The
// workers keep using the shared token; a scenario mints tokens out of process
// (ControlPlaneStateDB) and presents them through CP().Do. In-process only.
func WithWorkerTokens() Option {
	return func(h *H) { h.wantWorkerTokens = true }
}
