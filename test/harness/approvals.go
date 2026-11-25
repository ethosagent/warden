package harness

import (
	"path/filepath"

	"github.com/ethosagent/warden/internal/controlplane"
)

// The change-approval gate (W-P2-APPR-04): the control plane boots with
// console.approvals.enabled, so the draft routes under /dashboard/api/changes
// serve and a widening draft needs a second person. It needs console.auth oidc,
// the versioned policy store and the admin audit log, so it implies
// WithConsoleOIDC, WithVersionedPolicyStore and WithAdminAudit.

// ConsoleEditorGroup is the group console.roles maps to editor.
const ConsoleEditorGroup = "console-editors"

// WithApprovals boots the control plane with console.approvals.enabled: true.
// In-process only.
func WithApprovals() Option {
	return func(h *H) {
		h.wantApprovals = true
		h.wantConsole, h.wantAdminAudit, h.versionedPolicy = true, true, true
		h.wantIssuer = true
	}
}

// approvalsYAML renders the console.approvals block (indented for console:).
func (h *H) approvalsYAML() string {
	if !h.wantApprovals {
		return ""
	}
	return "  approvals:\n    enabled: true\n"
}

func (h *H) applyApprovals(p *controlplane.Params) {
	if !h.wantApprovals {
		return
	}
	p.StateDir = filepath.Join(h.root, "cp-state")
}
