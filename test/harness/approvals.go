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
	y := "  approvals:\n    enabled: true\n"
	if h.wantEmergencyApply {
		y += "    allowEmergencyApply: true\n"
	}
	return y
}

func (h *H) applyApprovals(p *controlplane.Params) {
	if !h.wantApprovals {
		return
	}
	p.StateDir = filepath.Join(h.root, "cp-state")
}

// WithEmergencyApply boots the control plane with
// console.approvals.allowEmergencyApply: true (W-P2-APPR-07), so a break-glass
// session may emergency-apply a pending draft. It needs WithApprovals and
// WithBreakGlass. In-process only.
func WithEmergencyApply() Option {
	return func(h *H) { h.wantEmergencyApply = true }
}
