package approvals

import "github.com/ethosagent/warden/internal/config"

// Doc is the canonical policy document a change is classified over: the same
// redacted allowlist, denylist and settings the versioned policy store holds
// (blockedUsers is a separate target and is not part of it). Settings is a
// pointer so an absent block and an empty one compare equal.
type Doc struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
	Settings  *config.SettingsWire    `json:"settings,omitempty"`
}
