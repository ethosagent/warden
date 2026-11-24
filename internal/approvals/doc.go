// Package approvals decides which policy changes need a second person
// (W-P2-APPR-02 onward). Classify is a pure function over two canonical policy
// docs: it never reads a clock, a store or the network, so the draft API, the
// single clearance check and the apply path can all call it and agree.
package approvals

import "github.com/ethosagent/warden/internal/config"

// Doc is the canonical policy document a change is classified over: the same
// redacted allowlist, denylist and settings the versioned policy store holds
// (blockedUsers is a separate target and is not part of it). Settings is a
// pointer so an absent block and an empty one compare equal.
//
// W-P2-APPR-01 owns the draft store and may widen this type; Classify reads
// only these three fields.
type Doc struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
	Settings  *config.SettingsWire    `json:"settings,omitempty"`
}
