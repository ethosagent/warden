package config

import (
	"fmt"
	"strings"
)

// DLPConfig gates outbound REQUEST-body data-loss-prevention scanning. Phase 1
// scans the buffered request body in monitor mode only: findings ride the audit
// event + bounded metrics, but nothing is blocked, redacted, or mutated. Off by
// default; a zero value means "no DLP scanning" and is byte-identical to before.
//
// The nearest precedent is ResponseScanConfig (responsescan.go): the same
// off/monitor/enforce vocabulary, the same raw->typed->validate pipeline. DLP
// deliberately reuses the SAME detectors the response scanner and MCP wedge use;
// no new detectors land this phase.
type DLPConfig struct {
	// Mode is one of off|monitor|enforce. off disables the stage entirely.
	// monitor scans + records findings but never blocks. enforce is ACCEPTED as
	// valid config now so an operator can pre-declare intent, but Phase 1 treats
	// it as monitor (block/redact land in Phase 3/4) — the worker logs once that
	// enforce is not yet active. Empty normalizes to off (disabled by default).
	Mode string
}

// rawDLP mirrors the on-disk `dlp:` block. Pointer so an absent block is distinct
// from an explicit one. KnownFields(true) is strict, so this MUST be registered
// on rawConfig or configs carrying a `dlp` block fail to parse.
type rawDLP struct {
	Mode string `yaml:"mode"`
}

// defaultDLPMode is applied when the dlp block (or its mode) is omitted: DLP is
// off unless explicitly enabled, so an absent block is byte-identical to before.
const defaultDLPMode = "off"

// parseDLP converts the raw dlp block into a typed DLPConfig, applying the
// documented default. An absent block yields a disabled (off), harmless value.
func parseDLP(r *rawDLP) DLPConfig {
	d := DLPConfig{Mode: defaultDLPMode}
	if r == nil {
		return d
	}
	if strings.TrimSpace(r.Mode) != "" {
		d.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	}
	return d
}

// Active reports whether DLP should run: only monitor or enforce enable the
// stage. off and the zero value ("") both disable it. Phase 1 DLP is LOCAL
// config (Policy.DLP is json:"-"), so a control-plane-managed worker decodes it
// as the zero value — Active() must read that as disabled, exactly as a worker
// that never configured DLP.
func (d DLPConfig) Active() bool {
	return d.Mode == "monitor" || d.Mode == "enforce"
}

// validateDLP enforces the dlp block's mode enum. off/monitor/enforce are all
// valid, and the empty zero value is accepted as "off" (disabled): because
// Policy.DLP is json:"-" it never crosses the control-plane wire, so a managed
// worker decodes an empty mode that must validate — the same zero-value-is-valid
// discipline ResponseScanConfig relies on. enforce is accepted now (Phase 1
// treats it as monitor) so config can be written ahead of the enforce landing.
func validateDLP(d DLPConfig) error {
	switch d.Mode {
	case "", "off", "monitor", "enforce":
		return nil
	default:
		return fmt.Errorf("config: dlp.mode %q is invalid; must be one of: off, monitor, enforce", d.Mode)
	}
}
