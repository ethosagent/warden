package config

import (
	"fmt"
	"strings"
)

// ResponseScanConfig gates scanning of ordinary (non-MCP) HTTP/HTTPS response
// bodies for credential leakage, prompt injection, and PII using the SAME
// detectors the MCP wedge uses. Everything is off by default; a zero value means
// "no response scanning" and is byte-identical to before. MCP responses are
// scanned by the MCP gateway and are never double-scanned here.
type ResponseScanConfig struct {
	// Enabled gates the whole feature. Default false.
	Enabled bool
	// Mode is one of off|monitor|enforce. monitor detects+logs but never blocks;
	// enforce additionally replaces a flagged response body with an error. Empty
	// normalizes to monitor.
	Mode string
	// MaxBodyBytes caps the buffered response body scanned inline. A response with
	// a Content-Length above this cap, or a streaming/SSE/unknown-length response,
	// is forwarded unchanged and logged as skipped (never silently truncated).
	// Default 1 MiB (1048576).
	MaxBodyBytes int
	// PII configures the opt-in PII detectors (email/card/SSN always on; phone opt-in).
	PII ResponseScanPIIConfig
	// Evidence captures a MASKED sample (last-4 + length, never the raw value) per
	// finding, so an operator can judge a real leak from a false positive. Default
	// false. LOCAL config.
	Evidence bool
}

// ResponseScanPIIConfig opts in to the noisier PII detectors for response
// scanning. email/card/SSN are always on; phone is opt-in because bare digit runs
// over-match.
type ResponseScanPIIConfig struct {
	Phone bool
}

// rawResponseScan mirrors the on-disk `responseScan:` block. Pointer so an absent
// block is distinct from an explicit (disabled) one. MaxBodyBytes is a pointer so
// absent-vs-zero can be distinguished (an explicit 0 is a real, validated value).
// KnownFields(true) is strict, so this MUST be registered or configs with the
// block fail to parse.
type rawResponseScan struct {
	Enabled      bool                `yaml:"enabled"`
	Mode         string              `yaml:"mode"`
	MaxBodyBytes *int                `yaml:"maxBodyBytes"`
	PII          *rawResponseScanPII `yaml:"pii"`
	Evidence     bool                `yaml:"evidence"`
}

type rawResponseScanPII struct {
	Phone bool `yaml:"phone"`
}

// responseScan defaults applied when the corresponding field is omitted.
const (
	defaultResponseScanMode         = "monitor"
	defaultResponseScanMaxBodyBytes = 1048576 // 1 MiB
)

// parseResponseScan converts the raw responseScan block into a typed
// ResponseScanConfig, applying the documented defaults. An absent block yields a
// disabled, harmless value with those defaults. Cross-field validation (mode enum,
// non-negative cap) happens in validate, only when enabled.
func parseResponseScan(r *rawResponseScan) ResponseScanConfig {
	rs := ResponseScanConfig{
		Mode:         defaultResponseScanMode,
		MaxBodyBytes: defaultResponseScanMaxBodyBytes,
	}
	if r == nil {
		return rs
	}
	rs.Enabled = r.Enabled
	if strings.TrimSpace(r.Mode) != "" {
		rs.Mode = strings.ToLower(strings.TrimSpace(r.Mode))
	}
	if r.MaxBodyBytes != nil {
		rs.MaxBodyBytes = *r.MaxBodyBytes
	}
	if r.PII != nil {
		rs.PII.Phone = r.PII.Phone
	}
	rs.Evidence = r.Evidence
	return rs
}

// validateResponseScan enforces the responseScan block's requirements only when
// it is enabled, so a disabled block with default-valued config is always valid
// (back-compat: configs that omit responseScan never fail here).
func validateResponseScan(rs ResponseScanConfig) error {
	if !rs.Enabled {
		return nil
	}
	switch rs.Mode {
	case "off", "monitor", "enforce":
	default:
		return fmt.Errorf("config: responseScan.mode %q is invalid; must be one of: off, monitor, enforce", rs.Mode)
	}
	if rs.MaxBodyBytes < 0 {
		return fmt.Errorf("config: responseScan.maxBodyBytes must not be negative")
	}
	return nil
}
