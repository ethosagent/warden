package config

import (
	"fmt"
	"strings"
)

// AuditConfig groups the signed-receipt and compliance-tagging features.
type AuditConfig struct {
	SignedReceipts SignedReceiptsConfig
	Compliance     ComplianceConfig
}

// SignedReceiptsConfig configures Ed25519-signed, independently-verifiable
// receipts for every mediated event.
type SignedReceiptsConfig struct {
	Enabled bool
	// KeyFile is the Ed25519 private-key path (PKCS#8 PEM). It is generated and
	// persisted on first run if absent, and its public key is logged at startup.
	KeyFile string
	// Log is the JSONL receipts output path (one signed receipt per line).
	Log string
}

// ComplianceConfig toggles tagging events with OWASP/MITRE control IDs.
type ComplianceConfig struct {
	Enabled bool
}

// rawAudit mirrors the on-disk `audit:` block.
type rawAudit struct {
	SignedReceipts *struct {
		Enabled bool   `yaml:"enabled"`
		KeyFile string `yaml:"keyFile"`
		Log     string `yaml:"log"`
	} `yaml:"signedReceipts"`
	Compliance *struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"compliance"`
}

// parseAudit converts the raw audit block into typed config. An absent block
// yields both features disabled.
func parseAudit(r *rawAudit) AuditConfig {
	var a AuditConfig
	if r == nil {
		return a
	}
	if r.SignedReceipts != nil {
		a.SignedReceipts.Enabled = r.SignedReceipts.Enabled
		a.SignedReceipts.KeyFile = strings.TrimSpace(r.SignedReceipts.KeyFile)
		a.SignedReceipts.Log = strings.TrimSpace(r.SignedReceipts.Log)
	}
	if r.Compliance != nil {
		a.Compliance.Enabled = r.Compliance.Enabled
	}
	return a
}

// validateAudit enforces the audit block's requirements only for enabled features.
func validateAudit(a AuditConfig) error {
	if a.SignedReceipts.Enabled && a.SignedReceipts.Log == "" {
		return fmt.Errorf("config: audit.signedReceipts.log is required when signed receipts are enabled")
	}
	return nil
}
