package config

import (
	"fmt"
	"strings"
)

// AuditConfig groups the signed-receipt and compliance-tagging features.
type AuditConfig struct {
	SignedReceipts SignedReceiptsConfig
	Compliance     ComplianceConfig
	// JSONLog configures the node-local JSON decision stream (warden.decision.v1).
	JSONLog JSONLogConfig
}

// JSON log output targets and query modes.
const (
	JSONLogOutputStdout = "stdout"
	JSONLogOutputStderr = "stderr"
	JSONLogOutputFile   = "file"

	JSONLogQueryDrop = "drop"
	JSONLogQueryKeys = "keys"

	defaultJSONLogMaxSizeMB  = 100
	defaultJSONLogMaxBackups = 10
	defaultJSONLogMaxAgeDays = 30
	defaultJSONLogFileMode   = 0o600
)

// JSONLogConfig configures the JSON decision stream, one line per stored
// analytics event, for a SIEM shipper. Node-local and restart-only (Config.Audit
// is json:"-", so it never travels in SettingsWire). Absent block = disabled.
type JSONLogConfig struct {
	Enabled bool
	// Output is stdout, stderr or file. Default stdout.
	Output string
	// Path is the log file; required when Output is file.
	Path string
	// MaxSizeMB, MaxBackups and MaxAgeDays drive rotation of the file output.
	MaxSizeMB  int
	MaxBackups int
	MaxAgeDays int
	// Compress gzips rotated files.
	Compress bool
	// FileMode is the permission bits of the log file: 0600 to 0640, owner-rw.
	FileMode uint32
	// Query is drop (no query data in url_path) or keys (sorted parameter names,
	// never values). Default drop.
	Query string
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
	JSONLog *struct {
		Enabled    bool   `yaml:"enabled"`
		Output     string `yaml:"output"`
		Path       string `yaml:"path"`
		MaxSizeMB  *int   `yaml:"maxSizeMB"`
		MaxBackups *int   `yaml:"maxBackups"`
		MaxAgeDays *int   `yaml:"maxAgeDays"`
		Compress   bool   `yaml:"compress"`
		FileMode   *int   `yaml:"fileMode"`
		Query      string `yaml:"query"`
	} `yaml:"jsonLog"`
}

// parseAudit converts the raw audit block into typed config. An absent block
// yields every feature disabled (jsonLog carries its defaults).
func parseAudit(r *rawAudit) AuditConfig {
	a := AuditConfig{JSONLog: JSONLogConfig{
		Output:     JSONLogOutputStdout,
		MaxSizeMB:  defaultJSONLogMaxSizeMB,
		MaxBackups: defaultJSONLogMaxBackups,
		MaxAgeDays: defaultJSONLogMaxAgeDays,
		FileMode:   defaultJSONLogFileMode,
		Query:      JSONLogQueryDrop,
	}}
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
	if j := r.JSONLog; j != nil {
		a.JSONLog.Enabled = j.Enabled
		if o := strings.TrimSpace(j.Output); o != "" {
			a.JSONLog.Output = o
		}
		a.JSONLog.Path = strings.TrimSpace(j.Path)
		if j.MaxSizeMB != nil {
			a.JSONLog.MaxSizeMB = *j.MaxSizeMB
		}
		if j.MaxBackups != nil {
			a.JSONLog.MaxBackups = *j.MaxBackups
		}
		if j.MaxAgeDays != nil {
			a.JSONLog.MaxAgeDays = *j.MaxAgeDays
		}
		a.JSONLog.Compress = j.Compress
		if j.FileMode != nil {
			// YAML 0600 is octal; an out-of-range or negative value is kept as
			// an impossible mode so validateAudit rejects it by name.
			if *j.FileMode < 0 {
				a.JSONLog.FileMode = ^uint32(0)
			} else {
				a.JSONLog.FileMode = uint32(*j.FileMode)
			}
		}
		if q := strings.TrimSpace(j.Query); q != "" {
			a.JSONLog.Query = q
		}
	}
	return a
}

// validateAudit enforces the audit block's requirements only for enabled features.
func validateAudit(a AuditConfig) error {
	if a.SignedReceipts.Enabled && a.SignedReceipts.Log == "" {
		return fmt.Errorf("config: audit.signedReceipts.log is required when signed receipts are enabled")
	}
	return validateJSONLog(a.JSONLog)
}

// validateJSONLog checks the jsonLog block. Values are checked even while the
// stream is disabled so a typo surfaces before it is switched on.
func validateJSONLog(j JSONLogConfig) error {
	if j == (JSONLogConfig{}) {
		// Never went through parseAudit (a policy decoded from the CP wire,
		// where Audit is json:"-"): no defaults were applied and nothing is on.
		return nil
	}
	switch j.Output {
	case JSONLogOutputStdout, JSONLogOutputStderr, JSONLogOutputFile:
	default:
		return fmt.Errorf("config: audit.jsonLog.output %q is not one of stdout, stderr, file", j.Output)
	}
	switch j.Query {
	case JSONLogQueryDrop, JSONLogQueryKeys:
	default:
		return fmt.Errorf("config: audit.jsonLog.query %q is not one of drop, keys", j.Query)
	}
	if j.Output == JSONLogOutputFile && j.Path == "" {
		return fmt.Errorf("config: audit.jsonLog.path is required when audit.jsonLog.output is file")
	}
	if j.MaxSizeMB <= 0 {
		return fmt.Errorf("config: audit.jsonLog.maxSizeMB must be positive, got %d", j.MaxSizeMB)
	}
	if j.MaxBackups < 0 {
		return fmt.Errorf("config: audit.jsonLog.maxBackups must not be negative, got %d", j.MaxBackups)
	}
	if j.MaxAgeDays < 0 {
		return fmt.Errorf("config: audit.jsonLog.maxAgeDays must not be negative, got %d", j.MaxAgeDays)
	}
	if j.FileMode&^0o640 != 0 || j.FileMode&0o600 != 0o600 {
		return fmt.Errorf("config: audit.jsonLog.fileMode %#o must be 0600 or 0640 (owner read-write, optional group read)", j.FileMode)
	}
	return nil
}
