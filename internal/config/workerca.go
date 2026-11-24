package config

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Worker CA key sources (workerCA.keySource).
const (
	// WorkerCAKeySourceKeys loads the intermediate key through the signing-key
	// manager (keys.enabled, purpose ca). The default.
	WorkerCAKeySourceKeys = "keys"
	// WorkerCAKeySourceFile reads a PKCS#8 PEM file (mode 0600, outside
	// --state-dir). Development only.
	WorkerCAKeySourceFile = "file"
)

// Worker CA defaults and bounds (W-P2-WCA-01).
const (
	workerCADefaultCertTTL           = 24 * time.Hour
	workerCAMinCertTTL               = time.Hour
	workerCAMaxCertTTL               = 7 * 24 * time.Hour
	workerCADefaultEnrollTokenTTL    = time.Hour
	workerCADefaultEnrollTokenMaxTTL = 24 * time.Hour
	workerCAMaxEnrollTokenMaxTTL     = 7 * 24 * time.Hour
)

// workerCATrustDomainRe is a lowercase DNS-style name: the trust domain is the
// host of every worker SPIFFE ID and the URI name constraint of the
// intermediate, so it must be a plain host (no port, no path, no wildcard).
var workerCATrustDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// WorkerCAConfig is the control-plane-local `workerCA:` block (W-P2-WCA-01): a
// CP-held intermediate CA that issues short-lived worker client certificates.
// Like console: and keys: it is read by the control plane from --config only
// (LoadWorkerCA) and never leaves it: Policy.WorkerCA is json:"-", so it is not
// on the worker wire. Disabled by default; when disabled nothing is loaded and
// the control plane behaves as before.
type WorkerCAConfig struct {
	// Enabled turns the worker CA on.
	Enabled bool
	// TrustDomain is the SPIFFE trust domain of worker identities
	// (spiffe://<TrustDomain>/warden/worker/<id>). Required when enabled.
	TrustDomain string
	// CertFile is the PEM chain of the worker intermediate (leaf first).
	CertFile string
	// PreviousCertFile is the previous intermediate chain, trusted for
	// verification only while the intermediate is being rotated.
	PreviousCertFile string
	// CertTTL is the lifetime of an issued worker certificate (default 24h,
	// 1h to 7d).
	CertTTL time.Duration
	// EnrollTokenTTL is the default lifetime of an enrollment token (default 1h).
	EnrollTokenTTL time.Duration
	// EnrollTokenMaxTTL is the longest an operator may ask for (default 24h,
	// at most 7d).
	EnrollTokenMaxTTL time.Duration
	// KeySource is WorkerCAKeySourceKeys (default) or WorkerCAKeySourceFile.
	KeySource string
	// KeyFile is the PKCS#8 PEM key file for KeySource file.
	KeyFile string
}

// rawWorkerCA mirrors the on-disk `workerCA:` block. Durations stay strings so
// an absent field differs from an explicit zero.
type rawWorkerCA struct {
	Enabled           bool   `yaml:"enabled"`
	TrustDomain       string `yaml:"trustDomain"`
	CertFile          string `yaml:"certFile"`
	PreviousCertFile  string `yaml:"previousCertFile"`
	CertTTL           string `yaml:"certTTL"`
	EnrollTokenTTL    string `yaml:"enrollTokenTTL"`
	EnrollTokenMaxTTL string `yaml:"enrollTokenMaxTTL"`
	KeySource         string `yaml:"keySource"`
	KeyFile           string `yaml:"keyFile"`
}

// parseWorkerCA converts the raw block and applies defaults. An absent block is
// the disabled default.
func parseWorkerCA(r *rawWorkerCA) (WorkerCAConfig, error) {
	c := WorkerCAConfig{
		CertTTL:           workerCADefaultCertTTL,
		EnrollTokenTTL:    workerCADefaultEnrollTokenTTL,
		EnrollTokenMaxTTL: workerCADefaultEnrollTokenMaxTTL,
		KeySource:         WorkerCAKeySourceKeys,
	}
	if r == nil {
		return c, nil
	}
	c.Enabled = r.Enabled
	c.TrustDomain = strings.TrimSpace(r.TrustDomain)
	c.CertFile = strings.TrimSpace(r.CertFile)
	c.PreviousCertFile = strings.TrimSpace(r.PreviousCertFile)
	c.KeyFile = strings.TrimSpace(r.KeyFile)
	if s := strings.TrimSpace(r.KeySource); s != "" {
		c.KeySource = s
	}
	for _, f := range []struct {
		name string
		raw  string
		dst  *time.Duration
	}{
		{"workerCA.certTTL", r.CertTTL, &c.CertTTL},
		{"workerCA.enrollTokenTTL", r.EnrollTokenTTL, &c.EnrollTokenTTL},
		{"workerCA.enrollTokenMaxTTL", r.EnrollTokenMaxTTL, &c.EnrollTokenMaxTTL},
	} {
		if err := parseDurationField(f.name, f.raw, f.dst); err != nil {
			return WorkerCAConfig{}, err
		}
	}
	return c, nil
}

// ValidWorkerCATrustDomain reports whether s is usable as a trust domain.
func ValidWorkerCATrustDomain(s string) bool {
	return len(s) <= 253 && workerCATrustDomainRe.MatchString(s)
}

// validateWorkerCA enforces the block's invariants. Value checks run whether or
// not the block is enabled, so a typo surfaces when the file is written; the
// required keys only when enabled.
func validateWorkerCA(c WorkerCAConfig) error {
	switch c.KeySource {
	case WorkerCAKeySourceKeys, WorkerCAKeySourceFile:
	default:
		return fmt.Errorf("config: workerCA.keySource %q is not supported; use %q or %q", c.KeySource, WorkerCAKeySourceKeys, WorkerCAKeySourceFile)
	}
	if c.TrustDomain != "" && !ValidWorkerCATrustDomain(c.TrustDomain) {
		return fmt.Errorf("config: workerCA.trustDomain %q must be a lowercase DNS name (no scheme, port, path or wildcard)", c.TrustDomain)
	}
	if c.CertTTL < workerCAMinCertTTL || c.CertTTL > workerCAMaxCertTTL {
		return fmt.Errorf("config: workerCA.certTTL %s must be between %s and %s", c.CertTTL, workerCAMinCertTTL, workerCAMaxCertTTL)
	}
	if c.EnrollTokenMaxTTL <= 0 || c.EnrollTokenMaxTTL > workerCAMaxEnrollTokenMaxTTL {
		return fmt.Errorf("config: workerCA.enrollTokenMaxTTL %s must be positive and at most %s", c.EnrollTokenMaxTTL, workerCAMaxEnrollTokenMaxTTL)
	}
	if c.EnrollTokenTTL <= 0 || c.EnrollTokenTTL > c.EnrollTokenMaxTTL {
		return fmt.Errorf("config: workerCA.enrollTokenTTL %s must be positive and at most workerCA.enrollTokenMaxTTL (%s)", c.EnrollTokenTTL, c.EnrollTokenMaxTTL)
	}
	if c.KeySource == WorkerCAKeySourceKeys && c.KeyFile != "" {
		return fmt.Errorf("config: workerCA.keyFile is only valid with workerCA.keySource %q", WorkerCAKeySourceFile)
	}
	if !c.Enabled {
		return nil
	}
	if c.TrustDomain == "" {
		return fmt.Errorf("config: workerCA.trustDomain is required when workerCA.enabled is true")
	}
	if c.CertFile == "" {
		return fmt.Errorf("config: workerCA.certFile is required when workerCA.enabled is true")
	}
	if c.KeySource == WorkerCAKeySourceFile && c.KeyFile == "" {
		return fmt.Errorf("config: workerCA.keyFile is required when workerCA.keySource is %q", WorkerCAKeySourceFile)
	}
	return nil
}

// DefaultWorkerCA returns the block with every default applied and enabled
// false.
func DefaultWorkerCA() WorkerCAConfig {
	c, _ := parseWorkerCA(nil)
	return c
}

// LoadWorkerCA reads only the `workerCA:` block of the YAML file at path, with
// the same strict decoder and validation as a full config load. The control
// plane calls it on the operator-owned --config file (never the served copy).
func LoadWorkerCA(path string) (WorkerCAConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return WorkerCAConfig{}, fmt.Errorf("config: read %q: %w", path, err)
	}
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return WorkerCAConfig{}, fmt.Errorf("config: parse yaml: %w", err)
	}
	c, err := parseWorkerCA(raw.WorkerCA)
	if err != nil {
		return WorkerCAConfig{}, err
	}
	if err := validateWorkerCA(c); err != nil {
		return WorkerCAConfig{}, err
	}
	return c, nil
}
