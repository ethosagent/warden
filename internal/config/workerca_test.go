package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadWorkerCAYAML(t *testing.T, block string) (WorkerCAConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, keysYAML(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadWorkerCA(path)
}

const workerCAEnabledYAML = "workerCA:\n  enabled: true\n  trustDomain: warden.local\n  certFile: /etc/warden/intermediate-chain.pem\n"

// TestWorkerCAConfigDefaults: an absent block is disabled, with the documented
// defaults, from LoadWorkerCA and from a full policy load.
func TestWorkerCAConfigDefaults(t *testing.T) {
	want := WorkerCAConfig{
		CertTTL: 24 * time.Hour, EnrollTokenTTL: time.Hour, EnrollTokenMaxTTL: 24 * time.Hour,
		KeySource: "keys",
	}
	c, err := loadWorkerCAYAML(t, "")
	if err != nil {
		t.Fatal(err)
	}
	if c != want {
		t.Errorf("LoadWorkerCA(absent) = %+v, want %+v", c, want)
	}
	if DefaultWorkerCA() != want {
		t.Errorf("DefaultWorkerCA = %+v", DefaultWorkerCA())
	}
	prov, err := parse(keysYAML(""))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	if p.WorkerCA != want {
		t.Errorf("Policy.WorkerCA = %+v", p.WorkerCA)
	}
}

func TestWorkerCAConfigValid(t *testing.T) {
	c, err := loadWorkerCAYAML(t, workerCAEnabledYAML+"  previousCertFile: /p.pem\n  certTTL: 12h\n  enrollTokenTTL: 30m\n  enrollTokenMaxTTL: 48h\n")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled || c.TrustDomain != "warden.local" || c.CertFile != "/etc/warden/intermediate-chain.pem" ||
		c.PreviousCertFile != "/p.pem" || c.CertTTL != 12*time.Hour || c.EnrollTokenTTL != 30*time.Minute ||
		c.EnrollTokenMaxTTL != 48*time.Hour || c.KeySource != "keys" {
		t.Errorf("parsed = %+v", c)
	}
	f, err := loadWorkerCAYAML(t, workerCAEnabledYAML+"  keySource: file\n  keyFile: /k.pem\n")
	if err != nil || f.KeySource != "file" || f.KeyFile != "/k.pem" {
		t.Errorf("file source: %+v %v", f, err)
	}
}

// TestWorkerCAConfigInvalid: every bad value fails the load and names the key.
func TestWorkerCAConfigInvalid(t *testing.T) {
	for name, tc := range map[string]struct{ block, key string }{
		"no trust domain":    {"workerCA:\n  enabled: true\n  certFile: /c.pem\n", "workerCA.trustDomain"},
		"no cert file":       {"workerCA:\n  enabled: true\n  trustDomain: warden.local\n", "workerCA.certFile"},
		"bad trust domain":   {"workerCA:\n  trustDomain: https://x\n", "workerCA.trustDomain"},
		"upper trust domain": {"workerCA:\n  trustDomain: Warden.Local\n", "workerCA.trustDomain"},
		"key source":         {"workerCA:\n  keySource: kms\n", "workerCA.keySource"},
		"file needs keyFile": {workerCAEnabledYAML + "  keySource: file\n", "workerCA.keyFile"},
		"keys with keyFile":  {"workerCA:\n  keyFile: /k\n", "workerCA.keyFile"},
		"certTTL low":        {"workerCA:\n  certTTL: 30m\n", "workerCA.certTTL"},
		"certTTL high":       {"workerCA:\n  certTTL: 200h\n", "workerCA.certTTL"},
		"certTTL junk":       {"workerCA:\n  certTTL: soon\n", "workerCA.certTTL"},
		"token ttl zero":     {"workerCA:\n  enrollTokenTTL: 0s\n", "workerCA.enrollTokenTTL"},
		"token ttl over max": {"workerCA:\n  enrollTokenTTL: 25h\n", "workerCA.enrollTokenTTL"},
		"max over 7d":        {"workerCA:\n  enrollTokenMaxTTL: 200h\n", "workerCA.enrollTokenMaxTTL"},
		"unknown key":        {"workerCA:\n  bogus: 1\n", "bogus"},
	} {
		_, err := loadWorkerCAYAML(t, tc.block)
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: err = %v, want it to name %s", name, err, tc.key)
		}
		// A full policy load fails the same way.
		if _, err := parse(keysYAML(tc.block)); err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s (full load): err = %v", name, err)
		}
	}
}

// TestWorkerCAConfigNotOnTheWire: the block is CP-local, so a marshalled
// Policy never carries it.
func TestWorkerCAConfigNotOnTheWire(t *testing.T) {
	prov, err := parse(keysYAML(workerCAEnabledYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"warden.local", "intermediate-chain", "WorkerCA", "workerCA"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("policy JSON carries %q", leak)
		}
	}
}
