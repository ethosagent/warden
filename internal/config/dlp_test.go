package config

import "testing"

// An omitted dlp block is off by default and always valid (back-compat: existing
// configs never fail on this new block).
func TestParse_DLPOmittedOff(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
`
	p, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.DLP.Mode != "off" {
		t.Fatalf("dlp.mode default = %q, want off", pol.DLP.Mode)
	}
}

// off/monitor/enforce all parse as valid (enforce is accepted now; Phase 1
// treats it as monitor at wiring time), and the block round-trips.
func TestParse_DLPModes(t *testing.T) {
	for _, mode := range []string{"off", "monitor", "enforce"} {
		y := "policy:\n  allowlist:\n    - domain: api.openai.com\ndlp:\n  mode: " + mode + "\n"
		p, err := parse([]byte(y))
		if err != nil {
			t.Fatalf("mode %q: parse: %v", mode, err)
		}
		pol, _ := p.GetPolicy()
		if pol.DLP.Mode != mode {
			t.Fatalf("mode %q round-trip = %q", mode, pol.DLP.Mode)
		}
	}
}

// Mode is normalized to lower-case, mirroring responseScan.
func TestParse_DLPModeLowercased(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: MONITOR
`
	p, err := parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol, _ := p.GetPolicy()
	if pol.DLP.Mode != "monitor" {
		t.Fatalf("mode = %q, want monitor (lowercased)", pol.DLP.Mode)
	}
}

func TestValidate_DLPBadMode(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: bogus
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for invalid dlp.mode")
	}
}

// KnownFields(true) is strict: an unknown field under dlp must fail to parse.
func TestParse_DLPUnknownFieldStrict(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: monitor
  bogusField: 1
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected parse error for unknown field under dlp")
	}
}
