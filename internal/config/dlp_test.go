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

// The D2 example config (classes + rules + custom) parses clean and round-trips.
const d2DLPYAML = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  classes:
    pii.contact: { action: redact }
  rules:
    - class: pii.*
      to: ["*.zendesk.com"]
      action: allow
    - class: pii.*
      to: ["api.openai.com", "api.anthropic.com", "openrouter.ai"]
      action: block
    - class: source_code
      to: ["github.com", "*.githubusercontent.com"]
      action: allow
    - class: source_code
      action: block
  custom:
    - name: project_codename
      regex: "ACME-\\d{4}"
      severity: medium
`

func TestParse_DLPD2ExampleClean(t *testing.T) {
	p, err := parse([]byte(d2DLPYAML))
	if err != nil {
		t.Fatalf("D2 example must parse clean: %v", err)
	}
	pol, _ := p.GetPolicy()
	d := pol.DLP
	if d.Mode != "enforce" {
		t.Fatalf("mode = %q", d.Mode)
	}
	if got := d.Classes["pii.contact"].Action; got != "redact" {
		t.Fatalf("classes[pii.contact].action = %q", got)
	}
	if len(d.Rules) != 4 {
		t.Fatalf("want 4 rules, got %d", len(d.Rules))
	}
	if d.Rules[1].Action != "block" || len(d.Rules[1].To) != 3 {
		t.Fatalf("rule[1] = %+v", d.Rules[1])
	}
	if len(d.Custom) != 1 || d.Custom[0].Name != "project_codename" || d.Custom[0].Severity != "medium" {
		t.Fatalf("custom = %+v", d.Custom)
	}
}

func TestValidate_DLPBadAction(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  rules:
    - class: pii.*
      action: bogus
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for invalid dlp rule action")
	}
}

func TestValidate_DLPUnknownClass(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  rules:
    - class: not_a_class
      action: block
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for unknown dlp class")
	}
}

func TestValidate_DLPBadDestination(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  rules:
    - class: pii.*
      to: ["a.*.b.com"]
      action: block
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for invalid dlp destination wildcard")
	}
}

func TestValidate_DLPBadCustomRegex(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  custom:
    - name: broken
      regex: "([unterminated"
      severity: medium
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for uncompilable custom regex")
	}
}

func TestValidate_DLPDuplicateCustomName(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  custom:
    - name: dup
      regex: "a"
      severity: low
    - name: dup
      regex: "b"
      severity: low
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for duplicate custom class name")
	}
}

// A rule referencing custom.<name> is valid only when that custom class is declared.
func TestValidate_DLPCustomClassSpec(t *testing.T) {
	const ok = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  custom:
    - name: codename
      regex: "ACME-[0-9]+"
      severity: medium
  rules:
    - class: custom.codename
      action: block
`
	if _, err := parse([]byte(ok)); err != nil {
		t.Fatalf("declared custom class in a rule must validate: %v", err)
	}
	const bad = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  rules:
    - class: custom.undeclared
      action: block
`
	if _, err := parse([]byte(bad)); err == nil {
		t.Fatal("expected error for rule referencing an undeclared custom class")
	}
}

// A custom class with an invalid severity is a config error.
func TestValidate_DLPBadCustomSeverity(t *testing.T) {
	const y = `
policy:
  allowlist:
    - domain: api.openai.com
dlp:
  mode: enforce
  custom:
    - name: x
      regex: "a"
      severity: critical
`
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("expected error for invalid custom severity")
	}
}
