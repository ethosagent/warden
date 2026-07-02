package integration

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSeverityStringAndParse(t *testing.T) {
	cases := []struct {
		sev  Severity
		name string
	}{
		{SevInfo, "info"},
		{SevLow, "low"},
		{SevMedium, "medium"},
		{SevHigh, "high"},
		{SevCritical, "critical"},
	}
	for _, c := range cases {
		if got := c.sev.String(); got != c.name {
			t.Errorf("String(%d) = %q, want %q", c.sev, got, c.name)
		}
		// Round-trip and case-insensitivity.
		for _, in := range []string{c.name, strings.ToUpper(c.name), " " + c.name + " "} {
			got, err := ParseSeverity(in)
			if err != nil {
				t.Errorf("ParseSeverity(%q) error: %v", in, err)
			}
			if got != c.sev {
				t.Errorf("ParseSeverity(%q) = %v, want %v", in, got, c.sev)
			}
		}
	}
	if _, err := ParseSeverity("bogus"); err == nil {
		t.Error("ParseSeverity(bogus) expected error")
	}
	if got := Severity(99).String(); !strings.Contains(got, "99") {
		t.Errorf("String of unknown severity = %q, want to contain 99", got)
	}
}

func TestSeverityMarshalText(t *testing.T) {
	b, err := json.Marshal(struct {
		S Severity `json:"s"`
	}{S: SevHigh})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); got != `{"s":"high"}` {
		t.Errorf("marshal = %s, want severity as name", got)
	}
}

func TestMaxSeverity(t *testing.T) {
	if maxSeverity(SevLow, SevCritical) != SevCritical {
		t.Error("max(low, critical) should be critical")
	}
	if maxSeverity(SevHigh, SevInfo) != SevHigh {
		t.Error("max(high, info) should be high")
	}
	if maxSeverity(SevMedium, SevMedium) != SevMedium {
		t.Error("max(medium, medium) should be medium")
	}
}

func TestAlertIDDeterministicFromDedupKey(t *testing.T) {
	a := alertID("error_rate:api.foo.com")
	b := alertID("error_rate:api.foo.com")
	if a != b {
		t.Errorf("alertID not deterministic: %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("alertID length = %d, want 16", len(a))
	}
	if alertID("error_rate:api.foo.com") == alertID("error_rate:api.bar.com") {
		t.Error("different dedup keys should yield different IDs")
	}
}

func TestRuleIDFromDedupKey(t *testing.T) {
	cases := map[string]string{
		"error_rate:api.foo.com": "error_rate",
		"integration_down:sec":   "integration_down",
		"norule":                 "norule",
		":leading":               "",
	}
	for in, want := range cases {
		if got := ruleIDFromDedupKey(in); got != want {
			t.Errorf("ruleIDFromDedupKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBoundingCaps(t *testing.T) {
	longSummary := strings.Repeat("a", maxSummaryBytes+50)
	bs := boundedSummary(longSummary)
	if len(bs) > maxSummaryBytes {
		t.Errorf("boundedSummary len %d exceeds cap %d", len(bs), maxSummaryBytes)
	}
	if !strings.HasSuffix(bs, truncationMarker) {
		t.Error("truncated summary should end with marker")
	}

	longEvidence := Evidence(strings.Repeat("b", maxEvidenceBytes+50))
	be := boundEvidence(longEvidence)
	if len(be) > maxEvidenceBytes {
		t.Errorf("boundEvidence len %d exceeds cap %d", len(be), maxEvidenceBytes)
	}

	// Short strings are unchanged.
	if got := boundedSummary("hi"); got != "hi" {
		t.Errorf("short summary changed: %q", got)
	}
}

func TestBoundStringRuneSafe(t *testing.T) {
	// Multi-byte runes right at the boundary must not be split into invalid
	// UTF-8. Use 3-byte runes and a cap that would land mid-rune on a naive cut.
	s := strings.Repeat("世", 100) // 300 bytes
	out := boundString(s, 10)
	if len(out) > 10 {
		t.Errorf("boundString len %d exceeds 10", len(out))
	}
	if strings.ContainsRune(out, '�') {
		t.Error("output contains replacement char (split rune)")
	}
	// Trim marker and ensure the remainder is whole runes.
	body := strings.TrimSuffix(out, truncationMarker)
	for _, r := range body {
		if r == '�' {
			t.Error("body has invalid rune")
		}
	}
}

func TestAssertEgressSafe(t *testing.T) {
	ok := Alert{ID: "x", Summary: "fine", Evidence: "fine"}
	if err := assertEgressSafe(ok); err != nil {
		t.Errorf("assertEgressSafe(ok) = %v, want nil", err)
	}

	bigSummary := Alert{ID: "x", Summary: strings.Repeat("a", maxSummaryBytes+1)}
	if err := assertEgressSafe(bigSummary); err == nil {
		t.Error("assertEgressSafe should reject oversized summary")
	}

	bigEvidence := Alert{ID: "x", Evidence: Evidence(strings.Repeat("a", maxEvidenceBytes+1))}
	if err := assertEgressSafe(bigEvidence); err == nil {
		t.Error("assertEgressSafe should reject oversized evidence")
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("one\ntwo\nthree"); got != "one" {
		t.Errorf("firstLine = %q, want one", got)
	}
	if got := firstLine("single"); got != "single" {
		t.Errorf("firstLine = %q, want single", got)
	}
}

func TestStatusConstants(t *testing.T) {
	// Guard the wire values; sinks and stored rows depend on them.
	if StatusFiring != "firing" || StatusResolved != "resolved" {
		t.Errorf("status wire values changed: %q %q", StatusFiring, StatusResolved)
	}
	_ = time.Now
}
