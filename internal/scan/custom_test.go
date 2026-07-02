package scan

import "testing"

// A custom class emits a detection carrying custom.<name> as its DataClass, with
// the configured severity, and flows through the normal scan path.
func TestWithCustomClasses(t *testing.T) {
	s := NewScanner(WithCustomClasses([]CustomClass{
		{Name: "project_codename", Regex: `ACME-\d{4}`, Severity: "high"},
	}))
	dets := s.ScanResponse([]byte("meeting notes about ACME-4271 launch"))
	var found *Detection
	for i := range dets {
		for _, c := range dets[i].Classes {
			if c == DataClass("custom.project_codename") {
				found = &dets[i]
			}
		}
	}
	if found == nil {
		t.Fatalf("expected a custom.project_codename detection, got %+v", dets)
	}
	if found.Severity != "high" {
		t.Fatalf("custom severity = %q, want high", found.Severity)
	}
	if found.Category != "custom" {
		t.Fatalf("custom category = %q, want custom", found.Category)
	}
}

// An omitted severity defaults to medium; a body that does not match emits nothing.
func TestWithCustomClasses_DefaultSeverityAndNoMatch(t *testing.T) {
	s := NewScanner(WithCustomClasses([]CustomClass{
		{Name: "widget", Regex: `WIDGET-[0-9]+`},
	}))
	dets := s.ScanResponse([]byte("has WIDGET-99 inside"))
	for _, d := range dets {
		for _, c := range d.Classes {
			if c == DataClass("custom.widget") {
				if d.Severity != "medium" {
					t.Fatalf("default severity = %q, want medium", d.Severity)
				}
				return
			}
		}
	}
	t.Fatalf("expected custom.widget detection, got %+v", dets)
}

// An invalid custom regex is skipped at build (config validation rejects it
// upstream); the scanner still constructs and scans without panicking.
func TestWithCustomClasses_InvalidRegexSkipped(t *testing.T) {
	s := NewScanner(WithCustomClasses([]CustomClass{
		{Name: "broken", Regex: `([unterminated`, Severity: "low"},
	}))
	if dets := s.ScanResponse([]byte("nothing here")); len(dets) != 0 {
		t.Fatalf("invalid custom regex must yield no detections, got %+v", dets)
	}
}
