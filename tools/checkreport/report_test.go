package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFinalizeScrubsEveryStringAndCaps(t *testing.T) {
	canary := "AKIAABCDEFGHIJKLMNOP"
	r := &Report{Stages: []Stage{{
		Name: "test", Tool: "go", Findings: []Finding{{
			Rule: "test/failed", Severity: "error", Message: "leaked " + canary,
			Fix: "fix " + canary, File: "x_test.go", Output: canary + strings.Repeat("x", 10000),
		}},
	}}}
	r.Finalize(NewScrubber(nil))
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), canary) {
		t.Fatalf("canary in report: %s", b)
	}
	if len(r.Stages[0].Findings[0].Output) > outputCap+len(truncMarker) {
		t.Errorf("output not capped: %d", len(r.Stages[0].Findings[0].Output))
	}
	if r.OK || r.Stages[0].OK {
		t.Error("a stage with error findings cannot be ok")
	}
}

func TestFinalizeOKAndNilFindingsMarshalAsArray(t *testing.T) {
	r := &Report{Stages: []Stage{{Name: "format", Tool: "gofmt", OK: true}}}
	r.Finalize(NewScrubber(nil))
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"findings":[]`) || !strings.Contains(string(b), `"schema":"warden.check.v1"`) || !r.OK {
		t.Errorf("unexpected: %s", b)
	}
}

func TestCrashedStageBecomesFinding(t *testing.T) {
	st := runStage("lint", "golangci-lint@v1", func() Stage { panic("boom") })
	if st.OK || len(st.Findings) != 1 || st.Findings[0].Rule != "stage/crashed" || st.Findings[0].Fix == "" {
		t.Fatalf("got %+v", st)
	}
}

func TestFinalizeScrubsMetrics(t *testing.T) {
	canary := "AKIAABCDEFGHIJKLMNOP"
	r := &Report{Stages: []Stage{{Name: "coverage", Tool: "go", Metrics: map[string]any{
		"note": "leak " + canary, "n": 1.5, "list": []string{canary}, "pk": []pkgCoverage{{Package: canary, Percent: 1}},
	}}}}
	r.Finalize(NewScrubber(nil))
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), canary) {
		t.Fatalf("canary in metrics: %s", b)
	}
	if !strings.Contains(string(b), `"n":1.5`) {
		t.Errorf("non-string metric lost: %s", b)
	}
}
