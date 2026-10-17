package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewDerivesVerdictFromFindings(t *testing.T) {
	warn := New("s", "t", []Finding{{Rule: "a", Severity: SevWarning, Message: "m", Fix: "f"}}, nil)
	if !warn.OK || !warn.Stages[0].OK {
		t.Fatalf("a warning alone must not fail: %+v", warn)
	}
	// An unset severity is an error: a finding is never silently advisory.
	bad := New("s", "t", []Finding{{Rule: "a", Message: "m", Fix: "f"}}, nil)
	if bad.OK || bad.Stages[0].OK || bad.Stages[0].Findings[0].Severity != SevError {
		t.Fatalf("unset severity must default to error: %+v", bad)
	}
}

func TestWriteIsSchemaShaped(t *testing.T) {
	var buf bytes.Buffer
	if err := New("s", "t", nil, map[string]any{"k": 1}).Write(&buf); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != SchemaID || doc["ok"] != true {
		t.Fatalf("doc = %v", doc)
	}
	stage := doc["stages"].([]any)[0].(map[string]any)
	if f, ok := stage["findings"].([]any); !ok || len(f) != 0 {
		t.Fatalf("findings must be an empty array, not null: %v", stage["findings"])
	}
}
