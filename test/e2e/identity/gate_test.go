//go:build e2e

package identity

import (
	"strings"
	"testing"
)

// TestStackGate proves "blocked is not passed" without Docker: with the stack
// missing, CI=true fails with a BLOCKED: message and a local run skips with a
// loud one; with the stack present neither happens.
func TestStackGate(t *testing.T) {
	const why = "no docker CLI on PATH"
	cases := []struct {
		name       string
		ci         bool
		available  bool
		wantFail   bool
		wantPrefix string // "" = no message
	}{
		{"CI, stack missing: fail", true, false, true, "BLOCKED: "},
		{"local, stack missing: loud skip", false, false, false, "BLOCKED (skipped, not passed): "},
		{"CI, stack present: neither", true, true, false, ""},
		{"local, stack present: neither", false, true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fail, msg := stackGate(c.ci, c.available, why)
			if fail != c.wantFail {
				t.Errorf("fail = %v, want %v (msg %q)", fail, c.wantFail, msg)
			}
			if c.wantPrefix == "" {
				if msg != "" {
					t.Errorf("msg = %q, want none", msg)
				}
				return
			}
			if !strings.HasPrefix(msg, c.wantPrefix) {
				t.Errorf("msg = %q, want prefix %q", msg, c.wantPrefix)
			}
			if !strings.Contains(msg, why) {
				t.Errorf("msg = %q does not say why (%q)", msg, why)
			}
		})
	}
	// The two prefixes must not overlap: "BLOCKED:" never matches the skip text.
	_, skipMsg := stackGate(false, false, why)
	if strings.HasPrefix(skipMsg, "BLOCKED:") {
		t.Errorf("skip message %q starts with the failure prefix", skipMsg)
	}
}
