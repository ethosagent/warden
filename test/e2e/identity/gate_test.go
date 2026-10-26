//go:build e2e

package identity

import (
	"strings"
	"testing"
)

// TestStackGate proves "blocked is not passed" without Docker: with the stack
// missing, the gate returns a BLOCKED: message that requireStack turns into a
// failure, in CI and locally alike; with the stack present it returns none.
func TestStackGate(t *testing.T) {
	const why = "no docker CLI on PATH"
	if msg := stackGate(false, why); !strings.HasPrefix(msg, "BLOCKED: ") || !strings.Contains(msg, why) {
		t.Errorf("stack missing: msg = %q, want a BLOCKED: message naming %q", msg, why)
	}
	if msg := stackGate(true, why); msg != "" {
		t.Errorf("stack present: msg = %q, want none", msg)
	}
}
