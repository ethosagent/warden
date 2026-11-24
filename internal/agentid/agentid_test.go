package agentid

import (
	"errors"
	"strings"
	"testing"
)

func TestPortBindingIdentifier(t *testing.T) {
	var id Identifier = NewPortBindingIdentifier("agent")
	if got := id.Identify(8080); got != "agent:8080" {
		t.Errorf("Identify = %q, want agent:8080", got)
	}
}

func TestPortBindingIdentifier_DefaultPrefix(t *testing.T) {
	id := NewPortBindingIdentifier("")
	if got := id.Identify(9000); got != "agent:9000" {
		t.Errorf("default prefix Identify = %q, want agent:9000", got)
	}
}

func TestValidID(t *testing.T) {
	tests := []struct {
		id string
		ok bool
	}{
		{"agent:8080", true},
		{"a", true},
		{"0", true},
		{"My.Agent_1-x:2", true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 65), false},
		{"", false},
		{"!identity-scoped", false},
		{"-x", false},
		{".x", false},
		{":x", false},
		{"_x", false},
		{" a", false},
		{"a b", false},
		{"a/b", false},
		{"a\n", false},
		{"caf\u00e9", false},
	}
	for _, tc := range tests {
		err := ValidID(tc.id)
		if tc.ok && err != nil {
			t.Errorf("ValidID(%q) = %v, want nil", tc.id, err)
		}
		if !tc.ok {
			if !errors.Is(err, ErrInvalidID) {
				t.Errorf("ValidID(%q) = %v, want ErrInvalidID", tc.id, err)
			} else if len(tc.id) > 10 && strings.Contains(err.Error(), tc.id) {
				t.Errorf("error %q echoes the id", err)
			}
		}
	}
}

func TestValidID_AcceptsPortBindingIdentity(t *testing.T) {
	if err := ValidID(NewPortBindingIdentifier("").Identify(65535)); err != nil {
		t.Fatalf("port-binding identity rejected: %v", err)
	}
}
