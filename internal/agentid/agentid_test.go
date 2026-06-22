package agentid

import "testing"

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
