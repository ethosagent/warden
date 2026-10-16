package config

import "testing"

func parseEcho(t *testing.T, block string) (EchoGuardConfig, error) {
	t.Helper()
	p, err := parse([]byte("policy:\n  allowlist:\n    - domain: api.openai.com\n" + block))
	if err != nil {
		return EchoGuardConfig{}, err
	}
	pol, _ := p.GetPolicy()
	return pol.EchoGuard, nil
}

// An omitted echoGuard block means on, block (#389: on by default).
func TestParse_EchoGuardDefaultsOn(t *testing.T) {
	c, err := parseEcho(t, "")
	if err != nil || c.Disabled || c.Monitor() || c.Action != "block" {
		t.Fatalf("default = %+v, err %v; want enabled, block", c, err)
	}
}

func TestParse_EchoGuardSwitches(t *testing.T) {
	c, err := parseEcho(t, "echoGuard:\n  enabled: false\n")
	if err != nil || !c.Disabled {
		t.Fatalf("enabled:false = %+v, %v", c, err)
	}
	c, err = parseEcho(t, "echoGuard:\n  action: Monitor\n")
	if err != nil || c.Disabled || !c.Monitor() {
		t.Fatalf("action:monitor = %+v, %v", c, err)
	}
	if _, err = parseEcho(t, "echoGuard:\n  action: allow\n"); err == nil {
		t.Fatal("an unknown action must be rejected")
	}
}
