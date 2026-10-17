package config

import (
	"fmt"
	"strings"
)

// EchoGuardConfig controls the check that stops an upstream response carrying a
// secret Warden swapped into the same request (#389). It is ON by default and
// independent of responseScan; a zero value is the default (enabled, action
// block). The fields are inverted/empty-means-default so a Policy built without
// this block keeps the guard on.
type EchoGuardConfig struct {
	// Disabled turns the guard off (echoGuard.enabled: false).
	Disabled bool
	// Action is "block" (default; "" is block) or "monitor" (record the hit as an
	// allow event with reason secret_echo but forward the response — the agent
	// then holds the secret, so this is for evaluation only).
	Action string
}

// Monitor reports whether a hit is recorded but not blocked.
func (c EchoGuardConfig) Monitor() bool { return c.Action == "monitor" }

// rawEchoGuard mirrors the on-disk `echoGuard:` block. Enabled is a pointer so an
// absent key means the default (true), distinct from an explicit false.
type rawEchoGuard struct {
	Enabled *bool  `yaml:"enabled"`
	Action  string `yaml:"action"`
}

func parseEchoGuard(r *rawEchoGuard) EchoGuardConfig {
	c := EchoGuardConfig{Action: "block"}
	if r == nil {
		return c
	}
	c.Disabled = r.Enabled != nil && !*r.Enabled
	if a := strings.ToLower(strings.TrimSpace(r.Action)); a != "" {
		c.Action = a
	}
	return c
}

func validateEchoGuard(c EchoGuardConfig) error {
	switch c.Action {
	case "", "block", "monitor":
		return nil
	}
	return fmt.Errorf("config: echoGuard.action %q is invalid; must be one of: block, monitor", c.Action)
}
