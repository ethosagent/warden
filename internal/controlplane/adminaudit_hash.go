package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

// Admin audit state hashers. A hasher returns the keyed hash of one target's
// current state, so an audit row's before_hash and after_hash say whether and
// how the state moved. Built-in hashers cover policy, settings, integrations,
// detection and llmproviders; later features (worker tokens, block list,
// policy versions) register their own through RegisterStateHasher. A target
// with no hasher (the secret stores, whose state lives outside Warden, and
// sessions) records empty hashes.

// RegisterStateHasher sets the state hasher for target, replacing any
// earlier one. fn must return a keyed hash (stateHashJSON) and never the
// state itself. It is a no-op when admin audit is disabled. Register before
// the server takes traffic.
func (s *Server) RegisterStateHasher(target string, fn func(ctx context.Context) (string, error)) {
	if s.audit == nil {
		return
	}
	s.audit.hashersMu.Lock()
	defer s.audit.hashersMu.Unlock()
	s.audit.hashers[target] = fn
}

// stateHash runs target's hasher. A target without one hashes to "".
func (a *adminAuditor) stateHash(ctx context.Context, target string) (string, error) {
	a.hashersMu.RLock()
	fn := a.hashers[target]
	a.hashersMu.RUnlock()
	if fn == nil {
		return "", nil
	}
	return fn(ctx)
}

// stateHashJSON is the keyed hash of v's JSON encoding for target.
func (s *Server) stateHashJSON(target string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("controlplane: encode %s state: %w", target, err)
	}
	return s.audit.mac(target, b)
}

// registerBuiltinStateHashers registers the hashers for the state the control
// plane itself holds.
func (s *Server) registerBuiltinStateHashers() {
	s.RegisterStateHasher("policy", func(context.Context) (string, error) {
		w, _, _, _ := s.policy.snapshot()
		return s.stateHashJSON("policy", config.Policy{Allowlist: w.Allowlist, Denylist: w.Denylist})
	})
	s.RegisterStateHasher("settings", func(context.Context) (string, error) {
		w, _, _, _ := s.policy.snapshot()
		return s.stateHashJSON("settings", w.Settings)
	})
	s.RegisterStateHasher("llmproviders", func(context.Context) (string, error) {
		w, _, _, _ := s.policy.snapshot()
		var ps []config.LLMProviderSettings
		if w.Settings != nil {
			ps = w.Settings.LLMProviders
		}
		return s.stateHashJSON("llmproviders", ps)
	})
	s.RegisterStateHasher("detection", func(context.Context) (string, error) {
		return s.stateHashJSON("detection", s.currentDetectionConfig())
	})
	s.RegisterStateHasher("integrations", func(context.Context) (string, error) {
		block, err := s.configBlock("integrations")
		if err != nil {
			return "", err
		}
		return s.stateHashJSON("integrations", block)
	})
}

// configBlock returns the named top-level block of the served config file as
// a generic value (nil when absent). Integrations live only there: they are
// CP-local and never part of the served policy wire.
func (s *Server) configBlock(key string) (any, error) {
	raw, err := os.ReadFile(s.cfg.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("controlplane: read the served config: %w", err)
	}
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("controlplane: parse the served config: %w", err)
	}
	return root[key], nil
}
