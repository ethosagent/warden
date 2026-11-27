package controlplane

import (
	"context"
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The rollout guard of per-user secrets (W-P3-PUS-08). A worker that does not
// advertise usersecrets/v1 forwards the literal placeholder instead of swapping
// it, so a mapping enabled for an agent it serves would silently not work. The
// control plane therefore refuses a save that enables the block or adds an
// agent to a mapping while a connected worker bound to that agent lacks the
// capability, with 409 workers_lack_capability naming the workers, unless an
// admin passes force=true (audited with the worker ids, exactly like
// identity require mode). "Connected" is the registry's own meaning: a heartbeat
// or poll within the last staleAfter. A worker that appears later is not
// refused (the control plane cannot stop it); it leaks nothing.

// perUserPairs returns the (agent, placeholder) pairs c serves: empty when the
// block is disabled.
func perUserPairs(c config.PerUserSecretsConfig) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	if !c.Enabled {
		return out
	}
	for _, m := range c.Mappings {
		for _, a := range m.Agents {
			if out[a] == nil {
				out[a] = map[string]bool{}
			}
			out[a][m.Placeholder] = true
		}
	}
	return out
}

// perUserGuard refuses next, the block about to be saved, when it newly serves a
// mapping to an agent (the block newly enabled, or an agent added to a mapping
// relative to live) while a connected worker bound to that agent lacks
// usersecrets/v1. A worker that reports no agent id is never affected: the
// mapping reaches it only through an agent id. See forceWorkersLack for force.
func (s *Server) perUserGuard(ctx context.Context, live, next config.PerUserSecretsConfig) error {
	have, want := perUserPairs(live), perUserPairs(next)
	lacking, total := s.registry.WorkersLackingCap(config.CapUserSecretsV1, func(agentID string) bool {
		for placeholder := range want[agentID] {
			if !have[agentID][placeholder] {
				return true
			}
		}
		return false
	})
	return s.forceWorkersLack(ctx, lacking, total, "per_user_secrets_forced", "per-user secrets (usersecrets/v1)")
}

// WritePerUserSecrets saves in as the perUserSecrets block of the served config
// and wakes the long poll, so the signed bundle carries the new mappings. The
// whole document is validated by the full loader first (placeholders against
// the static secrets included), an enabled block must pass the startup checks
// (consent.store, token service, signed bundles, registered providers), and the
// rollout guard runs on the result (see perUserGuard); a refused save changes
// nothing. The caller authorizes the request (admin): force=true on ctx is
// honoured only for an admin.
func (s *Server) WritePerUserSecrets(ctx context.Context, in config.PerUserSecretsConfig) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if in.Enabled && (s.cfg.PerUserLoad == nil || s.cfg.PerUserCheck == nil) {
		return &dashboard.InvalidPolicyError{Err: errors.New("per-user secrets are not available on this control plane")}
	}
	prov, err := config.NewLocalYAMLProvider(s.cfg.PolicyPath)
	if err != nil {
		return fmt.Errorf("controlplane: read live config: %w", err)
	}
	cur, err := prov.GetPolicy()
	if err != nil {
		return fmt.Errorf("controlplane: read live config: %w", err)
	}
	live := cur.PerUserSecrets

	root := map[string]yaml.Node{}
	if data, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		_ = yaml.Unmarshal(data, &root)
	}
	node, err := config.EncodePerUserSecretsNode(in)
	if err != nil {
		return err
	}
	root["perUserSecrets"] = node
	if err := s.atomicWriteConfigChecked(root, func(p config.Policy) error {
		next := p.PerUserSecrets
		if next.Enabled {
			if err := s.cfg.PerUserCheck(next); err != nil {
				return &dashboard.InvalidPolicyError{Err: err}
			}
		}
		return s.perUserGuard(ctx, live, next)
	}); err != nil {
		return err
	}
	s.refresh()
	s.cfg.Logger.Info("control plane per-user secrets updated", "enabled", in.Enabled, "mappings", len(in.Mappings))
	return nil
}
