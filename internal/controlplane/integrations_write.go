package controlplane

// integrations_write.go adds the CONTROL-PLANE-ONLY integrations editor: persist
// an edited `integrations:` block to the served config file (preserving every
// other block byte-for-byte) and hot-reload the live alert-delivery manager over
// the SAME alert store — so adding/removing a Slack/webhook sink takes effect
// without a restart and without dropping live alerting. It mirrors WritePolicy /
// WriteSettings. Nothing here holds or surfaces a raw secret: config secret
// fields stay as ${ENV} references and are expanded only at Integration.Start.

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/integration"
)

// currentManager returns the live integrations manager from the embedded alert
// pipeline (which owns the pointer + reload swap). It is nil-safe: a control
// plane with no alert DB path (or a failed build) has no pipeline/manager, and
// callers degrade to empty.
func (s *Server) currentManager() *integration.Manager {
	if s.pipeline == nil {
		return nil
	}
	return s.pipeline.CurrentManager()
}

// integrationStatuses adapts the live manager's per-instance runtime status into
// the dashboard's value-free view. It is wired via dash.SetIntegrationsSource.
// A nil manager (never configured) yields nil → the endpoint reports no instances.
func (s *Server) integrationStatuses() []dashboard.IntegrationInstanceStatus {
	m := s.currentManager()
	if m == nil {
		return nil
	}
	statuses := m.InstanceStatuses()
	out := make([]dashboard.IntegrationInstanceStatus, 0, len(statuses))
	for _, st := range statuses {
		v := dashboard.IntegrationInstanceStatus{
			Name:   st.Name,
			Type:   st.Type,
			Status: st.Status,
			Reason: st.Reason,
			Config: st.Config,
		}
		for _, mc := range st.Match {
			v.Match = append(v.Match, config.IntegrationMatch{
				Severity: mc.Severity, Category: mc.Category, Domain: mc.Domain, Rule: mc.Rule,
			})
		}
		out = append(out, v)
	}
	return out
}

// toManagerInstances maps persisted config instances to the integration
// package's InstanceConfig for a manager rebuild (mirrors cmd's toInstanceConfigs).
func toManagerInstances(insts []config.IntegrationInstance) []integration.InstanceConfig {
	out := make([]integration.InstanceConfig, 0, len(insts))
	for _, in := range insts {
		ic := integration.InstanceConfig{Type: in.Type, Name: in.Name, Config: in.Config}
		for _, m := range in.Match {
			ic.Match = append(ic.Match, integration.MatchClause{
				Severity: m.Severity, Category: m.Category, Domain: m.Domain, Rule: m.Rule,
			})
		}
		out = append(out, ic)
	}
	return out
}

// WriteIntegrations validates and atomically persists an edited `integrations:`
// block to the served config file. Like WritePolicy/WriteSettings it round-trips
// the file through a top-level YAML map so every block it does not own (policy,
// logging, mcp, judge, secrets, audit, …) survives byte-for-byte; it replaces
// ONLY the `integrations` key. An EMPTY list DELETES the key (consistent with how
// WriteSettings removes absent blocks) rather than writing `integrations: []`.
//
// Persistence goes through atomicWriteConfig, which validates the candidate with
// the full loader (config.NewLocalYAMLProvider → validateIntegrations) before it
// can replace the good file — so an invalid edit (bad match key, duplicate name)
// is rejected there and we do not reimplement that validation. Integrations are
// CP-local (never in policyWire), so this does NOT refresh the policy watch;
// reloadIntegrations re-points the live manager instead.
func (s *Server) WriteIntegrations(instances []config.IntegrationInstance) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the block we
		// own; the loader validation in atomicWriteConfig still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}

	if len(instances) == 0 {
		delete(root, "integrations")
	} else {
		node, err := config.EncodeIntegrationsNode(instances)
		if err != nil {
			return fmt.Errorf("controlplane: encode integrations block: %w", err)
		}
		root["integrations"] = node
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	s.cfg.Logger.Info("control plane integrations updated via dashboard", "count", len(instances))
	return nil
}

// reloadIntegrations hot-swaps the live alert-delivery manager to run
// newInstances, reusing the SAME Server-owned alert store (never reopening the
// DB). It delegates to the embedded pipeline's ReloadManager — which builds a
// fresh manager, Starts it, atomically swaps the pointer under the pipeline's
// lock, then stops the OLD manager's instances WITHOUT closing the shared store.
// The Server keeps the swap logic in ONE place (the pipeline) so the tick, the
// ingest bridge, and the dashboard alerts source all re-point to the new manager.
//
// Fail-safe: if the new manager cannot be BUILT, the old one keeps running and
// the error is returned — a bad reload never kills live alerting. A per-instance
// Start failure (e.g. a slack instance whose runtime is not built) is NOT fatal:
// the manager's Start skips it and reports it as non-connected status.
func (s *Server) reloadIntegrations(newInstances []integration.InstanceConfig) error {
	if s.pipeline == nil {
		return errors.New("controlplane: integrations runtime is not available on this control plane")
	}
	return s.pipeline.ReloadManager(newInstances)
}
