package controlplane

import (
	"context"
	"slices"
	"sort"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The rollout guard of identity require mode (W-P2-WBND-07). A worker that does
// not know `require` rejects the settings it was sent and keeps its previous
// config, which is attribute mode: it would let token-less traffic through for
// an agent the operator believes is enforced. So the control plane refuses to
// serve require for an agent while a connected worker serving it lacks
// identity/require-v1, unless an admin forces it (audited). "Connected" is the
// registry's own meaning: a heartbeat or poll within the last staleAfter (45s).
// A worker that was offline when the mode was set, or that appears later
// without the capability, is not refused (the CP cannot stop it); it is
// flagged in the fleet view and logged once per ETag (flagNoIdentityRequire,
// noteIdentityRequire).

// WorkersLackingCap returns the ids of connected (online) workers that do not
// advertise cap and serve one of agentIDs, or, when anyAgent is true, any
// worker (the identity default applies to every agent). A worker that reports
// no agent id never matches agentIDs. Sorted and capped at 100.
func (r *WorkerRegistry) WorkersLackingCap(cap string, agentIDs []string, anyAgent bool) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []string
	for id, w := range r.workers {
		if now.Sub(w.lastSeen) >= staleAfter || slices.Contains(w.caps, cap) {
			continue
		}
		if anyAgent || (w.agentID != "" && slices.Contains(agentIDs, w.agentID)) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	if len(out) > maxWorkersWithoutCap {
		out = out[:maxWorkersWithoutCap]
	}
	return out
}

// newRequire reports what in switches to require relative to live: the ids of
// the agents whose own identity mode becomes require, and whether the identity
// default does. A document that leaves an existing require setting alone
// reports nothing, so saving an unrelated field is never refused because an
// old worker connected after require was set.
func newRequire(live *config.SettingsWire, in config.SettingsWire) (agents []string, def bool) {
	liveAgent := map[string]string{}
	liveDefault := ""
	if live != nil {
		for _, a := range live.Agents {
			liveAgent[a.ID] = a.Identity
		}
		if live.Identity != nil {
			liveDefault = live.Identity.DefaultMode
		}
	}
	for _, a := range in.Agents {
		if a.Identity == config.IdentityModeRequire && liveAgent[a.ID] != config.IdentityModeRequire && !slices.Contains(agents, a.ID) {
			agents = append(agents, a.ID)
		}
	}
	def = in.Identity != nil && in.Identity.DefaultMode == config.IdentityModeRequire && liveDefault != config.IdentityModeRequire
	return agents, def
}

// requireGuard refuses a settings document that newly sets require mode while a
// connected worker serving the agent (any worker, for identity.defaultMode)
// lacks identity/require-v1: a *dashboard.WorkersLackCapabilityError naming the
// workers. ?force=true by an admin lets it through and records force and the
// worker ids on the request's admin audit row. live is the settings in force.
func (s *Server) requireGuard(ctx context.Context, live *config.SettingsWire, in config.SettingsWire) error {
	agents, def := newRequire(live, in)
	if len(agents) == 0 && !def {
		return nil
	}
	lacking := s.registry.WorkersLackingCap(config.CapIdentityRequireV1, agents, def)
	if len(lacking) == 0 {
		return nil
	}
	if !dashboard.ForceFrom(ctx) {
		return &dashboard.WorkersLackCapabilityError{Workers: lacking}
	}
	// Only an admin may force. console.auth none has no roles: its write guard
	// is the bearer token, which is admin by definition.
	if s.cfg.Console.Auth == config.ConsoleAuthOIDC {
		var role config.Role
		if p, ok := PrincipalFrom(ctx); ok {
			role = principalRole(s.cfg.Console, p)
		}
		if role < config.RoleAdmin {
			return &dashboard.RoleRequiredError{Need: config.RoleAdmin.String(), Fields: []string{"force"}}
		}
	}
	d := map[string]string{adminaudit.DetailForce: "true"}
	putList(d, adminaudit.DetailWorkersLacking, lacking)
	adminaudit.Annotate(ctx, "", d)
	s.cfg.Logger.Warn("require_mode_forced", "workers", lacking)
	return nil
}

// requireModeFor is the identity mode in force for a worker serving agentID
// under w: the agent's own override, else the identity default.
func requireModeFor(w *config.SettingsWire, agentID string) bool {
	if w == nil {
		return false
	}
	if agentID != "" {
		for _, a := range w.Agents {
			if a.ID == agentID && a.Identity != "" {
				return a.Identity == config.IdentityModeRequire
			}
		}
	}
	return w.Identity != nil && w.Identity.DefaultMode == config.IdentityModeRequire
}

// FlagNoIdentityRequire sets NoIdentityRequire on every online view whose caps
// lack identity/require-v1 while the served settings put its agent in require
// mode. Such a worker rejects the unknown mode and keeps attribute mode.
func FlagNoIdentityRequire(views []dashboard.WorkerView, served *config.SettingsWire) {
	for i := range views {
		v := &views[i]
		v.NoIdentityRequire = v.Online && !slices.Contains(v.Caps, config.CapIdentityRequireV1) && requireModeFor(served, v.AgentID)
	}
}

// servedSettings is the settings the control plane currently serves.
func (s *Server) servedSettings() *config.SettingsWire {
	wire, _, ok, _ := s.policy.snapshot()
	if !ok {
		return nil
	}
	return wire.Settings
}

// noteIdentityRequire logs worker_lacks_identity_require once per worker per
// ETag while its agent is served in require mode and its caps lack
// identity/require-v1. The line carries the proxy id and agent id only.
func (s *Server) noteIdentityRequire(proxyID, agentID string, caps []string) {
	if proxyID == "" || slices.Contains(caps, config.CapIdentityRequireV1) {
		return
	}
	wire, etag, ok, _ := s.policy.snapshot()
	if !ok || !requireModeFor(wire.Settings, agentID) {
		return
	}
	s.cf.mu.Lock()
	if s.cf.loggedRequire == nil || len(s.cf.loggedRequire) >= maxGroupPolicyLogMarks {
		s.cf.loggedRequire = make(map[string]string)
	}
	seen := s.cf.loggedRequire[proxyID] == etag
	s.cf.loggedRequire[proxyID] = etag
	s.cf.mu.Unlock()
	if seen {
		return
	}
	s.cfg.Logger.Warn("worker_lacks_identity_require", "proxy_id", proxyID, "agent_id", agentID)
}
