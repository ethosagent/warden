package controlplane

import (
	"context"
	"slices"
	"sort"
	"strconv"

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
// advertise cap and for which affected(agentID) is true, sorted, with the id
// list capped at 100, and the uncapped total. affected gets the agent id the
// worker reports ("" when it reports none).
func (r *WorkerRegistry) WorkersLackingCap(cap string, affected func(agentID string) bool) (ids []string, total int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for id, w := range r.workers {
		if now.Sub(w.lastSeen) >= staleAfter || slices.Contains(w.caps, cap) || !affected(w.agentID) {
			continue
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	total = len(ids)
	if len(ids) > maxWorkersWithoutCap {
		ids = ids[:maxWorkersWithoutCap]
	}
	return ids, total
}

// requireGuard refuses a settings document that newly sets require mode while a
// connected worker serving the agent (any worker, for identity.defaultMode)
// lacks identity/require-v1: a *dashboard.WorkersLackCapabilityError naming the
// workers. ?force=true by an admin lets it through and records force and the
// worker ids on the request's admin audit row. live is the settings in force.
func (s *Server) requireGuard(ctx context.Context, live *config.SettingsWire, in config.SettingsWire) error {
	// A worker is affected when its effective mode (its agent's own identity,
	// else the default) becomes require: clearing an override under a require
	// default counts, a new default does not reach an agent with an override.
	lacking, total := s.registry.WorkersLackingCap(config.CapIdentityRequireV1, func(agentID string) bool {
		return requireModeFor(&in, agentID) && !requireModeFor(live, agentID)
	})
	if len(lacking) == 0 {
		return nil
	}
	// The require 409 body names no capability (it predates the field).
	return s.forceOrRefuse(ctx, "", lacking, total, "require_mode_forced")
}

// userLimitsGuard is the rollout guard of per-user rate limits (W-P3-PUL-09).
// A worker without userlimits/v1 refuses a whole policy wire that carries a
// limit rule and freezes on its last-known-good policy (no further allow,
// deny or block-list updates), so a write that introduces a rule with a
// rateLimit (live has none) is refused with 409 workers_lack_capability,
// capability userlimits/v1, while any connected worker lacks the cap, unless
// an admin forces it (audited). live and next are the docs before and after.
func (s *Server) userLimitsGuard(ctx context.Context, live, next policyWire) error {
	if !hasRateLimitRule(next) || hasRateLimitRule(live) {
		return nil
	}
	lacking, total := s.registry.WorkersLackingCap(config.CapUserLimitsV1, func(string) bool { return true })
	if len(lacking) == 0 {
		return nil
	}
	return s.forceOrRefuse(ctx, config.CapUserLimitsV1, lacking, total, "user_limits_forced")
}

// hasRateLimitRule reports whether w carries a per-user limit rule with a
// rateLimit.
func hasRateLimitRule(w policyWire) bool {
	for _, l := range w.UserLimits {
		if l.RateLimit != "" {
			return true
		}
	}
	return (w.DefaultUserLimit != nil && w.DefaultUserLimit.RateLimit != "") ||
		(w.AnonymousLimit != nil && w.AnonymousLimit.RateLimit != "")
}

// forceOrRefuse is the shared end of a capability rollout guard with lacking
// workers: without force=true a *dashboard.WorkersLackCapabilityError (naming
// capability, "" for the require guard); with it, an admin's write goes
// through and the admin audit row records force and the worker ids.
func (s *Server) forceOrRefuse(ctx context.Context, capability string, lacking []string, total int, logMsg string) error {
	if !dashboard.ForceFrom(ctx) {
		return &dashboard.WorkersLackCapabilityError{Workers: lacking, Capability: capability}
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
	d[adminaudit.DetailWorkersLacking+adminaudit.DetailCountSuffix] = strconv.Itoa(total)
	adminaudit.Annotate(ctx, "", d)
	s.cfg.Logger.Warn(logMsg, "workers", lacking)
	return nil
}

// requireModeFor reports whether the identity mode in force for a worker
// serving agentID under w is require, resolved as the worker resolves it
// (config.EffectiveIdentityMode): the agent's own override, else the default.
func requireModeFor(w *config.SettingsWire, agentID string) bool {
	if w == nil {
		return false
	}
	var id config.IdentitySettings
	if w.Identity != nil {
		id = *w.Identity
	}
	mode, _ := config.EffectiveIdentityMode(agentID, config.AgentsFromSettings(w.Agents), id)
	return mode == config.IdentityModeRequire
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
