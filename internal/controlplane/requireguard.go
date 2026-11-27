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
	if !dashboard.ForceFrom(ctx) {
		return &dashboard.WorkersLackCapabilityError{Workers: lacking}
	}
	if err := s.forceByAdmin(ctx); err != nil {
		return err
	}
	annotateForced(ctx, "", lacking, total)
	s.cfg.Logger.Warn("require_mode_forced", "workers", lacking)
	return nil
}

// forceByAdmin refuses a force=true request whose principal is below admin
// (403 role_required naming force). console.auth none has no roles: its write
// guard is the bearer token, which is admin by definition.
func (s *Server) forceByAdmin(ctx context.Context) error {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		return nil
	}
	var role config.Role
	if p, ok := PrincipalFrom(ctx); ok {
		role = principalRole(s.cfg.Console, p)
	}
	if role < config.RoleAdmin {
		return &dashboard.RoleRequiredError{Need: config.RoleAdmin.String(), Fields: []string{"force"}}
	}
	return nil
}

// annotateForced records a forced capability guard on the request's admin
// audit row: force, the capability when named, and the lacking worker ids
// with their uncapped count.
func annotateForced(ctx context.Context, capability string, lacking []string, total int) {
	d := map[string]string{adminaudit.DetailForce: "true"}
	if capability != "" {
		d[adminaudit.DetailCapability] = capability
	}
	putList(d, adminaudit.DetailWorkersLacking, lacking)
	d[adminaudit.DetailWorkersLacking+adminaudit.DetailCountSuffix] = strconv.Itoa(total)
	adminaudit.Annotate(ctx, "", d)
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
