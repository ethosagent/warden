package controlplane

import (
	"context"

	"github.com/ethosagent/warden/internal/config"
)

// The rollout guard of per-user cost caps (W-P3-PUL-08, the W-P2-WBND-07
// pattern). A worker without usercost/v1 does not enforce dailyCostUSD or
// costBlockedUsers: it fails open on cost caps. So a policy save that adds a
// rule with dailyCostUSD, or sets dailyCostUSD on a rule that had none, is
// refused while any connected worker lacks the capability, unless an admin
// forces it (audited). Rate-limit-only rules and a changed cap value need no
// check. Every versioned writer reaches it (dashboard policy write, rollback,
// approvals apply through publish), and so does the file-mode policy write.

// userLimitCaps maps each rule of w (userLimits by name, defaultUserLimit and
// anonymousLimit under their reserved names) to its dailyCostUSD.
func userLimitCaps(userLimits []config.UserLimit, def, anon *config.UserLimit) map[string]float64 {
	m := make(map[string]float64, len(userLimits)+2)
	for _, l := range userLimits {
		m[l.Name] = l.DailyCostUSD
	}
	if def != nil {
		m[config.UserLimitNameDefault] = def.DailyCostUSD
	}
	if anon != nil {
		m[config.UserLimitNameAnonymous] = anon.DailyCostUSD
	}
	return m
}

// wireCostCaps is userLimitCaps of a policy doc.
func wireCostCaps(w policyWire) map[string]float64 {
	return userLimitCaps(w.UserLimits, w.DefaultUserLimit, w.AnonymousLimit)
}

// addsCostCap reports whether next has a rule with dailyCostUSD whose
// same-named rule in prev had none (or did not exist).
func addsCostCap(prev, next map[string]float64) bool {
	for name, c := range next {
		if c > 0 && prev[name] <= 0 {
			return true
		}
	}
	return false
}

// costCapGuard refuses next when it adds a dailyCostUSD cap over prev while a
// connected worker lacks usercost/v1: a *dashboard.WorkersLackCapabilityError
// naming the workers and the capability (409). ?force=true by an admin lets it
// through and records force, the capability and the worker ids on the
// request's admin audit row.
func (s *Server) costCapGuard(ctx context.Context, prev, next map[string]float64) error {
	if !addsCostCap(prev, next) {
		return nil
	}
	s.warnUserCostOff(next)
	lacking, total := s.registry.WorkersLackingCap(config.CapUserCostV1, func(string) bool { return true })
	if len(lacking) == 0 {
		return nil
	}
	return s.forceOrRefuse(ctx, config.CapUserCostV1, lacking, total, "cost_cap_forced")
}

// rolloutGuards runs every capability rollout guard of a policy write in one
// fixed order (identity require mode, userlimits/v1, usercost/v1), so every
// writer names the same first 409. live and next are the docs before and after;
// a nil next.Settings skips the require guard (a writer that does not carry
// settings).
func (s *Server) rolloutGuards(ctx context.Context, live, next policyWire) error {
	if next.Settings != nil {
		if err := s.requireGuard(ctx, live.Settings, *next.Settings); err != nil {
			return err
		}
	}
	if err := s.userLimitsGuard(ctx, live, next); err != nil {
		return err
	}
	return s.costCapGuard(ctx, wireCostCaps(live), wireCostCaps(next))
}
