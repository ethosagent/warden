package proxy

import (
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/policy"
)

// deferred says what a connection-level admission left undecided. A destination
// is either NoMatch (the judge decides each request) or it matched an entry
// (static allow, or an identity-scoped entry that needs each request's
// subject), so the values are mutually exclusive.
type deferred uint8

const (
	// deferNone: the destination is statically allowed; nothing is left to
	// decide per request beyond the constraint gate.
	deferNone deferred = iota
	// deferJudge: the destination matched no rule and the judge is enabled; the
	// judge decides every request on the terminated tunnel.
	deferJudge
	// deferIdentity: the destination is reachable only for some identities
	// (a Conditional result, or an allow through a scoped entry); every request
	// is decided with its own subject. The judge is never consulted.
	deferIdentity
)

func (d deferred) String() string {
	switch d {
	case deferNone:
		return "deferNone"
	case deferJudge:
		return "deferJudge"
	case deferIdentity:
		return "deferIdentity"
	default:
		return "deferUnknown"
	}
}

// deferredFor maps a connection-level verdict to what it defers. Deny maps to
// deferNone: it never reaches the per-request stages.
func deferredFor(v policy.RequestVerdict) deferred {
	switch v.Decision {
	case policy.NoMatch:
		return deferJudge
	case policy.Conditional:
		return deferIdentity
	case policy.Allow:
		if v.Scoped {
			return deferIdentity
		}
	}
	return deferNone
}

// gateResult is the outcome of the connection-level admission gate.
type gateResult struct {
	verdict policy.RequestVerdict
	// deny is true when the connection is refused with reason.
	deny   bool
	reason denyreason.Reason
	// defers is what the admitted connection still has to decide per request.
	defers deferred
}

// admit is the ONE connection-level gate shared by the CONNECT floor and both
// transparent listeners, so the three cannot diverge. It is an exhaustive
// switch over the evaluator's decision whose default denies: a decision value
// added later fails closed here until a case is written for it.
func (p *Proxy) admit(rc policy.RequestContext) gateResult {
	v := p.cfg.Policy.EvaluateFor(rc)
	switch v.Decision {
	case policy.Allow:
		return gateResult{verdict: v, defers: deferredFor(v)}
	case policy.NoMatch:
		// NoMatch is not a deny in policy (it is judge-eligible); without a
		// judge it is the default-deny, named here at the gate.
		if p.judge() == nil {
			return gateResult{verdict: v, deny: true, reason: denyreason.PolicyNoMatch}
		}
		return gateResult{verdict: v, defers: deferJudge}
	case policy.Conditional:
		return gateResult{verdict: v, defers: deferIdentity}
	case policy.Deny:
		return gateResult{verdict: v, deny: true, reason: v.Reason}
	default:
		p.cfg.Logger.Error("unhandled policy decision", "decision", int(v.Decision), "domain", rc.Domain, "port", rc.Port)
		return gateResult{verdict: v, deny: true, reason: denyreason.PolicyNoMatch}
	}
}

// failClosedReason is the deny reason for a branch that cannot run the
// per-request stages while something is still deferred: identity_required for
// an identity deferral, no_tls (the judge path's reason) otherwise.
func failClosedReason(d deferred) denyreason.Reason {
	if d == deferIdentity {
		return denyreason.IdentityRequired
	}
	return denyreason.NoTLS
}
