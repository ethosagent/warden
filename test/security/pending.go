package security

// Pending lists every enum value the suite must test and no case covers yet,
// with the ticket that will add the case. TestEnumCompleteness fails when:
//
//   - an identity.Reason, bundle.Reason, token-service denial reason or
//     worker-facing CP route has neither a registered Case.Covers entry nor a
//     line here, so a new reason or route cannot ship untested;
//   - a line here names a value that no longer exists, or one a case now
//     covers (the ticket that adds the case removes its lines);
//   - a line names a ticket outside the suite.
//
// The feature is done when this list is empty.
type Pending struct {
	// Item is a Cover* string (CoverIdentity, CoverBundle, CoverToken,
	// CoverRoute).
	Item string
	// Ticket is the roadmap key of the ticket that adds the case.
	Ticket string
}

// Ticket keys of the suite.
const (
	TicketForgery = "W-P2-SECT-02" // token forgery, confusion and replay
	TicketBinding = "W-P2-SECT-03" // binding, cross-agent, issued-token lifetime
	TicketCerts   = "W-P2-SECT-04" // worker cert and signed bundle attacks
	TicketRoutes  = "W-P2-SECT-06" // CP route boundaries and enrollment
	TicketDegrade = "W-P2-SECT-07" // degraded and restart modes
)

func pend(ticket string, items ...string) []Pending {
	out := make([]Pending, 0, len(items))
	for _, it := range items {
		out = append(out, Pending{Item: it, Ticket: ticket})
	}
	return out
}

func joinPending(parts ...[]Pending) []Pending {
	var out []Pending
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// pending is the list. Keep each ticket's block together.
var pending = joinPending(
	// W-P2-SECT-03: binding, cross-agent, issued-token lifetime.
	pend(TicketBinding,
		CoverToken("agent_disabled"), CoverToken("user_blocked"), CoverToken("group_not_allowed"),
		CoverToken("scope_not_allowed"), CoverToken("session_revoked"),
		// Identity reasons added by W-P2-WBND-02 (#112).
		CoverIdentity("agent_unregistered"), CoverIdentity("agent_disabled"),
		CoverIdentity("agent_mismatch"), CoverIdentity("cnf_mismatch"),
	),
	// W-P2-SECT-06: CP route boundaries and enrollment.
	pend(TicketRoutes,
		CoverRoute("/control/enroll"), CoverRoute("/control/renew"),
	),
	// W-P2-SECT-07: degraded and restart modes.
	pend(TicketDegrade,
		CoverIdentity("jwks_unavailable"),
		CoverToken("agent_store_unavailable"), CoverToken("replay_store_unavailable"),
		CoverToken("verifier_misconfigured"), CoverToken("idp_unavailable"),
		CoverToken("block_store_unavailable"),
		CoverToken("session_store_unavailable"), CoverToken("event_store_unavailable"),
	),
)
