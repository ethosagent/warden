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
// The feature is done when this list is empty, which it now is: the test fails
// on any entry.
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

// pending is the list of values still waiting for a case. It is empty: every
// ticket of the suite has landed, and TestEnumCompleteness fails on any entry,
// so a new reason or route ships with a case (or an exclusion below), never with
// a promise.
var pending []Pending

// Exclusion is an enum value the black-box suite cannot drive and says why: the
// ticket that closes it names the unit tests that cover it. Unlike a Pending
// entry it is final: the suite is complete with it.
type Exclusion struct {
	Item   string
	Reason string
}

// exclusions lists the values no case covers by design. Every entry needs a
// reason that names its covering tests.
var exclusions = []Exclusion{{
	Item: CoverIdentity("agent_disabled"),
	Reason: "a disabled agent is refused by the agent kill switch (403 agent_disabled) before identity runs, " +
		"and the gate flips ahead of the snapshot install in the same bundle apply (internal/worker/agentgate.go " +
		"gatedEvaluator), so the binding's own agent_disabled reason is defence in depth that only a race " +
		"between the two reaches; driving it needs a seam inside the applier. Covered by " +
		"internal/proxy/identity_binding_test.go and internal/worker/binding_longpoll_test.go",
}, {
	Item: CoverToken("block_store_unavailable"),
	Reason: "the block list is held in memory once loaded and keeps its previous contents when a reload fails, " +
		"so the only way for the token endpoint to see it unavailable is a control plane that serves before " +
		"its first load, and the control plane does not: a state database whose blocked_users table cannot " +
		"be read stops the versioned policy store from loading its head and the control plane refuses to " +
		"start (observed driving this ticket), so no exchange can reach the refusal end to end. The refusal " +
		"(503 temporarily_unavailable, no token) is covered by internal/tokensvc/service_test.go " +
		"(check error fails closed) and the not-ready checker by internal/controlplane/blockchecker_test.go " +
		"and internal/controlplane/blockedusers_test.go",
}, {
	Item: CoverToken("verifier_misconfigured"),
	Reason: "the reason answers an assertion verifier or subject resolver that was assembled without its " +
		"agent registry, replay store, issuer, clock or IdP verifier. The control plane's assembly " +
		"(newTokenService) either builds all of them or does not enable the endpoint, so a running " +
		"control plane cannot reach it, and nothing a test may change after startup removes one. Covered by " +
		"internal/tokensvc/assertion_test.go (a misconfigured verifier fails closed) and " +
		"internal/tokensvc/service_test.go",
}}
