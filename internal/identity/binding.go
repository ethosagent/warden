package identity

// BindingCheck decides whether a verified token may act for the worker bound
// to agentID, against snap (W-P2-WBND-02). It gives agent match and key
// liveness, not proof of possession: a token is a bearer credential, and
// cnf.jkt only says the key it was minted for is still registered.
//
// Only a Warden token can be bound. Any other token type, including an IdP
// token, is ReasonUnboundToken; the proxy calls BindingCheck for Warden tokens
// only today, and require mode (W-P2-WBND-03) calls it for every token so an
// IdP token never satisfies it.
//
// For a Warden token the checks run in a fixed order and the first failure is
// the reason: the bound agent is not in the snapshot (agent_unregistered), it
// is disabled (agent_disabled), act.sub is another agent (agent_mismatch),
// cnf.jkt is not one of its registered key thumbprints (cnf_mismatch). A nil
// snapshot fails closed as agent_unregistered.
//
// The result is a pure function of the arguments and is never cached: callers
// must read snap from the verifier on every use, so a bundle that removes a key
// or disables the agent takes effect on the next request. It does not allocate.
func BindingCheck(snap *WardenSnapshot, agentID string, c Claims) (Reason, bool) {
	if c.TokenType != TokenWarden {
		return ReasonUnboundToken, false
	}
	a, ok := snap.Agent(agentID)
	switch {
	case agentID == "" || !ok:
		return ReasonAgentUnregistered, false
	case !a.Active:
		return ReasonAgentDisabled, false
	case c.Act != agentID:
		return ReasonAgentMismatch, false
	}
	if _, ok := a.JKT[c.CnfJKT]; !ok || c.CnfJKT == "" {
		return ReasonCnfMismatch, false
	}
	return "", true
}

// Snapshot returns the Warden snapshot the dispatcher verifies against, so the
// binding check reads the same bundle the token was verified with. nil before
// the first snapshot.
func (m *MultiVerifier) Snapshot() *WardenSnapshot { return m.warden.Snapshot() }
