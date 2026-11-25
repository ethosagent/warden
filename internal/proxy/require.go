package proxy

import (
	"net"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// Identity require mode (W-P2-WBND-03, docs/identity-contract.md). It is
// challenge mode without the sign-in: a CONNECT must carry a valid Warden token
// bound to this worker's agent (verified and bound by verifyToken, which also
// turns every IdP token into unbound_token), and a request of a terminated
// tunnel must resolve to a valid identity again. Everything else is refused
// before the block list, the policy and any dial. Nothing here ever writes a 401
// or WWW-Authenticate: after TLS termination a 401 looks like an upstream
// challenge and starts credential or OAuth discovery in MCP clients.

// requireReason is the bounded `reason` of the 407: the verifier's reason when
// there is one (unbound_token, agent_unregistered, jwks_unavailable,
// bad_signature, ...), else the identity status (none, expired, invalid,
// unverified). Never token text or a library error.
func requireReason(ci connIdentity) string {
	if ci.Reason != "" {
		return string(ci.Reason)
	}
	return challengeReason(ci.status())
}

// requireConnect is the require gate on a CONNECT. It runs right after the
// connection identity is resolved and BEFORE the block-list check, policy
// evaluation and any dial. A connection whose identity is not a valid, bound
// Warden token gets the 407 (Proxy-Authenticate: Basic realm="warden",
// Connection: close, body {"error":"identity_required","reason":...}) and one
// deny event with reason identity_required; it returns true and the caller
// returns. It fails closed: before the first verified bundle, with an empty key
// set or with an unregistered agent no token verifies, so the reason is
// jwks_unavailable or agent_unregistered. In every other mode it does nothing.
func (p *Proxy) requireConnect(conn net.Conn, ci connIdentity, domain string, port int) bool {
	h := p.identity()
	if h == nil || h.mode != IdentityModeRequire {
		return false
	}
	if ci.status() == identity.StatusValid && ci.Claims.TokenType == identity.TokenWarden {
		return false
	}
	if ci.status() == identity.StatusValid {
		// A valid identity that is not a Warden token cannot have come through
		// the binding check; refuse it as an IdP token rather than admit it.
		ci = connIdentity{Claims: ci.Claims, Status: identity.StatusInvalid, Reason: identity.ReasonUnboundToken}
	}
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(denyreason.IdentityRequired),
	})
	writeChallenge(conn, challengeBody{Error: string(denyreason.IdentityRequired), Reason: requireReason(ci)})
	return true
}

// requireTerminated enforces require mode on a request of a terminated tunnel
// (h1, h2 stream, WebSocket upgrade, MCP over HTTP; all run identityStage): the
// request must resolve to a valid identity. Past the CONNECT token's exp plus
// skew it is identity_expired; a second subject or agent in X-Warden-Identity is
// identity_conflict; anything else that is not valid (a binding that no longer
// holds, a request with no CONNECT identity on a transparent leg) is
// identity_required. Each answers a JSON 403 with Connection: close and ends the
// request. It reports whether the request ended.
func (p *Proxy) requireTerminated(s *requestScope) bool {
	var reason denyreason.Reason
	var body string
	switch s.idStatus {
	case identity.StatusValid:
		return false
	case identity.StatusExpired:
		reason, body = denyreason.IdentityExpired, identityExpiredBody
	case identity.StatusConflict:
		reason, body = denyreason.IdentityConflict, identityConflictBody
	default:
		reason, body = denyreason.IdentityRequired, identityRequiredBody
	}
	p.emitDeny(s, reason, denyExtra{LatencyMs: s.latencyMs()})
	s.out.errorJSON(http.StatusForbidden, body)
	return true
}

// requireHeaderConflicts reports whether an X-Warden-Identity header presented
// next to a live CONNECT identity names a different subject or agent. The header
// result need not be valid: a Warden token for another agent fails binding
// (agent_mismatch) yet its claims still say whose it is. A header with no
// parseable subject proves nothing and is not a conflict.
func requireHeaderConflicts(hr idResult, conn identity.Claims) bool {
	if hr.claims.Sub == "" {
		return false
	}
	return hr.claims.Sub != conn.Sub || hr.claims.Act != conn.Act
}
