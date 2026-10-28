package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

// userBlockedBody is the JSON body of every user_blocked 403. It is built from
// the declared reason, never a second literal of it.
var userBlockedBody = `{"error":"` + string(denyreason.UserBlocked) + `"}`

// claimsBlocked reports whether c names a user on the admin block list. A sub
// is an exact match; the email is lowercased here (ToLower returns its input
// unchanged, with no allocation, when there is nothing to lowercase) and matched
// against the lowercase set. Claims with neither field (no token, a token the
// verifier could not read) skip the lock entirely.
//
// The claims may be unverified (an expired or bad-signature token): a match can
// only deny, so trusting them is safe. They are never used to allow anything.
func (p *Proxy) claimsBlocked(c identity.Claims) bool {
	if c.Sub == "" && c.Email == "" {
		return false
	}
	return p.cfg.Policy.IsBlocked(c.Sub, strings.ToLower(c.Email))
}

// blockStage denies a request whose identity names a blocked user. It runs right
// after identityStage and before every policy gate, so a blocked user's request
// reaches no judge, no secret swap and no upstream. It checks every claims set
// the request carries: the connection's CONNECT identity, the resolved
// per-request identity (the same one or a header identity) and, on a
// CONNECT/header conflict, the header's claims, so a blocked user cannot hide
// behind a second token. A request with no token is not matched (attribute
// mode; require mode is P2). The blocked list is read live, so a Replace blocks
// the next request of an open keep-alive, h2 or WebSocket session.
func (p *Proxy) blockStage(s *requestScope) (endSession bool) {
	// The CONNECT claims usually equal the resolved ones: look them up once.
	connSame := s.ci.Claims.Sub == s.idClaims.Sub && s.ci.Claims.Email == s.idClaims.Email
	if !p.claimsBlocked(s.idClaims) && (connSame || !p.claimsBlocked(s.ci.Claims)) && !p.claimsBlocked(s.idHeaderClaims) {
		// Not blocked now: register the session under every identity this request
		// carried, so a later block can cut it (an anonymous request binds nothing).
		s.sess.bind(s.ci)
		s.sess.bind(connIdentity{Claims: s.idClaims, Status: s.idStatus})
		// idHeaderClaims is only ever set from a header that verified valid.
		s.sess.bind(connIdentity{Claims: s.idHeaderClaims, Status: identity.StatusValid})
		return false
	}
	p.emitDeny(s, denyreason.UserBlocked, denyExtra{LatencyMs: s.latencyMs()})
	s.out.errorJSON(http.StatusForbidden, userBlockedBody)
	return true
}

// connectBlocked is the CONNECT-time check: before the policy evaluation, any
// dial and the 200. It records the deny through the shared chokepoint (the user
// fields are stamped by recordEvent) and answers a JSON 403.
func (p *Proxy) connectBlocked(w io.Writer, ci connIdentity, domain string, port int) bool {
	if !p.claimsBlocked(ci.Claims) {
		return false
	}
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(denyreason.UserBlocked),
	})
	writeJSONResponse(w, http.StatusForbidden, userBlockedBody)
	return true
}

// writeJSONResponse writes an HTTP/1.1 response with a JSON body and
// Connection: close.
func writeJSONResponse(w io.Writer, status int, body string) {
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"application/json"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
	_ = resp.Write(w)
}
