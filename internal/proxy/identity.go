package proxy

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
)

// The identity header names and the CONNECT Basic username are a contract with
// the agent side (the identity client env renderer and the contract drift
// test pin their values). hopheaders.go strips the same names.
const (
	// IdentityHeader carries "Bearer <user token>" on HTTP that Warden terminates.
	IdentityHeader = "X-Warden-Identity"
	// ProxyAuthUsername is the Basic username on CONNECT's Proxy-Authorization;
	// the password is the token. "Bearer <token>" is accepted too.
	ProxyAuthUsername = "session"
)

const (
	proxyAuthorizationHeader = "Proxy-Authorization"
	// identityVerifyTimeout bounds one Verify call on the request path. A cached
	// token returns in microseconds; the bound only matters when the verifier
	// has to fetch keys, and it then fails open to status unverified, never to
	// a hang (HOT-1, HOT-8).
	identityVerifyTimeout = 2 * time.Second
)

// IdentityMode is an agent's identity mode. Only off and attribute exist in
// P1; any other value is treated as off, so an unknown mode never verifies.
type IdentityMode string

const (
	IdentityModeOff       IdentityMode = "off"
	IdentityModeAttribute IdentityMode = "attribute"
)

// IdentityConfig seeds the identity holder from proxy.Config. The zero value
// is mode off.
type IdentityConfig struct {
	Verifier identity.Verifier
	Mode     IdentityMode
}

// identityHolder is the immutable value behind Proxy.identityP. It exists only
// in attribute mode: a nil pointer means off.
type identityHolder struct {
	v identity.Verifier
	// skew is the verifier's exp tolerance, used to re-check a CONNECT
	// identity's expiry on each later request. Verifiers expose it through
	// ClockSkew(); one that does not gets the default.
	skew time.Duration
}

func newIdentityHolder(v identity.Verifier, mode IdentityMode) *identityHolder {
	if v == nil || mode != IdentityModeAttribute {
		return nil
	}
	skew := identity.DefaultClockSkew
	if sk, ok := v.(interface{ ClockSkew() time.Duration }); ok {
		skew = sk.ClockSkew()
	}
	return &identityHolder{v: v, skew: skew}
}

// SetIdentity atomically swaps the identity verifier and mode. A nil verifier
// or any mode but attribute turns identity off. It is race-free against the
// hot path; connections already open keep the identity they resolved at CONNECT.
// The mode is the agent's resolved mode, decided by the caller.
func (p *Proxy) SetIdentity(v identity.Verifier, mode IdentityMode) {
	p.identityP.Store(newIdentityHolder(v, mode))
	p.warnIdentityCoverage()
}

// warnIdentityCoverage logs, once each, the two places attribute mode cannot
// see a token: raw tunnels (no CA) and a transparent-only worker (no CONNECT).
func (p *Proxy) warnIdentityCoverage() {
	if p.identityP.Load() == nil {
		return
	}
	if p.caCert == nil {
		p.warnNoCA.Do(func() {
			p.cfg.Logger.Warn("identity attribute mode without a CA: only the CONNECT Proxy-Authorization identity is available; X-Warden-Identity cannot be read from unterminated tunnels")
		})
	}
	if p.cfg.Mode == config.ProxyModeTransparent {
		p.warnTransparentOnly.Do(func() {
			p.cfg.Logger.Warn("identity attribute mode on a transparent-only worker: there is no CONNECT, so only X-Warden-Identity on terminated traffic can attribute")
		})
	}
}

// connIdentity is the identity resolved once at CONNECT and carried by the
// connection. The zero value is status none (transparent listeners, pre-CONNECT
// failures). Claims keeps the unverified sub and email that Verify returns for
// expired and invalid tokens, for the block-list deny check only; they never
// become a Subject (identity.SubjectFrom yields one only for status valid).
type connIdentity struct {
	Claims identity.Claims
	Status identity.Status
	Reason identity.Reason
	// Expiry is the token's exp, re-checked (plus the verifier's skew) on every
	// request of the connection.
	Expiry time.Time
}

// status reads Status with the zero value meaning none.
func (c connIdentity) status() identity.Status {
	if c.Status == "" {
		return identity.StatusNone
	}
	return c.Status
}

// idResult is one request's resolved identity.
type idResult struct {
	claims identity.Claims
	status identity.Status
	reason identity.Reason
}

// resolveConnIdentity turns the Proxy-Authorization lines of a CONNECT into a
// connIdentity: lines is how many were present and value the first one. In
// mode off a token is only noted (status off), never parsed or verified.
func (p *Proxy) resolveConnIdentity(lines int, value string) connIdentity {
	if lines == 0 {
		return connIdentity{Status: identity.StatusNone}
	}
	h := p.identityP.Load()
	if h == nil {
		return connIdentity{Status: identity.StatusOff}
	}
	if lines > 1 {
		return p.malformedConn()
	}
	tok, ok := parseProxyAuthorization(value)
	if !ok {
		return p.malformedConn()
	}
	r := p.verifyToken(h, tok)
	return connIdentity{Claims: r.claims, Status: r.status, Reason: r.reason, Expiry: r.claims.Expiry}
}

func (p *Proxy) malformedConn() connIdentity {
	r := p.malformed()
	return connIdentity{Status: r.status, Reason: r.reason}
}

// malformed is the result for a token that is not in an accepted form: it is
// never sent to the verifier.
func (p *Proxy) malformed() idResult {
	p.cfg.Metrics.RecordIdentityVerify(string(identity.StatusInvalid), string(identity.ReasonMalformed))
	return idResult{status: identity.StatusInvalid, reason: identity.ReasonMalformed}
}

// verifyToken runs one bounded Verify and counts it. The raw token goes to the
// verifier and nowhere else.
func (p *Proxy) verifyToken(h *identityHolder, tok string) idResult {
	ctx, cancel := context.WithTimeout(context.Background(), identityVerifyTimeout)
	c, st, r := h.v.Verify(ctx, tok)
	cancel()
	p.recordIdentity(st, r)
	return idResult{claims: c, status: st, reason: r}
}

func (p *Proxy) recordIdentity(st identity.Status, r identity.Reason) {
	reason := string(r)
	if reason == "" {
		reason = "none"
	}
	p.cfg.Metrics.RecordIdentityVerify(string(st), reason)
}

// parseProxyAuthorization extracts the token from a CONNECT Proxy-Authorization
// value: Basic with username "session" (the password is the token), or Bearer.
// Any other form is malformed.
func parseProxyAuthorization(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if rest, ok := cutScheme(v, "basic"); ok {
		dec, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return "", false
		}
		user, tok, found := strings.Cut(string(dec), ":")
		if !found || user != ProxyAuthUsername || tok == "" {
			return "", false
		}
		return tok, true
	}
	return bearerToken(v)
}

// bearerToken extracts the token from "Bearer <token>".
func bearerToken(v string) (string, bool) {
	rest, ok := cutScheme(strings.TrimSpace(v), "bearer")
	if !ok || rest == "" || strings.ContainsAny(rest, " \t") {
		return "", false
	}
	return rest, true
}

// cutScheme returns what follows "<scheme> " (scheme matched case-insensitively),
// with surrounding space trimmed.
func cutScheme(v, scheme string) (string, bool) {
	if len(v) <= len(scheme) || !strings.EqualFold(v[:len(scheme)], scheme) || v[len(scheme)] != ' ' {
		return "", false
	}
	return strings.TrimSpace(v[len(scheme)+1:]), true
}

// captureIdentityHeader copies the raw X-Warden-Identity value onto the scope.
// It MUST run before stripHopHeaders, which deletes the header: an identity
// read after the strip would always be empty. Only the first value and the
// count are kept; a count above one is malformed in identityStage.
func (p *Proxy) captureIdentityHeader(s *requestScope) {
	if vals := s.req.Header[IdentityHeader]; len(vals) > 0 {
		s.rawIdentity, s.rawIdentityN = vals[0], len(vals)
	}
}

// identityStage resolves who made this request and sets s.subject. It never
// ends the request: in attribute mode identity is recorded, not enforced
// (a 403 identity_conflict is reserved for require mode in P2). The raw header
// value is dropped here, so no later stage (judge, DLP, MCP) can see it.
//
// Rules, in order:
//   - mode off: a token (CONNECT or header) gives status off, with no Verify;
//   - a valid CONNECT identity is re-checked against its exp plus the verifier's
//     skew on every request and becomes expired once that passes;
//   - the header is used only when CONNECT carried no token (none or off);
//   - a valid CONNECT identity plus a valid header with a different sub gives
//     conflict and no subject;
//   - otherwise the CONNECT result stands (a failed CONNECT token is not
//     overridden by a header).
//
// Only status valid yields a Subject.
func (p *Proxy) identityStage(s *requestScope) (endSession bool) {
	raw, n := s.rawIdentity, s.rawIdentityN
	s.rawIdentity = ""
	ci := s.ci
	cs := ci.status()

	h := p.identityP.Load()
	if h == nil {
		if n > 0 || (cs != identity.StatusNone) {
			s.idStatus = identity.StatusOff
		} else {
			s.idStatus = identity.StatusNone
		}
		return false
	}

	start := time.Now()
	var r idResult
	connLive := cs == identity.StatusValid
	if connLive && !p.clock().Before(ci.Expiry.Add(h.skew)) {
		// Past exp plus skew (or no exp at all, which a valid token always has:
		// fail closed). The connection's identity is spent.
		connLive, cs = false, identity.StatusExpired
		p.recordIdentity(identity.StatusExpired, "")
	}
	switch {
	case cs == identity.StatusNone || cs == identity.StatusOff:
		switch {
		case n == 0:
			r = idResult{status: identity.StatusNone}
			p.recordIdentity(identity.StatusNone, "")
		case n > 1:
			r = p.malformed()
		default:
			tok, ok := bearerToken(raw)
			if !ok {
				r = p.malformed()
			} else {
				r = p.verifyToken(h, tok)
			}
		}
	case connLive:
		r = idResult{claims: ci.Claims, status: identity.StatusValid}
		if n > 0 {
			if hr := p.headerResult(h, raw, n); hr.status == identity.StatusValid && hr.claims.Sub != ci.Claims.Sub {
				r = idResult{status: identity.StatusConflict}
				p.recordIdentity(identity.StatusConflict, "")
			}
		}
	default:
		r = idResult{claims: ci.Claims, status: cs, reason: ci.Reason}
	}
	s.idStatus, s.idReason, s.idClaims = r.status, r.reason, r.claims
	if r.status == identity.StatusValid {
		s.subject = identity.SubjectFrom(r.claims, r.status)
		s.subject.AgentID = p.cfg.AgentID
	}
	p.cfg.Metrics.ObserveAddedLatency("identity", time.Since(start))
	return false
}

// headerResult verifies a header presented next to a live CONNECT identity.
func (p *Proxy) headerResult(h *identityHolder, raw string, n int) idResult {
	if n > 1 {
		return p.malformed()
	}
	tok, ok := bearerToken(raw)
	if !ok {
		return p.malformed()
	}
	return p.verifyToken(h, tok)
}
