package proxy

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
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

// IdentityMode is an agent's identity mode. Any value but attribute, challenge
// and require is treated as off, so an unknown mode never verifies.
type IdentityMode string

const (
	IdentityModeOff       IdentityMode = "off"
	IdentityModeAttribute IdentityMode = "attribute"
	// IdentityModeChallenge verifies like attribute and refuses a CONNECT with
	// no valid identity with a 407 that carries a sign-in URL (challenge.go).
	IdentityModeChallenge IdentityMode = "challenge"
	// IdentityModeRequire refuses a CONNECT without a valid Warden token bound
	// to this worker's agent with a 407 and no sign-in offer, and a terminated
	// request whose identity is not valid with a 403 (require.go). An IdP token
	// never satisfies it (unbound_token).
	IdentityModeRequire IdentityMode = "require"
)

// IdentityConfig seeds the identity holder from proxy.Config. The zero value
// is mode off. SignIn is used in challenge mode only; nil there means a 407
// with sign_in_error and no sign_in object.
type IdentityConfig struct {
	Verifier identity.Verifier
	Mode     IdentityMode
	SignIn   SignInStarter
}

// identityHolder is the immutable value behind Proxy.identityP. It exists only
// in attribute, challenge and require mode: a nil pointer means off.
type identityHolder struct {
	v    identity.Verifier
	mode IdentityMode
	// signin starts device authorizations in challenge mode (may be nil).
	signin SignInStarter
	// skew is the verifier's exp tolerance, used to re-check a CONNECT
	// identity's expiry on each later request. Verifiers expose it through
	// ClockSkew(); one that does not gets the default.
	skew time.Duration
	// snapshot returns the Warden snapshot a Warden token is bound against; nil
	// for a verifier without one (the bare IdP verifier). It is read on every
	// binding check, never held, so a new bundle applies on the next request.
	snapshot func() *identity.WardenSnapshot
}

// snapshotSource is a verifier that serves the Warden snapshot Warden tokens are
// bound against (identity.MultiVerifier, identity.WardenVerifier).
type snapshotSource interface {
	Snapshot() *identity.WardenSnapshot
}

func newIdentityHolder(v identity.Verifier, mode IdentityMode, signin SignInStarter) *identityHolder {
	if v == nil || (mode != IdentityModeAttribute && mode != IdentityModeChallenge && mode != IdentityModeRequire) {
		return nil
	}
	if mode != IdentityModeChallenge {
		signin = nil
	}
	skew := identity.DefaultClockSkew
	if sk, ok := v.(interface{ ClockSkew() time.Duration }); ok {
		skew = sk.ClockSkew()
	}
	h := &identityHolder{v: v, mode: mode, signin: signin, skew: skew}
	if sv, ok := v.(snapshotSource); ok {
		h.snapshot = sv.Snapshot
	}
	return h
}

// identity loads the live holder; nil means mode off. One snapshot per use keeps
// a concurrent SetIdentity from changing the verifier mid-request.
func (p *Proxy) identity() *identityHolder { return p.identityP.Load() }

// SetIdentity atomically swaps the identity verifier and mode. A nil verifier
// or any mode but attribute, challenge or require turns identity off. It is race-free
// against the hot path; connections already open keep the identity they
// resolved at CONNECT. The mode is the agent's resolved mode, decided by the
// caller. Challenge mode has no sign-in starter here: use SetIdentityWithSignIn.
func (p *Proxy) SetIdentity(v identity.Verifier, mode IdentityMode) {
	p.SetIdentityWithSignIn(v, mode, nil)
}

// SetIdentityWithSignIn is SetIdentity plus the starter challenge mode uses to
// put a sign-in URL in its 407. The starter is ignored in other modes.
func (p *Proxy) SetIdentityWithSignIn(v identity.Verifier, mode IdentityMode, signin SignInStarter) {
	p.identityP.Store(newIdentityHolder(v, mode, signin))
	p.warnIdentityCoverage()
}

// IdentityModeName is the effective identity mode this proxy enforces now: off
// when no verifier is installed, else attribute, challenge or require. The heartbeat
// reports it, so the control plane sees what runs, not what was requested.
func (p *Proxy) IdentityModeName() string {
	if h := p.identity(); h != nil {
		return string(h.mode)
	}
	return string(IdentityModeOff)
}

// SupportsChallenge reports whether this worker can answer a 407: it needs a
// CONNECT listener, which a transparent-only worker does not have.
func (p *Proxy) SupportsChallenge() bool { return p.cfg.Mode != config.ProxyModeTransparent }

// warnIdentityCoverage logs, once each, the two places attribute mode cannot
// see a token: raw tunnels (no CA) and a transparent-only worker (no CONNECT).
func (p *Proxy) warnIdentityCoverage() {
	h := p.identity()
	if h == nil {
		return
	}
	if h.mode == IdentityModeChallenge {
		if p.cfg.Mode == config.ProxyModeBoth {
			p.warnChallengeTransparent.Do(func() {
				p.cfg.Logger.Warn("identity challenge mode on a worker with a transparent listener: the transparent leg has no CONNECT, so it cannot be challenged and is not refused for a missing identity")
			})
		}
		if p.caCert == nil {
			p.warnChallengeNoCA.Do(func() {
				p.cfg.Logger.Warn("identity challenge mode without a CA: a raw tunnel is checked at CONNECT only and is not cut when the token expires")
			})
		}
	}
	if h.mode == IdentityModeRequire {
		if p.cfg.Mode == config.ProxyModeTransparent {
			p.warnRequireTransparent.Do(func() {
				p.cfg.Logger.Warn("identity require mode on a transparent-only worker: there is no CONNECT, so a request is admitted only with a valid bound Warden token in X-Warden-Identity")
			})
		}
		if p.caCert == nil {
			p.warnRequireNoCA.Do(func() {
				p.cfg.Logger.Warn("identity require mode without a CA: a raw tunnel is checked at CONNECT only and is not cut when the token expires or its binding is revoked")
			})
		}
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
	h := p.identity()
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
	p.cfg.Metrics.RecordIdentityVerify(string(identity.StatusInvalid), string(identity.ReasonMalformed), string(identity.TokenNone))
	return idResult{status: identity.StatusInvalid, reason: identity.ReasonMalformed}
}

// verifyToken runs one bounded Verify and counts it. The raw token goes to the
// verifier and nowhere else.
func (p *Proxy) verifyToken(h *identityHolder, tok string) idResult {
	timeout := p.identityTimeout
	if timeout <= 0 {
		timeout = identityVerifyTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	c, st, r := h.v.Verify(ctx, tok)
	cancel()
	res := p.bind(h, idResult{claims: c, status: st, reason: r})
	p.recordIdentity(res.status, res.reason, tokenTypeOf(res.claims))
	return res
}

// rebind re-checks a live CONNECT identity against the current snapshot on each
// later request: the signing key must still be in the bundle's token JWKS
// (unknown_kid, e.g. an emergency key removal), the issuer must still match
// (wrong_iss), and the token must still bind to the agent and key. Allocation
// free. A non-Warden identity passes, except in require mode, where it fails
// as unbound_token.
func (p *Proxy) rebind(h *identityHolder, r idResult) idResult {
	if r.status != identity.StatusValid {
		return r
	}
	warden := r.claims.TokenType == identity.TokenWarden
	// An IdP identity opened under another mode is not bound there; in require
	// mode it must not outlive the flip, so it goes through the binding check
	// (unbound_token) like every other valid identity.
	if !warden && h.mode != IdentityModeRequire {
		return r
	}
	var snap *identity.WardenSnapshot
	if h.snapshot != nil {
		snap = h.snapshot() // read once for the whole re-check
	}
	if warden && h.snapshot != nil {
		switch {
		case !snap.HasKey(r.claims.KID):
			return idResult{claims: r.claims, status: identity.StatusInvalid, reason: identity.ReasonUnknownKID}
		case snap.Issuer() != r.claims.Issuer:
			return idResult{claims: r.claims, status: identity.StatusInvalid, reason: identity.ReasonWrongIss}
		}
	}
	return p.bindSnap(h, snap, r)
}

// bind applies agent binding (W-P2-WBND-02) to a verified result. Only a valid
// Warden token is bound; every other result passes through. A token that fails
// binding becomes invalid with the binding reason and no Subject, but keeps its
// claims: the block-list check still matches the parsed sub and email, because
// a match can only deny. The snapshot is read here, per call, so a binding is
// never older than the bundle currently applied. A Warden token with no
// snapshot to bind against fails closed. In require mode a valid token of any
// other type (an IdP token) fails as unbound_token.
func (p *Proxy) bind(h *identityHolder, r idResult) idResult {
	var snap *identity.WardenSnapshot
	if h.snapshot != nil {
		snap = h.snapshot()
	}
	return p.bindSnap(h, snap, r)
}

// bindSnap is bind against a snapshot the caller already read.
func (p *Proxy) bindSnap(h *identityHolder, snap *identity.WardenSnapshot, r idResult) idResult {
	if r.status != identity.StatusValid {
		return r
	}
	// In require mode every valid token is bound, so an IdP token is refused as
	// unbound_token (BindingCheck): it never satisfies the mode.
	if r.claims.TokenType != identity.TokenWarden && h.mode != IdentityModeRequire {
		return r
	}
	if reason, ok := identity.BindingCheck(snap, p.cfg.AgentID, r.claims); !ok {
		return idResult{claims: r.claims, status: identity.StatusInvalid, reason: reason}
	}
	return r
}

// tokenTypeOf is the token_type metric label for claims a verifier returned. A
// dispatching verifier says which kind of token it held; one that does not
// (the bare IdP verifier) means an IdP token.
func tokenTypeOf(c identity.Claims) string {
	if c.TokenType == "" {
		return string(identity.TokenIdP)
	}
	return string(c.TokenType)
}

func (p *Proxy) recordIdentity(st identity.Status, r identity.Reason, tokenType string) {
	reason := string(r)
	if reason == "" {
		reason = "none"
	}
	p.cfg.Metrics.RecordIdentityVerify(string(st), reason, tokenType)
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

// identityStage resolves who made this request and sets s.subject. In attribute
// mode it never ends the request: identity is recorded, not enforced. In
// challenge mode an expired connection identity or a conflicting header ends it
// with a 403 (challenge.go); in require mode so does any identity that is not
// valid (require.go). The raw header value is dropped here, so no later
// stage (judge, DLP, MCP) can see it.
//
// Rules, in order:
//   - mode off: a token (CONNECT or header) gives status off, with no Verify;
//   - a valid CONNECT identity is re-checked against its exp plus the verifier's
//     skew on every request and becomes expired once that passes;
//   - the header is used only when CONNECT carried no token (none or off);
//   - a valid CONNECT identity plus a valid header with a different sub gives
//     conflict and no subject;
//   - a header that is not one well-formed Bearer value is invalid/malformed,
//     even next to a live CONNECT identity;
//   - otherwise the CONNECT result stands (a failed CONNECT token is not
//     overridden by a header).
//
// Only status valid yields a Subject.
func (p *Proxy) identityStage(s *requestScope) (endSession bool) {
	raw, n := s.rawIdentity, s.rawIdentityN
	s.rawIdentity = ""
	ci := s.ci
	cs := ci.status()

	h := p.identity()
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
	if connLive && !p.validityClock().Before(ci.Expiry.Add(h.skew)) {
		// Past exp plus skew (or no exp at all, which a valid token always has:
		// fail closed). The connection's identity is spent.
		connLive, cs = false, identity.StatusExpired
		p.recordIdentity(identity.StatusExpired, "", tokenTypeOf(ci.Claims))
	}
	switch {
	case cs == identity.StatusNone || cs == identity.StatusOff:
		switch {
		case n == 0:
			r = idResult{status: identity.StatusNone}
			p.recordIdentity(identity.StatusNone, "", string(identity.TokenNone))
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
		// A tunnel outlives the bundle it was opened under: bind again against
		// the snapshot current now, so a removed key or a disabled agent ends
		// the identity on this request, not at token expiry. Before the Subject
		// is built below, which stamps the worker's agent.
		if br := p.rebind(h, r); br.status != identity.StatusValid {
			r = br
			s.idRebound = true
			p.recordIdentity(br.status, br.reason, tokenTypeOf(br.claims))
		}
		if n > 0 && r.status == identity.StatusValid {
			hr := p.headerResult(h, raw, n)
			switch {
			case hr.status == identity.StatusInvalid && hr.reason == identity.ReasonMalformed:
				// A header that is not a single well-formed Bearer value is malformed
				// even next to a live CONNECT identity.
				r = hr
			case hr.status == identity.StatusValid && hr.claims.Sub != ci.Claims.Sub,
				h.mode == IdentityModeRequire && requireHeaderConflicts(hr, ci.Claims):
				if hr.status == identity.StatusValid {
					s.idHeaderClaims = hr.claims
				}
				r = idResult{status: identity.StatusConflict}
				p.recordIdentity(identity.StatusConflict, "", tokenTypeOf(ci.Claims))
			}
		}
	default:
		r = idResult{claims: ci.Claims, status: cs, reason: ci.Reason}
	}
	s.idStatus, s.idReason, s.idClaims = r.status, r.reason, r.claims
	if r.status == identity.StatusValid {
		// Binding already ran: a Warden token reaching here has act.sub equal to
		// this worker's agent, so this stamp changes nothing for it and only
		// names the agent for an IdP token.
		s.subject = identity.SubjectFrom(r.claims, r.status)
		s.subject.AgentID = p.cfg.AgentID
	}
	p.cfg.Metrics.ObserveAddedLatency("identity", time.Since(start))
	if h.mode == IdentityModeRequire {
		return p.requireTerminated(s)
	}
	return p.challengeTerminated(s, h)
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

// stamp writes the identity onto an event about to be stored. on is whether
// identity is live for this worker (mode attribute). With identity off the event
// is left untouched, whatever the connection carried, so it is byte-identical to
// one written before identity existed. With identity on, every event gets a
// status: a request with no token gets none, which an auditor can tell apart
// from off (empty). The reason is written with it; the user_* fields only for
// status valid, so the unverified sub, email or groups that Verify returns for
// an expired or invalid token never reach storage.
func (c connIdentity) stamp(ev *analytics.Event, on bool) {
	if !on {
		return
	}
	st := c.status()
	ev.IdentityStatus = string(st)
	ev.IdentityReason = string(c.Reason)
	if st != identity.StatusValid {
		return
	}
	ev.UserSub = c.Claims.Sub
	ev.UserEmail = c.Claims.Email
	ev.UserGroups = c.Claims.Groups
	ev.UserGroupsTruncated = c.Claims.GroupsTruncated
	ev.UserSID = c.Claims.SID
	ev.UserAct = c.Claims.Act
	ev.IdentityTokenType = string(c.Claims.TokenType)
}

// recordEvent is the one place the proxy hands an event to the analytics
// store: it stamps the caller's identity first (only while identity is on). A new StoreEvent call anywhere
// else in the package fails TestAllEventsCarryIdentity.
func (p *Proxy) recordEvent(ci connIdentity, ev analytics.Event) {
	ci.stamp(&ev, p.identity() != nil)
	_ = p.analyticsStore().StoreEvent(ev)
}

// resolved is the identity this request's events carry: the per-request result
// once identityStage has run (it can differ from the CONNECT identity: expired,
// conflict, a header identity), the connection's identity before that.
func (s *requestScope) resolved() connIdentity {
	if s.idStatus == "" {
		return s.ci
	}
	return connIdentity{Claims: s.idClaims, Status: s.idStatus, Reason: s.idReason}
}
