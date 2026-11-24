// Package tokensvc is the domain of the control plane's token endpoint
// (RFC 8693 token exchange). This file set covers client authentication: an
// agent proves who it is with a private_key_jwt assertion (RFC 7523) signed by
// a key in the agent registry. Minting the exchanged token is a later ticket.
//
// The package does no I/O and reads no wall clock: the registry (agentreg.Store)
// and the replay table (ReplayStore) are ports, and time comes from an
// injected function. The SQLite ReplayStore and its cpstate migration live in
// internal/tokensvc/adapters/sqlite.
//
// The raw assertion and the raw jti never appear in an error, a log line or a
// test failure: an assertion is a bearer credential until it is consumed.
package tokensvc

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/ethosagent/warden/internal/agentid"
	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/keys"
)

// Limits and defaults of assertion verification.
const (
	// MaxAssertionSize caps the raw assertion, in bytes.
	MaxAssertionSize = 8 << 10
	// DefaultSkew is the clock skew tolerated on exp, iat and nbf.
	DefaultSkew = 60 * time.Second
	// DefaultMaxAge is the longest exp-iat an assertion may claim.
	DefaultMaxAge = 5 * time.Minute
	// TokenPath is appended to the issuer to form the second accepted aud.
	TokenPath = "/oauth2/token"

	maxJTILen = 128
	// maxNumericDate keeps a NumericDate inside what time.Unix handles
	// without overflow (year 5138).
	maxNumericDate = 1e11
)

// Client is an authenticated agent.
type Client struct {
	AgentID string
	// KID is the registry key id of the verifying key.
	KID string
	// JKT is the RFC 7638 thumbprint computed from the verifying JWK: the
	// same value agentreg.Thumbprints serves to workers, never the header kid.
	JKT string
}

// AssertionVerifier authenticates agents by private_key_jwt assertion. Agents,
// Replay, Issuer and Now are required; a verifier missing any of them fails
// every assertion closed rather than skip a check.
type AssertionVerifier struct {
	Agents agentreg.Store
	Replay ReplayStore
	// Issuer is the control plane's issuer URL from configuration. The
	// accepted audiences are Issuer and Issuer + TokenPath; the audience is
	// never derived from the request.
	Issuer string
	// Now is the clock. Production passes clock.Real().Now.
	Now func() time.Time
	// Skew defaults to DefaultSkew, MaxAge to DefaultMaxAge.
	Skew, MaxAge time.Duration
}

// claims is the assertion payload. Pointer members distinguish absent from
// zero; a member of the wrong JSON type fails decoding and is malformed.
type claims struct {
	Iss      *string         `json:"iss"`
	Sub      *string         `json:"sub"`
	Aud      json.RawMessage `json:"aud"`
	Exp      *float64        `json:"exp"`
	Iat      *float64        `json:"iat"`
	Nbf      *float64        `json:"nbf"`
	Jti      *string         `json:"jti"`
	ClientID *string         `json:"client_id"`
}

// VerifyClientAssertion authenticates raw, a compact JWS client assertion. See
// VerifyClientAssertionFor.
func (v *AssertionVerifier) VerifyClientAssertion(ctx context.Context, raw string) (Client, error) {
	return v.VerifyClientAssertionFor(ctx, raw, "")
}

// VerifyClientAssertionFor is VerifyClientAssertion for a request that also
// carried a form client_id: a non-empty formClientID must equal the
// assertion's iss.
//
// The checks run in this order: size, parse, lookup, key and alg, signature,
// claims, agent status, replay. The replay row is written last, only for an
// assertion that passed everything else, so a rejected assertion never burns
// a jti. A failure is a *Error with Code invalid_client (or
// temporarily_unavailable when the registry or replay store failed); an
// unknown agent, an unknown kid and a bad signature are indistinguishable by
// code, message and (by a dummy verification) timing.
func (v *AssertionVerifier) VerifyClientAssertionFor(ctx context.Context, raw, formClientID string) (Client, error) {
	if v == nil || v.Agents == nil || v.Replay == nil || v.Now == nil || v.Issuer == "" {
		return Client{}, fail(ReasonStoreUnavailable, "", "")
	}
	if len(raw) > MaxAssertionSize {
		return Client{}, fail(ReasonTooLarge, "", "")
	}
	h, payload, input, sig, err := keys.ParseCompact(raw)
	if err != nil {
		if errors.Is(err, keys.ErrUnsupportedAlg) {
			return Client{}, fail(ReasonAlgNotAllowed, "", "")
		}
		return Client{}, fail(ReasonMalformed, "", "")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss == nil {
		return Client{}, fail(ReasonMalformed, "", "")
	}
	// Every failure from here until the signature check spends a dummy
	// verification first, so timing does not tell a registered agent from a
	// made-up one.
	unknown := func(r Reason, agent string) (Client, error) {
		dummyVerify(h.Alg, input, sig)
		return Client{}, fail(r, agent, "")
	}
	if agentid.ValidID(*c.Iss) != nil {
		return unknown(ReasonAgentUnknown, "")
	}
	agentID := *c.Iss
	if h.Kid == "" {
		return unknown(ReasonUnknownKID, agentID)
	}
	agent, err := v.Agents.Get(ctx, agentID)
	switch {
	case errors.Is(err, agentreg.ErrNotFound):
		return unknown(ReasonAgentUnknown, agentID)
	case err != nil:
		return Client{}, fail(ReasonStoreUnavailable, agentID, "")
	}
	key, ok := selectKey(agent, h.Kid)
	if !ok {
		return unknown(ReasonUnknownKID, agentID)
	}
	if h.Alg != key.Alg {
		return unknown(ReasonAlgNotAllowed, agentID)
	}
	jwk, err := key.PublicJWK()
	if err != nil {
		return Client{}, fail(ReasonStoreUnavailable, agentID, "")
	}
	if err := keys.Verify(jwk, h.Alg, input, sig); err != nil {
		if errors.Is(err, keys.ErrAlgMismatch) || errors.Is(err, keys.ErrUnsupportedAlg) {
			return Client{}, fail(ReasonAlgNotAllowed, agentID, "")
		}
		return Client{}, fail(ReasonBadSignature, agentID, "")
	}
	jkt, err := keys.Thumbprint(jwk)
	if err != nil {
		return Client{}, fail(ReasonStoreUnavailable, agentID, "")
	}

	now := v.Now()
	exp, jtiHash, reason := v.checkClaims(&c, agentID, formClientID, now)
	if reason != "" {
		return Client{}, fail(reason, agentID, jtiHash)
	}
	if agent.Status != agentreg.StatusActive {
		return Client{}, fail(ReasonAgentDisabled, agentID, jtiHash)
	}
	first, err := v.Replay.Consume(ctx, agentID, jtiHash, exp.Add(v.skew()))
	if err != nil {
		return Client{}, fail(ReasonStoreUnavailable, agentID, jtiHash)
	}
	if !first {
		return Client{}, fail(ReasonReplay, agentID, jtiHash)
	}
	return Client{AgentID: agentID, KID: key.KID, JKT: jkt}, nil
}

// checkClaims validates the claims of a signature-verified assertion. It
// returns the expiry and the jti hash on success and a non-empty reason on
// failure (jtiHash is returned whenever the jti was valid, for the log).
func (v *AssertionVerifier) checkClaims(c *claims, agentID, formClientID string, now time.Time) (exp time.Time, jtiHash string, reason Reason) {
	if c.Sub == nil || *c.Sub != agentID {
		return time.Time{}, "", ReasonWrongIss
	}
	if formClientID != "" && formClientID != agentID {
		return time.Time{}, "", ReasonWrongIss
	}
	if c.ClientID != nil && *c.ClientID != agentID {
		return time.Time{}, "", ReasonWrongIss
	}
	if c.Jti == nil || !validJTI(*c.Jti) {
		return time.Time{}, "", ReasonMalformed
	}
	jtiHash = JTIHash(*c.Jti)
	if !v.audienceOK(c.Aud) {
		return time.Time{}, jtiHash, ReasonWrongAud
	}
	expT, ok := numericDate(c.Exp)
	iatT, ok2 := numericDate(c.Iat)
	if !ok || !ok2 {
		return time.Time{}, jtiHash, ReasonMalformed
	}
	life := expT.Sub(iatT)
	if life <= 0 {
		return time.Time{}, jtiHash, ReasonMalformed
	}
	if life > v.maxAge() {
		return time.Time{}, jtiHash, ReasonLifetimeTooLong
	}
	skew := v.skew()
	if !expT.After(now.Add(-skew)) {
		return time.Time{}, jtiHash, ReasonExpired
	}
	if iatT.After(now.Add(skew)) {
		return time.Time{}, jtiHash, ReasonNotYetValid
	}
	if c.Nbf != nil {
		nbf, ok := numericDate(c.Nbf)
		if !ok {
			return time.Time{}, jtiHash, ReasonMalformed
		}
		if nbf.After(now.Add(skew)) {
			return time.Time{}, jtiHash, ReasonNotYetValid
		}
	}
	return expT, jtiHash, ""
}

// audienceOK accepts a single audience, as a string or an array of exactly
// one string, equal to the issuer or the issuer's token endpoint.
func (v *AssertionVerifier) audienceOK(raw json.RawMessage) bool {
	var aud string
	if err := json.Unmarshal(raw, &aud); err != nil {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil || len(list) != 1 {
			return false
		}
		aud = list[0]
	}
	return aud != "" && (aud == v.Issuer || aud == trimSlash(v.Issuer)+TokenPath)
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func (v *AssertionVerifier) skew() time.Duration {
	if v.Skew > 0 {
		return v.Skew
	}
	return DefaultSkew
}

func (v *AssertionVerifier) maxAge() time.Duration {
	if v.MaxAge > 0 {
		return v.MaxAge
	}
	return DefaultMaxAge
}

// numericDate converts a JWT NumericDate; absent, negative and absurd values
// are rejected.
func numericDate(p *float64) (time.Time, bool) {
	if p == nil || math.IsNaN(*p) || *p < 0 || *p > maxNumericDate {
		return time.Time{}, false
	}
	sec := math.Floor(*p)
	return time.Unix(int64(sec), int64((*p-sec)*1e9)), true
}

// validJTI reports whether jti is 1 to 128 printable ASCII characters.
func validJTI(jti string) bool {
	if jti == "" || len(jti) > maxJTILen {
		return false
	}
	for i := 0; i < len(jti); i++ {
		if jti[i] < 0x21 || jti[i] > 0x7e {
			return false
		}
	}
	return true
}

// selectKey finds the registry key named by kid: its key id or its RFC 7638
// thumbprint.
func selectKey(a agentreg.Agent, kid string) (agentreg.Key, bool) {
	for _, k := range a.Keys {
		if k.KID == kid || k.JKT == kid {
			return k, true
		}
	}
	return agentreg.Key{}, false
}

// dummyVerify spends one signature verification against a fixed public key.
// Its result is discarded.
func dummyVerify(alg string, input, sig []byte) {
	if jwk, ok := dummyKey(alg); ok {
		_ = keys.Verify(jwk, alg, input, sig)
	}
}

// fail builds the *Error for a reason. Every reason but a store failure is
// invalid_client; jtiHash is the full hash and only an 8-hex prefix is kept.
func fail(r Reason, agentID, jtiHash string) *Error {
	code := CodeInvalidClient
	if r == ReasonStoreUnavailable {
		code = CodeTemporarilyUnavailable
	}
	e := &Error{Code: code, Reason: r, AgentID: agentID}
	if len(jtiHash) >= 8 {
		e.JTI = jtiHash[:8]
	}
	return e
}
