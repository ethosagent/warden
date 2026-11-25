package identity

import (
	"context"
	"sort"
	"time"
)

// Status is the outcome class of a token check.
type Status string

const (
	StatusOff        Status = "off"
	StatusNone       Status = "none"
	StatusValid      Status = "valid"
	StatusInvalid    Status = "invalid"
	StatusExpired    Status = "expired"
	StatusUnverified Status = "unverified"
	StatusConflict   Status = "conflict"
)

// TokenType is the identity verify metric's token_type label value.
type TokenType string

// Token types for the identity verify metric's token_type label. A request
// without a token (or with one that never reached a verifier) is TokenNone.
const (
	TokenIdP    TokenType = "idp"
	TokenWarden TokenType = "warden"
	TokenNone   TokenType = "none"
)

// Reason is the bounded explanation for a non-valid Status. Raw token text and
// library error strings never become a Reason.
type Reason string

const (
	ReasonBadSignature    Reason = "bad_signature"
	ReasonWrongIss        Reason = "wrong_iss"
	ReasonWrongAud        Reason = "wrong_aud"
	ReasonWrongAZP        Reason = "wrong_azp"
	ReasonUnknownKID      Reason = "unknown_kid"
	ReasonAlgNotAllowed   Reason = "alg_not_allowed"
	ReasonMalformed       Reason = "malformed"
	ReasonTooLarge        Reason = "too_large"
	ReasonTTLTooLong      Reason = "ttl_too_long"
	ReasonJWKSUnavailable Reason = "jwks_unavailable"
	ReasonWrongNonce      Reason = "wrong_nonce"
	// ReasonMissingClaim is a Warden token without a required claim (sub,
	// act.sub, sid, jti or cnf.jkt).
	ReasonMissingClaim Reason = "missing_claim"
	// ReasonUnboundToken is a token that cannot satisfy agent binding: an IdP
	// token on a worker that does not accept them (identity.acceptDexTokens
	// false), and in require mode every IdP token.
	ReasonUnboundToken Reason = "unbound_token"
)

// Reasons returns the complete bounded Reason set.
func Reasons() []Reason {
	return []Reason{
		ReasonBadSignature, ReasonWrongIss, ReasonWrongAud, ReasonWrongAZP,
		ReasonUnknownKID, ReasonAlgNotAllowed, ReasonMalformed, ReasonTooLarge,
		ReasonTTLTooLong, ReasonJWKSUnavailable, ReasonWrongNonce,
		ReasonMissingClaim, ReasonUnboundToken,
	}
}

// Limits and defaults that Warden enforces itself.
const (
	MaxTokenBytes = 16 << 10
	MaxGroups     = 64
	// MaxConsoleGroups is the cap the console login applies: a human can hold
	// more groups than an agent token.
	MaxConsoleGroups   = 256
	MaxGroupBytes      = 256
	DefaultClockSkew   = 60 * time.Second
	MaxClockSkew       = 5 * time.Minute
	DefaultMaxTokenTTL = time.Hour
	DefaultGroupsClaim = "groups"
)

// Claims is what Warden keeps from a token.
type Claims struct {
	Sub             string
	Email           string
	EmailVerified   bool
	Groups          []string
	GroupsTruncated bool
	SID             string
	Issuer          string
	AZP             string
	Nonce           string
	IssuedAt        time.Time
	Expiry          time.Time

	// The fields below are set for a Warden token (TokenType warden) only.

	// Act is act.sub: the agent the token was minted for.
	Act string
	// CnfJKT is cnf.jkt: the RFC 7638 thumbprint of the agent key the token is
	// bound to. It is a key-liveness check input, not proof of possession.
	CnfJKT string
	// Scope is the space-delimited scope claim; parsed, not enforced.
	Scope string
	// KID is the key id the token was signed with.
	KID string
	// TokenType says which verifier path produced the claims: idp (a user
	// token from the configured IdP), warden (a CP-issued token) or none (the
	// token reached no verifier). Empty means a verifier that does not set it,
	// which callers count as idp.
	TokenType TokenType
}

// Subject is the policy-facing identity of a caller. Only a valid token
// yields one.
type Subject struct {
	Sub             string
	Email           string
	EmailVerified   bool
	Groups          []string
	GroupsTruncated bool
	AgentID         string
}

// SubjectFrom returns the policy subject for c, or nil unless s is
// StatusValid. AgentID is act.sub for a Warden token and empty for an IdP
// token; the proxy fills it from the worker's own agent.
func SubjectFrom(c Claims, s Status) *Subject {
	if s != StatusValid {
		return nil
	}
	var groups []string
	if len(c.Groups) > 0 {
		groups = append([]string(nil), c.Groups...)
	}
	return &Subject{
		Sub:             c.Sub,
		Email:           c.Email,
		EmailVerified:   c.EmailVerified,
		Groups:          groups,
		GroupsTruncated: c.GroupsTruncated,
		AgentID:         c.Act,
	}
}

// NormalizeGroups drops empty entries, drops (never cuts) any entry over
// MaxGroupBytes, sorts, de-duplicates and keeps at most MaxGroups. The bool is
// true when anything was dropped for size or count, so callers can fail closed
// on a partial list.
func NormalizeGroups(in []string) ([]string, bool) { return NormalizeGroupsMax(in, MaxGroups) }

// NormalizeGroupsMax is NormalizeGroups with a caller-chosen entry cap.
func NormalizeGroupsMax(in []string, maxGroups int) ([]string, bool) {
	truncated := false
	out := make([]string, 0, len(in))
	for _, g := range in {
		switch {
		case g == "":
		case len(g) > MaxGroupBytes:
			truncated = true
		default:
			out = append(out, g)
		}
	}
	sort.Strings(out)
	w := 0
	for i, g := range out {
		if i == 0 || g != out[w-1] {
			out[w] = g
			w++
		}
	}
	out = out[:w]
	if len(out) > maxGroups {
		out = out[:maxGroups]
		truncated = true
	}
	if len(out) == 0 {
		return nil, truncated
	}
	return out, truncated
}

// Verifier turns a raw token into Claims, a Status and a bounded Reason. It is
// safe for concurrent use and never returns the raw token in any output.
type Verifier interface {
	Verify(ctx context.Context, raw string, opts ...VerifyOption) (Claims, Status, Reason)
}

// VerifyOptions holds the per-call settings.
type VerifyOptions struct {
	// Nonce, when NonceSet, must equal the token's nonce claim. An empty
	// Nonce with NonceSet never matches, so it fails closed.
	Nonce    string
	NonceSet bool
}

// VerifyOption changes one Verify call.
type VerifyOption func(*VerifyOptions)

// WithNonce requires the token's nonce claim to equal n (console login).
func WithNonce(n string) VerifyOption {
	return func(o *VerifyOptions) { o.Nonce, o.NonceSet = n, true }
}

// ApplyOptions folds opts into a VerifyOptions.
func ApplyOptions(opts ...VerifyOption) VerifyOptions {
	var o VerifyOptions
	for _, f := range opts {
		if f != nil {
			f(&o)
		}
	}
	return o
}
