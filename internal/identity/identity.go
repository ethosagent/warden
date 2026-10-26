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
)

// Reasons returns the complete bounded Reason set.
func Reasons() []Reason {
	return []Reason{
		ReasonBadSignature, ReasonWrongIss, ReasonWrongAud, ReasonWrongAZP,
		ReasonUnknownKID, ReasonAlgNotAllowed, ReasonMalformed, ReasonTooLarge,
		ReasonTTLTooLong, ReasonJWKSUnavailable, ReasonWrongNonce,
	}
}

// Limits and defaults that Warden enforces itself.
const (
	MaxTokenBytes      = 16 << 10
	MaxGroups          = 64
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
// StatusValid. The proxy fills AgentID.
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
	}
}

// NormalizeGroups drops empty entries, drops (never cuts) any entry over
// MaxGroupBytes, sorts, de-duplicates and keeps at most MaxGroups. The bool is
// true when anything was dropped for size or count, so callers can fail closed
// on a partial list.
func NormalizeGroups(in []string) ([]string, bool) {
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
	if len(out) > MaxGroups {
		out = out[:MaxGroups]
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
