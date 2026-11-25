package tokensvc

import (
	"context"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

// Subject token types the endpoint can be asked to exchange.
const (
	// TokenTypeIDToken is an OIDC ID token from the configured IdP.
	TokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token"
	// TokenTypeJWT and TokenTypeAccessToken are the accepted
	// requested_token_type values; the issued token is a JWT either way.
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
)

// ResolvedSubject is a verified subject token: who the user is and when the
// proof of it ends.
type ResolvedSubject struct {
	// Subject is the verified identity; never nil in a successful result.
	Subject *identity.Subject
	// IdPIss is the issuer of the proof, the first half of the session key.
	IdPIss string
	// IdPSID is the IdP session id, when the proof carries one.
	IdPSID string
	// IssuedAt is when the subject token was issued; a session revoked at or
	// after it cannot be continued.
	IssuedAt time.Time
	// Expiry is when the proof ends; the issued token never outlives it.
	Expiry time.Time
}

// SubjectResolver verifies one kind of subject token. A failure is a *Error;
// the raw token never appears in it. P2 registers the id_token resolver;
// later subject types (delegation grants) add their own without a change to
// Exchange.
type SubjectResolver interface {
	Resolve(ctx context.Context, raw string) (ResolvedSubject, error)
}

// idTokenResolver verifies an IdP ID token with an identity.Verifier.
type idTokenResolver struct{ v identity.Verifier }

// NewIDTokenResolver returns the resolver for TokenTypeIDToken. v must accept
// only the IdP's tokens, with allowedAZP narrowed to the clients that may be
// exchanged, so that a Warden token can never be a subject token.
func NewIDTokenResolver(v identity.Verifier) SubjectResolver { return idTokenResolver{v: v} }

func (r idTokenResolver) Resolve(ctx context.Context, raw string) (ResolvedSubject, error) {
	if r.v == nil {
		return ResolvedSubject{}, &Error{Code: CodeTemporarilyUnavailable, Reason: ReasonVerifierMisconfigured}
	}
	claims, status, _ := r.v.Verify(ctx, raw)
	switch status {
	case identity.StatusValid:
	case identity.StatusExpired:
		return ResolvedSubject{}, &Error{Code: CodeInvalidGrant, Reason: ReasonSubjectExpired}
	case identity.StatusUnverified:
		return ResolvedSubject{}, &Error{Code: CodeTemporarilyUnavailable, Reason: ReasonIdPUnavailable}
	default:
		return ResolvedSubject{}, &Error{Code: CodeInvalidGrant, Reason: ReasonSubjectInvalid}
	}
	sub := identity.SubjectFrom(claims, status)
	if sub == nil || sub.Sub == "" || claims.Issuer == "" || claims.Expiry.IsZero() {
		return ResolvedSubject{}, &Error{Code: CodeInvalidGrant, Reason: ReasonSubjectInvalid}
	}
	return ResolvedSubject{
		Subject:  sub,
		IdPIss:   claims.Issuer,
		IdPSID:   claims.SID,
		IssuedAt: claims.IssuedAt,
		Expiry:   claims.Expiry,
	}, nil
}
