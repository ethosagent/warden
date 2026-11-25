package identity

// The Warden token's fixed header and claim values (docs/identity-contract.md).
const (
	// WardenTokenTyp is the JWS typ header of a Warden token.
	WardenTokenTyp = "wt+jwt"
	// WardenTokenVer is the claims schema version, the "ver" claim.
	WardenTokenVer = 1
	// WardenAudience is the one audience a Warden token carries: the workers.
	WardenAudience = "warden-worker"
)

// WardenClaims is the payload of a Warden token, the short-lived JWT the
// control plane's token endpoint mints and workers verify. The token service
// encodes it and the worker verifier (W-P2-WBND-01) decodes it, so both ends
// share one definition. It is a bearer token bound to an agent through
// Act.Sub and Cnf.JKT; it is not proof of possession.
type WardenClaims struct {
	Ver int    `json:"ver"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Sub string `json:"sub"`
	// IdPIss is the issuer of the subject's IdP token.
	IdPIss string `json:"idp_iss"`
	// Email and EmailVerified are set only when the IdP verified the email.
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	// GroupsTruncated marks a group list the verifier had to cut.
	GroupsTruncated bool `json:"groups_truncated,omitempty"`
	// Act names the agent the token is bound to (RFC 8693 actor).
	Act WardenActor `json:"act"`
	// SID is the Warden token session id (wts_...); IdPSID the IdP's sid.
	SID    string `json:"sid"`
	IdPSID string `json:"idp_sid,omitempty"`
	JTI    string `json:"jti"`
	Iat    int64  `json:"iat"`
	Nbf    int64  `json:"nbf"`
	Exp    int64  `json:"exp"`
	// Scope is space-delimited and omitted when empty.
	Scope string `json:"scope,omitempty"`
	// Cnf binds the token to the RFC 7638 thumbprint of the agent key that
	// authenticated the exchange.
	Cnf WardenConfirmation `json:"cnf"`
}

// WardenActor is the act claim: the agent that exchanged the token.
type WardenActor struct {
	Sub string `json:"sub"`
}

// WardenConfirmation is the cnf claim (RFC 7800).
type WardenConfirmation struct {
	JKT string `json:"jkt"`
}
