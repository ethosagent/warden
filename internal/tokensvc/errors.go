package tokensvc

import "fmt"

// OAuthCode is an RFC 6749 / RFC 8693 error code: the only part of a failure
// that reaches the wire.
type OAuthCode string

// The codes the token endpoint can answer with.
const (
	CodeInvalidRequest         OAuthCode = "invalid_request"
	CodeInvalidClient          OAuthCode = "invalid_client"
	CodeInvalidGrant           OAuthCode = "invalid_grant"
	CodeUnauthorizedClient     OAuthCode = "unauthorized_client"
	CodeInvalidScope           OAuthCode = "invalid_scope"
	CodeInvalidTarget          OAuthCode = "invalid_target"
	CodeUnsupportedGrantType   OAuthCode = "unsupported_grant_type"
	CodeTemporarilyUnavailable OAuthCode = "temporarily_unavailable"
)

// Reason says why a request failed, for logs and metrics only. It is a closed
// set of fixed words and never reaches the client: an unknown agent, an
// unknown kid, a bad signature and a disabled agent all answer the same
// invalid_client, so the response does not reveal which agent ids exist.
type Reason string

// The closed reason set.
const (
	ReasonAgentUnknown           Reason = "agent_unknown"
	ReasonUnknownKID             Reason = "unknown_kid"
	ReasonBadSignature           Reason = "bad_signature"
	ReasonAgentDisabled          Reason = "agent_disabled"
	ReasonReplay                 Reason = "replay"
	ReasonWrongAud               Reason = "wrong_aud"
	ReasonWrongIss               Reason = "wrong_iss"
	ReasonExpired                Reason = "expired"
	ReasonNotYetValid            Reason = "not_yet_valid"
	ReasonLifetimeTooLong        Reason = "lifetime_too_long"
	ReasonAlgNotAllowed          Reason = "alg_not_allowed"
	ReasonMalformed              Reason = "malformed"
	ReasonTooLarge               Reason = "too_large"
	ReasonAgentStoreUnavailable  Reason = "agent_store_unavailable"
	ReasonReplayStoreUnavailable Reason = "replay_store_unavailable"
	ReasonVerifierMisconfigured  Reason = "verifier_misconfigured"

	// Reasons of the exchange after the agent authenticated.
	ReasonUnsupportedTokenType    Reason = "unsupported_token_type"
	ReasonInvalidTarget           Reason = "invalid_target"
	ReasonSubjectInvalid          Reason = "subject_invalid"
	ReasonSubjectExpired          Reason = "subject_expired"
	ReasonIdPUnavailable          Reason = "idp_unavailable"
	ReasonUserBlocked             Reason = "user_blocked"
	ReasonBlockStoreUnavailable   Reason = "block_store_unavailable"
	ReasonGroupNotAllowed         Reason = "group_not_allowed"
	ReasonScopeNotAllowed         Reason = "scope_not_allowed"
	ReasonSessionRevoked          Reason = "session_revoked"
	ReasonSessionStoreUnavailable Reason = "session_store_unavailable"
	ReasonTokenTooLarge           Reason = "token_too_large"
	ReasonSignerUnavailable       Reason = "signer_unavailable"
)

// Error is a token endpoint failure. Code is what the client sees; Reason,
// AgentID and JTI are for logs and metrics.
//
// AgentID is set only when the assertion's iss passed agentid.ValidID, so it
// is safe to log. JTI is an 8-hex prefix of sha256(jti), never the jti. Error
// never includes the assertion or any claim value.
type Error struct {
	Code    OAuthCode
	Reason  Reason
	AgentID string
	JTI     string
}

// Error implements error with fixed words only.
func (e *Error) Error() string {
	return fmt.Sprintf("tokensvc: %s (%s)", e.Code, e.Reason)
}
