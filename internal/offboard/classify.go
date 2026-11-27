package offboard

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
)

// Class is the verdict on one refresh, pinned to the Dex v2.41.1 refresh
// responses (server/refreshhandlers.go). Only ClassUpstreamRefused can ever
// become an offboarding signal, and only after W-P3-OFFB-05 confirms it.
type Class string

// Classes.
const (
	// ClassOK: 200 with an ID token that verified for this link.
	ClassOK Class = "ok"
	// ClassTransient: no response, a timeout, 429, a 5xx other than the
	// refusal shape below, or any answer this table does not know.
	ClassTransient Class = "transient"
	// ClassExpired: 400 invalid_request "Refresh token expired." (the
	// chain's absolute lifetime). The user must sign in again.
	ClassExpired Class = "expired"
	// ClassTokenLost: 400 "Refresh token is invalid or has already been
	// claimed by another client." or any 400 invalid_grant: storage loss, a
	// newer login (Dex invalidates the earlier chain) or a lost rotation.
	// Re-auth and alert; never offboard.
	ClassTokenLost Class = "token_lost"
	// ClassUpstreamRefused: 500 invalid_request with no description, Dex's
	// answer when the connector refuses the refresh (for LDAP: userSearch no
	// longer finds the user). Recorded only in observe mode.
	ClassUpstreamRefused Class = "upstream_refused"
	// ClassConfigError: 401 invalid_client. The job pauses.
	ClassConfigError Class = "config_error"
	// ClassSuspect: the returned ID token is missing, fails verification or
	// names another subject. Never acted on.
	ClassSuspect Class = "suspect"
)

// Dex's refresh error descriptions (v2.41.1).
const (
	dexExpiredDescription = "Refresh token expired."
	dexClaimedFragment    = "invalid or has already been claimed"
)

// HTTP statuses the table names (net/http is not imported by a domain).
const (
	statusOK                  = 200
	statusBadRequest          = 400
	statusUnauthorized        = 401
	statusTooManyRequests     = 429
	statusInternalServerError = 500
)

// Result is one token-endpoint answer. Status 0 never happens: no response is
// the TokenClient's error. Description is IdP text: it is matched, never
// logged.
type Result struct {
	Status       int
	ErrorCode    string
	Description  string
	RefreshToken string
	IDToken      string
}

// LogValue keeps the tokens and the description out of structured logs.
func (r Result) LogValue() slog.Value {
	return slog.GroupValue(slog.Int("status", r.Status), slog.String("error", r.ErrorCode))
}

// String renders the result without its tokens.
func (r Result) String() string {
	return "offboard.Result{status=" + strconv.Itoa(r.Status) + " error=" + r.ErrorCode + "}"
}

// GoString keeps the tokens out of %#v.
func (r Result) GoString() string { return r.String() }

// classifyResponse classifies the token endpoint's answer (err is the
// TokenClient's no-response error). ClassOK here means only "200": the ID
// token is checked after. The code is the idp_links.last_error_code value, a
// fixed word, never IdP text.
func classifyResponse(r Result, err error) (Class, string) {
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ClassTransient, "timeout"
		}
		return ClassTransient, "unreachable"
	}
	switch {
	case r.Status == statusOK:
		return ClassOK, ""
	case r.Status == statusUnauthorized && r.ErrorCode == "invalid_client":
		return ClassConfigError, "invalid_client"
	case r.Status == statusBadRequest && r.ErrorCode == "invalid_request" && r.Description == dexExpiredDescription:
		return ClassExpired, "refresh_expired"
	case r.Status == statusBadRequest && (r.ErrorCode == "invalid_grant" || strings.Contains(r.Description, dexClaimedFragment)):
		return ClassTokenLost, "refresh_invalid"
	case r.Status == statusInternalServerError && r.ErrorCode == "invalid_request" && r.Description == "":
		return ClassUpstreamRefused, "upstream_refused"
	case r.Status == statusTooManyRequests:
		return ClassTransient, "http_429"
	case r.Status >= 500 && r.Status <= 599:
		return ClassTransient, "http_" + strconv.Itoa(r.Status)
	}
	// Unknown answers are transient: they never move a link to a state that
	// asks for a re-login or could lead to offboarding.
	return ClassTransient, "http_" + strconv.Itoa(r.Status)
}
