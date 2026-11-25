package identityclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

// RFC 8693 and RFC 7523 identifiers of the token endpoint's request.
const (
	grantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	assertionTypeJWT       = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	subjectTypeIDToken     = "urn:ietf:params:oauth:token-type:id_token"

	// WardenAudience is the audience parameter of every exchange.
	WardenAudience = identity.WardenAudience

	// maxExchangeBody caps a token endpoint response.
	maxExchangeBody = 64 << 10
	// maxRetryAfter caps a Retry-After a server may demand.
	maxRetryAfter = 5 * time.Minute
)

// Typed exchange errors. None carries a response body, a token or an
// assertion: only the RFC 6749 error code (from a closed list) is surfaced.
var (
	// ErrCPUnreachable means the control plane could not be reached (a
	// network error or timeout).
	ErrCPUnreachable = errors.New("identityclient: the control plane is unreachable")
	// ErrBadExchangeResponse means the token endpoint answered with something
	// that is not an RFC 6749 token or error response.
	ErrBadExchangeResponse = errors.New("identityclient: the token endpoint sent an invalid response")
)

// ErrExchangeDenied means the control plane refused the exchange for a reason
// retrying cannot fix (invalid_client, unauthorized_client, invalid_grant, and
// the other 4xx codes). Code is the RFC 6749 error code, never a description.
type ErrExchangeDenied struct{ Code string }

func (e ErrExchangeDenied) Error() string {
	return "identityclient: the control plane refused the token exchange (" + e.Code + ")"
}

// ErrRateLimited means the control plane answered 429; the caller may retry
// after RetryAfter.
type ErrRateLimited struct{ RetryAfter time.Duration }

func (e ErrRateLimited) Error() string {
	return "identityclient: the control plane rate-limited the token exchange (retry after " + e.RetryAfter.String() + ")"
}

// ErrUnavailable means the control plane answered 5xx (temporarily_unavailable
// when it is the token endpoint's own answer); the caller may retry after
// RetryAfter (zero when the server named none).
type ErrUnavailable struct{ RetryAfter time.Duration }

func (e ErrUnavailable) Error() string {
	return "identityclient: the control plane is temporarily unavailable (retry after " + e.RetryAfter.String() + ")"
}

// knownCodes is the closed set of error codes the endpoint can return; any
// other value from the wire is reported as "error", so a hostile or confused
// server cannot put text in front of the user.
var knownCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true,
	"unauthorized_client": true, "invalid_scope": true, "invalid_target": true,
	"unsupported_grant_type": true, "temporarily_unavailable": true, "rate_limited": true,
}

// WardenToken is an issued Warden token. It is a credential: String, GoString
// and LogValue show only a fingerprint.
type WardenToken struct {
	// AccessToken is the compact JWT. Never log it.
	AccessToken string
	// Scope is the issued scope, space-delimited.
	Scope string
	// ReceivedAt is the local time the response arrived; Expiry is ReceivedAt
	// plus expires_in.
	ReceivedAt, Expiry time.Time
}

// Lifetime is expires_in.
func (t WardenToken) Lifetime() time.Duration { return t.Expiry.Sub(t.ReceivedAt) }

func (t WardenToken) String() string {
	return "identityclient.WardenToken(fp=" + Fingerprint(t.AccessToken) + ")"
}
func (t WardenToken) GoString() string { return t.String() }
func (t WardenToken) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_fp", Fingerprint(t.AccessToken)), slog.Time("exp", t.Expiry))
}

// Exchanger performs one RFC 8693 token exchange against the control plane's
// token endpoint, authenticating with a fresh private_key_jwt assertion. It is
// safe for concurrent use. Retrying, caching and scheduling live in
// WardenTokenSource.
type Exchanger struct {
	// Endpoint is the URL the form is POSTed to.
	Endpoint string
	// Audience is the assertion's aud. Empty means Endpoint, byte for byte;
	// set it only when the control plane's configured issuer differs from the
	// URL the client reaches it by.
	Audience string
	AgentID  string
	Key      AgentKey
	// Scope is the optional space-delimited scope to request.
	Scope string
	// HTTP defaults to NewCPHTTPClient("").
	HTTP *http.Client
	Now  func() time.Time
	Log  *slog.Logger
}

func (e *Exchanger) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Exchanger) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ValidateTokenEndpoint checks a token endpoint URL: absolute, https (http only
// for a loopback host), no userinfo, query or fragment. There is no default.
func ValidateTokenEndpoint(raw string) error {
	if raw == "" {
		return errors.New("identityclient: the token endpoint is required (--token-endpoint or " + EnvTokenEndpoint + ")")
	}
	if err := identity.CheckClientIssuer(raw); err != nil {
		return errors.New("identityclient: the token endpoint must be an absolute https URL (http only for a loopback host) without userinfo, query or fragment")
	}
	return nil
}

// Exchange trades subject (a user's ID token) for a Warden token bound to this
// agent. Every call signs a new assertion. It makes one request and returns a
// typed error: ErrExchangeDenied, ErrRateLimited, ErrUnavailable,
// ErrCPUnreachable or ErrBadExchangeResponse.
func (e *Exchanger) Exchange(ctx context.Context, subject string) (WardenToken, error) {
	if subject == "" {
		return WardenToken{}, errors.New("identityclient: no subject token to exchange")
	}
	if err := ValidateTokenEndpoint(e.Endpoint); err != nil {
		return WardenToken{}, err
	}
	aud := e.Audience
	if aud == "" {
		aud = e.Endpoint
	}
	assertion, err := SignClientAssertion(ctx, e.Key, e.AgentID, aud, e.now())
	if err != nil {
		return WardenToken{}, err
	}
	form := url.Values{
		"grant_type":            {grantTypeTokenExchange},
		"subject_token":         {subject},
		"subject_token_type":    {subjectTypeIDToken},
		"client_assertion_type": {assertionTypeJWT},
		"client_assertion":      {assertion},
		"audience":              {WardenAudience},
	}
	if e.Scope != "" {
		form.Set("scope", e.Scope)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.Endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return WardenToken{}, errors.New("identityclient: build the token request")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	cl := e.HTTP
	if cl == nil {
		if cl, err = NewCPHTTPClient(""); err != nil {
			return WardenToken{}, err
		}
	}
	resp, err := cl.Do(req)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return WardenToken{}, cerr
		}
		// The transport error can carry the URL; only its class is kept.
		return WardenToken{}, ErrCPUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxExchangeBody))
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return WardenToken{}, cerr
		}
		return WardenToken{}, ErrCPUnreachable
	}
	received := e.now()
	if resp.StatusCode == http.StatusOK {
		return e.parseSuccess(body, received)
	}
	return WardenToken{}, e.parseFailure(resp, body)
}

func (e *Exchanger) parseSuccess(body []byte, received time.Time) (WardenToken, error) {
	var r struct {
		AccessToken string      `json:"access_token"`
		TokenType   string      `json:"token_type"`
		ExpiresIn   json.Number `json:"expires_in"`
		Scope       string      `json:"scope"`
	}
	if err := json.Unmarshal(body, &r); err != nil || r.AccessToken == "" || !strings.EqualFold(r.TokenType, "Bearer") {
		return WardenToken{}, ErrBadExchangeResponse
	}
	secs, err := r.ExpiresIn.Int64()
	if err != nil || secs <= 0 {
		return WardenToken{}, ErrBadExchangeResponse
	}
	tok := WardenToken{
		AccessToken: r.AccessToken, Scope: r.Scope,
		ReceivedAt: received, Expiry: received.Add(time.Duration(secs) * time.Second),
	}
	e.log().Debug("token exchanged", "outcome", "issued", "agent_id", e.AgentID,
		"exp", tok.Expiry, "token_fp", Fingerprint(tok.AccessToken))
	return tok, nil
}

func (e *Exchanger) parseFailure(resp *http.Response, body []byte) error {
	var r struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &r)
	code := r.Error
	if !knownCodes[code] {
		code = "error"
	}
	var err error
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		err = ErrRateLimited{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), e.now())}
	case resp.StatusCode >= 500:
		err = ErrUnavailable{RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), e.now())}
	case resp.StatusCode >= 400:
		err = ErrExchangeDenied{Code: code}
	default:
		err = ErrBadExchangeResponse
	}
	e.log().Debug("token exchange failed", "outcome", "denied", "agent_id", e.AgentID,
		"status", resp.StatusCode, "error_code", code)
	return err
}

// parseRetryAfter reads delta-seconds or an HTTP date, capped at maxRetryAfter;
// anything else is zero.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.ParseInt(v, 10, 64); err == nil {
		if secs < 0 {
			return 0
		}
		if secs > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter
		}
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, 0), maxRetryAfter)
}
