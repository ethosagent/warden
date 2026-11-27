package oauthbroker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"
)

// MaxProviderResponseBytes caps a provider token endpoint response. A real
// response is well under 8 KiB; the cap is the transport's, so a hostile or
// broken endpoint cannot make the control plane buffer an unbounded body.
const MaxProviderResponseBytes = 64 << 10

// ExchangeTimeout bounds one authorization code exchange.
const ExchangeTimeout = 10 * time.Second

// ExchangeRequest is one authorization code exchange (RFC 6749 section 4.1.3
// with the RFC 7636 code_verifier). Code, Verifier and ClientSecret are
// secrets: the type prints none of them under any formatting verb or in slog,
// so passing it to a logger by mistake stays safe.
type ExchangeRequest struct {
	TokenURL     string
	ClientID     string
	ClientSecret Secret
	Code         string
	Verifier     string
	RedirectURL  string
}

func (r ExchangeRequest) String() string {
	return fmt.Sprintf("ExchangeRequest{token_url=%s client_id=%s code=%s verifier=%s client_secret=%s}",
		r.TokenURL, r.ClientID, redacted, redacted, redacted)
}

// GoString keeps %#v from printing the code and verifier.
func (r ExchangeRequest) GoString() string { return r.String() }

// LogValue implements slog.LogValuer with the non-secret fields only.
func (r ExchangeRequest) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_url", r.TokenURL), slog.String("client_id", r.ClientID))
}

// TokenResponse is what a successful exchange returns. Scope is the provider's
// scope string as sent ("" when absent). Expiry and RefreshExpiry are absolute
// times; zero means the provider sent none. It redacts itself like
// TokenRecord.
type TokenResponse struct {
	AccessToken   string
	RefreshToken  string
	TokenType     string
	Scope         string
	Expiry        time.Time
	RefreshExpiry time.Time
}

func (r TokenResponse) String() string {
	return fmt.Sprintf("TokenResponse{token_type=%s scope=%q expiry=%s access_token=%s has_refresh_token=%t}",
		r.TokenType, r.Scope, r.Expiry.UTC().Format(time.RFC3339), redacted, r.RefreshToken != "")
}

// GoString keeps %#v from printing the tokens.
func (r TokenResponse) GoString() string { return r.String() }

// LogValue implements slog.LogValuer with the non-secret fields only.
func (r TokenResponse) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_type", r.TokenType), slog.String("scope", r.Scope),
		slog.Bool("has_refresh_token", r.RefreshToken != ""))
}

// TokenExchanger performs the code exchange against a provider token endpoint.
// The adapter (oauthbroker/adapters/exchange) dials through the SSRF-safe
// dialer, ignores the environment proxy, follows no redirect, bounds the call
// and caps the response; the domain only sees the outcome. A failure is an
// *ExchangeError.
type TokenExchanger interface {
	Exchange(ctx context.Context, req ExchangeRequest) (TokenResponse, error)
}

// ExchangeKind classifies a failed exchange.
type ExchangeKind int

const (
	// ExchangeDenied: the provider (or the user at the provider) refused with
	// error=access_denied.
	ExchangeDenied ExchangeKind = iota + 1
	// ExchangeRejected: the provider answered with an OAuth error (invalid_grant
	// and the like, including GitHub's HTTP 200 with an error field) or an
	// unusable token response (no access token, a token type that is not bearer).
	ExchangeRejected
	// ExchangeUnavailable: no usable answer: a transport failure, a timeout, an
	// oversized body, a 5xx, or a destination the SSRF guard refused.
	ExchangeUnavailable
)

// ErrorCodeAccessDenied is the OAuth error code of a user's refusal.
const ErrorCodeAccessDenied = "access_denied"

// ExchangeError is a failed code exchange. Code is a sanitized OAuth error
// code (SafeErrorCode), never the provider's error_description or body.
type ExchangeError struct {
	Kind ExchangeKind
	Code string
}

func (e *ExchangeError) Error() string {
	switch e.Kind {
	case ExchangeDenied:
		return "oauthbroker: code exchange denied by the provider"
	case ExchangeRejected:
		return "oauthbroker: code exchange rejected: " + e.Code
	default:
		return "oauthbroker: code exchange unavailable"
	}
}

var (
	// ErrExchangeDenied, ErrExchangeRejected and ErrExchangeUnavailable match an
	// *ExchangeError of that kind with errors.Is.
	ErrExchangeDenied      = errors.New("oauthbroker: exchange denied")
	ErrExchangeRejected    = errors.New("oauthbroker: exchange rejected")
	ErrExchangeUnavailable = errors.New("oauthbroker: exchange unavailable")
)

// Is lets errors.Is match the sentinels above.
func (e *ExchangeError) Is(target error) bool {
	switch e.Kind {
	case ExchangeDenied:
		return target == ErrExchangeDenied
	case ExchangeRejected:
		return target == ErrExchangeRejected
	case ExchangeUnavailable:
		return target == ErrExchangeUnavailable
	}
	return false
}

var errorCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)

// SafeErrorCode returns code when it is a plausible OAuth error code (RFC 6749
// section 5.2 uses [A-Za-z0-9_] words) and "invalid_response" otherwise, so a
// hostile token endpoint cannot put text in a log line or an audit row.
func SafeErrorCode(code string) string {
	if errorCodeRE.MatchString(code) {
		return code
	}
	return "invalid_response"
}
