// Package exchange is the oauthbroker.TokenExchanger: the authorization code
// exchange (RFC 6749 section 4.1.3 with the RFC 7636 code_verifier) over a
// hardened transport. It dials through proxy.SafeDialer, so a generic provider
// URL cannot reach a private, link-local or metadata address; it ignores the
// environment proxy; it drives an http.Transport directly, so a redirect is
// returned as is and the code and client secret are never forwarded (and no
// bare http.Client exists, architecture rule X4); it sends
// Accept: application/json, is bound by the caller's context plus a hard 10
// second cap, and refuses a response body over 64 KiB. A provider's own error
// text is never returned: only a sanitized OAuth error code survives.
//
// It deliberately does not use golang.org/x/oauth2's Config.Exchange: that
// needs an *http.Client, and a new client constructor is a protected change
// (X4 lists the shared constructors). The wire format here is the same, and the
// exchange is covered by a fake provider that checks the PKCE verifier.
package exchange

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/oauthbroker/adapters/httpclient"
	"github.com/ethosagent/warden/internal/proxy"
)

// Exchanger implements oauthbroker.TokenExchanger.
type Exchanger struct {
	post oauthbroker.FormPoster
	now  func() time.Time
}

var _ oauthbroker.TokenExchanger = (*Exchanger)(nil)

// Options configure New.
type Options struct {
	// AllowPrivate lists CIDRs exempted from the SSRF blocklist: an operator's
	// GitHub Enterprise Server on a private network, or loopback in a lab. Empty
	// in the default deployment.
	AllowPrivate []string
	// Resolver is the dialer's DNS resolver (nil = the default).
	Resolver proxy.NameResolver
	// Now is the clock that places expires_in (nil = time.Now).
	Now func() time.Time
}

// New builds the Exchanger over the shared adapters/httpclient transport (SSRF
// dialer, no proxy, no redirects, 64 KiB cap, hard timeout).
func New(opts Options) (*Exchanger, error) {
	post, err := httpclient.New(opts.AllowPrivate, opts.Resolver)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Exchanger{now: now, post: post}, nil
}

func unavailable() error {
	return &oauthbroker.ExchangeError{Kind: oauthbroker.ExchangeUnavailable}
}

func rejected(code string) error {
	return &oauthbroker.ExchangeError{Kind: oauthbroker.ExchangeRejected, Code: oauthbroker.SafeErrorCode(code)}
}

// Exchange implements oauthbroker.TokenExchanger.
func (e *Exchanger) Exchange(ctx context.Context, r oauthbroker.ExchangeRequest) (oauthbroker.TokenResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, oauthbroker.ExchangeTimeout)
	defer cancel()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {r.Code}, "redirect_uri": {r.RedirectURL},
		"client_id": {r.ClientID}, "client_secret": {r.ClientSecret.Reveal()}, "code_verifier": {r.Verifier},
	}
	status, body, err := e.post.PostForm(ctx, oauthbroker.FormRequest{URL: r.TokenURL, Form: form.Encode()})
	if err != nil {
		// The error text can name hosts and addresses (an SSRF refusal does);
		// it is dropped.
		return oauthbroker.TokenResponse{}, unavailable()
	}
	if len(body) > oauthbroker.MaxProviderResponseBytes {
		return oauthbroker.TokenResponse{}, unavailable()
	}
	if status >= 500 {
		return oauthbroker.TokenResponse{}, unavailable()
	}
	f, ok := parseBody("", body)
	// An error field is a failure whatever the status or the token fields say
	// (GitHub answers failures with HTTP 200).
	if ok && f.errCode != "" {
		code := oauthbroker.SafeErrorCode(f.errCode)
		if code == oauthbroker.ErrorCodeAccessDenied {
			return oauthbroker.TokenResponse{}, &oauthbroker.ExchangeError{Kind: oauthbroker.ExchangeDenied, Code: code}
		}
		return oauthbroker.TokenResponse{}, rejected(code)
	}
	if status < 200 || status > 299 || !ok || f.accessToken == "" {
		return oauthbroker.TokenResponse{}, rejected("invalid_response")
	}
	out := oauthbroker.TokenResponse{
		AccessToken: f.accessToken, RefreshToken: f.refreshToken, IDToken: f.idToken, TokenType: f.tokenType, Scope: f.scope,
	}
	if out.TokenType == "" {
		out.TokenType = "Bearer" // RFC 6749 requires it; x/oauth2 also defaults
	}
	now := e.now()
	if f.expiresIn > 0 {
		out.Expiry = now.Add(time.Duration(f.expiresIn) * time.Second)
	}
	if f.refreshExpiresIn > 0 {
		out.RefreshExpiry = now.Add(time.Duration(f.refreshExpiresIn) * time.Second)
	}
	return out, nil
}

// fields are the members of a token endpoint response the broker reads.
type fields struct {
	accessToken, refreshToken, idToken, tokenType, scope, errCode string
	expiresIn, refreshExpiresIn                                   int64
}

// parseBody reads a JSON body (the normal case) or a form-encoded one (GitHub
// when Accept is not honoured). ok is false when the body is neither.
func parseBody(contentType string, body []byte) (fields, bool) {
	trimmed := bytes.TrimSpace(body)
	if strings.Contains(contentType, "json") || bytes.HasPrefix(trimmed, []byte("{")) {
		var m map[string]json.RawMessage
		if json.Unmarshal(trimmed, &m) != nil {
			return fields{}, false
		}
		f := fields{
			accessToken: str(m["access_token"]), refreshToken: str(m["refresh_token"]), idToken: str(m["id_token"]),
			tokenType: str(m["token_type"]), scope: str(m["scope"]),
			expiresIn: num(m["expires_in"]), refreshExpiresIn: num(m["refresh_token_expires_in"]),
		}
		if raw, present := m["error"]; present && string(raw) != "null" {
			// An object or number is still an error; only a string is a code.
			f.errCode = str(raw)
			if f.errCode == "" {
				f.errCode = "invalid_response"
			}
		}
		return f, true
	}
	v, err := url.ParseQuery(string(trimmed))
	if err != nil || len(v) == 0 {
		return fields{}, false
	}
	n := func(k string) int64 { i, _ := strconv.ParseInt(v.Get(k), 10, 64); return i }
	return fields{
		accessToken: v.Get("access_token"), refreshToken: v.Get("refresh_token"), idToken: v.Get("id_token"), tokenType: v.Get("token_type"),
		scope: v.Get("scope"), errCode: v.Get("error"), expiresIn: n("expires_in"), refreshExpiresIn: n("refresh_token_expires_in"),
	}, true
}

// str reads a JSON string member ("" for anything else).
func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// num reads a JSON number or a numeric string (0 otherwise).
func num(raw json.RawMessage) int64 {
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			return int64(f)
		}
	}
	return 0
}
