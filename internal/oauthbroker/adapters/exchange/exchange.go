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
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/proxy"
)

// DialTimeout bounds connect, TLS handshake and response headers.
const DialTimeout = 5 * time.Second

// Exchanger implements oauthbroker.TokenExchanger.
type Exchanger struct {
	rt  http.RoundTripper
	now func() time.Time
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

// New builds the Exchanger.
func New(opts Options) (*Exchanger, error) {
	sd, err := proxy.NewSafeDialerWithResolver(DialTimeout, opts.AllowPrivate, opts.Resolver)
	if err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Exchanger{now: now, rt: &http.Transport{
		Proxy: nil,
		DialTLSContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return sd.DialTLS(network, addr, &tls.Config{MinVersion: tls.VersionTLS12})
		},
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return sd.Dial(network, addr)
		},
		TLSHandshakeTimeout:   DialTimeout,
		ResponseHeaderTimeout: DialTimeout,
		// An exchange happens once per consent, so a pooled connection would
		// idle for nothing (and outlive the control plane's shutdown).
		DisableKeepAlives: true,
	}}, nil
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return oauthbroker.TokenResponse{}, unavailable()
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := e.rt.RoundTrip(req)
	if err != nil {
		// The error text can name hosts and addresses (an SSRF refusal does);
		// it is dropped.
		return oauthbroker.TokenResponse{}, unavailable()
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, oauthbroker.MaxProviderResponseBytes+1))
	if err != nil || len(body) > oauthbroker.MaxProviderResponseBytes {
		return oauthbroker.TokenResponse{}, unavailable()
	}
	if resp.StatusCode >= 500 {
		return oauthbroker.TokenResponse{}, unavailable()
	}
	f, ok := parseBody(resp.Header.Get("Content-Type"), body)
	// An error field is a failure whatever the status or the token fields say
	// (GitHub answers failures with HTTP 200).
	if ok && f.errCode != "" {
		code := oauthbroker.SafeErrorCode(f.errCode)
		if code == oauthbroker.ErrorCodeAccessDenied {
			return oauthbroker.TokenResponse{}, &oauthbroker.ExchangeError{Kind: oauthbroker.ExchangeDenied, Code: code}
		}
		return oauthbroker.TokenResponse{}, rejected(code)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || !ok || f.accessToken == "" {
		return oauthbroker.TokenResponse{}, rejected("invalid_response")
	}
	out := oauthbroker.TokenResponse{
		AccessToken: f.accessToken, RefreshToken: f.refreshToken, TokenType: f.tokenType, Scope: f.scope,
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
	accessToken, refreshToken, tokenType, scope, errCode string
	expiresIn, refreshExpiresIn                          int64
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
			accessToken: str(m["access_token"]), refreshToken: str(m["refresh_token"]),
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
		accessToken: v.Get("access_token"), refreshToken: v.Get("refresh_token"), tokenType: v.Get("token_type"),
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
