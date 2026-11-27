package oauthbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// MaxProviderResponseBytes caps every provider token-endpoint response body.
const MaxProviderResponseBytes = 64 << 10

// RefreshTimeout is the per-call deadline of one refresh_token exchange.
const RefreshTimeout = 5 * time.Second

// The refresh error set is closed. Callers branch with errors.Is; no error
// holds a token, the client secret, a response body or an error_description,
// only (at most) the sanitised OAuth error code.
var (
	// ErrNotRefreshable: the record has no refresh token (a GitHub OAuth-app
	// token never expires and has none). No HTTP call was made.
	ErrNotRefreshable = errors.New("oauthbroker: grant is not refreshable")
	// ErrRefreshInvalidGrant: the provider rejected the refresh token
	// (invalid_grant, or GitHub's bad_refresh_token). The user must reconsent.
	ErrRefreshInvalidGrant = errors.New("oauthbroker: refresh token rejected (reconsent required)")
	// ErrRefreshInvalidClient: the provider rejected the client credentials
	// (invalid_client / 401). An operator error, not the user's grant. It also
	// satisfies errors.Is(err, ErrRefreshPermanent).
	ErrRefreshInvalidClient = errors.New("oauthbroker: provider rejected the client credentials")
	// ErrRefreshPermanent: another definite provider refusal (4xx, malformed
	// 200, an error field). Retrying the same request will not help.
	ErrRefreshPermanent = errors.New("oauthbroker: provider refused the refresh")
	// ErrRefreshRetryable: 429, 5xx or a transport failure. The grant is
	// untouched; try again later.
	ErrRefreshRetryable = errors.New("oauthbroker: provider refresh failed (retryable)")
	// ErrRefreshUnconfigured: the provider has no HTTP client or clock (a
	// wiring bug, not a provider failure).
	ErrRefreshUnconfigured = errors.New("oauthbroker: refresh client is not configured")
)

type refreshInvalidClient struct{}

func (refreshInvalidClient) Error() string { return ErrRefreshInvalidClient.Error() }
func (refreshInvalidClient) Is(t error) bool {
	return t == ErrRefreshInvalidClient || t == ErrRefreshPermanent
}

// FormRequest is one form POST to a provider token endpoint.
type FormRequest struct {
	URL  string
	Form string // application/x-www-form-urlencoded body
	// BasicUser and BasicPass, when BasicUser is set, become the HTTP Basic
	// Authorization header (client_secret_basic), already form-urlencoded.
	BasicUser, BasicPass string
}

// FormPoster is the provider HTTP port. Implementations send Accept:
// application/json, follow no redirects (a 3xx is returned as is), bound the
// call by ctx, return at most MaxProviderResponseBytes+1 body bytes, and never
// put credentials in a returned error. Production gets the SSRF-safe
// implementation from adapters/httpclient (assembly injects it through
// Options.HTTPClient); tests inject an httptest-backed one.
type FormPoster interface {
	PostForm(ctx context.Context, r FormRequest) (status int, body []byte, err error)
}

// RefreshOutcome names the outcome label of warden_cp_oauth_refresh_total.
const (
	RefreshOK            = "ok"
	RefreshInvalidGrant  = "invalid_grant"
	RefreshInvalidClient = "invalid_client"
	RefreshPermanent     = "permanent"
	RefreshRetryable     = "retryable"
	RefreshNotRefresh    = "not_refreshable"
	RefreshUnconfigured  = "unconfigured"
)

// RefreshCounters is the in-memory warden_cp_oauth_refresh_total{provider,
// outcome} counter. Labels use configured provider ids and the fixed outcome
// names only.
type RefreshCounters struct {
	mu sync.Mutex
	m  map[[2]string]uint64
}

func (c *RefreshCounters) inc(provider, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[[2]string]uint64)
	}
	c.m[[2]string{provider, outcome}]++
}

// Count returns the counter value for one label pair.
func (c *RefreshCounters) Count(provider, outcome string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[[2]string{provider, outcome}]
}

// Snapshot returns a copy keyed by provider then outcome.
func (c *RefreshCounters) Snapshot() map[string]map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]map[string]uint64)
	for k, v := range c.m {
		if out[k[0]] == nil {
			out[k[0]] = make(map[string]uint64)
		}
		out[k[0]][k[1]] = v
	}
	return out
}

// RefreshCounters returns the registry's refresh counter.
func (r *Registry) RefreshCounters() *RefreshCounters { return &r.refresh }

// flexInt decodes a JSON number or a numeric string (some providers quote it).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		fl, ferr := strconv.ParseFloat(s, 64)
		if ferr != nil {
			return errors.New("not a number")
		}
		n = int64(fl)
	}
	*f = flexInt(n)
	return nil
}

type refreshResponse struct {
	AccessToken      string  `json:"access_token"`
	TokenType        string  `json:"token_type"`
	RefreshToken     string  `json:"refresh_token"`
	Scope            string  `json:"scope"`
	ExpiresIn        flexInt `json:"expires_in"`
	RefreshExpiresIn flexInt `json:"refresh_token_expires_in"`
	Error            string  `json:"error"`
}

// Refresh exchanges rec's refresh token at provider's token endpoint and
// returns the updated record. The CP is the only caller (the W-P3-PUS-03
// engine); the caller persists the result (a rotated refresh token is in it)
// before using the new access token.
//
// google and generic send client_secret_basic; github and githubApp send
// client_secret_post. The returned record keeps grant_id, provider, client_id
// and, when the response has none, the stored refresh token (and its expiry).
func Refresh(ctx context.Context, p *Provider, rec TokenRecord, clientSecret Secret) (TokenRecord, error) {
	out, err := p.refresh(ctx, rec, clientSecret)
	p.countRefresh(err)
	return out, err
}

func (p *Provider) countRefresh(err error) {
	if p.counters == nil {
		return
	}
	var outcome string
	switch {
	case err == nil:
		outcome = RefreshOK
	case errors.Is(err, ErrNotRefreshable):
		outcome = RefreshNotRefresh
	case errors.Is(err, ErrRefreshInvalidGrant):
		outcome = RefreshInvalidGrant
	case errors.Is(err, ErrRefreshInvalidClient):
		outcome = RefreshInvalidClient
	case errors.Is(err, ErrRefreshRetryable):
		outcome = RefreshRetryable
	case errors.Is(err, ErrRefreshUnconfigured):
		outcome = RefreshUnconfigured
	default:
		outcome = RefreshPermanent
	}
	p.counters.inc(p.ID, outcome)
}

func (p *Provider) refresh(ctx context.Context, rec TokenRecord, clientSecret Secret) (TokenRecord, error) {
	if rec.RefreshToken == "" {
		return TokenRecord{}, ErrNotRefreshable
	}
	if p.httpc == nil || p.now == nil {
		return TokenRecord{}, ErrRefreshUnconfigured
	}
	if clientSecret.IsZero() {
		return TokenRecord{}, fmt.Errorf("%w: no client secret", ErrRefreshUnconfigured)
	}
	if !refreshURLAllowed(p.TokenURL) {
		return TokenRecord{}, fmt.Errorf("%w: token endpoint is not https", ErrRefreshPermanent)
	}

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rec.RefreshToken}}
	post := p.Type == config.OAuthProviderGitHub || p.Type == config.OAuthProviderGitHubApp
	if post {
		form.Set("client_id", p.ClientID)
		form.Set("client_secret", clientSecret.Reveal())
	}
	ctx, cancel := context.WithTimeout(ctx, RefreshTimeout)
	defer cancel()
	fr := FormRequest{URL: p.TokenURL, Form: form.Encode()}
	if !post {
		// RFC 6749 2.3.1: the id and secret are form-urlencoded before base64.
		fr.BasicUser, fr.BasicPass = url.QueryEscape(p.ClientID), url.QueryEscape(clientSecret.Reveal())
	}

	status, body, err := p.httpc.PostForm(ctx, fr)
	if err != nil {
		// The transport error text is dropped on purpose: only the class is kept.
		return TokenRecord{}, fmt.Errorf("%w: transport failure", ErrRefreshRetryable)
	}
	if len(body) > MaxProviderResponseBytes {
		return TokenRecord{}, fmt.Errorf("%w: response too large", ErrRefreshPermanent)
	}
	var tr refreshResponse
	parsed := json.Unmarshal(body, &tr) == nil
	code := sanitizeOAuthCode(tr.Error)

	switch {
	case status == 429 || status >= 500:
		return TokenRecord{}, fmt.Errorf("%w: status %d", ErrRefreshRetryable, status)
	case status != 200:
		if !parsed {
			code = ""
		}
		err := p.classify(code, status)
		return TokenRecord{}, err
	case !parsed:
		return TokenRecord{}, fmt.Errorf("%w: malformed response", ErrRefreshPermanent)
	case tr.Error != "":
		return TokenRecord{}, p.classify(code, status)
	case tr.AccessToken == "":
		return TokenRecord{}, fmt.Errorf("%w: response has no access token", ErrRefreshPermanent)
	}

	now := p.now().UTC().Unix()
	out := rec
	out.AccessToken = tr.AccessToken
	if tr.TokenType != "" {
		out.TokenType = tr.TokenType
	}
	if tr.Scope != "" {
		out.Scope = strings.Join(ParseScopes(tr.Scope), " ")
	}
	out.ObtainedAt = now
	out.Expiry = 0
	if tr.ExpiresIn > 0 {
		out.Expiry = now + int64(tr.ExpiresIn)
	}
	if tr.RefreshToken != "" {
		out.RefreshToken = tr.RefreshToken
		out.RefreshExpiry = 0
		if tr.RefreshExpiresIn > 0 {
			out.RefreshExpiry = now + int64(tr.RefreshExpiresIn)
		}
	} else if tr.RefreshExpiresIn > 0 {
		out.RefreshExpiry = now + int64(tr.RefreshExpiresIn)
	}
	return out, nil
}

// classify maps an OAuth error code (already sanitised; "" when unknown) and
// status to the closed error set. Only the code is ever kept in the message.
func (p *Provider) classify(code string, status int) error {
	switch {
	case code == "invalid_grant" || code == "bad_refresh_token":
		return fmt.Errorf("%w: %s", ErrRefreshInvalidGrant, code)
	case code == "invalid_client" || status == 401:
		if p.logger != nil {
			p.logger.Error("oauth_refresh_invalid_client",
				"provider", p.ID,
				"hint", "the provider rejected the client credentials; check the consent.providers client secret and restart the control plane after rotating it")
		}
		return fmt.Errorf("%w: %w", refreshInvalidClient{}, errors.New(orUnknown(code)))
	case code != "":
		return fmt.Errorf("%w: %s", ErrRefreshPermanent, code)
	case status == 200:
		return fmt.Errorf("%w: unrecognised error", ErrRefreshPermanent)
	default:
		return fmt.Errorf("%w: status %d", ErrRefreshPermanent, status)
	}
}

func orUnknown(code string) string {
	if code == "" {
		return "unauthorized"
	}
	return code
}

// sanitizeOAuthCode keeps an OAuth error code only when it is a short token of
// [A-Za-z0-9_.-]; anything else (free text that could echo a secret) is dropped.
func sanitizeOAuthCode(s string) string {
	if s == "" || len(s) > 64 {
		if s != "" {
			return "unrecognized"
		}
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
		default:
			return "unrecognized"
		}
	}
	return s
}

// refreshURLAllowed: https, or http on a loopback host.
func refreshURLAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "::1" || strings.HasPrefix(h, "127.")
}
