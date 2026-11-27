package oauthbroker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// RevokeTimeout is the per-call deadline of one provider revoke.
const RevokeTimeout = 10 * time.Second

// MaxRevokeResponseBytes caps what Revoke reads of a revoke response.
const MaxRevokeResponseBytes = 16 << 10

// The revoke error set. Revoke only calls the provider: deleting the stored
// secret and the grant row stays with the caller (RevokeUserGrant, offboarding).
var (
	// ErrRevokeUnsupported: the provider has no revoke endpoint. No HTTP call
	// was made; callers still delete the stored secret.
	ErrRevokeUnsupported = errors.New("oauthbroker: provider has no revoke endpoint")
	// ErrRevokeUnconfigured: the provider has no request-capable HTTP client
	// (a wiring bug, not a provider failure).
	ErrRevokeUnconfigured = errors.New("oauthbroker: revoke client is not configured")
)

// RevokeError is a failed revoke. It never holds a token, the client secret,
// a response body or an error_description. A blocked destination also
// satisfies errors.Is(err, ErrBlockedDestination).
type RevokeError struct {
	Provider string
	// Status is the provider's HTTP status, 0 for a transport or local failure.
	Status int
	// Retryable: network errors, 429 and 5xx. 4xx (401, 403, 422, ...) are not.
	Retryable bool
	blocked   bool
}

func (e *RevokeError) Error() string {
	kind := "failed"
	if e.Retryable {
		kind = "failed (retryable)"
	}
	if e.Status == 0 {
		return fmt.Sprintf("oauthbroker: revoke at provider %q %s: no response", e.Provider, kind)
	}
	return fmt.Sprintf("oauthbroker: revoke at provider %q %s: status %d", e.Provider, kind, e.Status)
}

// Is reports a blocked destination as ErrBlockedDestination.
func (e *RevokeError) Is(t error) bool { return e.blocked && t == ErrBlockedDestination }

// Revoke outcome labels of warden_cp_oauth_revoke_total.
const (
	RevokeOK          = "ok"
	RevokeAlready     = "already"
	RevokeRetryable   = "retryable"
	RevokeFailed      = "failed"
	RevokeUnsupported = "unsupported"
)

// RevokeCounters is the in-memory warden_cp_oauth_revoke_total{provider,
// outcome} counter; labels are configured provider ids and the fixed outcomes.
type RevokeCounters struct {
	mu sync.Mutex
	m  map[[2]string]uint64
}

func (c *RevokeCounters) inc(provider, outcome string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = make(map[[2]string]uint64)
	}
	c.m[[2]string{provider, outcome}]++
}

// Count returns the counter value for one label pair.
func (c *RevokeCounters) Count(provider, outcome string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[[2]string{provider, outcome}]
}

// Snapshot returns a copy keyed by provider then outcome.
func (c *RevokeCounters) Snapshot() map[string]map[string]uint64 {
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

// RevokeCounters returns the registry's revoke counter.
func (r *Registry) RevokeCounters() *RevokeCounters { return &r.revoke }

// Request is one outbound provider HTTP call with an arbitrary method and
// body (GitHub revoke is a DELETE with a JSON body). Never log or %v it: it
// holds credentials.
type Request struct {
	Method, URL string
	Body        []byte
	// ContentType is set when Body is non-empty.
	ContentType string
	// Accept overrides the default application/json.
	Accept string
	// BasicUser and BasicPass, when BasicUser is set, become the HTTP Basic
	// Authorization header. Callers form-urlencode them for RFC 6749 clients.
	BasicUser, BasicPass string
	// Bearer, when set, becomes the Authorization: Bearer header (userinfo).
	Bearer string
	// MaxBytes bounds the response read (the adapter reads at most MaxBytes+1
	// bytes); 0 means the adapter default, MaxProviderResponseBytes.
	MaxBytes int
}

// String, GoString and LogValue print a placeholder: a Request holds tokens
// and client credentials.
func (Request) String() string       { return redacted }
func (Request) GoString() string     { return redacted }
func (Request) LogValue() slog.Value { return slog.StringValue(redacted) }

// Requester is the second narrow provider HTTP port next to FormPoster. It
// has the same hardening contract (no environment proxy, no redirects, SSRF
// dialer returning *BlockedError, bounded by ctx plus a hard timeout, at most
// the response cap plus one byte of body, no credentials in errors) and is
// implemented by the same adapters/httpclient Poster. Revoke reaches it by
// asserting Options.HTTPClient to Requester.
type Requester interface {
	Do(ctx context.Context, r Request) (status int, body []byte, err error)
}

func (p *Provider) countRevoke(outcome string) {
	if p.revokeCounters != nil {
		p.revokeCounters.inc(p.ID, outcome)
	}
}

// Revoke ends the provider-side grant for rec. It returns nil for a revoke
// that succeeded and for a grant the provider already considers gone (Google
// 400 invalid_token, GitHub 404), so callers can treat it as idempotent. It
// returns ErrRevokeUnsupported (no HTTP call) when the provider has no revoke
// URL, and a *RevokeError otherwise.
//
// Google sends the refresh token (falling back to the access token); revoking
// either ends the whole grant. github and githubApp DELETE the app's grant for
// the user with client basic auth, which removes EVERY token of that OAuth app
// for the user, not only rec. generic is RFC 7009 with client_secret_basic.
//
// For github and githubApp with a refreshable record near or past its expiry,
// Revoke refreshes internally and the refreshed tokens are never persisted, so
// callers must treat the stored record as consumed after ANY call (a retry
// then sees the old refresh token rejected; Revoke handles that by trying the
// stored access token). The whole call, refresh included, is bounded by
// RevokeTimeout.
//
// userKey is for the log line only. Tokens, the secret and response bodies
// never appear in a log line or an error.
func Revoke(ctx context.Context, p *Provider, rec TokenRecord, clientSecret Secret, userKey string) error {
	start := time.Time{}
	if p.now != nil {
		start = p.now()
	}
	status, outcome, err := p.revoke(ctx, rec, clientSecret)
	p.countRevoke(outcome)
	if outcome == RevokeOK || outcome == RevokeAlready {
		p.revokeBlockedLogged.Store(false)
	}
	if p.logger != nil {
		var ms int64
		if p.now != nil {
			ms = p.now().Sub(start).Milliseconds()
		}
		p.logger.Info("oauth_revoke", "provider", p.ID, "user_key", userKey,
			"status", status, "outcome", outcome, "duration_ms", ms)
	}
	return err
}

func (p *Provider) revoke(ctx context.Context, rec TokenRecord, secret Secret) (status int, outcome string, err error) {
	endpoint := p.RevokeEndpoint()
	if endpoint == "" {
		return 0, RevokeUnsupported, ErrRevokeUnsupported
	}
	rq, _ := p.httpc.(Requester)
	if rq == nil {
		return 0, RevokeFailed, ErrRevokeUnconfigured
	}
	fail := func(status int) (int, string, error) {
		return status, RevokeFailed, &RevokeError{Provider: p.ID, Status: status}
	}
	if !refreshURLAllowed(endpoint) {
		return fail(0)
	}

	// One deadline covers the inner refresh and the DELETE(s).
	ctx, cancel := context.WithTimeout(ctx, RevokeTimeout)
	defer cancel()

	var req Request
	refreshed := false
	req.Method, req.URL = "POST", endpoint
	switch p.Type {
	case config.OAuthProviderGoogle:
		tok := firstNonEmpty(rec.RefreshToken, rec.AccessToken)
		if tok == "" {
			return fail(0)
		}
		req.Body = []byte(url.Values{"token": {tok}}.Encode())
		req.ContentType = "application/x-www-form-urlencoded"
	case config.OAuthProviderGitHub, config.OAuthProviderGitHubApp:
		// GitHub's grant endpoint takes the access token (a refresh token is
		// not accepted) and the client credentials as basic auth.
		access := rec.AccessToken
		if rec.Expiry > 0 && rec.RefreshToken != "" && p.now != nil && rec.Expiry <= p.now().UTC().Unix()+revokeExpirySkew {
			// An expired token would 404 as "already revoked" while the grant
			// lives on, so mint a fresh access token first. It is not persisted.
			fresh, rErr := p.refresh(ctx, rec, secret)
			switch {
			case rErr == nil:
				access, refreshed = fresh.AccessToken, true
			case errors.Is(rErr, ErrRefreshInvalidGrant):
				// The refresh token is dead, but the stored access token may
				// still be live: try it and classify the DELETE normally.
				if p.logger != nil {
					p.logger.Info("oauth_revoke_refresh", "provider", p.ID, "reason", "refresh_invalid_grant")
				}
			case errors.Is(rErr, ErrBlockedDestination):
				return 0, RevokeFailed, &RevokeError{Provider: p.ID, blocked: true}
			case errors.Is(rErr, ErrRefreshRetryable):
				return 0, RevokeRetryable, &RevokeError{Provider: p.ID, Retryable: true}
			default:
				return fail(0)
			}
		}
		if access == "" || secret.IsZero() {
			return fail(0)
		}
		b, mErr := json.Marshal(map[string]string{"access_token": access})
		if mErr != nil {
			return fail(0)
		}
		req.Method, req.Body, req.ContentType = "DELETE", b, "application/json"
		req.Accept = "application/vnd.github+json"
		req.BasicUser, req.BasicPass = p.ClientID, secret.Reveal()
	default: // generic, RFC 7009
		tok, hint := rec.RefreshToken, "refresh_token"
		if tok == "" {
			tok, hint = rec.AccessToken, "access_token"
		}
		if tok == "" || secret.IsZero() {
			return fail(0)
		}
		req.Body = []byte(url.Values{"token": {tok}, "token_type_hint": {hint}}.Encode())
		req.ContentType = "application/x-www-form-urlencoded"
		req.BasicUser, req.BasicPass = url.QueryEscape(p.ClientID), url.QueryEscape(secret.Reveal())
	}

	req.MaxBytes = MaxRevokeResponseBytes
	status, body, derr := rq.Do(ctx, req)
	if refreshed && revokeRetryable(status, derr) {
		// The refreshed (possibly rotated) refresh token is not persisted, so a
		// caller retry would see invalid_grant: retry the DELETE here once.
		status, body, derr = rq.Do(ctx, req)
	}
	if derr != nil {
		var be *BlockedError
		if errors.As(derr, &be) {
			if p.logger != nil && p.revokeBlockedLogged.CompareAndSwap(false, true) {
				p.logger.Error("oauth_revoke_blocked_destination",
					"provider", p.ID, "reason", be.Reason, "addr_class", be.AddrClass,
					"hint", "the provider revoke endpoint resolves to an address the SSRF policy refuses")
			}
			return 0, RevokeFailed, &RevokeError{Provider: p.ID, blocked: true}
		}
		// The transport error text is dropped on purpose.
		return 0, RevokeRetryable, &RevokeError{Provider: p.ID, Retryable: true}
	}
	if len(body) > MaxRevokeResponseBytes {
		body = body[:MaxRevokeResponseBytes]
	}
	switch {
	case status == 429 || status >= 500:
		return status, RevokeRetryable, &RevokeError{Provider: p.ID, Status: status, Retryable: true}
	case status >= 200 && status < 300:
		return status, RevokeOK, nil
	case status == 404 && p.githubNotFound(body):
		return status, RevokeAlready, nil
	case status == 400 && p.Type != config.OAuthProviderGitHub && p.Type != config.OAuthProviderGitHubApp:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error == "invalid_token" {
			return status, RevokeAlready, nil
		}
	}
	return fail(status)
}

// revokeExpirySkew is the margin before Expiry at which a GitHub record is
// refreshed before its DELETE.
const revokeExpirySkew = 60

// revokeRetryable: a transport failure (not an SSRF block), 429 or 5xx.
func revokeRetryable(status int, err error) bool {
	if err != nil {
		var be *BlockedError
		return !errors.As(err, &be)
	}
	return status == 429 || status >= 500
}

// githubNotFound reports whether a 404 from a github or githubApp revoke means
// "the app has no grant for this token". A 404 from anywhere else (a wrong
// host, a proxy, an HTML error page) is a failure: it must not be taken for
// success while the token stays live. The revoke host must be the token host
// or, for the built-in pair, api.github.com next to github.com.
func (p *Provider) githubNotFound(body []byte) bool {
	if p.Type != config.OAuthProviderGitHub && p.Type != config.OAuthProviderGitHubApp {
		return false
	}
	ru, err1 := url.Parse(p.RevokeEndpoint())
	tu, err2 := url.Parse(p.TokenURL)
	if err1 != nil || err2 != nil {
		return false
	}
	rh, th := ru.Hostname(), tu.Hostname()
	builtin := strings.EqualFold(th, "github.com") && strings.EqualFold(rh, "api.github.com")
	if !strings.EqualFold(rh, th) && !builtin {
		return false
	}
	var e struct {
		Message string `json:"message"`
	}
	return json.Unmarshal(body, &e) == nil && e.Message == "Not Found"
}
