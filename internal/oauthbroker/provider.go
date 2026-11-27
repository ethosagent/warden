package oauthbroker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/ethosagent/warden/internal/config"
)

// Built-in endpoints. They are constants on purpose: a google or github
// provider with no override always talks to exactly these hosts. The only way
// to change them is an operator's explicit authURL/tokenURL/revokeURL/
// userinfoURL in the CP-local config (GitHub Enterprise Server), validated as
// https (loopback excepted) at load.
const (
	GoogleAuthURL   = "https://accounts.google.com/o/oauth2/v2/auth"
	GoogleTokenURL  = "https://oauth2.googleapis.com/token"
	GoogleRevokeURL = "https://oauth2.googleapis.com/revoke"

	GitHubAuthURL     = "https://github.com/login/oauth/authorize"
	GitHubTokenURL    = "https://github.com/login/oauth/access_token"
	GitHubRevokeURL   = "https://api.github.com/applications/{client_id}/grant"
	GitHubUserinfoURL = "https://api.github.com/user"
)

// Sentinel errors. Handlers map ErrUnknownProvider to 404/400 and
// ErrProviderUnavailable to 503 provider_unavailable.
var (
	ErrUnknownProvider     = errors.New("oauthbroker: unknown provider")
	ErrProviderUnavailable = errors.New("oauthbroker: provider client secret unavailable")
)

// SecretResolver reads a logical consent.store key (oauth-clients/<id>); the
// control plane wires it to consent.store (W-P3-BRKR-06).
type SecretResolver interface {
	ResolveSecret(ctx context.Context, key string) (string, error)
}

// secretFailCache is how long a failed consent.store read is remembered, so an
// outage costs one store call per window rather than one per request.
const secretFailCache = 5 * time.Second

// secretReadTimeout bounds the shared consent.store read.
const secretReadTimeout = 10 * time.Second

// Options are the injected dependencies of NewRegistry.
type Options struct {
	// LookupEnv reads a clientSecretEnv variable at startup (os.LookupEnv in
	// production). It is injected because this is a domain package.
	LookupEnv func(string) (string, bool)
	// Resolver reads clientSecretKey secrets; nil means none can be read yet and
	// they report ErrProviderUnavailable until a resolver exists.
	Resolver SecretResolver
	// Now is the clock for the secret-read failure cache (injected: domain code
	// does not read the wall clock). Nil disables the cache.
	Now    func() time.Time
	Logger *slog.Logger
	// HTTPClient is the SSRF-safe provider client used by Refresh (built by
	// adapters/httpclient at assembly). Nil makes Refresh return
	// ErrRefreshUnconfigured.
	HTTPClient FormPoster
}

// Provider is one configured OAuth provider with its endpoint defaults applied.
// It is immutable after NewRegistry: callers must not mutate its exported
// slices or maps (they are shared by every request). It prints only non-secret fields under
// every formatting verb and in slog.
type Provider struct {
	ID       string
	Type     string
	ClientID string
	// AuthURL, TokenURL, RevokeURL and UserinfoURL are absolute https (or
	// loopback http) URLs. RevokeURL may hold {client_id}; use RevokeEndpoint.
	AuthURL     string
	TokenURL    string
	RevokeURL   string
	UserinfoURL string
	// AllowedScopes is the operator's cap; DefaultScopes is a subset of it. Both
	// are sorted and de-duplicated. A githubApp provider has none.
	AllowedScopes []string
	DefaultScopes []string
	// ExtraAuthParams are merged into the authorization URL after the broker's
	// own parameters (config validation bars overriding those).
	ExtraAuthParams       map[string]string
	AllowedAccountDomains []string
	RequireEmailMatch     bool

	secretKey string // logical consent.store key, when the secret is not from env
	resolver  SecretResolver

	mu      sync.Mutex
	secret  Secret
	sf      singleflight.Group
	failErr error // last read failure, served for secretFailCache
	failAt  time.Time
	failTTL time.Duration
	now     func() time.Time
	// clock is now with a time.Now default; the failure cache keys off now
	// being nil, id_token expiry never may.
	clock func() time.Time

	httpc          FormPoster
	logger         *slog.Logger
	counters       *RefreshCounters
	revokeCounters *RevokeCounters

	// hinted and blockedLogged rate-limit the operator log lines to one per
	// provider until a refresh succeeds.
	hinted, blockedLogged atomic.Bool
	revokeBlockedLogged   atomic.Bool
}

// RevokeEndpoint returns RevokeURL with {client_id} replaced by the
// path-escaped client id, or "" when the provider has no revoke endpoint.
func (p *Provider) RevokeEndpoint() string {
	if p.RevokeURL == "" {
		return ""
	}
	return strings.ReplaceAll(p.RevokeURL, "{client_id}", url.PathEscape(p.ClientID))
}

// CapScopes caps requested to this provider's AllowedScopes; see CapScopes.
func (p *Provider) CapScopes(requested []string) (capped, rejected []string) {
	return CapScopes(requested, p.AllowedScopes)
}

// ClientSecret returns the client secret. An env secret was read at startup. A
// consent.store secret is read on first use when startup could not read it, and
// a failure is ErrProviderUnavailable (503 provider_unavailable); the underlying
// error is wrapped for the operator log but never carries the secret.
func (p *Provider) ClientSecret(ctx context.Context) (Secret, error) {
	if r, done := p.cachedSecret(); done {
		return r.s, r.err
	}
	// The store is called without p.mu held, and concurrent callers share one
	// read, so an outage does not queue every connect behind a slow call. The
	// shared read has its own deadline and each caller also honours its ctx.
	ch := p.sf.DoChan("secret", func() (any, error) {
		// Re-check under the lock: a read that finished after our caller's
		// check but before we joined the group must not trigger a second one.
		if r, done := p.cachedSecret(); done {
			return r, nil
		}
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), secretReadTimeout)
		defer cancel()
		val, err := p.resolver.ResolveSecret(rctx, p.secretKey)
		if err == nil && val == "" {
			err = errors.New("empty secret")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if err != nil {
			p.failErr = fmt.Errorf("%w: provider %s: %w", ErrProviderUnavailable, p.ID, err)
			if p.now != nil {
				p.failAt = p.now()
			}
			return secretResult{Secret{}, p.failErr}, nil
		}
		p.secret = NewSecret(val)
		p.failErr = nil
		return secretResult{p.secret, nil}, nil
	})
	select {
	case r := <-ch:
		res := r.Val.(secretResult)
		return res.s, res.err
	case <-ctx.Done():
		return Secret{}, fmt.Errorf("%w: provider %s: %w", ErrProviderUnavailable, p.ID, ctx.Err())
	}
}

type secretResult struct {
	s   Secret
	err error
}

// cachedSecret reports a final answer without calling the store: the cached
// secret, a configuration error, or a failure still inside its window.
func (p *Provider) cachedSecret() (secretResult, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.secret.IsZero() {
		return secretResult{p.secret, nil}, true
	}
	if p.secretKey == "" || p.resolver == nil {
		return secretResult{Secret{}, fmt.Errorf("%w: provider %s", ErrProviderUnavailable, p.ID)}, true
	}
	if p.failErr != nil && p.now != nil && p.now().Sub(p.failAt) < p.failTTL {
		return secretResult{Secret{}, p.failErr}, true
	}
	return secretResult{}, false
}

func (p *Provider) String() string {
	if p == nil {
		return "Provider(nil)"
	}
	return fmt.Sprintf("Provider{id=%s type=%s client_id=%s auth=%s token=%s client_secret=%s}", p.ID, p.Type, p.ClientID, p.AuthURL, p.TokenURL, redacted)
}

// GoString keeps %#v from walking the struct (and its secret).
func (p *Provider) GoString() string { return p.String() }

// LogValue implements slog.LogValuer with non-secret fields only.
func (p *Provider) LogValue() slog.Value {
	if p == nil {
		return slog.StringValue("nil")
	}
	return slog.GroupValue(
		slog.String("id", p.ID),
		slog.String("type", p.Type),
		slog.String("client_id", p.ClientID),
		slog.String("client_secret", redacted),
	)
}

// Registry holds the configured providers. It is fixed after NewRegistry; a
// change needs a CP restart.
type Registry struct {
	byID    map[string]*Provider
	ids     []string
	refresh RefreshCounters
	revoke  RevokeCounters
}

// NewRegistry validates cfgs (the same rules as config load), applies the
// built-in endpoint defaults and reads every clientSecretEnv. A missing or
// empty variable is a fatal error naming it. A clientSecretKey that cannot be
// read now logs WARN and is retried on first use. It logs one INFO line
// oauth_providers_loaded when there is at least one provider; with none it
// returns an empty registry and logs nothing.
func NewRegistry(cfgs []config.OAuthProviderConfig, opts Options) (*Registry, error) {
	if err := config.ValidateOAuthProviders(cfgs); err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	r := &Registry{byID: make(map[string]*Provider, len(cfgs))}
	for _, c := range cfgs {
		p, err := buildProvider(c, opts, logger, &r.refresh, &r.revoke)
		if err != nil {
			return nil, err
		}
		r.byID[p.ID] = p
		r.ids = append(r.ids, p.ID)
	}
	sort.Strings(r.ids)
	if len(r.ids) > 0 {
		logger.Info("oauth_providers_loaded", "ids", r.ids)
	}
	return r, nil
}

func buildProvider(c config.OAuthProviderConfig, opts Options, logger *slog.Logger, counters *RefreshCounters, revoke *RevokeCounters) (*Provider, error) {
	p := &Provider{
		ID:                    c.ID,
		Type:                  c.Type,
		ClientID:              c.ClientID,
		AuthURL:               c.AuthURL,
		TokenURL:              c.TokenURL,
		RevokeURL:             c.RevokeURL,
		UserinfoURL:           c.UserinfoURL,
		AllowedScopes:         normalizeScopes(c.AllowedScopes),
		DefaultScopes:         normalizeScopes(c.DefaultScopes),
		AllowedAccountDomains: append([]string(nil), c.AllowedAccountDomains...),
		RequireEmailMatch:     c.RequireEmailMatch,
		resolver:              opts.Resolver,
		failTTL:               secretFailCache,
		now:                   opts.Now,
		clock:                 nowOrDefault(opts.Now),
		httpc:                 opts.HTTPClient,
		logger:                logger,
		counters:              counters,
		revokeCounters:        revoke,
	}
	switch c.Type {
	case config.OAuthProviderGoogle:
		p.AuthURL = firstNonEmpty(c.AuthURL, GoogleAuthURL)
		p.TokenURL = firstNonEmpty(c.TokenURL, GoogleTokenURL)
		p.RevokeURL = firstNonEmpty(c.RevokeURL, GoogleRevokeURL)
		p.ExtraAuthParams = map[string]string{"access_type": "offline", "prompt": "consent"}
	case config.OAuthProviderGitHub, config.OAuthProviderGitHubApp:
		p.AuthURL = firstNonEmpty(c.AuthURL, GitHubAuthURL)
		p.TokenURL = firstNonEmpty(c.TokenURL, GitHubTokenURL)
		p.RevokeURL = firstNonEmpty(c.RevokeURL, GitHubRevokeURL)
		p.UserinfoURL = firstNonEmpty(c.UserinfoURL, GitHubUserinfoURL)
	}
	if len(c.ExtraAuthParams) > 0 && p.ExtraAuthParams == nil {
		p.ExtraAuthParams = make(map[string]string, len(c.ExtraAuthParams))
	}
	for k, v := range c.ExtraAuthParams { // operator values override type defaults
		p.ExtraAuthParams[k] = v
	}

	switch {
	case c.ClientSecretEnv != "":
		if opts.LookupEnv == nil {
			return nil, fmt.Errorf("oauthbroker: provider %q uses clientSecretEnv %s but no environment lookup was supplied", c.ID, c.ClientSecretEnv)
		}
		v, ok := opts.LookupEnv(c.ClientSecretEnv)
		if !ok || v == "" {
			return nil, fmt.Errorf("oauthbroker: provider %q: environment variable %s (consent.providers clientSecretEnv) is not set", c.ID, c.ClientSecretEnv)
		}
		p.secret = NewSecret(v)
	default:
		p.secretKey = c.ClientSecretKey
		if opts.Resolver != nil {
			if _, err := p.ClientSecret(context.Background()); err != nil {
				logger.Warn("oauth_client_secret_unavailable", "provider", c.ID, "err", err.Error())
			}
		}
	}
	return p, nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// Get returns the provider id or ErrUnknownProvider.
func (r *Registry) Get(id string) (*Provider, error) {
	if p, ok := r.byID[id]; ok {
		return p, nil
	}
	return nil, ErrUnknownProvider
}

// List returns the configured provider ids, sorted.
func (r *Registry) List() []string { return append([]string(nil), r.ids...) }

// Providers returns the configured providers in List order.
func (r *Registry) Providers() []*Provider {
	out := make([]*Provider, 0, len(r.ids))
	for _, id := range r.ids {
		out = append(out, r.byID[id])
	}
	return out
}

// Len returns the number of providers.
func (r *Registry) Len() int { return len(r.ids) }

// nowOrDefault keeps a nil clock from disabling time checks (id_token exp).
func nowOrDefault(f func() time.Time) func() time.Time {
	if f == nil {
		return time.Now
	}
	return f
}
