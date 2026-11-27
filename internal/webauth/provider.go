package webauth

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"golang.org/x/oauth2"
)

const (
	// DiscoveryBackoffMin and DiscoveryBackoffMax bound the retry delay of a
	// failed discovery.
	DiscoveryBackoffMin = time.Second
	DiscoveryBackoffMax = 30 * time.Second
	// DiscoveryTimeout bounds one discovery attempt.
	DiscoveryTimeout = 10 * time.Second
)

// Endpoints are the two OAuth endpoints a login needs, as the provider's
// discovery document publishes them.
type Endpoints struct {
	AuthURL, TokenURL string
}

// ProviderConfig configures NewProvider. The consumer builds the shared OIDC
// HTTP client from its section's issuer and internalIssuerURL and passes it in
// through Discover and HTTPContext, so this package never builds a client.
type ProviderConfig struct {
	// Name is the front door ("console", "portal"). It only labels log lines.
	Name string
	// Issuer is the configured issuer, logged on discovery.
	Issuer string
	// OAuth is the client: ClientID, ClientSecret, RedirectURL and Scopes. Its
	// Endpoint is filled from discovery.
	OAuth oauth2.Config
	// Discover fetches the provider's endpoints through the shared client.
	// Nil leaves the provider never ready (login answers 503).
	Discover func(ctx context.Context) (Endpoints, error)
	// HTTPContext returns ctx carrying the shared client, for the code
	// exchange and the ID-token verification. Nil uses ctx unchanged.
	HTTPContext func(ctx context.Context) context.Context
	Logger      *slog.Logger
}

// Provider is an OIDC provider discovered lazily: Run retries discovery with
// backoff until it succeeds, and until then the provider is not ready, so an
// unreachable IdP never delays startup and never affects anything but login.
// A nil *Provider is never ready.
type Provider struct {
	cfg                    ProviderConfig
	endpoints              atomic.Pointer[Endpoints]
	backoffMin, backoffMax time.Duration
}

// NewProvider builds a provider. It does no network I/O.
func NewProvider(cfg ProviderConfig) *Provider {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Provider{cfg: cfg, backoffMin: DiscoveryBackoffMin, backoffMax: DiscoveryBackoffMax}
}

// SetBackoff replaces the discovery retry bounds. Call it before Run; tests
// use it to retry quickly. A nil provider ignores it.
func (p *Provider) SetBackoff(minWait, maxWait time.Duration) {
	if p == nil {
		return
	}
	p.backoffMin, p.backoffMax = minWait, maxWait
}

// SetEndpoints marks the provider discovered with ep, as a successful Run
// would.
func (p *Provider) SetEndpoints(ep Endpoints) { p.endpoints.Store(&ep) }

// Run fetches the provider's endpoints, retrying with backoff until it
// succeeds or ctx is done.
func (p *Provider) Run(ctx context.Context) {
	if p == nil || p.cfg.Discover == nil {
		return
	}
	wait := p.backoffMin
	for {
		dctx, cancel := context.WithTimeout(ctx, DiscoveryTimeout)
		ep, err := p.cfg.Discover(dctx)
		cancel()
		if err == nil {
			p.SetEndpoints(ep)
			p.cfg.Logger.Info("control plane: "+p.cfg.Name+" oidc discovery succeeded", "issuer", p.cfg.Issuer)
			return
		}
		p.cfg.Logger.Warn("control plane: "+p.cfg.Name+" oidc discovery failed; login stays unavailable and will be retried",
			"issuer", p.cfg.Issuer, "retry_in", wait.String(), "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = min(wait*2, p.backoffMax)
	}
}

// Ready reports whether discovery has succeeded.
func (p *Provider) Ready() bool { return p != nil && p.endpoints.Load() != nil }

// Config returns the oauth config with the discovered endpoints, or false
// while discovery has not succeeded.
func (p *Provider) Config() (oauth2.Config, bool) {
	if p == nil {
		return oauth2.Config{}, false
	}
	ep := p.endpoints.Load()
	if ep == nil {
		return oauth2.Config{}, false
	}
	c := p.cfg.OAuth
	c.Endpoint = oauth2.Endpoint{AuthURL: ep.AuthURL, TokenURL: ep.TokenURL, AuthStyle: oauth2.AuthStyleInHeader}
	return c, true
}

// httpContext returns ctx carrying the shared client.
func (p *Provider) httpContext(ctx context.Context) context.Context {
	if p.cfg.HTTPContext == nil {
		return ctx
	}
	return p.cfg.HTTPContext(ctx)
}
