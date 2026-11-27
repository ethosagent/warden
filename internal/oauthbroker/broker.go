package oauthbroker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/ratelimit"
)

// StartsPerMinute is the POST /connect/start rate limit per user_key (the
// ratelimit token bucket assembly builds: StartsPerMinute events per minute).
const StartsPerMinute = 10

// BlockChecker is the block list as the broker reads it. The control plane
// implements it over its BlockStore snapshot; an error (the list is not
// loaded) must be treated as "cannot tell" and fail closed, never as "not
// blocked". email is matched lowercased only when the caller vouches for it.
type BlockChecker interface {
	IsBlocked(ctx context.Context, sub, email string) (bool, error)
}

// Config is what New needs. Registry, Store, Blocks, RedirectURL, UserKey,
// Rand and Now are required; Limiter and Logger are optional.
type Config struct {
	Registry *Registry
	Store    GrantStore
	Blocks   BlockChecker
	// Limiter throttles starts per user_key; nil allows all (tests).
	Limiter ratelimit.RateLimiter
	// RedirectURL is consent.connect.redirectURL, the provider's callback.
	RedirectURL string
	// UserKey derives the user_key from the VERIFIED (iss, sub) of the portal
	// session; assembly injects secrets.UserKey (a repository this domain may
	// not import).
	UserKey func(iss, sub string) (string, error)
	// Rand is the entropy for state, verifier and cookie values (crypto/rand
	// in production; injected because this is a domain package).
	Rand io.Reader
	Now  func() time.Time
	// Logger may be nil (slog.Default).
	Logger *slog.Logger

	// The fields below are needed only by Callback and Reconcile (W-P3-BRKR-04);
	// Start works without them, and Callback answers CodeInternal when one of
	// Vault, GrantKey and Exchanger is missing.

	// Vault is consent.store, where the TokenRecord lives.
	Vault TokenVault
	// GrantKey builds the logical consent.store key of a grant
	// (secrets.UserGrantKey; injected like UserKey).
	GrantKey func(userKey, provider string) (string, error)
	// NotFound reports whether a Vault.Get error means "no such key"
	// (secrets.ErrSecretNotFound).
	NotFound func(error) bool
	// Exchanger performs the code exchange over an SSRF-safe client.
	Exchanger TokenExchanger
	// Audit records connect.granted and connect.denied; nil means admin audit
	// is off.
	Audit AuditSink
	// Locks is the per-(userKey, provider) mutex shared with the refresh
	// engine, revoke and offboarding; nil means a private set (tests).
	Locks *GrantLocks
}

// Broker runs the connect flows of the OAuth broker. It is safe for
// concurrent use.
type Broker struct {
	reg     *Registry
	store   GrantStore
	blocks  BlockChecker
	limiter ratelimit.RateLimiter
	redir   string
	userKey func(iss, sub string) (string, error)
	rand    io.Reader
	now     func() time.Time
	logger  *slog.Logger

	vault     TokenVault
	grantKey  func(userKey, provider string) (string, error)
	notFound  func(error) bool
	exchanger TokenExchanger
	audit     AuditSink
	locks     *GrantLocks

	metrics connectMetrics
}

// New returns a Broker over cfg, or an error naming the missing piece.
func New(cfg Config) (*Broker, error) {
	switch {
	case cfg.Registry == nil:
		return nil, errors.New("oauthbroker: Config.Registry is required")
	case cfg.Store == nil:
		return nil, errors.New("oauthbroker: Config.Store is required")
	case cfg.Blocks == nil:
		return nil, errors.New("oauthbroker: Config.Blocks is required")
	case cfg.RedirectURL == "":
		return nil, errors.New("oauthbroker: Config.RedirectURL is required")
	case cfg.UserKey == nil:
		return nil, errors.New("oauthbroker: Config.UserKey is required")
	case cfg.Rand == nil:
		return nil, errors.New("oauthbroker: Config.Rand is required")
	case cfg.Now == nil:
		return nil, errors.New("oauthbroker: Config.Now is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	locks := cfg.Locks
	if locks == nil {
		locks = NewGrantLocks()
	}
	notFound := cfg.NotFound
	if notFound == nil {
		notFound = func(error) bool { return false }
	}
	return &Broker{
		reg: cfg.Registry, store: cfg.Store, blocks: cfg.Blocks, limiter: cfg.Limiter,
		redir: cfg.RedirectURL, userKey: cfg.UserKey, rand: cfg.Rand, now: cfg.Now, logger: logger,
		vault: cfg.Vault, grantKey: cfg.GrantKey, notFound: notFound, exchanger: cfg.Exchanger,
		audit: cfg.Audit, locks: locks,
		metrics: connectMetrics{counts: map[ConnectKey]uint64{}, exchange: map[string]*exchangeTiming{}},
	}, nil
}

// Stages and outcomes of warden_cp_oauth_connect_total{provider,stage,outcome}.
const (
	StageStart    = "start"
	StageCallback = "callback"

	OutcomeOK     = "ok"
	OutcomeDenied = "denied"
	OutcomeError  = "error"
)

// ConnectKey labels one warden_cp_oauth_connect_total series. Provider is a
// configured provider id, or UnknownProviderLabel for a request that named
// none (a request value is never a label).
type ConnectKey struct {
	Provider, Stage, Outcome string
}

// UnknownProviderLabel is the provider label of a start that named an
// unconfigured provider.
const UnknownProviderLabel = "unknown"

type connectMetrics struct {
	mu       sync.Mutex
	counts   map[ConnectKey]uint64
	exchange map[string]*exchangeTiming
	orphans  int
}

// exchangeTiming is the sum and count behind
// warden_cp_oauth_token_exchange_seconds{provider}.
type exchangeTiming struct {
	count uint64
	sum   time.Duration
}

func (m *connectMetrics) inc(k ConnectKey) {
	m.mu.Lock()
	m.counts[k]++
	m.mu.Unlock()
}

// ConnectCounts returns warden_cp_oauth_connect_total since start, a copy.
// W-P5-RETN-06 adds it to the export list.
func (b *Broker) ConnectCounts() map[ConnectKey]uint64 {
	b.metrics.mu.Lock()
	defer b.metrics.mu.Unlock()
	out := make(map[ConnectKey]uint64, len(b.metrics.counts))
	for k, v := range b.metrics.counts {
		out[k] = v
	}
	return out
}

// Providers returns the configured provider ids, sorted.
func (b *Broker) Providers() []string {
	ids := b.reg.List()
	sort.Strings(ids)
	return ids
}
