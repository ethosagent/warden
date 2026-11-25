package controlplane

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	agentregsqlite "github.com/ethosagent/warden/internal/agentreg/adapters/sqlite"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/tokensvc"
	tokensvcsqlite "github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
)

// tokenOverlapSlack is what keys.token.overlap must exceed the token ttl by:
// worker clock skew (1m) plus one long-poll wait (1m), so a key that stopped
// signing keeps verifying until the last token it signed is gone everywhere.
const tokenOverlapSlack = 2 * time.Minute

// resolveTokenService reads the tokenService block from the operator-owned
// --config file (never the served copy, like console: and keys:) and checks
// what an enabled service needs at startup, each failure naming the setting
// at fault: a state dir, a served identity issuer and audience, keys.enabled,
// and a token key overlap that covers the ttl. The block is the only switch:
// absent or disabled it returns the disabled default and nothing else runs.
func resolveTokenService(logger *slog.Logger, configPath, stateDir string, id config.IdentitySettings, kc config.KeysConfig) (config.TokenServiceConfig, error) {
	tc := config.DefaultTokenService()
	if configPath != "" {
		var err error
		if tc, err = config.LoadTokenService(configPath); err != nil {
			return config.TokenServiceConfig{}, fmt.Errorf("control-plane: %w", err)
		}
	}
	if !tc.Enabled {
		return tc, nil
	}
	switch {
	case stateDir == "":
		return config.TokenServiceConfig{}, errors.New("control-plane: tokenService.enabled needs --state-dir (replay protection and token sessions live in the state database)")
	case id.Issuer == "" || id.Audience == "":
		return config.TokenServiceConfig{}, errors.New("control-plane: tokenService.enabled needs a served identity block with issuer and audience (subject tokens are verified against the same IdP as workers)")
	case !kc.Enabled:
		return config.TokenServiceConfig{}, errors.New("control-plane: tokenService.enabled needs keys.enabled: true (issued tokens are signed with the token key)")
	case sameIssuer(tc.Issuer, id.Issuer):
		// A shared issuer would let a worker accept an IdP-issued token where a
		// Warden token is expected (and the other way round): the two token
		// kinds are told apart by their issuer.
		return config.TokenServiceConfig{}, fmt.Errorf("control-plane: tokenService.issuer %q must differ from identity.issuer %q (Warden tokens and IdP tokens are told apart by their issuer)", tc.Issuer, id.Issuer)
	}
	if need := tc.TTL + tokenOverlapSlack; kc.Token.Overlap < need {
		return config.TokenServiceConfig{}, fmt.Errorf("control-plane: keys.token.overlap %s is below tokenService.ttl + 2m (%s): a retired key must keep verifying until the last token it signed expires", kc.Token.Overlap, need)
	}
	return tc, nil
}

// sameIssuer reports whether two issuer URLs name the same issuer, ignoring a
// trailing slash and ASCII case (scheme and host are case-insensitive, and an
// operator typing one with a slash must not slip past the collision check).
func sameIssuer(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(strings.TrimSpace(a), "/"), strings.TrimRight(strings.TrimSpace(b), "/"))
}

// tokenKeyPublishWindow is how long a token key must have been published
// before the service mints with it: the longest policy long-poll wait (a
// worker that polled just before the key appeared learns of it one wait later)
// plus the worker's clock skew. Normal rotations never wait on it, because
// keys.token.prepublish (min 10m) already covers the window; only a first key
// and an emergency promotion of a barely published key do.
const tokenKeyPublishWindow = maxLongPollWait + time.Minute

// servedSigners hands out the token key only once verifiers can be expected to
// hold it: the active key must have been published (its persisted PublishAt)
// for tokenKeyPublishWindow. Until then the service answers signer_unavailable
// with Retry-After instead of minting a token no worker can verify yet. The
// window comes from the persisted key metadata, so a restart does not reset it.
//
// served is the second hook: the kid must also be in the JWKS this server
// serves. TODO(#96): also require the kid to be in the policy server's
// last-served bundle tokenJWKS.
type servedSigners struct {
	inner   tokensvc.Signers
	records func(purpose string) []keys.Record
	now     func() time.Time
	served  func(kid string) bool
}

// Active implements tokensvc.Signers.
func (g servedSigners) Active(purpose string) (keys.Signer, error) {
	sg, err := g.inner.Active(purpose)
	if err != nil {
		return nil, err
	}
	if purpose != keys.PurposeToken {
		return sg, nil
	}
	if g.served != nil && !g.served(sg.KID()) {
		return nil, keys.ErrNoActiveKey
	}
	for _, r := range g.records(purpose) {
		if r.KID == sg.KID() {
			if g.now().Before(r.PublishAt.Add(tokenKeyPublishWindow)) {
				return nil, keys.ErrNoActiveKey
			}
			return sg, nil
		}
	}
	// No metadata row for the active key: unknown, so not mintable.
	return nil, keys.ErrNoActiveKey
}

// servesTokenKID reports whether the token JWKS this server serves holds kid.
// It is false until Handler has mounted the JWKS.
func (s *Server) servesTokenKID(kid string) bool {
	j := s.jwks.Load()
	return j != nil && j.serves(kid)
}

// EnableTokens installs the token service and its edge (the pre-authentication
// limits, the metrics and the retention purge) on the server. Run calls it
// before Handler; once Handler has built the mux the routes are fixed.
func (s *Server) EnableTokens(ex TokenExchanger, issuer string, edge TokenEdge) {
	s.cfg.Tokens, s.cfg.TokenIssuer, s.cfg.TokenEdge = ex, issuer, edge
	// The same value is the signed bundle's tokenIssuer (W-P2-WBND-06), so the
	// issuer a worker verifies Warden tokens against is the one that mints them.
	s.policy.setTokenIssuer(issuer)
}

// tokenRetentionInterval is how often expired token rows are purged.
const tokenRetentionInterval = time.Hour

// TokenEdge is what surrounds the token endpoint outside tokensvc.Service. The
// zero value limits nothing, counts nothing and purges nothing (unit tests
// that mount a fake exchanger).
type TokenEdge struct {
	// IP limits requests per client IP before the body is parsed. nil allows
	// everything.
	IP tokensvc.RateLimiter
	// MaxInFlight caps concurrent requests; 0 means no cap.
	MaxInFlight int
	// Metrics is the service's Metrics, so a refusal before the service is
	// counted in the same place. nil is fine.
	Metrics *tokensvc.Metrics
	// Retention purges expired token rows; nil purges nothing.
	Retention *TokenRetention
	// Sessions is the token session store behind the admin revoke and list
	// routes (W-P2-TOKX-07); nil leaves them 404.
	Sessions tokensvc.SessionStore
}

// EventPurger deletes issuance records older than a cutoff.
type EventPurger interface {
	Purge(ctx context.Context, cutoff time.Time) (int64, error)
}

// TokenRetention is the retention work of the token tables: expired assertion
// replay rows, idle and long-revoked sessions, and old issuance records. It
// runs on the control plane's clock from Server.Start whenever the tables
// exist (tokenService.enabled), not only while the endpoint is mounted.
type TokenRetention struct {
	Sessions tokensvc.SessionStore
	Replay   tokensvc.ReplayStore
	Events   EventPurger
	// SessionIdle is tokenService.session.idle: a live session unused for this
	// long would not be continued anyway.
	SessionIdle time.Duration
	// SubjectMax is the longest a subject token can still verify after it was
	// issued: the identity maxTokenTTL plus its clock skew. A revoked session
	// row is the only thing that refuses a subject token issued before the
	// revoke, so it is kept at least this long.
	SubjectMax time.Duration
	// EventRetention is tokenService.eventRetention.
	EventRetention time.Duration
	Logger         *slog.Logger
}

// subjectLifetimeBound is identity max token TTL plus clock skew, with the
// IdP verifier's defaults for unset values.
func subjectLifetimeBound(id config.IdentitySettings) time.Duration {
	ttl := time.Duration(id.MaxTokenTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = identity.DefaultMaxTokenTTL
	}
	skew := time.Duration(id.ClockSkewSeconds) * time.Second
	if skew <= 0 {
		skew = identity.DefaultClockSkew
	}
	return ttl + skew
}

// Purge runs one retention pass at now. Each table is purged on its own: one
// failing store does not stop the others, and the error is logged without any
// row content.
func (r *TokenRetention) Purge(ctx context.Context, now time.Time) {
	if r == nil {
		return
	}
	if r.Replay != nil {
		if _, err := r.Replay.Purge(ctx, now); err != nil && ctx.Err() == nil {
			r.Logger.Warn("control plane: token replay purge failed", "error_type", errorKind(err))
		}
	}
	if r.Sessions != nil {
		if _, err := r.Sessions.Purge(ctx, now.Add(-r.SessionIdle), now.Add(-r.SubjectMax)); err != nil && ctx.Err() == nil {
			r.Logger.Warn("control plane: token session purge failed", "error_type", errorKind(err))
		}
	}
	if r.Events != nil {
		if _, err := r.Events.Purge(ctx, now.Add(-r.EventRetention)); err != nil && ctx.Err() == nil {
			r.Logger.Warn("control plane: token event purge failed", "error_type", errorKind(err))
		}
	}
}

// runTokenRetention purges once at start and then every tokenRetentionInterval
// on the control plane's clock until ctx is done.
func (s *Server) runTokenRetention(ctx context.Context) {
	r := s.cfg.TokenEdge.Retention
	if r == nil {
		return
	}
	go func() {
		for {
			r.Purge(ctx, s.cfg.Clock.Now())
			t := s.cfg.Clock.NewTimer(tokenRetentionInterval)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C():
			}
		}
	}()
}

// newTokenService assembles the token service on the open state database:
// the agent registry, the replay and session tables, the block list, the IdP
// verifier of the served identity block (narrowed to tokenService.allowedAZP)
// and the token signing keys behind the publish-window guard. agents is the
// process's one registry Store; Run starts its single Watch.
func newTokenService(tc config.TokenServiceConfig, id config.IdentitySettings, state *cpstate.DB, agents *agentregsqlite.Store, srv *Server, km *keys.Manager, clk clock.Clock, logger *slog.Logger) (*tokenService, error) {
	if state == nil || km == nil || agents == nil || srv.blocks == nil {
		return nil, errors.New("control-plane: the token service needs the state database, the agent registry, the signing keys and the block list")
	}
	idp, err := oidc.NewOIDCVerifier(oidc.Config{
		Issuer:            id.Issuer,
		InternalIssuerURL: id.InternalIssuerURL,
		Audience:          id.Audience,
		AllowedAZP:        tc.AllowedAZP,
		JWKSURL:           id.JWKSURL,
		GroupsClaim:       id.GroupsClaim,
		ClockSkew:         time.Duration(id.ClockSkewSeconds) * time.Second,
		MaxTokenTTL:       time.Duration(id.MaxTokenTTLSeconds) * time.Second,
		Now:               clk.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("control-plane: tokenService: identity verifier: %w", err)
	}
	sessions := tokensvcsqlite.NewSessions(state)
	replay := tokensvcsqlite.New(state)
	events := tokensvcsqlite.NewEvents(state, logger)
	metrics := tokensvc.NewMetrics()
	limiter := func(name, rate string) (*tokensvc.Limiter, error) {
		rl, err := policy.ParseRateLimit(rate)
		if err != nil {
			return nil, fmt.Errorf("control-plane: tokenService.rateLimit.%s: %w", name, err)
		}
		return tokensvc.NewLimiter(rl.Limit, rl.Window), nil
	}
	ipLim, err := limiter("perIP", tc.RateLimit.PerIP)
	if err != nil {
		return nil, err
	}
	agentLim, err := limiter("perAgent", tc.RateLimit.PerAgent)
	if err != nil {
		return nil, err
	}
	userLim, err := limiter("perUser", tc.RateLimit.PerUser)
	if err != nil {
		return nil, err
	}
	// One issuer value feeds both the assertion audience and the iss of every
	// issued token.
	assertions := &tokensvc.AssertionVerifier{
		Agents: agents, Replay: replay,
		Issuer: tc.Issuer, Now: clk.Now, Skew: tc.ClockSkew, MaxAge: tc.AssertionMaxAge,
	}
	svc, err := tokensvc.New(tokensvc.Config{
		Issuer:          tc.Issuer,
		TTL:             tc.TTL,
		SessionIdle:     tc.Session.Idle,
		SessionAbsolute: tc.Session.Absolute,
		Clients:         assertions,
		Agents:          agents,
		Blocks:          NewTokenBlockChecker(srv.blocks),
		Signers:         servedSigners{inner: km.KeySet(), records: km.KeySet().Records, now: clk.Now, served: srv.servesTokenKID},
		Sessions:        sessions,
		AgentLimiter:    agentLim,
		UserLimiter:     userLim,
		Recorder:        events,
		Metrics:         metrics,
		Logger:          logger,
		Resolvers:       map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(idp)},
		Now:             clk.Now,
		Rand:            rand.Reader,
	})
	if err != nil {
		return nil, fmt.Errorf("control-plane: tokenService: %w", err)
	}
	edge := TokenEdge{
		IP: ipLim, MaxInFlight: tc.RateLimit.MaxInFlight, Metrics: metrics,
		Sessions: sessions,
		Retention: &TokenRetention{
			Sessions: sessions, Replay: replay, Events: events,
			SessionIdle: tc.Session.Idle, SubjectMax: subjectLifetimeBound(id),
			EventRetention: tc.EventRetention, Logger: logger,
		},
	}
	return &tokenService{Service: svc, Sessions: sessions, Agents: agents, Edge: edge}, nil
}

// tokenService is the assembled token service and the stores around it, so
// later tickets (session revoke #254, purge #85) reach them without rebuilding.
type tokenService struct {
	Service  *tokensvc.Service
	Sessions *tokensvcsqlite.Sessions
	// Edge is the pre-authentication limits, metrics and retention that Run
	// hands to Server.EnableTokens.
	Edge TokenEdge
	// Agents is the one agent registry Store of the process. Its reads come
	// from a snapshot that its own writes invalidate directly and that Watch
	// refreshes for other processes' writes. Run hands the same Store to the
	// dashboard agent API (Config.AgentStore) and starts its one Watch: a second
	// Store on the single cpstate connection would never see this one's writes,
	// and a disabled agent would keep minting.
	Agents *agentregsqlite.Store
}

// logTokenService reports the enabled service: one INFO line, plus a WARN for
// a plain-http loopback issuer (development only; there is no insecure flag).
func logTokenService(logger *slog.Logger, tc config.TokenServiceConfig) {
	logger.Info("control plane token service", "enabled", true, "issuer", tc.Issuer, "ttl", tc.TTL.String())
	if strings.HasPrefix(tc.Issuer, "http://") {
		logger.Warn("control-plane: tokenService.issuer is plain http on a loopback host; this is the development profile, use an https issuer in production", "issuer", tc.Issuer)
	}
}
