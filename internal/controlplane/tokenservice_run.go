package controlplane

import (
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
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/keys"
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
	}
	if need := tc.TTL + tokenOverlapSlack; kc.Token.Overlap < need {
		return config.TokenServiceConfig{}, fmt.Errorf("control-plane: keys.token.overlap %s is below tokenService.ttl + 2m (%s): a retired key must keep verifying until the last token it signed expires", kc.Token.Overlap, need)
	}
	return tc, nil
}

// servedSigners hands out the token key only when the control plane already
// publishes it in the JWKS it serves. A key created or rotated this instant
// (first start, emergency rotation) may not be in any verifier's cache yet;
// until the JWKS rendering holds its kid the service answers
// signer_unavailable instead of minting a token no worker can verify.
type servedSigners struct {
	inner  tokensvc.Signers
	served func(kid string) bool
}

// Active implements tokensvc.Signers.
func (g servedSigners) Active(purpose string) (keys.Signer, error) {
	sg, err := g.inner.Active(purpose)
	if err != nil {
		return nil, err
	}
	if purpose == keys.PurposeToken && !g.served(sg.KID()) {
		return nil, keys.ErrNoActiveKey
	}
	return sg, nil
}

// servesTokenKID reports whether the token JWKS this server serves holds kid.
// It is false until Handler has mounted the JWKS.
func (s *Server) servesTokenKID(kid string) bool {
	j := s.jwks.Load()
	return j != nil && j.serves(kid)
}

// EnableTokens installs the token service on the server. Run calls it before
// Handler; once Handler has built the mux the routes are fixed.
func (s *Server) EnableTokens(ex TokenExchanger, issuer string) {
	s.cfg.Tokens, s.cfg.TokenIssuer = ex, issuer
}

// newTokenService assembles the token service on the open state database:
// the agent registry, the replay and session tables, the block list, the IdP
// verifier of the served identity block (narrowed to tokenService.allowedAZP)
// and the token signing keys behind the served-JWKS guard. It also returns the
// registry store: its reads come from a cached snapshot, so Run must start its
// Watch to see an agent the offline CLI disabled.
func newTokenService(tc config.TokenServiceConfig, id config.IdentitySettings, state *cpstate.DB, srv *Server, km *keys.Manager, clk clock.Clock, logger *slog.Logger) (*tokensvc.Service, *agentregsqlite.Store, error) {
	if state == nil || km == nil || srv.blocks == nil {
		return nil, nil, errors.New("control-plane: the token service needs the state database, the signing keys and the block list")
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
		return nil, nil, fmt.Errorf("control-plane: tokenService: identity verifier: %w", err)
	}
	agents := agentregsqlite.New(state, agentregsqlite.WithClock(clk), agentregsqlite.WithLogger(logger))
	// One issuer value feeds both the assertion audience and the iss of every
	// issued token.
	assertions := &tokensvc.AssertionVerifier{
		Agents: agents, Replay: tokensvcsqlite.New(state),
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
		Signers:         servedSigners{inner: km.KeySet(), served: srv.servesTokenKID},
		Sessions:        tokensvcsqlite.NewSessions(state),
		Resolvers:       map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(idp)},
		Now:             clk.Now,
		Rand:            rand.Reader,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("control-plane: tokenService: %w", err)
	}
	return svc, agents, nil
}

// logTokenService reports the enabled service: one INFO line, plus a WARN for
// a plain-http loopback issuer (development only; there is no insecure flag).
func logTokenService(logger *slog.Logger, tc config.TokenServiceConfig) {
	logger.Info("control plane token service", "enabled", true, "issuer", tc.Issuer, "ttl", tc.TTL.String())
	if strings.HasPrefix(tc.Issuer, "http://") {
		logger.Warn("control-plane: tokenService.issuer is plain http on a loopback host; this is the development profile, use an https issuer in production", "issuer", tc.Issuer)
	}
}
