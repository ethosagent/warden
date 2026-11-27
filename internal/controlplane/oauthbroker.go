package controlplane

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokersqlite "github.com/ethosagent/warden/internal/oauthbroker/adapters/sqlite"
	oauthbrokerhttp "github.com/ethosagent/warden/internal/oauthbroker/http"
	"github.com/ethosagent/warden/internal/ratelimit"
	"github.com/ethosagent/warden/internal/secrets"
)

// The OAuth broker's gate (W-P3-BRKR-03). /connect/* is mounted only when
// consent.providers is non-empty, the cpstate DB is open (--state-dir), the
// consent sign-in block is configured and consent.store is persistent. With no
// providers the control plane adds no route, migration, goroutine or wire
// field; with providers and no usable store it refuses to start.

// oauthBrokerWanted reports whether the CP-local consent block asks for the
// broker: consent enabled and at least one provider.
func oauthBrokerWanted(c *config.ConsentConfig) bool {
	return c != nil && c.Enabled && len(c.Providers) > 0
}

// errBrokerNeedsStore is the startup error of providers without a usable
// consent.store.
var errBrokerNeedsStore = errors.New("control-plane: oauth broker requires a persistent consent.store: consent.providers is set but consent.store is " +
	"missing or the non-persistent echo backend (EchoStore.Get returns the key itself, so a token would never be stored); " +
	"configure consent.store with backend aws, or remove consent.providers")

// checkOAuthBrokerStore refuses to start with providers configured and no
// persistent consent.store. No providers (or consent off) passes.
func checkOAuthBrokerStore(c *config.ConsentConfig, st secrets.SecretStore) error {
	if !oauthBrokerWanted(c) {
		return nil
	}
	if st != nil && secrets.IsPersistent(st) {
		return nil
	}
	return errBrokerNeedsStore
}

// BrokerBlockChecker adapts BlockStore to oauthbroker.BlockChecker, the same
// way TokenBlockChecker serves the token service: an unloaded list is an
// error (fail closed), never "not blocked".
type BrokerBlockChecker struct{ store *BlockStore }

// NewBrokerBlockChecker returns the adapter over store.
func NewBrokerBlockChecker(store *BlockStore) *BrokerBlockChecker {
	return &BrokerBlockChecker{store: store}
}

// IsBlocked reports whether sub (exact) or email (lowercased by the store) is
// on the block list.
func (c *BrokerBlockChecker) IsBlocked(ctx context.Context, sub, email string) (bool, error) {
	if c == nil || c.store == nil || !c.store.Ready() {
		return false, ErrBlockListNotReady
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return c.store.IsBlocked(sub, email), nil
}

var _ oauthbroker.BlockChecker = (*BrokerBlockChecker)(nil)

// initBroker builds the connect routes' broker when every gate input is
// present; otherwise s.broker stays nil and /connect/* is 404.
func (s *Server) initBroker() {
	cfg := s.cfg
	if !oauthBrokerWanted(cfg.Consent) || cfg.OAuthRegistry == nil || cfg.GrantStore == nil ||
		s.portal == nil || s.portal.cookie.Name == "" || s.blocks == nil {
		return
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	b, err := oauthbroker.New(oauthbroker.Config{
		Registry:    cfg.OAuthRegistry,
		Store:       cfg.GrantStore,
		Blocks:      NewBrokerBlockChecker(s.blocks),
		Limiter:     ratelimit.NewLimiter(oauthbroker.StartsPerMinute, time.Minute),
		RedirectURL: cfg.Consent.Connect.RedirectURL,
		UserKey:     secrets.UserKey,
		Rand:        rand.Reader,
		Now:         now,
		Logger:      cfg.Logger,
	})
	if err != nil {
		cfg.Logger.Error("control plane: oauth broker unavailable", "error", err)
		return
	}
	c := s.portal.cookie.Named(oauthbrokerhttp.CookieBase)
	s.broker = b
	s.brokerHTTP = oauthbrokerhttp.New(oauthbrokerhttp.Config{
		Broker: b, Cookie: oauthbrokerhttp.Cookie{Name: c.Name, Secure: c.Secure}, Logger: cfg.Logger,
	})
}

// OAuthConnectCounts returns warden_cp_oauth_connect_total{provider,stage,
// outcome} since start, or nil when the broker is off. W-P5-RETN-06 adds it to
// the export list.
func (s *Server) OAuthConnectCounts() map[oauthbroker.ConnectKey]uint64 {
	if s.broker == nil {
		return nil
	}
	return s.broker.ConnectCounts()
}

// stateMigrationsWithBroker applies the OAuth broker migrations
// (oauthbroker/0001..0003) when the broker is enabled. They are Optional and
// always registered (StateMigrations) for the downgrade guard, so a control
// plane without consent.providers creates none of the broker tables. W-P3-BRKR-03
// calls it from Run with the consent config.
func stateMigrationsWithBroker(migs []cpstate.Migration, enabled bool) []cpstate.Migration {
	if enabled {
		return cpstate.Enable(migs, oauthbrokersqlite.EnabledMigrationIDs()...)
	}
	return migs
}

// sweepOAuthBroker runs the broker's 1-minute sweeper on the CP clock until ctx
// is done. Stale connecting grants are only logged by count until the
// W-P3-BRKR-04 reconciler is wired in as Reconcile.
func (s *Server) sweepOAuthBroker(ctx context.Context) {
	oauthbroker.RunSweeper(ctx, oauthbroker.SweeperConfig{
		Store:  s.cfg.GrantStore,
		Now:    s.cfg.Clock.Now,
		After:  s.cfg.Clock.After,
		Logger: s.cfg.Logger,
	})
}
