package controlplane

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
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
	s.grantLocks = oauthbroker.NewGrantLocks()
	bc := oauthbroker.Config{
		Registry:    cfg.OAuthRegistry,
		Store:       cfg.GrantStore,
		Blocks:      NewBrokerBlockChecker(s.blocks),
		Limiter:     ratelimit.NewLimiter(oauthbroker.StartsPerMinute, time.Minute),
		RedirectURL: cfg.Consent.Connect.RedirectURL,
		UserKey:     secrets.UserKey,
		Rand:        rand.Reader,
		Now:         now,
		Logger:      cfg.Logger,
		Locks:       s.grantLocks,
	}
	// The callback needs consent.store and the exchanger; without them only
	// /connect/start works (a test rig) and /connect/callback answers 404.
	callbackReady := cfg.UserStore != nil && cfg.OAuthExchanger != nil
	if callbackReady {
		bc.Vault = brokerVault{store: cfg.UserStore}
		bc.GrantKey = secrets.UserGrantKey
		bc.NotFound = func(err error) bool { return errors.Is(err, secrets.ErrSecretNotFound) }
		bc.Exchanger = cfg.OAuthExchanger
		bc.Audit = brokerAudit{s: s}
	}
	b, err := oauthbroker.New(bc)
	if err != nil {
		cfg.Logger.Error("control plane: oauth broker unavailable", "error", err)
		return
	}
	c := s.portal.cookie.Named(oauthbrokerhttp.CookieBase)
	s.broker = b
	hc := oauthbrokerhttp.Config{
		Broker: b, Cookie: oauthbrokerhttp.Cookie{Name: c.Name, Secure: c.Secure}, Logger: cfg.Logger,
	}
	if callbackReady {
		hc.Callback = b
	}
	s.brokerHTTP = oauthbrokerhttp.New(hc)
}

// brokerVault adapts consent.store (secrets.SecretStore) to
// oauthbroker.TokenVault. It adds the key listing the orphan pass reads.
type brokerVault struct{ store secrets.SecretStore }

func (v brokerVault) Get(ctx context.Context, key string) (string, error) {
	return v.store.Get(ctx, key)
}

func (v brokerVault) Put(ctx context.Context, key, value string) error {
	return v.store.Put(ctx, key, value)
}

func (v brokerVault) Delete(ctx context.Context, key string) error {
	return v.store.Delete(ctx, key)
}

func (v brokerVault) Keys(ctx context.Context) ([]string, error) {
	list, err := v.store.List(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(list))
	for _, m := range list {
		keys = append(keys, m.Key)
	}
	return keys, nil
}

var _ oauthbroker.TokenVault = brokerVault{}

// brokerAudit adapts the admin audit chain to oauthbroker.AuditSink. It reads
// the Server's auditor at call time, because initBroker runs before admin audit
// is enabled; with admin audit off both methods do nothing.
type brokerAudit struct{ s *Server }

const (
	targetConnectGrant = "grant:"
	// connectActorRole is the actor_role of a connect row: an employee on the
	// consent portal holds no console role.
	connectActorRole = "portal"
)

// Ready reports whether a connect row could be appended now. It probes the
// store itself (BEGIN IMMEDIATE, ROLLBACK), so a read-only or locked database
// fails the callback before the one-time code is spent.
func (a brokerAudit) Ready(ctx context.Context) error {
	au := a.s.audit
	if au == nil {
		return nil
	}
	if !au.healthy(ctx) {
		return errAuditUnhealthy
	}
	if au.probe != nil {
		if err := au.probe(ctx); err != nil {
			au.degraded.Store(true)
			return err
		}
	}
	return nil
}

var errAuditUnhealthy = errors.New("control-plane: admin audit is degraded")

// Record appends connect.granted or connect.denied. The row carries the
// provider, scopes, pending id and a fixed reason; never a token, code, state,
// verifier or secret reference.
func (a brokerAudit) Record(ctx context.Context, ev oauthbroker.AuditEvent) error {
	au := a.s.audit
	if au == nil {
		return nil
	}
	details := map[string]string{"provider": ev.Provider}
	if len(ev.Scopes) > 0 {
		details[adminaudit.DetailScopes] = fitDetail(strings.Join(ev.Scopes, ","))
	}
	if ev.PendingID != "" {
		details["pending_id"] = ev.PendingID
	}
	if ev.AccountID != "" {
		details["provider_account_id"] = fitDetail(ev.AccountID)
	}
	if ev.Reason != "" {
		details["reason"] = ev.Reason
	}
	in := adminaudit.Input{
		Actor: adminaudit.Actor{Sub: ev.Sub, Email: ev.Email}, ActorRole: connectActorRole,
		AuthMethod: adminaudit.AuthMethodPortal, Action: ev.Action,
		Target: targetConnectGrant + ev.Provider, Details: details,
		Outcome: ev.Outcome, HTTPStatus: ev.Status,
	}
	if ev.System {
		in.Actor, in.System, in.ActorRole, in.AuthMethod = adminaudit.Actor{}, true, "system", adminaudit.AuthMethodSystem
	}
	if ev.GrantID != "" {
		in.TargetRef = "grant_id:" + ev.GrantID
	}
	if _, err := au.rec.Record(context.WithoutCancel(ctx), in); err != nil {
		au.degraded.Store(true)
		return err
	}
	au.degraded.Store(false)
	return nil
}

// fitDetail cuts a detail value to the longest prefix an audit row accepts,
// at a separator.
func fitDetail(v string) string {
	if len(v) <= adminaudit.MaxDetailValueLen {
		return v
	}
	cut := v[:adminaudit.MaxDetailValueLen]
	if i := strings.LastIndex(cut, ","); i > 0 {
		cut = cut[:i]
	}
	return cut
}

var _ oauthbroker.AuditSink = brokerAudit{}

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
// is done. Stale connecting grants go to the broker's reconciler (W-P3-BRKR-04),
// and an hourly pass counts consent.store keys with no live grant into the
// orphan gauge.
func (s *Server) sweepOAuthBroker(ctx context.Context) {
	cfg := oauthbroker.SweeperConfig{
		Store:  s.cfg.GrantStore,
		Now:    s.cfg.Clock.Now,
		After:  s.cfg.Clock.After,
		Logger: s.cfg.Logger,
	}
	if s.broker != nil && s.cfg.UserStore != nil && s.cfg.OAuthExchanger != nil {
		cfg.Reconcile = s.broker.Reconcile
		go s.countOrphanedGrants(ctx)
	}
	oauthbroker.RunSweeper(ctx, cfg)
}

// countOrphanedGrants runs the broker's orphan count now and then every
// OrphanInterval until ctx is done. A failed pass is logged and retried.
func (s *Server) countOrphanedGrants(ctx context.Context) {
	for {
		if _, err := s.broker.SweepOrphans(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Warn("oauth broker: orphan key sweep failed", "error", err.Error())
		}
		if _, err := s.broker.CountOrphans(ctx); err != nil && ctx.Err() == nil {
			s.cfg.Logger.Warn("oauth broker: orphan count failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return
		case <-s.cfg.Clock.After(oauthbroker.OrphanInterval):
		}
	}
}

// OAuthExchangeSeconds returns warden_cp_oauth_token_exchange_seconds{provider}
// as (observations, total seconds), or nil when the broker is off.
func (s *Server) OAuthExchangeSeconds() map[string][2]float64 {
	if s.broker == nil {
		return nil
	}
	return s.broker.ExchangeSeconds()
}

// OAuthOrphanedGrants returns the orphaned-grants gauge, 0 when the broker is
// off.
func (s *Server) OAuthOrphanedGrants() int {
	if s.broker == nil {
		return 0
	}
	return s.broker.OrphanedGrants()
}
