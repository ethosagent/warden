package controlplane

import (
	"time"

	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/oauthbroker"
)

// findingUserTokenWritebackFailed is the rule id and DedupKey prefix of the
// finding published when a rotated refresh token could not be persisted.
const findingUserTokenWritebackFailed = oauthbroker.FindingWritebackFailed

// initUserTokens builds the user-token refresh engine (W-P3-PUS-03) over the
// broker's grant metadata store, the consent.store grant records and the one
// shared grantLocks. It needs consent.store; without it s.userTokens stays nil.
// The engine is inert (every refresh fails closed to ErrTokenUnavailable) until
// W-P3-PUS-07 wires NewRegistry Options{HTTPClient, Resolver} (run.go; sibling
// #281 wires the HTTPClient) and Config.UserTokenMetrics.
// The engine has no route here: W-P3-PUS-07 exposes it on POST
// /control/user-token, and RevokeUserGrant and offboarding take their grant
// locks through Engine.WithGrantLock.
func (s *Server) initUserTokens(now func() time.Time) {
	cfg := s.cfg
	if cfg.UserStore == nil || cfg.GrantStore == nil || cfg.OAuthRegistry == nil || s.grantLocks == nil {
		return
	}
	e, err := oauthbroker.NewEngine(oauthbroker.EngineConfig{
		Registry: cfg.OAuthRegistry,
		Grants:   cfg.GrantStore,
		Records:  NewGrantRecords(cfg.UserStore),
		Locks:    s.grantLocks,
		Metrics:  cfg.UserTokenMetrics,
		Alerter:  writebackAlerter{s: s, now: now},
		Now:      now,
		Logger:   cfg.Logger,
	})
	if err != nil {
		cfg.Logger.Error("control plane: user token engine unavailable", "error", err)
		return
	}
	s.userTokens = e
}

// writebackAlerter publishes the high user_token_writeback_failed finding. Its
// DedupKey and evidence hold only the opaque user key and the provider id,
// never a sub, an email or a token.
type writebackAlerter struct {
	s   *Server
	now func() time.Time
}

func (a writebackAlerter) WritebackFailed(userKey, provider string) {
	a.s.publishFinding(integration.Finding{
		RuleID:   findingUserTokenWritebackFailed,
		Category: "operations",
		Severity: integration.SevHigh,
		Summary:  "A rotated OAuth refresh token could not be saved to consent.store; it is held in memory only, and a control plane restart before the next successful write forces the user to reconnect",
		Evidence: integration.Evidence("provider=" + provider + " user_key=" + userKey),
		DedupKey: findingUserTokenWritebackFailed + ":" + userKey + ":" + provider,
		Ts:       a.now(),
	})
}

var _ oauthbroker.WritebackAlerter = writebackAlerter{}
