package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/filestore"
	"github.com/ethosagent/warden/internal/keys/adapters/metastore"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// keysEvidenceMax bounds the error text a signing_key_unavailable Finding
// carries.
const keysEvidenceMax = 200

// resolveKeys reads the keys block from the operator-owned --config file (the
// served copy is never consulted, like console:) and resolves its directory
// against --state-dir. An empty configPath means the defaults — the keys CLI
// accepts a state dir without a --config. Enabled without a state dir is a
// startup error.
func resolveKeys(configPath, stateDir string) (config.KeysConfig, error) {
	var kc config.KeysConfig
	var err error
	if configPath == "" {
		kc = config.DefaultKeys()
	} else if kc, err = config.LoadKeys(configPath); err != nil {
		return config.KeysConfig{}, fmt.Errorf("control-plane: %w", err)
	}
	kc, err = kc.Resolve(stateDir)
	if err != nil {
		return config.KeysConfig{}, fmt.Errorf("control-plane: %w", err)
	}
	return kc, nil
}

// stateMigrationsFor returns StateMigrations with the feature-gated ones the
// config turns on: signing_keys/0001 is applied only with keys.enabled, so a
// control plane without keys creates no table.
func stateMigrationsFor(kc config.KeysConfig) []cpstate.Migration {
	migs := StateMigrations()
	if kc.Enabled {
		migs = cpstate.Enable(migs, metastore.MigrationID)
	}
	return migs
}

// newKeyManager builds the signing-key manager on the open state database. The
// private key store is the file backend at keys.store.file.dir unless store is
// injected (tests and the harness). Nothing is loaded or created yet: Init
// does that once the alert pipeline can carry a Finding.
func newKeyManager(kc config.KeysConfig, state *cpstate.DB, store keys.PrivateKeyStore, clk clock.Clock, logger *slog.Logger, rec adminaudit.Recorder, alerts keys.AlertSink) (*keys.Manager, error) {
	if state == nil {
		return nil, errors.New("control-plane: keys need the state database")
	}
	if store == nil {
		fs, err := filestore.New(kc.Store.File.Dir)
		if err != nil {
			return nil, fmt.Errorf("control-plane: keys: %w", err)
		}
		store = fs
	}
	cfg := keys.ManagerConfig{
		Store:   store,
		Meta:    metastore.New(state),
		Codec:   signer.Codec{},
		Backend: kc.Store.Backend,
		Algs:    map[string]string{keys.PurposeToken: kc.Token.Alg, keys.PurposeBundle: kc.Bundle.Alg},
		Timings: map[string]keys.Timing{
			// The config layer already validated and defaulted these.
			keys.PurposeToken:  {Interval: kc.Token.RotationInterval, Prepublish: kc.Token.Prepublish, Overlap: kc.Token.Overlap},
			keys.PurposeBundle: {Interval: kc.Bundle.RotationInterval, Prepublish: kc.Bundle.Prepublish, Overlap: kc.Bundle.Overlap},
		},
		Now:    clk.Now,
		Wait:   func(ctx context.Context, d time.Duration) bool { return waitOn(ctx, clk, d) },
		Logger: logger,
		Alerts: alerts,
	}
	if rec != nil {
		cfg.Audit = keysAudit{rec: rec}
	}
	m, err := keys.NewManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("control-plane: keys: %w", err)
	}
	return m, nil
}

// waitOn sleeps d on clk and reports false if ctx ended first.
func waitOn(ctx context.Context, clk clock.Clock, d time.Duration) bool {
	t := clk.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C():
		return true
	}
}

// keysAudit adapts the admin audit Recorder to the key manager's AuditSink.
// The entry names the purpose and kid, never key material.
type keysAudit struct{ rec adminaudit.Recorder }

func (a keysAudit) RecordKeyEvent(ctx context.Context, ev keys.AuditEvent) error {
	_, err := a.rec.Record(ctx, adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: ev.Actor.Subject},
		ActorRole:  ev.Actor.AuthMethod,
		AuthMethod: ev.Actor.AuthMethod,
		Action:     ev.Action,
		Target:     "keys:" + ev.Purpose,
		TargetRef:  "kid:" + ev.KID,
		Outcome:    adminaudit.OutcomeOK,
	})
	return err
}

// keysAlerts publishes the key manager's alerts as Findings through the
// server's FindingPublisher. The server does not exist when the manager is
// built, so it is bound afterwards; an alert raised before then is only logged.
type keysAlerts struct {
	srv    atomic.Pointer[Server]
	logger *slog.Logger
	clk    clock.Clock
}

func (a *keysAlerts) Raise(_ context.Context, al keys.Alert) {
	s := a.srv.Load()
	if s == nil {
		a.logger.Error("keys alert before the control plane was ready", "rule", al.Rule, "purpose", al.Purpose)
		return
	}
	s.publishFinding(keysFinding(al, a.clk.Now()))
}

// keysFinding maps an alert to a Finding. The dedup key is per rule and
// purpose, so an outage that lasts hours is one alert.
func keysFinding(al keys.Alert, now time.Time) integration.Finding {
	detail := al.Detail
	if len(detail) > keysEvidenceMax {
		detail = detail[:keysEvidenceMax]
	}
	sev, summary := keysAlertText(al)
	return integration.Finding{
		RuleID:   al.Rule,
		Category: "security",
		Severity: sev,
		Subject:  integration.Subject{Tool: "keys"},
		Summary:  summary,
		Evidence: integration.Evidence(fmt.Sprintf("purpose=%s reason=%s", al.Purpose, detail)),
		DedupKey: al.Rule + ":" + al.Purpose,
		Ts:       now,
	}
}

// keysAlertText is each rule's severity and operator-facing summary.
func keysAlertText(al keys.Alert) (integration.Severity, string) {
	switch al.Rule {
	case keys.AlertKeyRotationFailed:
		return integration.SevHigh, fmt.Sprintf("%s key rotation failed: the current key keeps signing and the scheduler retries", al.Purpose)
	case keys.AlertKeyOverdue:
		return integration.SevMedium, fmt.Sprintf("%s signing key is overdue: rotation has not moved it for more than twice its interval", al.Purpose)
	default:
		return integration.SevHigh, fmt.Sprintf("%s signing key is unavailable: the control plane cannot sign until it loads", al.Purpose)
	}
}
