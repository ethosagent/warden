package oauthbroker

import (
	"context"
	"log/slog"
	"time"
)

// SweepInterval is the default sweeper cadence. Attempts live 10 minutes and
// pendings 1m-1h, so a minute is precise enough; it is deliberately not the
// hourly analytics retention ticker.
const SweepInterval = time.Minute

// Sweeper is what RunSweeper drives; every GrantStore is one.
type Sweeper interface {
	Sweep(ctx context.Context, now time.Time) (SweepResult, error)
}

// SweeperConfig configures RunSweeper. Now and After are the CP clock
// (clock.Clock's methods), so tests drive the loop with a fake clock.
type SweeperConfig struct {
	Store    Sweeper
	Interval time.Duration // 0 = SweepInterval
	Now      func() time.Time
	After    func(time.Duration) <-chan time.Time
	Logger   *slog.Logger // nil = slog.Default()
	// Reconcile, when set, receives the stale connecting grants of each pass
	// (W-P3-BRKR-04 deletes their consent-store key and revokes them). It runs
	// on the sweeper goroutine, before the next wait.
	Reconcile func(ctx context.Context, stale []Grant)
}

// RunSweeper sweeps once at once and then every Interval until ctx is done.
// A failed pass is logged and retried on the next tick. Log lines carry counts
// only, never ids of attempts or any state hash.
func RunSweeper(ctx context.Context, cfg SweeperConfig) {
	interval := cfg.Interval
	if interval <= 0 {
		interval = SweepInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for {
		res, err := cfg.Store.Sweep(ctx, cfg.Now())
		switch {
		case err != nil && ctx.Err() != nil:
			return
		case err != nil:
			logger.Warn("oauth broker: sweep failed", "error", err)
		default:
			if res.AttemptsDeleted+res.PendingsExpired+res.PendingsDeleted+len(res.StaleConnecting) > 0 {
				logger.Info("oauth_broker_sweep",
					"attempts_deleted", res.AttemptsDeleted,
					"pendings_expired", res.PendingsExpired,
					"pendings_deleted", res.PendingsDeleted,
					"stale_connecting", len(res.StaleConnecting))
			}
			if len(res.StaleConnecting) > 0 && cfg.Reconcile != nil {
				cfg.Reconcile(ctx, res.StaleConnecting)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-cfg.After(interval):
		}
	}
}
