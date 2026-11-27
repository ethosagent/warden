package controlplane

import (
	"context"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/oauthbroker"
	oauthbrokersqlite "github.com/ethosagent/warden/internal/oauthbroker/adapters/sqlite"
)

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
