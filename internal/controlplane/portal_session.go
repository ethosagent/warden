package controlplane

import (
	"context"
	"database/sql"
	"time"

	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/webauth"
)

// The portal's sessions (W-P3-CSIG-02) are their own table, portal_sessions,
// built with the shared webauth.SessionStore: only sha256(id) is stored, the
// id is 32 fresh random bytes per login, idle and absolute expiry follow the
// control plane's clock, and last_seen_at is written at most once a minute.
// The console's middleware reads only `sessions`; nothing here reads that.

// portalSessionTable is the portal's session table. It has no auth_method
// column: every portal session is an OIDC login with an idle timeout.
func portalSessionTable() webauth.SessionTable {
	return webauth.SessionTable{
		Name: "portal_sessions", MigrationID: "portal_sessions/0001",
		// 0002 records the IdP's email_verified claim: requireEmailMatch on an
		// OAuth provider (BRKR-08) trusts the session email only when it is set.
		EmailVerifiedMigrationID: "portal_sessions/0002",
	}
}

// PortalSessionMigrations are the cpstate migrations of portal_sessions. Run
// passes them to cpstate.Open in every mode (as it does SessionMigrations), so
// switching consent on and off never trips the downgrade guard.
func PortalSessionMigrations() []cpstate.Migration { return portalSessionTable().Migrations() }

// PortalSessionStore keeps portal sessions: Create, Lookup, Touch, Delete,
// DeleteBySub, DeleteByEmail, List and SweepExpired over portal_sessions.
// W-P3-CSIG-04 calls DeleteBySub and DeleteByEmail from the block-list path.
type PortalSessionStore struct{ *webauth.SessionStore }

// NewPortalSessionStore builds the store over db (a cpstate DB opened with
// PortalSessionMigrations). A nil now uses time.Now.
func NewPortalSessionStore(db *sql.DB, idle, absolute time.Duration, now func() time.Time) *PortalSessionStore {
	return &PortalSessionStore{webauth.NewSessionStore(db, portalSessionTable(), idle, absolute, now)}
}

// sweepSessions deletes expired portal sessions every minute until ctx
// is done.
func (p *portalService) sweepSessions(ctx context.Context) {
	t := time.NewTicker(webauth.SessionSweepInterval)
	defer t.Stop()
	for {
		if n, err := p.sessions.SweepExpired(ctx); err != nil {
			p.logger.Warn("control plane: portal session sweep failed", "error", err)
		} else if n > 0 {
			p.logger.Info("control plane: expired portal sessions removed", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
