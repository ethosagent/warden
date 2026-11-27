package controlplane

import (
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/webauth"
)

// The pending-login store lives in internal/webauth, shared with every front
// door; the console's rows carry purpose "console".
const pendingCap = webauth.PendingCap

// pendingLogin is one started, not yet completed login.
type pendingLogin = webauth.Pending

// OIDCPendingMigrations are the cpstate migrations of the pending-login table.
// Run passes them to cpstate.Open in every mode, like SessionMigrations, so
// switching console.auth never trips the downgrade guard.
func OIDCPendingMigrations() []cpstate.Migration { return webauth.PendingMigrations() }

// sha256Hex is the hex sha256 of s.
func sha256Hex(s string) string { return webauth.SHA256Hex(s) }
