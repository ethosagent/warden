package tokensvc

import (
	"context"
	"errors"
	"time"
)

// SessionPrefix starts every token session id.
const SessionPrefix = "wts_"

// ErrSessionRevoked is returned by SessionStore.Touch when the subject token
// was issued at or before the revocation of the session it would continue.
var ErrSessionRevoked = errors.New("tokensvc: session revoked")

// SessionKey identifies a token session: one user at one IdP using one agent.
type SessionKey struct {
	IdPIss  string
	Sub     string
	AgentID string
}

// SessionPolicy is what Touch needs to decide between reusing a session and
// starting a new one.
type SessionPolicy struct {
	// Idle ends a session that has not been used for this long.
	Idle time.Duration
	// Absolute ends a session this long after it was created.
	Absolute time.Duration
}

// SessionStore keeps token sessions (the cpstate token_sessions table, not the
// console sessions table). Implementations are safe for concurrent use.
type SessionStore interface {
	// Touch returns the session id for key at now. The live session (not
	// revoked, idle less than policy.Idle, younger than policy.Absolute) is
	// reused and its last use is updated. Otherwise Touch starts a session
	// with newSID, unless the key has a revoked session whose revoked_at is at
	// or after subjectIssuedAt: then it returns ErrSessionRevoked, because the
	// user must sign in again.
	Touch(ctx context.Context, key SessionKey, subjectIssuedAt, now time.Time, policy SessionPolicy, newSID string) (sid string, err error)
	// Revoke marks the session sid revoked at now. It reports whether the
	// session exists; revoking a revoked session keeps its first revoked_at.
	Revoke(ctx context.Context, sid string, now time.Time) (found bool, err error)
	// RevokeAll revokes every live session matching filter (at least one
	// field must be set) and returns how many it revoked.
	RevokeAll(ctx context.Context, filter SessionFilter, now time.Time) (int64, error)
	// Purge deletes sessions that were last used or revoked before cutoff and
	// returns how many it removed.
	Purge(ctx context.Context, cutoff time.Time) (int64, error)
}

// SessionFilter selects sessions for RevokeAll. Empty fields match anything;
// an all-empty filter is refused.
type SessionFilter struct {
	IdPIss  string
	Sub     string
	AgentID string
}

// Empty reports whether the filter has no field set.
func (f SessionFilter) Empty() bool { return f.IdPIss == "" && f.Sub == "" && f.AgentID == "" }
