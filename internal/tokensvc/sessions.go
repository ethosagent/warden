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
	// Purge deletes sessions that are not revoked and were last used before
	// liveCutoff, and revoked sessions whose revoked_at is before
	// revokedCutoff; it returns how many it removed. A revoked row is what
	// refuses a subject token issued before the revoke, so revokedCutoff must
	// be at most now minus (the longest subject token lifetime the IdP
	// verifier accepts, plus its clock skew): then no pre-revoke subject
	// token can still be valid when its revoke row goes.
	Purge(ctx context.Context, liveCutoff, revokedCutoff time.Time) (int64, error)
	// List returns sessions (live and revoked) matching q, newest first.
	List(ctx context.Context, q SessionQuery) ([]SessionInfo, error)
	// RevokedState summarises the revoked rows: how many there are and the
	// latest revoked_at (zero when none). The admin audit hashes it before and
	// after a revoke, so a revoke that changes nothing hashes the same.
	RevokedState(ctx context.Context) (count int64, latest time.Time, err error)
}

// MaxSessionPage is the most rows List returns in one page.
const MaxSessionPage = 200

// SessionQuery selects sessions for List. Empty AgentID and Sub match
// anything. Limit is capped at MaxSessionPage+1 (0 means that too: a page plus
// one row, so a caller can tell whether another page follows). A
// non-empty AfterSID continues after the row (AfterCreated, AfterSID) that
// ended the previous page.
type SessionQuery struct {
	AgentID      string
	Sub          string
	Limit        int
	AfterCreated time.Time
	AfterSID     string
}

// SessionInfo is one token session as an admin sees it. The sid is an
// identifier, not a credential: nothing here can mint or continue a token.
type SessionInfo struct {
	SID        string
	IdPIss     string
	Sub        string
	AgentID    string
	CreatedAt  time.Time
	LastUsedAt time.Time
	// RevokedAt is zero for a live session.
	RevokedAt time.Time
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
