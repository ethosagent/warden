package tokensvc

import (
	"context"
	"time"
)

// EventSchema is the schema of the token_exchange log line and the version of
// the token_events row layout.
const EventSchema = "warden.token.v1"

// Event outcomes.
const (
	OutcomeIssued = "issued"
	OutcomeDenied = "denied"
)

// Event is one recorded outcome of an exchange whose client assertion
// verified. Machine traffic never goes to the hash-chained admin audit.
//
// It holds no credential: not the subject token, the client assertion, the
// issued token or the Authorization header, and no group list. The user is
// the pair (IdPIss, Sub), which the Recorder pseudonymises before storing or
// logging it.
type Event struct {
	TS      time.Time
	Outcome string
	// Reason is empty for an issued token, else a member of AllReasons.
	Reason  Reason
	AgentID string
	// IdPIss and Sub identify the user once the subject token verified; both
	// are empty for a denial before that.
	IdPIss, Sub string
	// SID, JTI, KID and Exp describe the issued token; empty for a denial.
	SID, JTI, KID string
	Exp           time.Time
	Scope         string
}

// Recorder stores an Event before the response is sent. An error makes the
// exchange fail closed: no token is released for an outcome that could not be
// recorded. Implementations are safe for concurrent use; the SQLite one is
// internal/tokensvc/adapters/sqlite.
type Recorder interface {
	Record(ctx context.Context, ev Event) error
}
