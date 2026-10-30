package keys

import (
	"context"
	"time"
)

// State is a key's position in its lifecycle. State only moves forward — next,
// active, retired, destroyed — or to revoked in an emergency.
type State string

const (
	// StateNext is generated and published but not yet signing.
	StateNext State = "next"
	// StateActive is the one key that signs.
	StateActive State = "active"
	// StateRetired no longer signs; its public key stays published until
	// retire_at + overlap.
	StateRetired State = "retired"
	// StateRevoked was withdrawn in an emergency: out of every key set at once.
	StateRevoked State = "revoked"
	// StateDestroyed is past its overlap; only the row remains.
	StateDestroyed State = "destroyed"
)

// Record is one signing_keys row: the public metadata of a key. Private bytes
// never appear here or in the database. Zero times mean "unset".
type Record struct {
	KID          string
	Purpose      string
	Alg          string
	State        State
	PublicJWK    JWK
	StoreBackend string
	CreatedAt    time.Time
	PublishAt    time.Time
	ActivateAt   time.Time
	RetireAt     time.Time
	DestroyedAt  time.Time
	CreatedBy    string
}

// MetaStore persists signing-key metadata (the signing_keys table on the
// control plane's state database). Every write is atomic and serialised with
// other processes' writes, so the manager, the scheduler and the CLI never
// race each other into an impossible state.
type MetaStore interface {
	// List returns every row, oldest first.
	List(ctx context.Context) ([]Record, error)
	// Insert adds one row. A kid that exists, or a second active or next row
	// for the purpose, is ErrConflict.
	Insert(ctx context.Context, rec Record) error
	// InsertIfEmpty adds recs, all of one purpose, only when the purpose has
	// no rows at all, in one transaction. It reports whether it inserted.
	// This is what lets two callers on an empty store end with exactly one
	// active and one next key.
	InsertIfEmpty(ctx context.Context, purpose string, recs []Record) (bool, error)
	// UpdateState moves kid from one state to another as a compare-and-swap:
	// it changes the row only if it is still in from, stamps the timestamp
	// column that belongs to to with at, and reports whether it changed it.
	UpdateState(ctx context.Context, kid string, from, to State, at time.Time) (bool, error)
	// Promote moves purpose's signing slot in ONE transaction: the active key
	// oldKID to oldTo, then the next key nextKID to active, both stamped with
	// at. A peer reading between the two writes sees either both changes or
	// neither, so the purpose is never observable without an active key. An
	// empty oldKID skips the retire (the slot is already vacant). Either row
	// not where the caller expects it is a lost race: nothing is written and
	// Promote reports false.
	Promote(ctx context.Context, purpose, oldKID string, oldTo State, nextKID string, at time.Time) (bool, error)
	// DataVersion returns the database's data version, a counter that changes
	// on every write from any process using the same database file. The manager
	// polls it to pick up another process's writes (the keys CLI) without
	// re-reading the table every second.
	DataVersion(ctx context.Context) (int64, error)
}
