package apikeys

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"
)

// TTL and field bounds.
const (
	// MinTTL is the shortest lifetime Create accepts.
	MinTTL = time.Hour

	maxNameChars        = 64
	maxDescriptionChars = 512
)

// Errors returned by a Store.
var (
	// ErrInvalidTTL: ttl below MinTTL or above the caller's maxTTL.
	ErrInvalidTTL = errors.New("apikeys: ttl out of range")
	// ErrTooMany: the owner already has the maximum number of active keys.
	ErrTooMany = errors.New("apikeys: owner already has the maximum number of active keys")
	// ErrNameTaken: the owner already has a key (active or revoked) with this name.
	ErrNameTaken = errors.New("apikeys: key name already in use for this owner")
	// ErrNotFound: no key has this id.
	ErrNotFound = errors.New("apikeys: key not found")
	// ErrInvalidInput: a name, owner, scope list, actor or limit is not acceptable.
	ErrInvalidInput = errors.New("apikeys: invalid input")
)

// Key is a key's metadata. It never holds the plaintext, the secret or the
// stored hash. Zero times mean "unset". Slices are shared with the Index's
// snapshot: treat them as read-only.
type Key struct {
	ID          string
	Name        string
	Description string
	// Owner is the human the key acts for, as recorded when it was created.
	OwnerIss    string
	OwnerSub    string
	OwnerEmail  string
	OwnerGroups []string
	Scopes      []Scope
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
	LastUsedIP  string
	RevokedAt   time.Time
	RevokedBy   string
}

// Status of a key at an instant.
type Status string

// Key statuses.
const (
	StatusActive  Status = "active"
	StatusExpired Status = "expired"
	StatusRevoked Status = "revoked"
)

// StatusAt reports the key's status at now; revoked wins over expired.
func (k Key) StatusAt(now time.Time) Status {
	switch {
	case !k.RevokedAt.IsZero():
		return StatusRevoked
	case !now.Before(k.ExpiresAt):
		return StatusExpired
	}
	return StatusActive
}

// HasScope reports whether the key was created with s.
func (k Key) HasScope(s Scope) bool {
	for _, have := range k.Scopes {
		if have == s {
			return true
		}
	}
	return false
}

// String prints the id and name only, so %v and %+v are log-safe.
func (k Key) String() string { return fmt.Sprintf("api key id=%s name=%q", k.ID, k.Name) }

// GoString keeps %#v as log-safe as %v (no owner email or groups).
func (k Key) GoString() string { return k.String() }

// LogValue keeps slog output to the id, name and scopes.
func (k Key) LogValue() slog.Value {
	names := make([]string, len(k.Scopes))
	for i, s := range k.Scopes {
		names[i] = string(s)
	}
	return slog.GroupValue(slog.String("id", k.ID), slog.String("name", k.Name),
		slog.String("scopes", strings.Join(names, ",")))
}

// CreateParams describes a key to mint. MaxTTL and MaxActive come from the
// caller's configuration (console.apiKeys), not from this package. The per-owner
// cap and the name-uniqueness rule key on OwnerSub alone, not on the
// (issuer, subject) pair, as the feature design specifies.
type CreateParams struct {
	Name        string
	Description string
	OwnerIss    string
	OwnerSub    string
	OwnerEmail  string
	OwnerGroups []string
	Scopes      []Scope
	// TTL is the key's lifetime: MinTTL <= TTL <= MaxTTL.
	TTL    time.Duration
	MaxTTL time.Duration
	// MaxActive is the most unrevoked, unexpired keys the owner may hold,
	// counting the new one. It must be positive.
	MaxActive int
}

func validateText(field, v string, min, max int) error {
	n := utf8.RuneCountInString(v)
	if !utf8.ValidString(v) || n < min || n > max {
		return fmt.Errorf("%w: %s must be %d-%d characters", ErrInvalidInput, field, min, max)
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s has control characters", ErrInvalidInput, field)
		}
	}
	return nil
}

// Validate checks the parameters against reg without touching a store, so
// every Store implementation applies the same rules. A nil reg is an error.
func (p CreateParams) Validate(reg *Registry) error {
	if reg == nil {
		return fmt.Errorf("%w: no scope registry", ErrInvalidInput)
	}
	if err := validateText("name", p.Name, 1, maxNameChars); err != nil {
		return err
	}
	if err := validateText("description", p.Description, 0, maxDescriptionChars); err != nil {
		return err
	}
	if p.OwnerIss == "" || p.OwnerSub == "" {
		return fmt.Errorf("%w: owner issuer and subject are required", ErrInvalidInput)
	}
	if p.MaxActive <= 0 {
		return fmt.Errorf("%w: maximum active keys must be positive", ErrInvalidInput)
	}
	if len(p.Scopes) == 0 {
		return ErrNoScopes
	}
	seen := make(map[Scope]struct{}, len(p.Scopes))
	for _, sc := range p.Scopes {
		if _, ok := reg.Lookup(sc); !ok {
			return fmt.Errorf("%w: %q", ErrUnknownScope, string(sc))
		}
		if _, dup := seen[sc]; dup {
			return fmt.Errorf("%w: %q", ErrDuplicateScope, string(sc))
		}
		seen[sc] = struct{}{}
	}
	if p.TTL < MinTTL || p.TTL > p.MaxTTL {
		return fmt.Errorf("%w: ttl %s outside [%s, %s]", ErrInvalidTTL, p.TTL, MinTTL, p.MaxTTL)
	}
	return nil
}

// ListFilter narrows List. The zero value lists every key, oldest first.
type ListFilter struct {
	// OwnerSub, when set, lists only that owner's keys.
	OwnerSub string
	// ActiveOnly drops revoked and expired keys.
	ActiveOnly bool
	// ExpiresBefore, when non-zero, keeps only unrevoked keys expiring before
	// it that have not expired yet (the expiry-warning query).
	ExpiresBefore time.Time
}

// Use is one key's latest use, recorded in memory and flushed in batches.
type Use struct {
	At time.Time
	IP string
}

// Change describes what a Store just committed in this process. A Store calls
// its OnChange hooks with one after every Create, Revoke and RevokeByOwner that
// changed a row. The revocation fields let the Index stop accepting a key
// immediately, in memory, without reading the database back.
type Change struct {
	// RevokedIDs lists keys a Revoke just revoked.
	RevokedIDs []string
	// OwnerIss and OwnerSub, when set, mean every key of that owner was just
	// revoked (RevokeByOwner).
	OwnerIss, OwnerSub string
	// RevokedAt and RevokedBy are the values written to the revoked rows.
	RevokedAt time.Time
	RevokedBy string
}

func (c Change) revokes() bool { return len(c.RevokedIDs) > 0 || c.OwnerSub != "" }

// Snapshot is every row of the table plus the data_version it was read at,
// what an Index loads from. It is opaque so a caller cannot read a stored hash
// back out of it.
type Snapshot struct {
	version int64
	entries []entry
}

type entry struct {
	key  Key
	hash [sha256.Size]byte
}

// Add appends a key and the sha256 of its secret. It is how a Store
// implementation builds a Snapshot.
func (s *Snapshot) Add(k Key, secretHash [sha256.Size]byte) {
	s.entries = append(s.entries, entry{key: k, hash: secretHash})
}

// SetVersion records the change counter the snapshot was read at.
func (s *Snapshot) SetVersion(v int64) { s.version = v }

// Len is the number of keys in the snapshot.
func (s *Snapshot) Len() int { return len(s.entries) }

// Store is the persistence port for keys. A later Postgres backend implements
// the same interface. No method returns a plaintext or a stored hash except
// Snapshot, which hands its hashes to an Index in an opaque value.
type Store interface {
	// Create mints a key and returns its plaintext, which no later call returns.
	Create(ctx context.Context, p CreateParams) (plaintext string, k Key, err error)
	Get(ctx context.Context, id string) (Key, error)
	List(ctx context.Context, f ListFilter) ([]Key, error)
	// Revoke soft-deletes a key. It is idempotent: a revoked key keeps its first
	// revoked_at and revoked_by. An unknown id is ErrNotFound.
	Revoke(ctx context.Context, id, by string) error
	// RevokeByOwner revokes every unrevoked key of one owner and returns how many.
	RevokeByOwner(ctx context.Context, iss, sub, by string) (int, error)
	// FlushLastUsed writes the given last-use values in one transaction.
	FlushLastUsed(ctx context.Context, uses map[string]Use) error
	// Snapshot reads every row for an Index.
	Snapshot(ctx context.Context) (Snapshot, error)
	// DataVersion is a counter that changes when another process commits to
	// the same database (not for this process's own writes).
	DataVersion(ctx context.Context) (int64, error)
	// OnChange registers fn, called after this process commits a change,
	// outside any lock the Store holds.
	OnChange(fn func(Change))
}
