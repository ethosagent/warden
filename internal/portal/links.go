package portal

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// The IdP link (W-P3-CSIG-03). With consent.idpLink enabled, a portal login
// stores the user's IdP refresh token in the CP-only user credential store
// (consent.store) at idp/<userKey>, and records only its Reference, the
// generation and the dates in idp_links. W-P3-OFFB-02 refreshes the token
// through LinkStore.Rotate.
//
// LinkStore is the domain service: it serializes every write of one user
// behind a per-user_key mutex, does the secret Put first and the row write
// second, and compare-and-swaps the generation on rotation. The SQL lives
// behind LinkRepo (internal/portal/adapters/sqlite); the store and the key
// helpers (secrets.UserKey, secrets.IdPLinkKey, secrets.Ref) are injected by
// the control plane, so this package never sees a backend.

// IdPLink is one idp_links row. It holds no token value: RefreshRef is the
// token's log-safe Reference (secrets.Ref(token).String()). A zero time means
// the column is NULL.
type IdPLink struct {
	Iss, Sub string
	// UserKey is secrets.UserKey(Iss, Sub).
	UserKey string
	// Email is for display only.
	Email string
	// SecretKey is the token's logical key in consent.store
	// (secrets.IdPLinkKey(UserKey) = idp/<UserKey>).
	SecretKey string
	// RefreshRef is the stored token's Reference, never the token.
	RefreshRef string
	// Generation starts at 1 and grows with every login and rotation.
	Generation int64
	// LinkedAt is the first link of this (Iss, Sub); a re-login keeps it.
	LinkedAt time.Time
	// RefreshIssuedAt is the login that started the current refresh chain;
	// RelinkDueAt = RefreshIssuedAt + consent.idpLink.refreshLifetime, the
	// IdP's absolute lifetime of that chain. Rotation changes neither.
	RefreshIssuedAt time.Time
	RelinkDueAt     time.Time
	// LastRefreshAt and LastRefreshStatus record the last rotation; a login
	// clears them.
	LastRefreshAt     time.Time
	LastRefreshStatus string
	// OffboardedAt is set by offboarding (W-P3-OFFB-01); a login clears it.
	OffboardedAt time.Time

	// The refresh job's record (W-P3-OFFB-02, idp_links/0002). A login resets
	// State to LinkActive and clears ConsecutiveFailures, LastErrorCode and
	// RotationPendingRef.

	// State is one of the Link* states below.
	State string
	// LastOKAt is the last successful refresh (zero: none yet).
	LastOKAt time.Time
	// ConsecutiveFailures counts the refreshes since the last success that
	// failed without a verdict (transport errors, timeouts, 429, 5xx).
	ConsecutiveFailures int64
	// LastErrorCode is the last failure's class code, never IdP text.
	LastErrorCode string
	// RotationPendingRef is the Reference of a rotated token the job holds in
	// memory and has not yet written (set before Rotate, cleared after it).
	// Non-empty after a crash means the chain may be lost.
	RotationPendingRef string
	// EmailVerified is the email_verified claim of the last verified ID token
	// (login or refresh).
	EmailVerified bool
}

// Link states (idp_links.link_state). Only the refresh job and a login write
// them; offboarding (W-P3-OFFB-01) sets LinkOffboarded.
const (
	// LinkActive: the chain refreshed (or was just linked) and is not near
	// its absolute lifetime.
	LinkActive = "active"
	// LinkExpiring: within consent.offboarding.reauthWarning of RelinkDueAt.
	LinkExpiring = "expiring"
	// LinkReauthRequired: the chain reached its absolute lifetime (RelinkDueAt
	// passed, or the IdP answered "Refresh token expired."). Only a login
	// revives it.
	LinkReauthRequired = "reauth_required"
	// LinkTokenLost: the stored token no longer works (the IdP says it is
	// invalid or claimed, or a rotated token could not be written). Never an
	// offboarding signal; the user is asked to sign in again.
	LinkTokenLost = "token_lost"
	// LinkSuspect: a refresh returned an ID token that failed verification
	// or named another subject. Nothing acts on it automatically.
	LinkSuspect = "suspect"
	// LinkOffboarded: offboarding erased the link (W-P3-OFFB-01).
	LinkOffboarded = "offboarded"
)

// RefreshState is the part of an idp_links row the refresh job writes with
// LinkStore.SetState. Every field is written as given (read the row, change
// it, write it back under the generation compare-and-swap).
type RefreshState struct {
	State               string
	LastOKAt            time.Time
	LastRefreshAt       time.Time
	LastRefreshStatus   string
	ConsecutiveFailures int64
	LastErrorCode       string
	RotationPendingRef  string
	Email               string
	EmailVerified       bool
}

// RefreshState returns the row's refresh-job columns.
func (l IdPLink) RefreshState() RefreshState {
	return RefreshState{
		State: l.State, LastOKAt: l.LastOKAt, LastRefreshAt: l.LastRefreshAt, LastRefreshStatus: l.LastRefreshStatus,
		ConsecutiveFailures: l.ConsecutiveFailures, LastErrorCode: l.LastErrorCode,
		RotationPendingRef: l.RotationPendingRef, Email: l.Email, EmailVerified: l.EmailVerified,
	}
}

// RefreshStatusRotated is LastRefreshStatus after a successful Rotate.
const RefreshStatusRotated = "rotated"

var (
	// ErrStaleGeneration is Rotate's answer when the stored generation is not
	// the expected one (a newer login or rotation won). Nothing was written.
	ErrStaleGeneration = errors.New("portal: idp link generation is stale")
	// ErrLinkNotFound: no idp_links row for (iss, sub).
	ErrLinkNotFound = errors.New("portal: idp link not found")
	// ErrNoRefreshToken: a write without a token.
	ErrNoRefreshToken = errors.New("portal: idp link needs a refresh token")
	// ErrLinkSecretStore: consent.store refused or failed the write. The
	// wrapping error names only the cause's type, never its text, which could
	// echo the value it was asked to write.
	ErrLinkSecretStore = errors.New("portal: idp link secret store write failed")
	// ErrLinkRow: the idp_links write failed after the secret write.
	ErrLinkRow = errors.New("portal: idp link row write failed")
	// ErrLinkInconsistent: the stored token is not the one the row's
	// Reference names (a write was split, or the store was changed behind
	// the control plane). TokenAt returns no token with it.
	ErrLinkInconsistent = errors.New("portal: stored idp link token does not match its row")
)

// writeTimeout bounds the locked secret-then-row section of a write. It runs
// detached from the caller's cancellation, so a closed browser tab cannot
// split the Put from the row write.
const writeTimeout = 10 * time.Second

// LinkRepo is the idp_links table (internal/portal/adapters/sqlite). It never
// sees a token, only its Reference.
type LinkRepo interface {
	// Get returns the row of (iss, sub), or ErrLinkNotFound.
	Get(ctx context.Context, iss, sub string) (IdPLink, error)
	// List returns every row, ordered by (iss, sub).
	List(ctx context.Context) ([]IdPLink, error)
	// Upsert writes a login's link: a new row gets generation 1 and
	// LinkedAt = l.LinkedAt; an existing one keeps LinkedAt, increments
	// generation, takes l's other columns and clears LastRefreshAt,
	// LastRefreshStatus and OffboardedAt. It returns the stored row.
	Upsert(ctx context.Context, l IdPLink) (IdPLink, error)
	// Rotate sets refresh_ref, last_refresh_at and last_refresh_status and
	// increments generation only WHERE generation = expectedGeneration, and
	// returns ErrStaleGeneration when no row matched.
	Rotate(ctx context.Context, iss, sub string, expectedGeneration int64, refreshRef string, at time.Time, status string) error
	// SetState writes st's columns only WHERE generation =
	// expectedGeneration, leaving the generation as it is, and returns
	// ErrStaleGeneration when no row matched.
	SetState(ctx context.Context, iss, sub string, expectedGeneration int64, st RefreshState) error
}

// LinkSecrets is the part of consent.store a LinkStore uses.
type LinkSecrets interface {
	Get(ctx context.Context, key string) (string, error)
	Put(ctx context.Context, key, value string) error
	Delete(ctx context.Context, key string) error
}

// LinkKeys are the per-user key helpers, injected from internal/secrets
// (secrets.UserKey, secrets.IdPLinkKey, secrets.Ref(token).String()): every
// P3 per-user key is built only through them.
type LinkKeys struct {
	UserKey   func(iss, sub string) (string, error)
	SecretKey func(userKey string) (string, error)
	Ref       func(token string) string
}

// LinkStoreConfig builds a LinkStore. Every field but Logger is required.
type LinkStoreConfig struct {
	Repo    LinkRepo
	Secrets LinkSecrets
	Keys    LinkKeys
	// RefreshLifetime is consent.idpLink.refreshLifetime.
	RefreshLifetime time.Duration
	// Now is the control plane's clock.
	Now    func() time.Time
	Logger *slog.Logger
}

// LinkStore stores and rotates IdP links. It implements LinkWriter.
type LinkStore struct {
	repo     LinkRepo
	secrets  LinkSecrets
	keys     LinkKeys
	lifetime time.Duration
	now      func() time.Time
	logger   *slog.Logger
	locks    keyedMutex
}

var _ LinkWriter = (*LinkStore)(nil)

// NewLinkStore returns a LinkStore, or an error naming a missing dependency.
func NewLinkStore(c LinkStoreConfig) (*LinkStore, error) {
	switch {
	case c.Repo == nil:
		return nil, errors.New("portal: link store needs a repo")
	case c.Secrets == nil:
		return nil, errors.New("portal: link store needs a secret store")
	case c.Keys.UserKey == nil || c.Keys.SecretKey == nil || c.Keys.Ref == nil:
		return nil, errors.New("portal: link store needs the user key helpers")
	case c.Now == nil:
		return nil, errors.New("portal: link store needs a clock")
	case c.RefreshLifetime <= 0:
		return nil, errors.New("portal: link store needs a positive refresh lifetime")
	}
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &LinkStore{repo: c.Repo, secrets: c.Secrets, keys: c.Keys, lifetime: c.RefreshLifetime, now: c.Now, logger: logger}, nil
}

// keysOf returns the user key and the secret key of (iss, sub).
func (s *LinkStore) keysOf(iss, sub string) (string, string, error) {
	uk, err := s.keys.UserKey(iss, sub)
	if err != nil {
		return "", "", err
	}
	sk, err := s.keys.SecretKey(uk)
	if err != nil {
		return "", "", err
	}
	return uk, sk, nil
}

// put writes token at key. A failure is returned as ErrLinkSecretStore plus
// the cause's type only.
func (s *LinkStore) put(ctx context.Context, key, token string) error {
	if err := s.secrets.Put(ctx, key, token); err != nil {
		return fmt.Errorf("%w (%T)", ErrLinkSecretStore, err)
	}
	return nil
}

// StoreLink stores a login's link: under the user's mutex, the token is Put at
// idp/<userKey> first, then the row is upserted with generation incremented.
// A failed Put writes no row. Iss and Sub must be the verified ID token's
// claims. The returned error never carries the token.
func (s *LinkStore) StoreLink(ctx context.Context, l Link) error {
	_, err := s.Link(ctx, l)
	return err
}

// Link is StoreLink returning the stored row.
func (s *LinkStore) Link(ctx context.Context, l Link) (IdPLink, error) {
	if l.RefreshToken == "" {
		return IdPLink{}, ErrNoRefreshToken
	}
	uk, sk, err := s.keysOf(l.Iss, l.Sub)
	if err != nil {
		return IdPLink{}, fmt.Errorf("portal: idp link key: %w", err)
	}
	unlock, err := s.locks.lock(ctx, uk)
	if err != nil {
		return IdPLink{}, err
	}
	defer unlock()
	// From here the write runs to completion (bounded) whatever the caller's
	// context does, so the Put and the row are never split by a cancel.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	_, gerr := s.repo.Get(wctx, l.Iss, l.Sub)
	isNew := errors.Is(gerr, ErrLinkNotFound)
	if gerr != nil && !isNew {
		return IdPLink{}, fmt.Errorf("%w: %w", ErrLinkRow, gerr)
	}
	if err := s.put(wctx, sk, l.RefreshToken); err != nil {
		return IdPLink{}, err
	}
	now := s.now().UTC()
	row, err := s.repo.Upsert(wctx, IdPLink{
		Iss: l.Iss, Sub: l.Sub, UserKey: uk, Email: l.Email, SecretKey: sk,
		RefreshRef: s.keys.Ref(l.RefreshToken),
		LinkedAt:   now, RefreshIssuedAt: now, RelinkDueAt: now.Add(s.lifetime),
		State: LinkActive, EmailVerified: l.EmailVerified,
	})
	if err != nil {
		if isNew {
			// No row names this token: drop it (best effort) so the store
			// holds no unreferenced credential.
			if derr := s.secrets.Delete(wctx, sk); derr != nil {
				s.logger.Warn("idp_link_orphan_delete_failed", "user_key", uk, "error_type", fmt.Sprintf("%T", derr))
			}
		}
		return IdPLink{}, fmt.Errorf("%w: %w", ErrLinkRow, err)
	}
	s.logger.Info("idp_link_stored", "user_key", uk, "ref", row.RefreshRef, "generation", row.Generation)
	return row, nil
}

// Get returns the link of (iss, sub), or ErrLinkNotFound.
func (s *LinkStore) Get(ctx context.Context, iss, sub string) (IdPLink, error) {
	return s.repo.Get(ctx, iss, sub)
}

// List returns every link.
func (s *LinkStore) List(ctx context.Context) ([]IdPLink, error) {
	return s.repo.List(ctx)
}

// TokenAt reads the link of (iss, sub) and its stored refresh token together,
// under the user's mutex, so the token is the one the row (and its
// generation) describes: W-P3-OFFB-02 refreshes with it and then calls Rotate
// with row.Generation. When the token's Reference differs from
// row.RefreshRef it returns ErrLinkInconsistent and no token. The caller must
// never log the token.
func (s *LinkStore) TokenAt(ctx context.Context, iss, sub string) (string, IdPLink, error) {
	uk, sk, err := s.keysOf(iss, sub)
	if err != nil {
		return "", IdPLink{}, fmt.Errorf("portal: idp link key: %w", err)
	}
	unlock, err := s.locks.lock(ctx, uk)
	if err != nil {
		return "", IdPLink{}, err
	}
	defer unlock()
	row, err := s.repo.Get(ctx, iss, sub)
	if err != nil {
		return "", IdPLink{}, err
	}
	tok, err := s.secrets.Get(ctx, sk)
	if err != nil {
		return "", row, fmt.Errorf("portal: idp link token read failed (%T)", err)
	}
	if s.keys.Ref(tok) != row.RefreshRef {
		return "", row, ErrLinkInconsistent
	}
	return tok, row, nil
}

// Rotate writes a refreshed token for (iss, sub) if the stored generation is
// still expectedGeneration. Under the user's mutex (shared with StoreLink) it
// reads the row and returns ErrStaleGeneration without any Put when the
// generation differs; otherwise it Puts the token and then updates the row
// WHERE generation = expectedGeneration, incrementing it. RefreshIssuedAt and
// RelinkDueAt are kept: the IdP keeps the chain's absolute lifetime. It
// returns the updated row; an error never carries the token.
func (s *LinkStore) Rotate(ctx context.Context, iss, sub string, expectedGeneration int64, token string) (IdPLink, error) {
	if token == "" {
		return IdPLink{}, ErrNoRefreshToken
	}
	uk, sk, err := s.keysOf(iss, sub)
	if err != nil {
		return IdPLink{}, fmt.Errorf("portal: idp link key: %w", err)
	}
	unlock, err := s.locks.lock(ctx, uk)
	if err != nil {
		return IdPLink{}, err
	}
	defer unlock()
	row, err := s.repo.Get(ctx, iss, sub)
	if err != nil {
		return IdPLink{}, err
	}
	if row.Generation != expectedGeneration {
		return IdPLink{}, ErrStaleGeneration
	}
	// As in Link: the Put and the row update are not split by a cancel.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	if err := s.put(wctx, sk, token); err != nil {
		return IdPLink{}, err
	}
	ref := s.keys.Ref(token)
	now := s.now().UTC()
	if err := s.repo.Rotate(wctx, iss, sub, expectedGeneration, ref, now, RefreshStatusRotated); err != nil {
		return IdPLink{}, err
	}
	row.RefreshRef, row.Generation = ref, expectedGeneration+1
	row.LastRefreshAt, row.LastRefreshStatus = now, RefreshStatusRotated
	s.logger.Info("idp_link_rotated", "user_key", uk, "ref", ref, "generation", row.Generation)
	return row, nil
}

// SetState writes the refresh job's columns of (iss, sub) if the stored
// generation is still expectedGeneration, under the user's mutex (shared with
// StoreLink and Rotate), so a verdict about an older token never lands on a
// row a newer login wrote: that case returns ErrStaleGeneration and writes
// nothing.
func (s *LinkStore) SetState(ctx context.Context, iss, sub string, expectedGeneration int64, st RefreshState) error {
	uk, err := s.keys.UserKey(iss, sub)
	if err != nil {
		return fmt.Errorf("portal: idp link key: %w", err)
	}
	unlock, err := s.locks.lock(ctx, uk)
	if err != nil {
		return err
	}
	defer unlock()
	return s.repo.SetState(ctx, iss, sub, expectedGeneration, st)
}

// Ref returns token's log-safe Reference, as idp_links stores it.
func (s *LinkStore) Ref(token string) string { return s.keys.Ref(token) }

// keyedMutex is one mutex per key, taken with a context. Entries live only
// while held or waited on.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	ch   chan struct{} // capacity 1: holding the token is holding the lock
	refs int
}

// lock takes key's mutex or returns ctx's error; the returned func releases it.
func (k *keyedMutex) lock(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	if k.m == nil {
		k.m = map[string]*keyedEntry{}
	}
	e := k.m[key]
	if e == nil {
		e = &keyedEntry{ch: make(chan struct{}, 1)}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()
	release := func() {
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
	select {
	case e.ch <- struct{}{}:
		return func() { <-e.ch; release() }, nil
	case <-ctx.Done():
		release()
		return nil, ctx.Err()
	}
}
