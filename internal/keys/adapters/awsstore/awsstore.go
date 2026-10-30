// Package awsstore is the optional keys.PrivateKeyStore over a CP-secret
// backend (in production AWS Secrets Manager): one value per key at the ref
// <purpose>/<kid>, the encoded private key the manager hands it, under the
// control plane's OWN name prefix.
//
// ISOLATION (W-P2-KEYS-07). The backend is built by assembly from the
// CP-local keys.store.aws block — its own client, its own name prefix
// (default warden-cp-keys/), credentials from the control plane's environment
// or IMDS only. It is never the worker secretStore block, and startup refuses
// a keys prefix that overlaps secretStore.aws.namePrefix in either direction,
// so worker IAM scoped to the secretStore namespace cannot reach signing keys.
//
// The store moves opaque encoded private keys and never interprets them, and
// it never logs: the manager logs purpose and kid, the backend's client logs
// region and prefix — values and credentials appear nowhere. Puts never
// overwrite (the file store's O_EXCL rule, re-checked against the backend
// before the write; the state DB's compare-and-swap inserts remain the
// cross-process guard). Deletes are idempotent, so a retirement and the orphan
// sweep can race without error.
package awsstore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ethosagent/warden/internal/keys"
)

// ErrNotFound is returned by Backend.Get for a ref with no value. It is the
// port's own sentinel — not the backend package's — so this package stays
// free of a dependency on the secret backend's types; assembly maps the
// backend's not-found onto it.
var ErrNotFound = errors.New("awsstore: no material under that ref")

// Backend is the CP-secret backend the Store keeps key material in, keyed by
// the ref the store builds. Assembly adapts the backend it builds from the
// keys.store.aws block onto this port; the port is deliberately value-shaped
// (strings, not key material types) and carries the not-found sentinel, so
// the adapter depends on nothing outside its own domain.
//
// BY-REFERENCE LOGGING ONLY, like every secret path: implementations may log
// the ref, never the value. Get hands the caller the value; nothing else in
// the port sees one.
type Backend interface {
	// Get returns the value stored under key, or ErrNotFound.
	Get(ctx context.Context, key string) (string, error)
	// Put stores value under key, creating or replacing it.
	Put(ctx context.Context, key, value string) error
	// Delete removes key. Deleting an absent key is not an error.
	Delete(ctx context.Context, key string) error
	// List returns value-free refs of the stored keys ("<purpose>/<kid>" and
	// other namespaces' entries alike). It MUST NOT read any value.
	List(ctx context.Context) ([]string, error)
}

// Store implements keys.PrivateKeyStore over a Backend.
type Store struct {
	backend Backend
}

var _ keys.PrivateKeyStore = (*Store)(nil)

// New returns a Store keeping key material in backend.
func New(backend Backend) (*Store, error) {
	if backend == nil {
		return nil, errors.New("awsstore: nil backend")
	}
	return &Store{backend: backend}, nil
}

// ref validates purpose and kid and returns the ref they address. Every
// backend key this store touches is built here, so a secret name can never
// escape the <purpose>/<kid> namespace.
func ref(purpose, kid string) (string, error) {
	if !keys.ValidPurpose(purpose) {
		return "", fmt.Errorf("%w: %q", keys.ErrInvalidPurpose, purpose)
	}
	if !keys.ValidKID(kid) {
		return "", fmt.Errorf("%w: kid is not a thumbprint", keys.ErrInvalidKey)
	}
	return purpose + "/" + kid, nil
}

// Put stores pem under the purpose/kid ref. Material already there is
// keys.ErrKeyExists and is left untouched: the pre-write read is what keeps a
// retried generation from replacing a key another process recorded.
func (s *Store) Put(ctx context.Context, purpose, kid string, pem []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := ref(purpose, kid)
	if err != nil {
		return err
	}
	if len(pem) == 0 {
		return fmt.Errorf("awsstore: put %s: empty key material", r)
	}
	_, err = s.backend.Get(ctx, r)
	switch {
	case err == nil:
		return fmt.Errorf("awsstore: put %s: %w", r, keys.ErrKeyExists)
	case !errors.Is(err, ErrNotFound):
		return fmt.Errorf("awsstore: put %s: %w", r, err)
	}
	if err := s.backend.Put(ctx, r, string(pem)); err != nil {
		return fmt.Errorf("awsstore: put %s: %w", r, err)
	}
	return nil
}

// Get returns the material for purpose/kid, or keys.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, purpose, kid string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r, err := ref(purpose, kid)
	if err != nil {
		return nil, err
	}
	v, err := s.backend.Get(ctx, r)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("awsstore: get %s: %w", r, keys.ErrKeyNotFound)
		}
		return nil, fmt.Errorf("awsstore: get %s: %w", r, err)
	}
	return []byte(v), nil
}

// Delete removes the material; an absent ref is not an error.
func (s *Store) Delete(ctx context.Context, purpose, kid string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r, err := ref(purpose, kid)
	if err != nil {
		return err
	}
	if err := s.backend.Delete(ctx, r); err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("awsstore: delete %s: %w", r, err)
	}
	return nil
}

// List returns the kids that have material under purpose. Backend refs
// outside the store's ref shape — another namespace's secrets, a ref without
// a thumbprint kid — are ignored, so List only ever names kids the store's
// Get and Delete can address.
func (s *Store) List(ctx context.Context, purpose string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !keys.ValidPurpose(purpose) {
		return nil, fmt.Errorf("%w: %q", keys.ErrInvalidPurpose, purpose)
	}
	refs, err := s.backend.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("awsstore: list %s key material: %w", purpose, err)
	}
	prefix := purpose + "/"
	var kids []string
	for _, r := range refs {
		kid, ok := strings.CutPrefix(r, prefix)
		if !ok || !keys.ValidKID(kid) {
			continue
		}
		kids = append(kids, kid)
	}
	return kids, nil
}
