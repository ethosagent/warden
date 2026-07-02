// echo.go — the ECHO secret backend. NOT FOR PRODUCTION.
//
// The echo backend is a deliberately non-secret SecretStore whose ONLY purpose
// is to prove the write→read→swap wiring (control-plane Put → worker Get → edge
// swap) with ZERO external dependencies — no cloud, no credentials, no network —
// and to power local dev and the demo.
//
// It works by returning the KEY ITSELF as the "value": Get(ctx, "OPENAI_API_KEY")
// returns "OPENAI_API_KEY". Because the returned "secret" is the (non-sensitive)
// key, the resulting edge swap is observable and harmless — you can watch a
// placeholder become its own key name end-to-end without ever handling a real
// value. Put PERSISTS NOTHING: the value is discarded the instant it arrives,
// never stored, never logged. Nothing survives the process.
//
// NEVER use the echo backend to protect a real secret value. It stores no value
// and reveals the key as the "secret". It exists only to validate the module
// shape; real deployments use a backend that actually keeps values (e.g. AWS
// Secrets Manager). This warning is repeated on the EchoStore type on purpose.
package secrets

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

// ErrEmptyKey is returned by EchoStore operations that require a non-empty key.
var ErrEmptyKey = errors.New("secrets: empty key")

// ErrEmptyValue is returned by EchoStore.Put when the value is empty.
var ErrEmptyValue = errors.New("secrets: empty value")

// EchoStore is a NON-PRODUCTION SecretStore that returns the key itself as the
// "value" and persists NOTHING. See the file-level doc comment: it exists only
// to prove the control-plane-write → worker-read → edge-swap wiring with zero
// external dependencies (no cloud, no credentials, no network) and to power
// local dev / the demo.
//
// Get returns the key verbatim as its "secret" — a non-sensitive value by
// construction, so the swap it feeds is observable and harmless. Put discards
// the value immediately (never stored, never logged) and only records the KEY
// (value-free metadata) in an in-memory, mutex-guarded map so List reflects the
// keys seen THIS process run; nothing survives the instance or a restart.
//
// NEVER use EchoStore to protect a real secret value.
type EchoStore struct {
	mu   sync.Mutex
	seen map[string]SecretMeta // key → value-free metadata for keys Put this run
	now  func() time.Time      // injectable clock; defaults to time.Now
}

// Compile-time assertion: EchoStore satisfies the write-capable SecretStore.
var _ SecretStore = (*EchoStore)(nil)

// NewEchoStore builds an empty, concurrency-safe echo store. A fresh instance
// tracks no keys (List is empty) until Put records them; nothing persists across
// instances. See the file-level doc: NOT FOR PRODUCTION.
func NewEchoStore() *EchoStore {
	return &EchoStore{
		seen: make(map[string]SecretMeta),
		now:  time.Now,
	}
}

// Get returns the key ITSELF as the "value" — the defining echo contract. It
// requires no prior Put (the echo value is derived purely from the key) and
// errors only on an empty key.
func (s *EchoStore) Get(_ context.Context, key string) (string, error) {
	if key == "" {
		return "", ErrEmptyKey
	}
	return key, nil
}

// Put PERSISTS NOTHING. The value is discarded immediately — never stored,
// never logged. Put records only the KEY (value-free SecretMeta with an
// incremented version + updated timestamp) so List reflects keys seen this run.
// It rejects an empty key or value.
func (s *EchoStore) Put(_ context.Context, key, value string) error {
	if key == "" {
		return ErrEmptyKey
	}
	if value == "" {
		return ErrEmptyValue
	}
	// value is intentionally never read beyond this emptiness check: the echo
	// backend keeps no value. (If this ever logs, it must log Ref(value) — a
	// by-reference descriptor — never the raw value; see secrets.go Reference.)
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.seen[key]
	version := 1
	if prev.Version != "" {
		if n, err := strconv.Atoi(prev.Version); err == nil {
			version = n + 1
		}
	}
	s.seen[key] = SecretMeta{
		Key:       key,
		Version:   strconv.Itoa(version),
		UpdatedAt: s.now(),
	}
	return nil
}

// Delete removes key from the in-memory seen-set. It is idempotent: deleting an
// absent (or never-Put) key is not an error. Persists nothing.
func (s *EchoStore) Delete(_ context.Context, key string) error {
	if key == "" {
		return ErrEmptyKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.seen, key)
	return nil
}

// List returns value-free SecretMeta for the keys Put this process run. A fresh
// instance returns an empty slice — nothing persists across instances.
func (s *EchoStore) List(_ context.Context) ([]SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SecretMeta, 0, len(s.seen))
	for _, m := range s.seen {
		out = append(out, m)
	}
	return out, nil
}
