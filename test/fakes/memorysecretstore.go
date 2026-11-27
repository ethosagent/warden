package fakes

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
)

// MemorySecretStore is a value-keeping, persistent in-memory
// secrets.SecretStore shared by the P3 tests as the CP-only consent.store
// (W-P3-CSIG-06). Unlike EchoStore it keeps every value and reports
// Persists() true, so it passes the persistent-store startup checks. GetErr,
// PutErr, DeleteErr and ListErr, when set, are returned by that verb instead of
// touching the map (a down backend). Get of an absent key returns an error
// matching secrets.ErrSecretNotFound.
type MemorySecretStore struct {
	mu       sync.Mutex
	values   map[string]string
	versions map[string]int
	updated  map[string]time.Time

	GetErr, PutErr, DeleteErr, ListErr error
	// Gets, Puts and Deletes count calls (including failed ones).
	Gets, Puts, Deletes int
}

var (
	_ secrets.SecretStore = (*MemorySecretStore)(nil)
	_ secrets.Persistent  = (*MemorySecretStore)(nil)
)

// NewMemorySecretStore returns an empty store.
func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{values: map[string]string{}, versions: map[string]int{}, updated: map[string]time.Time{}}
}

// Persists reports true: the store keeps values for its lifetime.
func (m *MemorySecretStore) Persists() bool { return true }

// SetErrors sets the injected errors under the store's lock (nil clears).
func (m *MemorySecretStore) SetErrors(get, put, del, list error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.GetErr, m.PutErr, m.DeleteErr, m.ListErr = get, put, del, list
}

// Get returns key's value, GetErr, or a not-found error.
func (m *MemorySecretStore) Get(_ context.Context, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Gets++
	if m.GetErr != nil {
		return "", m.GetErr
	}
	v, ok := m.values[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", secrets.ErrSecretNotFound, key)
	}
	return v, nil
}

// Put upserts key=value and bumps its version, or returns PutErr.
func (m *MemorySecretStore) Put(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Puts++
	if m.PutErr != nil {
		return m.PutErr
	}
	if key == "" {
		return secrets.ErrEmptyKey
	}
	m.values[key] = value
	m.versions[key]++
	m.updated[key] = time.Now()
	return nil
}

// Delete removes key (absent is not an error), or returns DeleteErr.
func (m *MemorySecretStore) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Deletes++
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	delete(m.values, key)
	delete(m.versions, key)
	delete(m.updated, key)
	return nil
}

// List returns value-free metadata sorted by key, or ListErr.
func (m *MemorySecretStore) List(_ context.Context) ([]secrets.SecretMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ListErr != nil {
		return nil, m.ListErr
	}
	out := make([]secrets.SecretMeta, 0, len(m.values))
	for k := range m.values {
		out = append(out, secrets.SecretMeta{Key: k, Version: fmt.Sprintf("v%d", m.versions[k]), UpdatedAt: m.updated[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Value returns key's stored value and whether it exists, without counting a
// Get (for assertions).
func (m *MemorySecretStore) Value(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	return v, ok
}
