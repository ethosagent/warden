// Package fakes provides hand-written in-memory test doubles for the three core
// interfaces (ConfigProvider, SecretProvider, AnalyticsStore) and the
// SecretStore write port so higher layers
// are testable without real backends.
package fakes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// FakeConfigProvider serves a fixed policy and an optional error.
type FakeConfigProvider struct {
	Policy config.Policy
	Err    error
}

var _ config.ConfigProvider = (*FakeConfigProvider)(nil)

// GetPolicy returns the configured policy or error.
func (f *FakeConfigProvider) GetPolicy() (config.Policy, error) {
	return f.Policy, f.Err
}

// FakeSecretProvider resolves placeholders from an in-memory map and records
// how many times RefreshSecrets was called. RefreshErr, when set, makes
// RefreshSecrets hard-fail.
type FakeSecretProvider struct {
	Values       map[string]string
	RefreshErr   error
	RefreshCount int
}

var _ secrets.SecretProvider = (*FakeSecretProvider)(nil)

// GetSecret returns the mapped value or ErrUnknownPlaceholder.
func (f *FakeSecretProvider) GetSecret(placeholder string) (string, error) {
	if v, ok := f.Values[placeholder]; ok {
		return v, nil
	}
	return "", fmt.Errorf("%w: %q", secrets.ErrUnknownPlaceholder, placeholder)
}

// RefreshSecrets records the call and returns RefreshErr.
func (f *FakeSecretProvider) RefreshSecrets() error {
	f.RefreshCount++
	return f.RefreshErr
}

// FakeAnalyticsStore records events in memory.
type FakeAnalyticsStore struct {
	Events []analytics.Event
}

var _ analytics.AnalyticsStore = (*FakeAnalyticsStore)(nil)

// EnforceDenyReason is the #409 deny-reason contract, enforced on the write
// side: a deny (or block) event with no Reason panics, so any exercised code
// path that records an anonymous deny fails the test run at the offending site
// — the panic stack names the writer. Production never reaches this: the
// proxy's single emitDeny/emitDenyEvent chokepoint substitutes the declared
// "unspecified" fallback, and this guard exists so a bypass of that helper
// cannot slip through a test suite silently.
func EnforceDenyReason(e analytics.Event) {
	if e.Reason == "" &&
		(strings.EqualFold(e.Decision, "deny") || strings.EqualFold(e.Decision, "block")) {
		panic(fmt.Sprintf("analytics fake: %q event recorded with an empty Reason — every deny must name a bounded reason from internal/denyreason (#409); route it through proxy emitDeny. Event: %+v", e.Decision, e))
	}
}

// StoreEvent appends an event, enforcing the #409 deny-reason contract.
func (f *FakeAnalyticsStore) StoreEvent(e analytics.Event) error {
	EnforceDenyReason(e)
	f.Events = append(f.Events, e)
	return nil
}

// GetEvents returns events matching a (subset of) filter fields, newest first.
func (f *FakeAnalyticsStore) GetEvents(filter analytics.EventFilter) ([]analytics.Event, error) {
	var out []analytics.Event
	for i := len(f.Events) - 1; i >= 0; i-- {
		e := f.Events[i]
		if filter.Domain != "" && e.Domain != filter.Domain {
			continue
		}
		if filter.Decision != "" && e.Decision != filter.Decision {
			continue
		}
		if !filter.MatchesUser(e) {
			continue
		}
		out = append(out, e)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}

// FakeSecretStore is an in-memory secrets.SecretStore. Get/Delete follow the
// port's contract: Get of an absent key is an error, Delete of one is not, and
// List returns metadata only (the value never leaves Get).
type FakeSecretStore struct {
	mu       sync.Mutex
	values   map[string]string
	versions map[string]int
	updated  map[string]time.Time
}

var _ secrets.SecretStore = (*FakeSecretStore)(nil)

// NewFakeSecretStore returns an empty store.
func NewFakeSecretStore() *FakeSecretStore {
	return &FakeSecretStore{
		values:   map[string]string{},
		versions: map[string]int{},
		updated:  map[string]time.Time{},
	}
}

// Get returns the value for key, or secrets.ErrSecretNotFound.
func (f *FakeSecretStore) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.values[key]
	if !ok {
		return "", fmt.Errorf("%w: %q", secrets.ErrSecretNotFound, key)
	}
	return v, nil
}

// Put upserts key=value and bumps the key's version.
func (f *FakeSecretStore) Put(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.values[key] = value
	f.versions[key]++
	f.updated[key] = time.Now()
	return nil
}

// Delete removes key; deleting an absent key is not an error.
func (f *FakeSecretStore) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.values, key)
	delete(f.versions, key)
	delete(f.updated, key)
	return nil
}

// List returns value-free metadata for every key, sorted by key.
func (f *FakeSecretStore) List(_ context.Context) ([]secrets.SecretMeta, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]secrets.SecretMeta, 0, len(f.values))
	for k := range f.values {
		out = append(out, secrets.SecretMeta{Key: k, Version: fmt.Sprintf("v%d", f.versions[k]), UpdatedAt: f.updated[k]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}
