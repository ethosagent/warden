// Package fakes provides hand-written in-memory test doubles for the three core
// interfaces (ConfigProvider, SecretProvider, AnalyticsStore) so higher layers
// are testable without real backends.
package fakes

import (
	"fmt"

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

// StoreEvent appends an event.
func (f *FakeAnalyticsStore) StoreEvent(e analytics.Event) error {
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
		out = append(out, e)
		if filter.Limit > 0 && len(out) >= filter.Limit {
			break
		}
	}
	return out, nil
}
