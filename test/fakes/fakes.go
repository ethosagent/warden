// Package fakes provides hand-written in-memory test doubles for the three core
// interfaces (ConfigProvider, SecretProvider, AnalyticsStore) and the
// SecretStore write port, and the keys.PrivateKeyStore port, so higher layers
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
	"github.com/ethosagent/warden/internal/keys"
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

// FakeKeyStore is an in-memory keys.PrivateKeyStore with switchable outages,
// for the control plane's degraded-mode tests: SetDown(true) makes every call
// fail, as an unreachable backend would, and SetDown(false) restores it. It
// follows the port's contract: Put never overwrites, Get of absent material is
// keys.ErrKeyNotFound, Delete of absent material is not an error.
type FakeKeyStore struct {
	mu   sync.Mutex
	down error
	m    map[string][]byte
}

var _ keys.PrivateKeyStore = (*FakeKeyStore)(nil)

// NewFakeKeyStore returns an empty, reachable store.
func NewFakeKeyStore() *FakeKeyStore { return &FakeKeyStore{m: map[string][]byte{}} }

// SetDown makes every call fail with err (nil restores the store).
func (f *FakeKeyStore) SetDown(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = err
}

func (f *FakeKeyStore) check(purpose, kid string) (string, error) {
	if f.down != nil {
		return "", f.down
	}
	if !keys.ValidPurpose(purpose) {
		return "", fmt.Errorf("%w: %q", keys.ErrInvalidPurpose, purpose)
	}
	return purpose + "/" + kid, nil
}

// Put stores a copy of pem; existing material is keys.ErrKeyExists.
func (f *FakeKeyStore) Put(_ context.Context, purpose, kid string, pem []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := f.check(purpose, kid)
	if err != nil {
		return err
	}
	if _, ok := f.m[k]; ok {
		return keys.ErrKeyExists
	}
	f.m[k] = append([]byte(nil), pem...)
	return nil
}

// Get returns a copy of the material, or keys.ErrKeyNotFound.
func (f *FakeKeyStore) Get(_ context.Context, purpose, kid string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := f.check(purpose, kid)
	if err != nil {
		return nil, err
	}
	b, ok := f.m[k]
	if !ok {
		return nil, keys.ErrKeyNotFound
	}
	return append([]byte(nil), b...), nil
}

// Delete removes the material; absent material is not an error.
func (f *FakeKeyStore) Delete(_ context.Context, purpose, kid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, err := f.check(purpose, kid)
	if err != nil {
		return err
	}
	delete(f.m, k)
	return nil
}

// List returns the kids stored under purpose.
func (f *FakeKeyStore) List(_ context.Context, purpose string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.check(purpose, ""); err != nil {
		return nil, err
	}
	var kids []string
	prefix := purpose + "/"
	for k := range f.m {
		if kid, ok := strings.CutPrefix(k, prefix); ok {
			kids = append(kids, kid)
		}
	}
	sort.Strings(kids)
	return kids, nil
}

// FakeAWSSecretsClient is an in-memory secrets.AWSSecretsClient over one AWS
// account's Secrets Manager secrets, with the IAM resource scope of the role
// that uses it: every operation on a secret name outside the scope is denied
// exactly as AWS would deny it, and ListSecrets never returns a name the role
// cannot see. Views (View) share the one account, so a test can hold the
// control plane's role and the worker's role side by side and prove a worker
// role scoped to the secretStore namespace cannot reach the control plane's
// signing keys. Values are returned by GetSecretValue only.
type FakeAWSSecretsClient struct {
	acct  *awsAccount
	scope string // IAM resource prefix; "" = the account's admin role
}

// awsAccount is the shared state of every view of one account. The mutex is
// shared with the maps, so views are safe for concurrent use.
type awsAccount struct {
	mu   sync.Mutex
	vals map[string]string // secret name → value
	vers map[string]int    // secret name → version counter
	down error
}

var _ secrets.AWSSecretsClient = (*FakeAWSSecretsClient)(nil)

// NewFakeAWSSecretsClient returns an empty account seen by an unrestricted
// role. Use View to scope further roles down (a worker role to warden/*, the
// control plane's keys role to warden-cp-keys/*).
func NewFakeAWSSecretsClient() *FakeAWSSecretsClient {
	return &FakeAWSSecretsClient{acct: &awsAccount{
		vals: map[string]string{},
		vers: map[string]int{},
	}}
}

// View returns the same account as the role scoped to scope sees: operations
// on names outside the scope are denied, ListSecrets filters to it.
func (f *FakeAWSSecretsClient) View(scope string) *FakeAWSSecretsClient {
	return &FakeAWSSecretsClient{acct: f.acct, scope: scope}
}

// SetDown makes every call from every view fail with err (nil restores).
func (f *FakeAWSSecretsClient) SetDown(err error) {
	f.acct.mu.Lock()
	defer f.acct.mu.Unlock()
	f.acct.down = err
}

// Seed plants a secret as an operator or a previous run of the control plane
// would have, bypassing the scope (the data is in the account either way).
func (f *FakeAWSSecretsClient) Seed(name, value string) {
	f.acct.mu.Lock()
	defer f.acct.mu.Unlock()
	f.acct.vals[name] = value
	f.acct.vers[name]++
}

// Has reports whether the account holds a secret under name — what the tests
// use to prove a delete really deleted.
func (f *FakeAWSSecretsClient) Has(name string) bool {
	f.acct.mu.Lock()
	defer f.acct.mu.Unlock()
	_, ok := f.acct.vals[name]
	return ok
}

// denied is the error AWS returns for an operation a role is not scoped for.
func denied(action, name string) error {
	return fmt.Errorf("secrets: aws %s failed: AccessDeniedException: User is not authorized to perform: secretsmanager:%s on resource: %s", action, action, name)
}

// allowed reports whether the role's scope covers name.
func (f *FakeAWSSecretsClient) allowed(name string) bool {
	return f.scope == "" || strings.HasPrefix(name, f.scope)
}

// GetSecretValue returns the current value for name, or ErrSecretNotFound.
func (f *FakeAWSSecretsClient) GetSecretValue(name string) (string, error) {
	a := f.acct
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down != nil {
		return "", a.down
	}
	if !f.allowed(name) {
		return "", denied("GetSecretValue", name)
	}
	v, ok := a.vals[name]
	if !ok {
		return "", fmt.Errorf("%w: GetSecretValue", secrets.ErrSecretNotFound)
	}
	return v, nil
}

// PutSecretValue stores a new version of an existing secret (ErrSecretNotFound
// when absent, like the real API).
func (f *FakeAWSSecretsClient) PutSecretValue(name, value string) (string, error) {
	a := f.acct
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down != nil {
		return "", a.down
	}
	if !f.allowed(name) {
		return "", denied("PutSecretValue", name)
	}
	if _, ok := a.vals[name]; !ok {
		return "", fmt.Errorf("%w: PutSecretValue", secrets.ErrSecretNotFound)
	}
	a.vals[name] = value
	a.vers[name]++
	return fmt.Sprintf("v%d", a.vers[name]), nil
}

// CreateSecret creates a new secret. An existing name is the real API's
// ResourceExistsException, surfaced verbatim (never a value).
func (f *FakeAWSSecretsClient) CreateSecret(name, value string) (string, error) {
	a := f.acct
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down != nil {
		return "", a.down
	}
	if !f.allowed(name) {
		return "", denied("CreateSecret", name)
	}
	if _, ok := a.vals[name]; ok {
		return "", fmt.Errorf("secrets: aws CreateSecret failed: ResourceExistsException: The operation failed because the secret %s already exists", name)
	}
	a.vals[name] = value
	a.vers[name]++
	return fmt.Sprintf("v%d", a.vers[name]), nil
}

// DeleteSecret removes the secret immediately (ForceDeleteWithoutRecovery);
// deleting an absent secret is the real API's ResourceNotFoundException.
func (f *FakeAWSSecretsClient) DeleteSecret(name string) error {
	a := f.acct
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down != nil {
		return a.down
	}
	if !f.allowed(name) {
		return denied("DeleteSecret", name)
	}
	if _, ok := a.vals[name]; !ok {
		return fmt.Errorf("%w: DeleteSecret", secrets.ErrSecretNotFound)
	}
	delete(a.vals, name)
	delete(a.vers, name)
	return nil
}

// ListSecrets returns value-free entries for the secrets under namePrefix the
// role can see, sorted by name. It never reads a value.
func (f *FakeAWSSecretsClient) ListSecrets(namePrefix string) ([]secrets.AWSSecretEntry, error) {
	a := f.acct
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down != nil {
		return nil, a.down
	}
	names := make([]string, 0, len(a.vals))
	for n := range a.vals {
		if strings.HasPrefix(n, namePrefix) && f.allowed(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	out := make([]secrets.AWSSecretEntry, 0, len(names))
	for _, n := range names {
		out = append(out, secrets.AWSSecretEntry{Name: n, Version: fmt.Sprintf("v%d", a.vers[n])})
	}
	return out, nil
}
