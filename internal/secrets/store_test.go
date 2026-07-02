package secrets

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSecretMeta_ValueFree is the structural guarantee for SecretMeta: no field
// may carry (or contain, transitively) a raw secret VALUE. It mirrors the
// SettingsWire secret-free reflect test — the point is that the type itself
// cannot hold a value, so a future value-bearing field is the ONLY way to break
// it and this test rejects it.
func TestSecretMeta_ValueFree(t *testing.T) {
	assertNoSecretValueFields(t, reflect.TypeOf(SecretMeta{}), map[reflect.Type]bool{})
}

// assertNoSecretValueFields walks a struct type tree and fails if any field
// name looks like it carries a secret value, or if any field is a large opaque
// blob ([]byte) that could smuggle one. Anything ending in "Env" is an
// env-NAME reference, not a value, and is allowed.
func assertNoSecretValueFields(t *testing.T, typ reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Map {
		// A []byte field is an opaque blob that could carry a raw value; reject
		// it before unwrapping to the element type.
		if typ.Kind() == reflect.Slice && typ.Elem().Kind() == reflect.Uint8 {
			t.Errorf("SecretMeta has an opaque []byte field — could smuggle a raw secret value")
		}
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || seen[typ] {
		return
	}
	seen[typ] = true
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		name := f.Name
		isEnvRef := strings.HasSuffix(name, "Env")
		lower := strings.ToLower(name)
		looksSecret := strings.Contains(lower, "secret") ||
			strings.Contains(lower, "value") ||
			strings.Contains(lower, "plaintext") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "credential") ||
			strings.Contains(lower, "accesskey") ||
			(strings.Contains(lower, "apikey") && !isEnvRef) ||
			lower == "token"
		if looksSecret && !isEnvRef {
			t.Errorf("SecretMeta field %q looks like a secret VALUE carrier (metadata must be value-free)", name)
		}
		if f.Type.Kind() == reflect.Slice && f.Type.Elem().Kind() == reflect.Uint8 {
			t.Errorf("SecretMeta field %q is an opaque []byte — could smuggle a raw secret value", name)
		}
		assertNoSecretValueFields(t, f.Type, seen)
	}
}

// fakeStore is a trivial in-memory SecretStore used ONLY in tests to exercise
// the interface contract and the storeFetcher adapter. It is not a production
// backend (echo lands in phase 2).
type fakeStore struct {
	mu   sync.Mutex
	data map[string]string
}

var _ SecretStore = (*fakeStore)(nil)

var errStoreKeyNotFound = errors.New("fakeStore: key not found")

func newFakeStore() *fakeStore {
	return &fakeStore{data: make(map[string]string)}
}

func (s *fakeStore) Get(_ context.Context, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return "", errStoreKeyNotFound
	}
	return v, nil
}

func (s *fakeStore) Put(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = value
	return nil
}

func (s *fakeStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

func (s *fakeStore) List(_ context.Context) ([]SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SecretMeta, 0, len(s.data))
	for k := range s.data {
		out = append(out, SecretMeta{Key: k, Version: "1"})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func TestSecretStore_RoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()

	if err := store.Put(ctx, "alpha", "value-a"); err != nil {
		t.Fatalf("Put alpha: %v", err)
	}
	if err := store.Put(ctx, "beta", "value-b"); err != nil {
		t.Fatalf("Put beta: %v", err)
	}

	// Put is upsert: a second Put updates in place.
	if err := store.Put(ctx, "alpha", "value-a2"); err != nil {
		t.Fatalf("Put alpha (upsert): %v", err)
	}

	got, err := store.Get(ctx, "alpha")
	if err != nil {
		t.Fatalf("Get alpha: %v", err)
	}
	if got != "value-a2" {
		t.Errorf("Get alpha = %q, want %q", got, "value-a2")
	}

	// List returns metadata for both keys and no value.
	metas, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 2 {
		t.Fatalf("List returned %d metas, want 2", len(metas))
	}
	if metas[0].Key != "alpha" || metas[1].Key != "beta" {
		t.Errorf("List keys = %v, want [alpha beta]", []string{metas[0].Key, metas[1].Key})
	}

	// After Delete, Get errors and List omits the key.
	if err := store.Delete(ctx, "alpha"); err != nil {
		t.Fatalf("Delete alpha: %v", err)
	}
	if _, err := store.Get(ctx, "alpha"); err == nil {
		t.Error("Get after Delete should error")
	}
	metas, err = store.List(ctx)
	if err != nil {
		t.Fatalf("List after Delete: %v", err)
	}
	if len(metas) != 1 || metas[0].Key != "beta" {
		t.Errorf("List after Delete = %v, want [beta]", metas)
	}
}

func TestStoreFetcher_DelegatesToGet(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	if err := store.Put(ctx, "openai_key", "sk-store-value"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	f := NewStoreFetcher(store)

	got, err := f.Fetch("openai_key")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	want, _ := store.Get(ctx, "openai_key")
	if got != want {
		t.Errorf("Fetch = %q, want %q (store.Get result)", got, want)
	}

	// Fetch on an unknown key surfaces the store's error unchanged.
	_, err = f.Fetch("unknown")
	if !errors.Is(err, errStoreKeyNotFound) {
		t.Errorf("Fetch unknown err = %v, want store's errStoreKeyNotFound", err)
	}
}

// TestStoreFetcher_BacksCache proves the seam: the existing Cache wraps a
// SecretStore via storeFetcher with no changes, resolving placeholders through
// store.Get.
func TestStoreFetcher_BacksCache(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	if err := store.Put(ctx, "tok", "resolved-token"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	cache, err := NewCache(NewStoreFetcher(store), time.Hour, []string{"tok"})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	got, err := cache.GetSecret("tok")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "resolved-token" {
		t.Errorf("GetSecret = %q, want %q", got, "resolved-token")
	}
}
