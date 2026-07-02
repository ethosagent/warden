package secrets

import (
	"context"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestEchoStore_GetReturnsKey pins the defining echo contract: Get returns the
// key ITSELF as the "value", and requires no prior Put.
func TestEchoStore_GetReturnsKey(t *testing.T) {
	ctx := context.Background()
	store := NewEchoStore()

	got, err := store.Get(ctx, "OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "OPENAI_API_KEY" {
		t.Errorf("Get = %q, want the key itself %q", got, "OPENAI_API_KEY")
	}

	// An empty key is the only Get error.
	if _, err := store.Get(ctx, ""); err == nil {
		t.Error("Get with empty key should error")
	}
}

// TestEchoStore_PutPersistsNothingAcrossInstances proves Put stores no value and
// nothing survives the instance: after a Put on one store, a FRESH store Lists
// empty.
func TestEchoStore_PutPersistsNothingAcrossInstances(t *testing.T) {
	ctx := context.Background()

	first := NewEchoStore()
	if err := first.Put(ctx, "K", "super-secret-value"); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Same instance: List reflects the key (metadata only, no value).
	metas, err := first.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 || metas[0].Key != "K" {
		t.Fatalf("List = %v, want one meta for key K", metas)
	}
	if metas[0].Version == "" {
		t.Error("SecretMeta.Version should be set after Put")
	}
	if metas[0].UpdatedAt.IsZero() {
		t.Error("SecretMeta.UpdatedAt should be set after Put")
	}

	// A FRESH instance shares nothing — proves no persistence beyond the process
	// object.
	second := NewEchoStore()
	metas2, err := second.List(ctx)
	if err != nil {
		t.Fatalf("List (fresh): %v", err)
	}
	if len(metas2) != 0 {
		t.Errorf("fresh store List = %v, want empty (nothing persists across instances)", metas2)
	}
}

// TestEchoStore_PutValidatesAndUpserts covers empty-key/value rejection and the
// version bump on repeated Put of the same key.
func TestEchoStore_PutValidatesAndUpserts(t *testing.T) {
	ctx := context.Background()
	store := NewEchoStore()

	if err := store.Put(ctx, "", "v"); err == nil {
		t.Error("Put with empty key should error")
	}
	if err := store.Put(ctx, "K", ""); err == nil {
		t.Error("Put with empty value should error")
	}

	if err := store.Put(ctx, "K", "v1"); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := store.Put(ctx, "K", "v2"); err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	metas, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("List len = %d, want 1", len(metas))
	}
	if metas[0].Version != "2" {
		t.Errorf("Version after two Puts = %q, want %q", metas[0].Version, "2")
	}
}

// TestEchoStore_DeleteIsIdempotent covers Delete removing a tracked key and
// being a no-op (no error) for an absent one.
func TestEchoStore_DeleteIsIdempotent(t *testing.T) {
	ctx := context.Background()
	store := NewEchoStore()

	// Delete of a never-Put key is not an error.
	if err := store.Delete(ctx, "absent"); err != nil {
		t.Errorf("Delete absent key = %v, want nil (idempotent)", err)
	}

	if err := store.Put(ctx, "K", "v"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Delete(ctx, "K"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	metas, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 0 {
		t.Errorf("List after Delete = %v, want empty", metas)
	}

	// Get still returns the key after Delete — the echo value is derived from
	// the key, not from stored state.
	if got, err := store.Get(ctx, "K"); err != nil || got != "K" {
		t.Errorf("Get after Delete = (%q, %v), want (%q, nil)", got, err, "K")
	}
}

// TestEchoStore_EndToEndThroughCache is the Phase-2 proof: drive the EchoStore
// through the Phase-1 storeFetcher behind the existing Cache, with ZERO external
// dependencies, and assert the read seam (store → fetcher → cache → the value
// the swap stage would use) resolves the placeholder to its key.
func TestEchoStore_EndToEndThroughCache(t *testing.T) {
	store := NewEchoStore()
	f := NewStoreFetcher(store)
	c, err := NewCache(f, time.Hour, []string{"OPENAI_API_KEY"})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	v, err := c.GetSecret("OPENAI_API_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if v != "OPENAI_API_KEY" {
		t.Errorf("end-to-end GetSecret = %q, want the key %q (echo contract)", v, "OPENAI_API_KEY")
	}

	// Operator-style Put then a cache read round-trips: echo ignores the Put
	// VALUE, and Get returns the key — this is exactly the echo contract.
	ctx := context.Background()
	if err := store.Put(ctx, "ANTHROPIC_API_KEY", "ignored-by-echo"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	c2, err := NewCache(NewStoreFetcher(store), time.Hour, []string{"ANTHROPIC_API_KEY"})
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	got, err := c2.GetSecret("ANTHROPIC_API_KEY")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "ANTHROPIC_API_KEY" {
		t.Errorf("post-Put GetSecret = %q, want the key %q (Put value is discarded)", got, "ANTHROPIC_API_KEY")
	}
}

// TestEchoStore_ConcurrentAccess exercises the mutex under -race with concurrent
// Put/Get/Delete/List.
func TestEchoStore_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store := NewEchoStore()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := "K" + strconv.Itoa(n%5)
			_ = store.Put(ctx, key, "value")
			_, _ = store.Get(ctx, key)
			_, _ = store.List(ctx)
			_ = store.Delete(ctx, key)
		}(i)
	}
	wg.Wait()
}

// TestEchoStore_ListSortedForDeterminism is a small helper-backed check that
// List returns exactly the tracked keys (order-independent).
func TestEchoStore_ListSortedForDeterminism(t *testing.T) {
	ctx := context.Background()
	store := NewEchoStore()
	for _, k := range []string{"b", "a", "c"} {
		if err := store.Put(ctx, k, "v"); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}
	metas, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	keys := make([]string, 0, len(metas))
	for _, m := range metas {
		keys = append(keys, m.Key)
	}
	sort.Strings(keys)
	want := []string{"a", "b", "c"}
	if len(keys) != len(want) {
		t.Fatalf("List keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Errorf("List keys = %v, want %v", keys, want)
			break
		}
	}
}
