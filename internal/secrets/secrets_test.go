package secrets

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// flakyFetcher returns values from a map but can be made to fail on demand.
type flakyFetcher struct {
	values map[string]string
	fail   bool
	calls  int
}

func (f *flakyFetcher) Fetch(p string) (string, error) {
	f.calls++
	if f.fail {
		return "", errors.New("backend down")
	}
	v, ok := f.values[p]
	if !ok {
		return "", ErrUnknownPlaceholder
	}
	return v, nil
}

func TestEnvFetcher(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-real-123456")
	f := NewEnvFetcher(map[string]string{"openai_secret_001": "OPENAI_API_KEY"})

	v, err := f.Fetch("openai_secret_001")
	if err != nil || v != "sk-real-123456" {
		t.Fatalf("Fetch = %q, %v", v, err)
	}
	if _, err := f.Fetch("unknown"); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("unknown placeholder err = %v", err)
	}
	// Mapped but env var not set.
	f2 := NewEnvFetcher(map[string]string{"x": "DEFINITELY_UNSET_VAR_XYZ"})
	if _, err := f2.Fetch("x"); err == nil {
		t.Error("expected error for unset env var")
	}
	if len(f.placeholders()) != 1 {
		t.Errorf("placeholders len = %d", len(f.placeholders()))
	}
}

func newTestCache(t *testing.T, ff *flakyFetcher, ttl time.Duration) *Cache {
	t.Helper()
	keys := make([]string, 0, len(ff.values))
	for k := range ff.values {
		keys = append(keys, k)
	}
	c, err := NewCache(ff, ttl, keys)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return c
}

// newClockCache builds a cache whose entries are stamped with a controllable
// clock, so TTL-expiry behavior is deterministic. It wires the clock before the
// prefetch by re-running RefreshSecrets under the fake clock.
func newClockCache(t *testing.T, ff *flakyFetcher, ttl time.Duration, clock func() time.Time) *Cache {
	t.Helper()
	c := newTestCache(t, ff, ttl)
	c.now = clock
	if err := c.RefreshSecrets(); err != nil {
		t.Fatalf("re-stamp refresh: %v", err)
	}
	return c
}

func TestCache_PrefetchAndGet(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}}
	c := newTestCache(t, ff, time.Hour)
	got, err := c.GetSecret("p1")
	if err != nil || got != "v1" {
		t.Fatalf("GetSecret = %q, %v", got, err)
	}
	if _, err := c.GetSecret("nope"); !errors.Is(err, ErrUnknownPlaceholder) {
		t.Errorf("unknown placeholder err = %v", err)
	}
}

func TestCache_PrefetchFailureIsLoud(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}, fail: true}
	if _, err := NewCache(ff, time.Hour, []string{"p1"}); err == nil {
		t.Fatal("expected prefetch failure to surface from NewCache")
	}
}

// Invariant: silent refresh on TTL expiry keeps the stale value when the
// backend is unavailable; requests keep flowing.
func TestCache_SilentRefresh_StaleOnFailure(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}}
	clock := time.Unix(0, 0)
	c := newClockCache(t, ff, time.Minute, func() time.Time { return clock })

	// Advance past TTL and make the backend fail.
	clock = clock.Add(2 * time.Minute)
	ff.fail = true

	got, err := c.GetSecret("p1")
	if err != nil {
		t.Fatalf("expected stale value, got err: %v", err)
	}
	if got != "v1" {
		t.Fatalf("stale value = %q, want v1", got)
	}
}

// Within TTL the cache does not call the fetcher again.
func TestCache_WithinTTLNoRefetch(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}}
	c := newTestCache(t, ff, time.Hour)
	before := ff.calls
	if _, err := c.GetSecret("p1"); err != nil {
		t.Fatal(err)
	}
	if ff.calls != before {
		t.Errorf("expected no refetch within TTL, calls went %d -> %d", before, ff.calls)
	}
}

// On expiry with a healthy backend the value is updated.
func TestCache_SilentRefresh_Success(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}}
	clock := time.Unix(0, 0)
	c := newClockCache(t, ff, time.Minute, func() time.Time { return clock })

	ff.values["p1"] = "v2"
	clock = clock.Add(2 * time.Minute)

	got, err := c.GetSecret("p1")
	if err != nil || got != "v2" {
		t.Fatalf("GetSecret = %q, %v; want v2", got, err)
	}
}

// Invariant: manual refresh drops the cache and hard-fails requests until a
// successful refetch.
func TestCache_ManualRefresh_HardFailOnFailure(t *testing.T) {
	ff := &flakyFetcher{values: map[string]string{"p1": "v1"}}
	c := newTestCache(t, ff, time.Hour)

	ff.fail = true
	if err := c.RefreshSecrets(); err == nil {
		t.Fatal("expected manual refresh to fail")
	}
	// Now requests hard-fail (not stale).
	if _, err := c.GetSecret("p1"); err == nil {
		t.Fatal("expected hard-fail after failed manual refresh")
	}

	// Recovery: a successful manual refresh restores service.
	ff.fail = false
	if err := c.RefreshSecrets(); err != nil {
		t.Fatalf("recovery refresh: %v", err)
	}
	if got, err := c.GetSecret("p1"); err != nil || got != "v1" {
		t.Fatalf("after recovery GetSecret = %q, %v", got, err)
	}
}

// Invariant: a reference never contains the raw value.
func TestRef_NeverLeaksRawValue(t *testing.T) {
	const raw = "sk-supersecret-abcd"
	r := Ref(raw)
	if r.Length != len(raw) {
		t.Errorf("length = %d, want %d", r.Length, len(raw))
	}
	if r.Last4 != "abcd" {
		t.Errorf("last4 = %q", r.Last4)
	}
	s := r.String()
	if strings.Contains(s, raw) {
		t.Fatalf("reference string leaked raw value: %q", s)
	}
	// The full secret (minus last 4) must not appear.
	if strings.Contains(s, "supersecret") {
		t.Fatalf("reference string leaked secret body: %q", s)
	}
	if !strings.HasPrefix(r.SHA256, "") || len(r.SHA256) != 64 {
		t.Errorf("sha256 = %q (len %d)", r.SHA256, len(r.SHA256))
	}
}

func TestRef_ShortSecret(t *testing.T) {
	r := Ref("ab")
	if r.Last4 != "ab" {
		t.Errorf("last4 for short secret = %q", r.Last4)
	}
	if !strings.Contains(r.String(), "len:2") {
		t.Errorf("string = %q", r.String())
	}
}
