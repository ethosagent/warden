package secrets

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingStore records every Get so a test can prove the backend was never
// reached for a reserved key.
type countingStore struct {
	*fakeStore
	mu    sync.Mutex
	calls int
}

func (c *countingStore) Get(ctx context.Context, key string) (string, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.fakeStore.Get(ctx, key)
}

func TestReservedKey_IsReservedKey(t *testing.T) {
	for key, want := range map[string]bool{
		"cp":                true,
		"cp/":               true,
		"cp/keys/ca/k1":     true,
		"  cp/keys/ca/k1  ": true,
		"\tcp\n":            true,
		"cpx":               false,
		"cpx/y":             false,
		"{{cp/x}}":          false,
		"warden/cp/x":       false,
		"OPENAI_API_KEY":    false,
		"":                  false,
	} {
		if got := IsReservedKey(key); got != want {
			t.Errorf("IsReservedKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestReservedKey_FetchRefusesBeforeBackend(t *testing.T) {
	cs := &countingStore{fakeStore: newFakeStore()}
	cs.data["cp/keys/ca/k1"] = "ca-material"
	f := NewStoreFetcher(cs)

	got, err := f.Fetch("cp/keys/ca/k1")
	if !errors.Is(err, ErrReservedKey) {
		t.Fatalf("Fetch err = %v, want ErrReservedKey", err)
	}
	if got != "" || strings.Contains(err.Error(), "ca-material") {
		t.Fatalf("reserved fetch leaked a value: %q / %v", got, err)
	}
	if cs.calls != 0 {
		t.Fatalf("backend Get calls = %d, want 0", cs.calls)
	}
	cs.data["plain"] = "v"
	if v, err := f.Fetch("plain"); err != nil || v != "v" {
		t.Fatalf("non-reserved Fetch = %q, %v", v, err)
	}
}

func TestReservedKey_CacheRefuses(t *testing.T) {
	cs := &countingStore{fakeStore: newFakeStore()}
	cs.data["plain"] = "v"
	c, err := NewCache(NewStoreFetcher(cs), time.Minute, []string{"plain"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	c.SetReservedKeyLog(NewReservedKeyLog(slog.New(slog.NewTextHandler(&buf, nil)), nil))
	before := cs.calls
	if _, err := c.GetSecret("cp/keys/ca/k1"); !errors.Is(err, ErrReservedKey) {
		t.Fatalf("GetSecret err = %v, want ErrReservedKey", err)
	}
	if cs.calls != before {
		t.Fatalf("backend was called for a reserved key")
	}
	if !strings.Contains(buf.String(), "reserved secret key refused") || strings.Contains(buf.String(), "k1") {
		t.Fatalf("log = %q, want the refusal line without the key tail", buf.String())
	}

	// A reserved placeholder in the prefetch set fails the refresh loudly.
	if _, err := NewCache(NewStoreFetcher(cs), time.Minute, []string{"cp/x"}); !errors.Is(err, ErrReservedKey) {
		t.Fatalf("NewCache err = %v, want ErrReservedKey", err)
	}
	if cs.calls != before {
		t.Fatalf("prefetch reached the backend for a reserved key")
	}
}

func TestReservedKey_LogRateLimitedPerSource(t *testing.T) {
	var buf bytes.Buffer
	now := time.Unix(1000, 0)
	l := NewReservedKeyLog(slog.New(slog.NewTextHandler(&buf, nil)), func() time.Time { return now })
	count := func() int { return strings.Count(buf.String(), "reserved secret key refused") }

	l.Refused("a", "cp/secret-tail")
	l.Refused("a", "cp/secret-tail")
	l.Refused("b", "cp/secret-tail")
	if count() != 2 {
		t.Fatalf("lines = %d, want 2 (one per source)", count())
	}
	now = now.Add(61 * time.Second)
	l.Refused("a", "cp/secret-tail")
	if count() != 3 {
		t.Fatalf("lines = %d, want 3 after the interval", count())
	}
	if strings.Contains(buf.String(), "secret-tail") {
		t.Fatalf("log leaked the key tail: %s", buf.String())
	}
	var nilLog *ReservedKeyLog
	nilLog.Refused("x", "cp/y") // must not panic
}
