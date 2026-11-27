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

// TestReservedSecretNamespace: the per-user namespaces of W-P3-CSIG-06 are
// reserved alongside cp/, with the same normalization.
func TestReservedSecretNamespace(t *testing.T) {
	for key, want := range map[string]bool{
		"idp":                  true,
		"idp/x":                true,
		"users/a/b":            true,
		"revoking/a/google":    true,
		"oauth-clients/google": true,
		" users/a ":            true,
		"/idp/x":               true,
		"//users/a/b":          true,
		"usersx/a":             false,
		"idpx":                 false,
		"Users/a":              false,
		"my-users/a":           false,
		"{{users/a}}":          false,
		"oauth-client/google":  false,
		"warden-cp/idp/x":      false,
		"OPENAI_API_KEY":       false,
	} {
		if got := IsReservedKey(key); got != want {
			t.Errorf("IsReservedKey(%q) = %v, want %v", key, got, want)
		}
	}
}

// TestFetcherRefusesReservedKeys: storeFetcher refuses every reserved namespace
// before calling Get, and the worker Cache refuses them too.
func TestFetcherRefusesReservedKeys(t *testing.T) {
	cs := &countingStore{fakeStore: newFakeStore()}
	cs.data["users/a/b"] = "grant-token"
	f := NewStoreFetcher(cs)
	for _, k := range []string{"users/a/b", "idp/x", "revoking/a/b", "oauth-clients/google", "/idp/x"} {
		got, err := f.Fetch(k)
		if !errors.Is(err, ErrReservedKey) || got != "" {
			t.Errorf("Fetch(%q) = %q, %v; want ErrReservedKey", k, got, err)
		}
		if err != nil && strings.Contains(err.Error(), "grant-token") {
			t.Errorf("Fetch(%q) error leaks the value", k)
		}
	}
	if cs.calls != 0 {
		t.Fatalf("backend Get called %d times for reserved keys, want 0", cs.calls)
	}
	if _, err := NewCache(f, time.Minute, []string{"idp/x"}); !errors.Is(err, ErrReservedKey) {
		t.Fatalf("NewCache over a reserved placeholder err = %v, want ErrReservedKey", err)
	}

	var buf bytes.Buffer
	c, err := NewCache(f, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.SetReservedKeyLog(NewReservedKeyLog(slog.New(slog.NewTextHandler(&buf, nil)), nil))
	if _, err := c.GetSecret("users/a/b"); !errors.Is(err, ErrReservedKey) {
		t.Fatalf("GetSecret err = %v, want ErrReservedKey", err)
	}
	if !strings.Contains(buf.String(), "keyPrefix=users/") || strings.Contains(buf.String(), "users/a/b") {
		t.Fatalf("refusal log = %q, want the users/ prefix and no key tail", buf.String())
	}
}

// TestPersistent: EchoStore keeps nothing, the AWS store persists, and a store
// without the method counts as non-persistent.
func TestPersistent(t *testing.T) {
	if IsPersistent(NewEchoStore()) {
		t.Error("EchoStore must report Persists() == false")
	}
	if p, ok := SecretStore(NewEchoStore()).(Persistent); !ok || p.Persists() {
		t.Error("EchoStore must implement Persistent with false")
	}
	aws := NewAWSSecretStore(newFakeAWSClient(), "us-east-1", "")
	if !IsPersistent(aws) {
		t.Error("the AWS store must report Persists() == true")
	}
	if IsPersistent(newFakeStore()) {
		t.Error("a store without Persists must count as non-persistent")
	}
}
