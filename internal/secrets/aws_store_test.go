package secrets

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestAWSSecretStore_RoundTrip drives the full lifecycle over the fake client:
// Put (create via not-found→Create) → Get → Put again (in-place update) → List
// (metadata only, prefix-stripped) → Delete → Get errors / List omits. It also
// asserts the warden/<key> name convention and its reversibility.
func TestAWSSecretStore_RoundTrip(t *testing.T) {
	fake := newFakeAWSClient()
	fake.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }
	store := NewAWSSecretStore(fake, "us-east-1", "warden/")
	ctx := context.Background()
	const key = "{{OPENAI_API_KEY}}"

	// First Put: no such secret yet → routes through CreateSecret (version 1).
	if err := store.Put(ctx, key, "sk-v1"); err != nil {
		t.Fatalf("Put(create): %v", err)
	}
	// Name convention: warden/ + reversible-encoded key. Braces are hex-escaped.
	const wantName = "warden/=7B=7BOPENAI_API_KEY=7D=7D"
	if _, ok := fake.store[wantName]; !ok {
		t.Fatalf("stored under wrong name; have %v, want %q", keysOf(fake.store), wantName)
	}
	if fake.store[wantName].version != 1 {
		t.Fatalf("first Put version = %d, want 1 (created)", fake.store[wantName].version)
	}

	// Get resolves the value.
	if got, err := store.Get(ctx, key); err != nil || got != "sk-v1" {
		t.Fatalf("Get = %q, %v; want sk-v1", got, err)
	}

	// Second Put: secret now exists → in-place update, version bumps to 2.
	if err := store.Put(ctx, key, "sk-v2"); err != nil {
		t.Fatalf("Put(update): %v", err)
	}
	if fake.store[wantName].version != 2 {
		t.Fatalf("second Put version = %d, want 2 (updated in place)", fake.store[wantName].version)
	}
	if got, _ := store.Get(ctx, key); got != "sk-v2" {
		t.Fatalf("Get after update = %q, want sk-v2", got)
	}

	// List: metadata only, key recovered from the name (reversibility).
	metas, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(metas) != 1 || metas[0].Key != key {
		t.Fatalf("List = %+v, want one entry keyed %q", metas, key)
	}
	if metas[0].Version != "2" {
		t.Errorf("List version = %q, want 2", metas[0].Version)
	}
	if metas[0].UpdatedAt.IsZero() {
		t.Errorf("List UpdatedAt is zero, want the fake clock")
	}

	// Delete then confirm Get errors and List omits.
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(ctx, key); err == nil {
		t.Fatal("Get after Delete should error")
	}
	if metas, _ := store.List(ctx); len(metas) != 0 {
		t.Fatalf("List after Delete = %+v, want empty", metas)
	}
	// Delete is idempotent: a second delete is not an error.
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
}

// TestAWSSecretStore_UpsertBranch isolates the Put→Create-on-not-found branch:
// the first Put on a missing key must create it, and a second Put must update in
// place (version changes, not a second create).
func TestAWSSecretStore_UpsertBranch(t *testing.T) {
	fake := newFakeAWSClient()
	store := NewAWSSecretStore(fake, "us-east-1", "warden/")
	ctx := context.Background()

	if err := store.Put(ctx, "K", "v1"); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if got := fake.store["warden/K"]; got == nil || got.version != 1 {
		t.Fatalf("after create: %+v, want version 1", got)
	}
	if err := store.Put(ctx, "K", "v2"); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	got := fake.store["warden/K"]
	if got.version != 2 || got.value != "v2" {
		t.Fatalf("after update: version=%d value=%q, want 2/v2", got.version, got.value)
	}
}

// TestAWSSecretStore_DefaultPrefix proves an empty prefix falls back to warden/.
func TestAWSSecretStore_DefaultPrefix(t *testing.T) {
	fake := newFakeAWSClient()
	store := NewAWSSecretStore(fake, "us-east-1", "")
	if err := store.Put(context.Background(), "K", "v"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, ok := fake.store["warden/K"]; !ok {
		t.Fatalf("empty prefix did not default to warden/; have %v", keysOf(fake.store))
	}
}

// TestAWSSecretStore_GetPropagatesError proves a non-not-found client error from
// Get surfaces (not swallowed).
func TestAWSSecretStore_GetPropagatesError(t *testing.T) {
	fake := newFakeAWSClient()
	fake.err = errors.New("access denied")
	store := NewAWSSecretStore(fake, "us-east-1", "warden/")
	if _, err := store.Get(context.Background(), "K"); err == nil {
		t.Fatal("expected Get to surface the client error")
	}
}

// TestEncodeDecodeKey_RoundTrip proves the name encoding is reversible across a
// range of keys, including AWS-disallowed characters, and that the encoded form
// contains only AWS-legal secret-name characters.
func TestEncodeDecodeKey_RoundTrip(t *testing.T) {
	for _, key := range []string{
		"OPENAI_API_KEY",
		"{{OPENAI_API_KEY}}",
		"openai_secret_001",
		"a/b.c-d+e@f",
		"has space and =equals",
		"weird\t\n{}%chars",
	} {
		enc := encodeKey(key)
		for i := 0; i < len(enc); i++ {
			if !isNameLegal(enc[i]) {
				t.Fatalf("encodeKey(%q)=%q has AWS-illegal byte %q", key, enc, enc[i])
			}
		}
		if got := decodeKey(enc); got != key {
			t.Fatalf("decodeKey(encodeKey(%q))=%q, want round-trip", key, got)
		}
	}
}

// isNameLegal reports whether b is in the AWS Secrets Manager secret-name
// charset (alphanumerics plus /_+=.@-). encodeKey output must satisfy this.
func isNameLegal(b byte) bool {
	if isNamePassthrough(b) {
		return true
	}
	return b == '=' // the reserved escape byte, itself AWS-legal
}

func keysOf(m map[string]*fakeEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
