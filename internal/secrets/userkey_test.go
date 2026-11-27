package secrets

import (
	"errors"
	"strings"
	"testing"
)

// The golden value is computed independently of this package:
// sha256(b"warden-user-v1\x00https://dex\x00a/b").hexdigest()[:32].
const goldenUserKey = "f88a447e7ede0f5dac946e07a3a1e113"

func mustUserKey(t *testing.T, iss, sub string) string {
	t.Helper()
	k, err := UserKey(iss, sub)
	if err != nil {
		t.Fatalf("UserKey(%q, %q): %v", iss, sub, err)
	}
	return k
}

func TestUserKey(t *testing.T) {
	got := mustUserKey(t, "https://dex", "a/b")
	if got != goldenUserKey {
		t.Fatalf("UserKey = %s, want golden %s", got, goldenUserKey)
	}
	if !ValidUserKey(got) || len(got) != UserKeyLen {
		t.Fatalf("UserKey %q is not 32 lowercase hex", got)
	}
	for name, other := range map[string]string{
		"sub a+b":               mustUserKey(t, "https://dex", "a+b"),
		"other issuer":          mustUserKey(t, "https://dex2", "a/b"),
		"split moved into iss":  mustUserKey(t, "https://dexa", "/b"),
		"split moved into sub":  mustUserKey(t, "https://de", "xa/b"),
		"issuer trailing slash": mustUserKey(t, "https://dex/", "a/b"),
	} {
		if other == got {
			t.Errorf("%s: key equals the golden key", name)
		}
	}
	for _, in := range [][2]string{
		{"", "a"}, {"https://dex", ""}, {"", ""},
		{"https://dex\x00", "a"}, {"https://dex", "a\x00b"},
	} {
		if k, err := UserKey(in[0], in[1]); !errors.Is(err, ErrInvalidUserKey) || k != "" {
			t.Errorf("UserKey(%q, %q) = %q, %v; want ErrInvalidUserKey", in[0], in[1], k, err)
		}
	}
	// Deterministic.
	if again := mustUserKey(t, "https://dex", "a/b"); again != got {
		t.Fatal("UserKey is not deterministic")
	}
}

func TestKeyBuilders(t *testing.T) {
	uk := goldenUserKey
	for name, c := range map[string]struct {
		fn   func() (string, error)
		want string
	}{
		"grant":    {func() (string, error) { return UserGrantKey(uk, "google") }, "users/" + uk + "/google"},
		"prefix":   {func() (string, error) { return UserPrefix(uk) }, "users/" + uk + "/"},
		"idp":      {func() (string, error) { return IdPLinkKey(uk) }, "idp/" + uk},
		"revoking": {func() (string, error) { return RevokingKey(uk, "github-app") }, "revoking/" + uk + "/github-app"},
		"client":   {func() (string, error) { return ClientSecretKey("google") }, "oauth-clients/google"},
	} {
		got, err := c.fn()
		if err != nil || got != c.want {
			t.Errorf("%s = %q, %v; want %q", name, got, err, c.want)
		}
		if !IsReservedKey(got) {
			t.Errorf("%s: built key %q is not reserved", name, got)
		}
	}

	badProviders := []string{"_idp", "Google", strings.Repeat("a", 33), "", "9lives", "a/b", "a.b", "a b"}
	for _, p := range badProviders {
		if _, err := UserGrantKey(uk, p); !errors.Is(err, ErrInvalidProviderID) {
			t.Errorf("UserGrantKey(%q) err = %v, want ErrInvalidProviderID", p, err)
		}
		if _, err := RevokingKey(uk, p); !errors.Is(err, ErrInvalidProviderID) {
			t.Errorf("RevokingKey(%q) err = %v, want ErrInvalidProviderID", p, err)
		}
		if _, err := ClientSecretKey(p); !errors.Is(err, ErrInvalidProviderID) {
			t.Errorf("ClientSecretKey(%q) err = %v, want ErrInvalidProviderID", p, err)
		}
	}
	if !ValidProviderID(strings.Repeat("a", 32)) || !ValidProviderID("a") || !ValidProviderID("github-app") {
		t.Error("ValidProviderID rejects a valid id")
	}

	badKeys := []string{"", "a/b", strings.ToUpper(uk), uk[:31], uk + "0", "../" + uk[3:], strings.Repeat("g", 32)}
	for _, k := range badKeys {
		for name, fn := range map[string]func() (string, error){
			"grant":    func() (string, error) { return UserGrantKey(k, "google") },
			"prefix":   func() (string, error) { return UserPrefix(k) },
			"idp":      func() (string, error) { return IdPLinkKey(k) },
			"revoking": func() (string, error) { return RevokingKey(k, "google") },
		} {
			if got, err := fn(); !errors.Is(err, ErrInvalidUserKey) || got != "" {
				t.Errorf("%s(%q) = %q, %v; want ErrInvalidUserKey", name, k, got, err)
			}
		}
	}
}
