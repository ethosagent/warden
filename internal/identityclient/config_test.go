package identityclient_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func fileOf(content string) func(string) ([]byte, error) {
	return func(string) ([]byte, error) { return []byte(content), nil }
}

func noFile(string) ([]byte, error) { return nil, fs.ErrNotExist }

const fileYAML = `
issuer: https://file.example.com
client_id: file-client
audience: file-aud
client_secret_env: FILE_SECRET
scopes: [file-scope]
cache_dir: /file/cache
`

func TestLoadConfigPrecedence(t *testing.T) {
	env := map[string]string{
		identityclient.EnvIssuer: "https://env.example.com", identityclient.EnvClientID: "env-client",
		identityclient.EnvAudience: "env-aud", identityclient.EnvScopes: "env-scope, shared",
		identityclient.EnvCacheDir: "/env/cache",
	}
	flags := identityclient.Flags{Issuer: "https://flag.example.com", ClientID: "flag-client", Audience: "flag-aud",
		ClientSecretEnv: "FLAG_SECRET", Scopes: []string{"flag-scope"}, CacheDir: "/flag/cache"}

	got, err := identityclient.LoadConfig(flags, envOf(env), fileOf(fileYAML))
	if err != nil {
		t.Fatal(err)
	}
	want := identityclient.Config{Issuer: "https://flag.example.com", ClientID: "flag-client", Audience: "flag-aud",
		ClientSecretEnv: "FLAG_SECRET", CacheDir: "/flag/cache",
		Scopes: append(append([]string{}, identityclient.DefaultScopes...), "flag-scope")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flags over env over file:\n got %+v\nwant %+v", got, want)
	}

	got, err = identityclient.LoadConfig(identityclient.Flags{}, envOf(env), fileOf(fileYAML))
	if err != nil {
		t.Fatal(err)
	}
	want = identityclient.Config{Issuer: "https://env.example.com", ClientID: "env-client", Audience: "env-aud",
		ClientSecretEnv: "FILE_SECRET", CacheDir: "/env/cache",
		Scopes: append(append([]string{}, identityclient.DefaultScopes...), "env-scope", "shared")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("env over file:\n got %+v\nwant %+v", got, want)
	}

	got, err = identityclient.LoadConfig(identityclient.Flags{}, envOf(nil), fileOf(fileYAML))
	if err != nil {
		t.Fatal(err)
	}
	want = identityclient.Config{Issuer: "https://file.example.com", ClientID: "file-client", Audience: "file-aud",
		ClientSecretEnv: "FILE_SECRET", CacheDir: "/file/cache",
		Scopes: append(append([]string{}, identityclient.DefaultScopes...), "file-scope")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("file only:\n got %+v\nwant %+v", got, want)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	got, err := identityclient.LoadConfig(identityclient.Flags{Issuer: "http://localhost:5556/dex", CacheDir: "/c"}, envOf(nil), noFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "warden-cli" || got.Audience != "warden" || got.ClientSecretEnv != "" {
		t.Fatalf("defaults: %+v", got)
	}
	if !reflect.DeepEqual(got.Scopes, []string{"openid", "email", "profile", "groups", "offline_access"}) {
		t.Fatalf("scopes: %v", got.Scopes)
	}
	// Added scopes are deduplicated against the defaults.
	got, _ = identityclient.LoadConfig(identityclient.Flags{Issuer: "https://i.example.com", CacheDir: "/c",
		Scopes: []string{"openid", "audience:server:client_id:warden"}}, envOf(nil), noFile)
	if n := len(got.Scopes); n != 6 || got.Scopes[5] != "audience:server:client_id:warden" {
		t.Fatalf("scopes: %v", got.Scopes)
	}
	// The default cache dir comes from os.UserCacheDir.
	t.Setenv("XDG_CACHE_HOME", "/xdg")
	t.Setenv("HOME", "/home/x")
	got, err = identityclient.LoadConfig(identityclient.Flags{Issuer: "https://i.example.com"}, envOf(nil), noFile)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(mustCacheDir(t), "warden", "identity"); got.CacheDir != want {
		t.Fatalf("cache dir %q, want %q", got.CacheDir, want)
	}
}

func mustCacheDir(t *testing.T) string {
	t.Helper()
	d, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLoadConfigNoLiteralSecret(t *testing.T) {
	const secret = "hunter2-literal!"
	// A literal in the flag is not a variable name.
	_, err := identityclient.LoadConfig(identityclient.Flags{Issuer: "https://i.example.com", ClientSecretEnv: secret}, envOf(nil), noFile)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("want an error that does not echo the value, got %v", err)
	}
	// The same through the file, plus a client_secret key, which is unknown.
	for _, y := range []string{"issuer: https://i.example.com\nclient_secret_env: " + `"` + secret + `"`, "issuer: https://i.example.com\nclient_secret: " + secret} {
		_, err = identityclient.LoadConfig(identityclient.Flags{}, envOf(nil), fileOf(y))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("file %q: want an error without the value, got %v", y, err)
		}
	}
	// No env var feeds the secret name either.
	if _, ok := reflect.TypeOf(identityclient.Config{}).FieldByName("ClientSecret"); ok {
		t.Fatal("Config must not have a ClientSecret field")
	}
}

func TestLoadConfigFileErrors(t *testing.T) {
	// A missing default file is fine; a missing explicit one is not.
	if _, err := identityclient.LoadConfig(identityclient.Flags{Issuer: "https://i.example.com", CacheDir: "/c"}, envOf(nil), noFile); err != nil {
		t.Fatal(err)
	}
	if _, err := identityclient.LoadConfig(identityclient.Flags{ConfigFile: "/nope.yaml"}, envOf(nil), noFile); err == nil {
		t.Fatal("explicit missing file must fail")
	}
	boom := func(string) ([]byte, error) { return nil, errors.New("boom") }
	if _, err := identityclient.LoadConfig(identityclient.Flags{Issuer: "https://i.example.com"}, envOf(nil), boom); err == nil {
		t.Fatal("read error must fail")
	}
	if _, err := identityclient.LoadConfig(identityclient.Flags{}, envOf(nil), fileOf(": : :\n\t- [")); err == nil {
		t.Fatal("bad yaml must fail")
	}
	if _, err := identityclient.LoadConfig(identityclient.Flags{}, envOf(nil), fileOf("")); err == nil {
		t.Fatal("no issuer must fail")
	}
	// The explicit file is the one read.
	var read string
	spy := func(p string) ([]byte, error) {
		read = p
		return []byte("issuer: https://i.example.com\ncache_dir: /c"), nil
	}
	if _, err := identityclient.LoadConfig(identityclient.Flags{ConfigFile: "/etc/x.yaml"}, envOf(nil), spy); err != nil || read != "/etc/x.yaml" {
		t.Fatalf("read %q err %v", read, err)
	}
}

func TestHTTPIssuerLoopbackOnly(t *testing.T) {
	ok := []string{"http://localhost:5556/dex", "http://127.0.0.1:5556/dex", "http://[::1]:5556/dex", "https://idp.example.com", "https://10.0.0.5/dex"}
	bad := []string{"http://dex:5556/dex", "http://10.0.0.5/dex", "http://idp.example.com", "http://localhost.evil.example/dex",
		"https://idp.example.com/dex?x=1", "https://idp.example.com/dex#f", "https://u:p@idp.example.com", ""}
	for _, iss := range ok {
		if _, err := identityclient.LoadConfig(identityclient.Flags{Issuer: iss, CacheDir: "/c"}, envOf(nil), noFile); err != nil {
			t.Errorf("%s: want accepted, got %v", iss, err)
		}
	}
	for _, iss := range bad {
		_, err := identityclient.LoadConfig(identityclient.Flags{Issuer: iss, CacheDir: "/c"}, envOf(nil), noFile)
		if err == nil {
			t.Errorf("%s: want rejected", iss)
		} else if strings.Contains(err.Error(), "p@idp") {
			t.Errorf("error leaks userinfo: %v", err)
		}
	}
}
