package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	testDeviceCode = "DEVICE-CODE-SECRET-0001"
	testUserCode   = "ABCD-EFGH"
	testRefresh    = "refresh-token-secret"
	testAccess     = "access-token-secret"
	testTokenTTL   = 30 * time.Minute
)

// idp is a fake OIDC issuer (discovery, device authorization, token) whose ID
// tokens are signed by test/fakes.OIDCIssuer.
type idp struct {
	srv    *httptest.Server
	signer *fakes.OIDCIssuer

	jti       atomic.Int64
	mu        sync.Mutex
	rotations int
	refresh   string
}

func newIdP(t *testing.T) *idp {
	t.Helper()
	p := &idp{signer: fakes.NewOIDCIssuer(t), refresh: testRefresh}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": p.srv.URL, "token_endpoint": p.srv.URL + "/token",
			"device_authorization_endpoint": p.srv.URL + "/device",
		})
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": testDeviceCode, "user_code": testUserCode,
			"verification_uri": p.srv.URL + "/activate", "expires_in": 600, "interval": 1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		defer p.mu.Unlock()
		if g := r.PostForm.Get("grant_type"); g == "refresh_token" && r.PostForm.Get("refresh_token") != p.refresh {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "IDP-ERROR-BODY-MARKER"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		p.rotations++
		p.refresh = testRefresh + "-" + string(rune('a'+p.rotations))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": testAccess, "token_type": "bearer", "expires_in": int(testTokenTTL.Seconds()),
			"refresh_token": p.refresh, "id_token": p.mint(time.Now(), testTokenTTL),
		})
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *idp) mint(iat time.Time, ttl time.Duration) string {
	// A fresh jti makes every token distinct even within one second.
	return p.signer.Mint(fakes.Valid("user-1", "u@example.com", "eng", "ops"),
		fakes.WithIss(p.srv.URL), fakes.WithAud("warden"), fakes.WithAZP("warden-cli"),
		fakes.WithIAT(iat), fakes.WithExp(iat.Add(ttl)), fakes.WithClaim("jti", p.jti.Add(1)))
}

// rig runs identity commands with hermetic inputs: an env map instead of the
// process environment, and no identity.yaml from the real home directory.
type rig struct {
	t        *testing.T
	env      map[string]string
	stdin    string
	skew     time.Duration // added to the client clock
	cacheDir string
	// parent holds extra parent variables `exec` may look up, beyond env,
	// PATH and the helper mode.
	parent map[string]string
}

func newRig(t *testing.T, issuer string) *rig {
	t.Helper()
	cache := filepath.Join(t.TempDir(), "cache")
	return &rig{t: t, cacheDir: cache, env: map[string]string{
		identityclient.EnvIssuer: issuer, identityclient.EnvCacheDir: cache,
	}}
}

func (r *rig) deps() identityDeps {
	return identityDeps{
		getenv: func(k string) string { return r.env[k] },
		readFile: func(p string) ([]byte, error) {
			if filepath.Base(p) == "identity.yaml" {
				return nil, fs.ErrNotExist
			}
			return os.ReadFile(p)
		},
		openFile: func(p string) (io.ReadCloser, error) { return os.Open(p) },
		stdin:    strings.NewReader(r.stdin),
	}
}

// run executes `warden <args>` with the identity subtree and returns stdout, stderr and the error.
func (r *rig) run(args ...string) (string, string, error) {
	r.t.Helper()
	d := r.deps()
	skew := r.skew
	d.tune = func(c *identityclient.Client) {
		c.Sleep = noSleep
		c.Now = func() time.Time { return time.Now().Add(skew) }
	}
	root := &cobra.Command{Use: "warden"}
	root.PersistentFlags().String("config", "configs/config.example.yaml", "")
	root.AddCommand(newIdentityCmdWith(d))
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), errb.String(), err
}

func noSleep(ctx context.Context, _ time.Duration) error { return ctx.Err() }

// loggedIn runs `login` against the fake issuer and returns the cached entry.
func (r *rig) loggedIn() identityclient.Entry {
	r.t.Helper()
	if _, _, err := r.run("identity", "login"); err != nil {
		r.t.Fatalf("login: %v", err)
	}
	cfg, err := identityclient.LoadConfig(identityclient.Flags{}, func(k string) string { return r.env[k] },
		func(string) ([]byte, error) { return nil, fs.ErrNotExist })
	if err != nil {
		r.t.Fatal(err)
	}
	e, err := identityclient.NewFileStore(cfg).Load()
	if err != nil {
		r.t.Fatal(err)
	}
	return e
}

func TestIdentityCmd(t *testing.T) {
	t.Run("five subcommands are registered", func(t *testing.T) {
		root := newRootCmd()
		for _, name := range []string{"login", "token", "status", "env", "logout"} {
			c, _, err := root.Find([]string{"identity", name})
			if err != nil || c.Name() != name {
				t.Errorf("identity %s not registered: %v", name, err)
			}
		}
	})

	t.Run("no flag takes a literal client secret", func(t *testing.T) {
		id := newIdentityCmd()
		usages := id.PersistentFlags().FlagUsages()
		for _, c := range id.Commands() {
			usages += c.LocalFlags().FlagUsages()
		}
		var names []string
		for _, m := range regexp.MustCompile(`--([a-z][a-z-]*)`).FindAllStringSubmatch(usages, -1) {
			names = append(names, m[1])
		}
		if len(names) < 10 {
			t.Fatalf("flag scan found too few flags: %v", names)
		}
		var secretFlags []string
		for _, n := range names {
			if strings.Contains(n, "secret") || strings.Contains(n, "password") {
				secretFlags = append(secretFlags, n)
			}
			if n == "token" || n == "refresh-token" || n == "id-token" {
				t.Errorf("flag --%s would take a token on argv", n)
			}
		}
		if len(secretFlags) != 1 || secretFlags[0] != "client-secret-env" {
			t.Errorf("secret-related flags = %v, want only client-secret-env", secretFlags)
		}

		r := newRig(t, "http://127.0.0.1:1")
		if _, _, err := r.run("identity", "token", "--client-secret", "hunter2"); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("--client-secret should be an unknown flag, got %v", err)
		}
		_, stderr, err := r.run("identity", "token", "--client-secret-env", "s3cr3t-literal!")
		if err == nil || strings.Contains(err.Error()+stderr, "s3cr3t-literal") {
			t.Errorf("a literal secret must be refused without being echoed: %v %q", err, stderr)
		}
	})

	t.Run("the root --config is not read", func(t *testing.T) {
		p := newIdP(t)
		r := newRig(t, p.srv.URL)
		r.loggedIn()
		bad := filepath.Join(t.TempDir(), "worker.yaml")
		if err := os.WriteFile(bad, []byte("::: not yaml {{{"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, cfg := range []string{bad, filepath.Join(t.TempDir(), "missing.yaml")} {
			stdout, _, err := r.run("--config", cfg, "identity", "status")
			if err != nil || !strings.Contains(stdout, "sub: user-1") {
				t.Errorf("--config %s: status = %q, %v", cfg, stdout, err)
			}
		}
	})

	t.Run("--token is rejected as an argv value", func(t *testing.T) {
		r := newRig(t, "http://127.0.0.1:1")
		for _, args := range [][]string{
			{"identity", "env", "--worker", "h:1", "--token", "SECRET-TOKEN-VALUE"},
			{"identity", "env", "--worker", "h:1", "--token=SECRET-TOKEN-VALUE"},
			{"identity", "env", "--worker", "h:1", "SECRET-TOKEN-VALUE"},
			{"identity", "token", "--token", "SECRET-TOKEN-VALUE"},
		} {
			stdout, _, err := r.run(args...)
			if err == nil {
				t.Errorf("%v: expected an error", args)
			}
			if stdout != "" {
				t.Errorf("%v: printed %q", args, stdout)
			}
		}
	})

	t.Run("verbose output carries no token, refresh token or device code", func(t *testing.T) {
		p := newIdP(t)
		r := newRig(t, p.srv.URL)
		var stderrAll strings.Builder
		run := func(args ...string) string {
			stdout, stderr, err := r.run(args...)
			if err != nil {
				t.Fatalf("%v: %v", args, err)
			}
			stderrAll.WriteString(stderr)
			return stdout
		}
		run("identity", "login", "--verbose")
		first := run("identity", "token", "--verbose")
		r.skew = 25 * time.Minute // past 2/3 of the lifetime: forces a refresh and rotation
		second := run("identity", "token", "--verbose")
		run("identity", "status", "--verbose")
		r.stdin = strings.TrimSpace(second)
		run("identity", "env", "--worker", "w:8080", "--token-stdin", "--verbose")
		run("identity", "logout", "--verbose")

		if strings.TrimSpace(first) == strings.TrimSpace(second) {
			t.Fatal("the second token call should have refreshed")
		}
		all := stderrAll.String()
		if !strings.Contains(all, testUserCode) {
			t.Errorf("login must print the user code to stderr:\n%s", all)
		}
		if !strings.Contains(all, "token_fp=") {
			t.Errorf("--verbose should log the token fingerprint:\n%s", all)
		}
		secrets := []string{testDeviceCode, testRefresh, testAccess, "IDP-ERROR-BODY-MARKER"}
		for _, tok := range []string{first, second} {
			secrets = append(secrets, strings.TrimSpace(tok))
			secrets = append(secrets, strings.Split(strings.TrimSpace(tok), ".")...)
		}
		for _, s := range secrets {
			if len(s) >= 8 && strings.Contains(all, s) {
				t.Errorf("stderr leaks %q", s[:8]+"...")
			}
		}
	})
}

func TestIdentityCmdOutputs(t *testing.T) {
	p := newIdP(t)
	r := newRig(t, p.srv.URL)
	e := r.loggedIn()

	t.Run("login prints the verification URI and user code to stderr only", func(t *testing.T) {
		stdout, stderr, err := r.run("identity", "login")
		if err != nil || stdout != "" {
			t.Fatalf("stdout %q err %v", stdout, err)
		}
		if !strings.Contains(stderr, p.srv.URL+"/activate") || !strings.Contains(stderr, testUserCode) {
			t.Errorf("stderr lacks the URI or code:\n%s", stderr)
		}
	})
	t.Run("token prints the token to stdout only", func(t *testing.T) {
		e = r.loggedIn()
		stdout, stderr, err := r.run("identity", "token")
		if err != nil || strings.TrimSpace(stdout) != e.IDToken || stderr != "" {
			t.Errorf("stdout %q stderr %q err %v", stdout, stderr, err)
		}
	})
	t.Run("status prints the claims and cache path, never the token", func(t *testing.T) {
		stdout, stderr, err := r.run("identity", "status")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"iss: " + p.srv.URL, "sub: user-1", "email: u@example.com", "groups: eng,ops", "exp: ", "cache: " + r.cacheDir} {
			if !strings.Contains(stdout, want) {
				t.Errorf("status lacks %q:\n%s", want, stdout)
			}
		}
		if strings.Contains(stdout+stderr, e.IDToken) || strings.Contains(stdout+stderr, strings.Split(e.IDToken, ".")[2]) {
			t.Error("status printed the token")
		}
	})
	t.Run("env from the cache", func(t *testing.T) {
		stdout, stderr, err := r.run("identity", "env", "--worker", "w:8080", "--format", "dotenv", "--ca", "/etc/ca.pem")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout, `HTTPS_PROXY="http://session:`+e.IDToken+`@w:8080"`) || !strings.Contains(stdout, `NODE_EXTRA_CA_CERTS="/etc/ca.pem"`) {
			t.Errorf("unexpected env:\n%s", stdout)
		}
		if strings.Contains(stderr, e.IDToken) || !strings.Contains(stderr, "token expires at") || !strings.Contains(stderr, "child process") {
			t.Errorf("stderr should carry the expiry and the child-process warning, not the token:\n%s", stderr)
		}
	})
	t.Run("env from stdin and from a file", func(t *testing.T) {
		tok := p.mint(time.Now(), time.Hour)
		r.stdin = tok + "\n"
		stdout, stderr, err := r.run("identity", "env", "--worker", "w:8080", "--token-stdin", "--shell", "fish", "--include-http")
		if err != nil || !strings.Contains(stdout, "set -gx HTTPS_PROXY 'http://session:"+tok+"@w:8080'") || !strings.Contains(stdout, "set -gx http_proxy ") {
			t.Fatalf("stdin env: %q %v", stdout, err)
		}
		if !strings.Contains(stderr, "denies plain http") {
			t.Errorf("--include-http should note on stderr that the worker denies plain http:\n%s", stderr)
		}
		f := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(f, []byte(tok), 0o600); err != nil {
			t.Fatal(err)
		}
		stdout, _, err = r.run("identity", "env", "--worker", "w:8080", "--token-file", f, "--format", "json")
		if err != nil || !strings.Contains(stdout, `"HTTPS_PROXY": "http://session:`+tok) {
			t.Fatalf("file env: %q %v", stdout, err)
		}
		big := filepath.Join(t.TempDir(), "big")
		if err := os.WriteFile(big, bytes.Repeat([]byte("a"), 70<<10), 0o600); err != nil {
			t.Fatal(err)
		}
		if stdout, _, err := r.run("identity", "env", "--worker", "w:8080", "--token-file", big); err == nil || stdout != "" {
			t.Errorf("an oversize token file must be refused: %q %v", stdout, err)
		}
		if _, _, err := r.run("identity", "env", "--worker", "w:8080", "--token-stdin", "--token-file", f); err == nil {
			t.Error("--token-stdin with --token-file should be refused")
		}
	})
	t.Run("env needs --worker and a valid shell", func(t *testing.T) {
		if _, _, err := r.run("identity", "env"); err == nil {
			t.Error("--worker is required")
		}
		if _, _, err := r.run("identity", "env", "--worker", "w:8080", "--shell", "csh"); err == nil {
			t.Error("unknown shell should fail")
		}
	})
	t.Run("logout deletes the cache entry", func(t *testing.T) {
		if _, _, err := r.run("identity", "logout"); err != nil {
			t.Fatal(err)
		}
		entries, _ := os.ReadDir(r.cacheDir)
		for _, en := range entries {
			if strings.HasSuffix(en.Name(), ".json") {
				t.Errorf("cache file %s remains after logout", en.Name())
			}
		}
		if _, _, err := r.run("identity", "token"); exitCode(err) != 2 {
			t.Errorf("token after logout: %v", err)
		}
	})
}

func TestIdentityExitCodes(t *testing.T) {
	t.Run("login required exits 2", func(t *testing.T) {
		p := newIdP(t)
		r := newRig(t, p.srv.URL)
		for _, sub := range []string{"token", "status"} {
			stdout, _, err := r.run("identity", sub)
			if !errors.Is(err, identityclient.ErrLoginRequired) || exitCode(err) != 2 || stdout != "" {
				t.Errorf("%s: code %d, err %v, stdout %q", sub, exitCode(err), err, stdout)
			}
		}
		if _, _, err := r.run("identity", "env", "--worker", "w:1"); exitCode(err) != 2 {
			t.Errorf("env from an empty cache: code %d, %v", exitCode(err), err)
		}
	})

	t.Run("issuer down with no valid cache exits 3", func(t *testing.T) {
		p := newIdP(t)
		r := newRig(t, p.srv.URL)
		cfg, err := identityclient.LoadConfig(identityclient.Flags{}, func(k string) string { return r.env[k] },
			func(string) ([]byte, error) { return nil, fs.ErrNotExist })
		if err != nil {
			t.Fatal(err)
		}
		past := time.Now().Add(-2 * time.Hour)
		err = identityclient.NewFileStore(cfg).Save(identityclient.Entry{
			Issuer: p.srv.URL, ClientID: identityclient.DefaultClientID, RefreshToken: testRefresh,
			IDToken: p.mint(past, time.Hour), ReceivedAt: past,
		})
		if err != nil {
			t.Fatal(err)
		}
		p.srv.Close() // the issuer is down
		stdout, _, err := r.run("identity", "token")
		if !errors.Is(err, identityclient.ErrIssuerUnreachable) || exitCode(err) != 3 || stdout != "" {
			t.Errorf("code %d, err %v, stdout %q", exitCode(err), err, stdout)
		}
	})

	t.Run("a still-valid cached token is served with a warning when the issuer is down", func(t *testing.T) {
		p := newIdP(t)
		r := newRig(t, p.srv.URL)
		e := r.loggedIn()
		p.srv.Close()
		r.skew = 25 * time.Minute // refresh is due, but the token has not expired
		stdout, stderr, err := r.run("identity", "token")
		if err != nil || strings.TrimSpace(stdout) != e.IDToken || !strings.Contains(stderr, "warning: ") {
			t.Errorf("stdout %q stderr %q err %v", stdout, stderr, err)
		}
	})

	t.Run("other errors exit 1", func(t *testing.T) {
		r := newRig(t, "")
		_, _, err := r.run("identity", "token")
		if err == nil || exitCode(err) != 1 {
			t.Errorf("a missing issuer: code %d, %v", exitCode(err), err)
		}
		r.env[identityclient.EnvIssuer] = "http://example.com" // plain http on a non-loopback host
		if _, _, err := r.run("identity", "login"); err == nil || exitCode(err) != 1 {
			t.Errorf("a non-loopback http issuer: code %d, %v", exitCode(err), err)
		}
	})

	t.Run("exitCode of a plain error is 1 and of nil is irrelevant", func(t *testing.T) {
		if exitCode(errors.New("x")) != 1 {
			t.Error("plain errors exit 1")
		}
	})
}
