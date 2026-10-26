package deploy

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	tokPassword = "pw-DO-NOT-LEAK-1"
	tokSecret   = "cs-DO-NOT-LEAK-2"
	tokRefresh  = "rt-SECRET-REFRESH"
	tokScope    = "openid email profile groups offline_access audience:server:client_id:warden"
)

func requireTools(t *testing.T) {
	t.Helper()
	for _, name := range []string{"curl", "jq"} {
		if _, err := exec.LookPath(name); err != nil {
			if os.Getenv("CI") == "true" {
				t.Fatalf("curl and jq are required in CI: %s not on PATH", name)
			}
			t.Skipf("BLOCKED (skipped, not passed): %s not on PATH", name)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// mkJWT builds an unsigned JWT-shaped token; the script only decodes it.
func mkJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return b64([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + b64(body) + "." + b64([]byte("sig-NOT-A-REAL-SIGNATURE"))
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": "http://localhost:5556/dex", "sub": "CiQwOA-sub", "email": "alice@example.test",
		"groups": []string{"warden-admins", "eng"}, "aud": []string{"agent-harness", "warden"},
		"azp": "agent-harness", "iat": 1000, "exp": 4600,
	}
}

func TestDexTokenScript(t *testing.T) {
	requireTools(t)
	script := filepath.Join(repoRoot(t), "scripts", "dex-token.sh")

	type fake struct {
		mu   sync.Mutex
		form url.Values
		auth string
		hits int
	}
	serve := func(t *testing.T, status int, body func() any) (*httptest.Server, *fake) {
		f := &fake{}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/dex/token" {
				http.NotFound(w, r)
				return
			}
			_ = r.ParseForm()
			f.mu.Lock()
			f.form, f.auth = r.PostForm, r.Header.Get("Authorization")
			f.hits++
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(body())
		}))
		t.Cleanup(srv.Close)
		return srv, f
	}
	tokenBody := func(claims map[string]any) func() any {
		return func() any {
			return map[string]any{"id_token": mkJWT(t, claims), "refresh_token": tokRefresh,
				"access_token": "at", "token_type": "bearer", "expires_in": 3600}
		}
	}
	with := func(c map[string]any, k string, v any) map[string]any {
		out := map[string]any{}
		for kk, vv := range c {
			out[kk] = vv
		}
		out[k] = v
		return out
	}
	run := func(t *testing.T, env map[string]string, args ...string) (string, string, int) {
		t.Helper()
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		for k, v := range env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		var so, se strings.Builder
		cmd.Stdout, cmd.Stderr = &so, &se
		err := cmd.Run()
		code := 0
		if err != nil {
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("run script: %v", err)
			}
			code = ee.ExitCode()
		}
		return so.String(), se.String(), code
	}
	baseEnv := func(srv *httptest.Server) map[string]string {
		return map[string]string{
			"DEX_URL": srv.URL + "/dex", "DEX_TEST_PASSWORD": tokPassword,
			"HARNESS_DEX_CLIENT_SECRET": tokSecret,
		}
	}
	noLeak := func(t *testing.T, out string, tok string) {
		t.Helper()
		for _, s := range []string{tokPassword, tokSecret, tokRefresh, "sig-NOT-A-REAL-SIGNATURE", b64([]byte("sig-NOT-A-REAL-SIGNATURE"))} {
			if strings.Contains(out, s) {
				t.Errorf("output leaks %q", s)
			}
		}
		if tok != "" && strings.Contains(out, tok) {
			t.Errorf("output leaks the token")
		}
	}

	t.Run("default_url", func(t *testing.T) {
		_, stderr, code := run(t, map[string]string{})
		if code == 0 {
			t.Fatal("want non-zero exit for no arguments")
		}
		if !strings.Contains(stderr, "http://localhost:5556/dex") {
			t.Errorf("usage must name the default DEX_URL: %q", stderr)
		}
	})

	t.Run("happy", func(t *testing.T) {
		srv, f := serve(t, 200, tokenBody(goodClaims()))
		stdout, stderr, code := run(t, baseEnv(srv), "alice")
		if code != 0 {
			t.Fatalf("exit %d, stderr=%q", code, stderr)
		}
		for _, w := range []string{"sub", "email", "groups", "aud", "azp", "exp", "iat", "warden-admins"} {
			if !strings.Contains(stdout, w) {
				t.Errorf("stdout missing %q: %s", w, stdout)
			}
		}
		var got map[string]json.RawMessage
		if err := json.Unmarshal([]byte(stdout), &got); err != nil {
			t.Fatalf("stdout is not one JSON object: %v: %s", err, stdout)
		}
		if len(got) != 7 {
			t.Errorf("stdout must hold exactly the 7 listed claims, got %d: %s", len(got), stdout)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.auth != "" {
			t.Errorf("credentials must travel in the form body, got an Authorization header")
		}
		for k, v := range map[string]string{"grant_type": "password", "username": "alice", "scope": tokScope, "client_id": "agent-harness"} {
			if f.form.Get(k) != v {
				t.Errorf("form %s = %q, want %q", k, f.form.Get(k), v)
			}
		}
		if f.form.Get("client_secret") != tokSecret || f.form.Get("password") != tokPassword {
			t.Errorf("credentials missing from the request")
		}
		noLeak(t, stdout+stderr, mkJWT(t, goodClaims()))
	})

	t.Run("aud_string", func(t *testing.T) {
		srv, _ := serve(t, 200, tokenBody(with(goodClaims(), "aud", "warden")))
		stdout, stderr, code := run(t, baseEnv(srv), "alice")
		if code != 0 {
			t.Fatalf("exit %d, stderr=%q", code, stderr)
		}
		noLeak(t, stdout+stderr, mkJWT(t, with(goodClaims(), "aud", "warden")))
	})

	for _, tc := range []struct {
		name string
		body func() any
		want string
	}{
		{"body_not_object", func() any { return "<html>oops</html>" }, "not JSON"},
		{"no_id_token", func() any { return map[string]any{"access_token": "at"} }, "no id_token"},
		{"payload_not_json", func() any { return map[string]any{"id_token": "h." + b64([]byte("not json")) + ".s"} }, "not JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := serve(t, 200, tc.body)
			stdout, stderr, code := run(t, baseEnv(srv), "alice")
			if code == 0 || !strings.Contains(stderr, tc.want) {
				t.Errorf("want non-zero exit naming %q; code=%d stderr=%q", tc.want, code, stderr)
			}
			noLeak(t, stdout+stderr, "")
		})
	}

	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"wrong_azp", with(goodClaims(), "azp", "other"), "azp"},
		{"aud_without_warden", with(goodClaims(), "aud", []string{"agent-harness"}), "aud"},
		{"lifetime", with(goodClaims(), "exp", 8200), "exp-iat"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := serve(t, 200, tokenBody(tc.claims))
			stdout, stderr, code := run(t, baseEnv(srv), "alice")
			if code == 0 {
				t.Fatal("want non-zero exit")
			}
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("stderr must name %q: %q", tc.want, stderr)
			}
			noLeak(t, stdout+stderr, mkJWT(t, tc.claims))
		})
	}

	for _, v := range []string{"DEX_TEST_PASSWORD", "HARNESS_DEX_CLIENT_SECRET"} {
		t.Run("missing_"+v, func(t *testing.T) {
			srv, f := serve(t, 200, tokenBody(goodClaims()))
			env := baseEnv(srv)
			delete(env, v)
			stdout, stderr, code := run(t, env, "alice")
			if code == 0 || !strings.Contains(stderr, v) {
				t.Errorf("want non-zero exit naming %s; code=%d stderr=%q", v, code, stderr)
			}
			noLeak(t, stdout+stderr, "")
			if f.hits != 0 {
				t.Error("no request may be made when a variable is missing")
			}
		})
	}

	t.Run("wrong_password", func(t *testing.T) {
		srv, _ := serve(t, 401, func() any {
			return map[string]any{"error": "invalid_grant", "error_description": "bad login for " + tokPassword}
		})
		stdout, stderr, code := run(t, baseEnv(srv), "alice")
		if code == 0 || !strings.Contains(stderr, "invalid_grant") {
			t.Errorf("want non-zero exit naming invalid_grant; code=%d stderr=%q", code, stderr)
		}
		if strings.Contains(stderr, "bad login") {
			t.Error("error_description must not be printed")
		}
		noLeak(t, stdout+stderr, "")
	})

	t.Run("raw", func(t *testing.T) {
		srv, _ := serve(t, 200, tokenBody(goodClaims()))
		stdout, stderr, code := run(t, baseEnv(srv), "alice", "--raw")
		if code != 0 {
			t.Fatalf("exit %d, stderr=%q", code, stderr)
		}
		if want := mkJWT(t, goodClaims()) + "\n"; stdout != want {
			t.Errorf("stdout must be exactly the token line; got %q", stdout)
		}
		noLeak(t, stderr, mkJWT(t, goodClaims()))
		for _, s := range []string{tokPassword, tokSecret, tokRefresh} {
			if strings.Contains(stdout, s) {
				t.Errorf("stdout leaks %q", s)
			}
		}
	})
}
