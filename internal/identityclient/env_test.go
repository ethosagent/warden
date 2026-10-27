package identityclient_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

// parseDotenv reads KEY="value" lines as emitted by the dotenv format.
func parseDotenv(t *testing.T, out string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
			t.Fatalf("bad dotenv line %q", line)
		}
		v = v[1 : len(v)-1]
		m[k] = strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\$`, `$`).Replace(v)
	}
	return m
}

// TestEnvConnectHeader parses the dotenv output, points an http.Transport at
// the resulting HTTPS_PROXY and checks that a CONNECT listener sees the
// session credentials.
func TestEnvConnectHeader(t *testing.T) {
	const token = "aaa.bbb.ccc"
	var mu sync.Mutex
	var gotAuth, gotMethod string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth, gotMethod = r.Header.Get("Proxy-Authorization"), r.Method
		mu.Unlock()
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer proxy.Close()
	worker := strings.TrimPrefix(proxy.URL, "http://")

	out, err := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{Format: identityclient.FormatDotenv})
	if err != nil {
		t.Fatal(err)
	}
	env := parseDotenv(t, out)
	if _, ok := env["HTTP_PROXY"]; ok || strings.Contains(out, "HTTP_PROXY") || strings.Contains(out, "http_proxy") {
		t.Errorf("default output must not set HTTP_PROXY:\n%s", out)
	}
	if env["NO_PROXY"] != "localhost,127.0.0.1" || env["HTTPS_PROXY"] != env["https_proxy"] {
		t.Errorf("unexpected env: %v", env)
	}
	pu, err := http.NewRequest(http.MethodGet, env["HTTPS_PROXY"], nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: http.ProxyURL(pu.URL)}
	defer tr.CloseIdleConnections()
	req, _ := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	if resp, err := (&http.Client{Transport: tr}).Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("the stub proxy refuses CONNECT; the request should fail")
	}
	mu.Lock()
	defer mu.Unlock()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+token))
	if gotMethod != http.MethodConnect || gotAuth != want {
		t.Errorf("proxy saw %s with Proxy-Authorization %q, want CONNECT with %q", gotMethod, gotAuth, want)
	}

	withHTTP, err := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{Format: identityclient.FormatDotenv, IncludeHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	e2 := parseDotenv(t, withHTTP)
	if e2["HTTP_PROXY"] != env["HTTPS_PROXY"] || e2["http_proxy"] != env["HTTPS_PROXY"] {
		t.Errorf("--include-http must add HTTP_PROXY: %v", e2)
	}
}

func TestProxyEnvFormats(t *testing.T) {
	const worker = "worker.internal:8080"
	// A token and CA path full of shell-special characters.
	const token = `t'k"$x y\z` + "`;&"
	const ca = `/etc/my ca's/"bundle" $HOME.pem`
	ca4 := []string{"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"}

	t.Run("json", func(t *testing.T) {
		out, err := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{Format: identityclient.FormatJSON, CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]string
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("not json: %v\n%s", err, out)
		}
		for _, n := range ca4 {
			if m[n] != ca {
				t.Errorf("%s = %q", n, m[n])
			}
		}
		if m["HTTPS_PROXY"] == "" || m["NO_PROXY"] != "localhost,127.0.0.1" {
			t.Errorf("missing proxy vars: %v", m)
		}
	})
	t.Run("dotenv", func(t *testing.T) {
		out, err := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{Format: identityclient.FormatDotenv, CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		m := parseDotenv(t, out)
		for _, n := range ca4 {
			if m[n] != ca {
				t.Errorf("%s = %q, want %q", n, m[n], ca)
			}
		}
	})
	t.Run("no CA by default", func(t *testing.T) {
		out, _ := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{})
		for _, n := range ca4 {
			if strings.Contains(out, n) {
				t.Errorf("%s set without --ca", n)
			}
		}
	})
	t.Run("sh", func(t *testing.T) {
		out, err := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "export HTTPS_PROXY='http://session:") || !strings.Contains(out, "export NO_PROXY='localhost,127.0.0.1'\n") {
			t.Errorf("unexpected sh output:\n%s", out)
		}
		// A real shell must read the CA path back verbatim.
		if sh, err := exec.LookPath("sh"); err == nil {
			got, err := exec.Command(sh, "-c", out+`printf %s "$SSL_CERT_FILE"`).Output()
			if err != nil || string(got) != ca {
				t.Errorf("sh read back %q (%v), want %q", got, err, ca)
			}
		}
	})
	t.Run("fish", func(t *testing.T) {
		out, err := identityclient.ProxyEnv(worker, "tok", identityclient.EnvOptions{Shell: identityclient.ShellFish, CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		wantCA := `set -gx SSL_CERT_FILE '/etc/my ca\'s/"bundle" $HOME.pem'`
		if !strings.Contains(out, "set -gx HTTPS_PROXY 'http://session:tok@worker.internal:8080'\n") || !strings.Contains(out, wantCA+"\n") {
			t.Errorf("unexpected fish output:\n%s", out)
		}
		bs, _ := identityclient.ProxyEnv(worker, "tok", identityclient.EnvOptions{Shell: identityclient.ShellFish, CA: `C:\certs\a.pem`})
		if !strings.Contains(bs, `'C:\\certs\\a.pem'`) {
			t.Errorf("backslashes must be doubled for fish:\n%s", bs)
		}
	})
	t.Run("powershell", func(t *testing.T) {
		out, err := identityclient.ProxyEnv(worker, "tok", identityclient.EnvOptions{Shell: identityclient.ShellPowerShell, CA: ca})
		if err != nil {
			t.Fatal(err)
		}
		wantCA := `$env:SSL_CERT_FILE = '/etc/my ca''s/"bundle" $HOME.pem'`
		if !strings.Contains(out, "$env:HTTPS_PROXY = 'http://session:tok@worker.internal:8080'\n") || !strings.Contains(out, wantCA+"\n") {
			t.Errorf("unexpected powershell output:\n%s", out)
		}
	})
	t.Run("token is percent-encoded in the URL", func(t *testing.T) {
		out, _ := identityclient.ProxyEnv(worker, token, identityclient.EnvOptions{Format: identityclient.FormatDotenv})
		if strings.Contains(out, `"$x`) || strings.Contains(out, "t'k") {
			t.Errorf("raw special characters leaked into the proxy URL:\n%s", out)
		}
	})
}

func TestProxyEnvRejects(t *testing.T) {
	cases := map[string]struct {
		worker, token string
		opts          identityclient.EnvOptions
	}{
		"no port":       {"worker", "SECRET-TOK", identityclient.EnvOptions{}},
		"scheme":        {"http://worker:8080", "SECRET-TOK", identityclient.EnvOptions{}},
		"newline host":  {"wor\nker:8080", "SECRET-TOK", identityclient.EnvOptions{}},
		"bad port":      {"worker:99999", "SECRET-TOK", identityclient.EnvOptions{}},
		"userinfo":      {"u@worker:8080", "SECRET-TOK", identityclient.EnvOptions{}},
		"empty token":   {"worker:8080", "", identityclient.EnvOptions{}},
		"newline token": {"worker:8080", "a\nb", identityclient.EnvOptions{}},
		"newline CA":    {"worker:8080", "SECRET-TOK", identityclient.EnvOptions{CA: "a\nb"}},
		"unknown shell": {"worker:8080", "SECRET-TOK", identityclient.EnvOptions{Shell: "csh"}},
		"unknown fmt":   {"worker:8080", "SECRET-TOK", identityclient.EnvOptions{Format: "xml"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := identityclient.ProxyEnv(c.worker, c.token, c.opts)
			if err == nil {
				t.Fatalf("expected an error, got %q", out)
			}
			if c.token != "" && strings.Contains(err.Error(), c.token) {
				t.Errorf("error echoes the token: %v", err)
			}
		})
	}
}

func TestTokenExpiry(t *testing.T) {
	r := newRig(t)
	r.login(t)
	e, err := r.cl.Store().Load()
	if err != nil {
		t.Fatal(err)
	}
	got, err := identityclient.TokenExpiry(e.IDToken)
	if err != nil || !got.Equal(r.clock.Now().Add(tokenTTL)) {
		t.Errorf("TokenExpiry = %v, %v", got, err)
	}
	if _, err := identityclient.TokenExpiry("not-a-jwt"); err == nil {
		t.Error("expected an error for a non-JWT")
	}
}
