package worker

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/proxy"
)

// countingDialer records every upstream dial a worker attempts and makes none.
type countingDialer struct{ n atomic.Int64 }

func (d *countingDialer) Dial(string, string) (net.Conn, error) {
	d.n.Add(1)
	return nil, errors.New("no upstream in this test")
}

func (d *countingDialer) DialTLS(string, string, *tls.Config) (*tls.Conn, error) {
	d.n.Add(1)
	return nil, errors.New("no upstream in this test")
}

// jwtShaped is a three-segment token no key signed: header {"alg":"RS256",
// "typ":"JWT"}, a payload naming iss, and a junk signature.
func jwtShaped(iss string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256","typ":"JWT","kid":"k1"}`)) + "." +
		enc([]byte(`{"iss":"`+iss+`","sub":"u1","aud":"warden","exp":4102444800,"iat":1}`)) + ".c2ln"
}

// connectWith sends one CONNECT with the given Proxy-Authorization value ("" for
// none) and returns the reply with its body read.
func connectWith(t *testing.T, addr, hostPort, auth string) (*http.Response, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if auth != "" {
		req += "Proxy-Authorization: " + auth + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read the CONNECT reply: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// startRequireWorker boots a managed worker whose control plane serves settings
// with require for its agent but no signed bundle (the worker has no pins), the
// state before the first verified bundle. It returns the proxy address and the
// dialer that counts upstream dials.
func startRequireWorker(t *testing.T, settings config.SettingsWire) (string, *countingDialer) {
	t.Helper()
	wire, err := json.Marshal(map[string]any{
		"allowlist": []map[string]string{{"domain": "api.example.test"}},
		"settings":  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/policy", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait") != "" && r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write(wire)
	})
	mux.HandleFunc("/control/heartbeat", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cp := httptest.NewTLSServer(mux)
	t.Cleanup(cp.Close)
	caPath := filepath.Join(t.TempDir(), "cp-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WARDEN_CP_TOKEN", "test-token")
	cfg := `
controlPlane:
  endpoint: ` + cp.URL + `/policy
  tokenEnv: WARDEN_CP_TOKEN
  caCert: ` + caPath + `
  longPollWait: 50ms
  heartbeatInterval: 1s
logging:
  level: error
  format: text
`
	p := runParams(t, writeConfig(t, cfg))
	p.AgentID = "boot-agent"
	dialer := &countingDialer{}
	p.Overrides = &Overrides{Dialer: dialer}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ProxyListener = ln
	ready := make(chan string, 1)
	p.OnReady = func(proxyAddr, _ string) { ready <- proxyAddr }
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- Run(ctx, &syncBuffer{}, p) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runErr:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after ctx cancel")
		}
	})
	select {
	case addr := <-ready:
		return addr, dialer
	case err := <-runErr:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the worker never became ready")
	}
	return "", nil
}

// TestRequireModeBeforeFirstBundle: a managed worker the control plane serves
// require for refuses every CONNECT from the first request, while it has no
// verified bundle (no pins): no token, an IdP-issued token and a forged Warden
// token all get the 407, and nothing is dialed.
func TestRequireModeBeforeFirstBundle(t *testing.T) {
	addr, dialer := startRequireWorker(t, config.SettingsWire{
		Identity: &config.IdentitySettings{Issuer: "https://127.0.0.1:1", Audience: "warden"},
		Agents:   []config.AgentSettings{{ID: "boot-agent", Identity: config.IdentityModeRequire}},
	})
	basic := func(tok string) string { return "Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+tok)) }
	for _, tc := range []struct {
		name, auth string
	}{
		{"no token", ""},
		{"dex token", basic(jwtShaped("https://127.0.0.1:1"))},
		{"forged warden token", basic(jwtShaped("https://cp.example.test"))},
		{"garbage", "Bearer not-a-jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := connectWith(t, addr, "api.example.test:443", tc.auth)
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("status = %d, want 407; body %s", resp.StatusCode, body)
			}
			if got := resp.Header.Get("Proxy-Authenticate"); got != `Basic realm="warden"` {
				t.Errorf("Proxy-Authenticate = %q", got)
			}
			if resp.Header.Get("WWW-Authenticate") != "" {
				t.Error("a WWW-Authenticate header was written")
			}
			var b struct{ Error, Reason string }
			if err := json.Unmarshal([]byte(body), &b); err != nil || b.Error != "identity_required" || b.Reason == "" {
				t.Errorf("body = %s (%v)", body, err)
			}
			if strings.Contains(body, tc.auth) && tc.auth != "" {
				t.Error("the body echoes the credential")
			}
		})
	}
	if n := dialer.n.Load(); n != 0 {
		t.Fatalf("%d upstream dials; require mode must refuse before any dial", n)
	}
}

// TestRequireRejectedForStandaloneWorker: a worker with no control plane
// refuses to start with require in its local YAML.
func TestRequireRejectedForStandaloneWorker(t *testing.T) {
	cfg := `
policy:
  allowlist:
    - domain: api.example.test
identity:
  defaultMode: require
`
	err := runUntilCtxDone(t, runParams(t, writeConfig(t, cfg)))
	if err == nil || !strings.Contains(err.Error(), "control-plane-managed") {
		t.Fatalf("Run = %v, want a refusal naming the control-plane-managed requirement", err)
	}
}

func requireWire(skew int) *config.SettingsWire {
	return &config.SettingsWire{
		Identity: &config.IdentitySettings{DefaultMode: "off", Issuer: "http://idp.test", ClockSkewSeconds: skew},
		Agents:   []config.AgentSettings{{ID: "default", Identity: "require"}},
	}
}

// TestRequireNeedsNoIdPVerifier: require with an issuer but no audience (valid
// config: require alone needs neither) builds a verifier with no IdP leg, so it
// does not lock the agent out, and an IdP-issued token is refused as
// unbound_token without a key fetch.
func TestRequireNeedsNoIdPVerifier(t *testing.T) {
	a, fake, builds, _, _ := identityApplier(t)
	fake.settings = requireWire(0)
	a.Apply()
	w := a.identity
	if w.live.mode != proxy.IdentityModeRequire || w.live.refusing || *builds != 0 {
		t.Fatalf("live = mode %q refusing %v, IdP builds %d; want a working require verifier with no IdP build", w.live.mode, w.live.refusing, *builds)
	}
	_, st, reason := w.live.v.Verify(context.Background(), jwtShaped("http://idp.test"))
	if st != identity.StatusInvalid || reason != identity.ReasonUnboundToken {
		t.Fatalf("an IdP-issued token = %s/%s, want invalid/unbound_token", st, reason)
	}
}

// TestRequireRefusingVerifier: a require verifier that cannot be built refuses
// everything (never keeps a laxer config), is rebuilt on the next apply, and a
// later good build replaces it.
func TestRequireRefusingVerifier(t *testing.T) {
	a, fake, _, _, _ := identityApplier(t)
	w := a.identity

	fake.settings = requireWire(400) // skew over the 5m limit: the build fails
	a.Apply()
	if w.live.mode != proxy.IdentityModeRequire || !w.live.refusing {
		t.Fatalf("live = mode %q refusing %v, want the refusing require verifier", w.live.mode, w.live.refusing)
	}
	if got := a.p.IdentityModeName(); got != "require" {
		t.Fatalf("proxy mode = %q, want require", got)
	}
	if _, st, r := w.live.v.Verify(context.Background(), "x"); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
		t.Fatalf("refusing verifier = %s/%s", st, r)
	}
	a.Apply() // still failing: stays refusing, rebuilt (not skipped)
	if !w.live.refusing {
		t.Fatal("a failing rebuild must keep refusing")
	}
	fake.settings = requireWire(30)
	a.Apply()
	if w.live.refusing || w.live.mode != proxy.IdentityModeRequire {
		t.Fatalf("after a good build: refusing %v mode %q, want a working require verifier", w.live.refusing, w.live.mode)
	}
}

// TestRequireKeepsWorkingVerifier: a working require verifier survives a failed
// rebuild; a laxer previous mode does not (it is replaced by refusing).
func TestRequireKeepsWorkingVerifier(t *testing.T) {
	a, fake, _, _, _ := identityApplier(t)
	w := a.identity
	fake.settings = requireWire(30)
	a.Apply()
	good := w.live
	fake.settings = requireWire(400)
	a.Apply()
	if w.live.v != good.v || w.live.refusing {
		t.Fatal("a failed rebuild replaced a working require verifier")
	}

	a2, fake2, _, _, _ := identityApplier(t)
	fake2.settings = identityWire("http://idp.test") // attribute
	a2.Apply()
	if a2.identity.live.mode != proxy.IdentityModeAttribute {
		t.Fatal("setup: not in attribute mode")
	}
	fake2.settings = requireWire(400)
	a2.Apply()
	if a2.identity.live.mode != proxy.IdentityModeRequire || !a2.identity.live.refusing {
		t.Fatalf("attribute then a failing require: mode %q refusing %v, want refusing require", a2.identity.live.mode, a2.identity.live.refusing)
	}
}
