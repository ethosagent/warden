package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

// fakeStarter is a SignInStarter that returns a canned offer or outcome and
// counts calls.
type fakeStarter struct {
	mu      sync.Mutex
	offer   SignInOffer
	outcome SignInOutcome
	starts  int
	forgot  []string
}

func (f *fakeStarter) Start(_ context.Context, agent string) (SignInOffer, SignInOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	if f.outcome == SignInStarted || f.outcome == SignInReused {
		return f.offer, f.outcome
	}
	return SignInOffer{}, f.outcome
}

func (f *fakeStarter) Forget(agent string) {
	f.mu.Lock()
	f.forgot = append(f.forgot, agent)
	f.mu.Unlock()
}

func (f *fakeStarter) counts() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, append([]string(nil), f.forgot...)
}

func testOffer() SignInOffer {
	return SignInOffer{
		Issuer: "http://idp.test/dex", VerificationURI: "http://idp.test/dex/device",
		VerificationURIComplete: "http://idp.test/dex/device?user_code=ABCD-EFGH",
		UserCode:                "ABCD-EFGH", DeviceCode: "dev-opaque", TokenEndpoint: "http://idp.test/dex/token",
		ClientID: "warden-cli", Interval: 5, ExpiresIn: 300,
	}
}

func newChallengeEnv(t *testing.T, st SignInStarter) *idEnv {
	t.Helper()
	return newIDEnvCfg(t, IdentityModeChallenge, func(c *Config) { c.Identity.SignIn = st })
}

// TestChallengeConnect: the 407 is written before the block list, the policy and
// any dial; it carries the sign-in offer; valid identities pass and end the
// agent's pending sign-in.
func TestChallengeConnect(t *testing.T) {
	st := &fakeStarter{offer: testOffer(), outcome: SignInStarted}
	e := newChallengeEnv(t, st)

	raw := func(host, auth string) (*http.Response, []byte) {
		t.Helper()
		conn, err := dialRaw(e.p.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		req := "CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + ":443\r\n"
		if auth != "" {
			req += "Proxy-Authorization: " + auth + "\r\n"
		}
		_, _ = io.WriteString(conn, req+"\r\n")
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, b
	}

	for _, tc := range []struct {
		name, host, auth, reason, status string
	}{
		{"no token", idHost, "", "none", "none"},
		{"expired", idHost, basicAuth("tok-expired"), "expired", "expired"},
		{"invalid", idHost, basicAuth("tok-bad"), "invalid", "invalid"},
		{"unverified fails closed", idHost, basicAuth("tok-down"), "unverified", "unverified"},
		{"malformed", idHost, "Basic !!!", "invalid", "invalid"},
		// The 407 precedes the policy: a destination that is not allowlisted
		// asks for a sign-in too, instead of a 403 that names the host.
		{"before policy", "denied.test", "", "none", "none"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(e.store.snapshot())
			resp, b := raw(tc.host, tc.auth)
			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Fatalf("status %d, want 407 (body %q)", resp.StatusCode, b)
			}
			if resp.Header.Get("Proxy-Authenticate") != `Basic realm="warden"` || resp.Header.Get("Cache-Control") != "no-store" ||
				resp.Header.Get("Content-Type") != "application/json" || !resp.Close || resp.Header.Get("WWW-Authenticate") != "" {
				t.Errorf("headers %v close=%v", resp.Header, resp.Close)
			}
			var body struct {
				Error, Reason string
				SignIn        *SignInOffer `json:"sign_in"`
			}
			if err := json.Unmarshal(b, &body); err != nil {
				t.Fatalf("body %q: %v", b, err)
			}
			if body.Error != "identity_required" || body.Reason != tc.reason || body.SignIn == nil || *body.SignIn != testOffer() {
				t.Errorf("body = %+v, want identity_required / %s with the offer", body, tc.reason)
			}
			evs := e.store.snapshot()[before:]
			if len(evs) != 1 || evs[0].Decision != "deny" || evs[0].Reason != "identity_required" || evs[0].IdentityStatus != tc.status ||
				evs[0].UserSub != "" || evs[0].Domain != tc.host {
				t.Errorf("events = %+v", evs)
			}
		})
	}
	if n := e.dials.Load(); n != 0 {
		t.Errorf("%d dials; the 407 must come before any dial", n)
	}
	if got := e.m.signInCount("started"); got != 6 {
		t.Errorf("signin started count = %d, want 6", got)
	}
	for _, s := range []string{"dev-opaque", "ABCD-EFGH"} {
		if strings.Contains(e.logs.String(), s) {
			t.Errorf("the logs contain a sign-in credential")
		}
		if strings.Contains(e.m.describe(), s) {
			t.Errorf("the metrics contain a sign-in credential")
		}
	}

	// A valid identity is let through and ends the agent's pending sign-in.
	conn, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
	_ = conn
	if !strings.Contains(status, "200") {
		t.Fatalf("valid token: %q, want 200", status)
	}
	if _, forgot := st.counts(); len(forgot) != 1 || forgot[0] != "agent" {
		t.Errorf("Forget calls = %v, want [agent]", forgot)
	}
}

// TestChallengeNoSignIn: with no starter, a failing issuer or a limit, the 407
// stays and names why in sign_in_error, with no sign_in object.
func TestChallengeNoSignIn(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   SignInStarter
		want SignInOutcome
	}{
		{"no starter", nil, SignInIssuerUnreachable},
		{"issuer down", &fakeStarter{outcome: SignInIssuerUnreachable}, SignInIssuerUnreachable},
		{"rate limited", &fakeStarter{outcome: SignInRateLimited}, SignInRateLimited},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newChallengeEnv(t, tc.st)
			conn, err := dialRaw(e.p.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			_, _ = io.WriteString(conn, "CONNECT "+idHost+":443 HTTP/1.1\r\nHost: "+idHost+":443\r\n\r\n")
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			var body map[string]any
			if err := json.Unmarshal(b, &body); err != nil {
				t.Fatalf("body %q: %v", b, err)
			}
			if resp.StatusCode != 407 || body["sign_in_error"] != string(tc.want) || body["reason"] != "none" {
				t.Errorf("status %d body %v, want 407 with sign_in_error %s", resp.StatusCode, body, tc.want)
			}
			if _, has := body["sign_in"]; has {
				t.Errorf("body has a sign_in object: %v", body)
			}
			if got := e.m.signInCount(string(tc.want)); got != 1 {
				t.Errorf("signin %s count = %d, want 1", tc.want, got)
			}
		})
	}
}

// readH1 sends GET /x on an open h1 tunnel and returns the response and body.
func readH1(t *testing.T, c *idH1, extra string) (*http.Response, string) {
	t.Helper()
	_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n"+extra+"\r\n")
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, string(b)
}

// TestChallengeExpiredInTunnel: a request on a terminated tunnel after the
// CONNECT identity's exp plus skew gets a 403 identity_expired with
// Connection: close (h1) or on the stream (h2); a second subject in
// X-Warden-Identity is a 403 identity_conflict. Attribute mode keeps serving.
func TestChallengeExpiredInTunnel(t *testing.T) {
	newEnv := func(t *testing.T, mode IdentityMode) *idEnv {
		e := newIDEnvCfg(t, mode, nil)
		exp := e.clk.now().Add(30 * time.Second)
		e.v.Set("tok-short", idClaims("alice", exp), identity.StatusValid, "")
		return e
	}
	pastExp := 30*time.Second + identity.DefaultClockSkew + time.Second
	auth := func() string { return "Proxy-Authorization: " + basicAuth("tok-short") + "\r\n" }

	t.Run("h1", func(t *testing.T) {
		e := newEnv(t, IdentityModeChallenge)
		c := e.h1(auth())
		if resp, _ := readH1(t, c, ""); resp.StatusCode != 200 {
			t.Fatalf("before exp: status %d, want 200", resp.StatusCode)
		}
		e.clk.advance(pastExp)
		resp, body := readH1(t, c, "")
		if resp.StatusCode != 403 || body != `{"error":"identity_expired"}` || !resp.Close {
			t.Fatalf("after exp: status %d body %q close %v, want 403 identity_expired with Connection: close", resp.StatusCode, body, resp.Close)
		}
		evs := e.store.snapshot()
		last := evs[len(evs)-1]
		if last.Decision != "deny" || last.Reason != "identity_expired" || last.IdentityStatus != "expired" || last.UserSub != "" {
			t.Errorf("event = %+v", last)
		}
		if got := e.m.blockedCount("identity_expired"); got != 1 {
			t.Errorf("blocked{identity_expired} = %d, want 1", got)
		}
	})

	t.Run("h2 stream", func(t *testing.T) {
		e := newEnv(t, IdentityModeChallenge)
		cc := e.h2(auth())
		if st := h2Get(t, cc, nil); st != 200 {
			t.Fatalf("before exp: status %d, want 200", st)
		}
		e.clk.advance(pastExp)
		req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || string(b) != `{"error":"identity_expired"}` {
			t.Fatalf("after exp: status %d body %q, want 403 identity_expired", resp.StatusCode, b)
		}
	})

	t.Run("conflict", func(t *testing.T) {
		e := newEnv(t, IdentityModeChallenge)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
		resp, body := readH1(t, c, "X-Warden-Identity: Bearer tok-bob\r\n")
		if resp.StatusCode != 403 || body != `{"error":"identity_conflict"}` || !resp.Close {
			t.Fatalf("status %d body %q close %v, want 403 identity_conflict with Connection: close", resp.StatusCode, body, resp.Close)
		}
		evs := e.store.snapshot()
		if last := evs[len(evs)-1]; last.Reason != "identity_conflict" || last.IdentityStatus != "conflict" {
			t.Errorf("event = %+v", last)
		}
	})

	t.Run("attribute mode is unchanged", func(t *testing.T) {
		e := newEnv(t, IdentityModeAttribute)
		c := e.h1(auth())
		e.clk.advance(pastExp)
		if resp, _ := readH1(t, c, ""); resp.StatusCode != 200 {
			t.Fatalf("attribute mode after exp: status %d, want the upstream's 200", resp.StatusCode)
		}
		c2 := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
		if resp, _ := readH1(t, c2, "X-Warden-Identity: Bearer tok-bob\r\n"); resp.StatusCode != 200 {
			t.Fatalf("attribute mode conflict: status %d, want 200", resp.StatusCode)
		}
	})
}

// dialRaw dials addr with a deadline.
func dialRaw(addr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn, nil
}

// TestChallengeNoCAWarning: without a CA a raw tunnel is checked at CONNECT only
// and cannot be cut at exp; the proxy says so once.
func TestChallengeNoCAWarning(t *testing.T) {
	e := newIDEnvCfg(t, IdentityModeChallenge, func(c *Config) { c.CACertPath, c.CAKeyPath = "", "" })
	e.p.SetIdentity(e.v, IdentityModeChallenge)
	if n := strings.Count(e.logs.String(), "identity challenge mode without a CA"); n != 1 {
		t.Errorf("no-CA challenge warning logged %d times, want once:\n%s", n, e.logs.String())
	}
}
