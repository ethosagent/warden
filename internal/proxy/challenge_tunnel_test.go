package proxy

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// inTunnelHead sends a CONNECT with extra header lines and returns the conn,
// its reader, the status code and the response headers of the head.
func (e *idEnv) inTunnelHead(host, extra string) (net.Conn, *bufio.Reader, *http.Response) {
	e.t.Helper()
	conn, err := dialRaw(e.p.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	_, _ = io.WriteString(conn, "CONNECT "+host+":443 HTTP/1.1\r\nHost: "+host+":443\r\n"+extra+"\r\n")
	br := bufio.NewReader(conn)
	// A CONNECT 200 has no body; ReadResponse with a CONNECT request knows that.
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		e.t.Fatal(err)
	}
	return conn, br, resp
}

// tunnelBody is the in-tunnel 403 body as an SDK would parse it.
type tunnelBodyT struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	SignIn *struct {
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		UserCode                string `json:"user_code"`
		ExpiresIn               int    `json:"expires_in"`
	} `json:"sign_in"`
	SignInError string `json:"sign_in_error"`
}

const askInTunnel = ChallengeHeader + ": " + ChallengeInTunnel + "\r\n"

func decodeTunnelBody(t *testing.T, b []byte) tunnelBodyT {
	t.Helper()
	for _, banned := range []string{"device_code", "token_endpoint", "dev-opaque", "client_id", "tok-"} {
		if strings.Contains(string(b), banned) {
			t.Errorf("the 403 body contains %q: %s", banned, b)
		}
	}
	var tb tunnelBodyT
	if err := json.Unmarshal(b, &tb); err != nil {
		t.Fatalf("body %q: %v", b, err)
	}
	return tb
}

// assertNoSignInSecrets fails when the worker's logs or metrics hold either
// code of the login in progress.
func assertNoSignInSecrets(t *testing.T, e *idEnv) {
	t.Helper()
	for _, s := range []string{"dev-opaque", "ABCD-EFGH"} {
		if strings.Contains(e.logs.String(), s) {
			t.Errorf("the logs contain a sign-in credential %q", s)
		}
		if strings.Contains(e.m.describe(), s) {
			t.Errorf("the metrics contain a sign-in credential %q", s)
		}
		for _, ev := range e.store.snapshot() {
			if b, _ := json.Marshal(ev); strings.Contains(string(b), s) {
				t.Errorf("an event contains a sign-in credential %q", s)
			}
		}
	}
}

// TestChallengeInTunnelH1: no token + the in-tunnel header on a TLS-terminating
// worker is a 200 with the offer in X-Warden-Sign-In; the first request inside
// gets the 403 that names the link and the connection closes. Nothing is dialled
// and one identity_required deny event is recorded.
func TestChallengeInTunnelH1(t *testing.T) {
	st := &fakeStarter{offer: testOffer(), outcome: SignInStarted}
	e := newChallengeEnv(t, st)

	conn, br, head := e.inTunnelHead(idHost, askInTunnel)
	if head.StatusCode != 200 {
		t.Fatalf("CONNECT status %d, want 200", head.StatusCode)
	}
	raw := head.Header.Get(SignInHeader)
	if raw == "" {
		t.Fatalf("no %s header on the 200: %v", SignInHeader, head.Header)
	}
	dec, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("offer header is not unpadded base64url: %v", err)
	}
	var got SignInOffer
	if err := json.Unmarshal(dec, &got); err != nil || got != testOffer() {
		t.Errorf("offer = %+v (%v), want the starter's offer", got, err)
	}

	tc := e.tlsOver(conn, br, "http/1.1")
	c := &idH1{t: t, tc: tc, br: bufio.NewReader(tc)}
	resp, body := readH1(t, c, "")
	if resp.StatusCode != http.StatusForbidden || !resp.Close {
		t.Fatalf("status %d close %v, want 403 with Connection: close", resp.StatusCode, resp.Close)
	}
	if resp.Header.Get("Content-Type") != "application/json" || resp.Header.Get("Cache-Control") != "no-store" ||
		resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("headers %v", resp.Header)
	}
	tb := decodeTunnelBody(t, []byte(body))
	if tb.Type != "error" || tb.Error.Type != "identity_required" || tb.Error.Code != "identity_required" {
		t.Errorf("body = %+v", tb)
	}
	for _, want := range []string{"Sign in to continue: http://idp.test/dex/device?user_code=ABCD-EFGH", "ABCD-EFGH"} {
		if !strings.Contains(tb.Error.Message, want) {
			t.Errorf("message %q lacks %q", tb.Error.Message, want)
		}
	}
	if tb.SignIn == nil || tb.SignIn.UserCode != "ABCD-EFGH" || tb.SignIn.ExpiresIn != 300 ||
		tb.SignIn.VerificationURI != "http://idp.test/dex/device" {
		t.Errorf("sign_in = %+v", tb.SignIn)
	}
	// The connection is closed after the answer.
	_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.br.Read(make([]byte, 1)); err == nil {
		t.Errorf("the connection stayed open (read %d bytes)", n)
	}

	if n := e.dials.Load(); n != 0 {
		t.Errorf("%d upstream dials; the challenge tunnel never dials", n)
	}
	evs := e.waitDeny(t, "identity_required", 1)
	if len(evs) != 1 || evs[0].Domain != idHost || evs[0].UserSub != "" {
		t.Errorf("deny events = %+v", evs)
	}
	if got := e.m.signInCount("started"); got != 1 {
		t.Errorf("signin started count = %d, want 1", got)
	}
	assertNoSignInSecrets(t, e)
}

// TestChallengeInTunnelH2: an h2 client gets the same 403 on its stream, then
// GOAWAY (a later request cannot reuse the connection).
func TestChallengeInTunnelH2(t *testing.T) {
	e := newChallengeEnv(t, &fakeStarter{offer: testOffer(), outcome: SignInStarted})
	cc := e.h2(askInTunnel)

	req, _ := http.NewRequest("POST", "https://"+idHost+"/backend-api/codex/responses", strings.NewReader(`{"input":"hi"}`))
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 || resp.ProtoMajor != 2 {
		t.Fatalf("status %s proto %s, want an h2 403", resp.Status, resp.Proto)
	}
	tb := decodeTunnelBody(t, b)
	if tb.Error.Type != "identity_required" || !strings.Contains(tb.Error.Message, "ABCD-EFGH") {
		t.Errorf("body = %+v", tb)
	}
	// GOAWAY: the connection takes no new stream.
	deadline := time.Now().Add(5 * time.Second)
	for {
		req2, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
		r2, err := cc.RoundTrip(req2)
		if err != nil {
			break
		}
		_ = r2.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("the h2 connection still takes streams after the 403; want GOAWAY")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n := e.dials.Load(); n != 0 {
		t.Errorf("%d upstream dials, want 0", n)
	}
	e.waitDeny(t, "identity_required", 1)
	assertNoSignInSecrets(t, e)
}

// TestChallengeInTunnelFallsBackTo407: without the header (or with another
// value) the answer is the 407 of #558; a worker with no CA cannot serve a
// tunnel and sends the 407 too.
func TestChallengeInTunnelFallsBackTo407(t *testing.T) {
	cases := []struct {
		name  string
		extra string
		edit  func(*Config)
	}{
		{"no header", "", nil},
		{"other value", ChallengeHeader + ": later\r\n", nil},
		{"no CA", askInTunnel, func(c *Config) { c.CACertPath, c.CAKeyPath = "", "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeStarter{offer: testOffer(), outcome: SignInStarted}
			e := newIDEnvCfg(t, IdentityModeChallenge, func(c *Config) {
				c.Identity.SignIn = st
				if tc.edit != nil {
					tc.edit(c)
				}
			})
			_, br, head := e.inTunnelHead(idHost, tc.extra)
			if head.StatusCode != http.StatusProxyAuthRequired || head.Header.Get(SignInHeader) != "" {
				t.Fatalf("status %d headers %v, want the plain 407", head.StatusCode, head.Header)
			}
			b, _ := io.ReadAll(br)
			var body struct {
				Error  string       `json:"error"`
				SignIn *SignInOffer `json:"sign_in"`
			}
			_ = json.Unmarshal(b, &body)
			if body.Error != "identity_required" || body.SignIn == nil || *body.SignIn != testOffer() {
				t.Errorf("body %q", b)
			}
		})
	}
}

// TestChallengeInTunnelFirstHeaderWins: a second X-Warden-Challenge line does
// not turn the in-tunnel answer on when the first asked for something else.
func TestChallengeInTunnelFirstHeaderWins(t *testing.T) {
	e := newChallengeEnv(t, &fakeStarter{offer: testOffer(), outcome: SignInStarted})
	_, _, head := e.inTunnelHead(idHost, ChallengeHeader+": later\r\n"+askInTunnel)
	if head.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status %d, want 407 (the first line wins)", head.StatusCode)
	}
}

// TestChallengeInTunnelNoOffer: when no sign-in could be started the tunnel is
// still served, with no offer header and a body that names why.
func TestChallengeInTunnelNoOffer(t *testing.T) {
	e := newChallengeEnv(t, &fakeStarter{outcome: SignInRateLimited})
	conn, br, head := e.inTunnelHead(idHost, askInTunnel)
	if head.StatusCode != 200 || head.Header.Get(SignInHeader) != "" {
		t.Fatalf("status %d headers %v, want a 200 with no offer header", head.StatusCode, head.Header)
	}
	tc := e.tlsOver(conn, br, "http/1.1")
	c := &idH1{t: t, tc: tc, br: bufio.NewReader(tc)}
	resp, body := readH1(t, c, "")
	tb := decodeTunnelBody(t, []byte(body))
	if resp.StatusCode != 403 || tb.Error.Type != "identity_required" || tb.SignIn != nil || tb.SignInError != "rate_limited" ||
		strings.Contains(tb.Error.Message, "Sign in to continue") {
		t.Errorf("status %d body %+v", resp.StatusCode, tb)
	}
	if got := e.m.signInCount("rate_limited"); got != 1 {
		t.Errorf("rate_limited count = %d, want 1", got)
	}
}

// TestChallengeInTunnelValidTokenUnchanged: a CONNECT with a valid token is
// admitted as before even when it carries the header.
func TestChallengeInTunnelValidTokenUnchanged(t *testing.T) {
	e := newChallengeEnv(t, &fakeStarter{offer: testOffer(), outcome: SignInStarted})
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n" + askInTunnel)
	if st := c.get(""); st != 200 {
		t.Fatalf("status %d, want the upstream's 200", st)
	}
}

// TestChallengeInTunnelNotTLS: a client that sends plaintext after the 200 is
// dropped; nothing is dialled and nothing is written beyond the handshake error.
func TestChallengeInTunnelNotTLS(t *testing.T) {
	e := newChallengeEnv(t, &fakeStarter{offer: testOffer(), outcome: SignInStarted})
	conn, br, head := e.inTunnelHead(idHost, askInTunnel)
	if head.StatusCode != 200 {
		t.Fatalf("status %d", head.StatusCode)
	}
	_, _ = io.WriteString(conn, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n\r\n")
	b, _ := io.ReadAll(br)
	if strings.Contains(string(b), "ABCD-EFGH") {
		t.Errorf("a plaintext client was given the user code: %q", b)
	}
	if n := e.dials.Load(); n != 0 {
		t.Errorf("%d dials, want 0", n)
	}
}

// TestChallengeInTunnelStallIsCut: a client that completes the handshake and
// then sends nothing (h1) or no frames (h2) is cut at the tunnel bound; it does
// not hold the connection open.
func TestChallengeInTunnelStallIsCut(t *testing.T) {
	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			e := newChallengeEnv(t, &fakeStarter{offer: testOffer(), outcome: SignInStarted})
			e.p.challengeTimeout = 300 * time.Millisecond
			conn, br, head := e.inTunnelHead(idHost, askInTunnel)
			if head.StatusCode != 200 {
				t.Fatalf("status %d", head.StatusCode)
			}
			tc := e.tlsOver(conn, br, proto)
			if proto == "h2" {
				// The client preface and an empty SETTINGS, then silence: the
				// connection is idle with no stream (the server's own 10 s preface
				// wait is not what is under test).
				_, _ = io.WriteString(tc, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
			}
			_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
			start := time.Now()
			if _, err := io.Copy(io.Discard, tc); err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "reset") {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Fatalf("the worker still held the stalled %s tunnel after 5 s", proto)
				}
			}
			if d := time.Since(start); d > 4*time.Second {
				t.Errorf("the stalled %s tunnel closed after %s, want about 300 ms", proto, d)
			}
		})
	}
}
