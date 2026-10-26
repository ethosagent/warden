package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/test/fakes"
)

// These tests cover W-P1-VRFY-02: the identity header is read before the
// proxy-only strip, verified through the identityP holder, and resolved by the
// status rules, on CONNECT, HTTP/1.1, WebSocket upgrades and h2/gRPC. The
// verifier is the fakes.Verifier; metrics are the fakeMetrics counter.

const idHost = "hdr.test"

// idClock is a controllable proxy clock.
type idClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *idClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *idClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// idEnv is one identity world: a proxy over a header-recording TLS backend.
type idEnv struct {
	t     *testing.T
	p     *Proxy
	caPEM []byte
	v     *fakes.Verifier
	m     *fakeMetrics
	clk   *idClock
	logs  *lockedBuf
	be    *headerBackend
}

// idClaims is a valid token's claims, expiring ttl after now.
func idClaims(sub string, exp time.Time) identity.Claims {
	return identity.Claims{Sub: sub, Email: sub + "@example.test", EmailVerified: true, Groups: []string{"eng"}, Expiry: exp}
}

// newIDEnv builds a forward-mode proxy with an identity verifier in mode. The
// fake verifier knows these tokens: tok-alice and tok-bob (valid), tok-expired,
// tok-bad (invalid, bad_signature) and tok-down (unverified).
func newIDEnv(t *testing.T, mode IdentityMode) *idEnv {
	t.Helper()
	e := &idEnv{t: t, v: fakes.NewVerifier(), m: newFakeMetrics(), logs: &lockedBuf{}}
	e.clk = &idClock{t: time.Now()}
	exp := e.clk.now().Add(time.Hour)
	e.v.Set("tok-alice", idClaims("alice", exp), identity.StatusValid, "")
	e.v.Set("tok-bob", idClaims("bob", exp), identity.StatusValid, "")
	e.v.Set("tok-expired", identity.Claims{Sub: "mallory", Expiry: e.clk.now().Add(-time.Hour)}, identity.StatusExpired, "")
	e.v.Set("tok-bad", identity.Claims{Sub: "mallory"}, identity.StatusInvalid, identity.ReasonBadSignature)
	e.v.Set("tok-down", identity.Claims{}, identity.StatusUnverified, identity.ReasonJWKSUnavailable)

	e.be = newHeaderBackend(t, false)
	backendAddr := strings.TrimPrefix(e.be.srv.URL, "https://")
	caPEM, caKeyPEM, _, _ := generateTestCA(t)
	e.caPEM = caPEM
	dir := t.TempDir()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy: policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: idHost, Port: 443},
		}}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &syncStore{},
		AgentID:    "agent",
		Metrics:    e.m,
		Logger:     slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		CACertPath: filepath.Join(dir, "ca.crt"),
		CAKeyPath:  filepath.Join(dir, "ca.key"),
		Identity:   IdentityConfig{Verifier: e.v, Mode: mode},
	}
	if err := os.WriteFile(cfg.CACertPath, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.CAKeyPath, caKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = e.clk.now
	p.dialTLS = func(_, _ string, c *tls.Config) (*tls.Conn, error) {
		return tls.Dial("tcp", backendAddr, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	e.p = p
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	waitForAddr(t, p)
	return e
}

func basicAuth(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyAuthUsername+":"+tok))
}

// connect opens a CONNECT tunnel with extra header lines (CRLF-terminated) and
// returns the raw conn, its reader and the status line.
func (e *idEnv) connect(extra string) (net.Conn, *bufio.Reader, string) {
	e.t.Helper()
	conn, err := net.Dial("tcp", e.p.Addr().String())
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n%s\r\n", idHost, idHost, extra)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		e.t.Fatal(err)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" {
			break
		}
	}
	return conn, br, status
}

func (e *idEnv) tlsOver(conn net.Conn, br *bufio.Reader, protos ...string) *tls.Conn {
	e.t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	tc := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{ServerName: idHost, RootCAs: pool, NextProtos: protos})
	if err := tc.Handshake(); err != nil {
		e.t.Fatalf("client TLS handshake: %v", err)
	}
	return tc
}

// idH1 is an HTTP/1.1 client session over a CONNECT tunnel.
type idH1 struct {
	t  *testing.T
	tc *tls.Conn
	br *bufio.Reader
}

func (e *idEnv) h1(connectExtra string) *idH1 {
	e.t.Helper()
	conn, br, status := e.connect(connectExtra)
	if !strings.Contains(status, "200") {
		e.t.Fatalf("CONNECT status = %q, want 200", status)
	}
	tc := e.tlsOver(conn, br, "http/1.1")
	return &idH1{t: e.t, tc: tc, br: bufio.NewReader(tc)}
}

// get sends GET /x with extra header lines and returns the status.
func (c *idH1) get(extra string) int {
	c.t.Helper()
	_, _ = io.WriteString(c.tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\n"+extra+"\r\n")
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		c.t.Fatalf("read response: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func h2Get(t *testing.T, cc http.RoundTripper, hdr map[string]string) int {
	t.Helper()
	req, _ := http.NewRequest("GET", "https://"+idHost+"/x", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// stageProxy is a proxy for driving identityStage directly (no network).
func stageProxy(t testing.TB, v identity.Verifier, mode IdentityMode, clk *idClock, m MetricsRecorder) *Proxy {
	t.Helper()
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{}),
		Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
		Analytics:  &syncStore{},
		AgentID:    "agent-7",
		Metrics:    m,
		Identity:   IdentityConfig{Verifier: v, Mode: mode},
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if clk != nil {
		p.now = clk.now
	}
	return p
}

// stageScope is a request scope as runRequestStages sees it right after
// readRequest, carrying the given identity header values.
func stageScope(ci connIdentity, headerValues ...string) *requestScope {
	r := httptest.NewRequest("GET", "http://hdr.test/x", nil)
	for _, v := range headerValues {
		r.Header.Add(IdentityHeader, v)
	}
	return &requestScope{req: r, ci: ci}
}

// runIdentity does what runRequestStages does around the strip: capture, strip,
// then the stage.
func runIdentity(t testing.TB, p *Proxy, s *requestScope) {
	t.Helper()
	p.captureIdentityHeader(s)
	if p.stripHopHeaders(s) {
		t.Fatal("stripHopHeaders ended the request")
	}
	if p.identityStage(s) {
		t.Fatal("identityStage ended the request")
	}
}

// --- TestIdentityCapturedBeforeStrip ---

// Red-first evidence for the ordering: with captureIdentityHeader moved after
// stripHopHeaders the verifier sees no token (zero calls) and the status is none.
func TestIdentityCapturedBeforeStrip(t *testing.T) {
	assertVerified := func(t *testing.T, e *idEnv, be interface{ headers() http.Header }) {
		t.Helper()
		if got := e.v.Calls(); got != 1 {
			t.Errorf("verifier calls = %d, want 1 (the header was not read before the strip)", got)
		}
		if got := e.m.identityCount("valid", "none"); got != 1 {
			t.Errorf("identity valid count = %d, want 1; metrics: %s", got, e.m.describe())
		}
		if got := e.m.identityCount("none", "none"); got != 0 {
			t.Errorf("identity none count = %d, want 0", got)
		}
		if be != nil {
			requireStripped(t, be.headers())
		}
	}

	t.Run("h1", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		c := e.h1("")
		if st := c.get("X-Warden-Identity: Bearer tok-alice\r\n"); st != 200 {
			t.Fatalf("status = %d", st)
		}
		assertVerified(t, e, e.be)
	})

	t.Run("h2", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		cc := e.h2("")
		if st := h2Get(t, cc, map[string]string{"X-Warden-Identity": "Bearer tok-alice"}); st != 200 {
			t.Fatalf("status = %d", st)
		}
		assertVerified(t, e, e.be)
	})

	t.Run("grpc", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		cc := e.h2("")
		req, _ := http.NewRequest("POST", "https://"+idHost+"/pkg.Svc/M", strings.NewReader(""))
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		req.Header.Set("X-Warden-Identity", "Bearer tok-alice")
		resp, err := cc.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		assertVerified(t, e, e.be)
	})

	t.Run("websocket", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		_, _, caCert, caKey := generateTestCA(t)
		b := &wsBackend{reqHeaders: make(chan string, 1)}
		ln := startWSBackend(t, caCert, caKey, b)
		e.p.dialTLS = dialBackend(ln)
		conn, br, status := e.connect("")
		if !strings.Contains(status, "200") {
			t.Fatalf("CONNECT status = %q", status)
		}
		tc := e.tlsOver(conn, br, "http/1.1")
		_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"X-Warden-Identity: Bearer tok-alice\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
		line, err := bufio.NewReader(tc).ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
			t.Fatalf("status = %q err %v, want 101", line, err)
		}
		select {
		case raw := <-b.reqHeaders:
			if strings.Contains(strings.ToLower(raw), "x-warden-identity") {
				t.Errorf("X-Warden-Identity reached the websocket upstream:\n%s", raw)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("backend saw no upgrade request")
		}
		assertVerified(t, e, nil)
	})

	// The same ordering at the unit level: the stage sees the token only because
	// the capture ran ahead of the strip.
	t.Run("stage_order", func(t *testing.T) {
		v := fakes.NewVerifier()
		v.Set("tok", idClaims("alice", time.Now().Add(time.Hour)), identity.StatusValid, "")
		p := stageProxy(t, v, IdentityModeAttribute, nil, nil)
		s := stageScope(connIdentity{}, "Bearer tok")
		p.captureIdentityHeader(s)
		if p.stripHopHeaders(s) {
			t.Fatal("strip ended the request")
		}
		if s.req.Header.Get(IdentityHeader) != "" {
			t.Fatal("strip did not delete the header")
		}
		p.identityStage(s)
		if s.idStatus != identity.StatusValid || s.subject == nil || s.subject.Sub != "alice" {
			t.Errorf("status %q subject %+v, want valid alice", s.idStatus, s.subject)
		}
		if s.subject != nil && s.subject.AgentID != "agent-7" {
			t.Errorf("subject agent = %q, want agent-7", s.subject.AgentID)
		}
		if s.rawIdentity != "" {
			t.Error("raw identity left on the scope after the stage")
		}
	})
}

// --- TestIdentityStripping ---

// The strip is on main (#396); this is the regression that neither header
// reaches the upstream with identity unconfigured, off or in attribute mode,
// on every path.
func TestIdentityStripping(t *testing.T) {
	modes := []struct {
		name string
		mode IdentityMode
		cfg  bool
	}{
		{"no_settings", "", false},
		{"off", IdentityModeOff, true},
		{"attribute", IdentityModeAttribute, true},
	}
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			mk := func(t *testing.T) *idEnv {
				e := newIDEnv(t, m.mode)
				if !m.cfg {
					e.p.SetIdentity(nil, "")
				}
				return e
			}
			t.Run("h1", func(t *testing.T) {
				e := mk(t)
				c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
				if st := c.get("X-Warden-Identity: Bearer tok-alice\r\nProxy-Authorization: Bearer tok-alice\r\n"); st != 200 {
					t.Fatalf("status = %d", st)
				}
				requireStripped(t, e.be.headers())
			})
			t.Run("h2", func(t *testing.T) {
				e := mk(t)
				cc := e.h2("")
				if st := h2Get(t, cc, map[string]string{"X-Warden-Identity": "Bearer tok-alice", "Proxy-Authorization": "Bearer tok-alice"}); st != 200 {
					t.Fatalf("status = %d", st)
				}
				requireStripped(t, e.be.headers())
			})
			t.Run("websocket", func(t *testing.T) {
				e := mk(t)
				_, _, caCert, caKey := generateTestCA(t)
				b := &wsBackend{reqHeaders: make(chan string, 1)}
				e.p.dialTLS = dialBackend(startWSBackend(t, caCert, caKey, b))
				conn, br, _ := e.connect("")
				tc := e.tlsOver(conn, br, "http/1.1")
				_, _ = io.WriteString(tc, "GET /ws HTTP/1.1\r\nHost: "+idHost+"\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
					"X-Warden-Identity: Bearer tok-alice\r\nProxy-Authorization: Bearer tok-alice\r\n"+
					"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
				if line, err := bufio.NewReader(tc).ReadString('\n'); err != nil || !strings.HasPrefix(line, "HTTP/1.1 101") {
					t.Fatalf("status = %q err %v", line, err)
				}
				select {
				case raw := <-b.reqHeaders:
					lower := strings.ToLower(raw)
					for _, h := range []string{"x-warden-identity", "proxy-authorization"} {
						if strings.Contains(lower, h+":") {
							t.Errorf("%s reached the upstream:\n%s", h, raw)
						}
					}
				case <-time.After(5 * time.Second):
					t.Fatal("backend saw no upgrade request")
				}
			})
		})
	}
}

// --- TestIdentityModeOff ---

func TestIdentityModeOff(t *testing.T) {
	e := newIDEnv(t, IdentityModeOff)
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
	if st := c.get("X-Warden-Identity: Bearer tok-alice\r\n"); st != 200 {
		t.Fatalf("status = %d", st)
	}
	if got := e.v.Calls(); got != 0 {
		t.Errorf("verifier calls = %d, want 0 in mode off", got)
	}
	if n := len(e.m.describe()); n > 0 && strings.Contains(e.m.describe(), "RecordIdentityVerify") {
		t.Errorf("mode off recorded identity metrics: %s", e.m.describe())
	}

	// Resolved status, at the stage: a token on CONNECT or on the request is off.
	p := stageProxy(t, e.v, IdentityModeOff, nil, nil)
	for name, s := range map[string]*requestScope{
		"header":  stageScope(connIdentity{}, "Bearer tok-alice"),
		"connect": stageScope(p.resolveConnIdentity(1, basicAuth("tok-alice"))),
	} {
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusOff || s.subject != nil {
			t.Errorf("%s: status %q subject %+v, want off and nil", name, s.idStatus, s.subject)
		}
	}
	s := stageScope(connIdentity{})
	runIdentity(t, p, s)
	if s.idStatus != identity.StatusNone {
		t.Errorf("no token: status %q, want none", s.idStatus)
	}
	if got := e.v.Calls(); got != 0 {
		t.Errorf("verifier calls = %d after stage runs, want 0", got)
	}
}

// --- TestIdentityAttributeMode ---

func TestIdentityAttributeMode(t *testing.T) {
	cases := []struct {
		name        string
		connectAuth string // Proxy-Authorization value on CONNECT, "" for none
		header      string // X-Warden-Identity value, "" for none
		want        identity.Status
		reason      identity.Reason
	}{
		{"invalid", "", "Bearer tok-bad", identity.StatusInvalid, identity.ReasonBadSignature},
		{"expired", "", "Bearer tok-expired", identity.StatusExpired, ""},
		{"none", "", "", identity.StatusNone, ""},
		{"unverified", "", "Bearer tok-down", identity.StatusUnverified, identity.ReasonJWKSUnavailable},
		{"conflict", basicAuth("tok-alice"), "Bearer tok-bob", identity.StatusConflict, ""},
		{"malformed_header", "", "Token tok-alice", identity.StatusInvalid, identity.ReasonMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantReason := string(tc.reason)
			if wantReason == "" {
				wantReason = "none"
			}

			// End to end: attribute mode never blocks, and the outcome is counted.
			e := newIDEnv(t, IdentityModeAttribute)
			connectExtra := ""
			if tc.connectAuth != "" {
				connectExtra = "Proxy-Authorization: " + tc.connectAuth + "\r\n"
			}
			hdr := ""
			if tc.header != "" {
				hdr = "X-Warden-Identity: " + tc.header + "\r\n"
			}
			c := e.h1(connectExtra)
			if st := c.get(hdr); st != 200 {
				t.Fatalf("status = %d, want the upstream's 200", st)
			}
			if got := e.m.identityCount(string(tc.want), wantReason); got != 1 {
				t.Errorf("warden.identity.verify.total{%s,%s} = %d, want 1; metrics: %s", tc.want, wantReason, got, e.m.describe())
			}
			requireStripped(t, e.be.headers())

			// Stage level: the exact status, reason and a nil Subject.
			p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
			ci := connIdentity{}
			if tc.connectAuth != "" {
				ci = p.resolveConnIdentity(1, tc.connectAuth)
			}
			var vals []string
			if tc.header != "" {
				vals = []string{tc.header}
			}
			s := stageScope(ci, vals...)
			runIdentity(t, p, s)
			if s.idStatus != tc.want || s.idReason != tc.reason {
				t.Errorf("status %q reason %q, want %q %q", s.idStatus, s.idReason, tc.want, tc.reason)
			}
			if s.subject != nil {
				t.Errorf("subject = %+v, want nil for status %s", s.subject, tc.want)
			}
		})
	}

	t.Run("valid_yields_subject", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		s := stageScope(connIdentity{}, "Bearer tok-alice")
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusValid || s.subject == nil || s.subject.Sub != "alice" || s.subject.Email != "alice@example.test" {
			t.Errorf("status %q subject %+v, want valid alice", s.idStatus, s.subject)
		}
	})

	t.Run("same_sub_is_valid", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		s := stageScope(p.resolveConnIdentity(1, basicAuth("tok-alice")), "Bearer tok-alice")
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusValid || s.subject == nil {
			t.Errorf("status %q subject %+v, want valid", s.idStatus, s.subject)
		}
	})

	t.Run("failed_connect_token_is_not_overridden_by_header", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		s := stageScope(p.resolveConnIdentity(1, basicAuth("tok-bad")), "Bearer tok-alice")
		before := e.v.Calls()
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusInvalid || s.subject != nil {
			t.Errorf("status %q subject %+v, want invalid and nil", s.idStatus, s.subject)
		}
		if e.v.Calls() != before {
			t.Error("header was verified next to a failed CONNECT token")
		}
		// The unverified claims stay for the block-list check, never a Subject.
		if s.idClaims.Sub != "mallory" {
			t.Errorf("idClaims.Sub = %q, want the unverified sub kept", s.idClaims.Sub)
		}
	})

	t.Run("token_never_logged", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
		c.get("X-Warden-Identity: Bearer tok-bob\r\n")
		if out := e.logs.String(); strings.Contains(out, "tok-alice") || strings.Contains(out, "tok-bob") {
			t.Errorf("a token reached the logs:\n%s", out)
		}
	})
}

// --- TestIdentityConnectExpiry ---

func TestIdentityConnectExpiry(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	exp := e.clk.now().Add(30 * time.Second)
	e.v.Set("tok-short", idClaims("alice", exp), identity.StatusValid, "")

	t.Run("stage", func(t *testing.T) {
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		ci := p.resolveConnIdentity(1, basicAuth("tok-short"))
		if ci.Status != identity.StatusValid || !ci.Expiry.Equal(exp) {
			t.Fatalf("connIdentity = %+v, want valid with exp %v", ci, exp)
		}
		s := stageScope(ci)
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusValid || s.subject == nil {
			t.Fatalf("first request: status %q subject %+v, want valid", s.idStatus, s.subject)
		}
		// Past exp but inside the skew: still valid.
		e.clk.advance(30*time.Second + identity.DefaultClockSkew - time.Second)
		s = stageScope(ci)
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusValid {
			t.Fatalf("inside the skew: status %q, want valid", s.idStatus)
		}
		// Past exp plus skew: expired, no subject, and no second Verify.
		e.clk.advance(2 * time.Second)
		calls := e.v.Calls()
		s = stageScope(ci)
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusExpired || s.subject != nil {
			t.Fatalf("after exp+skew: status %q subject %+v, want expired and nil", s.idStatus, s.subject)
		}
		if e.v.Calls() != calls {
			t.Error("an expired connection identity was re-verified")
		}
	})

	t.Run("keepalive_session", func(t *testing.T) {
		e2 := newIDEnv(t, IdentityModeAttribute)
		exp := e2.clk.now().Add(30 * time.Second)
		e2.v.Set("tok-short", idClaims("alice", exp), identity.StatusValid, "")
		c := e2.h1("Proxy-Authorization: " + basicAuth("tok-short") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("first request status = %d", st)
		}
		if got := e2.m.identityCount("expired", "none"); got != 0 {
			t.Fatalf("expired recorded before exp: %d", got)
		}
		e2.clk.advance(30*time.Second + identity.DefaultClockSkew + time.Second)
		if st := c.get(""); st != 200 {
			t.Fatalf("request after exp status = %d, want the upstream's 200 (attribute never blocks)", st)
		}
		if got := e2.m.identityCount("expired", "none"); got != 1 {
			t.Errorf("expired count = %d, want 1; metrics: %s", got, e2.m.describe())
		}
		if got := e2.m.identityCount("valid", "none"); got != 1 {
			t.Errorf("valid count = %d, want 1 (the CONNECT verification only)", got)
		}
	})

	t.Run("valid_without_exp_fails_closed", func(t *testing.T) {
		v := fakes.NewVerifier()
		v.Set("tok-noexp", identity.Claims{Sub: "alice"}, identity.StatusValid, "")
		p := stageProxy(t, v, IdentityModeAttribute, nil, nil)
		s := stageScope(p.resolveConnIdentity(1, basicAuth("tok-noexp")))
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusExpired || s.subject != nil {
			t.Errorf("status %q subject %+v, want expired and nil", s.idStatus, s.subject)
		}
	})
}

// --- TestIdentityDuplicateHeaders ---

func TestIdentityDuplicateHeaders(t *testing.T) {
	t.Run("connect_two_proxy_authorization", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\nProxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
		if st := c.get(""); st != 200 {
			t.Fatalf("status = %d, want 200 (attribute never blocks)", st)
		}
		if got := e.m.identityCount("invalid", "malformed"); got != 1 {
			t.Errorf("invalid/malformed = %d, want 1; metrics: %s", got, e.m.describe())
		}
		if e.v.Calls() != 0 {
			t.Errorf("verifier calls = %d, a duplicate must not be verified", e.v.Calls())
		}
	})

	t.Run("request_two_identity_headers", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		c := e.h1("")
		if st := c.get("X-Warden-Identity: Bearer tok-alice\r\nX-Warden-Identity: Bearer tok-alice\r\n"); st != 200 {
			t.Fatalf("status = %d", st)
		}
		if got := e.m.identityCount("invalid", "malformed"); got != 1 {
			t.Errorf("invalid/malformed = %d, want 1; metrics: %s", got, e.m.describe())
		}
		if e.v.Calls() != 0 {
			t.Errorf("verifier calls = %d, a duplicate must not be verified", e.v.Calls())
		}
		requireStripped(t, e.be.headers())
	})

	t.Run("duplicate_next_to_live_connect", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		ci := p.resolveConnIdentity(1, basicAuth("tok-alice"))
		for _, vals := range [][]string{{"Bearer tok-alice", "Bearer tok-alice"}, {"Token tok-alice"}} {
			s := stageScope(ci, vals...)
			runIdentity(t, p, s)
			if s.idStatus != identity.StatusInvalid || s.idReason != identity.ReasonMalformed || s.subject != nil {
				t.Errorf("%q: status %q reason %q subject %+v, want invalid/malformed", vals, s.idStatus, s.idReason, s.subject)
			}
		}
	})

	t.Run("stage", func(t *testing.T) {
		e := newIDEnv(t, IdentityModeAttribute)
		p := stageProxy(t, e.v, IdentityModeAttribute, e.clk, nil)
		s := stageScope(connIdentity{}, "Bearer tok-alice", "Bearer tok-alice")
		runIdentity(t, p, s)
		if s.idStatus != identity.StatusInvalid || s.idReason != identity.ReasonMalformed || s.subject != nil {
			t.Errorf("request: status %q reason %q subject %+v", s.idStatus, s.idReason, s.subject)
		}
		ci := p.resolveConnIdentity(2, basicAuth("tok-alice"))
		if ci.Status != identity.StatusInvalid || ci.Reason != identity.ReasonMalformed {
			t.Errorf("connect: %+v, want invalid/malformed", ci)
		}
	})
}

// --- parsing ---

func TestParseProxyAuthorization(t *testing.T) {
	long := strings.Repeat("a", 100)
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{basicAuth("tok"), "tok", true},
		{"basic " + base64.StdEncoding.EncodeToString([]byte("session:tok")), "tok", true},
		{"  " + basicAuth("tok") + "\r\n", "tok", true},
		{basicAuth(long), long, true},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("session:a:b")), "a:b", true},
		{"Bearer tok", "tok", true},
		{"bearer tok", "tok", true},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("other:tok")), "", false},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("session:")), "", false},
		{"Basic " + base64.StdEncoding.EncodeToString([]byte("sessiontok")), "", false},
		{"Basic !!!notbase64", "", false},
		{"Basic", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Bearer a b", "", false},
		{"Digest abc", "", false},
		{"tok", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := parseProxyAuthorization(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseProxyAuthorization(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
	if got, ok := bearerToken("Bearer tok"); !ok || got != "tok" {
		t.Errorf("bearerToken = %q, %v", got, ok)
	}
	if _, ok := bearerToken("Basic dG9r"); ok {
		t.Error("bearerToken accepted Basic")
	}
}

func TestIsHeaderLine(t *testing.T) {
	for line, want := range map[string]bool{
		"Proxy-Authorization: x\r\n": true,
		"proxy-authorization:x\r\n":  true,
		"PROXY-AUTHORIZATION: x\n":   true,
		"Proxy-Authorization\r\n":    false,
		"Proxy-Authorizationx: y\n":  false,
		"X-Proxy-Authorization: x":   false,
		"Proxy-Auth: x":              false,
		"":                           false,
	} {
		if got := isHeaderLine(line, proxyAuthorizationHeader); got != want {
			t.Errorf("isHeaderLine(%q) = %v, want %v", line, got, want)
		}
	}
}

// --- TestConnectLargeProxyAuthorization ---

func TestConnectLargeProxyAuthorization(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	tok := strings.Repeat("a", identity.MaxTokenBytes)
	e.v.Set(tok, idClaims("alice", e.clk.now().Add(time.Hour)), identity.StatusValid, "")
	// A Basic 16 KiB token is ~21.8 KiB on the wire: inside the 64 KiB block.
	c := e.h1("Proxy-Authorization: " + basicAuth(tok) + "\r\n")
	if st := c.get(""); st != 200 {
		t.Fatalf("status = %d", st)
	}
	if e.v.Calls() != 1 {
		t.Errorf("verifier calls = %d, want 1", e.v.Calls())
	}
	if got := e.m.identityCount("valid", "none"); got != 1 {
		t.Errorf("valid count = %d, want 1; metrics: %s", got, e.m.describe())
	}
	if strings.Contains(e.logs.String(), tok[:64]) {
		t.Error("the token reached the logs")
	}
}

// --- TestIdentityHotSwap ---

func TestIdentityHotSwap(t *testing.T) {
	e := newIDEnv(t, IdentityModeAttribute)
	other := fakes.NewVerifier()
	other.Set("tok-alice", idClaims("alice", e.clk.now().Add(time.Hour)), identity.StatusValid, "")

	stop := make(chan struct{})
	var swaps sync.WaitGroup
	swaps.Add(1)
	go func() {
		defer swaps.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			switch i % 3 {
			case 0:
				e.p.SetIdentity(e.v, IdentityModeAttribute)
			case 1:
				e.p.SetIdentity(other, IdentityModeAttribute)
			default:
				e.p.SetIdentity(nil, IdentityModeOff)
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var failed atomic.Int64
	var clients sync.WaitGroup
	for i := 0; i < 4; i++ {
		clients.Add(1)
		go func() {
			defer clients.Done()
			conn, br, status := e.connect("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
			if !strings.Contains(status, "200") {
				failed.Add(1)
				return
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(e.caPEM)
			tc := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{ServerName: idHost, RootCAs: pool, NextProtos: []string{"http/1.1"}})
			if tc.Handshake() != nil {
				failed.Add(1)
				return
			}
			rd := bufio.NewReader(tc)
			for j := 0; j < 25; j++ {
				_, _ = io.WriteString(tc, "GET /x HTTP/1.1\r\nHost: "+idHost+"\r\nX-Warden-Identity: Bearer tok-bob\r\n\r\n")
				resp, err := http.ReadResponse(rd, nil)
				if err != nil {
					failed.Add(1)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					failed.Add(1)
				}
			}
		}()
	}
	clients.Wait()
	close(stop)
	swaps.Wait()
	if n := failed.Load(); n != 0 {
		t.Errorf("%d requests failed during hot swaps; a swap must never change the response", n)
	}
}

// --- TestIdentityTransparent ---

func TestIdentityTransparent(t *testing.T) {
	v := fakes.NewVerifier()
	v.Set("tok-alice", idClaims("alice", time.Now().Add(time.Hour)), identity.StatusValid, "")
	e := newTransparentEnv(t, transparentOpts{plainHTTP: true, identity: IdentityConfig{Verifier: v, Mode: IdentityModeAttribute}})
	count := func(entry string) int {
		n := 0
		for _, r := range e.metrics.snapshot() {
			if r == entry {
				n++
			}
		}
		return n
	}
	upstreamSaw := func(h string) bool {
		e.backend.mu.Lock()
		defer e.backend.mu.Unlock()
		for _, s := range e.backend.seen {
			if len(s.header.Values(h)) > 0 {
				return true
			}
		}
		return false
	}

	// A terminated transparent request with the header is attributed...
	req, _ := http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	req.Header.Set(IdentityHeader, "Bearer tok-alice")
	req.Header.Set("Proxy-Authorization", basicAuth("tok-alice"))
	if _, st, err := e.doH1(invHost, req); err != nil || st != 200 {
		t.Fatalf("with header: status %d err %v", st, err)
	}
	if got := count("identity_verify result=valid reason=none"); got != 1 {
		t.Errorf("valid count = %d, want 1; metrics: %v", got, e.metrics.snapshot())
	}
	// ...and Proxy-Authorization is never consulted: exactly one Verify, for the header.
	if v.Calls() != 1 {
		t.Errorf("verifier calls = %d, want 1 (Proxy-Authorization must not be verified)", v.Calls())
	}

	// ...one without it is anonymous.
	req, _ = http.NewRequest(http.MethodGet, "https://"+invHost+"/plain", nil)
	if _, st, err := e.doH1(invHost, req); err != nil || st != 200 {
		t.Fatalf("without header: status %d err %v", st, err)
	}
	if got := count("identity_verify result=none reason=none"); got != 1 {
		t.Errorf("none count = %d, want 1; metrics: %v", got, e.metrics.snapshot())
	}

	// The plain-HTTP listener attributes the same way.
	if _, st, err := e.plainDo(invHost, "GET /plain HTTP/1.1\r\nHost: "+invHost+"\r\nX-Warden-Identity: Bearer tok-alice\r\nConnection: close\r\n\r\n"); err != nil || st != 200 {
		t.Fatalf("plain http: status %d err %v", st, err)
	}
	if got := count("identity_verify result=valid reason=none"); got != 2 {
		t.Errorf("valid count after plain http = %d, want 2", got)
	}

	if upstreamSaw(IdentityHeader) || upstreamSaw("Proxy-Authorization") {
		t.Error("a transparent request leaked an identity header to the upstream")
	}
	if strings.Contains(e.logs.String(), "tok-alice") {
		t.Error("the token reached the logs")
	}

	// The listener passes the zero connIdentity: status none.
	if (connIdentity{}).status() != identity.StatusNone {
		t.Error("zero connIdentity is not status none")
	}
}

// --- TestIdentityStartupWarnings ---

func TestIdentityStartupWarnings(t *testing.T) {
	v := fakes.NewVerifier()
	build := func(t *testing.T, mut func(*Config)) (*Proxy, *lockedBuf) {
		t.Helper()
		logs := &lockedBuf{}
		cfg := Config{
			ListenAddr: "127.0.0.1:0",
			Policy:     policy.NewEvaluator(config.Policy{}),
			Secrets:    &fakes.FakeSecretProvider{Values: map[string]string{}},
			Analytics:  &syncStore{},
			Logger:     slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		}
		mut(&cfg)
		p, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return p, logs
	}
	const noCA, transparentOnly = "without a CA", "transparent-only"

	t.Run("attribute_without_ca_once", func(t *testing.T) {
		p, logs := build(t, func(c *Config) { c.Identity = IdentityConfig{Verifier: v, Mode: IdentityModeAttribute} })
		p.SetIdentity(v, IdentityModeAttribute)
		p.SetIdentity(v, IdentityModeAttribute)
		if n := strings.Count(logs.String(), noCA); n != 1 {
			t.Errorf("no-CA warnings = %d, want 1:\n%s", n, logs.String())
		}
		if strings.Contains(logs.String(), transparentOnly) {
			t.Error("a forward worker got the transparent-only warning")
		}
	})

	t.Run("set_identity_after_new", func(t *testing.T) {
		p, logs := build(t, func(*Config) {})
		if logs.String() != "" {
			t.Fatalf("mode off logged: %s", logs.String())
		}
		p.SetIdentity(v, IdentityModeAttribute)
		if n := strings.Count(logs.String(), noCA); n != 1 {
			t.Errorf("no-CA warnings = %d, want 1", n)
		}
	})

	t.Run("off_is_silent", func(t *testing.T) {
		p, logs := build(t, func(c *Config) { c.Identity = IdentityConfig{Verifier: v, Mode: IdentityModeOff} })
		p.SetIdentity(nil, IdentityModeAttribute)
		if logs.String() != "" {
			t.Errorf("mode off logged: %s", logs.String())
		}
	})

	t.Run("transparent_only_once", func(t *testing.T) {
		certPath, keyPath, _ := invCA(t)
		p, logs := build(t, func(c *Config) {
			c.Mode = config.ProxyModeTransparent
			c.TransparentHTTPSListen = "127.0.0.1:0"
			c.CACertPath, c.CAKeyPath = certPath, keyPath
			c.Identity = IdentityConfig{Verifier: v, Mode: IdentityModeAttribute}
		})
		p.SetIdentity(v, IdentityModeAttribute)
		if n := strings.Count(logs.String(), transparentOnly); n != 1 {
			t.Errorf("transparent-only warnings = %d, want 1:\n%s", n, logs.String())
		}
		if strings.Contains(logs.String(), noCA) {
			t.Error("a worker with a CA got the no-CA warning")
		}
	})

	t.Run("forward_with_ca_is_silent", func(t *testing.T) {
		certPath, keyPath, _ := invCA(t)
		_, logs := build(t, func(c *Config) {
			c.CACertPath, c.CAKeyPath = certPath, keyPath
			c.Identity = IdentityConfig{Verifier: v, Mode: IdentityModeAttribute}
		})
		if logs.String() != "" {
			t.Errorf("unexpected warning: %s", logs.String())
		}
	})
}

// --- budget ---

// identityBudgetScope is a keep-alive request on a valid CONNECT identity, the
// cached-token path: no Verify, a Subject built per request.
func identityBudgetScope(t testing.TB, p *Proxy) *requestScope {
	ci := p.resolveConnIdentity(1, basicAuth("tok"))
	if ci.Status != identity.StatusValid {
		t.Fatalf("setup: connIdentity = %+v", ci)
	}
	return stageScope(ci)
}

func budgetProxy(t testing.TB) *Proxy {
	v := fakes.NewVerifier()
	v.Set("tok", idClaims("alice", time.Now().Add(time.Hour)), identity.StatusValid, "")
	return stageProxy(t, v, IdentityModeAttribute, nil, nil)
}

// Recorded allocation bounds. Cached CONNECT identity: the Subject and its group
// copy (SubjectFrom), measured 2. Header token: adds the Verify timeout context
// and the Bearer parse, measured 6.
const (
	maxIdentityStageAllocs       = 2
	maxIdentityHeaderStageAllocs = 7
)

// identityStageNsBudget is the per-request ceiling for the cached-token path
// (100 us/op), with the race detector's overhead well inside it.
const identityStageNsBudget = 100_000

func TestIdentityStageBudget(t *testing.T) {
	p := budgetProxy(t)
	s := identityBudgetScope(t, p)
	run := func() {
		s.subject, s.idStatus = nil, ""
		p.identityStage(s)
	}
	run()
	if s.idStatus != identity.StatusValid || s.subject == nil {
		t.Fatalf("setup: status %q subject %+v", s.idStatus, s.subject)
	}
	if allocs := testing.AllocsPerRun(200, run); allocs > maxIdentityStageAllocs {
		t.Errorf("identityStage allocs/op = %v, want <= %d", allocs, maxIdentityStageAllocs)
	}
	const n = 2000
	start := time.Now()
	for i := 0; i < n; i++ {
		run()
	}
	if per := time.Since(start) / n; per > identityStageNsBudget*time.Nanosecond {
		t.Errorf("identityStage = %v/op, want < %v", per, identityStageNsBudget*time.Nanosecond)
	}

	hdr := stageScope(connIdentity{}, "Bearer tok")
	runHdr := func() {
		hdr.subject, hdr.idStatus, hdr.rawIdentity, hdr.rawIdentityN = nil, "", "Bearer tok", 1
		p.identityStage(hdr)
	}
	if runHdr(); hdr.idStatus != identity.StatusValid {
		t.Fatalf("header setup: status %q", hdr.idStatus)
	}
	if allocs := testing.AllocsPerRun(200, runHdr); allocs > maxIdentityHeaderStageAllocs {
		t.Errorf("identityStage header allocs/op = %v, want <= %d", allocs, maxIdentityHeaderStageAllocs)
	}

	// With identity off the stage allocates nothing.
	off := stageProxy(t, nil, IdentityModeOff, nil, nil)
	so := stageScope(connIdentity{})
	if allocs := testing.AllocsPerRun(200, func() { off.identityStage(so) }); allocs != 0 {
		t.Errorf("identityStage off allocs/op = %v, want 0", allocs)
	}
}

func BenchmarkIdentityStage(b *testing.B) {
	b.Run("off", func(b *testing.B) {
		p := stageProxy(b, nil, IdentityModeOff, nil, nil)
		s := stageScope(connIdentity{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p.identityStage(s)
		}
	})
	b.Run("attribute_none", func(b *testing.B) {
		p := budgetProxy(b)
		s := stageScope(connIdentity{})
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p.identityStage(s)
		}
	})
	b.Run("attribute_connect_valid", func(b *testing.B) {
		p := budgetProxy(b)
		s := identityBudgetScope(b, p)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.subject = nil
			p.identityStage(s)
		}
	})
	b.Run("attribute_header_cached", func(b *testing.B) {
		p := budgetProxy(b)
		s := stageScope(connIdentity{}, "Bearer tok")
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.subject, s.rawIdentity, s.rawIdentityN = nil, "Bearer tok", 1
			p.identityStage(s)
		}
	})
	b.Run("capture", func(b *testing.B) {
		p := budgetProxy(b)
		s := stageScope(connIdentity{}, "Bearer tok")
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p.captureIdentityHeader(s)
		}
	})
}
