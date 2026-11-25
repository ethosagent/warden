package scenarios

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/harness"
)

// The token-injecting forwarder (W-P2-RCP-02): the real `identity forward`
// engine (identityclient.RunForwarder over a WardenTokenSource) in front of a
// CONNECT worker, with the real control-plane token service issuing the tokens.
// The worker here is a small fake that refuses (407) tokens it was told are
// revoked: enforcing Warden tokens on the worker is a later ticket, and what is
// proved here is the forwarder's half: the token is injected, a 407 leads to
// one refresh and one retry, a rotation drains the old tunnels, and the state
// of the token source is what /healthz reports.

// tokenWorker is a CONNECT listener that records the token of each CONNECT and
// answers 407 for a token in revoked, else 200 and an echo.
type tokenWorker struct {
	ln net.Listener

	mu      sync.Mutex
	tokens  []string
	revoked map[string]bool
}

func newTokenWorker(t *testing.T) *tokenWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &tokenWorker{ln: ln, revoked: map[string]bool{}}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go w.serve(c)
		}
	}()
	return w
}

func (w *tokenWorker) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	var tok string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if rest, ok := strings.CutPrefix(l, "Proxy-Authorization: Basic "); ok {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
				tok = strings.TrimPrefix(string(raw), "session:")
			}
		}
		if l == "\r\n" {
			break
		}
	}
	w.mu.Lock()
	w.tokens = append(w.tokens, tok)
	denied := w.revoked[tok]
	w.mu.Unlock()
	if denied {
		_, _ = io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"warden\"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_, _ = io.Copy(c, br)
}

func (w *tokenWorker) Tokens() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.tokens...)
}

func (w *tokenWorker) Revoke(tok string) {
	w.mu.Lock()
	w.revoked[tok] = true
	w.mu.Unlock()
}

// syncedBuffer is a log sink the forwarder's goroutines and the scenario share.
type syncedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncedBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncedBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// forwarderClient makes CONNECTs through the forwarder.
type forwarderClient struct {
	t    *testing.T
	addr string
}

// connect sends a CONNECT and returns the connection, its reader and the
// status line and headers the forwarder answered with.
func (f forwarderClient) connect(target string) (net.Conn, *bufio.Reader, string) {
	f.t.Helper()
	c, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n"); err != nil {
		f.t.Fatal(err)
	}
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			f.t.Fatalf("read the forwarder's answer (%q): %v", head.String(), err)
		}
		head.WriteString(l)
		if l == "\r\n" {
			return c, br, head.String()
		}
	}
}

func headStatus(head string) int {
	var n int
	for _, f := range strings.Fields(head)[1:2] {
		for _, r := range f {
			n = n*10 + int(r-'0')
		}
	}
	return n
}

func headReason(head string) string {
	for _, l := range strings.Split(head, "\r\n") {
		if name, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(name, "X-Warden-Forwarder-Reason") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// tunnelClosed reports whether the far end has closed c (a read that ends in
// anything but a timeout).
func tunnelClosed(c net.Conn, br *bufio.Reader) bool {
	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := br.ReadByte()
	if err == nil {
		return false
	}
	ne, ok := err.(net.Error)
	return !(ok && ne.Timeout())
}

// identityForwarder is the scenario.
func identityForwarder(t *testing.T, h *harness.H) {
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	const agentID = "harness-agent"
	h.RegisterTokenAgentKey(agentID, key.PublicJWK(), []string{"eng"}, []string{"read", "write"})
	subjectFile := filepath.Join(t.TempDir(), "subject")
	writeSubject := func() string {
		tok := tokenUser(h, "user-42", "eng")
		if err := os.WriteFile(subjectFile, []byte(tok+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return tok
	}
	user := writeSubject()

	ex := &identityclient.Exchanger{
		Endpoint: h.CP().TokenEndpointURL(), Audience: harness.TokenAudience(),
		AgentID: agentID, Key: key, Scope: "read", HTTP: h.CP().HTTPClient(), Now: h.Clock().Now,
	}
	src := identityclient.NewWardenTokenSource(ex, identityclient.FileSubject{Path: subjectFile})
	src.Now, src.Attempts, src.AgentID = h.Clock().Now, 1, agentID

	worker := newTokenWorker(t)
	logs := &syncedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fwd := &identityclient.Forwarder{
		WorkerAddr: worker.ln.Addr().String(), Source: src, AllowAnonymousClients: true, Log: log, Clock: h.Clock(),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = identityclient.RunForwarder(ctx, identityclient.ForwardRun{
			Forwarder: fwd, Listener: ln, Health: hl, State: src.State, Log: log, Clock: h.Clock(),
			Poke: func(ctx context.Context) { _, _ = src.Token(ctx) }, Grace: time.Second,
		})
	}()
	t.Cleanup(func() {
		cancel()
		h.Eventually("the forwarder to stop", func() bool {
			h.Clock().Advance(2 * time.Second)
			select {
			case <-done:
				return true
			default:
				return false
			}
		})
	})
	client := forwarderClient{t: t, addr: ln.Addr().String()}
	healthz := func() (int, string) {
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + hl.Addr().String() + "/healthz")
		if err != nil {
			t.Fatalf("healthz: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var body struct{ State, Exp string }
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("healthz body %q: %v", raw, err)
		}
		return resp.StatusCode, body.State
	}
	// advanceUntil moves the harness clock by step until cond holds, so every
	// loop on that clock (the forwarder's, the control plane's) gets its turn.
	advanceUntil := func(desc string, step time.Duration, cond func() bool) {
		h.Eventually(desc, func() bool {
			if cond() {
				return true
			}
			h.Clock().Advance(step)
			return false
		})
	}

	// 1. The control plane has just created its first signing key and will not
	// mint for about two minutes: the forwarder reports cp_unreachable, answers
	// a CONNECT 503 with that reason and dials nothing, and keeps running.
	advanceUntil("healthz to report the unpublished signing key", 0, func() bool { _, s := healthz(); return s == "cp_unreachable" })
	if code, _ := healthz(); code != http.StatusServiceUnavailable {
		t.Errorf("healthz status = %d, want 503", code)
	}
	if _, _, head := client.connect("api.example.com:443"); headStatus(head) != http.StatusServiceUnavailable || headReason(head) != "cp_unreachable" {
		t.Fatalf("CONNECT before the key is published: %q, want 503 cp_unreachable", head)
	}
	if n := len(worker.Tokens()); n != 0 {
		t.Fatalf("the worker saw %d connections with no token", n)
	}

	// 2. The window passes: the forwarder recovers by itself.
	waitTokenKeyPublished(h)
	user = writeSubject()
	advanceUntil("healthz to report a valid token", 3*time.Second, func() bool { _, s := healthz(); return s == "valid" })
	if code, _ := healthz(); code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", code)
	}

	// 3. A CONNECT carries the Warden token, not anything the client sent.
	oldConn, oldBR, head := client.connect("api.example.com:443")
	if headStatus(head) != http.StatusOK {
		t.Fatalf("CONNECT: %q, want 200", head)
	}
	first := worker.Tokens()
	if len(first) != 1 {
		t.Fatalf("worker tokens = %d, want 1", len(first))
	}
	_, c1 := verifyWardenToken(t, h, first[0])
	if c1.Sub != "user-42" || c1.Act.Sub != agentID {
		t.Errorf("injected token: sub %q act %q, want user-42 acting as %s", c1.Sub, c1.Act.Sub, agentID)
	}
	if _, err := io.WriteString(oldConn, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := oldBR.ReadString('\n'); got != "ping\n" {
		t.Fatalf("echo through the tunnel = %q", got)
	}

	// 4. The worker no longer accepts that token (revoked): the 407 makes the
	// forwarder exchange again (the 2s floor since the last exchange has passed)
	// and retry the CONNECT once, with the new token, which the worker accepts.
	h.Clock().Advance(3 * time.Second)
	user = writeSubject()
	worker.Revoke(first[0])
	c2conn, _, head := client.connect("api.example.com:443")
	defer func() { _ = c2conn.Close() }()
	if headStatus(head) != http.StatusOK {
		t.Fatalf("CONNECT with a revoked token: %q, want 200 after the retry", head)
	}
	toks := worker.Tokens()
	if len(toks) != 3 || toks[1] != first[0] || toks[2] == first[0] || toks[2] == "" {
		t.Fatalf("worker tokens after the 407 = %d (revoked token repeated: %v), want the revoked one, then a new one", len(toks), len(toks) > 2 && toks[2] == first[0])
	}
	_, c2 := verifyWardenToken(t, h, toks[2])
	if c2.SID != c1.SID || c2.JTI == c1.JTI {
		t.Errorf("refreshed token: sid %s jti %s, want sid %s and a fresh jti", c2.SID, c2.JTI, c1.SID)
	}

	// 5. The rotation drains the tunnel opened with the old token once it has
	// been idle for 2s; the tunnel made with the new token stays.
	advanceUntil("the old tunnel to be drained", 500*time.Millisecond, func() bool { return tunnelClosed(oldConn, oldBR) })
	if _, _, head := client.connect("api.example.com:443"); headStatus(head) != http.StatusOK {
		t.Errorf("CONNECT after the drain: %q", head)
	}
	if last := worker.Tokens(); last[len(last)-1] != toks[2] {
		t.Errorf("a new CONNECT carries a token other than the newest")
	}

	// 6. The agent is disabled at the control plane. The held token works until
	// the refresh fails and then until its own exp; after that the forwarder
	// reports exchange_denied and refuses CONNECTs with that reason.
	h.DisableTokenAgent(agentID)
	advanceUntil("healthz to report exchange_denied", 30*time.Second, func() bool {
		user = writeSubject()
		_, s := healthz()
		return s == "exchange_denied"
	})
	if code, _ := healthz(); code != http.StatusServiceUnavailable {
		t.Errorf("healthz status = %d, want 503", code)
	}
	dials := len(worker.Tokens())
	if _, _, head := client.connect("api.example.com:443"); headStatus(head) != http.StatusServiceUnavailable || headReason(head) != "exchange_denied" {
		t.Fatalf("CONNECT for a disabled agent: %q, want 503 exchange_denied", head)
	}
	if n := len(worker.Tokens()); n != dials {
		t.Errorf("the worker saw %d more connections for a disabled agent", n-dials)
	}

	// 7. Logging: each state change once, and no token or credential anywhere.
	out := logs.String()
	for _, want := range []string{"state=cp_unreachable", "state=valid", "state=exchange_denied"} {
		if n := strings.Count(out, want); n != 1 {
			t.Errorf("%q logged %d times, want once", want, n)
		}
	}
	for _, want := range []string{"tunnel_open", "tunnel_close", "token_rotated"} {
		if !strings.Contains(out, want) {
			t.Errorf("the forwarder log has no %s event", want)
		}
	}
	secrets := append([]string{user, base64.StdEncoding.EncodeToString([]byte("session:" + toks[2]))}, worker.Tokens()...)
	for _, s := range secrets {
		if s != "" && strings.Contains(out, s) {
			t.Errorf("the forwarder log holds a credential (%d bytes of it)", len(s))
		}
	}
	requireNoCredentialsInLogs(t, h, secrets...)
}
