package scenarios

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// The token-injecting forwarder (W-P2-RCP-02): the real `identity forward`
// engine (identityclient.RunForwarder over a WardenTokenSource) in front of the
// harness's real worker, which runs in require mode bound to the forwarder's
// agent, with the real control-plane token service issuing the tokens. A
// recording relay sits between the forwarder and the worker: it notes the token
// of every CONNECT and the status the worker answered, and changes nothing.
//
// What is proved: the token is injected and admitted; a plain rotation drains
// the tunnels of the old token; an emergency token-key rotation at the control
// plane makes the worker refuse the held token with its own 407, and the
// forwarder then refreshes once and retries once with a new token (different
// jti, same act); the signer window and a disabled agent show on /healthz and
// as 503 reason codes.

// forwarderAgent is the agent the forwarder acts for and the worker is bound to.
const forwarderAgent = "harness-agent"

// forwarderTarget is the CONNECT target of the scenario.
const forwarderTarget = identityHost + ":443"

func identityForwarderOpts() []harness.Option {
	return tokenServiceOpts(harness.WithBundles(controlplane.BundlesOffer), harness.WithBundlePins(), harness.WithWorkerAgent(forwarderAgent))
}

// relayRecord is one CONNECT the relay carried: the token it presented and the
// status the worker answered (0 when the worker never answered).
type relayRecord struct {
	token  string
	status int
}

// recordingRelay is a TCP relay in front of the real worker that records each
// CONNECT's Proxy-Authorization token and the worker's status, then pipes the
// bytes both ways untouched.
type recordingRelay struct {
	ln     net.Listener
	target string

	mu   sync.Mutex
	recs []relayRecord
}

func newRecordingRelay(t *testing.T, target string) *recordingRelay {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &recordingRelay{ln: ln, target: target}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *recordingRelay) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	var head strings.Builder
	var tok string
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(l)
		if rest, ok := strings.CutPrefix(l, "Proxy-Authorization: Basic "); ok {
			if raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
				tok = strings.TrimPrefix(string(raw), "session:")
			}
		}
		if l == "\r\n" {
			break
		}
	}
	wc, err := net.DialTimeout("tcp", r.target, 5*time.Second)
	if err != nil {
		return
	}
	defer func() { _ = wc.Close() }()
	if _, err := io.WriteString(wc, head.String()); err != nil {
		return
	}
	wbr := bufio.NewReader(wc)
	status, err := peekStatus(wbr)
	r.mu.Lock()
	r.recs = append(r.recs, relayRecord{token: tok, status: status})
	r.mu.Unlock()
	if err != nil {
		return
	}
	go func() {
		_, _ = io.Copy(wc, br)
		_ = wc.Close()
	}()
	_, _ = io.Copy(c, wbr)
}

// peekStatus reads the status code of the response at the head of br without
// consuming it.
func peekStatus(br *bufio.Reader) (int, error) {
	// "HTTP/1.1 NNN": the code is bytes 9..11.
	b, err := br.Peek(12)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(b[9:12]))
}

func (r *recordingRelay) records() []relayRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]relayRecord(nil), r.recs...)
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
	return !ok || !ne.Timeout()
}

// heldTunnel is a CONNECT through the forwarder with a TLS session inside it,
// terminated by the real worker.
type heldTunnel struct {
	conn net.Conn
	br   *bufio.Reader
	tls  *tls.Conn
	tbr  *bufio.Reader
}

// openTunnel CONNECTs through the forwarder and, on a 200, starts TLS to the
// worker's terminating listener. It returns the forwarder's answer head.
func openTunnel(t *testing.T, h *harness.H, client forwarderClient) (*heldTunnel, string) {
	t.Helper()
	conn, br, head := client.connect(forwarderTarget)
	if headStatus(head) != http.StatusOK {
		return nil, head
	}
	if br.Buffered() != 0 {
		t.Fatalf("the worker sent %d bytes before the TLS hello", br.Buffered())
	}
	cfg := h.AgentTLSConfig().Clone()
	cfg.ServerName = identityHost
	cfg.NextProtos = []string{"http/1.1"}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("TLS through the tunnel: %v", err)
	}
	return &heldTunnel{conn: conn, br: br, tls: tc, tbr: bufio.NewReader(tc)}, head
}

// get sends GET path on the tunnel and returns the status.
func (ht *heldTunnel) get(t *testing.T, path string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = ht.tls.SetDeadline(time.Now().Add(30 * time.Second))
	if err := req.Write(ht.tls); err != nil {
		t.Fatalf("write on the tunnel: %v", err)
	}
	resp, err := http.ReadResponse(ht.tbr, req)
	if err != nil {
		t.Fatalf("read on the tunnel: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (ht *heldTunnel) closed() bool { return tunnelClosed(ht.tls, ht.tbr) }

// identityForwarder is the scenario.
func identityForwarder(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	key, err := identityclient.GenerateAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	h.RegisterTokenAgentKey(forwarderAgent, key.PublicJWK(), []string{"eng"}, []string{"read", "write"})
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
		AgentID: forwarderAgent, Key: key, Scope: "read", HTTP: h.CP().HTTPClient(), Now: h.Clock().Now,
	}
	src := identityclient.NewWardenTokenSource(ex, identityclient.FileSubject{Path: subjectFile})
	src.Now, src.Attempts, src.AgentID = h.Clock().Now, 1, forwarderAgent

	relay := newRecordingRelay(t, h.ProxyAddr())
	logs := &syncedBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fwd := &identityclient.Forwarder{
		WorkerAddr: relay.ln.Addr().String(), Source: src, AllowAnonymousClients: true, Log: log, Clock: h.Clock(),
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
	// loop on that clock (the forwarder's, the control plane's, the worker's)
	// gets its turn.
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
	if _, _, head := client.connect(forwarderTarget); headStatus(head) != http.StatusServiceUnavailable || headReason(head) != "cp_unreachable" {
		t.Fatalf("CONNECT before the key is published: %q, want 503 cp_unreachable", head)
	}
	if n := len(relay.records()); n != 0 {
		t.Fatalf("the worker saw %d connections with no token", n)
	}

	// 2. The window passes: the forwarder recovers by itself. The worker is then
	// put in require mode for its agent, and the forwarder's token is admitted
	// once the worker holds the bundle that carries the token key.
	waitTokenKeyPublished(h)
	user = writeSubject()
	advanceUntil("healthz to report a valid token", 3*time.Second, func() bool { _, s := healthz(); return s == "valid" })
	if code, _ := healthz(); code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", code)
	}
	editSettings(t, h, func(s *config.SettingsWire) {
		s.Agents = append(s.Agents, config.AgentSettings{ID: forwarderAgent, Identity: config.IdentityModeRequire})
	})
	h.Eventually("the worker to apply require mode", func() bool {
		return requireConnect(t, h, "").status == http.StatusProxyAuthRequired
	})
	h.Eventually("the worker to admit the forwarder's token", func() bool {
		conn, br, head := client.connect(forwarderTarget)
		_ = br
		_ = conn.Close()
		return headStatus(head) == http.StatusOK
	})
	settled := len(relay.records())

	// 3. A CONNECT carries the Warden token, not anything the client sent, and
	// the real worker admits it in require mode.
	oldTun, head := openTunnel(t, h, client)
	if oldTun == nil {
		t.Fatalf("CONNECT: %q, want 200", head)
	}
	recs := relay.records()[settled:]
	if len(recs) != 1 || recs[0].status != http.StatusOK || recs[0].token == "" {
		t.Fatalf("relay records = %+v, want one CONNECT with a token answered 200", recs)
	}
	first := recs[0].token
	_, c1 := verifyWardenToken(t, h, first)
	if c1.Sub != "user-42" || c1.Act.Sub != forwarderAgent {
		t.Errorf("injected token: sub %q act %q, want user-42 acting as %s", c1.Sub, c1.Act.Sub, forwarderAgent)
	}
	if st := oldTun.get(t, "/first"); st != http.StatusOK {
		t.Fatalf("GET through the tunnel = %d, want 200", st)
	}

	// 4. A rotation (a plain refresh, the old token still valid at the worker)
	// drains the tunnel opened with the old token once it has been idle for 2s;
	// a tunnel opened with the new token stays.
	h.Clock().Advance(3 * time.Second)
	user = writeSubject()
	if _, err := src.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	cur, _ := src.Current()
	second := cur.AccessToken
	if second == first {
		t.Fatal("the refresh returned the same token")
	}
	_, c1b := verifyWardenToken(t, h, second) // before its key is revoked
	newTun, head := openTunnel(t, h, client)
	if newTun == nil {
		t.Fatalf("CONNECT after the rotation: %q, want 200", head)
	}
	if got := relay.records(); got[len(got)-1].token != second || got[len(got)-1].status != http.StatusOK {
		t.Fatalf("the CONNECT after the rotation = %+v, want the newest token answered 200", got[len(got)-1])
	}
	advanceUntil("the old tunnel to be drained", 500*time.Millisecond, oldTun.closed)
	if newTun.closed() {
		t.Error("the tunnel opened with the new token was drained")
	}
	if st := newTun.get(t, "/second"); st != http.StatusOK {
		t.Errorf("GET on the new tunnel after the drain = %d, want 200", st)
	}

	// 5. A real revocation: an emergency rotation of the token key at the
	// control plane revokes the key that signed both tokens held so far. The
	// worker applies the new bundle, closes the tunnel it holds for the revoked
	// token and refuses that token's next CONNECT with its own 407. The next
	// request through the forwarder meets that 407, makes one exchange and
	// retries once with a token signed by the new key.
	ctx5 := context.Background()
	o, err := controlplane.OpenKeysOffline(ctx5, h.KeyStateDir(), controlplane.KeysCLIOptions{Clock: h.Clock()})
	if err != nil {
		t.Fatalf("open the keys CLI: %v", err)
	}
	defer func() { _ = o.Close() }()
	if _, err := o.Rotate(ctx5, keys.PurposeToken, true); err != nil {
		t.Fatalf("emergency rotation: %v", err)
	}
	advanceUntil("the worker to refuse the revoked token", time.Second, func() bool {
		status, _ := h.ConnectReplyAt(0, forwarderTarget, basicAuth("session", second))
		return status == http.StatusProxyAuthRequired
	})
	advanceUntil("the worker to close the tunnel of the revoked token", 500*time.Millisecond, newTun.closed)
	if requireDeny(h, "unknown_kid") == 0 {
		t.Error("the worker recorded no unknown_kid refusal for the revoked token")
	}
	h.Clock().Advance(3 * time.Second) // past the forwarder's 2s floor between exchanges
	user = writeSubject()
	before := len(relay.records())
	retryTun, head := openTunnel(t, h, client)
	if retryTun == nil {
		t.Fatalf("CONNECT after the emergency rotation: %q, want 200 after the retry", head)
	}
	recs = relay.records()[before:]
	if len(recs) != 2 || recs[0].status != http.StatusProxyAuthRequired || recs[0].token != second ||
		recs[1].status != http.StatusOK || recs[1].token == "" || recs[1].token == second {
		t.Fatalf("relay records after the revocation = %+v, want the revoked token answered 407, then a new token answered 200", recs)
	}
	third := recs[1].token
	_, c2 := verifyWardenToken(t, h, third)
	if c2.Act.Sub != c1b.Act.Sub || c2.Sub != c1b.Sub {
		t.Errorf("refreshed token: sub %q act %q, want sub %q act %q", c2.Sub, c2.Act.Sub, c1b.Sub, c1b.Act.Sub)
	}
	if c2.JTI == c1b.JTI {
		t.Errorf("refreshed token has the revoked token's jti %s", c2.JTI)
	}
	if c2.SID != c1b.SID {
		t.Errorf("refreshed token sid %s, want the session's sid %s (a refresh continues the session)", c2.SID, c1b.SID)
	}
	if st := retryTun.get(t, "/retried"); st != http.StatusOK {
		t.Errorf("GET through the retried tunnel = %d, want 200", st)
	}

	// 6. The agent is disabled at the control plane. The held token works until
	// the refresh fails and then until its own exp; after that the forwarder
	// reports exchange_denied and refuses CONNECTs with that reason.
	h.DisableTokenAgent(forwarderAgent)
	advanceUntil("healthz to report exchange_denied", 30*time.Second, func() bool {
		user = writeSubject()
		_, s := healthz()
		return s == "exchange_denied"
	})
	if code, _ := healthz(); code != http.StatusServiceUnavailable {
		t.Errorf("healthz status = %d, want 503", code)
	}
	dials := len(relay.records())
	if _, _, head := client.connect(forwarderTarget); headStatus(head) != http.StatusServiceUnavailable || headReason(head) != "exchange_denied" {
		t.Fatalf("CONNECT for a disabled agent: %q, want 503 exchange_denied", head)
	}
	if n := len(relay.records()); n != dials {
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
	secrets := []string{user, base64.StdEncoding.EncodeToString([]byte("session:" + third))}
	for _, r := range relay.records() {
		secrets = append(secrets, r.token)
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(out, s) {
			t.Errorf("the forwarder log holds a credential (%d bytes of it)", len(s))
		}
	}
	requireNoCredentialsInLogs(t, h, secrets...)
}
