package identityclient_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identityclient"
)

const (
	fwdCred  = "per-run-credential-SECRET"
	fwdToken = "header.payload-SECRET.signature"
)

// fakeWorker plays the worker's CONNECT listener: it records each CONNECT head
// it receives, answers with reply and, for a 200, echoes the tunnel.
type fakeWorker struct {
	ln    net.Listener
	reply string
	dials atomic.Int64

	mu    sync.Mutex
	heads []string
}

func newFakeWorker(t *testing.T, reply string) *fakeWorker {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &fakeWorker{ln: ln, reply: reply}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			w.dials.Add(1)
			go w.serve(c)
		}
	}()
	return w
}

func (w *fakeWorker) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			return
		}
		head.WriteString(l)
		if l == "\r\n" {
			break
		}
	}
	w.mu.Lock()
	w.heads = append(w.heads, head.String())
	w.mu.Unlock()
	_, _ = io.WriteString(c, w.reply)
	if strings.HasPrefix(w.reply, "HTTP/1.1 200") {
		_, _ = io.Copy(c, br)
	}
}

func (w *fakeWorker) Heads() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.heads...)
}

const ok200 = "HTTP/1.1 200 Connection Established\r\n\r\n"

// fwdRig is a running Forwarder in front of a fake worker.
type fwdRig struct {
	fwd    *identityclient.Forwarder
	addr   string
	worker *fakeWorker
	logs   *bytes.Buffer
	done   chan error
	cancel context.CancelFunc
	token  atomic.Value // func(context.Context) (string, error)
}

func startForwarder(t *testing.T, workerReply string, tok func(context.Context) (string, error)) *fwdRig {
	t.Helper()
	return startForwarderWith(t, workerReply, tok, nil)
}

// startForwarderWith lets a test adjust the Forwarder before Serve starts.
func startForwarderWith(t *testing.T, workerReply string, tok func(context.Context) (string, error), tweak func(*identityclient.Forwarder)) *fwdRig {
	t.Helper()
	r := &fwdRig{worker: newFakeWorker(t, workerReply), logs: &bytes.Buffer{}, done: make(chan error, 1)}
	if tok == nil {
		tok = func(context.Context) (string, error) { return fwdToken, nil }
	}
	r.fwd = &identityclient.Forwarder{
		WorkerAddr:       r.worker.ln.Addr().String(),
		Token:            tok,
		ClientCredential: fwdCred,
		Log:              slog.New(slog.NewTextHandler(&lockedWriter{w: r.logs}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tweak != nil {
		tweak(r.fwd)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() { r.done <- r.fwd.Serve(ctx, ln); close(r.done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return r
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func (r *fwdRig) logText() string {
	// The buffer is guarded by lockedWriter; reading after traffic has ended is
	// race free because every handler wrote before its reply was read.
	return r.logs.String()
}

func basicHeader(user, secret string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret)) + "\r\n"
}

func goodAuth() string { return basicHeader("wx", fwdCred) }

// send writes raw to the forwarder and returns the connection, a reader and
// the response head (status line through the blank line).
func (r *fwdRig) send(t *testing.T, raw string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", r.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, raw); err != nil {
		t.Fatalf("write request: %v", err)
	}
	br := bufio.NewReader(c)
	return c, br, readHead(t, br)
}

func readHead(t *testing.T, br *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read response head (%q so far): %v", sb.String(), err)
		}
		sb.WriteString(l)
		if l == "\r\n" {
			return sb.String()
		}
	}
}

func statusOf(head string) int {
	f := strings.Fields(head)
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}

func connectReq(target, extra string) string {
	return "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n" + extra + "\r\n"
}

func TestForwarderInjectsSessionToken(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	// The client sends its own Proxy-Authorization (the credential) plus other
	// headers; none of them may reach the worker.
	req := connectReq("api.example.com:443", goodAuth()+"X-Client: leak-me\r\nUser-Agent: curl\r\n")
	_, _, head := r.send(t, req)
	if statusOf(head) != 200 {
		t.Fatalf("status %d, head %q", statusOf(head), head)
	}
	heads := r.worker.Heads()
	if len(heads) != 1 {
		t.Fatalf("worker saw %d CONNECTs, want 1", len(heads))
	}
	want := "CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n" +
		"Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+fwdToken)) + "\r\n\r\n"
	if heads[0] != want {
		t.Fatalf("worker received:\n%q\nwant:\n%q", heads[0], want)
	}
}

func TestForwarderInjectsTokenOverClientOwn(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	// A client-supplied token (a second Proxy-Authorization) makes the request
	// ambiguous and is refused before any dial.
	_, _, head := r.send(t, connectReq("a.example.com:443", goodAuth()+basicHeader("session", "client-own-token")))
	if statusOf(head) != 407 {
		t.Fatalf("two Proxy-Authorization lines: status %d, want 407", statusOf(head))
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderMethodNotAllowed(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	for _, m := range []string{"GET http://a.example.com/ HTTP/1.1", "POST / HTTP/1.1", "HEAD / HTTP/1.0"} {
		_, _, head := r.send(t, m+"\r\nHost: a\r\n"+goodAuth()+"\r\n")
		if statusOf(head) != 405 || !strings.Contains(head, "Allow: CONNECT") {
			t.Errorf("%q: head %q, want 405 with Allow: CONNECT", m, head)
		}
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderHeaderBlockTooLarge(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	var pad strings.Builder
	line := "X-Pad: " + strings.Repeat("a", 1000) + "\r\n"
	for pad.Len() < 70<<10 {
		pad.WriteString(line)
	}
	_, _, head := r.send(t, connectReq("a.example.com:443", goodAuth()+pad.String()))
	if statusOf(head) != 431 {
		t.Fatalf("70 KiB header block: status %d, want 431", statusOf(head))
	}
	// One enormous header line trips the same limit.
	_, _, head = r.send(t, connectReq("a.example.com:443", goodAuth()+"X-Big: "+strings.Repeat("b", 70<<10)+"\r\n"))
	if statusOf(head) != 431 {
		t.Fatalf("one 70 KiB header: status %d, want 431", statusOf(head))
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderRequestLineTooLong(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	long := strings.Repeat("h", 9<<10) + ".example.com:443"
	_, _, head := r.send(t, "CONNECT "+long+" HTTP/1.1\r\nHost: x\r\n"+goodAuth()+"\r\n")
	if statusOf(head) != 414 {
		t.Fatalf("9 KiB request line: status %d, want 414", statusOf(head))
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderMalformedRequest(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	for _, line := range []string{
		"CONNECT\r\n", "CONNECT a.example.com:443\r\n", "CONNECT a.example.com HTTP/1.1\r\n",
		"CONNECT :443 HTTP/1.1\r\n", "CONNECT a.example.com:99999 HTTP/1.1\r\n", "CONNECT a:443 SPDY/3\r\n",
	} {
		_, _, head := r.send(t, line+goodAuth()+"\r\n")
		if statusOf(head) != 400 {
			t.Errorf("%q: status %d, want 400", line, statusOf(head))
		}
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderClientCredential(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	cases := map[string]string{
		"missing":          "",
		"wrong secret":     basicHeader("wx", "nope"),
		"wrong user":       basicHeader("session", fwdCred),
		"prefix of secret": basicHeader("wx", fwdCred[:5]),
		"longer secret":    basicHeader("wx", fwdCred+"x"),
		"bearer scheme":    "Proxy-Authorization: Bearer " + fwdCred + "\r\n",
		"bad base64":       "Proxy-Authorization: Basic !!!\r\n",
		"duplicate":        goodAuth() + goodAuth(),
	}
	for name, hdr := range cases {
		_, _, head := r.send(t, connectReq("a.example.com:443", hdr))
		if statusOf(head) != 407 || !strings.Contains(head, "Proxy-Authenticate: Basic") {
			t.Errorf("%s: head %q, want 407 with Proxy-Authenticate: Basic", name, head)
		}
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
	// Header name and scheme are case-insensitive.
	lower := "proxy-authorization: basic " + base64.StdEncoding.EncodeToString([]byte("wx:"+fwdCred)) + "\r\n"
	if _, _, head := r.send(t, connectReq("a.example.com:443", lower)); statusOf(head) != 200 {
		t.Fatalf("lower-case header: head %q, want 200", head)
	}
}

func TestForwarderDialsOnlyWorker(t *testing.T) {
	// A listener standing for the CONNECT target: it must never be dialled.
	decoy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = decoy.Close() })
	var decoyConns atomic.Int64
	go func() {
		for {
			c, err := decoy.Accept()
			if err != nil {
				return
			}
			decoyConns.Add(1)
			_ = c.Close()
		}
	}()
	r := startForwarder(t, ok200, nil)
	target := decoy.Addr().String()
	for range 3 {
		c, _, head := r.send(t, connectReq(target, goodAuth()))
		if statusOf(head) != 200 {
			t.Fatalf("status %d", statusOf(head))
		}
		_ = c.Close()
	}
	if n := r.worker.dials.Load(); n != 3 {
		t.Fatalf("worker dials = %d, want 3", n)
	}
	for _, h := range r.worker.Heads() {
		if !strings.HasPrefix(h, "CONNECT "+target+" HTTP/1.1\r\n") {
			t.Fatalf("worker head %q does not carry the target", h)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := decoyConns.Load(); n != 0 {
		t.Fatalf("the CONNECT target was dialled %d times, want 0", n)
	}
}

func TestForwarderPreambleTimeout(t *testing.T) {
	r := startForwarderWith(t, ok200, nil, func(f *identityclient.Forwarder) { f.SetPreambleTimeout(150 * time.Millisecond) })
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	// A slow client that never finishes the preamble is dropped.
	_, _ = io.WriteString(c, "CONNECT a.example.com:443 HTTP/1.1\r\nHost: a\r\n")
	start := time.Now()
	if _, err := io.ReadAll(c); err != nil {
		t.Fatalf("read: %v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("connection held %s past a 150ms preamble budget", d)
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials, want 0", n)
	}
}

func TestForwarderRelayNon200Verbatim(t *testing.T) {
	for _, reply := range []string{
		"HTTP/1.1 403 Forbidden\r\n\r\n",
		"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\nContent-Length: 4\r\n\r\nnope",
	} {
		r := startForwarder(t, reply, nil)
		c, br, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
		wantHead := reply
		if i := strings.Index(reply, "\r\n\r\n"); i >= 0 {
			wantHead = reply[:i+4]
		}
		if head != wantHead {
			t.Errorf("relayed head %q, want %q", head, wantHead)
		}
		rest, _ := io.ReadAll(br)
		if string(rest) != reply[len(wantHead):] {
			t.Errorf("relayed body %q, want %q", rest, reply[len(wantHead):])
		}
		_ = c.Close()
	}
}

func TestForwarderRelaySplice(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	c, br, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
	if head != ok200 {
		t.Fatalf("head %q, want the worker's 200 verbatim", head)
	}
	// Client to worker and back (the fake worker echoes).
	if _, err := io.WriteString(c, "ping-1\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := br.ReadString('\n'); got != "ping-1\n" {
		t.Fatalf("echo %q", got)
	}
	// Half close: the client stops sending, the worker's remaining bytes still
	// arrive, and the tunnel then closes.
	if _, err := io.WriteString(c, "last\n"); err != nil {
		t.Fatal(err)
	}
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(br)
	if err != nil || string(rest) != "last\n" {
		t.Fatalf("after half-close read %q, %v; want %q", rest, err, "last\n")
	}
}

func TestForwarderRelayWorkerClosesTunnel(t *testing.T) {
	// The worker side ends first: the client must see EOF, not hang.
	r := startForwarder(t, "HTTP/1.1 200 Connection Established\r\n\r\nhello", nil)
	c, br, _ := r.send(t, connectReq("a.example.com:443", goodAuth()))
	got, _ := br.ReadString('o')
	if got != "hello" {
		t.Fatalf("got %q, want the bytes the worker sent after its 200", got)
	}
	_ = c.Close()
}

func TestForwarderRefresh(t *testing.T) {
	rg := newRig(t)
	rg.login(t)
	tokenFn := func(ctx context.Context) (string, error) {
		res, err := rg.cl.Token(ctx)
		return res.IDToken, err
	}
	r := startForwarder(t, ok200, tokenFn)

	c1, br1, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
	if statusOf(head) != 200 {
		t.Fatalf("first CONNECT: %q", head)
	}
	// Within the first 2/3 of the lifetime the cached token is reused.
	_, _, _ = r.send(t, connectReq("a.example.com:443", goodAuth()))
	if n := rg.idp.refreshCalls.Load(); n != 0 {
		t.Fatalf("%d refreshes inside the first 2/3, want 0", n)
	}

	rg.clock.Advance(tokenTTL*2/3 + time.Second)
	_, _, head = r.send(t, connectReq("a.example.com:443", goodAuth()))
	if statusOf(head) != 200 {
		t.Fatalf("CONNECT after 2/3: %q", head)
	}
	if n := rg.idp.refreshCalls.Load(); n != 1 {
		t.Fatalf("%d refreshes, want 1", n)
	}

	heads := r.worker.Heads()
	if len(heads) != 3 {
		t.Fatalf("worker saw %d CONNECTs, want 3", len(heads))
	}
	tokOf := func(h string) string {
		_, after, _ := strings.Cut(h, "Proxy-Authorization: Basic ")
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(after))
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		return strings.TrimPrefix(string(raw), "session:")
	}
	old, same, fresh := tokOf(heads[0]), tokOf(heads[1]), tokOf(heads[2])
	if old != same {
		t.Errorf("second CONNECT inside the window changed the token")
	}
	if fresh == old {
		t.Fatalf("the CONNECT after 2/3 of the lifetime carried the old token")
	}
	if cl, _ := rg.cl.Token(context.Background()); cl.IDToken != fresh {
		t.Errorf("the refreshed token is not the one the client now serves")
	}

	// The tunnel opened before the refresh keeps working.
	if _, err := io.WriteString(c1, "still-alive\n"); err != nil {
		t.Fatal(err)
	}
	if got, _ := br1.ReadString('\n'); got != "still-alive\n" {
		t.Fatalf("old tunnel echo %q", got)
	}
}

func TestForwarderNoToken(t *testing.T) {
	var mode atomic.Value
	mode.Store("login")
	tokenFn := func(context.Context) (string, error) {
		switch mode.Load().(string) {
		case "login":
			return "", fmt.Errorf("wrapped: %w", identityclient.ErrLoginRequired)
		case "down":
			return "", identityclient.ErrIssuerUnreachable
		case "other":
			return "", errors.New("disk exploded at /secret/path")
		case "empty":
			return "", nil
		}
		return fwdToken, nil
	}
	r := startForwarder(t, ok200, tokenFn)
	for _, tc := range []struct{ mode, class string }{
		{"login", "login_required"}, {"down", "issuer_unreachable"},
		{"other", "token_unavailable"}, {"empty", "token_unavailable"},
	} {
		mode.Store(tc.mode)
		c, br, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
		if statusOf(head) != 503 {
			t.Fatalf("%s: head %q, want 503", tc.mode, head)
		}
		body, _ := io.ReadAll(io.LimitReader(br, 1024))
		if !strings.Contains(string(body), tc.class) {
			t.Errorf("%s: body %q does not name %q", tc.mode, body, tc.class)
		}
		if strings.Contains(string(body), "disk") || strings.Contains(string(body), "wrapped") {
			t.Errorf("%s: body %q leaks error text", tc.mode, body)
		}
		_ = c.Close()
	}
	if n := r.worker.dials.Load(); n != 0 {
		t.Fatalf("%d dials with no valid token, want 0", n)
	}
	// A failure for one CONNECT does not poison the next.
	mode.Store("good")
	if _, _, head := r.send(t, connectReq("a.example.com:443", goodAuth())); statusOf(head) != 200 {
		t.Fatalf("CONNECT after recovery: %q", head)
	}
	if n := r.worker.dials.Load(); n != 1 {
		t.Fatalf("%d dials, want 1", n)
	}
}

func TestForwarderWorkerUnreachable(t *testing.T) {
	r := startForwarder(t, ok200, nil)
	_ = r.worker.ln.Close()
	_, _, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
	if statusOf(head) != 502 {
		t.Fatalf("head %q, want 502", head)
	}
}

func TestForwarderBadWorkerReply(t *testing.T) {
	r := startForwarder(t, "garbage\r\n\r\n", nil)
	_, _, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
	if statusOf(head) != 502 {
		t.Fatalf("head %q, want 502", head)
	}
}

func TestForwarderNoSecretsInLogs(t *testing.T) {
	failing := atomic.Bool{}
	tokenFn := func(context.Context) (string, error) {
		if failing.Load() {
			return "", errors.New("upstream said token=" + fwdToken + " cred=" + fwdCred)
		}
		return fwdToken, nil
	}
	r := startForwarder(t, ok200, tokenFn)
	var seen strings.Builder
	collect := func(c net.Conn, br *bufio.Reader, head string) {
		seen.WriteString(head)
		_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		rest, _ := io.ReadAll(br)
		seen.Write(rest)
		_ = c.Close()
	}
	collect(r.send(t, connectReq("a.example.com:443", goodAuth())))
	collect(r.send(t, connectReq("a.example.com:443", basicHeader("wx", "wrong-guess-SECRET"))))
	failing.Store(true)
	collect(r.send(t, connectReq("a.example.com:443", goodAuth())))
	collect(r.send(t, "GET / HTTP/1.1\r\n"+goodAuth()+"\r\n"))
	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	logs := r.logText()
	if !strings.Contains(logs, identityclient.Fingerprint(fwdToken)) {
		t.Errorf("logs lack the token fingerprint:\n%s", logs)
	}
	for _, secret := range []string{fwdToken, fwdCred, "wrong-guess-SECRET",
		base64.StdEncoding.EncodeToString([]byte("session:" + fwdToken)),
		base64.StdEncoding.EncodeToString([]byte("wx:" + fwdCred))} {
		if strings.Contains(logs, secret) {
			t.Errorf("a secret appears in the logs: %q", secret)
		}
		if strings.Contains(seen.String(), secret) {
			t.Errorf("a secret appears in what the client saw: %q", secret)
		}
	}
	// Serve configuration errors carry no secret either.
	bad := &identityclient.Forwarder{WorkerAddr: "w:1", Token: func(context.Context) (string, error) { return fwdToken, nil }}
	err := bad.Serve(context.Background(), nil)
	if err == nil || strings.Contains(err.Error(), fwdToken) {
		t.Errorf("Serve without a credential: %v", err)
	}
}

func TestForwarderServeLifecycle(t *testing.T) {
	ok := func(context.Context) (string, error) { return fwdToken, nil }
	for name, f := range map[string]*identityclient.Forwarder{
		"no worker":     {Token: ok, ClientCredential: fwdCred},
		"no token":      {WorkerAddr: "w:1", ClientCredential: fwdCred},
		"no credential": {WorkerAddr: "w:1", Token: ok},
	} {
		if err := f.Serve(context.Background(), nil); err == nil {
			t.Errorf("%s: Serve succeeded", name)
		}
	}

	// A closed listener ends Serve with nil.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &identityclient.Forwarder{WorkerAddr: "127.0.0.1:1", Token: ok, ClientCredential: fwdCred}
	done := make(chan error, 1)
	go func() { done <- f.Serve(context.Background(), ln) }()
	_ = ln.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after listener close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after the listener closed")
	}

	// Cancelling ctx closes open tunnels and returns.
	r := startForwarder(t, ok200, nil)
	c, br, head := r.send(t, connectReq("a.example.com:443", goodAuth()))
	if statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatalf("Serve after cancel: %v", err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Fatal("the tunnel stayed open after Serve returned")
	}
}

// TestForwarderLimitsMatchWorker pins the forwarder's limits to the documented
// 8 KiB, 64 KiB and 10 s and to the constants in the worker's source.
func TestForwarderLimitsMatchWorker(t *testing.T) {
	if identityclient.TestMaxConnectLineBytes != 8192 {
		t.Errorf("request line cap = %d, want 8192", identityclient.TestMaxConnectLineBytes)
	}
	if identityclient.TestMaxConnectHeaderBytes != 65536 {
		t.Errorf("header block cap = %d, want 65536", identityclient.TestMaxConnectHeaderBytes)
	}
	if identityclient.TestConnectPreamble != 10*time.Second {
		t.Errorf("preamble deadline = %s, want 10s", identityclient.TestConnectPreamble)
	}
	if identityclient.TestWorkerDialTimeout != 10*time.Second {
		t.Errorf("dial timeout = %s, want 10s", identityclient.TestWorkerDialTimeout)
	}

	src, err := os.ReadFile("../proxy/serve.go")
	if err != nil {
		t.Fatalf("read the worker source: %v", err)
	}
	num := func(name string) int {
		m := regexp.MustCompile(name + `\s*=\s*(\d+) << 10`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("worker constant %s not found in internal/proxy/serve.go", name)
		}
		n, _ := strconv.Atoi(string(m[1]))
		return n << 10
	}
	if got := num("maxConnectLineBytes"); got != identityclient.TestMaxConnectLineBytes {
		t.Errorf("worker line cap %d != forwarder %d", got, identityclient.TestMaxConnectLineBytes)
	}
	if got := num("maxConnectHeaderBytes"); got != identityclient.TestMaxConnectHeaderBytes {
		t.Errorf("worker header cap %d != forwarder %d", got, identityclient.TestMaxConnectHeaderBytes)
	}
	m := regexp.MustCompile(`connectPreambleTimeout\s*=\s*(\d+) \* time\.Second`).FindSubmatch(src)
	if m == nil {
		t.Fatal("worker constant connectPreambleTimeout not found")
	}
	if secs, _ := strconv.Atoi(string(m[1])); time.Duration(secs)*time.Second != identityclient.TestConnectPreamble {
		t.Errorf("worker preamble %ss != forwarder %s", m[1], identityclient.TestConnectPreamble)
	}
}
