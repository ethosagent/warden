package proxy

import (
	"bufio"
	"bytes"
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
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/test/fakes"
)

// The invariant suite's fixtures. invCanary is the REAL secret the provider
// holds; the agent only ever holds invPlaceholder. Anything that makes invCanary
// visible outside the upstream request is a leak.
const (
	invCanary      = "WARDEN-CANARY-7f3a91c0d2b84e56a1f0"
	invPlaceholder = "WARDEN_PH_CANARY_KEY"
	invHost        = "backend.test"
	invJudgedHost  = "judged.test"
)

// invCA generates the CA once (RSA keygen dominates the suite's runtime
// otherwise) and writes it under the caller's t.TempDir(), which the testing
// package removes.
var (
	invCAOnce                 sync.Once
	invCACertPEM, invCAKeyPEM []byte
)

func invCA(t testing.TB) (certPath, keyPath string, certPEM []byte) {
	t.Helper()
	invCAOnce.Do(func() { invCACertPEM, invCAKeyPEM, _, _ = generateTestCA(t) })
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")
	if err := os.WriteFile(certPath, invCACertPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, invCAKeyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, invCACertPEM
}

// lockedBuf is the captured log sink.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// metricSink records every label the proxy hands to the metrics recorder, so the
// suite can prove no label carries the canary.
type metricSink struct {
	mu   sync.Mutex
	recs []string
}

func (m *metricSink) add(format string, a ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recs = append(m.recs, fmt.Sprintf(format, a...))
}

func (m *metricSink) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.recs...)
}

func (m *metricSink) RecordRequest(decision, protocol string) {
	m.add("request decision=%s protocol=%s", decision, protocol)
}
func (m *metricSink) RecordBlocked(reason string)   { m.add("blocked reason=%s", reason) }
func (m *metricSink) RecordSecretSwap(ref string)   { m.add("secret_swap ref=%s", ref) }
func (m *metricSink) RecordScanFinding(kind string) { m.add("scan_finding kind=%s", kind) }
func (m *metricSink) RecordJudge(outcome string)    { m.add("judge outcome=%s", outcome) }
func (m *metricSink) ObserveAddedLatency(stage string, _ time.Duration) {
	m.add("latency stage=%s", stage)
}

// seenReq is one request the upstream received.
type seenReq struct {
	path   string
	header http.Header
	body   string
}

// invBackend is the upstream: an HTTPS server (HTTP/1.1 and h2) whose behavior
// is picked by request path, plus a raw TLS echo listener and a plain TCP one.
type invBackend struct {
	srv  *httptest.Server
	done chan struct{}

	mu   sync.Mutex
	seen []seenReq
	// wsData is every byte the upstream read after a WebSocket upgrade.
	wsData bytes.Buffer
}

func (b *invBackend) wsBytes() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.wsData.String()
}

type wsSink struct{ b *invBackend }

func (w wsSink) Write(p []byte) (int, error) {
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	return w.b.wsData.Write(p)
}

func (b *invBackend) record(r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	b.mu.Lock()
	b.seen = append(b.seen, seenReq{path: r.URL.RequestURI(), header: r.Header.Clone(), body: string(body)})
	b.mu.Unlock()
}

func (b *invBackend) requests() []seenReq {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]seenReq(nil), b.seen...)
}

// upstreamSawCanary reports whether any upstream request carried the real secret
// in a header, the URL or the body — i.e. whether the swap stage ran.
func (b *invBackend) upstreamSawCanary() bool {
	for _, r := range b.requests() {
		if strings.Contains(r.path, invCanary) || strings.Contains(r.body, invCanary) {
			return true
		}
		for _, vs := range r.header {
			for _, v := range vs {
				if strings.Contains(v, invCanary) || basicHasCanary(v) {
					return true
				}
			}
		}
	}
	return false
}

// basicHasCanary decodes an "Authorization: Basic" value: the swap hides the
// real secret inside base64 there.
func basicHasCanary(v string) bool {
	_, payload, ok := strings.Cut(v, " ")
	if !ok {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	return err == nil && strings.Contains(string(raw), invCanary)
}

// upstreamHeaders returns the named header from the most recent request, and
// whether any request has arrived.
func (b *invBackend) upstreamHeaders() (http.Header, bool) {
	rs := b.requests()
	if len(rs) == 0 {
		return nil, false
	}
	return rs[len(rs)-1].header, true
}

// invAfterBlock is content the peer sends after the offending one. The SSE relay
// and the WebSocket pump forward a message before they can judge it, then cut the
// stream, so the offending message itself is delivered and THIS trailing one is
// what proves the stop happened.
const (
	invAfterBlock  = "STOP-MARKER-after-deny"
	invSSEPoisoned = "data: " + mcpPoisonedList + "\n\n" +
		"data: {\"jsonrpc\":\"2.0\",\"id\":\"2\",\"result\":{\"note\":\"" + invAfterBlock + "\"}}\n\n"
)

func (b *invBackend) handle(w http.ResponseWriter, r *http.Request) {
	b.record(r)
	switch r.URL.Path {
	case "/echo":
		// A hostile or careless upstream that reflects what it received, request
		// headers included, in the body and in a response header.
		var buf bytes.Buffer
		_ = r.Header.Write(&buf)
		w.Header().Set("X-Echo-Authorization", r.Header.Get("Authorization"))
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			w.Header().Set("Content-Type", "application/grpc")
		}
		_, _ = w.Write(buf.Bytes())
	case "/abort":
		panic(http.ErrAbortHandler)
	case "/hang":
		select {
		case <-b.done:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	case "/sse":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: "+`{"jsonrpc":"2.0","id":"1","result":{"ok":true}}`+"\n\n")
	case "/sse-poisoned":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, invSSEPoisoned)
	case "/sse-stall":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{}}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-b.done:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	case "/sse-abort":
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		panic(http.ErrAbortHandler)
	case "/sse-echo":
		var buf bytes.Buffer
		_ = r.Header.Write(&buf)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"echo\":%q}}\n\n", buf.String())
	case "/mcp-echo":
		var buf bytes.Buffer
		_ = r.Header.Write(&buf)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"result\":{\"echo\":%q}}", buf.String())
	case "/mcp":
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"1","result":{"content":[{"type":"text","text":"ok"}]}}`)
	case "/ws":
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_, _ = io.Copy(wsSink{b}, brw)
	default:
		_, _ = io.WriteString(w, "ok")
	}
}

func newInvBackend(t *testing.T) *invBackend {
	t.Helper()
	b := &invBackend{done: make(chan struct{})}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(b.handle))
	b.srv.EnableHTTP2 = true
	b.srv.Config.ErrorLog = nil
	b.srv.StartTLS()
	// Order matters: release hanging handlers before Close waits on them.
	t.Cleanup(func() { b.srv.Close() })
	t.Cleanup(func() { close(b.done) })
	return b
}

// invEnv is one row's world: a proxy, its upstream, and every sink we inspect.
type invEnv struct {
	t       *testing.T
	p       *Proxy
	store   *syncStore
	logs    *lockedBuf
	metrics *metricSink
	backend *invBackend
	caPEM   []byte

	hitMu sync.Mutex
	hit   map[Path]bool

	// rawTLSAddr/rawTCPAddr redirect the non-HTTP upstream dials (raw TLS, tunnel).
	rawTLSAddr string
	rawTCPAddr string
	useRawTLS  bool
}

// invOpts are the per-row proxy knobs.
type invOpts struct {
	judge    Judge
	mcp      bool
	allow    []config.AllowlistEntry
	denylist []config.DenylistEntry
	dlp      *DLPScanner
	// secrets overrides the provider; nil = the canary provider.
	secrets *fakes.FakeSecretProvider
	// noPlaceholders runs the proxy with no swap configured.
	noPlaceholders bool
}

func newInvEnv(t *testing.T, o invOpts) *invEnv {
	t.Helper()
	certPath, keyPath, caPEM := invCA(t)
	e := &invEnv{
		t:       t,
		store:   &syncStore{},
		logs:    &lockedBuf{},
		metrics: &metricSink{},
		backend: newInvBackend(t),
		caPEM:   caPEM,
		hit:     map[Path]bool{},
	}
	allow := o.allow
	if allow == nil {
		allow = []config.AllowlistEntry{{Domain: invHost, Port: 443}}
	}
	sec := o.secrets
	if sec == nil {
		sec = &fakes.FakeSecretProvider{Values: map[string]string{invPlaceholder: invCanary}}
	}
	cfg := Config{
		ListenAddr: "127.0.0.1:0",
		Policy:     policy.NewEvaluator(config.Policy{Allowlist: allow, Denylist: o.denylist}),
		Secrets:    sec,
		Analytics:  e.store,
		CACertPath: certPath,
		CAKeyPath:  keyPath,
		AgentID:    "default",
		Metrics:    e.metrics,
		Logger:     slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Judge:      o.judge,
		DLP:        o.dlp,
	}
	if !o.noPlaceholders {
		cfg.PlaceholderNames = []string{invPlaceholder}
	}
	if o.mcp {
		mc := enforceMCPConfig()
		cfg.MCP = gateway.New(mc, scan.NewScanner(scan.WithPhonePII(mc.Scan.PII.Phone)), nil)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.p = p
	registered := map[Path]bool{}
	for _, rp := range ProtocolPaths() {
		registered[rp] = true
	}
	p.pathHook = func(path Path) {
		if !registered[path] {
			t.Errorf("dispatch reached unregistered path %q: add it to protocolPaths and give it invariant rows", path)
		}
		e.hitMu.Lock()
		e.hit[path] = true
		e.hitMu.Unlock()
	}
	p.dialTLS = func(_, addr string, c *tls.Config) (*tls.Conn, error) {
		target := e.backend.srv.Listener.Addr().String()
		if e.rawTLSAddr != "" && len(c.NextProtos) == 0 && e.useRawTLS {
			target = e.rawTLSAddr
		}
		return tls.Dial("tcp", target, &tls.Config{InsecureSkipVerify: true, NextProtos: c.NextProtos})
	}
	p.dialFunc = func(_, _ string) (net.Conn, error) {
		if e.rawTCPAddr == "" {
			return nil, fmt.Errorf("invariants: no tcp upstream")
		}
		return net.Dial("tcp", e.rawTCPAddr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = p.Serve(ctx) }()
	for i := 0; i < 200 && p.Addr() == nil; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy did not start")
	}
	return e
}

// hasDenyEvent reports whether any deny event was recorded.
func (e *invEnv) hasDenyEvent() bool {
	for _, ev := range e.store.snapshot() {
		if ev.Decision == "deny" {
			return true
		}
	}
	return false
}

func (e *invEnv) reached(path Path) bool {
	e.hitMu.Lock()
	defer e.hitMu.Unlock()
	return e.hit[path]
}

// startRawTCP starts a plain TCP upstream that answers every connection with
// "raw:" + what it read, or stays silent when silent is set.
func (e *invEnv) startRawTCP(silent bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = ln.Close() })
	e.rawTCPAddr = ln.Addr().String()
	go serveRaw(ln, silent, nil)
}

// startRawTLS starts a TLS upstream with the same behavior, for the raw-TLS path.
func (e *invEnv) startRawTLS(silent bool) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { _ = ln.Close() })
	e.rawTLSAddr = ln.Addr().String()
	e.useRawTLS = true
	tlsCfg := &tls.Config{Certificates: e.backend.srv.TLS.Certificates}
	go serveRaw(ln, silent, tlsCfg)
}

func serveRaw(ln net.Listener, silent bool, tlsCfg *tls.Config) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			if tlsCfg != nil {
				tc := tls.Server(c, tlsCfg)
				if tc.Handshake() != nil {
					return
				}
				c = tc
			}
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)
			if silent {
				time.Sleep(2 * time.Second)
				return
			}
			_, _ = c.Write(append([]byte("raw:"), buf[:n]...))
		}()
	}
}

// connectRaw opens a CONNECT tunnel to host:port and returns the connection and
// the status line; the caller owns the conn.
func (e *invEnv) connectRaw(target string) (net.Conn, *bufio.Reader, string, error) {
	conn, err := net.DialTimeout("tcp", e.p.Addr().String(), 2*time.Second)
	if err != nil {
		return nil, nil, "", err
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(conn)
	status, err := br.ReadString('\n')
	if err != nil {
		return conn, br, "", err
	}
	if strings.Contains(status, "200") {
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" || l == "\n" {
				break
			}
		}
	}
	return conn, br, status, nil
}

// connectTLS opens a CONNECT tunnel to host:443 and completes the MITM handshake.
func (e *invEnv) connectTLS(host string, nextProtos ...string) (*tls.Conn, error) {
	conn, br, status, err := e.connectRaw(host + ":443")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(status, "200") {
		return nil, fmt.Errorf("CONNECT refused: %q", strings.TrimSpace(status))
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(e.caPEM)
	tc := tls.Client(&bufferedTLSConn{Reader: br, Conn: conn}, &tls.Config{
		ServerName: host, RootCAs: pool, NextProtos: nextProtos,
	})
	_ = tc.SetDeadline(time.Now().Add(3 * time.Second))
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}

// invReq describes one agent request.
type invReq struct {
	host    string
	method  string
	path    string
	header  http.Header
	body    string
	timeout time.Duration
}

func (r invReq) build() *http.Request {
	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	host := r.host
	if host == "" {
		host = invHost
	}
	req, err := http.NewRequest(method, "https://"+host+r.path, strings.NewReader(r.body))
	if err != nil {
		panic(err)
	}
	if r.body == "" {
		req.Body = http.NoBody
		req.ContentLength = 0
	}
	for k, vs := range r.header {
		req.Header[k] = append([]string(nil), vs...)
	}
	return req
}

// doHTTP1 sends r over a fresh MITM connection and returns EVERYTHING the agent
// received, as text (status line, headers, body), plus the status code (0 if no
// response arrived).
func (e *invEnv) doHTTP1(r invReq) (view string, status int, err error) {
	tc, err := e.connectTLS(orDefault(r.host, invHost))
	if err != nil {
		return err.Error(), 0, err
	}
	return e.doHTTP1On(tc, r)
}

func (e *invEnv) doHTTP1On(tc *tls.Conn, r invReq) (string, int, error) {
	req := r.build()
	if err := req.Write(tc); err != nil {
		return "", 0, err
	}
	to := r.timeout
	if to == 0 {
		to = 3 * time.Second
	}
	_ = tc.SetReadDeadline(time.Now().Add(to))
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Build the view by hand so a stalled or aborted body still yields what the
	// agent did receive before the read failed.
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", resp.Status)
	_ = resp.Header.Write(&sb)
	body, _ := io.ReadAll(resp.Body)
	sb.Write(body)
	return sb.String(), resp.StatusCode, nil
}

// doH2 sends r over HTTP/2 through the MITM and returns the agent's view
// (headers, body, trailers) and status.
func (e *invEnv) doH2(r invReq) (view string, status int, err error) {
	// net/http speaks h2 on a connection that negotiated it, so no x/net client is needed.
	tr := &http.Transport{
		ForceAttemptHTTP2: true,
		DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return e.connectTLS(orDefault(r.host, invHost), "h2")
		},
	}
	defer tr.CloseIdleConnections()
	req := r.build()
	to := r.timeout
	if to == 0 {
		to = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), to)
	defer cancel()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return err.Error(), 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, rerr := io.ReadAll(resp.Body)
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s\n", resp.Status)
	_ = resp.Header.Write(&sb)
	sb.Write(body)
	_ = resp.Trailer.Write(&sb)
	return sb.String(), resp.StatusCode, rerr
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// settle waits until the sinks stop growing, so asynchronously written events
// and log lines are in before we inspect them. It never fails: a late write can
// only make an assertion miss a leak, never invent one.
func (e *invEnv) settle() {
	size := func() int {
		return len(e.store.snapshot()) + len(e.logs.String()) + len(e.metrics.snapshot())
	}
	last, stable := -1, 0
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		cur := size()
		if cur == last {
			stable++
		} else {
			last, stable = cur, 0
		}
		if stable >= 6 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// leaks scans every sink the agent or an operator could read and names the
// places invCanary shows up. agentView is whatever the agent received.
func (e *invEnv) leaks(agentView string) []string {
	var out []string
	add := func(where, text string) {
		i := strings.Index(text, invCanary)
		if i < 0 {
			return
		}
		lo, hi := max(0, i-30), min(len(text), i+len(invCanary)+30)
		out = append(out, fmt.Sprintf("canary in %s: ...%s...", where,
			strings.ReplaceAll(text[lo:hi], invCanary, "<CANARY>")))
	}
	add("agent response", agentView)
	for _, line := range strings.Split(e.logs.String(), "\n") {
		add("logs", line)
	}
	for i, ev := range e.store.snapshot() {
		add(fmt.Sprintf("analytics event #%d", i), fmt.Sprintf("%#v", ev))
	}
	for _, m := range e.metrics.snapshot() {
		add("metric labels", m)
	}
	return out
}
