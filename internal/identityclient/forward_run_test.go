package identityclient_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/identityclient"
)

func TestHealthHandler(t *testing.T) {
	now := t0
	exp := t0.Add(10 * time.Minute)
	for name, tc := range map[string]struct {
		st     identityclient.State
		code   int
		state  string
		hasExp bool
	}{
		"valid":             {identityclient.State{Reason: identityclient.ReasonValid, Expiry: exp}, 200, "valid", true},
		"expiring held":     {identityclient.State{Reason: identityclient.ReasonExpiring, Expiry: exp, LastError: "cp_unreachable"}, 200, "expiring", true},
		"expiring no token": {identityclient.State{Reason: identityclient.ReasonExpiring}, 503, "expiring", false},
		"expiring expired":  {identityclient.State{Reason: identityclient.ReasonExpiring, Expiry: t0.Add(-time.Second)}, 503, "expiring", true},
		"login required":    {identityclient.State{Reason: identityclient.ReasonLoginRequired}, 503, "login_required", false},
		"cp unreachable":    {identityclient.State{Reason: identityclient.ReasonCPUnreachable, LastError: "unavailable"}, 503, "cp_unreachable", false},
		"exchange denied":   {identityclient.State{Reason: identityclient.ReasonExchangeDenied, LastError: "exchange_denied:invalid_client"}, 503, "exchange_denied", false},
	} {
		t.Run(name, func(t *testing.T) {
			h := identityclient.HealthHandler(func() identityclient.State { return tc.st }, func() time.Time { return now })
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
			if rec.Code != tc.code {
				t.Errorf("status %d, want %d", rec.Code, tc.code)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["state"] != tc.state || (body["exp"] != "") != tc.hasExp || len(body) > 2 {
				t.Errorf("body %v, want state %s (exp %v) and nothing else", body, tc.state, tc.hasExp)
			}
			if tc.hasExp && body["exp"] != tc.st.Expiry.UTC().Format(time.RFC3339) {
				t.Errorf("exp = %q", body["exp"])
			}
			if strings.Contains(rec.Body.String(), "invalid_client") {
				t.Error("an error text reached /healthz")
			}
		})
	}
	h := identityclient.HealthHandler(func() identityclient.State { return identityclient.State{} }, func() time.Time { return now })
	for method, want := range map[string]int{http.MethodPost: 405, http.MethodDelete: 405, http.MethodHead: 503} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/healthz", nil))
		if rec.Code != want {
			t.Errorf("%s /healthz = %d, want %d", method, rec.Code, want)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/other", nil))
	if rec.Code != 404 {
		t.Errorf("GET /other = %d, want 404", rec.Code)
	}
}

func TestClientStateReasons(t *testing.T) {
	rg := newRig(t)
	cs := &identityclient.ClientState{Client: rg.cl, Now: rg.clock.Now}
	ctx := context.Background()
	if st := cs.State(); st.Reason != identityclient.ReasonExpiring || !st.Expiry.IsZero() {
		t.Errorf("before any call: %+v, want expiring with no exp", st)
	}
	if _, err := cs.Token(ctx); !errors.Is(err, identityclient.ErrLoginRequired) {
		t.Fatalf("Token with no login = %v", err)
	}
	if st := cs.State(); st.Reason != identityclient.ReasonLoginRequired {
		t.Errorf("no login: %+v", st)
	}
	rg.login(t)
	tok, err := cs.Token(ctx)
	if err != nil || tok == "" {
		t.Fatalf("Token after login: %v", err)
	}
	st := cs.State()
	if st.Reason != identityclient.ReasonValid || st.Expiry.IsZero() {
		t.Errorf("after login: %+v, want valid with an exp", st)
	}
	// Past exp with the issuer down: the cache cannot be refreshed.
	rg.idp.setDown(true)
	rg.clock.Advance(24 * time.Hour)
	if _, err := cs.Token(ctx); err == nil {
		t.Fatal("Token past exp with the issuer down succeeded")
	}
	if st := cs.State(); st.Reason != identityclient.ReasonLoginRequired {
		t.Errorf("issuer down past exp: %+v, want login_required", st)
	}
}

// runRig is RunForwarder over a fake source, with both listeners real and the
// clock fake.
type runRig struct {
	t      *testing.T
	clk    *clocktest.Fake
	state  *stateBox
	addr   string
	health string
	logs   *lockedWriter
	logBuf *bytes.Buffer
	cancel context.CancelFunc
	done   chan struct{}
	err    error
	sw     *scriptedWorker
}

type stateBox struct {
	mu sync.Mutex
	st identityclient.State
}

func (b *stateBox) set(st identityclient.State) { b.mu.Lock(); b.st = st; b.mu.Unlock() }
func (b *stateBox) get() identityclient.State   { b.mu.Lock(); defer b.mu.Unlock(); return b.st }

func startRun(t *testing.T, grace time.Duration) *runRig {
	t.Helper()
	r := &runRig{t: t, clk: clocktest.NewFake(t0), state: &stateBox{}, logBuf: &bytes.Buffer{}, done: make(chan struct{})}
	r.state.set(identityclient.State{Reason: identityclient.ReasonValid, Expiry: t0.Add(15 * time.Minute)})
	r.logs = &lockedWriter{w: r.logBuf}
	r.sw = newScriptedWorker(t, echoWorker)
	log := slog.New(slog.NewTextHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	src := newFakeSource(wtok("warden.tok.RUN", t0.Add(15*time.Minute)))
	fw := &identityclient.Forwarder{WorkerAddr: r.sw.ln.Addr().String(), Source: src, AllowAnonymousClients: true, Log: log}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.addr, r.health = ln.Addr().String(), hl.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	go func() {
		defer close(r.done)
		r.err = identityclient.RunForwarder(ctx, identityclient.ForwardRun{
			Forwarder: fw, Listener: ln, Health: hl, State: r.state.get, Log: log, Clock: r.clk, Grace: grace,
		})
	}()
	t.Cleanup(func() {
		cancel()
		r.clk.Advance(time.Hour)
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("RunForwarder did not return")
		}
	})
	return r
}

func (r *runRig) logText() string {
	r.logs.mu.Lock()
	defer r.logs.mu.Unlock()
	return r.logBuf.String()
}

func (r *runRig) healthz() (int, map[string]string) {
	r.t.Helper()
	resp, err := http.Get("http://" + r.health + "/healthz")
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestRunForwarderHealthAndTransitions(t *testing.T) {
	r := startRun(t, time.Second)
	waitFor(t, "the first state to be logged", func() bool { return strings.Contains(r.logText(), "state=valid") })
	if code, body := r.healthz(); code != 200 || body["state"] != "valid" {
		t.Fatalf("healthz = %d %v", code, body)
	}

	// Many ticks in one state log nothing more; each change logs once.
	step := func() {
		r.clk.Advance(time.Second)
		waitFor(t, "the loop to re-arm", func() bool { return r.clk.PendingTimers() >= 1 })
	}
	for range 5 {
		step()
	}
	r.state.set(identityclient.State{Reason: identityclient.ReasonExchangeDenied, LastError: "exchange_denied:invalid_client"})
	waitFor(t, "the denial to be logged", func() bool { step(); return strings.Contains(r.logText(), "state=exchange_denied") })
	for range 5 {
		step()
	}
	r.state.set(identityclient.State{Reason: identityclient.ReasonLoginRequired})
	waitFor(t, "login_required to be logged", func() bool { step(); return strings.Contains(r.logText(), "login_required") })
	for range 5 {
		step()
	}
	if code, body := r.healthz(); code != 503 || body["state"] != "login_required" {
		t.Errorf("healthz = %d %v", code, body)
	}
	logs := r.logText()
	for _, want := range []string{"state=exchange_denied", "msg=login_required", "state=valid"} {
		if n := strings.Count(logs, want); n != 1 {
			t.Errorf("%q logged %d times, want once:\n%s", want, n, logs)
		}
	}
	if strings.Contains(logs, "warden.tok.RUN") {
		t.Error("a token appears in the logs")
	}
}

func TestRunForwarderGracefulShutdown(t *testing.T) {
	r := startRun(t, 5*time.Second)
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(c)
	if _, err := io.WriteString(c, connectReq("a.example.com:443", "")); err != nil {
		t.Fatal(err)
	}
	if head := readHead(t, br); statusOf(head) != 200 {
		t.Fatalf("head %q", head)
	}
	r.cancel()
	// The listener is closed at once; the open tunnel still works.
	waitFor(t, "the listener to close", func() bool {
		cc, err := net.DialTimeout("tcp", r.addr, 200*time.Millisecond)
		if err != nil {
			return true
		}
		_ = cc.Close()
		return false
	})
	_, _ = io.WriteString(c, "still\n")
	if got, _ := br.ReadString('\n'); got != "still\n" {
		t.Fatalf("the tunnel did not survive the shutdown grace: %q", got)
	}
	select {
	case <-r.done:
		t.Fatalf("RunForwarder returned (%v) before the grace ended", r.err)
	case <-time.After(50 * time.Millisecond):
	}
	// Past the grace the rest is closed and Run returns.
	r.clk.Advance(6 * time.Second)
	select {
	case <-r.done:
		if r.err != nil {
			t.Fatalf("RunForwarder: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunForwarder did not return after the grace")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := br.ReadByte(); err == nil {
		t.Error("the tunnel stayed open after the grace")
	}
}

func BenchmarkForwarderConnect(b *testing.B) {
	wl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = wl.Close() }()
	go func() {
		for {
			c, err := wl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					if l == "\r\n" {
						break
					}
				}
				_, _ = io.WriteString(c, ok200)
			}()
		}
	}()
	src := newFakeSource(wtok("warden.tok.BENCH", time.Now().Add(time.Hour)))
	fw := &identityclient.Forwarder{WorkerAddr: wl.Addr().String(), Source: src, AllowAnonymousClients: true}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = fw.Serve(ctx, ln); close(done) }()
	defer func() { cancel(); <-done }()
	req := []byte(connectReq("api.example.com:443", ""))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.Write(req); err != nil {
			b.Fatal(err)
		}
		br := bufio.NewReader(c)
		for {
			l, err := br.ReadString('\n')
			if err != nil {
				b.Fatal(err)
			}
			if l == "\r\n" {
				break
			}
		}
		_ = c.Close()
	}
}
