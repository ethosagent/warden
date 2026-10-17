package harness

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// upstreamBodyLimit bounds how much of a request/response body the recorders
// keep. Bodies in the harness are oracles, not archives — enough to see a
// secret, a placeholder or a payload, never unbounded.
const upstreamBodyLimit = 1 << 20

// RecordedRequest is one request a fake upstream received, exactly as it
// arrived AFTER the worker's pipeline (swaps applied). It is the "what did the
// destination actually see" oracle.
type RecordedRequest struct {
	Method string
	Host   string
	Path   string
	Proto  string
	Header http.Header
	Body   []byte
}

// Upstream is a fake destination (h.Upstream(host)): an HTTPS server capable
// of HTTP/1.1 and HTTP/2 (ALPN), signed by the harness upstream CA, that
// records every request it receives and can be faulted (Delay, Fail,
// EchoHeaders). Flavors (FakeLLM, FakeMCP, FakeGRPC, FakeWS) mount handlers
// onto it; the recorder always runs first.
//
// Upstreams live in the harness registry until cleanup — get one once, then
// call the fault methods as the scenario needs.
type Upstream struct {
	h    *H
	host string
	srv  *httptest.Server
	// remote is non-nil when this Upstream is a VIEW over a fake the target
	// hosts out of process (compose: the fakeupstream recorder): Requests read
	// through the target and the server/fault levers have nothing to drive.
	remote UpstreamReader

	mu    sync.Mutex
	reqs  []RecordedRequest
	delay time.Duration
	fail  int
	echo  bool
	mux   *http.ServeMux
	next  http.Handler
	// parkGap is a test-only hook: wall-time delay injected between the request
	// arriving and the Delay timer being registered, so a test can hold open the
	// window in which an early park would let WaitParked return before the
	// timer exists. Always 0 outside tests.
	parkGap time.Duration
	// parked is how many in-flight requests are currently held on the Delay
	// timer (WaitParked's counter).
	parked int
}

// Upstream returns (creating on first use) the fake upstream for host. The
// production SafeDialer would refuse to route a fake name to loopback; the
// harness's dialer override maps host to this server's address instead. The
// host is NOT allowlisted — pair with Allow(host) for a scenario that needs
// the request to pass policy.
func (h *H) Upstream(host string) *Upstream {
	h.tb.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if u, ok := h.upstreams[host]; ok {
		return u
	}
	// On a target that hosts the fakes out of process (compose) an upstream is
	// a view over that fake's recording, not a server here: the deployment's
	// fake serves the traffic and answers the oracle, this process only reads.
	if h.remoteUpstreams {
		u := &Upstream{h: h, host: host, remote: h.target.(UpstreamReader)}
		h.upstreams[host] = u
		return u
	}
	leaf, err := h.upstreamCA.leaf(host)
	if err != nil {
		h.tb.Fatalf("harness: mint upstream cert for %s: %v", host, err)
	}
	u := &Upstream{h: h, host: host, mux: http.NewServeMux()}
	srv := httptest.NewUnstartedServer(u)
	// EnableHTTP2 + a real cert chain: upstreams negotiate ALPN exactly like
	// production destinations, so the worker's h2 leg is exercised too (its
	// pipeline parity is #388's business, not the harness's).
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		MinVersion:   tls.VersionTLS12,
	}
	// The fake's own error log is noise by construction: teardown (and any
	// faulted or abandoned scenario) closes client legs mid-handshake, and
	// net/http answers every one with "http: TLS handshake error ...: EOF" on
	// stderr. That is the harness working, not a failure — discard it.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	u.srv = srv
	h.upstreams[host] = u
	return u
}

// ServeHTTP records the request, applies faults, then dispatches to a mounted
// flavor handler (or the plain-200 default).
func (u *Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, upstreamBodyLimit+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))

	u.mu.Lock()
	u.reqs = append(u.reqs, RecordedRequest{
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
		Proto:  r.Proto,
		Header: r.Header.Clone(),
		Body:   body,
	})
	delay, fail, echo, parkGap := u.delay, u.fail, u.echo, u.parkGap
	mux, next := u.mux, u.next
	u.mu.Unlock()

	if delay > 0 {
		// Latency is a FAKE-clock fault: the request holds until the scenario
		// calls h.Clock().Advance(delay) — deterministic, never a sleep. The
		// ctx arm keeps a never-advanced delay from wedging cleanup when the
		// client disconnects. Parked counts the held requests so a scenario can
		// synchronize with the park (WaitParked) instead of racing it.
		//
		// ORDER IS THE CONTRACT: the timer is registered with the fake clock
		// BEFORE parked is incremented. Incrementing first let WaitParked(1)
		// return inside the gap before NewTimer, the scenario's Advance fire
		// into an empty timer registry, and the timer then arm ABOVE the
		// advanced instant — the request hung until the next Advance. Arming
		// first means a post-WaitParked Advance is guaranteed to hit an armed
		// timer (parkGap is the test-only hook that pins this).
		if parkGap > 0 {
			time.Sleep(parkGap)
		}
		timer := u.h.fake.NewTimer(delay)
		u.mu.Lock()
		u.parked++
		u.mu.Unlock()
		select {
		case <-timer.C():
			timer.Stop()
		case <-r.Context().Done():
			timer.Stop()
			u.mu.Lock()
			u.parked--
			u.mu.Unlock()
			return
		}
		u.mu.Lock()
		u.parked--
		u.mu.Unlock()
	}
	if fail != 0 {
		http.Error(w, fmt.Sprintf("harness: upstream %s faulted with status %d", u.host, fail), fail)
		return
	}
	if echo {
		u.echoHeaders(w, r)
		return
	}
	if mux != nil {
		if _, pattern := mux.Handler(r); pattern != "" {
			mux.ServeHTTP(w, r)
			return
		}
	}
	if next != nil {
		next.ServeHTTP(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// Requests returns a copy of every request recorded so far, in arrival order.
// On a remote view the records come from the target (compose: the recorder).
func (u *Upstream) Requests() []RecordedRequest {
	if u.remote != nil {
		reqs, err := u.remote.UpstreamRequests(u.host)
		if err != nil {
			u.h.tb.Fatalf("harness: read recorded requests for %s: %v", u.host, err)
		}
		return reqs
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]RecordedRequest, len(u.reqs))
	copy(out, u.reqs)
	return out
}

// inProcessOnly fails the test: the lever drives the in-process fake's server
// or fault machinery, and this upstream is a view over a fake the target hosts
// out of process — pretending would silently do nothing.
func (u *Upstream) inProcessOnly(lever string) {
	u.h.tb.Fatalf("harness: Upstream(%s).%s is in-process-only: this target hosts its fakes out of process, so the scenario cannot drive them", u.host, lever)
}

// Delay makes every subsequent request hang until the scenario advances the
// fake clock by at least d (h.Clock().Advance(d)) — the latency fault, on
// harness time instead of wall time.
func (u *Upstream) Delay(d time.Duration) {
	if u.remote != nil {
		u.inProcessOnly("Delay")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.delay = d
}

// WaitParked blocks until n requests are parked on the Delay timer — i.e. the
// agent's request(s) have REACHED the fault and are holding on the fake clock.
// A scenario that faults latency drives the sequence:
//
//	u.Delay(5 * time.Second)
//	go doRequest()          // or any async traffic
//	u.WaitParked(1)         // the request is now provably stuck on the timer
//	h.Clock().Advance(5 * time.Second)
//
// Without the WaitParked step, an Advance issued before the request arrives is
// silently absorbed (the timer arms after the advance) and the request then
// hangs until the NEXT advance — which is exactly the bug this closes. Requests
// released by the Advance unpark on their own; a client that disconnects
// unparks too, so cleanup never wedges.
func (u *Upstream) WaitParked(n int) {
	u.h.tb.Helper()
	if u.remote != nil {
		u.inProcessOnly("WaitParked")
	}
	u.h.EventuallyWithin(readyDeadline,
		fmt.Sprintf("%d request(s) to park on %s's Delay timer", n, u.host),
		func() bool {
			u.mu.Lock()
			defer u.mu.Unlock()
			return u.parked >= n
		})
}

// Parked reports how many requests are currently held on the Delay timer.
func (u *Upstream) Parked() int {
	if u.remote != nil {
		u.inProcessOnly("Parked")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.parked
}

// Fail makes every subsequent request answer with the given status code.
func (u *Upstream) Fail(status int) {
	if u.remote != nil {
		u.inProcessOnly("Fail")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.fail = status
}

// EchoHeaders makes every subsequent request answer with a rendering of its
// OWN request headers — a malicious or misbehaving reflector. With default
// worker config this returns the REAL swapped secret to the agent (the
// upstream-echo leak, #389); AssertCanaryNeverLeaked must catch it.
func (u *Upstream) EchoHeaders(on bool) {
	if u.remote != nil {
		u.inProcessOnly("EchoHeaders")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.echo = on
}

// SetNext mounts a catch-all response handler (used for custom bodies).
func (u *Upstream) SetNext(next http.Handler) {
	if u.remote != nil {
		u.inProcessOnly("SetNext")
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.next = next
}

// route mounts a flavor handler at pattern (longest-pattern wins; "/" makes
// the flavor the whole server). On a remote view there is nothing to mount —
// the deployment's fake serves its own handlers — so this is a no-op there;
// the flavors call it unconditionally and stay one code path on both targets.
func (u *Upstream) route(pattern string, handler http.Handler) {
	if u.remote != nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.mux.Handle(pattern, handler)
}

// URL is the fake's direct loopback base URL (https://127.0.0.1:port) for
// tests that exercise the fake itself, bypassing the worker. A remote view has
// no loopback URL — the fake lives in the deployment.
func (u *Upstream) URL() string {
	if u.remote != nil {
		u.inProcessOnly("URL")
	}
	return u.srv.URL
}

// addr is the loopback host:port the mapping dialer routes to.
func (u *Upstream) addr() string { return strings.TrimPrefix(u.srv.URL, "https://") }

// close shuts the server down (harness cleanup). CloseClientConnections first:
// a client leg still marked busy (a request that outlived the worker) would
// otherwise hold Server.Close open waiting on it.
func (u *Upstream) close() {
	if u.remote != nil {
		return // nothing here hosts it; the target tears its own fake down
	}
	u.srv.CloseClientConnections()
	u.srv.Close()
}

// echoHeaders reflects the request headers back as the body, keys sorted so a
// scenario's assertions are deterministic.
func (u *Upstream) echoHeaders(w http.ResponseWriter, r *http.Request) {
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	fmt.Fprintf(&b, "echo from %s%s\n", r.Host, r.URL.Path)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, b.String())
}

// FakeGRPC returns a fake gRPC server on grpc.example.com: a raw HTTP/2 unary
// echo service (no protobuf module). A gRPC request framed the standard way
// (5-byte prefix: compression flag + big-endian length) gets the identical
// message echoed back with grpc-status 0 — enough for a scenario to prove a
// request traversed the worker's h2 path intact.
func (h *H) FakeGRPC() *Upstream {
	h.tb.Helper()
	h.grpcOnce.Do(func() {
		u := h.Upstream(h.Host("grpc"))
		u.route("/", grpcEchoHandler{})
		h.grpcU = u
	})
	return h.grpcU
}

// grpcEchoHandler is the unary echo service.
type grpcEchoHandler struct{}

func (grpcEchoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Proto != "HTTP/2.0" {
		http.Error(w, "harness: gRPC requires HTTP/2", http.StatusHTTPVersionNotSupported)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, upstreamBodyLimit))
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Trailer", "Grpc-Status")
	w.WriteHeader(http.StatusOK)
	// Raw echo: a gRPC client always sends the 5-byte frame, so the received
	// bytes ARE a valid response frame — send them back verbatim.
	_, _ = w.Write(body)
	// Trailers carry gRPC's status; http.TrailerPrefix is how a net/http
	// server emits one after the body is written.
	w.Header().Set(http.TrailerPrefix+"Grpc-Status", "0")
}

// FakeWS returns a fake WebSocket server on ws.example.com with an echo
// endpoint at /ws (x/net/websocket, no new module). It is exercised directly
// (bypassing the worker): riding the worker's WS path requires the MCP
// gateway to be enabled for the frame-pump handoff, which is a scenario-level
// concern, not the fake's.
func (h *H) FakeWS() *Upstream {
	h.tb.Helper()
	h.wsOnce.Do(func() {
		u := h.Upstream(h.Host("ws"))
		u.route("/ws", websocket.Handler(func(conn *websocket.Conn) {
			_, _ = io.Copy(conn, conn)
		}))
		h.wsU = u
	})
	return h.wsU
}

// mappingDialer is the assembly-only dialer every harness worker boots with:
// it routes each registered fake hostname to that fake's loopback address —
// DNS replacement, not SSRF (production's SafeDialer stays production's). It
// keeps the tls.Config the proxy hands it: ServerName stays the fake host
// (matching the upstream leaf's SAN) and RootCAs stays the Overrides.UpstreamRootCAs
// pool the harness built — a regression in either override fails the handshake.
type mappingDialer struct{ h *H }

// Dial: plain HTTP upstreams are not a harness scenario (every fake is TLS).
// Refuse loudly so a mis-configured scenario reads as a harness error, not a
// hang.
func (m *mappingDialer) Dial(network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("harness: plain upstream dial to %s refused; fake upstreams are https-only", addr)
}

// DialTLS maps <host>:<port> to the fake's loopback address and handshakes
// with the proxy's own config.
func (m *mappingDialer) DialTLS(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("harness: dial target %q has no port", addr)
	}
	m.h.mu.Lock()
	up, ok := m.h.upstreams[host]
	m.h.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("harness: no fake upstream registered for %q (add h.Upstream(%q))", host, host)
	}
	// The proxy must have handed us the UpstreamRootCAs pool; if it ever builds
	// a bare config, fail with the cause instead of a confusing x509 error.
	if cfg == nil || cfg.RootCAs == nil {
		return nil, errors.New("harness: proxy handed DialTLS a tls.Config without RootCAs; Overrides.UpstreamRootCAs never reached the upstream TLS config")
	}
	raw, err := net.Dial(network, up.addr())
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, cfg)
	if err := conn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}
