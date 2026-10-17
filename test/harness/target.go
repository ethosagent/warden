package harness

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/worker"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// Target is where a scenario's traffic actually flows — and the ONLY way H
// reaches the deployment it is testing: the per-worker proxy/admin addresses,
// the control-plane address with its token and CA, the control-plane outage
// fault, and the oracle sources (logs, events, metrics). The L1 harness ships
// the `inprocess` implementation below (real worker.Run + controlplane.Run in
// this test process); #351 adds a `compose` implementation so the SAME scenarios
// run against a docker-compose stack through this one interface. H holds a
// Target, never *inprocess — a scenario body cannot tell the difference.
type Target interface {
	// Start boots the target. It is idempotent per instance and must return only
	// when the addresses below are serving (the in-process target waits on the
	// components' OnReady signals).
	Start(ctx context.Context) error
	// Stop tears the target down and waits for every component to return,
	// releasing any read handles the oracles opened. A component that exited
	// mid-scenario is reported in the returned error.
	Stop() error

	// ProxyAddr is worker-1's proxy address (host:port) — the one a Local harness
	// or a single-agent scenario points at. ProxyAddrs lists every worker's
	// proxy address, worker-1 first; AdminAddr is worker-1's admin address.
	ProxyAddr() string
	ProxyAddrs() []string
	AdminAddr() string

	// ControlPlaneAddr is the control plane's HTTPS address. ControlPlaneToken
	// is the bearer token its API authenticates with (in-process: the env var
	// the harness set, exactly as a deployment distributes it) and
	// ControlPlaneCA is the root pool its TLS cert verifies against (in-process:
	// the harness-minted proxy CA).
	ControlPlaneAddr() string
	ControlPlaneToken() (string, error)
	ControlPlaneCA() (*x509.CertPool, error)

	// StopControlPlane / StartControlPlane are the outage fault: take the
	// control plane down and bring it back on the SAME address the workers were
	// configured with, waiting for it to serve again. Both are no-ops when the
	// control plane is already in the requested state.
	StopControlPlane() error
	StartControlPlane(ctx context.Context) error

	// The oracle sources. Logs is everything the components logged (structured
	// lines, exactly as a deployment's stdout); Events is every analytics event
	// across the workers, worker-1 first, read through the production analytics
	// store; Metrics is the fleet-wide view flattened to name{label=value} ->
	// value (see H.Metrics for the exact shape). Callers own nothing: Events may
	// hold read handles that Stop releases.
	//
	// Events MUST be read-your-writes: when it returns, every event of traffic
	// the scenario has already finished making is visible. The in-process target
	// gets this from the harness's analytics drain (H flushes each worker's
	// async writer through the OnAnalyticsWriter seam before reading); a target
	// whose writers are out of its reach — compose — must flush or wait itself,
	// or a scenario reads a short list and fails confusingly late.
	Logs() string
	Events() ([]analytics.Event, error)
	Metrics() (map[string]float64, error)
}

// readyDeadline is the OnReady budget for one component (per the ticket: 10s).
const readyDeadline = 10 * time.Second

// stopDeadline is how long a component gets to return after cancellation.
const stopDeadline = 10 * time.Second

// inprocess is the in-process Target: one real control plane plus N real
// workers, each booted through its production Run function on loopback port-0
// listeners, so a harness instance binds nothing that can collide and leaves no
// fixed port behind.
type inprocess struct {
	cp      *cpProc
	workers []*workerProc

	// dbPaths are the workers' analytics SQLite files (Events opens them
	// read-only through the production store); readers are the per-worker OTel
	// readers (Metrics merges them); caPool and tokenEnv back the control-plane
	// accessors. All set once at harness boot, before Start.
	dbPaths  []string
	readers  []*sdkmetric.ManualReader
	caPool   *x509.CertPool
	tokenEnv string

	// cpDownAtBoot makes Start bind the control plane (to learn its address) and
	// release it again before any worker boots, so the workers' first policy pull
	// finds nothing listening.
	cpDownAtBoot bool

	// eventsMu guards the lazily-opened read handles.
	eventsMu    sync.Mutex
	eventStores []*analytics.SQLiteStore
}

var _ Target = (*inprocess)(nil)

// transparentReporter is the optional Target capability for interception mode
// (#376): per worker, the bound transparent listener addresses as
// {httpsAddr, httpAddr} ("httpAddr" empty when plain HTTP is not served).
// Targets that bind no transparent listeners do not implement it; H.
// TransparentAddrs fails the test loudly rather than handing a scenario an
// empty address.
type transparentReporter interface {
	transparentAddrs() [][2]string
}

// Start boots the control plane first (so every worker's initial policy pull
// succeeds and its fail-closed boot window closes before it accepts), then each
// worker. It returns when every component has reported OnReady. Components
// already running are left alone, so Start is safe to call after a partial
// boot or a StartControlPlane cycle.
func (ip *inprocess) Start(ctx context.Context) error {
	if !ip.cp.running() {
		if err := ip.cp.start(ctx); err != nil {
			return err
		}
		if ip.cpDownAtBoot {
			ip.cp.stop()
		}
	}
	for _, w := range ip.workers {
		if !w.running() {
			if err := w.start(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// Stop cancels every component, waits for each Run to return, releases the
// events read handles, and reports any component that did not exit cleanly
// (a mid-scenario exit is a bug the scenario must hear about, not paper over).
func (ip *inprocess) Stop() error {
	var errs []error
	for _, w := range ip.workers {
		w.stop()
		if w.exitErr != nil && !errors.Is(w.exitErr, context.Canceled) {
			errs = append(errs, fmt.Errorf("%s exited unexpectedly: %w", w.name, w.exitErr))
		}
	}
	if ip.cp != nil {
		ip.cp.stop()
		if ip.cp.exitErr != nil && !errors.Is(ip.cp.exitErr, context.Canceled) {
			errs = append(errs, fmt.Errorf("control plane exited unexpectedly: %w", ip.cp.exitErr))
		}
	}
	ip.eventsMu.Lock()
	stores := ip.eventStores
	ip.eventStores = nil
	ip.eventsMu.Unlock()
	for _, st := range stores {
		_ = st.Close()
	}
	return errors.Join(errs...)
}

func (ip *inprocess) ProxyAddr() string {
	if len(ip.workers) == 0 {
		return ""
	}
	return ip.workers[0].proxyAddr
}

func (ip *inprocess) ProxyAddrs() []string {
	out := make([]string, 0, len(ip.workers))
	for _, w := range ip.workers {
		out = append(out, w.proxyAddr)
	}
	return out
}

func (ip *inprocess) AdminAddr() string {
	if len(ip.workers) == 0 {
		return ""
	}
	return ip.workers[0].adminAddr
}

// transparentAddrs reports every worker's bound interception listeners, in
// worker order. A worker still booting reports empty strings — but Start does
// not return until each transparent-mode worker reported OnTransparentReady,
// so a caller after Start always sees bound addresses.
func (ip *inprocess) transparentAddrs() [][2]string {
	out := make([][2]string, 0, len(ip.workers))
	for _, w := range ip.workers {
		out = append(out, [2]string{w.tlsAddr, w.httpAddr})
	}
	return out
}

func (ip *inprocess) ControlPlaneAddr() string {
	if ip.cp == nil {
		return ""
	}
	return ip.cp.addr
}

// ControlPlaneToken reads the token from the env var the harness set — the same
// mechanism a deployment distributes it with. An empty token means the env was
// never set: report it, so a mis-wired target fails loudly instead of 401-ing.
func (ip *inprocess) ControlPlaneToken() (string, error) {
	token := os.Getenv(ip.tokenEnv)
	if token == "" {
		return "", fmt.Errorf("harness: control-plane token env %s is empty", ip.tokenEnv)
	}
	return token, nil
}

func (ip *inprocess) ControlPlaneCA() (*x509.CertPool, error) {
	if ip.caPool == nil {
		return nil, errors.New("harness: in-process target has no control-plane CA pool")
	}
	return ip.caPool, nil
}

// StopControlPlane takes the control plane down (the outage fault). A no-op
// when it is already stopped, so a scenario can Stop twice without a bind
// error on the next Start.
func (ip *inprocess) StopControlPlane() error {
	if !ip.cp.running() {
		return nil
	}
	ip.cp.stop()
	return nil
}

// StartControlPlane brings the control plane back on its recorded address and
// waits for OnReady. A no-op when it is already running.
func (ip *inprocess) StartControlPlane(ctx context.Context) error {
	if ip.cp.running() {
		return nil
	}
	return ip.cp.start(ctx)
}

// Logs is the components' structured stdout: workers first, then the control
// plane.
func (ip *inprocess) Logs() string {
	var b strings.Builder
	for _, w := range ip.workers {
		b.WriteString(w.logs.String())
	}
	if ip.cp != nil {
		b.WriteString(ip.cp.logs.String())
	}
	return b.String()
}

// eventsDSN opens a worker's live analytics DB for reading: a busy_timeout so
// a read that lands on the async writer's commit doesn't fail spuriously.
// The store appends mode=ro on top of these params.
const eventsDSN = "?_pragma=busy_timeout(10000)"

// Events reads every worker's analytics store through the production analytics
// package, worker-1 first. Handles are opened once and released by Stop.
func (ip *inprocess) Events() ([]analytics.Event, error) {
	ip.eventsMu.Lock()
	if ip.eventStores == nil {
		for i, path := range ip.dbPaths {
			st, err := analytics.NewSQLiteStore("file:"+path+eventsDSN, 0)
			if err != nil {
				ip.eventsMu.Unlock()
				return nil, fmt.Errorf("harness: open analytics store for worker-%d: %w", i+1, err)
			}
			ip.eventStores = append(ip.eventStores, st)
		}
	}
	stores := make([]*analytics.SQLiteStore, len(ip.eventStores))
	copy(stores, ip.eventStores)
	ip.eventsMu.Unlock()

	var out []analytics.Event
	for i, st := range stores {
		evs, err := st.GetEvents(analytics.EventFilter{})
		if err != nil {
			return nil, fmt.Errorf("harness: read analytics events for worker-%d: %w", i+1, err)
		}
		out = append(out, evs...)
	}
	return out, nil
}

// Metrics merges every worker's OTel reader into the fleet-wide view. An
// aggregation window is per-worker, so a fleet's counter under Metrics is the
// SUM across workers; histograms get two keys per label set, suffixed #count
// and #sum. Labels are sorted, so keys are stable — build expectations with
// MetricKey.
func (ip *inprocess) Metrics() (map[string]float64, error) {
	out := make(map[string]float64)
	for i, reader := range ip.readers {
		var rm metricdata.ResourceMetrics
		if err := reader.Collect(context.Background(), &rm); err != nil {
			return nil, fmt.Errorf("harness: collect metrics for worker-%d: %w", i+1, err)
		}
		collectMetrics(rm, out)
	}
	return out, nil
}

// workerProc is one booted worker.Run instance and its lifecycle handles.
type workerProc struct {
	name string
	// paramsFn is resolved at start time, not construction time: the worker's
	// policy points at the control plane's bound address, which exists only
	// once the CP has started.
	paramsFn func() worker.Params
	logs     *logBuffer

	ctx       context.Context
	cancel    context.CancelFunc
	errCh     chan error
	ready     chan struct{}
	params    worker.Params
	proxyAddr string
	adminAddr string
	ran       bool
	exitErr   error
	// transparent + the tlsAddr/httpAddr it fills: this worker boots the
	// interception listeners (#376) and reports their bound addresses through
	// Params.OnTransparentReady, which transReady makes Start wait for (Serve
	// binds them AFTER OnReady, so the first select alone would race a dialer).
	transparent bool
	tlsAddr     string
	httpAddr    string
	transReady  chan struct{}
}

func (w *workerProc) running() bool { return w.ran && w.cancel != nil }

// start boots the worker on fresh port-0 listeners and waits for OnReady.
func (w *workerProc) start(parent context.Context) error {
	w.params = w.paramsFn()
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = proxyLn.Close()
		return err
	}
	// Capture the bound addresses now: an injected listener's address IS what
	// OnReady reports (worker.Run guarantees this), and reading it here avoids
	// racing the OnReady callback with the caller.
	w.proxyAddr, w.adminAddr = proxyLn.Addr().String(), adminLn.Addr().String()
	w.params.ProxyListener = proxyLn
	w.params.AdminListener = adminLn
	w.ready = make(chan struct{})
	w.params.OnReady = func(proxyAddr, _ string) {
		if proxyAddr != w.proxyAddr {
			// The worker reports the injected listener's address; drift here is a
			// Run regression the harness must not paper over.
			w.proxyAddr = proxyAddr
		}
		close(w.ready)
	}
	if w.transparent {
		// Interception mode (#376): the worker binds the transparent listeners
		// inside Serve — after OnReady — so Start must ALSO wait for their
		// bound addresses before returning, or the first scenario dial races
		// the bind.
		w.transReady = make(chan struct{})
		w.params.OnTransparentReady = func(httpsAddr, httpAddr string) {
			w.tlsAddr, w.httpAddr = httpsAddr, httpAddr
			close(w.transReady)
		}
	}
	w.ctx, w.cancel = context.WithCancel(parent)
	w.errCh = make(chan error, 1)
	w.ran = true
	go func() { w.errCh <- worker.Run(w.ctx, w.logs, w.params) }()
	// waitFor is the one ready-budget select, shared by OnReady and
	// OnTransparentReady. The errCh case marks a failed boot stopped (see
	// below), exactly as the original inline select did.
	waitFor := func(ch <-chan struct{}, what string) error {
		select {
		case <-ch:
			return nil
		case err := <-w.errCh:
			// Run exited on its own before the signal — a failed boot, not a
			// component to stop. Mark it stopped: leaving cancel set made stop()
			// cancel a corpse and then wait the full stopDeadline on the errCh
			// THIS select just drained, reporting a bogus "did not stop within
			// 10s" for every failed boot. exitErr stays nil — the boot error is
			// Start's return.
			w.cancel = nil
			return err
		case <-time.After(readyDeadline):
			w.cancel()
			<-w.errCh
			w.cancel = nil
			return errors.New("worker " + w.name + " did not report " + what + " within " + readyDeadline.String())
		}
	}
	if err := waitFor(w.ready, "OnReady"); err != nil {
		return err
	}
	if w.transparent {
		return waitFor(w.transReady, "OnTransparentReady")
	}
	return nil
}

// stop cancels the worker and waits for Run to return, recording its exit error
// (nil on a clean ctx-driven shutdown) for the target's Stop to report.
func (w *workerProc) stop() {
	if w.cancel == nil {
		return
	}
	w.cancel()
	select {
	case w.exitErr = <-w.errCh:
	case <-time.After(stopDeadline):
		w.exitErr = errors.New("worker " + w.name + " did not stop within " + stopDeadline.String())
	}
	w.cancel = nil
}

// cpProc is the booted controlplane.Run instance. It owns its SERVING ADDRESS:
// Stop + Start re-bind the same address, so a worker configured against it can
// ride the outage and reconnect without re-reading config.
type cpProc struct {
	params controlplane.Params
	logs   *logBuffer
	addr   string

	ctx     context.Context
	cancel  context.CancelFunc
	errCh   chan error
	ready   chan string
	ran     bool
	exitErr error
}

func (c *cpProc) running() bool { return c.ran && c.cancel != nil }

// start binds the control plane and waits for OnReady. Called once at harness
// boot (fresh port 0) and again by StartControlPlane (the recorded address), so
// a stopped control plane comes back where the workers expect it.
func (c *cpProc) start(parent context.Context) error {
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	c.addr = ln.Addr().String()
	c.params.Listener = ln
	c.ready = make(chan string, 1)
	c.params.OnReady = func(addr string) { c.ready <- addr }
	c.ctx, c.cancel = context.WithCancel(parent)
	c.errCh = make(chan error, 1)
	c.ran = true
	go func() { c.errCh <- controlplane.Run(c.ctx, c.logs, c.params) }()
	select {
	case a := <-c.ready:
		c.addr = a
		return nil
	case err := <-c.errCh:
		// Run exited on its own before OnReady — a failed boot. Mark it stopped
		// (same contract as workerProc.start): cancel set plus a drained errCh
		// would make stop() burn stopDeadline and report a bogus timeout.
		c.cancel = nil
		return err
	case <-time.After(readyDeadline):
		c.cancel()
		<-c.errCh
		c.cancel = nil
		return errors.New("control plane did not report OnReady within " + readyDeadline.String())
	}
}

// stop cancels the control plane and waits for Run to return.
func (c *cpProc) stop() {
	if c.cancel == nil {
		return
	}
	c.cancel()
	select {
	case c.exitErr = <-c.errCh:
	case <-time.After(stopDeadline):
		c.exitErr = errors.New("control plane did not stop within " + stopDeadline.String())
	}
	c.cancel = nil
}

// fatalfOn converts a start error into a test failure at harness boot time.
func fatalfOn(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("harness: boot failed: %v", err)
	}
}
