package harness

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/worker"
	"github.com/ethosagent/warden/test/fakes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// fakeTarget is a scripted Target: planted addresses and oracle sources, plus
// counters for every lifecycle call. It is how the tests prove H routes
// EVERYTHING through the Target interface — a scenario (and the oracles)
// cannot tell it from the in-process target.
type fakeTarget struct {
	addr      string
	adminAddr string
	cpAddr    string

	logs    string
	events  []analytics.Event
	metrics map[string]float64

	token string
	ca    *x509.CertPool

	mu         sync.Mutex
	starts     int
	stops      int
	cpStops    int
	cpStarts   int
	tokens     int
	cas        int
	stopCalled chan struct{} // closed once, if set
}

func (f *fakeTarget) Start(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	return nil
}

func (f *fakeTarget) Stop() error {
	f.mu.Lock()
	f.stops++
	f.mu.Unlock()
	if f.stopCalled != nil {
		select {
		case <-f.stopCalled:
		default:
			close(f.stopCalled)
		}
	}
	return nil
}

func (f *fakeTarget) ProxyAddr() string        { return f.addr }
func (f *fakeTarget) ProxyAddrs() []string     { return []string{f.addr} }
func (f *fakeTarget) AdminAddr() string        { return f.adminAddr }
func (f *fakeTarget) ControlPlaneAddr() string { return f.cpAddr }

func (f *fakeTarget) ControlPlaneToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens++
	if f.token == "" {
		return "", errors.New("fakeTarget: no token planted")
	}
	return f.token, nil
}

func (f *fakeTarget) ControlPlaneCA() (*x509.CertPool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cas++
	if f.ca == nil {
		return nil, errors.New("fakeTarget: no CA planted")
	}
	return f.ca, nil
}

func (f *fakeTarget) StopControlPlane() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cpStops++
	return nil
}

func (f *fakeTarget) StartControlPlane(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cpStarts++
	return nil
}

func (f *fakeTarget) Host(alias string) (string, error) {
	if !knownAlias(alias) {
		return "", errors.New("fakeTarget: unknown alias " + alias)
	}
	return alias + ".fake", nil
}

func (f *fakeTarget) Logs() string { return f.logs }

func (f *fakeTarget) Events() ([]analytics.Event, error) { return f.events, nil }

func (f *fakeTarget) Metrics() (map[string]float64, error) { return f.metrics, nil }

func (f *fakeTarget) counters() (starts, stops, cpStops, cpStarts, tokens, cas int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.starts, f.stops, f.cpStops, f.cpStarts, f.tokens, f.cas
}

// TestWithTarget_HRoutesThroughTheInterface proves H is target-agnostic: with
// a fake Target supplied, every address, the control-plane client (its token
// and CA come from the target), the outage fault and the oracle sources all
// read through the interface — the in-process implementation is never touched.
// This is the seam #351's compose target rides.
func TestWithTarget_HRoutesThroughTheInterface(t *testing.T) {
	// A stand-in "control plane" whose TLS the fake target's CA anchors:
	// H.CP() must build its client from the target-supplied token and CA, so a
	// request through it both verifies TLS and authenticates.
	sawToken := make(chan string, 1)
	cpSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "" {
			select {
			case sawToken <- auth:
			default:
			}
		}
		if _, err := w.Write([]byte(`[]`)); err != nil {
			t.Errorf("write fleet view: %v", err)
		}
	}))
	defer cpSrv.Close()

	caPool := x509.NewCertPool()
	caPool.AddCert(cpSrv.Certificate())

	ft := &fakeTarget{
		addr:      "10.1.2.3:9000",
		adminAddr: "10.1.2.3:9001",
		cpAddr:    strings.TrimPrefix(cpSrv.URL, "https://"),
		logs:      `{"level":"info","msg":"fake target log line"}`,
		events:    []analytics.Event{{Domain: "fake.example", Decision: "allow"}},
		metrics:   map[string]float64{"warden.requests.total": 7},
		token:     "fake-target-token",
		ca:        caPool,
	}

	// Cleanup stops the target exactly once. Registered BEFORE New so it runs
	// AFTER the harness's own cleanup (t.Cleanup is LIFO).
	t.Cleanup(func() {
		if _, stops, _, _, _, _ := ft.counters(); stops != 1 {
			t.Errorf("target Stop called %d times by cleanup, want exactly 1", stops)
		}
	})

	h := New(t, WithTarget(ft))

	if got, want := h.ProxyAddr(), ft.addr; got != want {
		t.Errorf("ProxyAddr = %q, want the fake target's %q", got, want)
	}
	if got := h.ProxyAddrs(); len(got) != 1 || got[0] != ft.addr {
		t.Errorf("ProxyAddrs = %v, want [%s]", got, ft.addr)
	}
	if got, want := h.AdminAddr(), ft.adminAddr; got != want {
		t.Errorf("AdminAddr = %q, want %q", got, want)
	}
	if got, want := h.ControlPlaneAddr(), ft.cpAddr; got != want {
		t.Errorf("ControlPlaneAddr = %q, want %q", got, want)
	}
	if h.Target() != Target(ft) {
		t.Error("Target() is not the supplied target")
	}

	// Oracle sources route through the target, planted values and all.
	if got := h.Logs(); got != ft.logs {
		t.Errorf("Logs = %q, want the fake target's planted log", got)
	}
	if evs := h.Events(); len(evs) != 1 || evs[0].Domain != "fake.example" {
		t.Errorf("Events = %+v, want the fake target's planted event", evs)
	}
	if m := h.Metrics(); m["warden.requests.total"] != 7 {
		t.Errorf("Metrics = %v, want the fake target's planted counter", m)
	}

	// The CP client is built from the target's token and CA, and the outage
	// fault routes through it.
	workers, err := h.CP().Workers()
	if err != nil {
		t.Fatalf("CP().Workers() through the fake target's control plane: %v", err)
	}
	if len(workers) != 0 {
		t.Errorf("Workers = %v, want an empty fleet view", workers)
	}
	select {
	case auth := <-sawToken:
		if auth != "Bearer fake-target-token" {
			t.Errorf("control plane saw Authorization %q, want the target-supplied token", auth)
		}
	default:
		t.Error("the control plane saw no request; H.CP() did not use the fake target's address")
	}
	if _, _, _, _, tokens, cas := ft.counters(); tokens == 0 || cas == 0 {
		t.Errorf("ControlPlaneToken/ControlPlaneCA consulted %d/%d times, want >=1 each", tokens, cas)
	}

	h.CP().Stop()
	h.CP().Start()
	if _, _, cpStops, cpStarts, _, _ := ft.counters(); cpStops != 1 || cpStarts != 1 {
		t.Errorf("CP stop/start routed %d/%d calls to the target, want 1/1", cpStops, cpStarts)
	}
}

// bootFailTarget fails Start, so New's boot fails partway through. It embeds
// the fake by POINTER: a Target carries a mutex, and copying one is a lock
// copy the vet rightly flags.
type bootFailTarget struct {
	*fakeTarget
	startErr error
}

func (b *bootFailTarget) Start(_ context.Context) error { return b.startErr }

// TestNew_BootFailureStillStopsTarget pins the cleanup ordering: t.Cleanup is
// registered BEFORE boot, so a boot that fails partway still stops whatever the
// target started — a half-booted compose stack must not outlive the test. It
// drives New through a recording TB (boot's t.Fatalf must not abort THIS test)
// and then runs the harness cleanup by hand: it is idempotent, so the cleanup
// registered on the real t at test end is a no-op.
func TestNew_BootFailureStillStopsTarget(t *testing.T) {
	failing := &bootFailTarget{
		fakeTarget: &fakeTarget{stopCalled: make(chan struct{})},
		startErr:   errors.New("harness: compose stack did not come up"),
	}
	rec := &recordingTB{T: t}
	h := New(rec, WithTarget(failing))
	if !rec.Failed() {
		t.Fatal("New did not report a boot failure for a target that fails to start")
	}
	h.cleanup()
	select {
	case <-failing.stopCalled:
	default:
		t.Fatal("the failed boot never stopped the target; New must register t.Cleanup BEFORE boot")
	}
}

// TestInprocess_WorkerBootFailure_StopIsFastAndClean pins the start-failure
// contract on the REAL in-process target: a worker whose Run exits before
// OnReady is DEAD, not stoppable — workerProc.start must mark it stopped on
// every start-failure path. Leaving cancel set made Stop() cancel a corpse and
// then wait the full stopDeadline on an errCh start had already drained,
// reporting a bogus "did not stop within 10s" and burning ten seconds of every
// failed boot.
func TestInprocess_WorkerBootFailure_StopIsFastAndClean(t *testing.T) {
	h := New(t, Local())
	// A second, hand-assembled in-process target sharing the harness's CAs,
	// token and CP config, but with its own DB files (the harness's control
	// plane is still running on its own) and a worker whose ConfigProvider
	// hard-fails — worker.Run exits before OnReady, exactly like a bad boot.
	ip := &inprocess{
		cp: &cpProc{
			addr: "127.0.0.1:0",
			params: controlplane.Params{
				ConfigPath:        h.writeCPConfig(),
				TokenEnv:          cpTokenEnv,
				CACert:            h.proxyCACertDst,
				CAKey:             h.proxyCAKeyDst,
				TLSHost:           "127.0.0.1",
				MaxEvents:         10000,
				AnalyticsProvider: "memory",
				AnalyticsDB:       filepath.Join(h.root, "bootfail-cp-fleet.db"),
				AlertsDB:          filepath.Join(h.root, "bootfail-cp-alerts.db"),
			},
			logs: &logBuffer{},
		},
		workers: []*workerProc{{
			name: "worker-bootfail",
			paramsFn: func() worker.Params {
				p := h.workerParams(1)
				p.Config = &fakes.FakeConfigProvider{Err: errBrokenConfig}
				return p
			},
			logs: &logBuffer{},
		}},
		readers:  []*sdkmetric.ManualReader{sdkmetric.NewManualReader()},
		caPool:   h.proxyCA.pool(),
		tokenEnv: cpTokenEnv,
	}

	// The failure must be the WORKER's, not the control plane's: the CP boots
	// fine so the worker's start is genuinely what fails.
	err := ip.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), errBrokenConfig.Error()) {
		t.Fatalf("Start err = %v, want the worker's config failure (the CP must come up so the worker's start is what fails)", err)
	}
	if ip.workers[0].running() {
		t.Fatal("the worker still reports running after its start failed; start must mark a failed boot stopped")
	}

	start := time.Now()
	stopErr := ip.Stop()
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Stop took %s after a failed start, want near-instant (the proc was left mid-flight)", elapsed)
	}
	if stopErr != nil {
		t.Fatalf("Stop after a failed start = %v, want nil (nothing was running to stop, so no bogus exit to report)", stopErr)
	}
}

// errBrokenConfig is the planted boot failure of TestInprocess_WorkerBootFailure_StopIsFastAndClean.
var errBrokenConfig = errors.New("harness test: config provider failed")

// TestNew_BootFatalRunsTheRegisteredCleanup pins the order INSIDE New: the
// t.Cleanup must be registered BEFORE h.boot(), because a real testing.T
// unwinds a Fatal THROUGH the cleanups registered so far. The TB here is a
// faithful stand-in — its Fatal records the failure, runs its own cleanups
// (LIFO, as tRunner does at the Goexit), then Goexits the goroutine driving
// New — so the test observes what a scenario author's test would live through:
// a boot whose target will not start must still stop what the boot started. If
// the registration moves after h.boot(), the Fatal fires before any cleanup
// exists and the target is left running — this test goes red on exactly that.
func TestNew_BootFatalRunsTheRegisteredCleanup(t *testing.T) {
	failing := &bootFailTarget{
		fakeTarget: &fakeTarget{stopCalled: make(chan struct{})},
		startErr:   errors.New("harness: compose stack did not come up"),
	}
	recCh := make(chan *recordingTB, 1)
	go func() {
		rec := &recordingTB{T: t, goexitFatal: true}
		defer func() { recCh <- rec }()
		New(rec, WithTarget(failing)) // boot fails → Fatal → cleanups → Goexit
	}()
	rec := <-recCh
	if !rec.Failed() {
		t.Fatal("New did not fail a boot whose target would not start")
	}
	select {
	case <-failing.stopCalled:
	default:
		t.Fatal("the boot Fatal did not run the already-registered cleanup; " +
			"New must register t.Cleanup BEFORE h.boot(), or a real testing.T's Fatal leaves the target running")
	}
}

// TestNew_ParallelRejectedBeforeAnythingBoots drives New ITSELF (not just the
// guard) through a parallel-flagged TB: New must fail the test before booting
// a single component. The target here is a spy — if assertNotParallel were
// dropped from New, boot would proceed and start it, and this test goes red on
// the started count as well as on the missing failure.
func TestNew_ParallelRejectedBeforeAnythingBoots(t *testing.T) {
	if !reflectHasIsParallel(t) {
		t.Fatal("this Go's testing.T has no isParallel field; assertNotParallel cannot detect t.Parallel() — update it")
	}
	ft := &fakeTarget{}
	recCh := make(chan *recordingTB, 1)
	go func() {
		rec := &recordingTB{T: t, goexitFatal: true, isParallel: true}
		defer func() { recCh <- rec }()
		New(rec, WithTarget(ft))
	}()
	rec := <-recCh
	if !rec.Failed() {
		t.Fatal("New ran to completion in a t.Parallel() test; assertNotParallel must guard New itself, not only direct callers of the guard")
	}
	if msg := rec.failureMessage(); !strings.Contains(msg, "t.Parallel()") {
		t.Errorf("guard message does not tell the scenario author about t.Parallel():\n%s", msg)
	}
	if starts, _, _, _, _, _ := ft.counters(); starts != 0 {
		t.Errorf("the parallel test's target was started %d time(s); New must reject before booting anything", starts)
	}
}

// TestNew_RejectsParallel pins the misuse guard: New inside a t.Parallel()
// test fails clearly (fixed env names would collide across parallel harnesses
// in one process). The guard reads testing.T's unexported isParallel flag; if
// a Go release renames it, fail loudly rather than silently passing.
func TestNew_RejectsParallel(t *testing.T) {
	if !reflectHasIsParallel(t) {
		t.Fatal("this Go's testing.T has no isParallel field; assertNotParallel cannot detect t.Parallel() — update it")
	}
	rec := &recordingTB{T: t, isParallel: true}
	assertNotParallel(rec)
	if !rec.Failed() {
		t.Fatal("assertNotParallel did not fail a parallel test; New would silently collide with another harness")
	}
	if msg := rec.failureMessage(); !strings.Contains(msg, "t.Parallel()") {
		t.Errorf("guard message does not tell the scenario author about t.Parallel():\n%s", msg)
	}
}

// reflectHasIsParallel reports whether THIS Go's testing.T carries the
// unexported isParallel field assertNotParallel reads.
func reflectHasIsParallel(t *testing.T) bool {
	v := reflect.Indirect(reflect.ValueOf(t))
	if v.Kind() != reflect.Struct {
		return false
	}
	f := v.FieldByName("isParallel")
	return f.IsValid() && f.Kind() == reflect.Bool
}

// TestNoLeakCheck_OptsOut proves the option: with NoLeakCheck the harness
// boots normally but the built-in goroutine check is disabled.
func TestNoLeakCheck_OptsOut(t *testing.T) {
	h := New(t, NoLeakCheck())
	if h.leakCheck {
		t.Fatal("NoLeakCheck did not reach the harness; the built-in check would still run")
	}
	if h.ProxyAddr() == "" {
		t.Fatal("NoLeakCheck harness did not boot a worker")
	}
}

// TestNew_DoesNotWriteIntoThePackageDir pins a hygiene rule the harness must
// never break: every artifact (CA pair, worker DBs, control-plane config) lands
// in t.TempDir, never next to the harness sources. (A previous run left a
// stray warden-alerts.db in the package directory; this is the regression
// guard.) It checks the directory is clean at test start and that a booted
// harness did not add SQLite files there.
func TestNew_DoesNotWriteIntoThePackageDir(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the harness package dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			t.Errorf("stray SQLite file %s in the harness package dir; artifacts must stay in t.TempDir", e.Name())
		}
	}
	h := New(t)
	_ = h.ProxyAddr()
	entries, err = os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the harness package dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".db") {
			t.Errorf("the harness wrote %s into the package dir; artifacts must stay in t.TempDir", e.Name())
		}
	}
}
