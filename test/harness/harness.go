// Package harness is Warden's L1 in-process test harness (parent #350,
// ticket #363): a real control plane plus real workers, booted through their
// production Run functions inside the test process, with every external
// collaborator — upstream destinations, DNS, time, trust roots — replaced so a
// scenario never leaves loopback.
//
// The three core interfaces are never bypassed: workers boot Go-built policies
// through config.ConfigProvider (test/fakes), placeholders resolve through the
// worker's env SecretProvider, and analytics flow through the production
// SQLite store — the harness reads them back through the same package.
//
// Everything here is assembly-only: production wiring (cmd/) cannot reach any
// of it. The security posture is the production one, mirrored in miniature —
// default-deny (h.Upstream never allowlists anything; call Allow), the agent
// holds placeholders only (WithSecret keeps values in a harness-set env var,
// exactly as a deployment would), and AssertCanaryNeverLeaked fails the test
// if a secret value ever reaches the agent, the logs, the events, the metrics
// or an upstream outside its scope.
//
// CONCURRENCY: New cannot be used from a t.Parallel() test — every harness in
// a process boots its components from FIXED env names (the control-plane
// token), which parallel tests sharing the process would overwrite for each
// other. New fails the test clearly when it detects t.Parallel().
package harness

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/worker"
	"github.com/ethosagent/warden/test/fakes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// cpTokenEnv is the env var the harness's control plane reads its bearer token
// from (and every worker with it). Set once per harness instance with a random
// token, via t.Setenv — the same env mechanism a deployment uses. FIXED per
// process, which is exactly why a harness cannot run under t.Parallel().
const cpTokenEnv = "WARDEN_HARNESS_CP_TOKEN"

// defaultAllowlist are the harness's own well-known fake hostnames (see
// Upstream). They ship allowed because they ARE the harness's loopback
// stand-ins for real providers; everything else stays default-deny until
// Allow adds it, exactly as production starts from an explicit allowlist.
var defaultAllowlist = []string{
	"api.example.com",
	"llm.example.com",
	"mcp.example.com",
	"grpc.example.com",
	"ws.example.com",
}

// secretSpec is one WithSecret registration: the placeholder NAME the agent
// sees, the real value (kept here and in the env var only), and the hosts it
// may be swapped for. The canary oracle sweeps every registered value.
type secretSpec struct {
	name        string
	placeholder string
	value       string
	matchHosts  []string
}

// defaultQuiescenceDeadline bounds how long the oracles wait for the workers'
// in-flight request scopes to drain before failing the test with the still
// in-flight work named. A scenario that finishes its traffic reaches quiescence
// in microseconds (the wait wakes on the drain, never polls); the budget only
// ever expires on a defect — a parked request (Delay fault), a stuck stream —
// or on traffic a scenario deliberately left unfinished.
const defaultQuiescenceDeadline = 10 * time.Second

// H is one booted harness instance: a control plane, N workers, the fake
// upstream registry, the fake clock and the oracles. Create it with New; every
// resource it starts is torn down by the t.Cleanup it registers.
type H struct {
	tb   testing.TB
	root string // t.TempDir(); CP config, proxy CA pair, worker DBs

	proxyCACertDst string // proxy-ca.crt path (the worker reads paths)
	proxyCAKeyDst  string
	proxyCA        *ca
	upstreamCA     *ca

	workers    int
	allowExtra []string
	secrets    []secretSpec
	// mcpEnabled (WithMCP) boots the workers with the MCP gateway in monitor
	// mode, so WebSocket/SSE scenarios ride the worker's real stream paths.
	mcpEnabled bool

	// inflights is one quiescence tracker per worker (the assembly-only
	// worker.Overrides.Inflight seam): every request scope enters at request-read
	// and leaves only after its terminal bookkeeping. The oracles wait for every
	// tracker to drain BEFORE flushing and reading, which is what makes
	// h.Events()/h.Metrics()/h.Logs() deterministic instead of outwaiting the
	// proxy's post-response record (#363). Empty for targets without in-process
	// workers (compose): their oracles wait on the target itself.
	inflights []*proxy.Inflight
	// quiescenceDeadline bounds the oracles' drain wait (WithQuiescenceDeadline
	// overrides the default); expiring it fails the test naming what is still
	// in flight — never a silent short read.
	quiescenceDeadline time.Duration
	// beforeTerminal (withBookkeepingDelay / withBeforeTerminal, test-only) is
	// installed as the workers' proxy terminal-bookkeeping hook
	// (worker.Overrides.BeforeTerminal): the deterministic repro/trap for the
	// #363 window a red test can rely on.
	beforeTerminal func()

	// cpDownAtBoot (ControlPlaneDownAtBoot) starts the workers while the control
	// plane is unreachable.
	cpDownAtBoot bool

	// suppliedTarget, when set (WithTarget), replaces the in-process target:
	// boot mints the CAs and the clock as always but starts THIS instead.
	suppliedTarget Target
	target         Target

	fake   *clocktest.Fake
	dialer *mappingDialer
	// metricReaders is one in-process OTel reader per worker (a reader can be
	// attached to exactly one meter provider, so a fleet needs one each); the
	// target's Metrics() merges them into the fleet-wide view.
	metricReaders []*sdkmetric.ManualReader

	mu        sync.Mutex
	upstreams map[string]*Upstream
	// flushers is one analytics drain handle per worker (worker-N -> its async
	// writer's Flush), captured through the assembly-only OnAnalyticsWriter
	// seam. h.Events() flushes them all before reading, so a scenario's events
	// are readable deterministically instead of outwaiting the 250ms tick — and
	// a FAILED write comes back as an error, so the oracle fails the test
	// instead of reading a short list.
	flushers map[int]func() error

	agentOnce sync.Once
	agentCl   *http.Client
	h2Once    sync.Once
	agentH2Cl *http.Client
	agentRecs []RecordedResponse

	cpOnce sync.Once
	cpCl   *CPClient

	// flavors are singletons per harness: two calls to h.FakeLLM() hand back
	// the same fake, not a second server on the same name.
	llmOnce  sync.Once
	llm      *FakeLLM
	mcpOnce  sync.Once
	mcpU     *Upstream
	grpcOnce sync.Once
	grpcU    *Upstream
	wsOnce   sync.Once
	wsU      *Upstream

	// leakCheck (on by default, NoLeakCheck opts out) fails the test at cleanup
	// if the harness left goroutines behind; leakBaseline is the count captured
	// before boot started anything.
	leakCheck    bool
	leakBaseline int

	cleanOnce sync.Once
}

// Option customizes a harness at New time. Options are the ONLY way to
// configure the harness — that is what keeps a scenario's setup greppable.
type Option func(*H)

// Local boots one worker (the default; explicit for readability).
func Local() Option {
	return func(h *H) { h.workers = 1 }
}

// Fleet boots n workers behind the one shared control plane, numbered
// worker-1..worker-n. It panics on n < 1 — a fleet of zero is a typo, not a
// scenario.
func Fleet(n int) Option {
	return func(h *H) {
		if n < 1 {
			panic(fmt.Sprintf("harness: Fleet(%d): need at least one worker", n))
		}
		h.workers = n
	}
}

// Allow adds domains to the control-plane-served allowlist (exact names,
// "*.suffix" wildcards or "~regex", the policy dialect). The harness ships
// with only its own fake hostnames allowed; everything else is default-deny.
// If you called h.Upstream("payments.internal"), call Allow("payments.internal")
// — the harness never allows on your behalf.
func Allow(domains ...string) Option {
	return func(h *H) { h.allowExtra = append(h.allowExtra, domains...) }
}

// WithSecret registers a placeholder the worker can swap: the agent writes
// h.Placeholder(name), the worker replaces it with value — resolved from the
// env var the harness sets (the env backend, as in production) — for the
// given matchHosts (empty = any host). The value stays OUT of the agent's
// reach; if it ever reaches the agent, logs, events, metrics or an upstream
// that is not in matchHosts, AssertCanaryNeverLeaked fails the test.
func WithSecret(name, value string, matchHosts ...string) Option {
	return func(h *H) {
		h.tb.Setenv("WARDEN_HARNESS_SECRET_"+sanitizeEnvName(name), value)
		h.secrets = append(h.secrets, secretSpec{
			name:        name,
			placeholder: placeholderOf(name),
			value:       value,
			matchHosts:  matchHosts,
		})
	}
}

// RotateSecret changes the real value behind a WithSecret name — the env var the
// worker's secret backend reads, exactly what an operator does before calling
// POST /admin/refresh-secrets. The OLD value stays registered with the canary
// oracle (it must still never leak) alongside the new one. The in-process target
// reads the env of this process; it fails the test for an unknown name.
func (h *H) RotateSecret(name, value string) {
	h.tb.Helper()
	for _, s := range h.secrets {
		if s.name != name {
			continue
		}
		h.tb.Setenv("WARDEN_HARNESS_SECRET_"+sanitizeEnvName(name), value)
		h.secrets = append(h.secrets, secretSpec{
			name:        name,
			placeholder: s.placeholder,
			value:       value,
			matchHosts:  s.matchHosts,
		})
		return
	}
	h.tb.Fatalf("harness: RotateSecret(%q): no such WithSecret", name)
}

// WithTarget boots the harness against a caller-supplied Target instead of the
// default in-process one. Everything H does — the addresses, the control-plane
// client, the outage fault, the oracles — goes through the Target interface,
// so a scenario body is identical either way; this is the seam #351's compose
// target plugs into. boot still mints the CAs and the fake clock (the
// harness-side trust and time), then starts the target.
func WithTarget(t Target) Option {
	return func(h *H) { h.suppliedTarget = t }
}

// WithQuiescenceDeadline overrides how long the oracles wait for every worker's
// in-flight request scopes to drain before failing with the work named (the
// default is 10s; a scenario that deliberately parks traffic shortens it).
func WithQuiescenceDeadline(d time.Duration) Option {
	return func(h *H) { h.quiescenceDeadline = d }
}

// withBookkeepingDelay is the TEST-ONLY repro of #363 (assembly-only: it rides
// worker.Overrides.BeforeTerminal, which no YAML key or CLI flag can set): the
// workers' proxy spends d at the top of its terminal bookkeeping — after the
// response is already in the agent's hands — so a test can prove the oracles
// WAIT for that bookkeeping instead of racing it.
func withBookkeepingDelay(d time.Duration) Option {
	return func(h *H) {
		h.beforeTerminal = func() { time.Sleep(d) }
	}
}

// withBeforeTerminal installs f as the workers' proxy terminal-bookkeeping hook
// (worker.Overrides.BeforeTerminal), called at the top of every event, metric
// and decision-log record. Test-only: a scenario parks terminal bookkeeping in
// f at a deterministic point — the #363 window, after the response is delivered
// and before the event exists — and observes the quiescence tracker around it.
func withBeforeTerminal(f func()) Option {
	return func(h *H) { h.beforeTerminal = f }
}

// WithMCP boots the workers with the MCP gateway in monitor mode, so scenarios
// exercise the worker's real streaming paths (WebSocket upgrade, SSE relay)
// against the harness's ws.example.com / mcp.example.com fakes. Monitor mode
// never blocks: egress behaves exactly as without MCP.
func WithMCP() Option {
	return func(h *H) { h.mcpEnabled = true }
}

// ControlPlaneDownAtBoot boots the workers while the control plane is
// unreachable — the fail-closed-at-boot fault. The control plane's address is
// reserved (so the workers are configured against it) and then released before
// any worker starts; h.CP().Start() brings it up on that same address. Only the
// in-process target can do this: a supplied Target (WithTarget) fails the test.
func ControlPlaneDownAtBoot() Option {
	return func(h *H) { h.cpDownAtBoot = true }
}

// NoLeakCheck opts out of the built-in goroutine-leak check: by default New's
// cleanup fails the test when the harness leaves goroutines behind (every
// scenario gets the check; a scenario that knowingly tolerates a straggler —
// or a custom Target that manages processes externally — opts out here).
func NoLeakCheck() Option {
	return func(h *H) { h.leakCheck = false }
}

// Placeholder returns the literal token an agent uses to stand in for the
// named secret ({{name}}). Placeholders are matched byte-for-byte by the
// worker's swap stage.
func (h *H) Placeholder(name string) string { return placeholderOf(name) }

// placeholderOf backs Placeholder; scenarios use the method.
func placeholderOf(name string) string {
	return "{{" + name + "}}"
}

// New boots a harness for t: control plane first, then the workers, blocking
// until every component reports OnReady (a 10s budget each — never a sleep).
// It fails t on any boot error and registers a cleanup that stops everything,
// waits for each Run to return, and runs the goroutine-leak check.
//
// The cleanup is registered BEFORE boot, so a boot that fails partway still
// stops whatever started. New cannot be used from a t.Parallel() test (fixed
// env names, see the package comment) and fails clearly if it is.
func New(t testing.TB, opts ...Option) *H {
	t.Helper()
	assertNotParallel(t)
	h := &H{
		tb:                 t,
		root:               t.TempDir(),
		workers:            1,
		upstreams:          make(map[string]*Upstream),
		flushers:           make(map[int]func() error),
		quiescenceDeadline: defaultQuiescenceDeadline,
		leakCheck:          true,
	}
	for _, opt := range opts {
		opt(h)
	}
	// Baseline BEFORE boot: only goroutines the harness itself starts can
	// outlive it.
	h.leakBaseline = runtime.NumGoroutine()
	// Registered BEFORE boot: a boot that fails partway (t.Fatalf below) still
	// unwinds through this cleanup, which stops what started.
	t.Cleanup(h.cleanup)
	h.boot()
	return h
}

// assertNotParallel fails the test when New is called from a t.Parallel() test.
// testing.T's parallel flag is unexported, so this reads it by name and stays
// silent when a future Go renames it (the doc above still covers the rule).
func assertNotParallel(t testing.TB) {
	t.Helper()
	v := reflect.Indirect(reflect.ValueOf(t))
	if v.Kind() != reflect.Struct {
		return
	}
	f := v.FieldByName("isParallel")
	if f.IsValid() && f.Kind() == reflect.Bool && f.Bool() {
		t.Fatal("harness: New cannot run in a t.Parallel() test: every harness in a process " +
			"boots its components from fixed env names (WARDEN_HARNESS_*), which parallel tests " +
			"sharing the process would overwrite for each other. Run harness scenarios serially.")
	}
}

// boot mints the CAs, writes the control plane's config, builds the target and
// starts it. Any failure is a test failure with the component named.
func (h *H) boot() {
	h.proxyCA = newCA(h.tb, "warden-harness-proxy-ca")
	h.proxyCACertDst, h.proxyCAKeyDst = h.proxyCA.write(h.tb, h.root, "proxy-ca")
	h.upstreamCA = newCA(h.tb, "warden-harness-upstream-ca")

	h.fake = clocktest.NewFake(time.Now())
	h.metricReaders = make([]*sdkmetric.ManualReader, h.workers)
	for i := range h.metricReaders {
		h.metricReaders[i] = sdkmetric.NewManualReader()
	}
	// One quiescence tracker per worker, handed to each boot through the
	// assembly-only Overrides seam. The oracles wait for all of them to drain
	// before reading; a supplied (compose) target has no in-process workers and
	// simply leaves the slice unused.
	h.inflights = make([]*proxy.Inflight, h.workers)
	for i := range h.inflights {
		h.inflights[i] = proxy.NewInflight()
	}

	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		h.tb.Fatalf("harness: generate control-plane token: %v", err)
	}
	h.tb.Setenv(cpTokenEnv, hex.EncodeToString(token))

	h.dialer = &mappingDialer{h: h}

	if h.suppliedTarget != nil {
		if h.cpDownAtBoot {
			h.tb.Fatalf("harness: ControlPlaneDownAtBoot is an in-process fault; it cannot combine with WithTarget")
		}
		h.target = h.suppliedTarget
		fatalfOn(h.tb, h.target.Start(context.Background()))
		return
	}

	ip := h.buildInprocessTarget()
	ip.cpDownAtBoot = h.cpDownAtBoot
	h.target = ip
	fatalfOn(h.tb, h.target.Start(context.Background()))
}

// buildInprocessTarget assembles the default Target: the control plane's
// process params plus one workerProc per worker. Called from boot; the
// components start inside target.Start.
func (h *H) buildInprocessTarget() *inprocess {
	workers := make([]*workerProc, 0, h.workers)
	dbPaths := make([]string, 0, h.workers)
	for i := 1; i <= h.workers; i++ {
		i := i
		workers = append(workers, &workerProc{
			name:     fmt.Sprintf("worker-%d", i),
			paramsFn: func() worker.Params { return h.workerParams(i) },
			logs:     &logBuffer{},
		})
		dbPaths = append(dbPaths, h.workerDBPath(i))
	}

	ip := &inprocess{
		cp: &cpProc{
			addr: "127.0.0.1:0", // loopback, ephemeral; the cert's SAN is 127.0.0.1
			params: controlplane.Params{
				ConfigPath:        h.writeCPConfig(),
				TokenEnv:          cpTokenEnv,
				CACert:            h.proxyCACertDst,
				CAKey:             h.proxyCAKeyDst,
				TLSHost:           "127.0.0.1",
				MaxEvents:         10000,
				AnalyticsProvider: "memory",
				// The CP derives its alerts store from the ANALYTICS db path even
				// in memory mode (detection is on by default). Without these, both
				// default to the process working directory — the harness package
				// dir — and a test run litters it with SQLite files.
				AnalyticsDB: filepath.Join(h.root, "cp-fleet.db"),
				AlertsDB:    filepath.Join(h.root, "cp-alerts.db"),
			},
			logs: &logBuffer{},
		},
		workers:  workers,
		dbPaths:  dbPaths,
		readers:  h.metricReaders,
		caPool:   h.proxyCA.pool(),
		tokenEnv: cpTokenEnv,
	}
	return ip
}

// writeCPConfig writes the control plane's YAML: the allowlist the workers'
// pulled policy is projected from, plus info-level JSON logging so h.Logs()
// mirrors a production deployment's parseable output.
func (h *H) writeCPConfig() string {
	var b strings.Builder
	b.WriteString("logging:\n  level: info\n  format: json\n\npolicy:\n  allowlist:\n")
	for _, d := range h.allowDomains() {
		fmt.Fprintf(&b, "    - domain: %s\n", d)
	}
	path := filepath.Join(h.root, "cp-config.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		h.tb.Fatalf("harness: write control-plane config: %v", err)
	}
	return path
}

// allowDomains is the effective allowlist: the harness's fake hostnames plus
// every Allow() addition, deduplicated in order.
func (h *H) allowDomains() []string {
	all := append(append([]string{}, defaultAllowlist...), h.allowExtra...)
	seen := make(map[string]bool, len(all))
	out := make([]string, 0, len(all))
	for _, d := range all {
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// workerParams builds worker i's boot parameters: a Go-built policy through
// the same ConfigProvider interface production loads YAML through, and the
// assembly-only overrides (mapping dialer, upstream CA pool, fake clock,
// in-process metric reader, analytics drain handle). Called from workerProc.start
// AFTER the control plane is up — the endpoint embeds the CP's bound address.
func (h *H) workerParams(i int) worker.Params {
	entries := make([]config.AllowlistEntry, 0, len(defaultAllowlist)+len(h.allowExtra))
	for _, d := range h.allowDomains() {
		entries = append(entries, config.AllowlistEntry{Domain: d})
	}
	mappings := make([]config.SecretMapping, 0, len(h.secrets))
	for _, s := range h.secrets {
		mappings = append(mappings, config.SecretMapping{
			Placeholder: s.placeholder,
			EnvVar:      "WARDEN_HARNESS_SECRET_" + sanitizeEnvName(s.name),
			MatchHosts:  s.matchHosts,
		})
	}
	policy := config.Policy{
		Allowlist: entries,
		// A production-like secret cache: at 0 every request refetches, and a
		// refresh endpoint that does nothing would go unnoticed.
		CacheTTLSeconds: 3600,
		LogLevel:        "info",
		LogFormat:       "json",
		Secrets:         mappings,
		Observability:   config.ObservabilityConfig{Enabled: true, ServiceName: "warden-harness"},
		ControlPlane: config.ControlPlaneConfig{
			Endpoint:          "https://" + h.ControlPlaneAddr() + "/policy",
			TokenEnv:          cpTokenEnv,
			CACert:            h.proxyCACertDst,
			PollInterval:      time.Second,
			LongPollWait:      50 * time.Millisecond,
			HeartbeatInterval: time.Second,
		},
		Central: config.CentralConfig{ProxyID: fmt.Sprintf("worker-%d", i)},
	}
	if h.mcpEnabled {
		// Monitor mode: the worker's streaming paths (WS upgrade, SSE relay)
		// run with the real gateway in front, which never blocks.
		policy.MCP = config.MCPConfig{Enabled: true, Mode: "monitor"}
	}
	// The local allowlist mirrors the CP's. A managed worker ignores it (policy
	// comes only from the control plane) but keeping the two in sync means a
	// scenario's intent reads the same whichever mode boots.
	return worker.Params{
		Config:  &fakes.FakeConfigProvider{Policy: policy},
		DBPath:  h.workerDBPath(i),
		CACert:  h.proxyCACertDst,
		CAKey:   h.proxyCAKeyDst,
		Version: "harness",
		Overrides: &worker.Overrides{
			Dialer:          h.dialer,
			UpstreamRootCAs: h.upstreamCA.pool(),
			Clock:           h.fake,
			MetricsReader:   h.metricReaders[i-1],
			OnAnalyticsWriter: func(f worker.AnalyticsFlusher) {
				h.setFlusher(i, f.Flush)
			},
			// The quiescence tracker (#363): the oracles wait for this worker's
			// in-flight scopes to drain before flushing and reading. BeforeTerminal
			// is nil unless a test opted into the deterministic #363 repro/trap.
			Inflight:       h.inflights[i-1],
			BeforeTerminal: h.beforeTerminal,
		},
	}
}

// workerDBPath is worker i's analytics SQLite file (the Events oracle opens it
// read-only through the analytics store).
func (h *H) workerDBPath(i int) string {
	return filepath.Join(h.root, fmt.Sprintf("worker-%d.db", i))
}

// setFlusher records worker i's analytics drain handle (assembly seam). Called
// from the worker's boot, inside target.Start — before New returns.
func (h *H) setFlusher(i int, flush func() error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.flushers[i] = flush
}

// flushAnalytics drains every worker's async analytics queue, so the events of
// traffic a scenario has FINISHED making are readable without outwaiting the
// 250ms flush tick. A worker whose batch write FAILED is returned as an error —
// a failed flush never acks as persisted, so the caller fails the test instead
// of reading a short list. No-op for targets without in-process workers
// (compose; their Events must flush or wait themselves).
func (h *H) flushAnalytics() error {
	h.mu.Lock()
	ids := make([]int, 0, len(h.flushers))
	for i := range h.flushers {
		ids = append(ids, i)
	}
	sort.Ints(ids)
	flushers := make([]func() error, 0, len(ids))
	for _, i := range ids {
		flushers = append(flushers, h.flushers[i])
	}
	h.mu.Unlock()
	var errs []error
	for _, f := range flushers {
		if err := f(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ProxyAddr is worker-1's proxy address (host:port) — the one a Local harness
// or a single-agent scenario points at.
func (h *H) ProxyAddr() string { return h.target.ProxyAddr() }

// ProxyAddrs lists every worker's proxy address, worker-1 first.
func (h *H) ProxyAddrs() []string { return h.target.ProxyAddrs() }

// AdminAddr is worker-1's admin/dashboard address.
func (h *H) AdminAddr() string { return h.target.AdminAddr() }

// ControlPlaneAddr is the control plane's HTTPS address.
func (h *H) ControlPlaneAddr() string { return h.target.ControlPlaneAddr() }

// Target is the deployment behind this harness — the in-process one by
// default, or whatever WithTarget supplied. Scenarios and oracles go through
// this interface only, so #351's compose target swaps in without touching a
// scenario body.
func (h *H) Target() Target { return h.target }

// Eventually polls cond every few milliseconds until it holds or the 10s
// deadline passes, then fails with desc. Every harness wait goes through here
// (or EventuallyWithin) — the package contains no fixed sleeps.
func (h *H) Eventually(desc string, cond func() bool) {
	h.EventuallyWithin(readyDeadline, desc, cond)
}

// EventuallyWithin is Eventually with an explicit deadline.
func (h *H) EventuallyWithin(timeout time.Duration, desc string, cond func() bool) {
	h.tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		<-time.After(5 * time.Millisecond)
	}
	h.tb.Fatalf("harness: timed out after %s waiting for %s", timeout, desc)
}

// cleanup stops everything in dependency order — the target's workers first
// (they long-poll the control plane), then the control plane, then the fake
// upstreams (harness-owned, whatever the target is) — waits for every Run to
// return, and runs the goroutine-leak check. It also surfaces an unexpected
// mid-test exit: a component that died while the test was still running is a
// bug to report, so the failure carries the component's last logs.
func (h *H) cleanup() {
	h.cleanOnce.Do(func() {
		if h.target != nil {
			if err := h.target.Stop(); err != nil {
				h.tb.Errorf("harness: %v\nlast logs:\n%s", err, tail(h.target.Logs(), 2000))
			}
		}
		h.mu.Lock()
		ups := h.upstreams
		h.upstreams = make(map[string]*Upstream)
		h.mu.Unlock()
		for _, u := range ups {
			u.close()
		}
		if h.agentCl != nil {
			h.agentCl.CloseIdleConnections()
		}
		if h.agentH2Cl != nil {
			h.agentH2Cl.CloseIdleConnections()
		}
		if h.cpCl != nil {
			h.cpCl.CloseIdleConnections()
		}
		h.checkGoroutines()
	})
}

// checkGoroutines is the built-in leak check: anything still running that the
// harness started (baseline was captured before boot) fails the test with its
// stack. A short settle window absorbs goroutines that are ON their way out —
// a Run that returned after the last stop but whose goroutine the scheduler
// has not reaped yet is not a leak.
func (h *H) checkGoroutines() {
	if !h.leakCheck {
		return
	}
	// Count gate: if the process holds no more goroutines than it did before
	// boot, the harness cannot have left any behind. This is what keeps the
	// check from flagging goroutines that predate the harness — e.g. a parent
	// test goroutine still blocked in t.Run while a subtest's harness cleans
	// up — which stack filtering alone cannot attribute.
	if runtime.NumGoroutine() <= h.leakBaseline {
		return
	}
	leaked := harnessGoroutineLeaks()
	if len(leaked) == 0 {
		return
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		<-time.After(10 * time.Millisecond)
		if leaked = harnessGoroutineLeaks(); len(leaked) == 0 {
			return
		}
	}
	h.tb.Errorf("the harness leaked %d goroutine(s):\n%s", len(leaked), strings.Join(leaked, "\n\n---\n"))
}

// harnessGoroutineLeaks dumps all goroutine stacks and returns the blocks that
// are NOT the signal pump and NOT the test binary's own machinery — i.e. the
// blocks that constitute a real harness leak.
//
// One residue is allowed and documented: the FIRST harness in the process
// leaves the OS signal-pump goroutine behind (os/signal's signal_recv loop) —
// production controlplane.Run arms signal.NotifyContext, and the pump that
// Notify starts is process-global, runs for the life of the process, and is
// unreachable from outside Run (its deferred stop only unregisters the
// channel, never the pump). It is started once per process, not once per
// harness, so subsequent harnesses leave nothing.
//
// Live TEST goroutines are filtered too: a parent still blocked in t.Run while
// a subtest's harness cleans up is the framework, not a harness leak — the
// harness never spawns goroutines with testing frames on their stacks.
func harnessGoroutineLeaks() []string {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	var out []string
	for _, block := range strings.Split(string(buf[:n]), "\n\n") {
		switch {
		case strings.Contains(block, "os/signal.signal_recv"):
			continue // the once-per-process signal pump (see above)
		case strings.HasPrefix(block, "goroutine 1 "):
			continue // the test binary's main goroutine
		case strings.Contains(block, "runCleanup"):
			continue // the cleanup goroutine doing this very check
		case strings.Contains(block, "testing.(*T).Run("), strings.Contains(block, "testing.tRunner("):
			continue // a live parent/subtest goroutine (see above)
		}
		out = append(out, block)
	}
	return out
}

// logBuffer is a mutex-guarded buffer standing in for a component's stdout:
// worker.Run and controlplane.Run write their structured logs here and the
// target's Logs() oracle reads them back. Writes come from the components'
// goroutines; reads come from the test.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// sanitizeEnvName maps a secret name to an env-var-safe suffix (uppercase,
// underscores for anything not alphanumeric), so WithSecret("openai") sets
// WARDEN_HARNESS_SECRET_OPENAI.
func sanitizeEnvName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// tail returns at most n trailing characters of s (for bounded log excerpts).
func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
