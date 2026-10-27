package harness

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/dnstest"
	"github.com/ethosagent/warden/internal/identity/identitytest"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// FakeEntry registers the fake and conformance suite for one port.
type FakeEntry struct {
	// Fake names the fake's constructor, for the coverage report.
	Fake string
	// New builds a fresh fake, seeded as its Conformance suite expects.
	New func(tb testing.TB) any
	// Conformance exercises the fake's behaviour through the port; fake is
	// whatever New returned.
	Conformance func(t *testing.T, fake any)
}

// entry adapts a typed constructor and suite to a FakeEntry.
func entry[T any](fake string, mk func(tb testing.TB) T, suite func(t *testing.T, f T)) FakeEntry {
	return FakeEntry{
		Fake:        fake,
		New:         func(tb testing.TB) any { return mk(tb) },
		Conformance: func(t *testing.T, f any) { suite(t, f.(T)) },
	}
}

// Fakes maps each port ("<package>.<Interface>", the key TestPortCoverage
// derives from ./internal) to its fake and conformance suite. A port interface
// whose name ends in one of portSuffixes, or is listed in namedPorts, must be
// here or in Excluded, or CI fails naming it. New external
// dependency: add the port, its fake (reuse test/fakes) and an entry.
var Fakes = map[string]FakeEntry{
	"config.ConfigProvider":    entry("fakes.FakeConfigProvider", newConfigProviderFake, configProviderConformance),
	"secrets.SecretProvider":   entry("fakes.FakeSecretProvider", newSecretProviderFake, secretProviderConformance),
	"secrets.SecretStore":      entry("fakes.NewFakeSecretStore", func(testing.TB) *fakes.FakeSecretStore { return fakes.NewFakeSecretStore() }, secretStoreConformance),
	"analytics.AnalyticsStore": entry("fakes.FakeAnalyticsStore", func(testing.TB) *fakes.FakeAnalyticsStore { return &fakes.FakeAnalyticsStore{} }, analyticsStoreConformance),
	"proxy.Dialer":             entry("harness mappingDialer (via New)", newDialerFake, dialerConformance),
	"proxy.NameResolver":       entry("dnstest.New + proxy.NewUpstreamResolver", newNameResolverFake, nameResolverConformance),
	"identity.Verifier":        entry("fakes.NewVerifier", func(testing.TB) *fakes.Verifier { return fakes.NewVerifier() }, verifierConformance),
	"clock.Clock":              entry("clocktest.NewFake", func(testing.TB) *clocktest.Fake { return clocktest.NewFake(time.Unix(1_700_000_000, 0)) }, clockConformance),
}

// Excluded lists interfaces the name rule matches that are NOT a boundary the
// harness has to fake, each with the reason. Adding one needs a reviewer to
// agree with the reason; an exclusion for an interface that no longer exists
// fails TestPortCoverage.
var Excluded = map[string]string{
	"analytics.FleetStore":            "the control plane's own persistent store; the harness runs the real one (analytics.NewFleetStore), a fake would hide ingest bugs",
	"analytics.RemoteStore":           "the worker->control-plane event sink; the only implementation is the HTTP client, and the harness runs the real control plane on loopback",
	"gateway.Store":                   "MCP gateway persistence, implemented by the real SQLite analytics store the harness already boots; not an external dependency",
	"dashboard.MCPProvider":           "read-only view of the in-process MCP gateway; no external system behind it",
	"llmpolicy.LLMClient":             "the judge's provider client; the production client will run against FakeLLM at the HTTP wire; the first judge scenario must add a harness option for judge config",
	"proxy.Judge":                     "the proxy's view of llmpolicy.Judge, whose provider client is covered by the llmpolicy.LLMClient exclusion; a fake Judge would skip the prompt and fail-closed path the scenarios must exercise",
	"dashboard.SQLGenerator":          "the Explore tab's NL->SQL surface, satisfied by the real *llm.Client; it will run against FakeLLM at the HTTP wire once a scenario drives Explore",
	"secrets.Fetcher":                 "the per-placeholder loader behind the env SecretProvider the harness already uses; the vendor Fetchers (AWS, GCP) are covered by their package tests",
	"integration.Alerter":             "outbound alert sinks (webhook, alertmanager) behind the alert pipeline; no L1 scenario drives alert delivery yet, and package tests cover them with httptest servers",
	"integration.EventStreamer":       "the raw event firehose sink, defined but not wired (M2); nothing calls it, so there is no boundary to fake yet",
	"secrets.AWSSecretsClient":        "vendor SDK adapter behind secrets.SecretStore/Fetcher; package tests fake it, and the harness resolves secrets through the env SecretProvider",
	"secrets.GCPSecretClient":         "vendor SDK adapter behind a Fetcher; package tests fake it, and the harness resolves secrets through the env SecretProvider",
	"controlplane.PolicyVersionStore": "the control plane's own versioned policy store on the cpstate SQLite DB; the harness runs the real one (--policy-store=versioned), a fake would hide the compare-and-swap and transaction behaviour",
	"worker.ControlPlaneClient":       "the worker's view of the control plane; the harness runs the real control plane (*config.RemoteProvider) rather than a fake",
}

// --- identity.Verifier ---

func verifierConformance(t *testing.T, f *fakes.Verifier) {
	identitytest.RunVerifierSuite(t, func(*testing.T) identitytest.Fixture { return fakes.VerifierSuiteFixture(f) })
}

// --- config.ConfigProvider ---

func newConfigProviderFake(testing.TB) *fakes.FakeConfigProvider {
	return &fakes.FakeConfigProvider{Policy: config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "api.example.com"}}}}
}

func configProviderConformance(t *testing.T, f *fakes.FakeConfigProvider) {
	var p config.ConfigProvider = f
	got, err := p.GetPolicy()
	if err != nil || len(got.Allowlist) != 1 || got.Allowlist[0].Domain != "api.example.com" {
		t.Fatalf("GetPolicy = %+v, %v; want the seeded allowlist", got, err)
	}
	boom := errors.New("boom")
	f.Err = boom
	if _, err := p.GetPolicy(); !errors.Is(err, boom) {
		t.Errorf("GetPolicy error = %v, want the injected error (fail-closed callers depend on it)", err)
	}
}

// --- secrets.SecretProvider ---

func newSecretProviderFake(testing.TB) *fakes.FakeSecretProvider {
	return &fakes.FakeSecretProvider{Values: map[string]string{"ph": "real", "ph2": "real2"}}
}

func secretProviderConformance(t *testing.T, f *fakes.FakeSecretProvider) {
	var p secrets.SecretProvider = f
	if v, err := p.GetSecret("ph"); err != nil || v != "real" {
		t.Fatalf("GetSecret(ph) = %q, %v; want the seeded value", v, err)
	}
	if v, err := p.GetSecret("ph2"); err != nil || v != "real2" {
		t.Fatalf("GetSecret(ph2) = %q, %v; each placeholder must read its own value", v, err)
	}
	if _, err := p.GetSecret("nope"); !errors.Is(err, secrets.ErrUnknownPlaceholder) {
		t.Errorf("GetSecret(unknown) error = %v, want ErrUnknownPlaceholder", err)
	}
	if err := p.RefreshSecrets(); err != nil {
		t.Errorf("RefreshSecrets = %v", err)
	}
	f.RefreshErr = errors.New("backend down")
	if err := p.RefreshSecrets(); err == nil {
		t.Error("RefreshSecrets must hard-fail when the backend does")
	}
}

// --- proxy.NameResolver ---

// nameResolverFake is the stub DNS server (internal/dnstest) with the
// production upstream resolver pointed at it: real DNS over a real UDP socket,
// no host resolver and no network.
type nameResolverFake struct {
	srv *dnstest.Server
	r   proxy.NameResolver
}

func newNameResolverFake(tb testing.TB) *nameResolverFake {
	t, ok := tb.(*testing.T)
	if !ok {
		tb.Fatalf("the dnstest-backed resolver fake needs a *testing.T, got %T", tb)
	}
	srv := dnstest.New(t, map[string]string{"known.example.com": "192.0.2.7"})
	return &nameResolverFake{srv: srv, r: proxy.NewUpstreamResolver(srv.Addr(), nil)}
}

func nameResolverConformance(t *testing.T, f *nameResolverFake) {
	r := f.r
	ips, err := r.LookupIPAddr(context.Background(), "known.example.com")
	if err != nil || len(ips) != 1 || !ips[0].IP.Equal(net.ParseIP("192.0.2.7")) {
		t.Fatalf("LookupIPAddr(known) = %v, %v; want the stub's 192.0.2.7", ips, err)
	}
	if f.srv.Queries.Load() == 0 {
		t.Error("the lookup never reached the stub server: the system resolver answered")
	}
	if _, err := r.LookupIPAddr(context.Background(), "missing.example.com"); err == nil {
		t.Error("an unknown name must fail to resolve, not fall back to another resolver")
	}
}

// --- secrets.SecretStore ---

func secretStoreConformance(t *testing.T, f *fakes.FakeSecretStore) {
	var s secrets.SecretStore = f
	ctx := context.Background()

	if _, err := s.Get(ctx, "k"); !errors.Is(err, secrets.ErrSecretNotFound) {
		t.Fatalf("Get(absent) error = %v, want ErrSecretNotFound", err)
	}
	if err := s.Put(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get(ctx, "k"); err != nil || v != "v1" {
		t.Fatalf("Get after Put = %q, %v", v, err)
	}
	if _, err := s.Get(ctx, "a"); !errors.Is(err, secrets.ErrSecretNotFound) {
		t.Errorf("Get of a key never Put (another key exists) error = %v, want ErrSecretNotFound", err)
	}
	if err := s.Put(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get(ctx, "k"); v != "v2" {
		t.Errorf("Put must upsert; Get = %q, want v2", v)
	}
	if err := s.Put(ctx, "a", "va"); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"k": "v2", "a": "va"} {
		if v, err := s.Get(ctx, key); err != nil || v != want {
			t.Errorf("Get(%s) = %q, %v; each key must read its own value %q", key, v, err, want)
		}
	}

	metas, err := s.List(ctx)
	if err != nil || len(metas) != 2 || metas[0].Key != "a" || metas[1].Key != "k" {
		t.Fatalf("List = %+v, %v; want keys [a k]", metas, err)
	}
	for _, m := range metas {
		if m.Version == "" {
			t.Errorf("List(%s) has no version", m.Key)
		}
	}
	if metas[1].Version == "" || metas[1].Version == metas[0].Version {
		t.Errorf("a second Put must change the version: %+v", metas)
	}

	if err := s.Delete(ctx, "k"); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Get(ctx, "a"); err != nil || v != "va" {
		t.Errorf("Delete(k) must leave a alone; Get(a) = %q, %v", v, err)
	}
	if err := s.Delete(ctx, "k"); err != nil {
		t.Errorf("Delete of an absent key must be idempotent, got %v", err)
	}
	if _, err := s.Get(ctx, "k"); !errors.Is(err, secrets.ErrSecretNotFound) {
		t.Errorf("Get after Delete error = %v, want ErrSecretNotFound", err)
	}
}

// --- analytics.AnalyticsStore ---

func analyticsStoreConformance(t *testing.T, f *fakes.FakeAnalyticsStore) {
	var s analytics.AnalyticsStore = f
	for _, e := range []analytics.Event{
		{Domain: "a.com", Decision: "allow"},
		// A deny carries a declared reason: the fake enforces the #409 contract.
		{Domain: "b.com", Decision: "deny", Reason: string(denyreason.PolicyNoMatch)},
		{Domain: "a.com", Decision: "deny", Reason: string(denyreason.PolicyNoMatch)},
	} {
		if err := s.StoreEvent(e); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.GetEvents(analytics.EventFilter{})
	if err != nil || len(all) != 3 {
		t.Fatalf("GetEvents(all) = %d events, %v; want 3", len(all), err)
	}
	if all[0].Domain != "a.com" || all[0].Decision != "deny" {
		t.Errorf("events must come back newest first, got %+v first", all[0])
	}
	if got, _ := s.GetEvents(analytics.EventFilter{Domain: "a.com", Decision: "deny"}); len(got) != 1 {
		t.Errorf("Domain+Decision filter = %d events, want 1", len(got))
	}
	if got, _ := s.GetEvents(analytics.EventFilter{Limit: 2}); len(got) != 2 {
		t.Errorf("Limit 2 = %d events, want 2", len(got))
	}
}

// --- proxy.Dialer ---

// newDialerFake boots a harness and returns its mapping dialer with one fake
// upstream registered, because that dialer is the Dialer fake workers run on.
func newDialerFake(tb testing.TB) *mappingDialer {
	h := New(tb)
	h.Upstream("dial.example.com")
	return h.dialer
}

func dialerConformance(t *testing.T, d *mappingDialer) {
	var p proxy.Dialer = d

	if c, err := p.DialTLS("tcp", "unregistered.example.com:443", &tls.Config{RootCAs: d.h.upstreamCA.pool(), ServerName: "unregistered.example.com"}); err == nil {
		_ = c.Close()
		t.Error("DialTLS to a name with no fake must fail (default-deny stays in force)")
	}
	if c, err := p.Dial("tcp", "unregistered.example.com:80"); err == nil {
		_ = c.Close()
		t.Error("plain Dial to a name with no fake must fail (default-deny stays in force)")
	}
	if c, err := p.DialTLS("tcp", "dial.example.com:443", &tls.Config{ServerName: "dial.example.com"}); err == nil {
		_ = c.Close()
		t.Error("DialTLS without the upstream root pool must fail, not trust the system pool")
	}
	// Plain Dial to a REGISTERED fake routes to its plain twin: the transparent
	// :80 path's upstream hop is http (#376), so the fake must answer plain
	// HTTP too — but still only for names the scenario registered.
	if c, err := p.Dial("tcp", "dial.example.com:80"); err != nil {
		t.Errorf("plain Dial to the registered fake: %v", err)
	} else {
		_ = c.Close()
	}

	conn, err := p.DialTLS("tcp", "dial.example.com:443", &tls.Config{RootCAs: d.h.upstreamCA.pool(), ServerName: "dial.example.com"})
	if err != nil {
		t.Fatalf("DialTLS to the registered fake: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got := conn.ConnectionState().ServerName; got != "dial.example.com" {
		t.Errorf("handshake ServerName = %q, want the fake host kept as SNI", got)
	}
}

// --- clock.Clock ---

func clockConformance(t *testing.T, f *clocktest.Fake) {
	var c clock.Clock = f
	start := c.Now()

	after := c.After(time.Minute)
	timer := c.NewTimer(2 * time.Minute)
	stopped := c.NewTimer(time.Hour)
	if !stopped.Stop() {
		t.Error("Stop of a pending timer must report true")
	}

	select {
	case <-after:
		t.Fatal("After fired before the clock advanced")
	default:
	}
	f.Advance(time.Minute)
	if got := c.Now(); !got.Equal(start.Add(time.Minute)) {
		t.Errorf("Now after Advance(1m) = %v, want %v", got, start.Add(time.Minute))
	}
	select {
	case at := <-after:
		if !at.Equal(start.Add(time.Minute)) {
			t.Errorf("After delivered %v, want its deadline %v", at, start.Add(time.Minute))
		}
	default:
		t.Error("After(1m) did not fire at +1m")
	}
	select {
	case <-timer.C():
		t.Fatal("the 2m timer fired at +1m")
	default:
	}
	f.Advance(time.Minute)
	select {
	case <-timer.C():
	default:
		t.Error("the 2m timer did not fire at +2m")
	}
	if timer.Stop() {
		t.Error("Stop of a fired timer must report false")
	}
	if timer.Reset(time.Second); f.PendingTimers() != 1 {
		t.Errorf("Reset must re-arm the timer; pending = %d, want 1", f.PendingTimers())
	}
	f.Advance(time.Second)
	select {
	case <-timer.C():
	default:
		t.Error("a Reset timer did not fire after its new duration")
	}
}
