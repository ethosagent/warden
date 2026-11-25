package security

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
	keysigner "github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/worker"
	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Fixed names of the stack. Cases refer to them instead of hard-coding strings.
const (
	// UpstreamHost is the allowlisted destination every worker egresses to. The
	// workers' assembly-only Dialer maps it to the fakes.Upstream.
	UpstreamHost = "api.example.com"

	// SwappedPlaceholder is what the agent sends; the worker swaps it for the
	// canary value of SwappedSecret on UpstreamHost only.
	SwappedPlaceholder = "swapped_secret_001"
	// SwappedSecret is the planted real secret. It may appear in an upstream
	// request of an allowed case and nowhere else.
	SwappedSecret = "sk-security-canary-swapped-secret-7f3a91"

	// IdentityAudience and IdentityAZP are what the workers' identity block
	// expects of a user's ID token (MintUserToken stamps both).
	IdentityAudience = "warden"
	IdentityAZP      = "agent-harness"

	// ConsoleClientID, ConsoleAdminGroup and ConsoleViewerGroup are the
	// console OIDC client and the groups console.roles maps.
	ConsoleClientID    = "warden-console"
	ConsoleAdminGroup  = "console-admins"
	ConsoleViewerGroup = "console-viewers"

	// TrustDomain is the SPIFFE trust domain of the worker CA.
	TrustDomain = "warden.test"

	// TokenIssuer is tokenService.issuer: the loopback http origin the config
	// accepts. The client assertion audience is TokenIssuer + "/oauth2/token".
	TokenIssuer = "http://localhost"

	// TokenRateDefault is the harness's raised tokenService.rateLimit, high
	// enough that no matrix case trips it by accident.
	TokenRateDefault = "100000/minute"

	consoleSecretEnv = "WARDEN_SECURITY_CONSOLE_SECRET"
	swappedEnv       = "WARDEN_SECURITY_SWAPPED_SECRET"
	readyDeadline    = 20 * time.Second
	stopDeadline     = 15 * time.Second
)

// StackOptions tunes the stack. The zero value is the production-shaped
// topology of the security feature doc.
type StackOptions struct {
	// Agents are the agent ids the workers are bound to through
	// central.agentID, one worker each. Default: agent-a, agent-b.
	Agents []string
	// IdentityMode is identity.defaultMode the CP distributes. Default
	// "require": a worker refuses a CONNECT without a valid bound Warden token
	// with a 407, and terminated traffic with a 403.
	IdentityMode string
	// LongPollWait is controlPlane.longPollWait on the workers. Default 2s.
	LongPollWait time.Duration
	// EchoSecretStore turns on the CP's echo secret store, which mounts
	// /central/secrets. Workers then resolve every secret to its placeholder,
	// so the swapped-secret assertions do not hold: only the route-boundary
	// cases that need the route set it.
	EchoSecretStore bool
	// UnboundWorker adds a third worker with no central.agentID, named
	// worker-unbound: its agent id is the derived agent:<port>, which no
	// registry lists. Reach it with Stack.Worker("worker-unbound").
	UnboundWorker bool
	// NoCA starts every worker without a MITM CA, so a tunnel is raw (opaque,
	// bound at CONNECT only). The workers' clients then talk TLS to the
	// upstream directly.
	NoCA bool
	// DefaultTokenRate keeps tokenService.rateLimit at the production defaults
	// instead of the raised harness limit (the rate-limit case needs it).
	DefaultTokenRate bool
	// CPEndpoint, when set, is called for every worker before its config is
	// written and returns the host:port that worker dials as its control
	// plane ("" keeps the real CP). It is how a case puts a TamperProxy
	// between one worker and the CP: the func builds the proxy and returns
	// its address. It lives here, in the test package, and adds no seam to
	// production: the endpoint is an ordinary controlPlane.endpoint.
	CPEndpoint func(s *Stack, w *Worker) string
	// PinBundleIssuer sets controlPlane.bundleIssuer on every worker to the
	// CP's id, so a bundle signed by a pinned key for another CP is rejected
	// as issuer_mismatch. The id is read from the CP's state once it exists.
	PinBundleIssuer bool
	// AcceptDexTokens is identity.acceptDexTokens the CP distributes; nil
	// leaves it unset (true while identity.issuer is set).
	AcceptDexTokens *bool
	// ClockSkewSeconds is identity.clockSkewSeconds (0 = the default, 60).
	ClockSkewSeconds int
	// AgentModes maps an agent id to its own identity mode (the agents: block
	// of the CP config), overriding IdentityMode for that agent.
	AgentModes map[string]string
	// DebugCP logs the control plane at debug level, which is where the token
	// endpoint records the reason of a refusal whose client assertion did not
	// verify (no token_events row exists for it).
	DebugCP bool
}

// Stack is one running security stack: a control plane booted through
// controlplane.Run, two workers booted through worker.Run, and the fakes they
// talk to. Everything runs in this process on loopback; time is a fake clock
// every component shares, advanced by the test only on a condition.
//
// A Stack must not be used from a t.Parallel test: every worker reads its
// enrollment token from an environment variable (controlPlane.enrollment.
// tokenEnv) the stack sets with t.Setenv, and t.Setenv is incompatible with
// t.Parallel. The suite runs serially; that is by design.
type Stack struct {
	tb   testing.TB
	root string
	logs *logBuffer
	opts StackOptions

	// Clock is the fake clock the CP, the workers and the issuer share.
	Clock *clocktest.Fake
	// Issuer is the in-process OIDC provider: console login and user tokens.
	Issuer *fakes.OIDCIssuer
	// Upstream is the destination fake behind UpstreamHost.
	Upstream *fakes.Upstream
	// CPCA signs the control plane's TLS certificate; the workers and every
	// client pin it. ProxyCA is the workers' MITM CA, UpstreamCA signs the
	// upstream's certificate.
	CPCA, ProxyCA, UpstreamCA *harness.TestCA

	// CP is the control plane under test.
	CP *CP
	// Workers are the enrolled workers, in StackOptions.Agents order.
	Workers []*Worker

	tracker *tracker
	// id makes the stack's environment variable names unique.
	id string

	// wcaInter and wcaKey are the worker CA intermediate the CP issues from:
	// a case signs hostile worker certificates that still chain to it.
	wcaInter *x509.Certificate
	wcaKey   *ecdsa.PrivateKey
	// bundleIssuer is the CP id workers pin when PinBundleIssuer is set.
	bundleIssuer string
	// kv is scratch state a case's Attack shares with its test.
	kv sync.Map

	mu       sync.Mutex
	cps      *controlplane.Server
	km       *keys.Manager
	admin    *Session
	agents   map[string]*Agent
	controls map[string]bool
	scratch  map[string]any
}

// Put keeps v under key for the rest of the test: the state a Case.Setup
// builds for its Attack.
func (s *Stack) Put(key string, v any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scratch == nil {
		s.scratch = map[string]any{}
	}
	s.scratch[key] = v
}

// Get returns what Put kept under key (nil when nothing was).
func (s *Stack) Get(key string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scratch[key]
}

// CP is the running control plane.
type CP struct {
	// Addr is host:port; URL the https origin.
	Addr, URL string
	// HTTP trusts the CP CA and presents no credential.
	HTTP *http.Client
	// StateDir holds warden-cp.db.
	StateDir string
	// CertFile is the CP CA certificate path (controlPlane.caCert).
	CertFile string

	cancel context.CancelFunc
	errCh  chan error
}

// Worker is one running worker.
type Worker struct {
	// Name is "worker-a" for agent-a. AgentID is its central.agentID.
	Name, AgentID string
	// ProxyAddr and AdminAddr are the loopback listeners.
	ProxyAddr, AdminAddr string
	// TokenEnv is the env var that held its enrollment token.
	TokenEnv string
	// StateDir is controlPlane.stateDir (the certificate lives in cert/).
	StateDir string
	// DBPath is its analytics store.
	DBPath string

	// Tamper is the proxy between this worker and the CP, when StackOptions.
	// CPEndpoint built one (see NewTamperProxy).
	Tamper *TamperProxy

	// inflight tracks the worker's request scopes until their terminal
	// bookkeeping (event, decision log, metrics) is done.
	inflight *proxy.Inflight

	flushMu sync.Mutex
	flush   func() error
	cancel  context.CancelFunc
	errCh   chan error
}

// StartStack boots the whole stack and returns when every component is ready:
// the CP serves and has published its first signed bundle, and each worker has
// enrolled, applied that bundle and reports warden_bundle_seq above 0. It
// waits only on OnReady callbacks, HTTP conditions and the metrics gauge,
// never on fixed sleeps, and it fails the test naming the component and its
// last logs when one does not come up.
func StartStack(tb testing.TB, opts StackOptions) *Stack {
	tb.Helper()
	s := StartStackNoWait(tb, opts)
	s.awaitBundles()
	return s
}

// StartStackNoWait is StartStack without the final readiness waits.
func StartStackNoWait(tb testing.TB, opts StackOptions) *Stack {
	tb.Helper()
	if len(opts.Agents) == 0 {
		opts.Agents = []string{"agent-a", "agent-b"}
	}
	if opts.IdentityMode == "" {
		opts.IdentityMode = "require"
	}
	if opts.LongPollWait == 0 {
		opts.LongPollWait = 2 * time.Second
	}
	s := &Stack{tb: tb, root: tb.TempDir(), logs: &logBuffer{}, opts: opts, tracker: newTracker(), id: randHex(tb)}
	s.Clock = clocktest.NewFake(time.Now())
	tb.Cleanup(s.stop)

	s.Issuer = fakes.NewOIDCIssuer(tb, fakes.WithIssuerClock(s.Clock.Now))
	s.CPCA = harness.NewTestCA(tb, "warden-security-cp-ca")
	s.ProxyCA = harness.NewTestCA(tb, "warden-security-proxy-ca")
	s.UpstreamCA = harness.NewTestCA(tb, "warden-security-upstream-ca")
	s.Upstream = fakes.NewUpstream(tb, s.UpstreamCA.ServerCert(UpstreamHost))
	for _, ca := range []*harness.TestCA{s.CPCA, s.ProxyCA, s.UpstreamCA} {
		s.tracker.add("key PEM", string(ca.KeyPEM()))
	}
	s.tracker.add("swapped secret", SwappedSecret)

	s.startCP()
	if opts.PinBundleIssuer {
		s.bundleIssuer = s.readCPID()
	}
	s.Issuer.RegisterClient(ConsoleClientID, consoleSecretValue)
	for _, agent := range opts.Agents {
		s.startWorker(agent)
	}
	if opts.UnboundWorker {
		s.startWorker("")
	}
	return s
}

// consoleSecretValue is the console OIDC client secret the issuer fake and the
// CP agree on. It is a test value, not a credential.
const consoleSecretValue = "security-console-client-secret"

// Server is the CP's in-process server handle (OnServer).
func (s *Stack) Server() *controlplane.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cps
}

// Keys is the CP's key manager (KeysReady): the token and bundle keys.
func (s *Stack) Keys() *keys.Manager {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.km
}

// Worker returns the worker bound to agentID, or the one named agentID (the
// unbound worker has no agent id: its name is worker-unbound).
func (s *Stack) Worker(agentID string) *Worker {
	s.tb.Helper()
	for _, w := range s.Workers {
		if w.AgentID == agentID && agentID != "" || w.Name == agentID {
			return w
		}
	}
	s.tb.Fatalf("security: no worker is bound to agent or named %q", agentID)
	return nil
}

// Eventually polls cond every few milliseconds until it holds or the deadline
// passes, then fails the test with desc. It never advances the clock.
func (s *Stack) Eventually(desc string, cond func() bool) {
	s.tb.Helper()
	s.EventuallyWithin(readyDeadline, desc, cond)
}

// EventuallyWithin is Eventually with an explicit deadline.
func (s *Stack) EventuallyWithin(timeout time.Duration, desc string, cond func() bool) {
	s.tb.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		<-time.After(5 * time.Millisecond)
	}
	s.tb.Fatalf("security: timed out after %s waiting for %s\nlast log lines:\n%s", timeout, desc, tail(s.logs.String(), 2500))
}

// EventuallyAdvance is Eventually that advances the shared fake clock by step
// whenever cond does not hold yet: the way to drive a loop that only moves
// with time (a poll tick, a token key's publish window) to a condition.
func (s *Stack) EventuallyAdvance(desc string, step time.Duration, cond func() bool) {
	s.tb.Helper()
	deadline := time.Now().Add(readyDeadline)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		s.Clock.Advance(step)
		<-time.After(5 * time.Millisecond)
	}
	s.tb.Fatalf("security: timed out waiting for %s\nlast log lines:\n%s", desc, tail(s.logs.String(), 2500))
}

// startCP renders the CP config, boots controlplane.Run and waits for OnReady.
func (s *Stack) startCP() {
	s.tb.Helper()
	dir := s.root
	stateDir := filepath.Join(dir, "cp-state")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.tb.Fatalf("security: listen for the control plane: %v", err)
	}
	addr := ln.Addr().String()
	certFile, keyFile := s.CPCA.WriteFiles(dir, "cp-ca")
	chain := s.writeWorkerCA(dir)
	s.tb.Setenv(consoleSecretEnv, consoleSecretValue)

	cfg := s.cpConfig(addr, chain)
	cfgPath := filepath.Join(dir, "cp-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		_ = ln.Close()
		s.tb.Fatalf("security: write the control plane config: %v", err)
	}

	ready := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	p := controlplane.Params{
		ConfigPath:         cfgPath,
		CACert:             certFile,
		CAKey:              keyFile,
		TLSHost:            "127.0.0.1",
		StateDir:           stateDir,
		MaxEvents:          10000,
		AnalyticsProvider:  "memory",
		AnalyticsDB:        filepath.Join(dir, "cp-fleet.db"),
		AlertsDB:           filepath.Join(dir, "cp-alerts.db"),
		PolicyStore:        "versioned",
		Bundles:            controlplane.BundlesRequire,
		RequireWorkerCerts: true,
		Listener:           ln,
		Clock:              s.Clock,
		OnReady:            func(a string) { ready <- a },
		OnServer: func(srv *controlplane.Server) {
			s.mu.Lock()
			s.cps = srv
			s.mu.Unlock()
		},
		KeysReady: func(m *keys.Manager) {
			s.mu.Lock()
			s.km = m
			s.mu.Unlock()
		},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- controlplane.Run(ctx, s.logs, p) }()
	select {
	case a := <-ready:
		addr = a
	case err := <-errCh:
		cancel()
		s.tb.Fatalf("security: the control plane exited before it was ready: %v\n%s", err, tail(s.logs.String(), 2500))
	case <-time.After(readyDeadline):
		cancel()
		<-errCh
		s.tb.Fatalf("security: the control plane did not report OnReady within %s\n%s", readyDeadline, tail(s.logs.String(), 2500))
	}
	pool := s.CPCA.Pool()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	s.tb.Cleanup(tr.CloseIdleConnections)
	s.CP = &CP{
		Addr: addr, URL: "https://" + addr, StateDir: stateDir, CertFile: certFile,
		HTTP:   harness.NewLoopbackClient(tr, harness.ClientOptions{Timeout: 30 * time.Second}),
		cancel: cancel, errCh: errCh,
	}
}

// writeWorkerCA mints a throwaway root and an intermediate under the stack's
// trust domain and writes the chain and the intermediate key (workerCA.keySource
// file). Returns the chain path.
func (s *Stack) writeWorkerCA(dir string) (chain string) {
	s.tb.Helper()
	now := s.Clock.Now()
	root, rootKey, err := wcasigner.NewRoot(now)
	if err != nil {
		s.tb.Fatalf("security: worker CA root: %v", err)
	}
	key, err := wcasigner.GenerateKey()
	if err != nil {
		s.tb.Fatalf("security: worker CA key: %v", err)
	}
	inter, err := wcasigner.NewIntermediate(root, rootKey, &key.PublicKey, TrustDomain, now)
	if err != nil {
		s.tb.Fatalf("security: worker CA intermediate: %v", err)
	}
	s.wcaInter, s.wcaKey = inter, key
	chain = filepath.Join(dir, "worker-ca-chain.pem")
	if err := os.WriteFile(chain, workerca.EncodeCertsPEM(inter, root), 0o600); err != nil {
		s.tb.Fatalf("security: write the worker CA chain: %v", err)
	}
	keyPEM, err := keysigner.MarshalPKCS8PEM(key)
	if err != nil {
		s.tb.Fatalf("security: encode the worker CA key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "worker-ca.key"), keyPEM, 0o600); err != nil {
		s.tb.Fatalf("security: write the worker CA key: %v", err)
	}
	s.tracker.add("key PEM", strings.TrimSpace(string(keyPEM)))
	return chain
}

func (s *Stack) cpConfig(addr, chain string) string {
	rate := TokenRateDefault
	var b strings.Builder
	level := "info"
	if s.opts.DebugCP {
		level = "debug"
	}
	b.WriteString("logging:\n  level: " + level + "\n  format: json\n\npolicy:\n  allowlist:\n    - domain: " + UpstreamHost + "\n")
	fmt.Fprintf(&b, `
identity:
  defaultMode: %[1]s
  issuer: %[2]s
  internalIssuerURL: %[2]s
  audience: %[3]s
  allowedAZP: [%[4]s, warden-cli]
%[13]s
console:
  auth: oidc
  oidc:
    issuer: %[2]s
    internalIssuerURL: %[2]s
    clientID: %[5]s
    clientSecretEnv: %[6]s
    redirectURL: https://%[7]s/auth/callback
  roles:
    admin: [%[8]s]
    viewer: [%[9]s]
  adminAudit:
    enabled: true

keys:
  enabled: true

workerCA:
  enabled: true
  trustDomain: %[10]s
  certFile: %[11]s
  keySource: file
  keyFile: %[12]s
`, s.opts.IdentityMode, s.Issuer.Issuer(), IdentityAudience, IdentityAZP, ConsoleClientID, consoleSecretEnv,
		addr, ConsoleAdminGroup, ConsoleViewerGroup, TrustDomain, chain, filepath.Join(s.root, "worker-ca.key"), s.identityExtras())
	if len(s.opts.AgentModes) > 0 {
		b.WriteString("\nagents:\n")
		ids := make([]string, 0, len(s.opts.AgentModes))
		for id := range s.opts.AgentModes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Fprintf(&b, "  - id: %s\n    identity: %s\n", id, s.opts.AgentModes[id])
		}
	}
	if s.opts.EchoSecretStore {
		// The echo backend mounts /central/secrets (a route-boundary case
		// proves a worker certificate never opens it) but it also makes every
		// worker resolve a secret to its own placeholder, so it is opt-in.
		b.WriteString("\nsecretStore:\n  backend: echo\n")
	}
	b.WriteString("\ntokenService:\n  enabled: true\n  issuer: " + TokenIssuer + "\n")
	if !s.opts.DefaultTokenRate {
		b.WriteString("  rateLimit:\n    perIP: " + rate + "\n    perAgent: " + rate + "\n    perUser: " + rate + "\n")
	}
	return b.String()
}

// identityExtras renders the optional identity: keys of the options.
func (s *Stack) identityExtras() string {
	var b strings.Builder
	if s.opts.AcceptDexTokens != nil {
		fmt.Fprintf(&b, "  acceptDexTokens: %t\n", *s.opts.AcceptDexTokens)
	}
	if s.opts.ClockSkewSeconds > 0 {
		fmt.Fprintf(&b, "  clockSkewSeconds: %d\n", s.opts.ClockSkewSeconds)
	}
	return b.String()
}

// startWorker enrolls and boots the worker bound to agent. The enrollment
// token is minted through the admin API, so the admin session and the agent
// registry are exercised the way an operator uses them.
func (s *Stack) startWorker(agent string) {
	s.tb.Helper()
	suffix := strings.TrimPrefix(agent, "agent-")
	if agent == "" {
		suffix = "unbound"
	}
	w := &Worker{
		Name: "worker-" + suffix, AgentID: agent,
		TokenEnv: "WARDEN_SECURITY_ENROLL_" + s.id + "_" + strings.ToUpper(sanitizeEnv(suffix)),
		inflight: proxy.NewInflight(),
		StateDir: filepath.Join(s.root, "worker-"+suffix, "state"),
		DBPath:   filepath.Join(s.root, "worker-"+suffix, "analytics.db"),
	}
	if err := os.MkdirAll(filepath.Dir(w.DBPath), 0o700); err != nil {
		s.tb.Fatalf("security: worker dir: %v", err)
	}
	admin := s.AdminSession(s.tb)
	token := admin.CreateEnrollmentToken(s.tb, w.Name)
	s.tracker.add("enrollment token", token)
	s.tb.Setenv(w.TokenEnv, token)
	s.tb.Setenv(swappedEnv, SwappedSecret)

	cfgPath := filepath.Join(s.root, w.Name+"-config.yaml")
	if err := os.WriteFile(cfgPath, []byte(s.workerConfig(w)), 0o600); err != nil {
		s.tb.Fatalf("security: write the %s config: %v", w.Name, err)
	}
	caCert, caKey := s.ProxyCA.WriteFiles(filepath.Join(s.root, "worker-"+suffix), "proxy-ca")
	if s.opts.NoCA {
		caCert, caKey = "", ""
	}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		s.tb.Fatalf("security: listen for %s: %v", w.Name, err)
	}
	adminLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = proxyLn.Close()
		s.tb.Fatalf("security: listen for %s admin: %v", w.Name, err)
	}
	w.ProxyAddr, w.AdminAddr = proxyLn.Addr().String(), adminLn.Addr().String()

	ready := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.errCh = make(chan error, 1)
	params := worker.Params{
		ConfigPath:    cfgPath,
		DBPath:        w.DBPath,
		CACert:        caCert,
		CAKey:         caKey,
		Version:       "security",
		ProxyListener: proxyLn,
		AdminListener: adminLn,
		OnReady:       func(_, _ string) { close(ready) },
		Overrides: &worker.Overrides{
			Dialer:          &mapDialer{host: UpstreamHost, addr: s.Upstream.Addr()},
			UpstreamRootCAs: s.UpstreamCA.Pool(),
			Clock:           s.Clock,
			Inflight:        w.inflight,
			OnAnalyticsWriter: func(f worker.AnalyticsFlusher) {
				w.flushMu.Lock()
				w.flush = f.Flush
				w.flushMu.Unlock()
			},
		},
	}
	go func() { w.errCh <- worker.Run(ctx, s.logs, params) }()
	s.Workers = append(s.Workers, w)
	select {
	case <-ready:
	case err := <-w.errCh:
		w.cancel = nil
		s.tb.Fatalf("security: %s exited before it was ready: %v\n%s", w.Name, err, tail(s.logs.String(), 2500))
	case <-time.After(readyDeadline):
		s.tb.Fatalf("security: %s did not report OnReady within %s\n%s", w.Name, readyDeadline, tail(s.logs.String(), 2500))
	}
}

func (s *Stack) workerConfig(w *Worker) string {
	pins := s.bundlePins()
	raw, err := json.Marshal(pins)
	if err != nil {
		s.tb.Fatalf("security: encode the bundle pins: %v", err)
	}
	agentLine := ""
	if w.AgentID != "" {
		agentLine = "  agentID: " + w.AgentID + "\n"
	}
	endpoint := s.CP.Addr
	if s.opts.CPEndpoint != nil {
		if a := s.opts.CPEndpoint(s, w); a != "" {
			endpoint = a
		}
	}
	issuer := ""
	if s.bundleIssuer != "" {
		issuer = "  bundleIssuer: " + s.bundleIssuer + "\n"
	}
	return fmt.Sprintf(`logging:
  level: info
  format: json

controlPlane:
  endpoint: https://%[1]s/policy
  caCert: %[2]s
  longPollWait: %[3]s
  pollInterval: 1s
  heartbeatInterval: 1s
  requireSignedBundles: true
  bundleKeys: %[4]s
%[12]s  stateDir: %[5]s
  enrollment:
    tokenEnv: %[6]s

central:
%[7]s  proxyID: %[8]s

secrets:
  - placeholder: %[9]s
    envVar: %[10]s
    matchHosts: [%[11]s]

mcp:
  enabled: true
  mode: monitor

observability:
  enabled: true
  serviceName: warden-security
`, endpoint, s.CP.CertFile, s.opts.LongPollWait, raw, w.StateDir, w.TokenEnv, agentLine, w.Name,
		SwappedPlaceholder, swappedEnv, UpstreamHost, issuer)
}

// bundlePins are the CP's bundle public keys, the controlPlane.bundleKeys every
// worker pins.
func (s *Stack) bundlePins() []keys.JWK {
	km := s.Keys()
	if km == nil {
		s.tb.Fatal("security: the control plane never reported its key manager (KeysReady)")
	}
	return km.KeySet().JWKS(keys.PurposeBundle).Keys
}

// WaitIdle blocks until every worker's in-flight request scopes have finished
// their terminal bookkeeping. The proxy writes an allowed or denied request's
// event, decision log line and metrics after the response reaches the client,
// so every oracle read waits here first (the quiescence seam
// worker.Overrides.Inflight, as the L1 harness does).
func (s *Stack) WaitIdle(tb testing.TB) {
	tb.Helper()
	for _, w := range s.Workers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := w.inflight.WaitIdle(ctx)
		cancel()
		if err != nil {
			tb.Fatalf("security: %s still had requests in flight after 10s: %v", w.Name, w.inflight.InFlight())
		}
	}
}

func randHex(tb testing.TB) string {
	tb.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		tb.Fatalf("security: random id: %v", err)
	}
	return hex.EncodeToString(b)
}

// awaitBundles drives the stack to the state every case starts from: each
// worker has applied a signed bundle (warden_bundle_seq above 0). A freshly
// booted worker does not yet enforce the distributed identity settings: that
// is a production bug in the worker's boot path (it does not apply them at
// boot; fix on branch fix/worker-boot-identity), worked around in
// RegisterAgent, not here.
func (s *Stack) awaitBundles() {
	s.tb.Helper()
	for _, w := range s.Workers {
		w := w
		s.EventuallyAdvance(w.Name+" to apply a signed bundle (warden_bundle_seq > 0)", time.Second, func() bool {
			v, ok := s.TryMetric(w, "warden_bundle_seq", nil)
			return ok && v > 0
		})
	}
}

// probeConnect sends a credential-less CONNECT and returns its status without
// sending anything through the tunnel, so a worker that does not enforce
// identity yet answers 200 and still never reaches the upstream.
func (s *Stack) probeConnect(w *Worker) int { return s.probeConnectWith(w, "") }

// probeConnectWith is probeConnect carrying a Proxy-Authorization value.
func (s *Stack) probeConnectWith(w *Worker, proxyAuth string) int {
	conn, err := net.DialTimeout("tcp", w.ProxyAddr, 5*time.Second)
	if err != nil {
		return 0
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "CONNECT " + UpstreamHost + ":443 HTTP/1.1\r\nHost: " + UpstreamHost + ":443\r\n"
	if proxyAuth != "" {
		req += "Proxy-Authorization: " + proxyAuth + "\r\n"
	}
	if _, err := io.WriteString(conn, req+"\r\n"); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func (s *Stack) stop() {
	for _, w := range s.Workers {
		if w.cancel != nil {
			w.cancel()
		}
	}
	for _, w := range s.Workers {
		if w.cancel == nil {
			continue
		}
		select {
		case err := <-w.errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				s.tb.Errorf("security: %s exited with %v", w.Name, err)
			}
		case <-time.After(stopDeadline):
			s.tb.Errorf("security: %s did not stop within %s", w.Name, stopDeadline)
		}
	}
	if s.CP != nil && s.CP.cancel != nil {
		s.CP.cancel()
		select {
		case err := <-s.CP.errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				s.tb.Errorf("security: the control plane exited with %v", err)
			}
		case <-time.After(stopDeadline):
			s.tb.Errorf("security: the control plane did not stop within %s", stopDeadline)
		}
	}
}

// flushAnalytics persists everything the worker queued, so DenyEvents reads
// the traffic a case has already finished making.
func (w *Worker) flushAnalytics() error {
	w.flushMu.Lock()
	f := w.flush
	w.flushMu.Unlock()
	if f == nil {
		return nil
	}
	return f()
}

// mapDialer routes the one allowlisted fake hostname to the loopback upstream:
// DNS replacement for the assembly-only Overrides.Dialer seam, never a way
// around the SSRF guard in a shipped binary. Any other destination is refused.
type mapDialer struct{ host, addr string }

var _ proxy.Dialer = (*mapDialer)(nil)

func (m *mapDialer) check(addr string) error {
	h, _, err := net.SplitHostPort(addr)
	if err != nil || h != m.host {
		return fmt.Errorf("security: no fake upstream for %q", addr)
	}
	return nil
}

func (m *mapDialer) Dial(network, addr string) (net.Conn, error) {
	if err := m.check(addr); err != nil {
		return nil, err
	}
	return net.Dial(network, m.addr)
}

func (m *mapDialer) DialTLS(network, addr string, cfg *tls.Config) (*tls.Conn, error) {
	if err := m.check(addr); err != nil {
		return nil, err
	}
	if cfg == nil || cfg.RootCAs == nil {
		return nil, errors.New("security: the proxy handed DialTLS no RootCAs; Overrides.UpstreamRootCAs never reached the upstream TLS config")
	}
	raw, err := net.Dial(network, m.addr)
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

// logBuffer is a goroutine-safe writer shared by the CP and every worker.
type logBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func sanitizeEnv(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
}
