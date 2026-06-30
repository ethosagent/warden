// Package proxy is the listener / TCP-accept / TLS-termination skeleton. Phase 1
// (M1) fills in real connection handling: TCP accept with default-deny, TLS
// termination with a cert the agent trusts, protocol detection, secret swap,
// and forwarding. This file provides the constructor and small pure helpers so
// the wiring is testable without raw networking in the skeleton.
package proxy

import (
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config holds the proxy's listen address and collaborators. All external
// dependencies are interfaces, honoring the day-zero interface rule.
type Config struct {
	// ListenAddr is the loopback / pod-internal address the agent connects to
	// (e.g. "127.0.0.1:8080").
	ListenAddr       string
	Policy           *policy.Evaluator
	Secrets          secrets.SecretProvider
	Analytics        analytics.AnalyticsStore
	CACertPath       string
	CAKeyPath        string
	PlaceholderNames []string
	Transformers     []*auth.MatchedTransformer

	// Judge is the optional inline LLM judge. When nil the proxy behaves exactly
	// as before: a NoMatch destination is default-denied. When set, NoMatch
	// requests are forwarded to TLS termination so the judge can inspect the full
	// request. The judge is never authoritative over static rules.
	Judge Judge
	// AgentID identifies the single configured agent for judge lookups. The
	// port-binding model is one proxy per agent, so a single id suffices.
	AgentID string

	// Metrics is the optional OTel metric emitter. Nil-safe: when nil every
	// record call is a no-op, so observability never alters a decision or adds
	// latency to the hot path.
	Metrics *observability.Metrics
	// Logger is the optional structured logger for decision/lifecycle records.
	// When nil, proxy.New substitutes a discard logger so behavior and log volume
	// are unchanged.
	Logger *slog.Logger

	// MCP is the optional MCP egress gateway. Nil = MCP disabled: handleHTTP is
	// byte-identical to before. Non-nil = analyze MCP JSON-RPC traffic.
	MCP *gateway.Gateway

	// Cost is the optional LLM cost estimator. Nil-safe: when nil no cost is
	// attributed. When set, an allowed request to a known provider domain is
	// tagged with a heuristic dollar estimate from observed request/response
	// byte sizes — order-of-magnitude visibility, never billing-grade.
	Cost *cost.Estimator
}

// Judge renders an allow/deny verdict for a request that matched no static
// rule. It is defined here (consumer-side) so the proxy does not depend on the
// llmpolicy package directly. Implementations must fail closed (deny on error).
type Judge interface {
	Evaluate(agentID, method, url, host, contentType string, hasAuth bool) Verdict
}

// Verdict is the judge's decision. Decision is "allow" or "deny".
type Verdict struct {
	Decision string
	Reason   string
}

// Proxy is the egress guardrail front door. M1 adds Serve()/accept loops; the
// skeleton constructs it and validates its configuration.
type Proxy struct {
	cfg        Config
	listenerMu sync.Mutex
	listener   net.Listener
	caCert     *x509.Certificate
	caKey      crypto.PrivateKey
	certCache  sync.Map
	dialFunc   func(network, addr string) (net.Conn, error)
	dialTLS    func(network, addr string, cfg *tls.Config) (*tls.Conn, error)

	// mcp holds the live MCP gateway, swappable atomically while the hot path
	// reads it (control-plane settings can rebuild + replace it at runtime). A
	// nil pointer means MCP is disabled, exactly as a nil cfg.MCP did before. It
	// is seeded from cfg.MCP in New so an unmanaged worker's behavior is unchanged.
	mcp atomic.Pointer[gateway.Gateway]

	// judge holds the live inline judge, swappable atomically while the hot path
	// reads it (control-plane settings can rebuild + replace it at runtime). The
	// judge is an interface, so it is wrapped in judgeHolder to give the atomic
	// pointer a concrete type and to allow a nil judge (disabled). A nil pointer
	// — or a holder wrapping a nil interface — means the judge is disabled,
	// exactly as a nil cfg.Judge did before. It is seeded from cfg.Judge in New so
	// an unmanaged worker's behavior is unchanged.
	judgeP atomic.Pointer[judgeHolder]

	// secretsP holds the live secret provider, swappable atomically while the hot
	// path reads it (a control-plane cache.ttl change rebuilds the cache and
	// replaces it at runtime). SecretProvider is an interface, so it is wrapped in
	// secretsHolder to give the atomic pointer a concrete element type. It is
	// seeded from cfg.Secrets in New (which New validates as non-nil), so an
	// unmanaged worker's behavior is unchanged.
	secretsP atomic.Pointer[secretsHolder]

	// analyticsP holds the live analytics store, swappable atomically while the
	// hot path reads it (a control-plane compliance toggle rebuilds only the
	// tagging layer and replaces it at runtime). AnalyticsStore is an interface,
	// so it is wrapped in analyticsHolder. It is seeded from cfg.Analytics in New
	// (validated non-nil), so an unmanaged worker's behavior is unchanged.
	analyticsP atomic.Pointer[analyticsHolder]
}

// judgeHolder wraps the Judge interface so it can live behind an
// atomic.Pointer[judgeHolder] (which needs a concrete element type). A nil holder
// pointer, or a holder whose j is nil, both mean "judge disabled".
type judgeHolder struct{ j Judge }

// secretsHolder wraps the SecretProvider interface so it can live behind an
// atomic.Pointer[secretsHolder] (which needs a concrete element type). It is
// always non-nil after New (cfg.Secrets is required), so the hot-path reader
// never returns a nil provider.
type secretsHolder struct{ s secrets.SecretProvider }

// analyticsHolder wraps the AnalyticsStore interface so it can live behind an
// atomic.Pointer[analyticsHolder]. It is always non-nil after New (cfg.Analytics
// is required), so the hot-path reader never returns a nil store.
type analyticsHolder struct{ a analytics.AnalyticsStore }

// mcpGateway loads the current MCP gateway through the atomic pointer. A nil
// return means MCP is disabled (the hot path's `if gw != nil` guard then skips
// all MCP work, byte-identical to a worker that never configured MCP).
func (p *Proxy) mcpGateway() *gateway.Gateway { return p.mcp.Load() }

// SetMCPGateway atomically swaps in a new MCP gateway (or nil to disable). It is
// race-free against concurrent hot-path reads via the atomic pointer; the caller
// owns the lifecycle of the OLD gateway (the long-poll apply loop in cmd/proxy
// rebuilds and replaces on each control-plane change).
func (p *Proxy) SetMCPGateway(gw *gateway.Gateway) { p.mcp.Store(gw) }

// judge loads the current inline judge through the atomic pointer. A nil return
// means the judge is disabled (the hot path's `if j != nil` guard then skips the
// judge, byte-identical to a worker that never configured a judge). It mirrors
// mcpGateway: a single snapshot per request keeps a concurrent swap from
// changing the judge mid-request.
func (p *Proxy) judge() Judge {
	if h := p.judgeP.Load(); h != nil {
		return h.j
	}
	return nil
}

// SetJudge atomically swaps in a new inline judge (or nil to disable). It is
// race-free against concurrent hot-path reads via the atomic pointer. The judge
// is fail-safe advisory state, not a lifecycle-owning handle, so there is nothing
// to close on the OLD judge (unlike the MCP gateway). The long-poll apply loop in
// cmd/proxy rebuilds and replaces on each control-plane change.
func (p *Proxy) SetJudge(j Judge) { p.judgeP.Store(&judgeHolder{j: j}) }

// secrets loads the current secret provider through the atomic pointer. It is
// always non-nil after New (cfg.Secrets is required and seeded), matching the
// pre-swap behavior where p.cfg.Secrets was read directly. A single snapshot per
// request keeps a concurrent cache.ttl swap from changing the provider
// mid-request.
func (p *Proxy) secrets() secrets.SecretProvider { return p.secretsP.Load().s }

// SetSecrets atomically swaps in a new secret provider. It is race-free against
// concurrent hot-path reads via the atomic pointer. The control-plane apply loop
// rebuilds the cache (with a new TTL) and replaces it on a cache.ttl change;
// dropping the old cache's entries is acceptable, they simply re-fetch. The OLD
// provider has no lifecycle to close (the env-backed cache holds no handles).
func (p *Proxy) SetSecrets(s secrets.SecretProvider) { p.secretsP.Store(&secretsHolder{s: s}) }

// analyticsStore loads the current analytics store through the atomic pointer. It
// is always non-nil after New (cfg.Analytics is required and seeded), matching the
// pre-swap behavior where p.cfg.Analytics was read directly. A single snapshot per
// request keeps a concurrent compliance toggle from changing the store
// mid-request.
func (p *Proxy) analyticsStore() analytics.AnalyticsStore { return p.analyticsP.Load().a }

// SetAnalytics atomically swaps in a new analytics store. It is race-free against
// concurrent hot-path reads via the atomic pointer. The control-plane apply loop
// rebuilds ONLY the tagging layer around the shared base/signing store on a
// compliance toggle and replaces it here; the dashboard and central-forwarding
// consumers hold the base store directly and are unaffected by this swap.
func (p *Proxy) SetAnalytics(a analytics.AnalyticsStore) { p.analyticsP.Store(&analyticsHolder{a: a}) }

// New constructs a Proxy, validating that the required collaborators are
// present. It does not bind a socket; Serve (M1) does.
func New(cfg Config) (*Proxy, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("proxy: ListenAddr is required")
	}
	if cfg.Policy == nil {
		return nil, fmt.Errorf("proxy: Policy evaluator is required")
	}
	if cfg.Secrets == nil {
		return nil, fmt.Errorf("proxy: Secrets provider is required")
	}
	if cfg.Analytics == nil {
		return nil, fmt.Errorf("proxy: Analytics store is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = observability.DiscardLogger()
	}
	p := &Proxy{cfg: cfg}
	// Seed the swappable gateway from the configured one so an unmanaged worker's
	// behavior is unchanged; a managed worker's long-poll apply loop replaces it.
	p.mcp.Store(cfg.MCP)
	// Seed the swappable judge from cfg.Judge (may be nil = disabled), same
	// rationale as the gateway above.
	p.judgeP.Store(&judgeHolder{j: cfg.Judge})
	// Seed the swappable secret provider and analytics store from the (required,
	// non-nil) cfg values so an unmanaged worker reads exactly what it did before;
	// a managed worker's apply loop replaces them on cache.ttl / compliance changes.
	p.secretsP.Store(&secretsHolder{s: cfg.Secrets})
	p.analyticsP.Store(&analyticsHolder{a: cfg.Analytics})

	haveCert := cfg.CACertPath != ""
	haveKey := cfg.CAKeyPath != ""
	if haveCert != haveKey {
		return nil, fmt.Errorf("proxy: both CACertPath and CAKeyPath must be set")
	}
	if haveCert {
		certPEM, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("proxy: read CA cert: %w", err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("proxy: no PEM block in CA cert")
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("proxy: parse CA cert: %w", err)
		}
		p.caCert = caCert

		keyPEM, err := os.ReadFile(cfg.CAKeyPath)
		if err != nil {
			return nil, fmt.Errorf("proxy: read CA key: %w", err)
		}
		keyBlock, _ := pem.Decode(keyPEM)
		if keyBlock == nil {
			return nil, fmt.Errorf("proxy: no PEM block in CA key")
		}
		caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Fall back to PKCS#1 RSA key format
			rsaKey, rsaErr := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if rsaErr != nil {
				return nil, fmt.Errorf("proxy: parse CA key (tried PKCS#8 and PKCS#1): %w", err)
			}
			caKey = rsaKey
		}
		p.caKey = caKey

		// Validate that the certificate is actually a CA.
		if !caCert.IsCA || caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("proxy: CA cert is not a certificate authority")
		}

		// Verify key matches cert (RSA-only; gen-certs.sh only produces RSA keys).
		rsaPub, ok := caCert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("proxy: only RSA CA keys are supported")
		}
		rsaPriv, ok := caKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("proxy: only RSA CA keys are supported")
		}
		if rsaPub.N.Cmp(rsaPriv.N) != 0 {
			return nil, fmt.Errorf("proxy: CA key does not match CA cert")
		}
	}

	safeDial, err := NewSafeDialer(10*time.Second, nil)
	if err != nil {
		return nil, fmt.Errorf("proxy: safe dialer: %w", err)
	}
	p.dialFunc = safeDial.Dial
	p.dialTLS = safeDial.DialTLS

	return p, nil
}

// ListenAddr returns the configured listen address.
func (p *Proxy) ListenAddr() string { return p.cfg.ListenAddr }

// Addr returns the listener's address, or nil if the proxy has not started.
func (p *Proxy) Addr() net.Addr {
	p.listenerMu.Lock()
	ln := p.listener
	p.listenerMu.Unlock()
	if ln != nil {
		return ln.Addr()
	}
	return nil
}

// SplitHostPort parses a "host:port" destination into its host and numeric
// port. It is a thin, pure helper used on the accept path to feed the policy
// evaluator.
func SplitHostPort(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: split %q: %w", addr, err)
	}
	port, err = strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("proxy: bad port in %q: %w", addr, err)
	}
	return h, port, nil
}
