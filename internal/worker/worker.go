// Package worker holds the data-plane assembler: it wires the concrete
// implementations behind their interfaces, boots the proxy (fail-closed in
// managed mode), and runs the control-plane long-poll + heartbeat + MCP-push
// loops and the hot-reload apply loop. cmd/proxy only parses flags and calls Run.
package worker

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethosagent/warden/internal/admin"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/auth"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/policy"
	"github.com/ethosagent/warden/internal/proxy"
	"github.com/ethosagent/warden/internal/scan"
	"github.com/ethosagent/warden/internal/secrets"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// Params are the flag-derived inputs the worker boots from. cmd/proxy parses the
// cobra flags into this struct; the worker owns everything after that.
// ListenAddr, CACert, CAKey and AdminAddr are EXPLICIT flag overrides: empty
// means "not set", and the value then comes from config or the built-in default.
type Params struct {
	ConfigPath string
	ListenAddr string
	DBPath     string
	CACert     string
	CAKey      string
	AdminAddr  string
	// AdminTokenEnv is the explicit --admin-token-env override: the env var holding
	// the bearer token dashboard writes on the admin listener need. Empty falls back
	// to config `admin.tokenEnv`; with neither (or an empty value) writes are refused.
	AdminTokenEnv string
	Version       string
	LocalOnly     bool
	// ErrOut, when set, receives the operational log while audit.jsonLog writes
	// its decision stream to stdout (the logger moves off stdout so the streams
	// never mix). nil means os.Stderr; cmd/proxy never sets it.
	ErrOut io.Writer
	// AlertsDBPath is the SQLite alert-store path for the LOCAL-ONLY embedded alert
	// pipeline. Empty ⇒ default to a sibling of DBPath (warden-alerts.db). Ignored
	// in managed/fleet mode (the control plane hosts the pipeline there).
	AlertsDBPath string

	// Config, when set, is the ConfigProvider Run boots from instead of loading
	// ConfigPath. Assembly-only: cmd/proxy never sets it, so production always
	// loads the YAML file exactly as before; the L1 harness (#350) passes a
	// Go-built policy so an in-process worker needs no file.
	Config config.ConfigProvider

	// ProxyListener and AdminListener, when set, replace the resolved
	// listen/admin addresses as the sockets the proxy and the admin+dashboard
	// server accept on (an injected listener wins; the startup log states what
	// is actually used). Assembly-only: cmd/proxy never sets them. Run closes
	// both on a boot error — like controlplane.Run's fail closure — and the
	// serving paths close them on shutdown.
	ProxyListener net.Listener
	AdminListener net.Listener

	// OnReady is called once with the (proxyAddr, adminAddr) pair just before
	// the proxy starts accepting — after both listeners are bound, so the
	// kernel already queues connections and an immediate probe is drained the
	// moment Serve starts. An injected listener reports its bound address; with
	// no injection the resolved address is reported and a caller dials with
	// retry, exactly as the startup log reports it. Nil is allowed (production
	// never sets it).
	OnReady func(proxyAddr, adminAddr string)

	// OnTransparentReady is called once with the (httpsAddr, httpAddr) pair of
	// the BOUND transparent interception listeners (#376), just before the proxy
	// starts accepting — httpAddr is "" when plain HTTP is not served. Like
	// OnReady it only ever fires in transparent/both mode (forward mode binds no
	// transparent listener, so there is nothing to report); the L1 harness uses
	// it to dial the interception listeners without fixed ports. Nil is allowed
	// (production never sets it).
	OnTransparentReady func(httpsAddr, httpAddr string)

	// Overrides carries the assembly-only test seams (#362). Nil (production)
	// means every collaborator is built exactly as always; see Overrides.
	Overrides *Overrides
}

// Overrides are assembly-only replacements for collaborators the production
// worker always builds itself. They exist ONLY for the L1 harness (#350): a Go
// test maps allowlisted names onto local fake upstreams and drives time without
// sleeps, which production wiring must never be able to do. They are therefore
// Go-only BY DESIGN — no YAML key or CLI flag can set them (enforced by
// TestOverridesAreNotConfigurable) — and they are copied into proxy.Config and
// the loops at boot, never read again.
type Overrides struct {
	// Dialer replaces the proxy's SSRF-safe upstream dialer ENTIRELY — blocklist
	// included — so a scenario can route api.example.com to a loopback fake the
	// SafeDialer would rightly refuse. Only ever set by tests.
	Dialer proxy.Dialer
	// UpstreamRootCAs replaces the root pool the proxy's upstream TLS handshakes
	// verify against, so a fake upstream's test CA is trusted without touching
	// the system store. nil = system roots.
	UpstreamRootCAs *x509.CertPool
	// Clock is the worker's time port: the control-plane long-poll and
	// heartbeat loops tick on it. nil = clock.Real().
	Clock clock.Clock
	// MetricsReader, when set, is attached to the worker's OTel meter provider
	// as an extra reader (observability.Config.Reader) so a test can collect
	// metrics in-process. nil = no extra reader (production default).
	MetricsReader sdkmetric.Reader
	// OnAnalyticsWriter, when set, is called exactly once during boot with the
	// assembled async analytics writer's drain handle, so the L1 harness can
	// persist everything queued the moment a scenario stops making traffic and
	// read events back deterministically (h.Events()) instead of outwaiting the
	// 250ms flush tick. Assembly-only like the rest of Overrides: no YAML key or
	// CLI flag can set it (enforced by TestOverridesAreNotConfigurable), and
	// production never sets it — nil leaves boot byte-identical.
	OnAnalyticsWriter func(AnalyticsFlusher)
	// Inflight is installed as the proxy's quiescence tracker (proxy.Config
	// .Inflight): every request scope enters it at request-read and leaves only
	// after its terminal bookkeeping, so the harness's oracles wait for the
	// drain instead of racing the post-response record (#363). Production never
	// sets it — nil means the proxy runs untracked (one nil check per request).
	Inflight *proxy.Inflight
	// BeforeTerminal is installed as the proxy's terminal-bookkeeping hook
	// (proxy.Config.BeforeTerminal): called at the top of every terminal
	// bookkeeping section, it is a TEST-ONLY trap the harness parks in to make
	// the exact post-response window whose bookkeeping race the tracker closes
	// deterministic-red instead of flaky-red. Production never sets it (nil =
	// one nil check, no call). It must never grow beyond a test inconveniencer:
	// it delays bookkeeping, never egress decisions.
	BeforeTerminal func()
}

// AnalyticsFlusher is the drain capability of the async analytics writer: Flush
// persists everything already queued and returns (analytics flush semantics —
// no deadline, never a drop). A FAILED batch write is returned, not acked as
// persisted — the batch stays buffered for the next flush, and the caller
// learns the read-your-writes view it asked for does not exist. It is the ONLY
// surface handed out on the writer: no reach into the queue, the batch, or the
// underlying store.
type AnalyticsFlusher interface {
	Flush() error
}

// Run loads config, wires dependencies behind their interfaces, constructs the
// proxy, and starts serving. out replaces cmd.OutOrStdout(); ctx replaces
// cmd.Context(); p.Version replaces the cmd package's version var used for the
// observability ServiceVersion.
func Run(ctx context.Context, out io.Writer, p Params) error {
	configPath := p.ConfigPath
	dbPath := p.DBPath
	localOnlyFlag := p.LocalOnly

	// A failed boot must never leak the harness's ports: every early return
	// below precedes any server start, so both injected listeners are closed
	// here until the serving path takes ownership (booted). Mirrors
	// controlplane.Run's fail closure.
	booted := false
	defer func() {
		if booted {
			return
		}
		if p.ProxyListener != nil {
			_ = p.ProxyListener.Close()
		}
		if p.AdminListener != nil {
			_ = p.AdminListener.Close()
		}
	}()

	// Config source: an injected ConfigProvider (assembly-only harness seam)
	// wins; nil keeps the local YAML file load exactly as before.
	cfgProvider := p.Config
	if cfgProvider == nil {
		var err error
		cfgProvider, err = config.NewLocalYAMLProvider(configPath)
		if err != nil {
			return err
		}
	}
	pol, err := cfgProvider.GetPolicy()
	if err != nil {
		return err
	}

	// Flag > config > default for listen/admin-listen/CA paths; validated here
	// regardless of source, with errors naming the source.
	eff, err := config.ResolveListen(pol, config.ListenFlags{
		Listen: p.ListenAddr, AdminListen: p.AdminAddr, CACert: p.CACert, CAKey: p.CAKey,
	})
	if err != nil {
		return err
	}
	listenAddr, adminAddr := eff.Listen.Value, eff.AdminListen.Value
	caCert, caKey := eff.CACert.Value, eff.CAKey.Value

	mapping := make(map[string]string, len(pol.Secrets))
	placeholders := make([]string, 0, len(pol.Secrets))
	for _, m := range pol.Secrets {
		mapping[m.Placeholder] = m.EnvVar
		placeholders = append(placeholders, m.Placeholder)
	}
	// The secret fetcher + cache are built AFTER the initial control-plane pull
	// (below), so a MANAGED worker can resolve its secretStore backend from the
	// distributed settings.Secrets selector before wiring the cache — mirroring how
	// observability resolves from distributed settings at boot. The placeholders
	// slice + resolved fetcher are held on the applier so a cache.ttl change can
	// rebuild the cache; everything downstream treats it as a plain secrets.Fetcher.

	// Structured logger from logging.{level,format}. Built once and threaded into
	// the proxy; lifecycle logs below also use it. logCtrl is the live handle the
	// managed apply loop uses to change the level at runtime WITHOUT swapping the
	// (widely-captured) logger instance. Format is restart-only (see LogControl).
	// With the JSON decision stream on stdout the operational logger moves to
	// stderr, so the two streams never mix; the move is logged once below.
	logOut := out
	jsonLogOnStdout := pol.Audit.JSONLog.Enabled && jsonLogOutput(pol.Audit.JSONLog) == config.JSONLogOutputStdout
	if jsonLogOnStdout {
		logOut = errOut(p)
	}
	logger, logCtrl := observability.NewLogger(logOut, pol.LogLevel, pol.LogFormat)
	if jsonLogOnStdout {
		logger.Info("audit.jsonLog.output is stdout: operational logs moved to stderr so stdout carries only warden.decision.v1 lines")
	}
	logger.Info("effective listener config", eff.LogArgs()...)

	// Optional upstream DNS override (dns.upstreamResolver). When set, warden's
	// OWN upstream dials — the proxy's CONNECT tunnels and TLS-terminated
	// upstreams (SNI keeps the client-supplied hostname), plus the
	// SafeDialer-based auth-fetch client — resolve through that server instead
	// of the resolver the container inherits. This is the knob for corporate
	// VPN / split-horizon networks where the default resolver cannot resolve
	// the public allowlisted names. The dashboard/admin listeners keep system
	// resolution, and the agent's own DNS path is a separate concern entirely
	// (transparent interception, #376). ONE resolver instance is shared by every
	// SafeDialer-based consumer, so the first-failure log fires exactly once no
	// matter which path trips it; a dead resolver fails requests exactly like
	// any other upstream-connect failure — never a silent fallback.
	var upstreamDNS proxy.NameResolver
	if pol.DNS.UpstreamResolver != "" {
		resolverAddr := pol.DNS.UpstreamResolver
		upstreamDNS = proxy.NewUpstreamResolver(resolverAddr, func(err error) {
			logger.Warn("upstream DNS lookup failed via the configured resolver; if the server is unreachable, upstream dials fail until it answers (no fallback to the system resolver)",
				"resolver", resolverAddr, "error", err)
		})
		logger.Info("upstream DNS resolver configured for warden's own upstream dials", "resolver", resolverAddr)
	}

	// LOCAL-ONLY SSRF exceptions (upstream.allowPrivateCIDRs): punch holes in the
	// private-IP blocklist for lab/test networks where an allowlisted upstream
	// legitimately sits on a private range (the L2 container harness). Security-
	// relevant and never CP-distributable, so it is loud: one WARN naming every
	// active exception, so a production config that sets it cannot go unnoticed.
	if len(pol.Upstream.AllowPrivateCIDRs) > 0 {
		logger.Warn("upstream.allowPrivateCIDRs is active: the listed CIDR ranges are exempt from SSRF private-IP blocking — lab and test networks only, never set this in production",
			"exempt", strings.Join(pol.Upstream.AllowPrivateCIDRs, ","))
	}

	// Transparent interception sees TCP only (#376). An agent that falls back to
	// QUIC (HTTP/3 over UDP 443) or ECH bypasses the :443 listener entirely — the
	// network around Warden must block or redirect UDP 443 so clients fall back
	// to TCP. That is a deployment property no process can enforce, so it is
	// loud at startup whenever the interception listeners bind.
	if pol.Proxy.Mode == config.ProxyModeTransparent || pol.Proxy.Mode == config.ProxyModeBoth {
		logger.Warn("transparent interception mode serves TCP only: block or redirect UDP 443 on the egress network, or agents may reach the internet over QUIC/HTTP-3 (and ECH hides the SNI) and bypass the guardrail",
			"mode", string(pol.Proxy.Mode))
	}

	// Managed vs local-only. Managed = a control plane is configured and
	// --local-only is not set: the worker's allow/deny policy comes ONLY from the
	// control plane and it boots fail-closed (deny all) until the first pull.
	// Otherwise the worker enforces its local policy (standalone).
	localOnly := localOnlyFlag || pol.ControlPlane.LocalOnly
	managed := pol.ControlPlane.Endpoint != "" && !localOnly

	// Optional control plane (managed mode only): pull allow/deny policy AND the
	// behavioral settings document from the remote endpoint. The first pull happens
	// HERE, before OTel init, so observability can be resolved from the distributed
	// settings.Observability (apply-on-restart: OTel providers initialize once per
	// process and cannot be safely hot-swapped on the long-poll). A best-effort
	// initial pull narrows the fail-closed window; if it fails the worker stays
	// fail-closed and the long-poll loop applies policy once the CP is reachable.
	// Secrets/judge/audit-signing stay local.
	var (
		controlPlane *config.RemoteProvider
		remotePolicy *config.Policy // last-known-good remote allow/deny, applied to the evaluator below
	)
	if managed {
		token := os.Getenv(pol.ControlPlane.TokenEnv)
		rp, cpErr := config.NewRemoteProvider(pol.ControlPlane.Endpoint, token)
		if cpErr != nil {
			return cpErr
		}
		// Trust a privately-signed control plane via a per-connection CA, without
		// altering this worker's upstream TLS trust.
		if pol.ControlPlane.CACert != "" {
			if caErr := rp.SetCACert(pol.ControlPlane.CACert); caErr != nil {
				return caErr
			}
		}
		// Announce this worker's id on each pull/heartbeat so the control plane
		// lists it as connected even before it forwards analytics.
		rp.SetProxyID(expandEnv(pol.Central.ProxyID))
		// Shutdown hygiene: drop the pooled keep-alive conns when Run returns, so
		// a hosted worker leaves no open connections to the control plane.
		defer rp.CloseIdleConnections()
		if pullErr := rp.Pull(); pullErr != nil {
			logger.Warn("control plane unreachable at boot; starting FAIL-CLOSED (deny all) until policy arrives", "error", pullErr)
		} else if remote, gErr := rp.GetPolicy(); gErr == nil {
			remotePolicy = &remote
			logger.Info("control plane policy applied", "endpoint", pol.ControlPlane.Endpoint)
		}
		controlPlane = rp
	} else if pol.ControlPlane.Endpoint != "" && localOnly {
		logger.Info("control plane configured but --local-only set; enforcing LOCAL policy")
	}

	// Behavioral settings from the initial control-plane pull (nil when local-only
	// or the CP was unreachable at boot). Both observability and the secret-store
	// backend below resolve from it, preferring central config over local.
	var distributed *config.SettingsWire
	if managed && controlPlane != nil {
		distributed = controlPlane.Settings()
	}

	// Resolve the observability config OTel boots from. A managed worker prefers
	// the control-plane-distributed settings.Observability (so central config
	// actually takes effect on restart), falling back to local pol.Observability
	// when the distributed block is absent or the CP was unreachable at boot. A
	// local-only worker always uses its local config (unchanged behavior).
	obsCfg := pol.Observability
	if managed {
		obsCfg = resolveObservability(distributed, pol)
	}

	// Resolve the secret-store backend the worker reads through. A MANAGED worker
	// prefers the CP-distributed settings.Secrets selector (value-free:
	// backend/region/namePrefix), falling back to local pol.SecretStore when absent
	// or the CP was unreachable at boot. Apply-on-RESTART like observability: the
	// fetcher is built ONCE here from the resolved backend; a live long-poll
	// hot-swap of the fetcher is a follow-up (it is a plain secrets.Fetcher behind
	// the unchanged Cache). The local-only path is untouched (secretStoreCfg ==
	// pol.SecretStore), so backend env/none behaves exactly as before.
	secretStoreCfg := pol.SecretStore
	if managed {
		secretStoreCfg = resolveSecretStore(distributed, pol)
	}
	if secretStoreCfg.ResolvedBackend() == config.SecretBackendEcho {
		logger.Warn("ECHO secret backend active — NON-PRODUCTION: the resolved value is the placeholder key itself; never use it to protect a real secret")
	}
	// newSecretFetcher reads only SecretStore off the policy; feed it the RESOLVED
	// backend via a shallow copy so a distributed selector takes effect without
	// mutating the loaded policy.
	effectivePol := pol
	effectivePol.SecretStore = secretStoreCfg
	secretFetcher, secretStore, err := newSecretFetcher(effectivePol, mapping)
	if err != nil {
		return err
	}
	// secretStoreBackend is the resolved backend name; secretStore is non-nil only
	// for echo/aws. Both feed the dashboard's read-only secretstore tab below.
	secretStoreBackend := secretStoreCfg.ResolvedBackend()
	liveCacheTTL := time.Duration(pol.CacheTTLSeconds) * time.Second
	secretProvider, err := secrets.NewCache(secretFetcher, liveCacheTTL, placeholders)
	if err != nil {
		return err
	}

	// OTel metrics emitter (off by default). New returns a nil *Metrics + nil
	// handler when disabled, and record calls are nil-safe no-ops. OTel providers
	// init ONCE here; a distributed observability change applies on the NEXT
	// restart (the worker re-pulls settings at boot), never on a live long-poll.
	var metricsReader sdkmetric.Reader
	if p.Overrides != nil {
		metricsReader = p.Overrides.MetricsReader
	}
	metrics, metricsHandler, shutdownObs, err := observability.New(observability.Config{
		Enabled:            obsCfg.Enabled,
		ServiceName:        obsCfg.ServiceName,
		ServiceVersion:     p.Version,
		MetricsEnabled:     obsCfg.MetricsEnabled,
		OTLPEndpoint:       obsCfg.OTLPEndpoint,
		ResourceAttributes: obsCfg.ResourceAttributes,
		Reader:             metricsReader,
	})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownObs(ctx)
	}()

	store, err := analytics.NewSQLiteStore(dbPath, 0)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// MCP persistence lives in the gateway layer now (not analytics), but shares
	// the analytics store's single SQLite connection: the events store is built
	// above (its tables exist), and gateway.NewSQLiteStore migrates the MCP tables
	// on that SAME handle. Built unconditionally — as analytics.migrate used to
	// create the MCP tables regardless of MCP mode — so a later control-plane
	// enable finds them. Sharing the one connection is load-bearing:
	// SetMaxOpenConns(1) means a second read-write handle to the same file would
	// contend with it. store.Close() (deferred above) owns the handle's lifecycle;
	// the gateway store must not close it.
	mcpStore, err := gateway.NewSQLiteStore(store.DB())
	if err != nil {
		return err
	}

	// Optional inline judge. When judge.enabled is false, judge is nil and the
	// proxy behaves exactly as before (NoMatch default-denies).
	judge, agentID, err := buildJudge(pol, listenAddr, logger)
	if err != nil {
		return err
	}

	// Embedded alert pipeline (LOCAL-ONLY only). In fleet mode the pipeline is
	// CP-hosted and Findings ride central ingest; a standalone worker has no control
	// plane, so it runs the SAME embeddable pipeline in-process and feeds it from its
	// own analytics stream (teed off the async writer below). FAIL-OPEN: a store-open
	// or manager-build failure logs and disables alerting — it NEVER blocks proxying.
	// The alert DB is a sibling of the analytics DB unless --alerts-db overrides it.
	// A fleet (managed) worker builds nothing here — behavior is byte-identical to
	// before (no pipeline, no alert store, an empty Alerts tab).
	var alerts *workerAlerts
	if localOnly {
		alertDBPath := p.AlertsDBPath
		if alertDBPath == "" {
			alertDBPath = filepath.Join(filepath.Dir(dbPath), "warden-alerts.db")
		}
		alerts = newWorkerAlerts(pol, configPath, alertDBPath, agentID, logger)
	}
	// Stop instances + close the worker-owned alert store on shutdown. Registered
	// BEFORE the async writer's Close defer (below), so defer LIFO drains the async
	// queue FIRST — the final teed batch's Observe still reaches a live store + router
	// — and only then closes the alert store.
	if alerts != nil {
		defer alerts.Close()
	}

	// Reusable scanner for the MCP gateway. Constructed once from local config and
	// reused on every control-plane-driven gateway rebuild (the scanner, store,
	// and agentID are LOCAL — never distributed).
	mcpScanner := scan.NewScanner(
		scan.WithPhonePII(pol.MCP.Scan.PII.Phone),
		scan.WithEvidence(pol.MCP.Scan.Evidence),
	)

	// Optional MCP egress gateway. When mcp.enabled is false, mcpGW stays nil and
	// handleHTTP is byte-identical to before. A managed worker may later receive an
	// MCP settings block over the long-poll and rebuild+swap this at runtime.
	// bootGW is the interface value seeded into proxy.Config. It MUST stay an
	// untyped-nil proxy.MCPGateway when MCP is disabled — assigning a typed-nil
	// *gateway.Gateway would make the proxy's mcpGateway() return a non-nil
	// interface wrapping a nil pointer and panic on the hot path. mcpGW keeps the
	// concrete handle for lifecycle (Close) and the dashboard MCP provider.
	var mcpGW *gateway.Gateway
	var bootGW proxy.MCPGateway
	if pol.MCP.Enabled {
		mcpGW = gateway.New(pol.MCP, mcpScanner, logger, gateway.WithStore(mcpStore), gateway.WithAgentID(agentID))
		bootGW = mcpGW
		logger.Info("MCP egress gateway enabled", "mode", pol.MCP.Mode)
	}
	// Close the gateway before the store: deferred LIFO runs this first, so the
	// gateway's final flush completes while the store handle is still open. A
	// runtime swap replaces p's live gateway; the apply loop owns closing the old
	// one, so this defer only handles the gateway live at shutdown.

	// Optional non-MCP HTTP response scanner. Off unless responseScan.enabled; when
	// off, respScanner stays nil and handleHTTP forwards non-MCP responses
	// byte-identically. LOCAL config (scanner + evidence never distributed).
	var respScanner *proxy.ResponseScanner
	if pol.ResponseScan.Enabled && pol.ResponseScan.Mode != "off" {
		respScanner = proxy.NewResponseScanner(
			pol.ResponseScan.Mode,
			pol.ResponseScan.MaxBodyBytes,
			pol.ResponseScan.PII.Phone,
			pol.ResponseScan.Evidence,
		)
		logger.Info("HTTP response scanning enabled", "mode", pol.ResponseScan.Mode)
	}

	// Optional outbound REQUEST-body DLP scanner + per-class egress policy. Off
	// unless dlp.mode != "off"; when off, dlpScanner stays nil and the dlpScan
	// stage is a no-op (no body read) — byte-identical to before. LOCAL config
	// (scanner + rules never distributed this phase). monitor records the would-be
	// action but never blocks; enforce blocks on a block/redact verdict.
	var dlpScanner *proxy.DLPScanner
	if pol.DLP.Active() {
		// evidence=true captures the SAFE MASKED sample ("••••<last4> (len N)", never
		// the raw match) so the dashboard Activity screen can show why a finding fired.
		dlpScanner = proxy.NewDLPScanner(pol.DLP, false, true)
		logger.Info("outbound request-body DLP scanning enabled",
			"mode", pol.DLP.Mode,
			"rules", len(pol.DLP.Rules),
			"custom_classes", len(pol.DLP.Custom))
	}

	// Hot-swappable policy evaluator. In managed mode it starts EMPTY (deny all)
	// and is filled by the control plane; otherwise it enforces local policy. The
	// control-plane provider + first pull happened above (before OTel init); if
	// that pull succeeded, remotePolicy holds the remote allow/deny and we seed the
	// evaluator with it so the fail-closed window is as narrow as it was before.
	var evaluator *policy.Evaluator
	if managed {
		evaluator = policy.NewEvaluator(config.Policy{})
		if remotePolicy != nil {
			evaluator.Replace(*remotePolicy)
		}
	} else {
		evaluator = policy.NewEvaluator(pol)
	}

	// Cost estimator: always on. It only attributes a heuristic dollar figure to
	// traffic that matches a known provider domain; everything else is untouched.
	costEstimator := cost.NewEstimator()

	// Optional auth transforms (OAuth2 / SigV4 / HMAC / API-key) per destination.
	// The fetch client deliberately gets NO upstream.allowPrivateCIDRs: the SSRF
	// exception widens the proxy's dialer only (proxy.Config), never this one.
	var transformers []*auth.MatchedTransformer
	if len(pol.Auth) > 0 {
		authClient, acErr := newSafeHTTPClient(10*time.Second, "", upstreamDNS)
		if acErr != nil {
			return acErr
		}
		transformers, err = buildTransformers(pol.Auth, authClient)
		if err != nil {
			return err
		}
		logger.Info("auth transforms enabled", "count", len(transformers))
	}

	// Async analytics write decorator (D1). The base SQLiteStore.StoreEvent does
	// an INSERT + prune (SELECT COUNT/DELETE) on the request goroutine through a
	// single connection (~420µs/event). asyncWriter enqueues onto a bounded
	// channel and a single writer goroutine batch-inserts + prunes off the hot
	// path, so the request goroutine pays only the sub-µs enqueue. Overflow is
	// BACKPRESSURE, never drop — events are the audit trail. It closes on
	// shutdown (drains + flushes) below.
	// In local-only, tee each stored batch into the embedded alert pipeline's Observe
	// fan-in. The tee fires on the async writer's single writer goroutine (OFF the
	// request hot path — the request goroutine only enqueues), so alert detection
	// adds no latency to request handling. In fleet mode alerts is nil and no tee is
	// installed (zero overhead; behavior unchanged).
	asyncOpts := []analytics.AsyncOption{analytics.WithLogger(logger)}
	if alerts != nil {
		asyncOpts = append(asyncOpts, analytics.WithOnBatch(alerts.Observe))
	}
	// JSON decision stream (audit.jsonLog): a second tee on the same writer
	// goroutine. The sink hands batches to its own bounded queue and never blocks
	// it. Built (and its close deferred) BEFORE the async writer so the deferred
	// LIFO order closes the sink AFTER asyncStore.Close() has drained its final
	// batch into the tee. A path that cannot be opened fails startup here.
	if pol.Audit.JSONLog.Enabled {
		sinkOpts := []auditlog.Option{}
		if jsonLogOnStdout {
			sinkOpts = append(sinkOpts, auditlog.WithWriter(out))
		}
		sink, sErr := auditlog.New(pol.Audit.JSONLog, newAuditMeta(pol, agentID), metrics, logger, sinkOpts...)
		if sErr != nil {
			return sErr
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), jsonLogCloseTimeout)
			defer cancel()
			_ = sink.Close(ctx)
		}()
		asyncOpts = append(asyncOpts, analytics.WithOnBatch(sink.Observe))
	}
	asyncStore := analytics.NewAsyncWriter(store, asyncOpts...)
	// Drain + flush the async queue on shutdown BEFORE the store handle closes.
	// Deferred LIFO: store.Close() was registered earlier, so this runs first and
	// the final batch lands while the DB is still open. Close is idempotent, so
	// this fires exactly once even if shutdown paths overlap.
	defer func() { _ = asyncStore.Close() }()
	// Expose queue depth as warden_analytics_queue_depth (observable gauge). Nil-
	// safe when metrics are disabled. Read live from the writer on each scrape.
	if rqErr := metrics.RegisterAnalyticsQueueDepth(func() int64 {
		return int64(asyncStore.QueueDepth())
	}); rqErr != nil {
		logger.Warn("analytics queue depth metric not registered", "error", rqErr)
	}
	// Assembly-only harness seam (#363): hand the drain handle to whoever asked
	// for it at assembly time. Production never sets OnAnalyticsWriter, so this
	// is one nil check away from byte-identical behavior.
	if p.Overrides != nil && p.Overrides.OnAnalyticsWriter != nil {
		p.Overrides.OnAnalyticsWriter(asyncStore)
	}

	// Audit decorators wrap the analytics WRITE chain. Order matters and is load-
	// bearing — the final chain (outer→inner) is:
	//
	//	tagging → signing → async → sqlite
	//
	// tagging is OUTER so each event is stamped with compliance control IDs
	// BEFORE the signer signs it (the receipt then covers the tags). async sits
	// JUST ABOVE the base store so the signer signs, and the receipt covers, the
	// exact event that is persisted — the async layer only defers the write, it
	// never alters the event. Reads (dashboard, central forwarding) still hold
	// the BASE store directly (see dashData/syncWorker below) and bypass the
	// queue; only this WRITE chain gets the async decorator.
	//
	// signedStore is the async writer OR the signing layer over it. It is the
	// stable inner store the (optional) compliance tagging layer wraps. The
	// managed apply loop rebuilds ONLY the tagging layer around signedStore on a
	// compliance toggle, so the signing/async layers and the base store are never
	// disturbed by a live swap.
	// auditPubKey / auditReceiptLog are captured for the dashboard's read-only
	// audit tab (receipt verify + tail). Zero (nil key / "" path) when receipts are
	// disabled, which leaves the tab's receipts block zeroed.
	var (
		auditPubKey     ed25519.PublicKey
		auditReceiptLog string
	)
	var signedStore analytics.AnalyticsStore = asyncStore
	if pol.Audit.SignedReceipts.Enabled {
		signer, sErr := loadOrCreateSigner(pol.Audit.SignedReceipts.KeyFile)
		if sErr != nil {
			return sErr
		}
		receiptLog, oErr := os.OpenFile(pol.Audit.SignedReceipts.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if oErr != nil {
			return fmt.Errorf("audit: open receipts log: %w", oErr)
		}
		defer func() { _ = receiptLog.Close() }()
		signedStore = audit.NewSigningStore(signedStore, signer, receiptLog)
		auditPubKey = signer.PubKey()
		auditReceiptLog = pol.Audit.SignedReceipts.Log
		logger.Info("signed audit receipts enabled",
			"log", pol.Audit.SignedReceipts.Log,
			"pubkey", hex.EncodeToString(signer.PubKey()))
	}
	// complianceMapper is reused on each toggle so enable rebuilds the same tagging
	// behavior. liveCompliance tracks the running state so the apply loop only
	// rebuilds the tagging layer when it actually changes.
	complianceMapper := audit.NewMapper()
	liveCompliance := pol.Audit.Compliance.Enabled
	analyticsStore := signedStore
	if liveCompliance {
		analyticsStore = audit.NewTaggingStore(signedStore, complianceMapper)
		logger.Info("compliance mapping enabled")
	}

	// Optional central aggregation. aggregator: host an ingest endpoint into an
	// in-memory central store the dashboard reads from. worker: forward local
	// events to a remote aggregator. off: single-node (default).
	var (
		centralStore  *analytics.CentralStore
		ingestHandler http.Handler
		syncWorker    *analytics.SyncWorker
		centralRemote *analytics.HTTPRemoteStore
	)
	switch pol.Central.Mode {
	case "aggregator":
		centralStore = analytics.NewCentralStore(pol.Central.MaxEvents)
		ingestHandler = analytics.NewIngestHandler(centralStore, os.Getenv(pol.Central.TokenEnv))
		logger.Info("central aggregator enabled", "ingest", "/central/ingest")
	case "worker":
		// The control plane is the worker's own trusted, operator-configured
		// endpoint (often on a private network), so forwarding does NOT go through
		// the SafeDialer — SSRF protection is for agent-driven egress only.
		centralClient, ccErr := newControlPlaneHTTPClient(10*time.Second, pol.Central.CACert)
		if ccErr != nil {
			return ccErr
		}
		remote, rErr := analytics.NewHTTPRemoteStore(pol.Central.Endpoint, os.Getenv(pol.Central.TokenEnv), expandEnv(pol.Central.ProxyID), centralClient)
		centralRemote = remote
		if rErr != nil {
			return rErr
		}
		// Same shutdown hygiene as the policy client above.
		defer remote.CloseIdleConnections()
		syncWorker = analytics.NewSyncWorker(store, remote, expandEnv(pol.Central.ProxyID), pol.Central.BatchSize, pol.Central.BufferCap, pol.Central.Interval)
		logger.Info("central worker enabled", "endpoint", pol.Central.Endpoint, "proxyID", expandEnv(pol.Central.ProxyID))
	}

	// Transparent-only mode has NO CONNECT listener: an injected one is unused
	// by construction, so Run closes it here — a harness port must never leak,
	// and the proxy's serving paths never take ownership of a listener they do
	// not accept on (#376). forward/both keep the exact previous handoff.
	forwardListener := p.ProxyListener
	if pol.Proxy.Mode == config.ProxyModeTransparent && forwardListener != nil {
		_ = forwardListener.Close()
		forwardListener = nil
	}

	cfg := proxy.Config{
		ListenAddr:        listenAddr,
		Listener:          forwardListener,
		Policy:            evaluator,
		Secrets:           secretProvider,
		Analytics:         analyticsStore,
		PlaceholderNames:  placeholders,
		PlaceholderScopes: secretScopes(pol.Secrets, logger),
		CACertPath:        caCert,
		CAKeyPath:         caKey,
		AgentID:           agentID,
		Metrics:           metrics,
		Logger:            logger,
		MCP:               bootGW,
		ResponseScan:      respScanner,
		EchoGuard:         proxy.EchoGuardConfig{Disabled: pol.EchoGuard.Disabled, Monitor: pol.EchoGuard.Monitor()},
		DLP:               dlpScanner,
		Transformers:      transformers,
		Cost:              costEstimator,
		UpstreamResolver:  upstreamDNS,

		// Interception mode (#376): internal/config validated the proxy block
		// (mode enum, listener presence, clashes, CA requirement) during
		// ResolveListen, so this is a straight copy of the resolved values.
		Mode:                   pol.Proxy.Mode,
		TransparentHTTPSListen: pol.Proxy.Transparent.HTTPSListen,
		TransparentHTTPListen:  pol.Proxy.Transparent.HTTPListen,
		OnTransparentReady:     p.OnTransparentReady,

		UpstreamAllowPrivateCIDRs: pol.Upstream.AllowPrivateCIDRs,
	}
	if judge != nil {
		cfg.Judge = judge
		logger.Info("inline LLM judge enabled", "agent", agentID, "model", pol.Judge.Model)
	}
	// Assembly-only overrides (harness seam, #362): copied into proxy.Config and
	// never read again. Nil (production) changes nothing on this path.
	if p.Overrides != nil {
		cfg.Dialer = p.Overrides.Dialer
		cfg.UpstreamRootCAs = p.Overrides.UpstreamRootCAs
		cfg.Inflight = p.Overrides.Inflight
		cfg.BeforeTerminal = p.Overrides.BeforeTerminal
	}

	pxy, err := newProxy(cfg)
	if err != nil {
		if caCert != "" {
			return fmt.Errorf("%w (ca-cert %q from %s, ca-key %q from %s)", err, caCert, eff.CACert.Source, caKey, eff.CAKey.Source)
		}
		return err
	}

	// liveMCPGW tracks the gateway currently swapped into the proxy so shutdown
	// (and each rebuild) closes the right one. It starts as the boot-time gateway
	// (possibly nil); the managed apply loop below replaces it on each change.
	// mcpMu guards it against the concurrent apply goroutine.
	var mcpMu sync.Mutex
	liveMCPGW := mcpGW
	// Close the gateway live at shutdown before the store: deferred LIFO runs this
	// first, so the gateway's final flush completes while the store is still open.
	defer func() {
		mcpMu.Lock()
		gw := liveMCPGW
		mcpMu.Unlock()
		if gw != nil {
			_ = gw.Close()
		}
	}()

	// Start admin + dashboard HTTP server. In aggregator mode the dashboard reads
	// the fleet-wide central store instead of this node's local SQLite store.
	var dashData dashboard.DataSource = store
	if centralStore != nil {
		dashData = centralStore
	}
	adminMux := http.NewServeMux()
	adminSrv := admin.NewServer(secretProvider)
	dashSrv := dashboard.NewServer(dashData, pol, secretProvider)
	// Policy panel reflects the live (hot-reloadable) allow/deny, not the startup
	// snapshot, so a control-plane reload is visible in the dashboard.
	dashSrv.SetLivePolicy(evaluator.CurrentPolicy)
	if mcpGW != nil {
		dashSrv.SetMCPProvider(mcpGW)
	}
	// Dashboard-V3 read tabs wired from what EXISTS on a worker:
	//   - secretstore: the worker's read store lists KEY metadata (echo/aws). A nil
	//     store (env backend) → the tab reports backend "none".
	//   - audit: the worker signs receipts, so it can verify + tail its own log.
	//     Compliance aggregation needs no wiring (the dashboard reads events). When
	//     receipts are disabled, auditReceiptLog is "" → the receipts block zeroes.
	//   - alerts: a local-only worker runs the embedded pipeline, so the Alerts +
	//     integrations surfaces are wired to it exactly as the control plane wires
	//     them. A fleet worker has no pipeline (alerts == nil) → the tab returns [].
	dashSrv.SetSecretStore(secretStore, secretStoreBackend)
	dashSrv.SetAudit(auditReceiptLog, auditPubKey)
	// Read-only Explore/Query Builder: when the dashboard's data source is
	// SQL-backed (implements AnalyticsQuery), expose its sandboxed query surface —
	// the same wiring the control plane does. In local/fleet-worker mode dashData
	// is the local SQLite store (a dedicated read-only handle, so ad-hoc queries
	// never contend with the async writer's connection); in aggregator mode it is
	// the in-memory central store, which does not implement it, so the Explore tab
	// reports unavailable there.
	if q, ok := dashData.(analytics.AnalyticsQuery); ok {
		dashSrv.SetQueryEngine(q)
	}
	if alerts != nil {
		alerts.wireDashboard(dashSrv)
	}
	// NL→SQL for the Explore tab honors explore.llmProvider — a named entry in the
	// shared llmProviders registry — INDEPENDENT of the judge; an unset explore block
	// reuses the judge's client exactly as before (back-compat). SECRET-LOCAL: every
	// key is resolved from this node's OWN env. Fail-soft: judge off, an empty key
	// env, a malformed config, or a named-but-unresolved provider all leave the
	// generator unset (the Explore tab then reports "add an LLM provider") and never
	// block worker start.
	judgeClient, _ := BuildLLMClient(pol.Judge)
	exploreClients, exploreErrs := BuildLLMClients(pol.LLMProviders)
	logLLMClientErrs(logger, exploreErrs)
	// Guard the typed-nil interface trap: only box a non-nil concrete client into
	// the SQLGenerator interface (a boxed nil would break the 409 path).
	if gen := PickExploreLLM(pol.Explore.LLMProvider, exploreClients, judgeClient); gen != nil {
		dashSrv.SetSQLGenerator(gen)
	}
	// LLM Providers card — READ-ONLY on the worker. Surface the configured registry
	// with per-provider resolved status against THIS worker's OWN env, so an operator
	// can SEE which providers are usable. Editing the registry is a control-plane /
	// local-only WRITER capability; a managed worker leaves the writer nil (PUT → 405)
	// because a worker has no live judge/SQLGenerator reload seam (both are built once
	// at Run) — persisting here without a rebuild would be a misleading half-feature.
	// The registry is captured from startup config (correct for a local-only worker;
	// a managed worker's edits land on the control-plane dashboard).
	startupProviders := pol.LLMProviders
	dashSrv.SetLLMProvidersSource(func() dashboard.LLMProvidersView {
		return dashboard.LLMProvidersView{Providers: BuildLLMProviderViews(startupProviders)}
	})
	adminMux.Handle("/healthz", adminSrv.Handler())
	// Reads stay open; every state-changing route on this listener — the
	// dashboard writers and /admin/* (POST /admin/refresh-secrets, #430) —
	// needs the worker admin bearer token and fails closed (403) when none is
	// configured. One shared bearer guard for both mounts, same as the control
	// plane's.
	adminTokenEnv := config.ResolveAdminTokenEnv(pol, p.AdminTokenEnv)
	adminToken := ""
	if adminTokenEnv != "" {
		adminToken = os.Getenv(adminTokenEnv)
	}
	// Name the env var (never its value) so a typo'd name is visible at boot.
	if strings.TrimSpace(adminToken) == "" {
		logger.Warn("worker dashboard writes are disabled: set "+adminTokenEnvName(adminTokenEnv), "tokenEnv", adminTokenEnv)
	} else {
		logger.Info("worker dashboard writes require the admin token", "tokenEnv", adminTokenEnv)
	}
	adminBearer := dashboard.NewBearerWriteGuard(dashboard.BearerGuardConfig{
		Token: adminToken, Logger: logger, Component: "worker", TokenName: "worker admin token",
		ConfigHint: "Start it with --admin-token-env <ENV> (or admin.tokenEnv in the config; e.g. WARDEN_ADMIN_TOKEN)",
	})
	// admin.WriteGuard re-declares the dashboard's seam (the admin package
	// cannot import the dashboard), so the shared guard passes straight through.
	adminSrv.SetWriteGuard(admin.WriteGuard(adminBearer))
	adminMux.Handle("/admin/", adminSrv.Handler())
	dashSrv.SetWriteGuard(adminBearer)
	adminMux.Handle("/dashboard/", dashSrv.Handler())
	// Central ingest endpoint (aggregator mode only): workers POST event batches
	// here. It lives on the admin (private) listener, never the agent-facing port.
	if ingestHandler != nil {
		adminMux.Handle("/central/ingest", ingestHandler)
		logger.Info("central ingest endpoint enabled", "path", "/central/ingest", "addr", adminAddr)
	}
	// Prometheus /metrics lives ONLY on the admin (loopback/private) listener,
	// never the agent-facing proxy port. Registered only when metrics are on.
	if metricsHandler != nil {
		adminMux.Handle("/metrics", metricsHandler)
		logger.Info("metrics endpoint enabled", "path", "/metrics", "addr", adminAddr)
	}

	// The addresses the serving paths actually use and the startup log states:
	// an injected listener's bound address wins over the resolved one, exactly
	// like controlplane.Run's reportedAddr.
	proxyAddr := listenAddr
	if p.ProxyListener != nil {
		proxyAddr = p.ProxyListener.Addr().String()
	}
	adminServingAddr := adminAddr
	if p.AdminListener != nil {
		adminServingAddr = p.AdminListener.Addr().String()
	}

	// Admin+dashboard HTTP server. The injected listener wins; with none, the
	// goroutine binds adminAddr itself and a bind failure stays the logged,
	// non-fatal event it always was. Closing the server when Run returns (the
	// only exit after this point is pxy.Serve) releases the listener in every
	// shutdown path; Serve's own ErrServerClosed return is filtered below.
	adminHTTP := &http.Server{Handler: adminMux}
	defer func() { _ = adminHTTP.Close() }()
	go func() {
		logger.Info("admin+dashboard listening", "url", fmt.Sprintf("http://%s/dashboard/", adminServingAddr))
		ln := p.AdminListener
		if ln == nil {
			var lerr error
			ln, lerr = net.Listen("tcp", adminAddr)
			if lerr != nil {
				logger.Error("admin server stopped", "error", lerr)
				return
			}
		}
		if err := adminHTTP.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("admin server stopped", "error", err)
		}
	}()

	logger.Info("proxy listening", "addr", proxyAddr)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start the embedded alert pipeline under the run context (manager start +
	// detection tick loop, both ctx-scoped). Nil in fleet mode. The store is closed
	// by the deferred alerts.Close above, not on ctx.Done — the worker owns shutdown
	// ordering (async drain → StopInstances → store close).
	if alerts != nil {
		alerts.Start(ctx)
	}

	// Background workers tied to the proxy lifetime: control-plane policy polling
	// and central event forwarding. Both stop when ctx is cancelled.
	//
	// clk is the worker's time port (Overrides.Clock, assembly-only; production
	// is always clock.Real()). The loops below tick on it, so a test advances a
	// fake clock instead of sleeping.
	clk := clock.Real()
	if p.Overrides != nil && p.Overrides.Clock != nil {
		clk = p.Overrides.Clock
	}
	if controlPlane != nil {
		// applier rebuilds + atomically swaps the proxy's MCP gateway AND its
		// inline judge from the control-plane-distributed settings. It runs only for
		// MANAGED workers (this branch), so a local-only worker's seeded pol.MCP
		// gateway and pol.Judge are never touched. mcpMu (declared above) guards
		// liveMCPGW against the shutdown defer.
		applier := &SettingsApplier{
			cp:               controlPlane,
			p:                pxy,
			mcpScanner:       mcpScanner,
			mcpStore:         mcpStore,
			agentID:          agentID,
			logger:           logger,
			logCtrl:          logCtrl,
			signedStore:      signedStore,
			complianceMapper: complianceMapper,
			secretFetcher:    secretFetcher,
			placeholders:     placeholders,
			pol:              pol,
			obsCfg:           obsCfg,
			mcpMu:            &mcpMu,
			liveMCPGW:        &liveMCPGW,
			liveCompliance:   liveCompliance,
			liveCacheTTL:     liveCacheTTL,
		}
		go longPollControlPlane(ctx, clk, controlPlane, evaluator, pol.ControlPlane.LongPollWait, logger, applier.Apply)
		go heartbeatControlPlane(ctx, clk, controlPlane, pol.ControlPlane.HeartbeatInterval, logger)
	}
	if syncWorker != nil {
		syncWorker.Start(ctx)
	}
	// Forward this worker's MCP inventory + observed schema to the control plane
	// (only when both MCP and central worker forwarding are on).
	if centralRemote != nil && mcpGW != nil {
		go pushMCPSnapshots(ctx, mcpGW, centralRemote, pol.Central.MCPPushInterval, logger)
	}

	// Both listeners are bound and both servers are up: the kernel queues
	// connections in the accept backlogs, so an OnReady probe issued now is
	// drained the moment Serve starts (same discipline as controlplane.Run).
	// From here the serving paths own the listeners, so the boot-failure close
	// above stands down.
	booted = true
	if p.OnReady != nil {
		p.OnReady(proxyAddr, adminServingAddr)
	}
	return pxy.Serve(ctx)
}

// newSecretFetcher selects the worker's secret-resolution backend from
// pol.SecretStore. The result is a plain secrets.Fetcher, so the Cache, the
// applier's TTL rebuild, and the proxy swap all treat it identically regardless
// of backend:
//
//   - env (or omitted) → secrets.NewEnvFetcher(mapping): byte-identical to the
//     original path (the placeholder→envVar map resolves values from the
//     environment).
//   - echo → secrets.NewStoreFetcher(secrets.NewEchoStore()): the NON-PRODUCTION
//     echo store, where a placeholder resolves to itself. mapping is unused (the
//     placeholder IS the store key).
//   - aws → secrets.NewStoreFetcher over a read-scoped awsSecretStore backed by
//     the real net/http + SigV4 client (built from the resolved region/namePrefix
//     and ENV credentials). Missing creds fail fast here. mapping is unused.
//
// resolveSecretStore picks the secret-store backend a MANAGED worker reads
// through. The control-plane-distributed settings.Secrets selector wins when
// present (value-free: backend/region/namePrefix), so central config takes
// effect; otherwise it falls back to the worker's LOCAL pol.SecretStore (the CP
// sent no secrets block, or was unreachable at boot so distributed is nil). It is
// a pure function so the precedence is unit-testable, and mirrors
// resolveObservability's apply-on-RESTART discipline: the resolved backend is
// honored at the worker's next (re)start, not on a live long-poll.
func resolveSecretStore(distributed *config.SettingsWire, local config.Policy) config.SecretStoreConfig {
	if distributed != nil && distributed.Secrets != nil {
		return config.SecretStoreConfigFromSettings(distributed.Secrets)
	}
	return local.SecretStore
}

// newProxy is a test seam so tests can inspect the proxy.Config the worker
// assembles (e.g. that the secret scopes reach the proxy).
var newProxy = proxy.New

// awsSecretsClientFactory builds the AWS Secrets Manager client for a region,
// resolving credentials by precedence (explicit config keys → env → IMDS role).
// It is a package var so tests inject a fake without touching AWS or the network.
var awsSecretsClientFactory = secrets.NewAWSSecretsClient

// newSecretFetcher also returns the underlying SecretStore for the echo/aws
// backends (nil for env, which has no store) so the dashboard's read-only
// secretstore tab can list KEY metadata over the same store the Cache resolves
// through — without building a second backend client. The returned store is
// read-scoped in practice (the worker only ever calls Get/List through it).
func newSecretFetcher(pol config.Policy, mapping map[string]string) (secrets.Fetcher, secrets.SecretStore, error) {
	ss := pol.SecretStore
	switch ss.ResolvedBackend() {
	case config.SecretBackendEnv:
		return secrets.NewEnvFetcher(mapping), nil, nil
	case config.SecretBackendEcho:
		store := secrets.NewEchoStore()
		return secrets.NewStoreFetcher(store), store, nil
	case config.SecretBackendAWS:
		if ss.AWS == nil {
			return nil, nil, fmt.Errorf("secretStore.backend=aws requires an aws config block")
		}
		client, err := awsSecretsClientFactory(ss.AWS.Region, ss.AWS.AccessKeyID, ss.AWS.SecretAccessKey)
		if err != nil {
			return nil, nil, fmt.Errorf("secretStore.backend=aws: %w", err)
		}
		store := secrets.NewAWSSecretStore(client, ss.AWS.Region, ss.AWS.NamePrefix)
		return secrets.NewStoreFetcher(store), store, nil
	default:
		return nil, nil, fmt.Errorf("secretStore.backend %q is not supported", ss.Backend)
	}
}

// adminTokenEnvName is the env var to tell the operator to set: the resolved one,
// or the conventional example when none is configured.
func adminTokenEnvName(resolved string) string {
	if resolved == "" {
		return "--admin-token-env <ENV> (or admin.tokenEnv)"
	}
	return resolved
}
