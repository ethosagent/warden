// Package controlplane implements the Warden control plane: a server that
// distributes allow/deny policy to data-plane workers and aggregates their
// analytics for a fleet dashboard.
//
// Boundary invariant: the control plane is policy + visibility ONLY. It never
// holds or serves secrets. The policy sent to workers is an explicit allow/deny
// wire type (policyWire), so a future field added to config.Policy can never
// accidentally leak across the boundary — the guarantee is structural, not a
// matter of struct tags.
package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/alertpipeline"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/detect"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config configures the control-plane server.
type Config struct {
	// State is the durable control-plane state database (<state-dir>/warden-cp.db).
	// Nil without --state-dir, in which case behaviour is unchanged. Run opens
	// it and closes it after the HTTP server drains; feature stores build on
	// State.SQL() and register their migrations through cpstate.Open.
	State *cpstate.DB
	// PolicyStore is the --policy-store mode: PolicyStoreFile ("" = file, the
	// default) serves PolicyPath; PolicyStoreVersioned serves the head version
	// of the versioned store in State (and needs State; Run enforces it). With
	// an empty store (head 0) versioned mode serves PolicyPath exactly as file
	// mode does.
	PolicyStore string
	// AdminAudit is the signed admin audit chain on State. Nil means admin
	// audit is disabled (console.adminAudit.enabled false, the default).
	AdminAudit *adminaudit.Store
	// PolicyPath is the YAML file whose allow/deny policy is served to workers.
	// It is re-read on each /policy request so edits propagate on the next poll.
	PolicyPath string
	// Token is the shared (legacy) bearer token workers may present on /policy,
	// /control/heartbeat and /central/ingest, next to per-worker tokens. Empty
	// selects open mode: anonymous callers are accepted (development only).
	Token string
	// AdminToken is the CP's own admin bearer (--admin-token-env): the token
	// dashboard writes and /central/secrets take in console.auth none. It never
	// authenticates a worker route. Empty falls back to Token (back-compat)
	// unless RequireAdminToken is set.
	AdminToken string
	// RequireAdminToken is set when --admin-token-env was given. It turns the
	// fallback to Token off, so a flag naming an empty variable refuses writes
	// instead of reopening them to the shared worker token.
	RequireAdminToken bool
	// RequireWorkerTokens is --require-worker-tokens: the worker routes accept
	// wwt_ tokens only (strict mode). Run refuses it together with a shared
	// token, without a state dir, or without TLS.
	RequireWorkerTokens bool
	// MaxEvents caps the central analytics store (0 = default).
	MaxEvents int
	// Store is the fleet analytics backend (persistent SQLite or in-memory). When
	// nil, New defaults to an in-memory CentralStore(MaxEvents) — unchanged
	// behavior. A SQLite-backed store additionally powers the dashboard's read-only
	// Query Builder (it implements analytics.AnalyticsQuery).
	Store analytics.FleetStore
	// Logger receives lifecycle and policy-load logs. Defaults to slog.Default().
	Logger *slog.Logger
	// Integrations are the CP-hosted outbound alert integrations to run. Empty ⇒
	// no manager is constructed (zero overhead; policy serving is unaffected).
	Integrations []integration.InstanceConfig
	// AlertDBPath is the SQLite file backing the alert system-of-record. It must
	// be a real file path (not ":memory:", which is not shared across
	// connections). Required (non-empty) for integrations to run; ignored when
	// Integrations is empty.
	AlertDBPath string
	// SecretStore is the WRITE-scoped secret store backing the /central/secrets
	// endpoints. Nil (env/empty backend, or aws pre-Phase-5) ⇒ those endpoints are
	// NOT mounted and the control plane behaves exactly as before. Built from the
	// operator's OWN pol.SecretStore backend (see NewSecretStore), mirroring how
	// Store / Integrations are injected. The control plane holds a value only in
	// transit on Put and never persists one (see the secrets handlers).
	SecretStore secrets.SecretStore
	// SecretStoreBackend names the SecretStore's backend (echo/aws) for the
	// dashboard's read-only secretstore tab. Empty when no writable store is
	// configured, in which case that tab reports backend "none".
	SecretStoreBackend string
	// Console is the CP-local console sign-in config, resolved from --config by
	// resolveConsole. In oidc mode with State set it turns on server-side
	// sessions, login and role enforcement on /dashboard/ and /central/secrets;
	// the zero value (Auth "" == none) changes no behaviour.
	Console config.ConsoleConfig
	// ClientSecret is the console OIDC client secret, read by Run from the
	// environment variable console.oidc.clientSecretEnv names. It is never logged.
	ClientSecret string
	// Now is the clock for sessions, pending logins and ID-token checks (nil =
	// time.Now). The L1 harness injects its fake clock through Params.Clock.
	Now func() time.Time
	// DetectionEnabled gates the temporal-detection engine. When true (the
	// default when no detection block disables it), New builds the engine AND — so
	// alerts land without any sink configured — the always-on Alert Store (the
	// Manager is built even with ZERO integration instances, provided AlertDBPath
	// is set). When false the control plane behaves exactly as before (no engine;
	// the Manager is built only when integrations are configured).
	DetectionEnabled bool
	// Detection is the fully-resolved engine config (defaults already applied by
	// the cmd converter). Ignored when DetectionEnabled is false.
	Detection detect.Config
	// DetectionTick is how often the engine is evaluated and its Findings
	// published onto the alert bus. <= 0 falls back to DefaultDetectionTick.
	DetectionTick time.Duration
	// DetectionConfig is the CP-local typed detection config (operator overrides).
	// It is the source the dashboard detection editor reads and the base the
	// WriteDetection round-trip persists; the resolved Detection/DetectionEnabled/
	// DetectionTick fields above still drive the initial engine build.
	DetectionConfig config.DetectionConfig
	// ResolveTTL is the silence window after which a firing alert auto-resolves
	// (P4). 0 selects the AlertManager default; a negative value disables it.
	ResolveTTL time.Duration
	// Clock is the control plane's time port (nil = clock.Real()). The console
	// query/generate rate limit ticks on it.
	Clock clock.Clock
	// WorkerTokens is the per-worker token store. Run builds it when State is
	// open; nil means no wwt_ token is accepted and behaviour is unchanged.
	WorkerTokens *WorkerTokenStore
	// TLS reports that the control plane serves TLS; without it, token auth logs
	// a clear-text warning at startup.
	TLS bool
}

// policyWire is the shape sent to workers: allow/deny policy plus the optional
// behavioral settings document. Secrets never appear here — Settings is the
// explicit, secret-free config.SettingsWire (env-name references only), so a
// value can never accidentally cross the boundary. Settings is omitempty so a
// control plane serving only allow/deny stays byte-identical to before (the
// "settings" key is simply absent → back-compatible).
type policyWire struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
	// BlockedUsers is the user block list (sub and email only; reason and actor
	// stay on the CP). Omitempty keeps the wire and ETag unchanged when empty.
	BlockedUsers []config.BlockedUser `json:"blockedUsers,omitempty"`
	Settings     *config.SettingsWire `json:"settings,omitempty"`
	// ScopedAllowlist and ScopedAllowPos are filled only by projectScoped, at
	// serve time: identity-scoped allow entries move out of Allowlist so a
	// worker that decodes leniently cannot read one as global. Never stored.
	ScopedAllowlist []config.AllowlistEntry `json:"scopedAllowlist,omitempty"`
	ScopedAllowPos  []int                   `json:"scopedAllowPos,omitempty"`
}

// Long-poll bounds and the external-edit re-read cadence.
const (
	minLongPollWait      = 1 * time.Second
	maxLongPollWait      = 60 * time.Second
	policyReloadInterval = 3 * time.Second
	// retentionPruneInterval is how often the persistent fleet store prunes events
	// past its retention window. Retention is coarse, so an hourly sweep is ample.
	retentionPruneInterval = 1 * time.Hour
	// DefaultDetectionTick is the fallback evaluate cadence for the temporal
	// detection engine when Config.DetectionTick is unset (<= 0). It is re-exported
	// from alertpipeline so the cmd converter, this package, and the pipeline all
	// agree on one default value.
	DefaultDetectionTick = alertpipeline.DefaultDetectionTick
)

// Server is the control plane. It is safe for concurrent use. Its
// responsibilities are named by role interfaces its parts satisfy: policy is
// served by the composed PolicyServer (policy); config editing is the
// ConfigEditor seam (writePolicy/writeSettings); the fleet is tracked by the
// WorkerTracker seam; and central ingest lands in the IngestSink seam.
type Server struct {
	cfg      Config
	central  analytics.FleetStore
	registry *WorkerRegistry
	mcp      *mcpStore
	policy   *policyServer
	// workerAuth authenticates /policy, /control/heartbeat and /central/ingest.
	workerAuth *WorkerAuthenticator
	// versions is the versioned policy store; nil in file mode. Its Create
	// refreshes the policy server, so long-poll waiters wake at once.
	versions PolicyVersionStore

	// blocks is the user block list store; nil without State (and then no
	// blocked_users overlay is registered).
	blocks  *BlockStore
	writeMu sync.Mutex // serializes policy + integrations edits
	// gp holds the scoped-rule count of the served ETag and the per-worker
	// "lacks grouppolicy" log marks (W-P1-GPOL-07).
	gp groupPolicyFlags
	// pipeline is the embeddable alert-delivery assembly (manager + engine + tick +
	// bridge). Nil when no alert DB path is configured (or when its store/manager
	// failed to build — fail-open: a broken alert config never stops policy
	// serving). It owns the live manager pointer and the reload swap; the CP
	// delegates its integrations reload to pipeline.ReloadManager (design A), so
	// there is a single source of truth for "the live manager".
	pipeline *alertpipeline.Pipeline
	// integrationsStore is the alert system-of-record, owned by the Server (NOT the
	// pipeline) so a live reload can build a new manager over the SAME store without
	// closing it. The pipeline holds a non-owning reference for rebuilds; the Server
	// closes it exactly once, at shutdown. Nil ⇒ integrations unavailable.
	integrationsStore *integration.Store
	// secretStore backs the /central/secrets write path. Nil ⇒ the endpoints are
	// not mounted (env/empty backend, or aws pre-Phase-5).
	secretStore secrets.SecretStore
	// detectionConfig is the live typed detection config the dashboard editor reads
	// and WriteDetection updates. detectionMu guards it (a short read on GET, a write
	// at the end of WriteDetection) independent of writeMu so a GET never blocks on a
	// slow write's file IO.
	detectionMu     sync.RWMutex
	detectionConfig config.DetectionConfig
	// dash is the fleet dashboard built in Handler, retained so a settings /
	// llmProviders edit can RE-INJECT the Explore NL→SQL generator live (the CP's
	// only in-process LLM consumer; the judge runs on workers). Set once in Handler
	// before serving, then read under writeMu by WriteSettings/WriteLLMProviders.
	dash *dashboard.Server
	// sessions and sessionCookie are set only in console.auth oidc with a state
	// DB. When set, Handler wraps /dashboard/ and /central/secrets in withSession.
	sessions      *SessionStore
	sessionCookie SessionCookie
	sessionReader sessionReader
	// generateLimit is the per-session token bucket on POST
	// /dashboard/api/query/generate in oidc mode (it spends LLM tokens).
	generateLimit *sessionLimiter
	// auth is the console OIDC login (/auth/login, /auth/callback); set only when
	// sessions are.
	auth *authService
	// audit is the admin audit middleware's state; nil when cfg.AdminAudit is
	// (admin audit disabled), in which case no route is wrapped.
	audit *adminAuditor
	// breakGlass is the break-glass login (POST /auth/breakglass); nil unless
	// console.breakGlass.enabled (W-P1-OPS1-08).
	breakGlass *breakGlass
	// findings, when set, receives every Finding instead of the alert pipeline.
	// Tests inject a fake here.
	findings FindingPublisher
	// auditRec is cfg.AdminAudit as a Recorder (nil with admin audit off) and ext
	// tracks the served file's hashes for the file-mode external-edit audit
	// (adminaudit_external.go).
	auditRec adminaudit.Recorder
	ext      externalEdits
	// mirror is the versioned-mode write-through mirror and drift state
	// (W-P1-PVER-05, policystore.go); unused in file mode.
	mirror policyMirror
}

// Compile-time assertions that the concrete types satisfy their role interfaces.
var (
	_ PolicyServer  = (*policyServer)(nil)
	_ ConfigEditor  = (*Server)(nil)
	_ WorkerTracker = (*WorkerRegistry)(nil)
	_ IngestSink    = (*ingestSink)(nil)
)

// pruner is the optional retention capability a persistent store exposes: delete
// events past the configured retention window. The in-memory store does not
// implement it (it is size-capped on write), so retention pruning is skipped.
type pruner interface {
	PruneExpired() error
}

// New constructs a control-plane Server. It uses cfg.Store when set (e.g. a
// persistent SQLite fleet store); otherwise it defaults to an in-memory
// CentralStore(MaxEvents) — unchanged behavior.
func New(cfg Config) *Server {
	// A whitespace-only token (a stray space or newline in an env file) is NOT a
	// token: it counts as unset, so dashboard writes fail closed with the hint.
	cfg.Token = strings.TrimSpace(cfg.Token)
	cfg.AdminToken = strings.TrimSpace(cfg.AdminToken)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real()
	}
	store := cfg.Store
	if store == nil {
		store = analytics.NewCentralStore(cfg.MaxEvents)
	}
	registry := NewWorkerRegistry()
	s := &Server{
		cfg:      cfg,
		central:  store,
		registry: registry,
		mcp:      newMCPStore(),
		// The policy-serving component owns the watch; the initial load runs below,
		// after serve-time overlay registration.
		policy: newPolicyServer(cfg.PolicyPath, cfg.Token, cfg.Logger, registry),
		// Write-scoped secret store (nil ⇒ /central/secrets not mounted).
		secretStore: cfg.SecretStore,
		// Live typed detection config for the dashboard editor + WriteDetection base.
		detectionConfig: cfg.DetectionConfig,
		generateLimit:   newSessionLimiter(cfg.Clock, queryGenerateLimit, time.Minute),
	}
	// One authenticator for the three worker routes; the policy server was built
	// with a default one, replaced here by the configured one.
	s.workerAuth = NewWorkerAuthenticator(WorkerAuthConfig{
		Legacy: cfg.Token, Tokens: cfg.WorkerTokens, Registry: registry,
		Logger: cfg.Logger, Clock: cfg.Clock, TLS: cfg.TLS, Strict: cfg.RequireWorkerTokens,
	})
	s.policy.auth = s.workerAuth
	s.workerAuth.LogMode()
	// Register serve-time wire overlays (s.policy.addOverlay) here, before the
	// initial load, so they apply to the first served wire. Versioned mode
	// registers credential; W-P1-BLOCK-03 adds blocked_users.
	s.initPolicyStore()
	s.initBlockStore()
	s.policy.Refresh() // initial load so /policy and the dashboard have policy immediately
	s.initSessions()
	s.initAuth()
	s.initBreakGlass()
	s.warnAdminToken()
	s.failClosedWithoutAdminToken()
	if cfg.AdminAudit != nil {
		s.enableAdminAudit(cfg.AdminAudit, cfg.AdminAudit.Probe, cfg.AdminAudit.StateHash)
		s.auditRec = cfg.AdminAudit
		s.primeExternalEdit()
	}
	// Alert pipeline (CP-hosted alert delivery + always-on Alert Store). Constructed
	// whenever an alert DB path is set — even with ZERO configured integrations —
	// because it serves two always-on purposes:
	//   (a) the dashboard can ADD the first integration later: the reload rebuilds
	//       the manager over this same store (the Server, not the manager, owns the
	//       store so a reload can swap managers without closing it); and
	//   (b) with temporal detection ON (the default) the always-on Alert Store means
	//       detector Findings land in the store (and the dashboard /alerts) even with
	//       ZERO sinks configured — the Router simply binds none.
	// This gate is the SUPERSET of both: detection's Findings need the bus/store,
	// which now always exist when AlertDBPath is set. FAIL-OPEN: a store-open or
	// manager-build error is logged and skipped — a broken alert config must NEVER
	// stop the control plane serving policy.
	//
	// The Server OPENS the store (it owns the DB lifecycle and closes it once at
	// shutdown) and hands it to the embeddable alertpipeline, which builds the
	// manager + optional detection engine + tick + bridge. The pipeline never
	// closes the store. Detection is built inside the pipeline only when enabled AND
	// a manager came up (there must be a bus to publish onto) — the same gate as
	// before. Fail-open: if the store fails to OPEN, or the pipeline fails to build
	// a manager, alerting is disabled and the Server serves policy exactly as before.
	if cfg.AlertDBPath != "" {
		if store, err := integration.NewStore(cfg.AlertDBPath); err != nil {
			cfg.Logger.Error("control plane: alert pipeline disabled (alert store open failed)", "error", err)
		} else {
			p := alertpipeline.New(alertpipeline.Config{
				Store:      store,
				Instances:  cfg.Integrations,
				Detection:  cfg.Detection,
				Detect:     cfg.DetectionEnabled,
				Tick:       cfg.DetectionTick,
				ResolveTTL: cfg.ResolveTTL,
				Logger:     cfg.Logger,
			})
			if p.CurrentManager() == nil {
				// Manager build failed (fail-open): close the store we opened; the
				// pipeline built nothing runnable. Alerting stays disabled.
				cfg.Logger.Error("control plane: alert pipeline disabled (manager build failed)")
				_ = store.Close()
			} else {
				s.integrationsStore = store
				s.pipeline = p
			}
		}
	}
	return s
}

// Start launches the periodic re-read that catches EXTERNAL edits to the served
// policy file (editor edits refresh synchronously). It also starts the retention
// prune loop when the store supports it. It returns when ctx is done.
func (s *Server) Start(ctx context.Context) {
	if s.sessions != nil {
		go s.sweepSessions(ctx)
	}
	if s.auth != nil {
		go s.auth.discover(ctx)
		go s.auth.sweep(ctx)
	}
	// Alert pipeline: start the embeddable assembly (manager start + the
	// detection tick loop, both ctx-scoped). The pipeline captures ctx as its
	// lifecycle context so a live reload can bind a rebuilt manager's router
	// goroutines to the process lifetime. It does NOT close the store — the Server
	// owns that. A separate ctx-watcher stops the CURRENT manager's instances (a
	// reload may have swapped it) and then closes the Server-owned store exactly
	// once, preserving the StopInstances→Close ordering.
	if s.pipeline != nil {
		s.pipeline.Start(ctx)
	}
	if s.integrationsStore != nil {
		go func() {
			<-ctx.Done()
			if err := s.pipeline.StopInstances(context.Background()); err != nil {
				s.cfg.Logger.Warn("control plane: integrations shutdown error", "error", err)
			}
			if err := s.integrationsStore.Close(); err != nil {
				s.cfg.Logger.Warn("control plane: integrations store close error", "error", err)
			}
		}()
	}

	go func() {
		t := time.NewTicker(policyReloadInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.reloadPolicy(ctx)
			}
		}
	}()

	// Retention: a persistent store prunes events past its retention window on a
	// slow cadence. The in-memory store does not implement pruner (it is
	// size-capped on write), so this loop simply never starts for it.
	if p, ok := s.central.(pruner); ok {
		go func() {
			if err := p.PruneExpired(); err != nil { // once at startup
				s.cfg.Logger.Warn("control plane: analytics retention prune failed", "error", err)
			}
			t := time.NewTicker(retentionPruneInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := p.PruneExpired(); err != nil {
						s.cfg.Logger.Warn("control plane: analytics retention prune failed", "error", err)
					}
				}
			}
		}()
	}
}

// refresh reloads the served policy and wakes long-poll waiters. It delegates to
// the composed PolicyServer; the writePolicy/writeSettings editors call it after
// an atomic write so waiters serve the new policy immediately. Kept as a thin
// Server method so config-editing stays cohesive with the edit that triggers it.
func (s *Server) refresh() { s.policy.Refresh() }

// writePolicy / writeSettings are unexported forwarders to the exported
// ConfigEditor methods with no caller identity or write metadata, kept so
// internal call sites (and tests) read naturally.
func (s *Server) writePolicy(p config.Policy) error {
	return s.WritePolicy(context.Background(), p, dashboard.WriteMeta{})
}

func (s *Server) writeSettings(in config.SettingsWire) error {
	return s.WriteSettings(context.Background(), in, dashboard.WriteMeta{})
}

// Handler returns the control plane's HTTP routes:
//
//	GET  /policy          — allow/deny policy for workers (worker token or shared bearer)
//	POST /control/heartbeat, /central/ingest — worker heartbeat and fleet analytics ingest (same auth)
//	     /dashboard/      — fleet dashboard over the aggregated store (writes bearer-auth; sessions in oidc mode)
//	     /central/secrets — secret store writes, when one is configured (bearer; admin session in oidc mode)
//	GET  /healthz         — liveness
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	// /policy is served by the composed PolicyServer seam (serve + ETag long-poll).
	var policyServe PolicyServer = s.policy
	mux.HandleFunc("/policy", policyServe.ServePolicy)
	mux.HandleFunc("/control/heartbeat", s.handleHeartbeat)
	ingest := analytics.NewIngestHandler(s.central, s.workerAuth.IngestAuthorizer())
	// Central ingest lands in the IngestSink seam: tag worker activity in the
	// registry and store each worker's MCP snapshot. Wiring the seam's methods (vs
	// reaching into fields) documents the ingest surface; behavior is unchanged.
	var sink IngestSink = &ingestSink{registry: s.registry, mcp: s.mcp}
	ingest.SetOnIngest(sink.SeenIngest) // track which workers are forwarding
	ingest.SetOnMCP(sink.UpdateMCP)     // store each worker's MCP snapshot
	// Feed each ingested batch into the alert pipeline's Observe fan-in. Inside the
	// pipeline two consumers run over the same batch: (1) the temporal-detection
	// engine folds it into windowed state (the Start tick loop later Evaluates +
	// publishes), and (2) the event→Finding bridge publishes immediate block/reason
	// Findings onto the CURRENT manager's bus (a reload may have swapped it). Both
	// nil-safe; fail-open.
	if s.integrationsStore != nil {
		ingest.SetOnEvents(func(proxyID string, events []analytics.Event) {
			s.pipeline.Observe(proxyID, events)
		})
	}
	mux.Handle("/central/ingest", ingestAuthErrors(ingest))

	// Secret write path (/central/secrets), mounted ONLY when a writable store is
	// configured (echo now; aws in Phase 5). A nil store means the routes are
	// absent → 404, so a control plane on backend env/none behaves exactly as
	// before. In console.auth none the handlers apply the SAME constant-time
	// bearer gate as the other /central/* routes; in oidc mode they need an admin
	// session plus CSRF (secretsAuthOK). GET returns metadata only, and a POST
	// value is held in transit only and logged by-reference, never persisted.
	// With admin audit on, POST and DELETE are recorded (sessionAuditWrap).
	if s.secretStore != nil {
		cpRoutes := cpRouteTable()
		mux.Handle("/central/secrets", s.sessionAuditWrap(patternRoute(cpRoutes, "/central/secrets"), http.HandlerFunc(s.handleSecrets)))
		mux.Handle("/central/secrets/", s.sessionAuditWrap(patternRoute(cpRoutes, "/central/secrets/"), http.HandlerFunc(s.handleSecretByKey)))
	}

	// The fleet dashboard reads the aggregated central store. The control plane
	// holds no secrets, so it is given an empty secret provider and a
	// secret-free policy view; the dashboard's secrets panel is naturally empty.
	emptySecrets, _ := secrets.NewCache(secrets.NewEnvFetcher(map[string]string{}), 0, nil)
	wire, _, _, _ := s.policy.snapshot()
	dashPolicy := config.Policy{Allowlist: wire.Allowlist, Denylist: wire.Denylist}
	dash := dashboard.NewServer(s.central, dashPolicy, emptySecrets)
	// Retain the dashboard so a settings / llmProviders edit can re-inject the
	// Explore NL→SQL generator live (see injectExploreLLM). Set before serving.
	s.dash = dash
	// Policy panel reflects the live served policy (the watch), so edits show
	// immediately rather than a startup snapshot.
	dash.SetLivePolicy(func() config.Policy {
		w, _, _, _ := s.policy.snapshot()
		return config.Policy{Allowlist: w.Allowlist, Denylist: w.Denylist}
	})
	// Editing is a control-plane-only capability, sourced from the ConfigEditor
	// seam: persist edits to the served config file so workers pull them on their
	// next poll. The read side reflects the live watch.
	// In versioned mode each writer creates a policy version authored by the
	// request's Principal instead.
	var editor ConfigEditor = s
	dash.SetPolicyWriter(func(ctx context.Context, p config.Policy, meta dashboard.WriteMeta) error {
		if err := editor.WritePolicy(ctx, p, meta); err != nil {
			return err
		}
		// The admin audit entry (when enabled) names the version written.
		adminaudit.Annotate(ctx, "policy@"+s.policy.currentETag(), nil)
		return nil
	})
	// Drift banner: a hand edit of the served YAML in versioned mode
	// (W-P1-PVER-05). Always false in file mode.
	dash.SetPolicyDrift(s.policyDrift)
	// The settings writer is context-aware: in oidc mode it authorizes the edit
	// per field against the caller's role (writeSettingsAs); in none mode it is
	// editor.WriteSettings unchanged.
	dash.SetSettingsWriter(s.writeSettingsAs)
	dash.SetLiveSettings(func() *config.SettingsWire {
		w, _, _, _ := s.policy.snapshot()
		return w.Settings
	})
	// Read-only Query Builder: when the fleet store is SQL-backed (implements
	// AnalyticsQuery), expose its sandboxed query surface to the dashboard. The
	// in-memory store does not implement it, so the Query Builder reports
	// unavailable in that case.
	if q, ok := s.central.(analytics.AnalyticsQuery); ok {
		dash.SetQueryEngine(q)
	}
	// NL→SQL for the Explore tab honors explore.llmProvider (a named registry entry),
	// falling back to the judge's client — resolved from the CP's OWN env. Factored
	// into injectExploreLLM so a settings / llmProviders edit re-injects it live
	// (WriteSettings / WriteLLMProviders). Fail-soft: an unresolved selection clears
	// the generator (→ the Explore tab's "add an LLM provider" 409) and never blocks
	// CP start.
	s.injectExploreLLM(dash)
	// LLM Providers card: the source lists the CP's effective registry (from the
	// distributed settings) with per-provider resolved status against the CP's OWN
	// env; the writer persists the `llmProviders` block and reloads the consumers.
	// Editing is control-plane-only (workers get the source, not the writer → 405).
	dash.SetLLMProvidersSource(s.llmProvidersView)
	dash.SetLLMProvidersWriter(editor.WriteLLMProviders)
	// Version contract (W-P1-PVER-08): in versioned mode the policy, settings
	// and llmProviders GETs report the shared head and writes read If-Match
	// into WriteMeta.ExpectedHead; file mode reports no version.
	dash.SetPolicyVersion(s.policyVersionHead)
	// Block list admin API (W-P1-BLOCK-11). Without a state DB the stub answers
	// 503 state_dir_required; the hasher is a no-op without admin audit.
	dash.SetBlockListStore(s.blockListStore())
	s.RegisterStateHasher(blockedUsersTarget, s.blockedUsersHash)
	if s.versions != nil {
		// HTTP saves record before and after as v<N>:<doc_sha256>, replacing
		// the built-in hasher of the served allow/deny. A no-op without admin
		// audit.
		s.RegisterStateHasher(auditTargetPolicy, s.versionedPolicyHash)
		// History, diff and rollback routes (W-P1-PVER-03); without this they
		// answer 404.
		dash.SetPolicyHistory(s.policyHistoryAPI())
	}
	// Per-worker MCP view (inventory + observed schema), selected by ?proxy=.
	dash.SetMCPFleet(s.mcp.For)
	// Connected-workers list for the fleet view, with a "behind" flag for any
	// worker whose policy version differs from what the CP currently serves,
	// and (versioned mode) the version its heartbeat ETag maps to.
	var tracker WorkerTracker = s.registry
	dash.SetWorkers(func() []dashboard.WorkerView {
		cur := s.policy.currentETag()
		views := tracker.Views()
		FlagNoGroupPolicy(views, s.scopedEntries())
		for i := range views {
			views[i].Behind = views[i].PolicyETag != "" && views[i].PolicyETag != cur
		}
		fillPolicyVersions(s.versions, views)
		s.fillWorkerAuth(views)
		return views
	})
	// Worker token admin routes and their audit hasher (W-P1-WTOK-03).
	s.wireWorkerTokens(dash)
	// Dashboard-V3 read tabs. Each source EXISTS on the control plane:
	//   - secretstore: the CP's WRITE store lists KEY metadata (never values). Nil
	//     store (env/none backend) → the tab reports backend "none".
	//   - alerts: the integrations manager's alert store. Nil manager → the tab
	//     returns []. Wired only when integrations are configured.
	//   - audit: compliance is aggregated from the aggregated event store by the
	//     dashboard itself; the CP does not SIGN receipts (workers do), so no
	//     receipts source is wired and the receipts block stays zeroed.
	dash.SetSecretStore(s.secretStore, s.cfg.SecretStoreBackend)
	dash.SetAuthMode(s.authMode())
	// Admin audit log API (W-P1-AAUD-03): only with console.adminAudit on;
	// without a source the dashboard answers 404 and hides the tab.
	if s.cfg.AdminAudit != nil {
		dash.SetAdminAudit(adminAuditDashSource{store: s.cfg.AdminAudit, logger: s.cfg.Logger})
	}
	if s.integrationsStore != nil {
		// Alerts + integration status read from the CURRENT manager (re-pointed on
		// reload), so a reload never silently breaks the alerts tab or the status view.
		dash.SetAlerts(func(limit int) []integration.Alert {
			m := s.currentManager()
			if m == nil {
				return nil
			}
			return m.ListAlerts(limit)
		})
		dash.SetIntegrationsSource(s.integrationStatuses)
		// Editing integrations is a control-plane-only capability that persists to the
		// served config file and reloads the live manager. Workers never set this, so
		// they expose no integrations-write path (POST/DELETE → 405).
		dash.SetIntegrationsWriter(func(insts []config.IntegrationInstance) error {
			if err := s.WriteIntegrations(insts); err != nil {
				return err
			}
			return s.reloadIntegrations(toManagerInstances(insts))
		})
		// Detection editor (CP-only, mirrors integrations): the source is the live
		// typed config plus the engine's active-detector names + eviction count; the
		// writer persists the `detection:` block and hot-reloads the live engine.
		dash.SetDetectionSource(func() dashboard.DetectionView {
			return dashboard.NewDetectionView(s.currentDetectionConfig(), s.pipeline.Detectors(), s.pipeline.Evictions())
		})
		dash.SetDetectionWriter(s.WriteDetection)
	}
	// Write guard and mount (bearer in none mode; sessions and roles in oidc): routes.go.
	s.mountDashboard(mux, dash)
	s.registerAuthRoutes(mux)

	return mux
}

// handleHeartbeat records a worker liveness ping. Body: {"policyETag": "...", "caps": ["blocklist/v1"]}.
// It is one of the three worker→CP interactions; the CP never calls the worker.
func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	principal, err := s.workerAuth.Authenticate(r)
	if err != nil {
		WriteWorkerAuthError(w, err)
		return
	}
	var body struct {
		PolicyETag string   `json:"policyETag"`
		Caps       []string `json:"caps"`
	}
	// Body is optional/tiny; ignore decode errors (heartbeat is best-effort).
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body)
	caps := normalizeCaps(body.Caps)
	s.registry.SeenHeartbeat(principal.ProxyID, trimETag(body.PolicyETag), caps)
	s.noteGroupPolicy(principal.ProxyID, caps)
	w.WriteHeader(http.StatusNoContent)
}

// capPattern is the shape of an accepted worker capability string.
var capPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,31}$`)

// maxCaps bounds the capabilities kept per heartbeat.
const maxCaps = 16

// normalizeCaps drops capability strings that do not match capPattern, removes
// duplicates, sorts, and keeps at most maxCaps. It never trusts the worker.
func normalizeCaps(in []string) []string {
	var out []string
	for _, c := range in {
		if capPattern.MatchString(c) {
			out = append(out, c)
		}
	}
	sort.Strings(out)
	out = slices.Compact(out)
	if len(out) > maxCaps {
		out = out[:maxCaps]
	}
	return out
}

// policyYAML is the policy sub-block written back when policy is edited from the
// dashboard: allow/deny only — never secrets, which the control plane does not
// hold.
type policyYAML struct {
	Allowlist []config.AllowlistEntry `yaml:"allowlist"`
	Denylist  []config.DenylistEntry  `yaml:"denylist"`
	// BlockedUsers keeps policy.blockedUsers in the file across an edit.
	BlockedUsers []config.BlockedUser `yaml:"blockedUsers,omitempty"`
}

// writePolicy validates and atomically persists an edited allow/deny policy to
// the served file, so workers pull it on their next poll. It writes a temp file,
// validates it with the full config loader (rejecting an invalid edit), then
// renames it into place — so a bad edit never replaces a good policy.
//
// The CP config file may carry behavioral blocks (mcp/judge/observability/…)
// that the policy editor does not touch. To avoid silently deleting operator
// config, writePolicy round-trips the file through a top-level YAML map and
// rewrites ONLY the `policy` (and `logging`, when present) blocks, leaving every
// other block byte-for-byte intact.
//
// WritePolicy is the ConfigEditor seam's policy-write method; the lowercase
// writePolicy forwarder preserves the internal call sites. In versioned mode it
// creates a policy version instead (publishPolicy); ctx carries the author and
// meta the expected head and message. File mode ignores both.
func (s *Server) WritePolicy(ctx context.Context, p config.Policy, meta dashboard.WriteMeta) error {
	if s.versions != nil {
		return s.publishPolicy(ctx, p, meta)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	// Load the current file as a top-level YAML map so unknown/behavioral blocks
	// (mcp, judge, agents, observability, advisory, central, audit, secrets, …)
	// survive the edit untouched. A missing/unreadable file starts from empty.
	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the two
		// blocks we own; the loader validation below still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}

	if err := renderPolicyBlock(root, p.Allowlist, p.Denylist, p.BlockedUsers); err != nil {
		return err
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	// Update the watch immediately so any long-poll waiters wake and serve the
	// new policy now (rather than after the next periodic re-read).
	s.refresh()
	s.cfg.Logger.Info("control plane policy updated via dashboard",
		"allow", len(p.Allowlist), "deny", len(p.Denylist))
	return nil
}

// renderPolicyBlock replaces root's policy block with allow/deny and makes sure
// a logging block exists (kept from the current file when present, otherwise
// info/json). It is the policy half of WritePolicy and renderDocToRoot.
func renderPolicyBlock(root map[string]yaml.Node, allow []config.AllowlistEntry, deny []config.DenylistEntry, blocked []config.BlockedUser) error {
	var policyNode yaml.Node
	if err := policyNode.Encode(policyYAML{Allowlist: allow, Denylist: deny, BlockedUsers: blocked}); err != nil {
		return fmt.Errorf("controlplane: encode policy block: %w", err)
	}
	root["policy"] = policyNode
	if _, ok := root["logging"]; !ok {
		var logNode yaml.Node
		if err := logNode.Encode(map[string]string{"level": "info", "format": "json"}); err != nil {
			return fmt.Errorf("controlplane: encode logging block: %w", err)
		}
		root["logging"] = logNode
	}
	return nil
}

// readServedRoot is readRoot of the served file.
func (s *Server) readServedRoot() map[string]yaml.Node {
	return readRoot(s.cfg.PolicyPath)
}

// readRoot loads the config YAML at path (the served file, or a file being
// imported) as a top-level YAML map so blocks the caller does not own survive.
// A missing, unreadable or malformed file yields an empty map; the loader
// validation of the result still guards it.
func readRoot(path string) map[string]yaml.Node {
	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(path); err == nil {
		_ = yaml.Unmarshal(cur, &root)
	}
	return root
}

// renderDocToRoot renders a policy doc into root, a copy of the served YAML
// root: the policy block, the settings blocks WriteSettings owns and the
// llmProviders block, with the encoders the dashboard writers use. A
// credential the doc carries only as a fingerprint keeps the served file's
// live value (the preserve-on-empty rule). Blocks no dashboard writer owns
// (dlp, advisory) are left as the served file has them.
func renderDocToRoot(root map[string]yaml.Node, doc policyWire) error {
	if err := renderPolicyBlock(root, doc.Allowlist, doc.Denylist, nil); err != nil {
		return err
	}
	var settings config.SettingsWire
	if doc.Settings != nil {
		settings = *doc.Settings
	}
	if settings.Secrets != nil && isRedactedCredential(settings.Secrets.SecretAccessKey) {
		sec := *settings.Secrets
		sec.SecretAccessKey = ""
		settings.Secrets = &sec
	}
	if err := renderSettingsBlocks(root, settings); err != nil {
		return err
	}
	return renderLLMProvidersBlock(root, config.LLMProvidersFromSettings(settings.LLMProviders))
}

// validateDoc checks a candidate policy doc with the full config loader, the
// same check atomicWriteConfig makes before a write: it renders the doc into a
// copy of the served YAML root, writes it to a temp file and loads it. This
// enforces default-deny (an empty allowlist is rejected) and the cross-block
// references (judge/explore llmProvider). Nothing is persisted. Callers run it
// before PolicyVersionStore.Create.
func (s *Server) validateDoc(doc policyWire) error {
	return validateDocAgainst(s.cfg.PolicyPath, filepath.Dir(s.cfg.PolicyPath), doc)
}

// validateDocAgainst is validateDoc against the config YAML at rootPath: doc
// is rendered into a copy of that file's top-level map and the result is
// loaded from a temp file in tmpDir ("" = the system temp dir), then removed.
func validateDocAgainst(rootPath, tmpDir string, doc policyWire) error {
	root := readRoot(rootPath)
	if err := renderDocToRoot(root, doc); err != nil {
		return err
	}
	tmpName, err := writeValidatedTempIn(tmpDir, root)
	if err != nil {
		return err
	}
	_ = os.Remove(tmpName)
	return nil
}

// atomicWriteConfig marshals the top-level config map, writes it to a temp file
// in the policy file's directory, validates it with the full loader (so a bad
// edit can never replace a good config — default-deny is enforced here), then
// renames it into place. Callers refresh the watch afterward. The caller MUST
// hold s.writeMu.
func (s *Server) atomicWriteConfig(root map[string]yaml.Node) error {
	tmpName, err := s.writeValidatedTemp(root)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpName) }() // no-op once renamed
	// The bytes just validated, hashed by persist as this CP's own write so the
	// file-mode re-read does not audit it as an external edit (W-P1-AAUD-08).
	data, err := os.ReadFile(tmpName)
	if err != nil {
		return fmt.Errorf("controlplane: read temp policy: %w", err)
	}
	if err := s.ext.persist(tmpName, s.cfg.PolicyPath, data); err != nil {
		return fmt.Errorf("controlplane: persist policy: %w", err)
	}
	return nil
}

// writeValidatedTemp marshals root to a temp file next to the policy file and
// validates it with the full loader. It returns the temp file's name for the
// caller to rename or remove; on error nothing is left behind.
func (s *Server) writeValidatedTemp(root map[string]yaml.Node) (string, error) {
	name, _, err := s.writeCheckedTemp(root)
	return name, err
}

// writeCheckedTemp is writeValidatedTemp that also returns the loaded policy.
func (s *Server) writeCheckedTemp(root map[string]yaml.Node) (string, config.Policy, error) {
	return writeCheckedTempIn(filepath.Dir(s.cfg.PolicyPath), root)
}

// writeValidatedTempIn is writeValidatedTemp with the temp file in dir ("" =
// the system temp dir).
func writeValidatedTempIn(dir string, root map[string]yaml.Node) (string, error) {
	name, _, err := writeCheckedTempIn(dir, root)
	return name, err
}

// writeCheckedTempIn is writeCheckedTemp with the temp file in dir ("" = the
// system temp dir).
func writeCheckedTempIn(dir string, root map[string]yaml.Node) (string, config.Policy, error) {
	data, err := yaml.Marshal(root)
	if err != nil {
		return "", config.Policy{}, fmt.Errorf("controlplane: marshal config: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".warden-policy-*.yaml")
	if err != nil {
		return "", config.Policy{}, fmt.Errorf("controlplane: create temp policy: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", config.Policy{}, fmt.Errorf("controlplane: write temp policy: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", config.Policy{}, fmt.Errorf("controlplane: close temp policy: %w", err)
	}
	// Validate the candidate with the full loader before it can replace the live
	// file (this enforces default-deny: an empty allowlist is rejected here).
	prov, err := config.NewLocalYAMLProvider(tmpName)
	if err != nil {
		_ = os.Remove(tmpName)
		return "", config.Policy{}, fmt.Errorf("invalid policy: %w", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		_ = os.Remove(tmpName)
		return "", config.Policy{}, fmt.Errorf("invalid policy: %w", err)
	}
	return tmpName, p, nil
}

// writeSettings validates and atomically persists an edited behavioral settings
// document to the served config file, so workers pull the new settings on their
// next poll. It is the settings analogue of writePolicy: it round-trips the file
// through a top-level YAML map and rewrites ONLY the blocks this phase owns,
// preserving every other block (policy, central, controlPlane, the `secrets`
// placeholder list, audit signing, …) byte-for-byte.
//
// This writer owns the `mcp`, `judge`, `agents`, `observability`, `explore`,
// `secretStore`, `logging`, `cache`, and (nested) `audit.compliance` blocks. A
// nil/disabled in.MCP or in.Judge removes that block (the worker disables the
// feature); an empty in.Agents removes the agents list. in.Secrets (wire key
// `secrets`) maps to the on-disk `secretStore` backend selector: echo/aws are
// encoded, env/empty DELETES the key — the local `secrets:` placeholder list is
// a different block and always survives untouched.
//
// logging/cache are top-level and ride the settingsBlocks table; compliance is
// nested at audit.compliance.enabled and is merged into the existing audit node
// separately (below) so local-only audit sub-keys (e.g. signedReceipts) survive.
// A nil in.Logging/in.CacheTTLSeconds/in.Compliance leaves the existing block
// untouched (logging is co-owned by writePolicy's default, so writeSettings must
// not delete it).
//
// WriteSettings is the ConfigEditor seam's settings-write method; the lowercase
// writeSettings forwarder preserves the internal call sites.
// existingSecretAccessKey reads the on-disk secretStore.aws.secretAccessKey from
// the round-tripped top-level config map, or "" when absent. It powers
// WriteSettings' preserve-on-empty rule (keep a configured aws credential when the
// dashboard re-saves without resubmitting the never-echoed secret). It decodes
// into a local struct so the secrets package's unexported raw types stay private.
func existingSecretAccessKey(root map[string]yaml.Node) string {
	node, ok := root["secretStore"]
	if !ok {
		return ""
	}
	var existing struct {
		AWS struct {
			SecretAccessKey string `yaml:"secretAccessKey"`
		} `yaml:"aws"`
	}
	if err := node.Decode(&existing); err != nil {
		return ""
	}
	return existing.AWS.SecretAccessKey
}

// WriteSettings is the ConfigEditor seam's settings-write method. In versioned
// mode it creates a policy version instead (publishSettings); ctx carries the
// author and meta the expected head and message. File mode ignores both.
func (s *Server) WriteSettings(ctx context.Context, in config.SettingsWire, meta dashboard.WriteMeta) error {
	return s.writeSettingsChecked(ctx, in, meta, nil)
}

// writeSettingsChecked is WriteSettings with an optional check that runs under
// writeMu against the settings currently served without overlays (the file,
// or head in versioned mode), so nothing can change them between the check
// and the write. A check error refuses the write unchanged.
func (s *Server) writeSettingsChecked(ctx context.Context, in config.SettingsWire, meta dashboard.WriteMeta, check func(live *config.SettingsWire) error) error {
	if s.versions != nil {
		return s.publishSettings(ctx, in, meta, check)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if check != nil {
		// The on-disk settings, without serve-time overlays: overlays carry
		// data no settings writer owns.
		cur, err := s.policy.loadBase(context.Background())
		if err != nil {
			return fmt.Errorf("controlplane: read live settings: %w", err)
		}
		if err := check(cur.Settings); err != nil {
			return err
		}
	}

	// Load the current file as a top-level YAML map so policy/logging/secrets and
	// any block this phase does not own survive untouched. A missing/unreadable
	// file starts from empty (the loader validation below still guards the result).
	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		_ = yaml.Unmarshal(cur, &root)
	}

	if err := renderSettingsBlocks(root, in); err != nil {
		return err
	}

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	// Wake long-poll waiters with the new settings now, like writePolicy.
	s.refresh()
	// Re-inject the CP dashboard's Explore generator so a judge / explore provider
	// selection change takes effect on the CP without a restart (the judge itself
	// runs on workers, which rebuild it from the refreshed settings on next apply).
	s.reinjectExploreLLM()
	mode := "off"
	if in.MCP != nil && in.MCP.Enabled {
		mode = in.MCP.Mode
	}
	judge := "off"
	if in.Judge != nil && in.Judge.Enabled {
		judge = "on"
	}
	logging := "unchanged"
	if in.Logging != nil {
		logging = in.Logging.Level
	}
	compliance := "unchanged"
	if in.Compliance != nil {
		if in.Compliance.Enabled {
			compliance = "on"
		} else {
			compliance = "off"
		}
	}
	observability := "off"
	if in.Observability != nil && in.Observability.Enabled {
		observability = "on"
	}
	s.cfg.Logger.Info("control plane settings updated via dashboard",
		"mcp", mode, "judge", judge, "agents", len(in.Agents),
		"logging", logging, "compliance", compliance, "observability", observability)
	return nil
}

// renderSettingsBlocks rewrites the settings blocks WriteSettings owns in root
// from in: each block is encoded or, when absent or disabled, deleted (logging
// and cache only ever replaced), and compliance is merged into the audit block.
// It is the settings half of WriteSettings and renderDocToRoot.
func renderSettingsBlocks(root map[string]yaml.Node, in config.SettingsWire) error {
	// settingsBlocks is the per-block rewrite table. Each entry owns one top-level
	// key: it either encodes a replacement node (present) or removes the key
	// (absent). later phases append entries here (judge, observability, …) so a
	// new distributable block is a few lines, not a new code path.
	type blockEdit struct {
		key     string
		node    *yaml.Node // nil → delete the key
		present bool
	}
	settingsBlocks := []blockEdit{}

	// mcp: encode in.MCP → the on-disk mcp block, or delete it when MCP is absent
	// or disabled (so the worker turns MCP off).
	mcpEdit := blockEdit{key: "mcp"}
	if in.MCP != nil && in.MCP.Enabled {
		node, err := mcpSettingsNode(in.MCP)
		if err != nil {
			return fmt.Errorf("controlplane: encode mcp settings: %w", err)
		}
		mcpEdit.node, mcpEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, mcpEdit)

	// judge: encode in.Judge → the on-disk judge block, or delete it when the
	// judge is absent or disabled (so the worker turns the judge off).
	judgeEdit := blockEdit{key: "judge"}
	if in.Judge != nil && in.Judge.Enabled {
		node, err := judgeSettingsNode(in.Judge)
		if err != nil {
			return fmt.Errorf("controlplane: encode judge settings: %w", err)
		}
		judgeEdit.node, judgeEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, judgeEdit)

	// agents: encode the natural-language agent policies the judge consults, or
	// delete the key when none are configured.
	agentsEdit := blockEdit{key: "agents"}
	if len(in.Agents) > 0 {
		node, err := agentsSettingsNode(in.Agents)
		if err != nil {
			return fmt.Errorf("controlplane: encode agents settings: %w", err)
		}
		agentsEdit.node, agentsEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, agentsEdit)

	// identity: encode in.Identity → the on-disk identity block (same keys as the
	// wire), or delete it when nil. The block is secret-free.
	identityEdit := blockEdit{key: "identity"}
	if in.Identity != nil {
		var node yaml.Node
		if err := node.Encode(identityYAML(*in.Identity)); err != nil {
			return fmt.Errorf("controlplane: encode identity settings: %w", err)
		}
		identityEdit.node, identityEdit.present = &node, true
	}
	settingsBlocks = append(settingsBlocks, identityEdit)

	// observability: encode in.Observability → the on-disk observability block, or
	// delete it when observability is absent or disabled (so the worker turns OTel
	// off on its next restart).
	obsEdit := blockEdit{key: "observability"}
	if in.Observability != nil && in.Observability.Enabled {
		node, err := observabilitySettingsNode(in.Observability)
		if err != nil {
			return fmt.Errorf("controlplane: encode observability settings: %w", err)
		}
		obsEdit.node, obsEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, obsEdit)

	// explore: the Explore / NL→SQL provider SELECTION (a provider NAME only, never a
	// value). Encode it when a provider is named, else delete the key (Explore falls
	// back to the judge's client). It rides the settings wire so the CP can read
	// explore.llmProvider at dashboard-wiring/reinject time.
	exploreEdit := blockEdit{key: "explore"}
	if in.Explore != nil && in.Explore.LLMProvider != "" {
		node, err := exploreSettingsNode(in.Explore)
		if err != nil {
			return fmt.Errorf("controlplane: encode explore settings: %w", err)
		}
		exploreEdit.node, exploreEdit.present = node, true
	}
	settingsBlocks = append(settingsBlocks, exploreEdit)

	// secretStore: the value-free backend SELECTOR (env|echo|aws + aws region/
	// namePrefix). Encode it for echo/aws; DELETE the key for env/empty so a worker
	// falls back to its LOCAL placeholder→env map. Credentials never appear here —
	// they resolve from each node's OWN environment/IAM. Note the deliberate key
	// asymmetry: the wire/JSON key is `secrets` (SettingsWire.Secrets) while the
	// on-disk key is `secretStore` (`secrets:` on disk is the placeholder list,
	// which this edit must never touch).
	secretsEdit := blockEdit{key: "secretStore"}
	if cfg := config.SecretStoreConfigFromSettings(in.Secrets); cfg.ResolvedBackend() != config.SecretBackendEnv {
		// PRESERVE-ON-EMPTY (explicit aws credentials). The dashboard GET never
		// returns the raw secretAccessKey, so a form re-save cannot resubmit it. To
		// avoid blanking a configured credential, the UI sends the accessKeyId with an
		// EMPTY secretAccessKey to mean "keep the existing one". So: when the incoming
		// aws block has a non-empty accessKeyId but an empty secretAccessKey, read the
		// on-disk secretStore.aws.secretAccessKey (already round-tripped in `root`) and
		// carry it forward. When BOTH are empty (user cleared them / switched to
		// env/IMDS credentials), write neither key. When both are present, the incoming
		// pair wins (a rotation).
		if cfg.AWS != nil && cfg.AWS.AccessKeyID != "" && cfg.AWS.SecretAccessKey == "" {
			cfg.AWS.SecretAccessKey = existingSecretAccessKey(root)
		}
		node, err := config.EncodeSecretStoreNode(cfg)
		if err != nil {
			return fmt.Errorf("controlplane: encode secretStore settings: %w", err)
		}
		secretsEdit.node, secretsEdit.present = &node, true
	}
	settingsBlocks = append(settingsBlocks, secretsEdit)

	// logging: top-level `logging: {level, format}`. We OWN it only when the wire
	// carries a logging block; when in.Logging is nil we LEAVE any existing logging
	// block intact (do NOT delete it — writePolicy also maintains a default logging
	// block, and deleting it here would fight that). So logging joins the table only
	// in the present case; there is no delete branch for it.
	if in.Logging != nil {
		node, err := loggingSettingsNode(in.Logging)
		if err != nil {
			return fmt.Errorf("controlplane: encode logging settings: %w", err)
		}
		settingsBlocks = append(settingsBlocks, blockEdit{key: "logging", node: node, present: true})
	}

	// cache: the loader reads Policy.CacheTTLSeconds from top-level `cache: {ttl}`
	// (int seconds). Own it only when the wire sets a TTL; a nil leaves any existing
	// cache block untouched (no delete branch — same rationale as logging).
	if in.CacheTTLSeconds != nil {
		node, err := cacheSettingsNode(*in.CacheTTLSeconds)
		if err != nil {
			return fmt.Errorf("controlplane: encode cache settings: %w", err)
		}
		settingsBlocks = append(settingsBlocks, blockEdit{key: "cache", node: node, present: true})
	}

	for _, b := range settingsBlocks {
		if b.present {
			root[b.key] = *b.node
		} else {
			delete(root, b.key)
		}
	}

	// compliance is NESTED at audit.compliance.enabled, NOT a top-level key. The
	// `audit` block also carries LOCAL-ONLY sub-keys (e.g. signedReceipts key/log
	// paths) that the control plane must never clobber. So rather than replacing the
	// whole audit node (which the top-level table would do), we MERGE: decode the
	// existing audit node into a generic map, set only compliance.enabled, and
	// re-encode — every other audit sub-key survives byte-for-byte. A nil
	// in.Compliance leaves audit entirely untouched.
	if in.Compliance != nil {
		if err := mergeAuditCompliance(root, in.Compliance.Enabled); err != nil {
			return fmt.Errorf("controlplane: merge audit.compliance: %w", err)
		}
	}
	return nil
}

// loggingSettingsNode encodes a wire Logging block into a YAML node matching the
// on-disk `logging: {level, format}` shape. The loader normalizes empty
// level/format to info/json, so omitempty here is harmless: an unset field simply
// falls back to the loader default rather than writing a zero value.
func loggingSettingsNode(s *config.LoggingSettings) (*yaml.Node, error) {
	type loggingYAML struct {
		Level  string `yaml:"level,omitempty"`
		Format string `yaml:"format,omitempty"`
	}
	var node yaml.Node
	if err := node.Encode(loggingYAML{Level: s.Level, Format: s.Format}); err != nil {
		return nil, err
	}
	return &node, nil
}

// cacheSettingsNode encodes a secret-cache TTL into a YAML node matching the
// on-disk `cache: {ttl}` shape the loader reads for Policy.CacheTTLSeconds (int
// seconds). ttl is written unconditionally because the caller only reaches here
// when the wire explicitly set CacheTTLSeconds — including an explicit 0, which
// the loader treats as "use default"; that is the operator's intent, preserved.
func cacheSettingsNode(ttlSeconds int) (*yaml.Node, error) {
	type cacheYAML struct {
		TTL int `yaml:"ttl"`
	}
	var node yaml.Node
	if err := node.Encode(cacheYAML{TTL: ttlSeconds}); err != nil {
		return nil, err
	}
	return &node, nil
}

// mergeAuditCompliance sets audit.compliance.enabled in the top-level config map
// WITHOUT clobbering any other audit sub-key (notably the local-only
// signedReceipts key/log paths). It decodes the existing audit node into a
// generic map, overwrites only the compliance sub-block, and re-encodes — so
// every sibling audit field round-trips byte-for-byte. When no audit node exists
// yet, a fresh one carrying only compliance is created.
func mergeAuditCompliance(root map[string]yaml.Node, enabled bool) error {
	audit := map[string]yaml.Node{}
	if existing, ok := root["audit"]; ok {
		// Best-effort decode: a malformed audit node just means we rebuild it with
		// compliance only; the loader validation in atomicWriteConfig still guards.
		_ = existing.Decode(&audit)
	}
	var compNode yaml.Node
	if err := compNode.Encode(map[string]bool{"enabled": enabled}); err != nil {
		return err
	}
	audit["compliance"] = compNode
	var auditNode yaml.Node
	if err := auditNode.Encode(audit); err != nil {
		return err
	}
	root["audit"] = auditNode
	return nil
}

// mcpYAML mirrors the on-disk `mcp:` block (config.rawMCP). It is the encoder
// counterpart of the loader's raw type: the boolean sub-block fields use pointers
// so an explicit false (e.g. scan.toolArgs=false, which the loader defaults to
// true when absent) round-trips instead of being silently dropped or re-defaulted.
type mcpYAML struct {
	Enabled              bool           `yaml:"enabled"`
	Mode                 string         `yaml:"mode,omitempty"`
	FailClosedOnError    bool           `yaml:"failClosedOnError,omitempty"`
	MaxResponseScanBytes int            `yaml:"maxResponseScanBytes,omitempty"`
	Tools                *mcpToolsYAML  `yaml:"tools,omitempty"`
	Schema               *mcpSchemaYAML `yaml:"schema,omitempty"`
	Scan                 *mcpScanYAML   `yaml:"scan,omitempty"`
	Chain                *mcpChainYAML  `yaml:"chain,omitempty"`
}

type mcpToolsYAML struct {
	Allow       []string                     `yaml:"allow,omitempty"`
	Deny        []string                     `yaml:"deny,omitempty"`
	RateLimit   map[string]string            `yaml:"rateLimit,omitempty"`
	Constraints map[string]mcpConstraintYAML `yaml:"constraints,omitempty"`
}

// mcpConstraintYAML mirrors the on-disk constraint (config.rawMCPToolConstraint).
// config.MCPToolConstraints has no yaml tags, so encoding it directly would write
// lowercased keys the loader rejects (W-P1-GPOL-08: a groups allowWhen saved from
// the dashboard must reload).
type mcpConstraintYAML struct {
	MaxArgsBytes int                     `yaml:"maxArgsBytes,omitempty"`
	Fields       map[string]mcpFieldYAML `yaml:"fields,omitempty"`
	AllowWhen    *mcpConditionYAML       `yaml:"allowWhen,omitempty"`
}

type mcpFieldYAML struct {
	Match     string `yaml:"match,omitempty"`
	MaxLen    int    `yaml:"maxLen,omitempty"`
	Required  bool   `yaml:"required,omitempty"`
	Forbidden bool   `yaml:"forbidden,omitempty"`
}

type mcpConditionYAML struct {
	AgentID    string   `yaml:"agentId,omitempty"`
	TimeWindow string   `yaml:"timeWindow,omitempty"`
	Groups     []string `yaml:"groups,omitempty"`
	Users      []string `yaml:"users,omitempty"`
}

func mcpConstraintsYAML(in map[string]config.MCPToolConstraints) map[string]mcpConstraintYAML {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]mcpConstraintYAML, len(in))
	for tool, c := range in {
		y := mcpConstraintYAML{MaxArgsBytes: c.MaxArgsBytes}
		if len(c.Fields) > 0 {
			y.Fields = make(map[string]mcpFieldYAML, len(c.Fields))
			for name, f := range c.Fields {
				y.Fields[name] = mcpFieldYAML{Match: f.Match, MaxLen: f.MaxLen, Required: f.Required, Forbidden: f.Forbidden}
			}
		}
		if aw := c.AllowWhen; aw != nil {
			y.AllowWhen = &mcpConditionYAML{AgentID: aw.AgentID, TimeWindow: aw.TimeWindow, Groups: aw.Groups, Users: aw.Users}
		}
		out[tool] = y
	}
	return out
}

type mcpSchemaYAML struct {
	Pin bool `yaml:"pin"`
}

type mcpScanYAML struct {
	ToolArgs      *bool           `yaml:"toolArgs,omitempty"`
	ToolResults   *bool           `yaml:"toolResults,omitempty"`
	ProfileSchema *bool           `yaml:"profileSchema,omitempty"`
	PII           *mcpScanPIIYAML `yaml:"pii,omitempty"`
}

type mcpScanPIIYAML struct {
	Phone bool `yaml:"phone"`
}

type mcpChainYAML struct {
	Enabled    *bool    `yaml:"enabled,omitempty"`
	WindowSize *int     `yaml:"windowSize,omitempty"`
	Patterns   []string `yaml:"patterns,omitempty"`
}

// mcpSettingsNode encodes a wire MCP block into a YAML node matching the on-disk
// `mcp:` shape. It projects the WIRE settings (not a fully-defaulted MCPConfig)
// so that sub-blocks the operator never set stay ABSENT on disk and the loader
// applies its own defaults — emitting a fully-defaulted block would instead write
// concrete values (e.g. chain.windowSize=0) that fail loader validation. The
// scalar fields and any sub-block the operator DID set are written explicitly,
// with pointers where an explicit zero/false must survive the round-trip rather
// than be re-defaulted by the loader.
func mcpSettingsNode(s *config.MCPSettings) (*yaml.Node, error) {
	raw := mcpYAML{
		Enabled:              s.Enabled,
		Mode:                 s.Mode,
		FailClosedOnError:    s.FailClosedOnError,
		MaxResponseScanBytes: s.MaxResponseScanBytes,
	}
	if s.Schema != nil {
		raw.Schema = &mcpSchemaYAML{Pin: s.Schema.Pin}
	}
	if s.Scan != nil {
		raw.Scan = &mcpScanYAML{
			ToolArgs:      boolPtr(s.Scan.ToolArgs),
			ToolResults:   boolPtr(s.Scan.ToolResults),
			ProfileSchema: boolPtr(s.Scan.ProfileSchema),
			PII:           &mcpScanPIIYAML{Phone: s.Scan.PIIPhone},
		}
	}
	if s.Chain != nil {
		raw.Chain = &mcpChainYAML{
			Enabled:  boolPtr(s.Chain.Enabled),
			Patterns: s.Chain.Patterns,
		}
		// windowSize is a *int with omitempty, but omitempty on a pointer only
		// skips nil — a pointer-to-zero still marshals as "windowSize: 0", which
		// the loader re-reads and validateMCP rejects. So write it ONLY when the
		// wire carries a positive value (mirroring the judge encoder's
		// positive-only fields); leaving it nil keeps the field absent so the
		// loader applies its default (defaultMCPChainWindowSize=50) on re-parse.
		if s.Chain.WindowSize > 0 {
			raw.Chain.WindowSize = intPtr(s.Chain.WindowSize)
		}
	}
	if s.Tools != nil &&
		(len(s.Tools.Allow) > 0 || len(s.Tools.Deny) > 0 ||
			len(s.Tools.RateLimit) > 0 || len(s.Tools.Constraints) > 0) {
		// Reuse the wire→config tool mapping so allow/deny/rate/constraints stay in
		// one place; mcpConstraintsYAML gives them the on-disk key names.
		tools := config.MCPConfigFromSettings(s).Tools
		raw.Tools = &mcpToolsYAML{
			Allow:       tools.Allow,
			Deny:        tools.Deny,
			RateLimit:   tools.RateLimit,
			Constraints: mcpConstraintsYAML(tools.Constraints),
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// judgeYAML mirrors the on-disk `judge:` block (config.rawJudge). Durations live
// on disk as Go duration STRINGS ("5s", "30s", "5m"), and the loader treats an
// empty/absent duration string — and a zero maxFailures — as "apply the default".
// So this encoder writes a duration field ONLY when the wire carries a positive
// value: emitting "0s" or maxFailures:0 would override the loader's defaults with
// concrete zeros (the same defaults-vs-zero gotcha solved for the mcp block). The
// circuitBreaker/cache sub-blocks are pointers so they stay ABSENT when the wire
// has no tuning, leaving the loader free to apply its defaults.
type judgeYAML struct {
	Enabled        bool              `yaml:"enabled"`
	Provider       string            `yaml:"provider,omitempty"`
	LLMProvider    string            `yaml:"llmProvider,omitempty"`
	Model          string            `yaml:"model,omitempty"`
	BaseURL        string            `yaml:"baseURL,omitempty"`
	APIKeyEnv      string            `yaml:"apiKeyEnv,omitempty"`
	Timeout        string            `yaml:"timeout,omitempty"`
	RateLimit      string            `yaml:"rateLimit,omitempty"`
	CircuitBreaker *judgeCircuitYAML `yaml:"circuitBreaker,omitempty"`
	Cache          *judgeCacheYAML   `yaml:"cache,omitempty"`
}

type judgeCircuitYAML struct {
	MaxFailures int    `yaml:"maxFailures,omitempty"`
	Cooldown    string `yaml:"cooldown,omitempty"`
}

type judgeCacheYAML struct {
	TTL string `yaml:"ttl,omitempty"`
}

// agentYAML mirrors one on-disk `agents:` list item (config.rawAgent).
type agentYAML struct {
	ID       string `yaml:"id"`
	Policy   string `yaml:"policy,omitempty"`
	Identity string `yaml:"identity,omitempty"`
}

// identityYAML mirrors the on-disk `identity:` block (config.IdentitySettings
// yaml keys) with omitempty so unset tuning stays absent and the loader
// applies its defaults.
type identityYAML struct {
	DefaultMode        string   `yaml:"defaultMode,omitempty"`
	Issuer             string   `yaml:"issuer,omitempty"`
	Audience           string   `yaml:"audience,omitempty"`
	AllowedAZP         []string `yaml:"allowedAZP,omitempty"`
	JWKSURL            string   `yaml:"jwksURL,omitempty"`
	GroupsClaim        string   `yaml:"groupsClaim,omitempty"`
	ClockSkewSeconds   int      `yaml:"clockSkewSeconds,omitempty"`
	MaxTokenTTLSeconds int      `yaml:"maxTokenTTLSeconds,omitempty"`
	InternalIssuerURL  string   `yaml:"internalIssuerURL,omitempty"`
}

// secondsToDuration renders a positive whole-second count as a Go duration string
// the loader's time.ParseDuration accepts ("30s"), or "" when n<=0 so the field is
// omitted and the loader applies its own default.
func secondsToDuration(n int) string {
	if n <= 0 {
		return ""
	}
	return (time.Duration(n) * time.Second).String()
}

// judgeSettingsNode encodes a wire Judge block into a YAML node matching the
// on-disk `judge:` shape. It projects the WIRE settings (not a fully-defaulted
// JudgeConfig): timeout/cache/circuit-breaker fields are written only when the
// wire carries a positive value, so unset tuning stays ABSENT on disk and the
// loader applies its documented defaults rather than zero values.
func judgeSettingsNode(s *config.JudgeSettings) (*yaml.Node, error) {
	raw := judgeYAML{
		Enabled:     s.Enabled,
		Provider:    s.Provider,
		LLMProvider: s.LLMProvider,
		Model:       s.Model,
		BaseURL:     s.BaseURL,
		APIKeyEnv:   s.APIKeyEnv,
		RateLimit:   s.RateLimit,
		Timeout:     secondsToDuration(s.TimeoutSeconds),
	}
	if ttl := secondsToDuration(s.CacheTTLSeconds); ttl != "" {
		raw.Cache = &judgeCacheYAML{TTL: ttl}
	}
	if s.CircuitBreaker != nil {
		cd := secondsToDuration(s.CircuitBreaker.CooldownSeconds)
		if s.CircuitBreaker.MaxFailures != 0 || cd != "" {
			raw.CircuitBreaker = &judgeCircuitYAML{
				MaxFailures: s.CircuitBreaker.MaxFailures,
				Cooldown:    cd,
			}
		}
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}

// exploreSettingsNode encodes a wire Explore block into a YAML node matching the
// on-disk `explore:` shape — just `llmProvider`, a provider NAME (never a value).
// The caller only reaches here when a provider is selected, so the field is always
// non-empty; omitempty keeps the encoding minimal.
func exploreSettingsNode(s *config.ExploreSettings) (*yaml.Node, error) {
	type exploreYAML struct {
		LLMProvider string `yaml:"llmProvider,omitempty"`
	}
	var node yaml.Node
	if err := node.Encode(exploreYAML{LLMProvider: s.LLMProvider}); err != nil {
		return nil, err
	}
	return &node, nil
}

// agentsSettingsNode encodes the wire agent list into a YAML node matching the
// on-disk `agents:` list shape (id + policy text). Order is preserved.
func agentsSettingsNode(in []config.AgentSettings) (*yaml.Node, error) {
	out := make([]agentYAML, 0, len(in))
	for _, a := range in {
		out = append(out, agentYAML{ID: a.ID, Policy: a.Policy, Identity: a.Identity})
	}
	var node yaml.Node
	if err := node.Encode(out); err != nil {
		return nil, err
	}
	return &node, nil
}

// observabilityYAML mirrors the on-disk `observability:` block
// (config.rawObservability). The wire ObservabilitySettings FLATTENS
// metricsEnabled/otlpEndpoint, but on disk they NEST under `metrics:`, so this
// encoder re-nests them. serviceName/otlpEndpoint/resourceAttributes are
// omitempty so an unset value stays ABSENT and the loader applies its default
// (serviceName→"warden"). metrics.enabled is a POINTER and written
// unconditionally: the loader defaults it to true when the block is present, so
// emitting it explicitly is the only way an operator's explicit false survives
// the round-trip rather than being silently re-defaulted to true.
type observabilityYAML struct {
	Enabled            bool                  `yaml:"enabled"`
	ServiceName        string                `yaml:"serviceName,omitempty"`
	Metrics            *observabilityMetrics `yaml:"metrics,omitempty"`
	ResourceAttributes map[string]string     `yaml:"resourceAttributes,omitempty"`
}

type observabilityMetrics struct {
	Enabled      *bool  `yaml:"enabled"`
	OTLPEndpoint string `yaml:"otlpEndpoint,omitempty"`
}

// observabilitySettingsNode encodes a wire Observability block into a YAML node
// matching the on-disk `observability:` shape. The caller only reaches here when
// observability is enabled; the metrics sub-block is always emitted so the
// flattened metricsEnabled/otlpEndpoint round-trip (metrics.enabled as a pointer
// so an explicit false is not re-defaulted to true by the loader).
func observabilitySettingsNode(s *config.ObservabilitySettings) (*yaml.Node, error) {
	raw := observabilityYAML{
		Enabled:     s.Enabled,
		ServiceName: s.ServiceName,
		Metrics: &observabilityMetrics{
			Enabled:      boolPtr(s.MetricsEnabled),
			OTLPEndpoint: s.OTLPEndpoint,
		},
		ResourceAttributes: s.ResourceAttributes,
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return nil, err
	}
	return &node, nil
}
