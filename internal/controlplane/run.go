package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/ethosagent/warden/internal/integration/webhook" // register the webhook sink

	"github.com/ethosagent/warden/internal/alertpipeline"
	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/detect"
	"github.com/ethosagent/warden/internal/integration"
	"github.com/ethosagent/warden/internal/observability"
	"github.com/ethosagent/warden/internal/secrets"
)

// Params are the flag-derived inputs the control plane boots from. cmd/ fills
// them from parsed flags (rule C1: cmd/ holds only flag parsing and wiring);
// tests pass a Listener on port 0 to run a real control plane in-process.
type Params struct {
	ConfigPath, ListenAddr, TokenEnv string
	CACert, CAKey, TLSHost, StateDir string
	MaxEvents, RetentionDays         int
	AnalyticsProvider, AnalyticsDB   string
	AlertsDB                         string

	// Listener, when set, replaces ListenAddr. Tests pass a loopback listener on
	// port 0. Run closes it on a boot error and, on the serving path, on
	// shutdown (via httpSrv.Shutdown, which closes listeners Serve registered).
	Listener net.Listener
	// OnReady is called once with the bound address, after the listener is bound
	// (injected, or bound by Run) but just before Serve starts accepting.
	// Probing during that gap is safe: the kernel queues connections in the
	// listener's accept backlog and Serve drains them the moment it starts, so
	// nothing is refused. Nil is allowed (production never sets it).
	OnReady func(addr string)
}

// Run boots a control plane from Params and serves until ctx is cancelled. It
// is the moved body of cmd/proxy's runControlPlane (rule C1 in #349): the same
// config resolution, stores, and server wiring, now callable in-process — the
// seam the L1 harness (parent #350) starts a real control plane through.
func Run(ctx context.Context, out io.Writer, p Params) error {
	configPath, listenAddr, tokenEnv := p.ConfigPath, p.ListenAddr, p.TokenEnv
	caCert, caKey, tlsHost, stateDir := p.CACert, p.CAKey, p.TLSHost, p.StateDir
	maxEvents := p.MaxEvents
	// fail closes an injected listener on a boot error. httpSrv.Shutdown only
	// closes listeners Serve has registered, so a return before the serve
	// goroutine starts would otherwise leak the harness's bound port. Every
	// early return below precedes that goroutine, so this close never races
	// with — nor duplicates — the serving path's Shutdown close.
	fail := func(err error) error {
		if p.Listener != nil {
			_ = p.Listener.Close()
		}
		return err
	}
	// Resolve the SERVED path. With no --state-dir we serve+edit --config in place
	// (unchanged behavior). With --state-dir we serve+edit a writable copy seeded
	// once from --config, so the dashboard can persist edits even when --config is
	// a read-only mount and the container runs as a non-root user.
	servedPath := configPath
	seeded := false
	if stateDir != "" {
		servedPath = filepath.Join(stateDir, "config.yaml")
		var serr error
		seeded, serr = seedServedConfig(servedPath, configPath)
		if serr != nil {
			return fail(fmt.Errorf("control-plane: %w", serr))
		}
	}

	// Validate the SERVED file up front so the control plane fails loudly on a
	// bad/corrupt config (incl. a corrupt persisted copy) rather than only when a
	// worker first polls.
	prov, err := config.NewLocalYAMLProvider(servedPath)
	if err != nil {
		return fail(fmt.Errorf("control-plane: %w", err))
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		return fail(err)
	}
	logger, _ := observability.NewLogger(out, pol.LogLevel, pol.LogFormat)

	if stateDir != "" {
		if seeded {
			logger.Info("control plane serving writable config", "served", servedPath, "seededFrom", configPath)
		} else {
			logger.Info("control plane serving writable config", "served", servedPath, "reused", true)
		}
	} else {
		logger.Info("control plane serving config in place", "served", servedPath)
	}

	// Dashboard policy/settings editing writes a temp file next to the served file
	// then atomic-renames it into place. If that directory is not writable the edit
	// fails at runtime; warn now (actionably) but keep serving — read/serve is fine.
	if dir := filepath.Dir(servedPath); !dirWritable(dir) {
		logger.Warn("control-plane: served-config directory is not writable; dashboard policy/settings editing will FAIL",
			"dir", dir,
			"hint", "pass --state-dir pointing at a writable, container-user-owned volume (e.g. /data) so the control plane can seed and edit a writable copy")
	}

	var token string
	if tokenEnv != "" {
		token = os.Getenv(tokenEnv)
		if token == "" {
			logger.Warn("control-plane: token-env set but empty; serving WITHOUT auth", "env", tokenEnv)
		}
	} else {
		logger.Warn("control-plane: no token configured; serving WITHOUT auth (set --token-env for production)")
	}

	// Build the fleet analytics store. sqlite (default) persists events and powers
	// the read-only Query Builder; memory is ephemeral. The DB path defaults under
	// --state-dir (a writable volume) when set, else the working directory.
	dbPath := p.AnalyticsDB
	if dbPath == "" {
		if stateDir != "" {
			dbPath = filepath.Join(stateDir, "warden-fleet.db")
		} else {
			dbPath = "warden-fleet.db"
		}
	}
	store, err := analytics.NewFleetStore(analytics.FleetConfig{
		Provider:      p.AnalyticsProvider,
		SQLitePath:    dbPath,
		RetentionDays: p.RetentionDays,
		MaxEvents:     maxEvents,
	})
	if err != nil {
		return fail(fmt.Errorf("control-plane: analytics store: %w", err))
	}
	defer func() { _ = store.Close() }()
	if p.AnalyticsProvider == "memory" {
		logger.Info("control plane analytics store", "provider", "memory", "persistent", false)
	} else {
		logger.Info("control plane analytics store", "provider", "sqlite", "db", dbPath, "retentionDays", p.RetentionDays)
	}

	// Alert store path: an explicit --alerts-db wins; otherwise a sibling of the
	// analytics DB (which already encodes --state-dir vs the working dir), named
	// warden-alerts.db. The CP builds no manager when no integrations are
	// configured, so this path is unused in that case.
	alertDBPath := p.AlertsDB
	if alertDBPath == "" {
		alertDBPath = filepath.Join(filepath.Dir(dbPath), "warden-alerts.db")
	}
	integrations := toInstanceConfigs(pol.Integrations)
	if len(integrations) > 0 {
		logger.Info("control plane integrations", "count", len(integrations), "alertsDB", alertDBPath)
	}

	// Temporal detection: convert the CP-local detection config into the engine
	// config (starting from detect.DefaultConfig() so unset fields keep the engine
	// defaults — no default numbers are duplicated in internal/config). Detection is
	// ON by default; when enabled it makes the Alert Store always-on so findings
	// land even with zero integrations configured.
	detectCfg, detectionEnabled, detectionTick := toDetectConfig(pol.Detection)
	if detectionEnabled {
		logger.Info("control plane detection", "enabled", true, "tick", detectionTick.String(), "alertsDB", alertDBPath)
	}

	// Build the WRITE-scoped secret store from the CP's OWN secretStore.backend.
	// echo/aws mount the /central/secrets endpoints; env/none return a nil store so
	// the endpoints stay unmounted — back-compatible. An aws backend with missing
	// ENV credentials fails fast here rather than silently disabling writes.
	secretStore, err := NewSecretStore(pol.SecretStore, logger)
	if err != nil {
		return fail(fmt.Errorf("control-plane: secret store: %w", err))
	}

	srv := New(Config{
		PolicyPath:   servedPath,
		Token:        token,
		MaxEvents:    maxEvents,
		Store:        store,
		Logger:       logger,
		Integrations: integrations,
		AlertDBPath:  alertDBPath,
		SecretStore:  secretStore,
		// Report the backend name to the dashboard only when a writable store was
		// actually built (echo/aws); env/none leaves it empty → tab reports "none".
		SecretStoreBackend: secretStoreBackendName(secretStore, pol.SecretStore),
		// Temporal detection: when enabled (the default) the control plane builds
		// the engine AND the always-on Alert Store (Manager built even with zero
		// integrations) so findings land without any sink configured.
		DetectionEnabled: detectionEnabled,
		Detection:        detectCfg,
		DetectionTick:    detectionTick,
		// Typed CP-local detection config for the dashboard editor + WriteDetection
		// round-trip base (the resolved fields above drive the initial engine build).
		DetectionConfig: pol.Detection,
	})

	httpSrv := &http.Server{
		Addr:    listenAddr,
		Handler: srv.Handler(),
		// ReadHeaderTimeout bounds request-header reads; WriteTimeout is left 0 so
		// long-poll responses (held up to ~60s) are never cut off mid-flight.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// TLS: mint a server cert from the provided CA so workers trust it via their
	// configured controlPlane.caCert. Both flags required together.
	haveCA := caCert != "" && caKey != ""
	if (caCert != "") != (caKey != "") {
		return fail(fmt.Errorf("control-plane: both --ca-cert and --ca-key must be set together"))
	}
	if haveCA {
		tlsCfg, tErr := MintServerTLS(caCert, caKey, strings.Split(tlsHost, ","))
		if tErr != nil {
			return fail(tErr)
		}
		httpSrv.TLSConfig = tlsCfg
	} else {
		logger.Warn("control-plane: serving plain HTTP; workers require HTTPS for the policy pull (provide --ca-cert/--ca-key)")
	}

	// The address reported to operators and OnReady: with an injected listener
	// (in-process tests) the bound address is the listener's; otherwise it is the
	// --listen flag value, exactly as before.
	reportedAddr := listenAddr
	if p.Listener != nil {
		reportedAddr = p.Listener.Addr().String()
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Periodic re-read so external edits to the policy file propagate to workers.
	srv.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		scheme := "http"
		if haveCA {
			scheme = "https"
		}
		logger.Info("control plane listening",
			"addr", reportedAddr,
			"policy", scheme+"://"+reportedAddr+"/policy",
			"dashboard", scheme+"://"+reportedAddr+"/dashboard/")
		ln := p.Listener
		if ln == nil {
			var lerr error
			ln, lerr = net.Listen("tcp", listenAddr)
			if lerr != nil {
				errCh <- lerr
				return
			}
		}
		// The listener is bound, so the kernel already queues connections; Serve
		// (called next) begins accepting them. OnReady hands the harness the
		// address it can start probing.
		if p.OnReady != nil {
			p.OnReady(ln.Addr().String())
		}
		if haveCA {
			errCh <- httpSrv.ServeTLS(ln, "", "")
		} else {
			errCh <- httpSrv.Serve(ln)
		}
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// seedServedConfig ensures servedPath exists, seeding it once from seedPath when
// absent. It returns (true, nil) when it created servedPath from the seed, and
// (false, nil) when servedPath already existed (so dashboard edits persist across
// restarts — that is the point of the writable volume). The seed copy is written
// 0600 in a 0700 directory: only the container user can read or edit the served
// config.
func seedServedConfig(servedPath, seedPath string) (bool, error) {
	if _, err := os.Stat(servedPath); err == nil {
		return false, nil // already present — keep persisted edits
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat served config %s: %w", servedPath, err)
	}
	if err := os.MkdirAll(filepath.Dir(servedPath), 0o700); err != nil {
		return false, fmt.Errorf("create state dir %s: %w", filepath.Dir(servedPath), err)
	}
	seed, err := os.ReadFile(seedPath)
	if err != nil {
		return false, fmt.Errorf("read seed config %s: %w", seedPath, err)
	}
	if err := os.WriteFile(servedPath, seed, 0o600); err != nil {
		return false, fmt.Errorf("write served config %s: %w", servedPath, err)
	}
	return true, nil
}

// toInstanceConfigs maps the CP-local integrations config onto the integration
// package's InstanceConfig, keeping internal/config free of an integration
// import (the mapping is trivial glue). The opaque config map is passed through
// untouched; secrets inside it stay as ${ENV} strings and are expanded later by
// the integration at Start.
func toInstanceConfigs(insts []config.IntegrationInstance) []integration.InstanceConfig {
	if len(insts) == 0 {
		return nil
	}
	out := make([]integration.InstanceConfig, 0, len(insts))
	for _, in := range insts {
		ic := integration.InstanceConfig{Type: in.Type, Name: in.Name, Config: in.Config}
		for _, m := range in.Match {
			ic.Match = append(ic.Match, integration.MatchClause{
				Severity: m.Severity, Category: m.Category, Domain: m.Domain, Rule: m.Rule,
			})
		}
		out = append(out, ic)
	}
	return out
}

// toDetectConfig converts the CP-local detection config into the detect engine
// config, the enabled flag, and the tick interval. It delegates to the shared
// alertpipeline.DetectConfigFrom converter (the single home for this mapping, used
// by both the control plane and the worker's local-only pipeline) so the numeric
// defaults live in exactly one place (internal/detect) and never drift between the
// two hosts. Kept as a thin named wrapper so the call site in Run reads naturally.
func toDetectConfig(dc config.DetectionConfig) (detect.Config, bool, time.Duration) {
	return alertpipeline.DetectConfigFrom(dc)
}

// dirWritable reports whether dir is writable by creating and removing a temp
// file in it. A non-existent dir or one the process cannot write to returns
// false. It is used to warn early when dashboard policy/settings editing (which
// writes a temp file next to the served config, then atomic-renames it) would
// fail at runtime.
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".warden-writecheck-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

// secretStoreBackendName returns the backend name to show on the dashboard's
// secretstore tab: the resolved backend only when a writable store was actually
// built (echo/aws), else "" so the tab reports "none". This keeps the tab's
// backend label consistent with whether the /central/secrets endpoints exist.
func secretStoreBackendName(store secrets.SecretStore, cfg config.SecretStoreConfig) string {
	if store == nil {
		return ""
	}
	return cfg.ResolvedBackend()
}
