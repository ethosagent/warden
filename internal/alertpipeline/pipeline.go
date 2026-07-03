// Package alertpipeline is the embeddable alert-delivery assembly that both the
// control plane (fleet mode) and — later — the worker (local-only) construct to
// turn analytics events into delivered alerts. It owns four things:
//
//   - the integration Manager (bus → alertmanager → store persist + router → sinks),
//   - the optional temporal-detection Engine,
//   - the evaluate tick loop that publishes detector Findings, and
//   - the Observe fan-in (detector.Observe + the immediate event→Finding bridge).
//
// It was extracted from the control plane's previously-inlined build+tick+bridge
// so there is ONE code path both hosts share, not two. Its behavior is identical
// to the control plane's former inline assembly.
//
// # Ownership: the Store is CALLER-owned
//
// The Pipeline never opens or closes the alert Store — the caller passes an
// already-open *integration.Store and closes it exactly once at its own
// shutdown. A live reload rebuilds the Manager over the SAME store, so the
// Pipeline holds a non-owning reference to it for rebuilds only. This mirrors how
// the control-plane Server owns integrationsStore today.
//
// # Manager pointer + reload (design A)
//
// The Pipeline owns the Manager pointer and the RWMutex guarding it. Every
// reload-aware read (RunTick, Observe, CurrentManager) reads the CURRENT manager
// under the lock, so a live reload (ReloadManager) that swaps the pointer
// re-points the tick, the bridge, and the dashboard alerts source at the new
// manager. The control plane delegates its integrations reload to ReloadManager
// rather than keeping a second manager pointer, so there is a single source of
// truth for "the live manager".
//
// # Fail-open
//
// A nil Store, or a Manager build failure, yields a Pipeline whose methods are
// safe no-ops for the broken part — New NEVER returns an error that could abort
// proxy/CP startup. A broken alert subsystem must never stop proxying.
package alertpipeline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/detect"
	"github.com/ethosagent/warden/internal/integration"
)

// DefaultDetectionTick is the fallback evaluate cadence for the temporal
// detection engine when Config.Tick is unset (<= 0). It is exported so the cmd
// converter, the control plane, and this package all agree on one default value.
const DefaultDetectionTick = 20 * time.Second

// Config configures a Pipeline. Store is caller-owned (never closed here);
// everything else is copied by value at New.
type Config struct {
	// Store is the already-open alert system-of-record. Caller-owned: the Pipeline
	// reads/writes it via the Manager but NEVER closes it. Nil ⇒ the Pipeline is a
	// safe no-op (no manager, no engine).
	Store *integration.Store
	// Instances are the outbound alert integrations to run.
	Instances []integration.InstanceConfig
	// Detection is the fully-resolved engine config (defaults already applied by the
	// caller's converter). Ignored when Detect is false.
	Detection detect.Config
	// Detect gates the temporal-detection engine. When true AND a Manager was built
	// (there must be a bus to publish onto), New constructs the engine.
	Detect bool
	// Tick is how often the engine is evaluated and its Findings published (and the
	// resolve sweep runs). <= 0 falls back to DefaultDetectionTick.
	Tick time.Duration
	// ResolveTTL is the silence window after which a firing alert auto-resolves
	// (P4). It is threaded to the AlertManager's resolve sweep: 0 selects
	// integration.DefaultResolveTTL, a negative value disables auto-resolve.
	ResolveTTL time.Duration
	// Logger receives lifecycle logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Pipeline is the embeddable alert-delivery assembly. It is safe for concurrent
// use. See the package doc for the ownership + reload model.
type Pipeline struct {
	logger *slog.Logger
	// store is a NON-OWNING reference used only to rebuild the manager on reload.
	// The caller owns the store's lifecycle and closes it exactly once.
	store *integration.Store
	// tick is the evaluate cadence; <= 0 falls back to DefaultDetectionTick.
	tick time.Duration
	// resolveTTL is threaded to the AlertManager's resolve sweep (0 → default, <0 →
	// disabled). Captured at New and passed to every manager build (incl. reload).
	resolveTTL time.Duration
	// now is the clock used by the tick's resolve sweep; defaults to time.Now.
	now func() time.Time

	// mu guards manager, detector, and lifeCtx. Reads (RunTick/Observe/
	// CurrentManager/currentDetector/Detectors) take it for read; a reload takes it
	// for write to swap the manager OR the detector pointer, so every live wiring
	// observes the CURRENT pointers rather than captured-once ones and never sees a
	// half-swapped engine.
	mu sync.RWMutex
	// detector is the temporal-detection engine, or nil when detection is off (or
	// no manager was built, so there is no bus to publish onto). Guarded by mu so a
	// live ReloadDetection can enable/disable/replace it without racing the tick.
	detector *detect.Engine
	// manager is the live alert-delivery pipeline; re-pointed on reload. Nil when no
	// store was provided or the manager failed to build (fail-open).
	manager *integration.Manager
	// lifeCtx is the lifecycle context captured in Start so a reload can bind a
	// rebuilt manager's router goroutines to the process lifetime.
	lifeCtx context.Context
}

// New builds a Pipeline from cfg. It is FAIL-OPEN: a nil store or a manager build
// failure yields a Pipeline whose methods are safe no-ops for the broken part —
// New never returns an error that could abort startup. The engine is built only
// when Detect is set AND a Manager came up (there must be a bus to publish onto).
func New(cfg Config) *Pipeline {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	p := &Pipeline{logger: logger, store: cfg.Store, tick: cfg.Tick, resolveTTL: cfg.ResolveTTL, now: time.Now}
	if cfg.Store == nil {
		return p // no store ⇒ safe no-op (all methods nil-check the manager)
	}
	m, err := integration.NewManager(cfg.Store, cfg.Instances, logger, integration.RouterOptions{}, cfg.ResolveTTL)
	if err != nil {
		// Fail-open: a manager build failure disables alerting; it never aborts the
		// caller. The caller owns the store and closes it.
		logger.Error("alert pipeline: manager build failed (alerting disabled)", "error", err)
		return p
	}
	p.manager = m

	if cfg.Detect {
		p.detector = detect.NewEngine(cfg.Detection, nil)
		tick := cfg.Tick
		if tick <= 0 {
			tick = DefaultDetectionTick
		}
		logger.Info("alert pipeline detection engine",
			"detectors", p.detector.Detectors(), "tick", tick.String())
	}
	return p
}

// Start starts the current Manager and, when detection is enabled, launches the
// evaluate tick loop. It captures ctx as the lifecycle context so a live reload
// can bind a rebuilt manager's router goroutines to the process lifetime. It does
// NOT close the store and does NOT stop instances on ctx.Done — the caller owns
// shutdown ordering (StopInstances then store close). The tick loop is ctx-scoped
// and exits on ctx.Done; each tick is fail-open (see RunTick). Start is nil-safe.
func (p *Pipeline) Start(ctx context.Context) {
	p.mu.Lock()
	p.lifeCtx = ctx
	m := p.manager
	p.mu.Unlock()

	if m == nil {
		return // no manager ⇒ nothing to run (fail-open)
	}
	// A non-nil error is a JOINED report (unknown types / failed instances) — the
	// good instances still run, so LOG and continue.
	if err := m.Start(ctx); err != nil {
		p.logger.Warn("alert pipeline: some integrations failed to start", "error", err)
	}

	// The tick loop runs whenever a manager exists — NOT only when detection is on
	// at startup. It drives BOTH the detection evaluate/publish (when an engine is
	// present, possibly ENABLED later via a live ReloadDetection) AND the P4 resolve
	// sweep (which is independent of detection). Gating the loop on the manager (not
	// the engine) is what lets a dashboard PUT that turns detection ON start
	// producing findings without a restart, and keeps the resolve sweep running even
	// with detection off.
	tick := p.tick
	if tick <= 0 {
		tick = DefaultDetectionTick
	}
	go func() {
		t := time.NewTicker(tick)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.RunTick()
			}
		}
	}()
}

// StopInstances stops the CURRENT manager's instances (router + sinks) WITHOUT
// closing the store — a reload may have swapped the manager, so the current one
// is read here. The caller closes the store after this returns. Nil-safe: no
// manager ⇒ no-op.
func (p *Pipeline) StopInstances(ctx context.Context) error {
	m := p.CurrentManager()
	if m == nil {
		return nil
	}
	return m.StopInstances(ctx)
}

// Observe feeds one ingested event batch to both consumers: the temporal engine
// (folded into windowed state; the tick later Evaluates + publishes) and the
// immediate event→Finding bridge (block/reason Findings published onto the
// CURRENT manager's bus). proxyID is the worker that produced the batch; it is
// recorded on Subject.Worker. Nil-safe and fail-open: no detector ⇒ no fold; no
// manager ⇒ no bridge publish.
func (p *Pipeline) Observe(proxyID string, events []analytics.Event) {
	if d := p.currentDetector(); d != nil {
		d.Observe(events)
	}
	m := p.CurrentManager()
	if m == nil {
		return
	}
	bus := m.Bus()
	for _, e := range events {
		if f, ok := bridgeEvent(proxyID, e); ok {
			bus.PublishFinding(f)
		}
	}
}

// RunTick evaluates the temporal detectors once and publishes each resulting
// Finding onto the CURRENT manager's bus (→ AlertManager → Alert Store → Router).
// The manager is read here (not captured once) so the tick keeps publishing to
// the live pipeline across a reload; no engine or no manager yet ⇒ no-op. It is
// FAIL-OPEN: a panic in a detector's Evaluate or in publish is recovered and
// logged so one bad tick can never crash the tick loop. It logs only the COUNT of
// findings — never their content — preserving egress hygiene. It is exported so
// tests (here and in the control plane) can drive a single deterministic tick.
func (p *Pipeline) RunTick() {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Error("alert pipeline: detection tick panic (recovered)", "recover", r)
		}
	}()
	m := p.CurrentManager()
	if m == nil {
		return
	}
	// Detection evaluate + publish — only when an engine is present. The engine is
	// read under the lock (not captured once) so the tick keeps evaluating the live
	// engine across a ReloadDetection; a nil engine (detection off) skips this.
	if d := p.currentDetector(); d != nil {
		bus := m.Bus()
		findings := d.Evaluate()
		for _, f := range findings {
			bus.PublishFinding(f)
		}
		if len(findings) > 0 {
			p.logger.Debug("alert pipeline: detection tick emitted findings", "count", len(findings))
		}
	}
	// Resolve sweep (P4): runs every tick regardless of detection so a firing alert
	// silent for the resolve TTL flips to resolved. It reuses the store's ON CONFLICT
	// upsert (no new table) and is fail-open (ResolveStale recovers internally).
	if n := m.ResolveStale(p.now()); n > 0 {
		p.logger.Debug("alert pipeline: resolved stale alerts", "count", n)
	}
}

// CurrentManager returns the live Manager under the read lock. Nil-safe: a
// Pipeline with no store (or a failed build) has no manager, and callers degrade
// to empty.
func (p *Pipeline) CurrentManager() *integration.Manager {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.manager
}

// currentDetector returns the live detection engine under the read lock (nil when
// detection is off). Reading under the same lock that ReloadDetection swaps under
// guarantees the tick/Observe never see a half-swapped engine.
func (p *Pipeline) currentDetector() *detect.Engine {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.detector
}

// Detectors returns the active detector names in construction order, or nil when
// detection is off. It lets the caller report whether the engine is running
// without exposing the engine itself.
func (p *Pipeline) Detectors() []string {
	d := p.currentDetector()
	if d == nil {
		return nil
	}
	return d.Detectors()
}

// Evictions returns the total cardinality-cap evictions across the live engine's
// detectors, or 0 when detection is off. It lets the dashboard surface memory
// pressure (a read-only status number) without exposing the engine.
func (p *Pipeline) Evictions() uint64 {
	d := p.currentDetector()
	if d == nil {
		return 0
	}
	return d.Evictions()
}

// ReloadDetection hot-swaps the live detection engine to run cfg (when enabled),
// or DISABLES detection (nil engine) when enabled is false. It rebuilds
// detect.NewEngine OUTSIDE the lock, then swaps the engine pointer under the SAME
// RWMutex that guards the manager pointer — so a concurrent tick (Evaluate) or
// Observe never sees a half-swapped engine: each reads the CURRENT engine, an
// in-flight Evaluate finishes against the old one, and the next tick uses the new
// one. The already-running tick loop (started with the manager) picks up the
// swapped engine, so a dashboard PUT that ENABLES detection starts producing
// findings without a restart. Nil-safe.
//
// Fail-open by construction: detect.NewEngine never returns an error, so a reload
// can never tear down live alerting; the error return is kept for interface
// symmetry with ReloadManager and future build-validation. The tick INTERVAL is
// fixed at Start — a changed tickInterval takes effect on the next restart (a live
// cadence change is a small follow-up, out of M3 scope).
func (p *Pipeline) ReloadDetection(cfg detect.Config, enabled bool) error {
	// Build the engine only when a manager exists — there must be a bus to publish
	// findings onto (the same gate New applies). On a no-manager pipeline (fail-open
	// no-store), detection stays off.
	var eng *detect.Engine
	if enabled && p.CurrentManager() != nil {
		eng = detect.NewEngine(cfg, nil)
	}
	p.mu.Lock()
	p.detector = eng
	p.mu.Unlock()
	if eng != nil {
		p.logger.Info("alert pipeline detection reloaded", "detectors", eng.Detectors())
	} else {
		p.logger.Info("alert pipeline detection reloaded (disabled)")
	}
	return nil
}

// ReloadManager hot-swaps the live Manager to run newInstances, reusing the SAME
// caller-owned store (never reopening or closing the DB). It builds a fresh
// manager, Starts it, atomically swaps the pointer, then stops the OLD manager's
// instances WITHOUT closing the shared store.
//
// Fail-safe: if the new manager cannot be BUILT, the old one keeps running and
// the error is returned — a bad reload never kills live alerting. A per-instance
// Start failure is NOT fatal: the manager's Start skips it and reports it as a
// non-connected status, so we swap to the new manager (the source of truth for
// status) and only log the skips.
func (p *Pipeline) ReloadManager(newInstances []integration.InstanceConfig) error {
	p.mu.RLock()
	store := p.store
	ctx := p.lifeCtx
	p.mu.RUnlock()
	if store == nil {
		return errors.New("alertpipeline: reload requires a store; alerting is not available")
	}
	if ctx == nil {
		// Reload before Start (not expected on the live HTTP path): bind to a
		// non-cancelling context; StopInstances still tears the router down.
		ctx = context.Background()
	}

	m, err := integration.NewManager(store, newInstances, p.logger, integration.RouterOptions{}, p.resolveTTL)
	if err != nil {
		return fmt.Errorf("alertpipeline: rebuild manager: %w", err)
	}
	startErr := m.Start(ctx)

	p.mu.Lock()
	old := p.manager
	p.manager = m
	p.mu.Unlock()

	if old != nil {
		if err := old.StopInstances(context.Background()); err != nil {
			p.logger.Warn("alertpipeline: stop previous manager after reload", "error", err)
		}
	}
	if startErr != nil {
		p.logger.Warn("alertpipeline: some integrations not running after reload", "error", startErr)
	}
	return nil
}
