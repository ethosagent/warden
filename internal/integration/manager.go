package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Manager is the lifecycle glue that owns the registry instantiation, router,
// alertmanager, and bus. It wires: bus → alertmanager → (store persist) +
// router → instances.
type Manager struct {
	store     *Store
	instances []InstanceConfig
	logger    *slog.Logger

	bus    *Bus
	router *Router
	am     *AlertManager

	mu       sync.Mutex
	started  bool
	stopped  bool
	running  []Integration    // successfully started instances, for Stop
	statuses []InstanceStatus // per-configured-instance runtime status (set by Start)
}

// Instance status values reported to the dashboard. They describe whether a
// CONFIGURED instance is actually running:
//   - StatusConnected: a factory is registered AND the instance Started cleanly.
//   - StatusUnavailable: no factory is registered for the type (runtime not built).
//   - StatusError: a factory is registered but the instance's Start failed.
const (
	StatusConnected   = "connected"
	StatusUnavailable = "unavailable"
	StatusError       = "error"
)

// InstanceStatus is one configured instance's runtime status plus the metadata a
// read-only view needs. Config/Match are the operator-declared values (secrets in
// Config are ${ENV} references, never raw values), safe to surface as metadata.
type InstanceStatus struct {
	Name   string
	Type   string
	Status string // StatusConnected | StatusUnavailable | StatusError
	Reason string // human reason for a non-connected status; never a secret value
	Config map[string]any
	Match  []MatchClause
}

// NewManager builds the pipeline over store. It does NOT start anything or touch
// the registry yet — call Start for that. The Manager takes ownership of store
// and closes it (idempotently) on Stop. A nil logger defaults to slog.Default().
func NewManager(store *Store, instances []InstanceConfig, logger *slog.Logger, opts RouterOptions) (*Manager, error) {
	if store == nil {
		return nil, errors.New("integration: NewManager requires a non-nil store")
	}
	if logger == nil {
		logger = slog.Default()
	}
	bus := NewBus()
	bus.logger = logger
	router := NewRouter(store, bus, logger, opts)
	am := NewAlertManager(store, router, logger)
	bus.SetAlertManager(am)
	return &Manager{
		store:     store,
		instances: instances,
		logger:    logger,
		bus:       bus,
		router:    router,
		am:        am,
	}, nil
}

// Bus returns the producer entrypoint. Detectors publish Findings here.
func (m *Manager) Bus() *Bus { return m.bus }

// ListAlerts returns the persisted alerts newest-first (by last_seen), limited to
// limit rows (limit <= 0 returns all). It is the read accessor the dashboard uses
// to render the alerts tab; a store error yields nil (the tab degrades to empty
// rather than failing). Alerts are bounded, egress-safe metadata by construction.
func (m *Manager) ListAlerts(limit int) []Alert {
	alerts, err := m.store.ListAlerts(limit)
	if err != nil {
		m.logger.Error("integration: list alerts for dashboard failed", "error", err)
		return nil
	}
	return alerts
}

// Start instantiates each configured instance from the registry, Starts it with
// the reserved System handle and its decoded Config, binds it to the router, and
// starts the router. It is resilient (fail-open): an unknown type or a failing
// instance Start is logged and SKIPPED so one bad integration cannot sink the
// manager — but every such problem is surfaced in the joined error return. A
// non-nil error therefore does NOT mean the manager failed to start; the good
// instances are still running. Start is idempotent.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return nil
	}

	sys := newSystem()
	var errs []error
	m.statuses = make([]InstanceStatus, 0, len(m.instances))
	for _, ic := range m.instances {
		st := InstanceStatus{Name: ic.Name, Type: ic.Type, Config: ic.Config, Match: ic.Match}
		inst, ok := newInstance(ic.Type)
		if !ok {
			st.Status = StatusUnavailable
			st.Reason = "runtime not built yet — no factory registered for type " + ic.Type
			m.statuses = append(m.statuses, st)
			err := fmt.Errorf("integration: unknown type %q (name=%q); registered types: %v", ic.Type, ic.Name, registeredTypes())
			m.logger.Error("integration: skipping unknown integration type", "type", ic.Type, "name", ic.Name)
			errs = append(errs, err)
			continue
		}
		cfg := Config{Name: ic.Name, Raw: ic.Config}
		if err := inst.Start(ctx, sys, cfg); err != nil {
			st.Status = StatusError
			// Reason is deliberately GENERIC and secret-free: an integration's Start
			// error may quote interpolated config (e.g. a webhook URL that embeds a
			// token), so we never surface it to the dashboard. The full error is
			// logged server-side below for operators.
			st.Reason = "failed to start; see control-plane logs"
			m.statuses = append(m.statuses, st)
			m.logger.Error("integration: instance Start failed; skipping", "type", ic.Type, "name", ic.Name, "err", err)
			errs = append(errs, fmt.Errorf("integration: start %q/%q: %w", ic.Type, ic.Name, err))
			continue
		}
		st.Status = StatusConnected
		m.statuses = append(m.statuses, st)
		m.router.Bind(ic.Name, ic.Match, inst)
		m.running = append(m.running, inst)
	}

	m.router.Start(ctx)
	m.started = true
	return errors.Join(errs...)
}

// InstanceStatuses returns a snapshot of each configured instance's runtime
// status (populated by Start). It is the read accessor the control plane wires
// into the dashboard's integrations source. Before Start it returns an empty
// slice. The returned slice is a copy; Config/Match still share the underlying
// (read-only) values.
func (m *Manager) InstanceStatuses() []InstanceStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]InstanceStatus, len(m.statuses))
	copy(out, m.statuses)
	return out
}

// Stop stops the router, Stops every started instance, and closes the store. It
// is idempotent: a second call is a no-op. Errors from each step are joined.
func (m *Manager) Stop(ctx context.Context) error { return m.stop(ctx, true) }

// StopInstances stops the router and every started instance but LEAVES THE STORE
// OPEN. It exists for the control plane's live reload: a new manager is built
// over the SAME store, so the outgoing manager must not close a store the
// incoming one now owns. Store lifecycle then belongs to the reload owner (the
// control-plane Server), which closes it once at shutdown. Idempotent.
func (m *Manager) StopInstances(ctx context.Context) error { return m.stop(ctx, false) }

// stop is the shared teardown for Stop / StopInstances. It stops the router and
// each started instance, and — only when closeStore is set — closes the store.
func (m *Manager) stop(ctx context.Context, closeStore bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return nil
	}
	m.stopped = true

	var errs []error
	if err := m.router.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("integration: stop router: %w", err))
	}
	for _, inst := range m.running {
		if err := inst.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("integration: stop instance %q: %w", inst.Type(), err))
		}
	}
	m.running = nil
	if closeStore {
		if err := m.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("integration: close store: %w", err))
		}
	}
	return errors.Join(errs...)
}
