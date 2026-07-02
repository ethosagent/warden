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

	mu      sync.Mutex
	started bool
	stopped bool
	running []Integration // successfully started instances, for Stop
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
	for _, ic := range m.instances {
		inst, ok := newInstance(ic.Type)
		if !ok {
			err := fmt.Errorf("integration: unknown type %q (name=%q); registered types: %v", ic.Type, ic.Name, registeredTypes())
			m.logger.Error("integration: skipping unknown integration type", "type", ic.Type, "name", ic.Name)
			errs = append(errs, err)
			continue
		}
		cfg := Config{Name: ic.Name, Raw: ic.Config}
		if err := inst.Start(ctx, sys, cfg); err != nil {
			m.logger.Error("integration: instance Start failed; skipping", "type", ic.Type, "name", ic.Name, "err", err)
			errs = append(errs, fmt.Errorf("integration: start %q/%q: %w", ic.Type, ic.Name, err))
			continue
		}
		m.router.Bind(ic.Name, ic.Match, inst)
		m.running = append(m.running, inst)
	}

	m.router.Start(ctx)
	m.started = true
	return errors.Join(errs...)
}

// Stop stops the router, Stops every started instance, and closes the store. It
// is idempotent: a second call is a no-op. Errors from each step are joined.
func (m *Manager) Stop(ctx context.Context) error {
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
	if err := m.store.Close(); err != nil {
		errs = append(errs, fmt.Errorf("integration: close store: %w", err))
	}
	return errors.Join(errs...)
}
