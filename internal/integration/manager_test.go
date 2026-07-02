package integration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// managerSinkCh receives alerts delivered to the registered test sink. A single
// buffered channel is safe because the manager tests run sequentially and each
// Stops its manager (draining goroutines) before the next runs.
var managerSinkCh = make(chan Alert, 64)

type chanAlerter struct{ baseIntegration }

func (c *chanAlerter) Alert(_ context.Context, a Alert) error {
	managerSinkCh <- a
	return nil
}

type failStartIntegration struct{ baseIntegration }

func (f *failStartIntegration) Start(context.Context, System, Config) error {
	return errors.New("start boom")
}

func init() {
	Register("test_manager_sink", func() Integration {
		return &chanAlerter{baseIntegration: baseIntegration{typ: "test_manager_sink"}}
	})
	Register("test_manager_failstart", func() Integration {
		return &failStartIntegration{baseIntegration: baseIntegration{typ: "test_manager_failstart"}}
	})
}

func TestManagerEndToEnd(t *testing.T) {
	store := newTestStore(t)
	instances := []InstanceConfig{
		{Type: "test_manager_sink", Name: "sink", Match: []MatchClause{{Severity: "high"}}},
	}
	m, err := NewManager(store, instances, quietLogger(), RouterOptions{QueueDepth: 8})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	m.Bus().PublishFinding(Finding{Severity: SevHigh, Category: "reliability", DedupKey: "error_rate:e2e", Summary: "hi"})

	select {
	case a := <-managerSinkCh:
		if a.DedupKey != "error_rate:e2e" {
			t.Errorf("delivered dedup = %q", a.DedupKey)
		}
		if _, ok, _ := store.GetAlert(a.ID); !ok {
			t.Error("alert should be persisted before fan-out")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for manager end-to-end delivery")
	}

	if err := m.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}
	// Stop is idempotent.
	if err := m.Stop(context.Background()); err != nil {
		t.Errorf("second Stop should be nil: %v", err)
	}
}

func TestManagerUnknownTypeError(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, []InstanceConfig{{Type: "no_such_type", Name: "x"}}, quietLogger(), RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	err = m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("Start should surface unknown type error, got %v", err)
	}
	_ = m.Stop(context.Background())
}

func TestManagerOneBadInstanceDoesNotSinkOthers(t *testing.T) {
	store := newTestStore(t)
	instances := []InstanceConfig{
		{Type: "test_manager_failstart", Name: "bad"},
		{Type: "test_manager_sink", Name: "good", Match: []MatchClause{{Severity: "high"}}},
	}
	m, err := NewManager(store, instances, quietLogger(), RouterOptions{QueueDepth: 8})
	if err != nil {
		t.Fatal(err)
	}
	// Start surfaces the bad instance's error but still starts the good one.
	err = m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "start") {
		t.Errorf("Start should surface the failed instance error, got %v", err)
	}

	m.Bus().PublishFinding(Finding{Severity: SevHigh, Category: "reliability", DedupKey: "error_rate:resilient", Summary: "hi"})
	select {
	case a := <-managerSinkCh:
		if a.DedupKey != "error_rate:resilient" {
			t.Errorf("delivered dedup = %q", a.DedupKey)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("good instance should still deliver despite a bad sibling")
	}
	_ = m.Stop(context.Background())
}

func TestManagerStartIdempotent(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, nil, quietLogger(), RouterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Second Start is a no-op.
	if err := m.Start(context.Background()); err != nil {
		t.Errorf("second Start should be nil: %v", err)
	}
	_ = m.Stop(context.Background())
}

func TestNewManagerNilStore(t *testing.T) {
	if _, err := NewManager(nil, nil, quietLogger(), RouterOptions{}); err == nil {
		t.Error("NewManager with nil store should error")
	}
}
