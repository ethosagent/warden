package integration

import (
	"context"
	"testing"
)

// stubIntegration is a minimal Integration for registry tests.
type stubIntegration struct{ typ string }

func (s *stubIntegration) Type() string                                { return s.typ }
func (s *stubIntegration) Start(context.Context, System, Config) error { return nil }
func (s *stubIntegration) Stop(context.Context) error                  { return nil }

func TestRegisterAndLookup(t *testing.T) {
	const typ = "test_registry_lookup"
	Register(typ, func() Integration { return &stubIntegration{typ: typ} })

	inst, ok := newInstance(typ)
	if !ok {
		t.Fatal("newInstance should find registered type")
	}
	if inst.Type() != typ {
		t.Errorf("Type() = %q, want %q", inst.Type(), typ)
	}

	// Fresh instance each call.
	inst2, _ := newInstance(typ)
	if inst == inst2 {
		t.Error("newInstance should return a fresh instance each call")
	}

	if _, ok := newInstance("does_not_exist"); ok {
		t.Error("newInstance for unknown type should return false")
	}
}

func TestRegisterDuplicatePanics(t *testing.T) {
	const typ = "test_registry_dup"
	Register(typ, func() Integration { return &stubIntegration{typ: typ} })

	defer func() {
		if r := recover(); r == nil {
			t.Error("duplicate Register should panic")
		}
	}()
	Register(typ, func() Integration { return &stubIntegration{typ: typ} })
}

func TestRegisterNilFactoryPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Register with nil factory should panic")
		}
	}()
	Register("test_registry_nil", nil)
}

func TestRegisteredTypes(t *testing.T) {
	const typ = "test_registry_types_zzz"
	Register(typ, func() Integration { return &stubIntegration{typ: typ} })
	types := registeredTypes()
	found := false
	prev := ""
	for _, tp := range types {
		if tp < prev {
			t.Errorf("registeredTypes not sorted: %q before %q", prev, tp)
		}
		prev = tp
		if tp == typ {
			found = true
		}
	}
	if !found {
		t.Errorf("registeredTypes missing %q", typ)
	}
}
