package fakes

import (
	"context"
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/secrets"
)

func TestMemorySecretStore(t *testing.T) {
	ctx := context.Background()
	m := NewMemorySecretStore()
	if !secrets.IsPersistent(m) {
		t.Fatal("MemorySecretStore must be persistent")
	}
	if _, err := m.Get(ctx, "idp/k"); !errors.Is(err, secrets.ErrSecretNotFound) || !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("absent Get err = %v", err)
	}
	if err := m.Put(ctx, "idp/k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Put(ctx, "idp/k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, err := m.Get(ctx, "idp/k"); err != nil || v != "v2" {
		t.Fatalf("Get = %q, %v", v, err)
	}
	list, err := m.List(ctx)
	if err != nil || len(list) != 1 || list[0].Key != "idp/k" || list[0].Version != "v2" {
		t.Fatalf("List = %+v, %v", list, err)
	}

	boom := errors.New("backend down")
	m.SetErrors(boom, boom, boom, boom)
	if _, err := m.Get(ctx, "idp/k"); !errors.Is(err, boom) {
		t.Errorf("Get err = %v", err)
	}
	if err := m.Put(ctx, "idp/k", "v3"); !errors.Is(err, boom) {
		t.Errorf("Put err = %v", err)
	}
	if err := m.Delete(ctx, "idp/k"); !errors.Is(err, boom) {
		t.Errorf("Delete err = %v", err)
	}
	if _, err := m.List(ctx); !errors.Is(err, boom) {
		t.Errorf("List err = %v", err)
	}
	if v, ok := m.Value("idp/k"); !ok || v != "v2" {
		t.Fatalf("a failed Put or Delete changed the value: %q %v", v, ok)
	}
	m.SetErrors(nil, nil, nil, nil)
	if err := m.Delete(ctx, "idp/k"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Value("idp/k"); ok {
		t.Fatal("Delete kept the value")
	}
	if m.Puts != 3 || m.Deletes != 2 || m.Gets != 3 {
		t.Fatalf("counts gets=%d puts=%d deletes=%d", m.Gets, m.Puts, m.Deletes)
	}
}
