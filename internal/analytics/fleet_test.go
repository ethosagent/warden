package analytics

import (
	"testing"
)

func TestNewFleetStore_ProviderSelection(t *testing.T) {
	t.Run("memory", func(t *testing.T) {
		s, err := NewFleetStore(FleetConfig{Provider: "memory"})
		if err != nil {
			t.Fatalf("NewFleetStore(memory): %v", err)
		}
		defer func() { _ = s.Close() }()
		if _, ok := s.(*CentralStore); !ok {
			t.Fatalf("memory provider = %T, want *CentralStore", s)
		}
	})

	t.Run("sqlite", func(t *testing.T) {
		s, err := NewFleetStore(FleetConfig{Provider: "sqlite", SQLitePath: ":memory:"})
		if err != nil {
			t.Fatalf("NewFleetStore(sqlite): %v", err)
		}
		defer func() { _ = s.Close() }()
		if _, ok := s.(*FleetSQLiteStore); !ok {
			t.Fatalf("sqlite provider = %T, want *FleetSQLiteStore", s)
		}
	})

	t.Run("empty defaults to sqlite", func(t *testing.T) {
		s, err := NewFleetStore(FleetConfig{SQLitePath: ":memory:"})
		if err != nil {
			t.Fatalf("NewFleetStore(default): %v", err)
		}
		defer func() { _ = s.Close() }()
		if _, ok := s.(*FleetSQLiteStore); !ok {
			t.Fatalf("default provider = %T, want *FleetSQLiteStore", s)
		}
	})

	t.Run("postgres not implemented", func(t *testing.T) {
		_, err := NewFleetStore(FleetConfig{Provider: "postgres"})
		if err == nil {
			t.Fatal("NewFleetStore(postgres) = nil error, want not-implemented error")
		}
	})

	t.Run("unknown provider errors", func(t *testing.T) {
		_, err := NewFleetStore(FleetConfig{Provider: "bogus"})
		if err == nil {
			t.Fatal("NewFleetStore(bogus) = nil error, want error")
		}
	})
}
