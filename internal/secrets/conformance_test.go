package secrets_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// conformanceCase is one SecretStore implementation under the shared suite.
type conformanceCase struct {
	name string
	new  func(t *testing.T) secrets.SecretStore
	// echoesKey marks the echo backend: Get returns the key itself and no key
	// is ever missing, so the not-found case asserts that contract instead.
	echoesKey bool
	// versioned says whether the store must implement secrets.VersionedStore.
	versioned bool
}

func conformanceCases() []conformanceCase {
	return []conformanceCase{
		{name: "echo", new: func(*testing.T) secrets.SecretStore { return secrets.NewEchoStore() }, echoesKey: true},
		{name: "aws", new: func(*testing.T) secrets.SecretStore {
			return secrets.NewAWSSecretStore(secrets.NewFakeAWSClientForTest(), "us-east-1", "")
		}},
		{name: "vault", versioned: true, new: func(t *testing.T) secrets.SecretStore {
			kv := fakes.NewFakeVaultKV(t, "conformance-token")
			s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: kv.URL(), NamePrefix: "app/", Token: "conformance-token"}, kv.Client())
			if err != nil {
				t.Fatal(err)
			}
			return s
		}},
		{name: "fake", versioned: true, new: func(*testing.T) secrets.SecretStore { return fakes.NewFakeSecretStore() }},
	}
}

// TestStoreConformance runs one behaviour table against every SecretStore:
// Put/Get round trip, idempotent Delete, missing keys wrapping ErrNotFound, and
// compare-and-swap where the store is a VersionedStore.
func TestStoreConformance(t *testing.T) {
	ctx := context.Background()
	for _, tc := range conformanceCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("put_get_round_trip", func(t *testing.T) {
				s := tc.new(t)
				if err := s.Put(ctx, "openai", "sk-one"); err != nil {
					t.Fatalf("Put: %v", err)
				}
				if err := s.Put(ctx, "openai", "sk-two"); err != nil {
					t.Fatalf("Put (update): %v", err)
				}
				want := "sk-two"
				if tc.echoesKey {
					want = "openai"
				}
				if got, err := s.Get(ctx, "openai"); err != nil || got != want {
					t.Fatalf("Get = %q, %v; want %q", got, err, want)
				}
			})
			t.Run("delete_idempotent", func(t *testing.T) {
				s := tc.new(t)
				if err := s.Put(ctx, "k", "v"); err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 2; i++ {
					if err := s.Delete(ctx, "k"); err != nil {
						t.Fatalf("Delete #%d: %v", i+1, err)
					}
				}
				if err := s.Delete(ctx, "never-stored"); err != nil {
					t.Fatalf("Delete of a never-stored key: %v", err)
				}
			})
			t.Run("missing_key_wraps_ErrNotFound", func(t *testing.T) {
				s := tc.new(t)
				_, err := s.Get(ctx, "absent")
				if tc.echoesKey {
					if err != nil {
						t.Fatalf("echo Get must resolve every key to itself, got %v", err)
					}
					return
				}
				if !errors.Is(err, secrets.ErrNotFound) {
					t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
				}
				if err := s.Put(ctx, "gone", "v"); err != nil {
					t.Fatal(err)
				}
				if err := s.Delete(ctx, "gone"); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Get(ctx, "gone"); !errors.Is(err, secrets.ErrNotFound) {
					t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
				}
			})
			t.Run("versioned", func(t *testing.T) {
				vs, ok := tc.new(t).(secrets.VersionedStore)
				if ok != tc.versioned {
					t.Fatalf("implements VersionedStore = %v, want %v", ok, tc.versioned)
				}
				if !ok {
					return
				}
				if _, _, err := vs.GetVersion(ctx, "cas"); !errors.Is(err, secrets.ErrNotFound) {
					t.Fatalf("GetVersion(absent) = %v, want ErrNotFound", err)
				}
				if err := vs.PutIfVersion(ctx, "cas", "v1", 0); err != nil {
					t.Fatalf("PutIfVersion(absent, 0): %v", err)
				}
				if err := vs.PutIfVersion(ctx, "cas", "x", 0); !errors.Is(err, secrets.ErrVersionConflict) {
					t.Fatalf("PutIfVersion(existing, 0) = %v, want ErrVersionConflict", err)
				}
				v, ver, err := vs.GetVersion(ctx, "cas")
				if err != nil || v != "v1" || ver != 1 {
					t.Fatalf("GetVersion = %q, %d, %v; want v1 at 1", v, ver, err)
				}
				if err := vs.PutIfVersion(ctx, "cas", "v2", 1); err != nil {
					t.Fatalf("PutIfVersion(current): %v", err)
				}
				if err := vs.PutIfVersion(ctx, "cas", "stale", 1); !errors.Is(err, secrets.ErrVersionConflict) {
					t.Fatalf("PutIfVersion(stale) = %v, want ErrVersionConflict", err)
				}
				if v, ver, _ := vs.GetVersion(ctx, "cas"); v != "v2" || ver != 2 {
					t.Fatalf("after conflict GetVersion = %q, %d; want v2 at 2", v, ver)
				}
			})
		})
	}
}

// TestStoreConformance_EnvFetcherNotFound: the env fetcher path wraps
// ErrNotFound for a mapped placeholder whose env var is unset.
func TestStoreConformance_EnvFetcherNotFound(t *testing.T) {
	const envVar = "WARDEN_TEST_CONFORMANCE_UNSET_VAR"
	t.Setenv(envVar, "")
	f := secrets.NewEnvFetcher(map[string]string{"ph": envVar})
	if _, err := f.Fetch("ph"); err != nil {
		t.Fatalf("set (empty) var must resolve, got %v", err)
	}
	f = secrets.NewEnvFetcher(map[string]string{"ph": envVar + "_NEVER_SET"})
	if _, err := f.Fetch("ph"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Fetch(unset var) = %v, want ErrNotFound", err)
	}
}
