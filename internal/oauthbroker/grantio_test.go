package oauthbroker_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/oauthbroker"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

const (
	grantUserKey  = "0123456789abcdef0123456789abcdef"
	grantProvider = "google"
	grantToken    = "ACCESS-SECRET-VALUE"
)

func grantRec(id, refresh string) oauthbroker.TokenRecord {
	return oauthbroker.TokenRecord{
		V: 1, GrantID: id, Provider: grantProvider, ClientID: "cid", TokenType: "Bearer",
		AccessToken: grantToken, RefreshToken: refresh, Scope: "drive", Expiry: 1900000000, ObtainedAt: 1800000000,
	}
}

func grantKeyFor(t *testing.T) string {
	t.Helper()
	k, err := secrets.UserGrantKey(grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func putRec(t *testing.T, s secrets.SecretStore, rec oauthbroker.TokenRecord) {
	t.Helper()
	b, err := rec.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), grantKeyFor(t), string(b)); err != nil {
		t.Fatal(err)
	}
}

func noTokenIn(t *testing.T, err error) {
	t.Helper()
	if err != nil && (strings.Contains(err.Error(), grantToken) || strings.Contains(err.Error(), "REFRESH")) {
		t.Errorf("error leaks a token: %v", err)
	}
}

// vaultStore returns a real Vault store over the fake plus the fake itself.
func vaultStore(t *testing.T) (secrets.SecretStore, *fakes.FakeVaultKV) {
	t.Helper()
	kv := fakes.NewFakeVaultKV(t, "tok")
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: kv.URL(), Token: "tok", NamePrefix: "warden-cp/"}, kv.Client())
	if err != nil {
		t.Fatal(err)
	}
	return s, kv
}

func TestLoadGrantMissing(t *testing.T) {
	vs, _ := vaultStore(t)
	for name, s := range map[string]secrets.SecretStore{"memory": fakes.NewMemorySecretStore(), "vault": vs} {
		t.Run(name, func(t *testing.T) {
			_, _, err := oauthbroker.LoadGrant(context.Background(), s, grantUserKey, grantProvider)
			if !errors.Is(err, oauthbroker.ErrGrantMissing) {
				t.Fatalf("err = %v, want ErrGrantMissing", err)
			}
			noTokenIn(t, err)
		})
	}
}

func TestLoadGrantStoreErrorIsNotMissing(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	m.SetErrors(errors.New("backend down"), nil, nil, nil)
	_, _, err := oauthbroker.LoadGrant(context.Background(), m, grantUserKey, grantProvider)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("err = %v, want a non-missing error", err)
	}
	if _, _, err := oauthbroker.LoadGrant(context.Background(), m, "bad", grantProvider); err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("bad userKey err = %v", err)
	}
}

func TestLoadGrantCorruptRecord(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	if err := m.Put(context.Background(), grantKeyFor(t), "not json "+grantToken); err != nil {
		t.Fatal(err)
	}
	_, _, err := oauthbroker.LoadGrant(context.Background(), m, grantUserKey, grantProvider)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("err = %v", err)
	}
	noTokenIn(t, err)
}

func TestStoreRotatedVaultVersionConflict(t *testing.T) {
	s, kv := vaultStore(t)
	ctx := context.Background()
	putRec(t, s, grantRec("g1", "R1"))
	rec, read, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
	if err != nil || !read.Versioned || read.N != 1 {
		t.Fatalf("load = %v %+v", err, read)
	}
	// Another writer bumps the key to version 2 (same grant_id, rotated).
	putRec(t, s, grantRec("g1", "R-OTHER"))
	before, _ := kv.Value("warden-cp/" + grantKeyFor(t))
	rec.RefreshToken = "R-MINE"
	err = oauthbroker.StoreRotated(ctx, s, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	noTokenIn(t, err)
	if after, _ := kv.Value("warden-cp/" + grantKeyFor(t)); after != before {
		t.Error("stored value changed on a conflict")
	}
}

func TestStoreRotatedVaultCASHeld(t *testing.T) {
	s, kv := vaultStore(t)
	ctx := context.Background()
	putRec(t, s, grantRec("g1", "R1"))
	rec, read, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	// A second writer lands after the recheck read but before our CAS write.
	kv.OnRequest(http.MethodPost, "/v1/secret/data/warden-cp/"+grantKeyFor(t), func() {
		putRec(t, s, grantRec("g1", "R-RACE"))
	})
	rec.RefreshToken = "R2"
	err = oauthbroker.StoreRotated(ctx, s, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	got, _, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
	if err != nil || got.RefreshToken != "R-RACE" {
		t.Fatalf("stored = %+v, %v; the racing write must survive", got, err)
	}
}

func TestStoreRotatedSuccessAndIdempotentRetry(t *testing.T) {
	vs, _ := vaultStore(t)
	for name, s := range map[string]secrets.SecretStore{"memory": fakes.NewMemorySecretStore(), "vault": vs} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			putRec(t, s, grantRec("g1", "R1"))
			rec, read, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
			if err != nil {
				t.Fatal(err)
			}
			rec.RefreshToken = "R2"
			if err := oauthbroker.StoreRotated(ctx, s, grantUserKey, grantProvider, rec, read); err != nil {
				t.Fatalf("store = %v", err)
			}
			got, _, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
			if err != nil || got.RefreshToken != "R2" {
				t.Fatalf("after store = %+v, %v", got, err)
			}
			// A retry with the same stale read version: our own write already landed.
			if err := oauthbroker.StoreRotated(ctx, s, grantUserKey, grantProvider, rec, read); err != nil {
				t.Errorf("idempotent retry = %v, want nil", err)
			}
		})
	}
}

func TestStoreRotatedNonVersionedReconnect(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "R1"))
	rec, read, err := oauthbroker.LoadGrant(ctx, m, grantUserKey, grantProvider)
	if err != nil || read.Versioned {
		t.Fatalf("load = %v %+v", err, read)
	}
	putRec(t, m, grantRec("g2", "R-NEW")) // reconnect: new grant_id
	puts := m.Puts
	rec.RefreshToken = "R2"
	err = oauthbroker.StoreRotated(ctx, m, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	if m.Puts != puts {
		t.Error("a Put happened after the grant changed")
	}
	got, _, _ := oauthbroker.LoadGrant(ctx, m, grantUserKey, grantProvider)
	if got.GrantID != "g2" || got.RefreshToken != "R-NEW" {
		t.Errorf("stored = %+v", got)
	}
}

func TestStoreRotatedDeletedKey(t *testing.T) {
	vs, _ := vaultStore(t)
	for name, s := range map[string]secrets.SecretStore{"memory": fakes.NewMemorySecretStore(), "vault": vs} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			putRec(t, s, grantRec("g1", "R1"))
			rec, read, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Delete(ctx, grantKeyFor(t)); err != nil {
				t.Fatal(err)
			}
			rec.RefreshToken = "R2"
			err = oauthbroker.StoreRotated(ctx, s, grantUserKey, grantProvider, rec, read)
			if !errors.Is(err, oauthbroker.ErrGrantChanged) {
				t.Fatalf("err = %v, want ErrGrantChanged", err)
			}
			if _, _, err := oauthbroker.LoadGrant(ctx, s, grantUserKey, grantProvider); !errors.Is(err, oauthbroker.ErrGrantMissing) {
				t.Errorf("key was recreated: %v", err)
			}
		})
	}
}

func TestStoreRotatedGrantIDMismatch(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "R1"))
	_, read, err := oauthbroker.LoadGrant(ctx, m, grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	puts := m.Puts
	err = oauthbroker.StoreRotated(ctx, m, grantUserKey, grantProvider, grantRec("other", "R2"), read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) || m.Puts != puts {
		t.Fatalf("err = %v puts %d->%d", err, puts, m.Puts)
	}
}

func TestStoreRotatedTransportErrorIsNotConflict(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "R1"))
	rec, read, _ := oauthbroker.LoadGrant(ctx, m, grantUserKey, grantProvider)
	m.SetErrors(nil, errors.New("connection reset"), nil, nil)
	rec.RefreshToken = "R2"
	err := oauthbroker.StoreRotated(ctx, m, grantUserKey, grantProvider, rec, read)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want a non-conflict error", err)
	}
	noTokenIn(t, err)
}
