package controlplane

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
	if err != nil && (strings.Contains(err.Error(), grantToken) || strings.Contains(err.Error(), "REFRESH-CANARY")) {
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
			_, _, err := NewGrantRecords(s).LoadGrant(context.Background(), grantUserKey, grantProvider)
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
	_, _, err := NewGrantRecords(m).LoadGrant(context.Background(), grantUserKey, grantProvider)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("err = %v, want a non-missing error", err)
	}
	if _, _, err := NewGrantRecords(m).LoadGrant(context.Background(), "bad", grantProvider); err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("bad userKey err = %v", err)
	}
}

func TestLoadGrantCorruptRecord(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	if err := m.Put(context.Background(), grantKeyFor(t), "not json "+grantToken); err != nil {
		t.Fatal(err)
	}
	_, _, err := NewGrantRecords(m).LoadGrant(context.Background(), grantUserKey, grantProvider)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
		t.Fatalf("err = %v", err)
	}
	noTokenIn(t, err)
}

func TestStoreRotatedVaultVersionConflict(t *testing.T) {
	s, kv := vaultStore(t)
	ctx := context.Background()
	putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil || !read.Versioned || read.N != 1 {
		t.Fatalf("load = %v %+v", err, read)
	}
	// Another writer bumps the key to version 2 (same grant_id, rotated).
	putRec(t, s, grantRec("g1", "REFRESH-CANARY-OTHER"))
	before, _ := kv.Value("warden-cp/" + grantKeyFor(t))
	rec.RefreshToken = "REFRESH-CANARY-MINE"
	err = NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
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
	putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	// A second writer lands after the recheck read but before our CAS write.
	kv.OnRequest(http.MethodPost, "/v1/secret/data/warden-cp/"+grantKeyFor(t), func() {
		putRec(t, s, grantRec("g1", "REFRESH-CANARY-RACE"))
	})
	rec.RefreshToken = "REFRESH-CANARY-2"
	err = NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	noTokenIn(t, err)
	got, _, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil || got.RefreshToken != "REFRESH-CANARY-RACE" {
		t.Fatalf("stored = %+v, %v; the racing write must survive", got, err)
	}
}

func TestStoreRotatedSuccessAndIdempotentRetry(t *testing.T) {
	vs, _ := vaultStore(t)
	for name, s := range map[string]secrets.SecretStore{"memory": fakes.NewMemorySecretStore(), "vault": vs} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
			rec, read, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
			if err != nil {
				t.Fatal(err)
			}
			rec.RefreshToken = "REFRESH-CANARY-2"
			if err := NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read); err != nil {
				t.Fatalf("store = %v", err)
			}
			got, _, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
			if err != nil || got.RefreshToken != "REFRESH-CANARY-2" {
				t.Fatalf("after store = %+v, %v", got, err)
			}
			// A retry with the same stale read version: our own write already landed.
			if err := NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read); err != nil {
				t.Errorf("idempotent retry = %v, want nil", err)
			}
		})
	}
}

func TestStoreRotatedNonVersionedReconnect(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, err := NewGrantRecords(m).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil || read.Versioned {
		t.Fatalf("load = %v %+v", err, read)
	}
	putRec(t, m, grantRec("g2", "REFRESH-CANARY-NEW")) // reconnect: new grant_id
	puts := m.Puts
	rec.RefreshToken = "REFRESH-CANARY-2"
	err = NewGrantRecords(m).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	if m.Puts != puts {
		t.Error("a Put happened after the grant changed")
	}
	got, _, _ := NewGrantRecords(m).LoadGrant(ctx, grantUserKey, grantProvider)
	if got.GrantID != "g2" || got.RefreshToken != "REFRESH-CANARY-NEW" {
		t.Errorf("stored = %+v", got)
	}
}

func TestStoreRotatedDeletedKey(t *testing.T) {
	vs, _ := vaultStore(t)
	for name, s := range map[string]secrets.SecretStore{"memory": fakes.NewMemorySecretStore(), "vault": vs} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
			rec, read, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Delete(ctx, grantKeyFor(t)); err != nil {
				t.Fatal(err)
			}
			rec.RefreshToken = "REFRESH-CANARY-2"
			err = NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
			if !errors.Is(err, oauthbroker.ErrGrantChanged) {
				t.Fatalf("err = %v, want ErrGrantChanged", err)
			}
			if _, _, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider); !errors.Is(err, oauthbroker.ErrGrantMissing) {
				t.Errorf("key was recreated: %v", err)
			}
		})
	}
}

func TestStoreRotatedGrantIDMismatch(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "REFRESH-CANARY-1"))
	_, read, err := NewGrantRecords(m).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	puts := m.Puts
	err = NewGrantRecords(m).StoreRotated(ctx, grantUserKey, grantProvider, grantRec("other", "REFRESH-CANARY-2"), read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) || m.Puts != puts {
		t.Fatalf("err = %v puts %d->%d", err, puts, m.Puts)
	}
}

func TestStoreRotatedTransportErrorIsNotConflict(t *testing.T) {
	m := fakes.NewMemorySecretStore()
	ctx := context.Background()
	putRec(t, m, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, _ := NewGrantRecords(m).LoadGrant(ctx, grantUserKey, grantProvider)
	m.SetErrors(nil, errors.New("connection reset"), nil, nil)
	rec.RefreshToken = "REFRESH-CANARY-2"
	err := NewGrantRecords(m).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
	if err == nil || errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want a non-conflict error", err)
	}
	noTokenIn(t, err)
}

func TestStoreRotatedVaultRecreatedAtSameVersion(t *testing.T) {
	s, kv := vaultStore(t)
	ctx := context.Background()
	gr := NewGrantRecords(s)
	putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, err := gr.LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil || read.N != 1 {
		t.Fatalf("load = %v %+v", err, read)
	}
	// Revoke then reconnect: the key is recreated at version 1 with a new grant.
	if err := s.Delete(ctx, grantKeyFor(t)); err != nil {
		t.Fatal(err)
	}
	putRec(t, s, grantRec("g2", "REFRESH-CANARY-NEW"))
	if v := kv.Version("warden-cp/" + grantKeyFor(t)); v != 1 {
		t.Fatalf("recreated version = %d, want 1", v)
	}
	rec.RefreshToken = "REFRESH-CANARY-2"
	err = gr.StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	noTokenIn(t, err)
	got, _, err := gr.LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil || got.GrantID != "g2" || got.RefreshToken != "REFRESH-CANARY-NEW" {
		t.Fatalf("stored = %+v, %v; g2 must survive", got, err)
	}
}

func TestLoadGrantVaultFailuresAreNotMissing(t *testing.T) {
	for name, status := range map[string]int{"route404": http.StatusNotFound, "server500": http.StatusInternalServerError} {
		t.Run(name, func(t *testing.T) {
			s, kv := vaultStore(t)
			putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
			kv.ForceResponse(http.MethodGet, "/v1/secret/data/warden-cp/"+grantKeyFor(t), status, `{"errors":["no handler for route"]}`)
			_, _, err := NewGrantRecords(s).LoadGrant(context.Background(), grantUserKey, grantProvider)
			if err == nil || errors.Is(err, oauthbroker.ErrGrantMissing) {
				t.Fatalf("err = %v, want a non-missing error", err)
			}
			noTokenIn(t, err)
		})
	}
}

func TestStoreRotatedUnversionedReadOnVersionedStore(t *testing.T) {
	s, kv := vaultStore(t)
	ctx := context.Background()
	putRec(t, s, grantRec("g1", "REFRESH-CANARY-1"))
	rec, read, err := NewGrantRecords(s).LoadGrant(ctx, grantUserKey, grantProvider)
	if err != nil {
		t.Fatal(err)
	}
	read.Versioned = false // a read taken without compare-and-swap
	before, _ := kv.Value("warden-cp/" + grantKeyFor(t))
	rec.RefreshToken = "REFRESH-CANARY-2"
	err = NewGrantRecords(s).StoreRotated(ctx, grantUserKey, grantProvider, rec, read)
	if !errors.Is(err, oauthbroker.ErrGrantChanged) {
		t.Fatalf("err = %v, want ErrGrantChanged", err)
	}
	if after, _ := kv.Value("warden-cp/" + grantKeyFor(t)); after != before {
		t.Error("an unguarded write reached a versioned store")
	}
}
