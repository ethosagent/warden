package secrets_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

const vaultTestToken = "hvs.fake-vault-token-7f3a91"

// newVaultTestStore starts a fake KV v2 server and a store under prefix app/.
func newVaultTestStore(t *testing.T) (*fakes.FakeVaultKV, secrets.SecretStore) {
	t.Helper()
	kv := fakes.NewFakeVaultKV(t, vaultTestToken)
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{
		Addr: kv.URL(), NamePrefix: "app/", Token: vaultTestToken, Namespace: "team-a",
	}, kv.Client())
	if err != nil {
		t.Fatalf("NewVaultSecretStore: %v", err)
	}
	return kv, s
}

// newVaultTestStoreOn builds another store (prefix app/) on an existing fake.
func newVaultTestStoreOn(t *testing.T, kv *fakes.FakeVaultKV) (*fakes.FakeVaultKV, secrets.SecretStore) {
	t.Helper()
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: kv.URL(), NamePrefix: "app/", Token: vaultTestToken}, kv.Client())
	if err != nil {
		t.Fatalf("NewVaultSecretStore: %v", err)
	}
	return kv, s
}

func versioned(t *testing.T, s secrets.SecretStore) secrets.VersionedStore {
	t.Helper()
	vs, ok := s.(secrets.VersionedStore)
	if !ok {
		t.Fatal("the Vault store must implement secrets.VersionedStore")
	}
	return vs
}

// kv2Preflight answers the store's mount check as a KV v2 mount for the
// hand-rolled servers below; it reports whether it handled r.
func kv2Preflight(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
		return false
	}
	_, _ = w.Write([]byte(`{"data":{"type":"kv","path":"secret/","options":{"version":"2"}}}`))
	return true
}

func hasRequest(reqs []fakes.VaultRequest, method, path string) bool {
	for _, r := range reqs {
		if r.Method == method && r.Path == path {
			return true
		}
	}
	return false
}

// TestVaultStore_PutGetDelete: Put then Get of openai returns the value, a new
// key keeps one version, Delete hits metadata/ and Get then wraps ErrNotFound.
func TestVaultStore_PutGetDelete(t *testing.T) {
	kv, s := newVaultTestStore(t)
	ctx := context.Background()

	if err := s.Put(ctx, "openai", "sk-first-value"); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, "openai", "sk-second-value"); err != nil {
		t.Fatalf("Put (update): %v", err)
	}
	if got, err := s.Get(ctx, "openai"); err != nil || got != "sk-second-value" {
		t.Fatalf("Get = %q, %v; want sk-second-value", got, err)
	}
	reqs := kv.Requests()
	if !hasRequest(reqs, http.MethodPost, "/v1/secret/data/app/openai") || !hasRequest(reqs, http.MethodGet, "/v1/secret/data/app/openai") {
		t.Fatalf("requests = %+v; want POST and GET on /v1/secret/data/app/openai", reqs)
	}
	if !hasRequest(reqs, http.MethodPost, "/v1/secret/metadata/app/openai") {
		t.Fatalf("a new key must set metadata; requests = %+v", reqs)
	}
	if kv.MaxVersions("app/openai") != 1 || kv.StoredVersions("app/openai") != 1 {
		t.Fatalf("max_versions = %d, stored versions = %d; want 1 and 1 (old value not recoverable)",
			kv.MaxVersions("app/openai"), kv.StoredVersions("app/openai"))
	}
	for _, r := range reqs {
		if r.Namespace != "team-a" {
			t.Fatalf("request %s %s carried namespace %q, want team-a", r.Method, r.Path, r.Namespace)
		}
	}

	if err := s.Delete(ctx, "openai"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !hasRequest(kv.Requests(), http.MethodDelete, "/v1/secret/metadata/app/openai") {
		t.Fatalf("Delete must remove every version via metadata/; requests = %+v", kv.Requests())
	}
	if _, err := s.Get(ctx, "openai"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "openai"); err != nil {
		t.Fatalf("second Delete: %v", err)
	}
	kv.ForceStatus(http.MethodDelete, "/v1/secret/metadata/app/gone", http.StatusNotFound)
	if err := s.Delete(ctx, "gone"); err != nil {
		t.Fatalf("Delete answered 404 must succeed, got %v", err)
	}
	kv.ForceStatus(http.MethodDelete, "/v1/secret/metadata/app/broken", http.StatusInternalServerError)
	if err := s.Delete(ctx, "broken"); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("Delete answered 500 = %v, want an error naming the status", err)
	}
}

// TestVaultStore_ListMetadataOnly: List walks metadata/ recursively, returns
// value-free metas for a, b/c and b/d, and never touches a data/ path.
func TestVaultStore_ListMetadataOnly(t *testing.T) {
	kv, s := newVaultTestStore(t)
	ctx := context.Background()
	for _, k := range []string{"a", "b/c", "b/d"} {
		if err := s.Put(ctx, k, "value-of-"+k); err != nil {
			t.Fatalf("Put(%s): %v", k, err)
		}
	}
	before := len(kv.Requests())
	metas, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := make([]string, 0, len(metas))
	for _, m := range metas {
		got = append(got, m.Key)
	}
	if strings.Join(got, ",") != "a,b/c,b/d" {
		t.Fatalf("List keys = %v, want [a b/c b/d]", got)
	}
	listReqs := kv.Requests()[before:]
	if len(listReqs) == 0 {
		t.Fatal("List made no requests")
	}
	for _, r := range listReqs {
		if strings.Contains(r.Path, "/data/") {
			t.Fatalf("List requested a data path: %s %s", r.Method, r.Path)
		}
		if r.Method != "LIST" {
			t.Fatalf("List used method %s on %s, want LIST", r.Method, r.Path)
		}
	}
}

// TestVaultStore_ListEmptyAndCap: an empty prefix lists nothing; a listing over
// 10,000 keys fails closed with ErrListLimit; names that would leave the
// prefix are skipped.
func TestVaultStore_ListEmptyAndCap(t *testing.T) {
	_, s := newVaultTestStore(t)
	if metas, err := s.List(context.Background()); err != nil || len(metas) != 0 {
		t.Fatalf("List(empty) = %v, %v; want none", metas, err)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kv2Preflight(w, r) {
			return
		}
		var b strings.Builder
		b.WriteString(`{"data":{"keys":[`)
		for i := 0; i <= 10000; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"k%d"`, i)
		}
		b.WriteString(`]}}`)
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(huge.Close)
	hs, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: huge.URL, Token: vaultTestToken}, huge.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.List(context.Background()); !errors.Is(err, secrets.ErrListLimit) {
		t.Fatalf("List(10001 keys) = %v, want ErrListLimit", err)
	}

	var paths []string
	hostile := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kv2Preflight(w, r) {
			return
		}
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/v1/secret/metadata/app" {
			_, _ = w.Write([]byte(`{"data":{"keys":["../","..","ok",".","/abs"]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
	}))
	t.Cleanup(hostile.Close)
	hs, err = secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: hostile.URL, NamePrefix: "app/", Token: vaultTestToken}, hostile.Client())
	if err != nil {
		t.Fatal(err)
	}
	metas, err := hs.List(context.Background())
	if err != nil || len(metas) != 1 || metas[0].Key != "ok" {
		t.Fatalf("List(hostile) = %+v, %v; want only ok", metas, err)
	}
	if len(paths) != 1 {
		t.Fatalf("List followed a hostile directory name: %v", paths)
	}
}

// TestVaultStore_PutIfVersion: against a stored version 2, PutIfVersion at 1
// and at 0 both return ErrVersionConflict and leave the value; the current
// version succeeds; create-only on a new key sets max_versions.
func TestVaultStore_PutIfVersion(t *testing.T) {
	kv, s := newVaultTestStore(t)
	vs := versioned(t, s)
	ctx := context.Background()

	if err := s.Put(ctx, "grant", "rt-one"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "grant", "rt-two"); err != nil {
		t.Fatal(err)
	}
	v, ver, err := vs.GetVersion(ctx, "grant")
	if err != nil || v != "rt-two" || ver != 2 {
		t.Fatalf("GetVersion = %q, %d, %v; want rt-two at 2", v, ver, err)
	}
	for _, stale := range []int64{1, 0} {
		err := vs.PutIfVersion(ctx, "grant", "rt-lost", stale)
		if !errors.Is(err, secrets.ErrVersionConflict) {
			t.Fatalf("PutIfVersion(at %d) = %v, want ErrVersionConflict", stale, err)
		}
		if got, _ := kv.Value("app/grant"); got != "rt-two" {
			t.Fatalf("after conflict at %d the value is %q, want unchanged", stale, got)
		}
	}
	if err := vs.PutIfVersion(ctx, "grant", "rt-three", 2); err != nil {
		t.Fatalf("PutIfVersion(current): %v", err)
	}
	if _, ver, _ := vs.GetVersion(ctx, "grant"); ver != 3 {
		t.Fatalf("version after CAS write = %d, want 3", ver)
	}
	if err := vs.PutIfVersion(ctx, "grant", "x", -1); err == nil {
		t.Fatal("a negative version must be rejected")
	}

	if err := vs.PutIfVersion(ctx, "fresh", "rt-new", 0); err != nil {
		t.Fatalf("PutIfVersion(new, 0): %v", err)
	}
	if kv.MaxVersions("app/fresh") != 1 {
		t.Fatalf("create-only write must set max_versions=1, got %d", kv.MaxVersions("app/fresh"))
	}
}

// TestVaultStore_MetadataFailureWritesNothing: max_versions is written BEFORE
// the data, so when it fails nothing is written, nothing is rolled back (no
// DELETE), and the next successful Put still enforces max_versions=1.
func TestVaultStore_MetadataFailureWritesNothing(t *testing.T) {
	kv, s := newVaultTestStore(t)
	ctx := context.Background()
	kv.ForceStatus(http.MethodPost, "/v1/secret/metadata/app/k", http.StatusInternalServerError)
	if err := s.Put(ctx, "k", "v1"); err == nil {
		t.Fatal("Put must fail when max_versions cannot be set")
	}
	if _, ok := kv.Value("app/k"); ok {
		t.Fatal("no data may be written when max_versions failed")
	}
	for _, r := range kv.Requests() {
		if r.Method == http.MethodDelete || (r.Method == http.MethodPost && strings.Contains(r.Path, "/data/")) {
			t.Fatalf("a failed metadata write must not be followed by %s %s", r.Method, r.Path)
		}
	}
	for _, v := range []string{"v1", "v2", "v3"} {
		if err := s.Put(ctx, "k", v); err != nil {
			t.Fatalf("Put(%s): %v", v, err)
		}
	}
	if kv.MaxVersions("app/k") != 1 || kv.StoredVersions("app/k") != 1 {
		t.Fatalf("after recovery max_versions = %d, stored versions = %d; want 1 and 1",
			kv.MaxVersions("app/k"), kv.StoredVersions("app/k"))
	}

	// An existing key whose metadata write fails keeps its value.
	kv.ForceStatus(http.MethodPost, "/v1/secret/metadata/app/k", http.StatusInternalServerError)
	if err := s.Put(ctx, "k", "v4"); err == nil {
		t.Fatal("Put must fail when max_versions cannot be set")
	}
	if got, _ := kv.Value("app/k"); got != "v3" {
		t.Fatalf("value after failed Put = %q, want v3", got)
	}
}

// TestVaultStore_RacingWriterSurvivesMetadataFailure: writer B lands its value
// while writer A's create is in flight and A's metadata write fails; B's
// acknowledged value survives because A never deletes on failure.
func TestVaultStore_RacingWriterSurvivesMetadataFailure(t *testing.T) {
	kv, a := newVaultTestStore(t)
	_, b := newVaultTestStoreOn(t, kv)
	vb := versioned(t, b)
	ctx := context.Background()

	const meta = "/v1/secret/metadata/app/grant"
	var bErr error
	kv.ForceStatus(http.MethodPost, meta, http.StatusInternalServerError)
	kv.OnRequest(http.MethodPost, meta, func() { bErr = vb.PutIfVersion(ctx, "grant", "b-value", 0) })
	if err := versioned(t, a).PutIfVersion(ctx, "grant", "a-value", 0); err == nil {
		t.Fatal("A's create must fail when its metadata write fails")
	}
	if bErr != nil {
		t.Fatalf("B's create: %v", bErr)
	}
	if got, ok := kv.Value("app/grant"); !ok || got != "b-value" {
		t.Fatalf("value = %q, %v; B's acknowledged write must survive A's failure", got, ok)
	}
	if kv.MaxVersions("app/grant") != 1 {
		t.Fatalf("max_versions = %d, want 1 (set by B)", kv.MaxVersions("app/grant"))
	}
	for _, r := range kv.Requests() {
		if r.Method == http.MethodDelete {
			t.Fatalf("no writer may delete on failure: %s %s", r.Method, r.Path)
		}
	}
}

// TestVaultStore_KV1MountFailsClosed: against a KV v1 mount every operation
// fails with ErrNotKV2 before writing anything; if the mount preflight lies,
// the response-shape checks still refuse every write and read.
func TestVaultStore_KV1MountFailsClosed(t *testing.T) {
	ctx := context.Background()
	kv := fakes.NewFakeVaultKV1(t, vaultTestToken)
	_, s := newVaultTestStoreOn(t, kv)
	vs := versioned(t, s)
	_, gErr := s.Get(ctx, "k")
	_, _, gvErr := vs.GetVersion(ctx, "k")
	_, lErr := s.List(ctx)
	for op, err := range map[string]error{
		"put":          s.Put(ctx, "k", "v"),
		"putifversion": vs.PutIfVersion(ctx, "k", "v", 1),
		"get":          gErr,
		"getversion":   gvErr,
		"delete":       s.Delete(ctx, "k"),
		"list":         lErr,
	} {
		if !errors.Is(err, secrets.ErrNotKV2) {
			t.Errorf("%s on KV v1 = %v, want ErrNotKV2", op, err)
		}
	}
	if p := kv.FlatPaths(); len(p) != 0 {
		t.Fatalf("nothing may be written to a KV v1 mount, found %v", p)
	}
	for _, r := range kv.Requests() {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Path, "/v1/sys/internal/ui/mounts/") {
			t.Fatalf("only the mount check may reach a KV v1 mount, saw %s %s", r.Method, r.Path)
		}
	}

	// A mount that claims to be KV v2 but answers like v1.
	liar := fakes.NewFakeVaultKV1(t, vaultTestToken)
	liar.ReportMountVersion("2")
	_, ls := newVaultTestStoreOn(t, liar)
	lvs := versioned(t, ls)
	if err := ls.Put(ctx, "k", "v"); !errors.Is(err, secrets.ErrNotKV2) {
		t.Errorf("Put on a lying v1 mount = %v, want ErrNotKV2", err)
	}
	if err := lvs.PutIfVersion(ctx, "k", "v2", 1); !errors.Is(err, secrets.ErrNotKV2) {
		t.Errorf("PutIfVersion on a lying v1 mount = %v, want ErrNotKV2 (cas is ignored there)", err)
	}
	if _, err := ls.Get(ctx, "k"); !errors.Is(err, secrets.ErrNotKV2) {
		t.Errorf("Get on a lying v1 mount = %v, want ErrNotKV2", err)
	}
}

// TestVaultStore_NotFoundVsMissingRoute: a 404 naming errors (bad route,
// mount or namespace) is not ErrNotFound; a soft-deleted key is ErrNotFound
// with its latest version, so a CAS create can build on it.
func TestVaultStore_NotFoundVsMissingRoute(t *testing.T) {
	kv, s := newVaultTestStore(t)
	vs := versioned(t, s)
	ctx := context.Background()

	const route = `{"errors":["no handler for route \"secret/data/app/k\". route entry not found."]}`
	kv.ForceResponse(http.MethodGet, "/v1/secret/data/app/k", http.StatusNotFound, route)
	if _, err := s.Get(ctx, "k"); err == nil || errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("Get on a missing route = %v, want a non-NotFound error", err)
	}
	kv.ForceResponse(http.MethodDelete, "/v1/secret/metadata/app/k", http.StatusNotFound, route)
	if err := s.Delete(ctx, "k"); err == nil {
		t.Fatal("Delete on a missing route must fail, not report success")
	}
	kv.ForceResponse("LIST", "/v1/secret/metadata/app", http.StatusNotFound, route)
	if _, err := s.List(ctx); err == nil {
		t.Fatal("List on a missing route must fail, not report an empty listing")
	}

	if err := s.Put(ctx, "k", "one"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "k", "two"); err != nil {
		t.Fatal(err)
	}
	kv.SoftDelete("app/k")
	_, ver, err := vs.GetVersion(ctx, "k")
	if !errors.Is(err, secrets.ErrNotFound) || ver != 2 {
		t.Fatalf("GetVersion(soft-deleted) = %d, %v; want version 2 with ErrNotFound", ver, err)
	}
	if err := vs.PutIfVersion(ctx, "k", "three", 0); !errors.Is(err, secrets.ErrVersionConflict) {
		t.Fatalf("create-only over a soft-deleted version = %v, want ErrVersionConflict", err)
	}
	if err := vs.PutIfVersion(ctx, "k", "three", ver); err != nil {
		t.Fatalf("PutIfVersion at the reported version: %v", err)
	}
	if v, ver, err := vs.GetVersion(ctx, "k"); err != nil || v != "three" || ver != 3 {
		t.Fatalf("GetVersion = %q, %d, %v; want three at 3", v, ver, err)
	}
}

// TestVaultStore_RejectsUnsafeKeys: traversal-shaped keys fail before any HTTP
// call.
func TestVaultStore_RejectsUnsafeKeys(t *testing.T) {
	kv, s := newVaultTestStore(t)
	vs := versioned(t, s)
	ctx := context.Background()
	for _, key := range []string{"../x", "/x", "a/../b", "a..b", "a//b", "a/", "./a", "a\x00b", ""} {
		ops := map[string]error{}
		_, ops["get"] = s.Get(ctx, key)
		ops["put"] = s.Put(ctx, key, "v")
		ops["delete"] = s.Delete(ctx, key)
		_, _, ops["getversion"] = vs.GetVersion(ctx, key)
		ops["putifversion"] = vs.PutIfVersion(ctx, key, "v", 0)
		for op, err := range ops {
			if !errors.Is(err, secrets.ErrInvalidKey) && !errors.Is(err, secrets.ErrEmptyKey) {
				t.Errorf("%s(%q) = %v, want ErrInvalidKey", op, key, err)
			}
		}
	}
	if n := len(kv.Requests()); n != 0 {
		t.Fatalf("rejected keys reached Vault: %d requests", n)
	}
}

// TestVaultStore_EscapesSegments: each key segment is path-escaped and round
// trips, including through List.
func TestVaultStore_EscapesSegments(t *testing.T) {
	kv, s := newVaultTestStore(t)
	ctx := context.Background()
	const key = "{{OPENAI KEY}}/x?y#z"
	if err := s.Put(ctx, key, "v"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, key); err != nil || got != "v" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if !hasRequest(kv.Requests(), http.MethodGet, "/v1/secret/data/app/{{OPENAI KEY}}/x?y#z") {
		t.Fatalf("requests = %+v; want the escaped key decoded intact", kv.Requests())
	}
	metas, err := s.List(ctx)
	if err != nil || len(metas) != 1 || metas[0].Key != key {
		t.Fatalf("List = %+v, %v; want %q", metas, err, key)
	}
}

// TestVaultStore_Config: invalid configuration is refused at construction.
func TestVaultStore_Config(t *testing.T) {
	for name, cfg := range map[string]secrets.VaultStoreConfig{
		"no addr":         {Token: "t"},
		"bad scheme":      {Addr: "ftp://vault", Token: "t"},
		"userinfo":        {Addr: "https://u:p@vault", Token: "t"},
		"no token":        {Addr: "https://vault"},
		"prefix no slash": {Addr: "https://vault", Token: "t", NamePrefix: "app"},
		"prefix dotdot":   {Addr: "https://vault", Token: "t", NamePrefix: "../"},
		"mount traversal": {Addr: "https://vault", Token: "t", Mount: "a/../b"},
		"addr dotdot":     {Addr: "https://vault/a/../b", Token: "t"},
		"plain http":      {Addr: "http://vault.example:8200", Token: "t"},
		"mount sys":       {Addr: "https://vault", Token: "t", Mount: "sys"},
		"mount sys sub":   {Addr: "https://vault", Token: "t", Mount: "sys/mounts"},
		"mount auth":      {Addr: "https://vault", Token: "t", Mount: "auth/token"},
		"mount identity":  {Addr: "https://vault", Token: "t", Mount: "identity"},
		"mount cubbyhole": {Addr: "https://vault", Token: "t", Mount: "cubbyhole"},
		"mount SYS case":  {Addr: "https://vault", Token: "t", Mount: "SYS"},
	} {
		if _, err := secrets.NewVaultSecretStore(cfg, nil); err == nil {
			t.Errorf("%s: config accepted, want an error", name)
		}
	}
	for _, addr := range []string{"https://vault:8200/", "http://localhost:8200", "http://127.0.0.1:8200", "http://[::1]:8200"} {
		if _, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: addr, Token: "t", Mount: "kv/consent"}, nil); err != nil {
			t.Errorf("valid addr %q refused: %v", addr, err)
		}
	}
}

// TestVaultStore_NeverFollowsRedirects: a redirect is not followed, so the
// token never reaches another host.
func TestVaultStore_NeverFollowsRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "" {
			leaked.Store(true)
		}
	}))
	t.Cleanup(other.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: redir.URL, Token: vaultTestToken}, redir.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "k"); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("Get via redirect = %v, want an error naming status 307", err)
	}
	if leaked.Load() {
		t.Fatal("the token was sent to the redirect target")
	}
}

// TestVaultStore_CapsResponseBody: a body over 1 MiB is refused.
func TestVaultStore_CapsResponseBody(t *testing.T) {
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if kv2Preflight(w, r) {
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"value":"`))
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<20))
		_, _ = w.Write([]byte(`"}}}`))
	}))
	t.Cleanup(big.Close)
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: big.URL, Token: vaultTestToken}, big.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(context.Background(), "k"); err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("Get(oversized) = %v, want the 1 MiB cap error", err)
	}
}

// TestVaultStore_NoSecretsInErrorsOrLogs drives success and failure paths and
// asserts neither the token nor any stored value reaches an error string or a
// captured log line.
func TestVaultStore_NoSecretsInErrorsOrLogs(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	kv, s := newVaultTestStore(t)
	vs := versioned(t, s)
	ctx := context.Background()
	values := []string{"sk-live-value-AAAA", "sk-live-value-BBBB", "rt-refresh-value-CCCC"}
	var errs []error
	record := func(err error) {
		if err != nil {
			errs = append(errs, err)
		}
	}

	record(s.Put(ctx, "openai", values[0]))
	record(s.Put(ctx, "openai", values[1]))
	_, err := s.Get(ctx, "openai")
	record(err)
	record(vs.PutIfVersion(ctx, "openai", values[2], 1)) // conflict
	record(vs.PutIfVersion(ctx, "openai", values[2], 0)) // conflict
	_, err = s.Get(ctx, "missing")
	record(err)
	kv.ForceStatus(http.MethodPost, "/v1/secret/data/app/down", http.StatusInternalServerError)
	record(s.Put(ctx, "down", values[2]))
	_, err = s.List(ctx)
	record(err)

	wrong, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: kv.URL(), NamePrefix: "app/", Token: vaultTestToken + "-wrong"}, kv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = wrong.Get(ctx, "openai")
	record(err)
	record(wrong.Put(ctx, "openai", values[0]))

	if len(errs) < 5 {
		t.Fatalf("expected the failure paths to produce errors, got %d", len(errs))
	}
	secretsSeen := append([]string{vaultTestToken}, values...)
	for _, e := range errs {
		for _, sv := range secretsSeen {
			if strings.Contains(e.Error(), sv) {
				t.Fatalf("an error leaked a secret: %q", e.Error())
			}
		}
	}
	for _, sv := range secretsSeen {
		if strings.Contains(logs.String(), sv) {
			t.Fatalf("a log line leaked a secret: %q", logs.String())
		}
	}
}

// TestVaultStore_ProbeHonoursCallerContext: concurrent first calls share one
// mount probe, and with the probe hanging each returns within its own ctx
// deadline; with the probe failing they all fail fast.
func TestVaultStore_ProbeHonoursCallerContext(t *testing.T) {
	release := make(chan struct{})
	var probes atomic.Int32
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/sys/internal/ui/mounts/") {
			probes.Add(1)
			<-release
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(slow.Close)
	t.Cleanup(func() { close(release) })
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: slow.URL, Token: vaultTestToken}, slow.Client())
	if err != nil {
		t.Fatal(err)
	}

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	elapsed := make([]time.Duration, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, errs[i] = s.Get(ctx, "k")
			elapsed[i] = time.Since(start)
		}(i)
	}
	wg.Wait()
	for i := 0; i < callers; i++ {
		if !errors.Is(errs[i], context.DeadlineExceeded) {
			t.Errorf("caller %d: err = %v, want its own DeadlineExceeded", i, errs[i])
		}
		if elapsed[i] > 2*time.Second {
			t.Errorf("caller %d waited %v, past its 150ms deadline", i, elapsed[i])
		}
	}
	if n := probes.Load(); n != 1 {
		t.Errorf("concurrent first calls made %d probes, want 1 shared probe", n)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)
	fs, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: failing.URL, Token: vaultTestToken}, failing.Client())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := fs.Get(ctx, "k")
		cancel()
		if err == nil || !strings.Contains(err.Error(), "500") {
			t.Fatalf("Get with a failing probe = %v, want the probe's 500", err)
		}
	}
}

// TestVaultStore_ProbeRefusesSubPathMount: a mount configured as a sub-path of
// a KV v2 mount is refused at the probe, before any data request.
func TestVaultStore_ProbeRefusesSubPathMount(t *testing.T) {
	kv := fakes.NewFakeVaultKV(t, vaultTestToken)
	s, err := secrets.NewVaultSecretStore(secrets.VaultStoreConfig{Addr: kv.URL(), Mount: "secret/app", Token: vaultTestToken}, kv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(context.Background(), "k", "v"); !errors.Is(err, secrets.ErrNotKV2) {
		t.Fatalf("Put on a sub-path mount = %v, want ErrNotKV2", err)
	}
	for _, r := range kv.Requests() {
		if !strings.HasPrefix(r.Path, "/v1/sys/internal/ui/mounts/") {
			t.Fatalf("a refused mount must make no data request, saw %s %s", r.Method, r.Path)
		}
	}
}
