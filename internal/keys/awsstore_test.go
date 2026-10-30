package keys_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/awsstore"
	"github.com/ethosagent/warden/internal/keys/adapters/metastore"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/fakes"
)

// The AWS Secrets Manager key store (W-P2-KEYS-07): the control plane's keys
// live under their own CP-local prefix, a worker role scoped to the
// secretStore prefix can neither name nor read them, and a restart keeps the
// same kids against the same backend.

const (
	keysRegion = "eu-central-1"
	// keysPrefix is the CP-local namespace; workerPrefix is the secretStore
	// default the workers' role is scoped to.
	keysPrefix   = "warden-cp-keys/"
	workerPrefix = "warden/"
)

// secretBackend adapts a secrets.SecretStore — what assembly builds with
// secrets.NewAWSSecretStore from the keys.store.aws block — onto the
// awsstore.Backend port. It is the same mapping
// internal/controlplane installs in newKeyManager.
type secretBackend struct{ ss secrets.SecretStore }

func (b secretBackend) Get(ctx context.Context, key string) (string, error) {
	v, err := b.ss.Get(ctx, key)
	if errors.Is(err, secrets.ErrSecretNotFound) {
		return "", awsstore.ErrNotFound
	}
	return v, err
}

func (b secretBackend) Put(ctx context.Context, key, value string) error {
	return b.ss.Put(ctx, key, value)
}

func (b secretBackend) Delete(ctx context.Context, key string) error {
	return b.ss.Delete(ctx, key)
}

func (b secretBackend) List(ctx context.Context) ([]string, error) {
	metas, err := b.ss.List(ctx)
	if err != nil {
		return nil, err
	}
	refs := make([]string, 0, len(metas))
	for _, m := range metas {
		refs = append(refs, m.Key)
	}
	return refs, nil
}

// newAWSKeyStore builds the PrivateKeyStore assembly builds for
// keys.store.backend: aws — an awsstore.Store over the CP-local prefix of the
// account's admin view.
func newAWSKeyStore(t *testing.T, account *fakes.FakeAWSSecretsClient) keys.PrivateKeyStore {
	t.Helper()
	cp := account.View(keysPrefix)
	s, err := awsstore.New(secretBackend{secrets.NewAWSSecretStore(cp, keysRegion, keysPrefix)})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAWSStoreIsolation: a worker-scoped store built from the served
// secretStore block cannot Get any key ref written by the keys store — its
// whole namespace is secretStore.aws.namePrefix, so the ref does not even
// resolve to the keys secret, and the role's IAM scope denies the name
// directly.
func TestAWSStoreIsolation(t *testing.T) {
	ctx := context.Background()
	account := fakes.NewFakeAWSSecretsClient()
	keysStore := newAWSKeyStore(t, account)

	kid := "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	other := "3WhD3BsvBHm3Bn-SldLao1CiCU2fAz9rbr-aJy9UGnM"
	pem := []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n")
	for _, tc := range []struct{ purpose, k string }{
		{keys.PurposeToken, kid},
		{keys.PurposeBundle, other},
	} {
		if err := keysStore.Put(ctx, tc.purpose, tc.k, pem); err != nil {
			t.Fatal(err)
		}
	}
	// Sanity: the control plane reads its own keys back.
	if got, err := keysStore.Get(ctx, keys.PurposeToken, kid); err != nil || string(got) != string(pem) {
		t.Fatalf("keys store Get = %q, %v", got, err)
	}

	// The worker's view: the role the served secretStore block implies, scoped
	// to secretStore.aws.namePrefix, with the store built the way the worker
	// builds it from that block.
	workerClient := account.View(workerPrefix)
	workerStore := secrets.NewAWSSecretStore(workerClient, keysRegion, workerPrefix)

	for _, tc := range []struct{ purpose, k string }{
		{keys.PurposeToken, kid},
		{keys.PurposeBundle, other},
		{keys.PurposeCA, kid},
	} {
		v, err := workerStore.Get(ctx, tc.purpose+"/"+tc.k)
		if !errors.Is(err, secrets.ErrSecretNotFound) {
			t.Errorf("worker store Get(%s/%s) = %q, %v; want the ref to resolve to nothing", tc.purpose, tc.k, v, err)
		}
		if strings.Contains(v, "PRIVATE KEY") {
			t.Errorf("worker store saw key material under %s/%s", tc.purpose, tc.k)
		}
		// Even the store-level List — value-free metadata only — shows the
		// worker no keys ref.
	}
	metas, err := workerStore.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range metas {
		if strings.HasPrefix(m.Key, keys.PurposeToken+"/") || strings.HasPrefix(m.Key, keys.PurposeBundle+"/") {
			t.Errorf("worker store List shows a keys ref: %q", m.Key)
		}
	}
	// A worker that bypasses its store and names the keys secret directly is
	// denied by the scope, exactly as the IAM policy (docs/control-plane.md)
	// intends.
	if _, err := workerClient.GetSecretValue(keysPrefix + keys.PurposeToken + "/" + kid); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("worker role GetSecretValue(%s) = %v, want AccessDeniedException", keysPrefix+keys.PurposeToken+"/"+kid, err)
	}

	// And the control plane's role is scoped to its own namespace only: it
	// cannot wander into the worker secrets either.
	cpClient := account.View(keysPrefix)
	if _, err := cpClient.GetSecretValue(workerPrefix + "OPENAI_API_KEY"); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("keys role GetSecretValue(worker secret) = %v, want AccessDeniedException", err)
	}
}

// awsEnv is the manager environment of the AWS backend: the same shape as the
// file-backend env in manager_test.go, with the keys store over the fake
// account.
type awsEnv struct {
	t       *testing.T
	account *fakes.FakeAWSSecretsClient
	store   keys.PrivateKeyStore
	db      *cpstate.DB
	meta    keys.MetaStore
	clk     *clocktest.Fake
	logs    *syncBuffer
}

func newAWSEnv(t *testing.T) *awsEnv {
	t.Helper()
	e := &awsEnv{
		t:       t,
		account: fakes.NewFakeAWSSecretsClient(),
		clk:     clocktest.NewFake(time.Unix(1_800_000_000, 0)),
		logs:    &syncBuffer{},
	}
	db, err := cpstate.Open(context.Background(), t.TempDir()+"/warden-cp.db", cpstate.Enable(metastore.Migrations(), metastore.MigrationID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.meta = metastore.New(db)
	e.store = newAWSKeyStore(t, e.account)
	return e
}

func (e *awsEnv) manager() *keys.Manager {
	e.t.Helper()
	m, err := keys.NewManager(keys.ManagerConfig{
		Store: e.store, Meta: e.meta, Codec: signer.Codec{}, Backend: "aws",
		Algs: map[string]string{keys.PurposeToken: keys.AlgEdDSA, keys.PurposeBundle: keys.AlgEdDSA},
		Now:  e.clk.Now, Wait: waitOn(e.clk), Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

// secretName is the backend secret name of a ref, as the store builds it.
func secretName(purpose, kid string) string { return keysPrefix + purpose + "/" + kid }

// rows returns the signing_keys rows, oldest first.
func (e *awsEnv) rows() []keys.Record {
	e.t.Helper()
	rows, err := e.meta.List(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

// TestAWSStoreLifecycle: generation, restart and reload against the fake
// client keep the same kids and create no extra secrets; the orphan sweep
// deletes material with no row; retiring a key deletes its secret; and no log
// line or error ever carries the PEM or a credential.
func TestAWSStoreLifecycle(t *testing.T) {
	e := newAWSEnv(t)
	ctx := context.Background()

	m1 := e.manager()
	m1.Init(ctx)
	if !m1.Ready() {
		t.Fatalf("first start not ready: token=%q bundle=%q", m1.LastError(keys.PurposeToken), m1.LastError(keys.PurposeBundle))
	}
	first := e.rows()
	if len(first) != 4 {
		t.Fatalf("rows after the first start = %d, want an active and a next for token and bundle", len(first))
	}
	for _, r := range first {
		if r.StoreBackend != "aws" {
			t.Errorf("row %s/%s records store_backend %q, want aws", r.Purpose, r.KID, r.StoreBackend)
		}
		if !e.account.Has(secretName(r.Purpose, r.KID)) {
			t.Errorf("no secret for %s/%s under %s", r.Purpose, r.KID, keysPrefix)
		}
	}

	// A restart loads the same kids from the same backend and creates nothing.
	m2 := e.manager()
	m2.Init(ctx)
	second := e.rows()
	if len(second) != len(first) {
		t.Fatalf("restart changed the row count: %d -> %d", len(first), len(second))
	}
	seen := map[string]bool{}
	for i, r := range second {
		if r.KID != first[i].KID || r.State != first[i].State {
			t.Errorf("row %d changed across the restart: %s/%s -> %s/%s", i, first[i].Purpose, first[i].KID, r.Purpose, r.KID)
		}
		seen[r.Purpose+"/"+r.KID] = true
	}
	if _, err := m2.KeySet().Active(keys.PurposeToken); err != nil {
		t.Errorf("token signer after the restart: %v", err)
	}

	// The orphan sweep deletes material with no row — a crash between the Put
	// and the INSERT — and only that material.
	orphan := "b3JwaGFuLWtpZF9tYXRlcmlhbA"
	if err := e.store.Put(ctx, keys.PurposeToken, orphan, []byte("-----BEGIN PRIVATE KEY-----\nZA==\n-----END PRIVATE KEY-----\n")); err != nil {
		t.Fatal(err)
	}
	n, err := m2.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("Sweep = %d, want 1", n)
	}
	if e.account.Has(secretName(keys.PurposeToken, orphan)) {
		t.Error("the orphan secret survived the sweep")
	}
	for _, r := range second {
		if !e.account.Has(secretName(r.Purpose, r.KID)) {
			t.Errorf("the sweep deleted rowed material %s/%s", r.Purpose, r.KID)
		}
	}

	// Retirement deletes the secret at once (the overlap keeps only the public
	// JWK), and deleting what is already gone stays quiet.
	retired := second[0]
	if err := e.store.Delete(ctx, retired.Purpose, retired.KID); err != nil {
		t.Fatal(err)
	}
	if e.account.Has(secretName(retired.Purpose, retired.KID)) {
		t.Errorf("the retired %s/%s secret was not deleted", retired.Purpose, retired.KID)
	}
	if _, err := e.store.Get(ctx, retired.Purpose, retired.KID); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get of retired material = %v, want ErrKeyNotFound", err)
	}
	if err := e.store.Delete(ctx, retired.Purpose, retired.KID); err != nil {
		t.Errorf("second Delete of retired material = %v, want nil", err)
	}

	// Hygiene: region and prefix are nameable, key bytes and credentials are
	// not — in any log line.
	logs := e.logs.String()
	for _, banned := range []string{"PRIVATE KEY", "AKIA", "aws_secret_access_key", "wJalr"} {
		if strings.Contains(logs, banned) {
			t.Errorf("logs contain %q", banned)
		}
	}
}
