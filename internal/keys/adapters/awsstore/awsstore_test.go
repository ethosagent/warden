package awsstore

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

const kid = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

var pemBody = []byte("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n")

// fakeBackend is an in-memory Backend: a map of ref → value with the store
// semantics the real one (a secrets.SecretStore over AWS Secrets Manager) has
// — ErrNotFound for absent reads, idempotent deletes and a value-free List.
type fakeBackend struct {
	mu   sync.Mutex
	vals map[string]string
	down error
}

func newFakeBackend() *fakeBackend { return &fakeBackend{vals: map[string]string{}} }

func (f *fakeBackend) SetDown(err error) { f.down = err }

func (f *fakeBackend) Get(_ context.Context, key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return "", f.down
	}
	v, ok := f.vals[key]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

func (f *fakeBackend) Put(_ context.Context, key, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return f.down
	}
	f.vals[key] = value
	return nil
}

func (f *fakeBackend) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return f.down
	}
	delete(f.vals, key)
	return nil
}

func (f *fakeBackend) List(_ context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down != nil {
		return nil, f.down
	}
	refs := make([]string, 0, len(f.vals))
	for k := range f.vals {
		refs = append(refs, k)
	}
	return refs, nil
}

func newStore(t *testing.T) (*Store, *fakeBackend) {
	t.Helper()
	b := newFakeBackend()
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	return s, b
}

// TestPutGetDeleteRoundTrip is the seam's contract: store, read back, retire,
// and an absent read is ErrKeyNotFound.
func TestPutGetDeleteRoundTrip(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, keys.PurposeToken, kid)
	if err != nil || !strings.EqualFold(string(got), string(pemBody)) {
		t.Fatalf("Get = %q, %v; want the stored bytes", got, err)
	}
	if err := s.Delete(ctx, keys.PurposeToken, kid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, keys.PurposeToken, kid); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get after Delete = %v, want ErrKeyNotFound", err)
	}
	// Deleting what is not there is not an error (a retirement can race the
	// orphan sweep).
	if err := s.Delete(ctx, keys.PurposeToken, kid); err != nil {
		t.Errorf("second Delete = %v, want nil", err)
	}
}

// TestPutNeverOverwrites: a second Put under the same purpose and kid is
// ErrKeyExists and the first bytes survive — the file store's O_EXCL rule,
// kept for the AWS backend so a retried generation can never replace material.
func TestPutNeverOverwrites(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeBundle, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, keys.PurposeBundle, kid, []byte("other")); !errors.Is(err, keys.ErrKeyExists) {
		t.Fatalf("second Put = %v, want ErrKeyExists", err)
	}
	if got, _ := s.Get(ctx, keys.PurposeBundle, kid); string(got) != string(pemBody) {
		t.Errorf("first value was overwritten: %q", got)
	}
}

// TestPurposeNamespace: the same kid under another purpose is a different ref,
// and List returns only the purpose's kids.
func TestPurposeNamespace(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, keys.PurposeBundle, kid); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get(token kid as bundle) = %v, want ErrKeyNotFound", err)
	}
	if err := s.Put(ctx, keys.PurposeBundle, "3WhD3BsvBHm3Bn-SldLao1CiCU2fAz9rbr-aJy9UGnM", pemBody); err != nil {
		t.Fatal(err)
	}
	tokenKids, err := s.List(ctx, keys.PurposeToken)
	if err != nil || len(tokenKids) != 1 || tokenKids[0] != kid {
		t.Fatalf("List(token) = %v, %v; want [%s]", tokenKids, err, kid)
	}
	bundleKids, err := s.List(ctx, keys.PurposeBundle)
	if err != nil || len(bundleKids) != 1 {
		t.Fatalf("List(bundle) = %v, %v; want one kid", bundleKids, err)
	}
}

// TestRejectsInvalidRef: a ref that is not a valid purpose and thumbprint is
// refused before it can address a secret name outside the namespace.
func TestRejectsInvalidRef(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	for _, kid := range []string{"", "../escape", "a/b", "with space", "with.dot", string(make([]byte, 129))} {
		if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); !errors.Is(err, keys.ErrInvalidKey) {
			t.Errorf("Put(kid %q) = %v, want ErrInvalidKey", kid, err)
		}
		if _, err := s.Get(ctx, keys.PurposeToken, kid); !errors.Is(err, keys.ErrInvalidKey) {
			t.Errorf("Get(kid %q) = %v, want ErrInvalidKey", kid, err)
		}
	}
	for _, p := range []string{"audit", "", "Token", "token/"} {
		if err := s.Put(ctx, p, kid, pemBody); !errors.Is(err, keys.ErrInvalidPurpose) {
			t.Errorf("Put(purpose %q) = %v, want ErrInvalidPurpose", p, err)
		}
	}
	if _, err := s.List(ctx, "audit"); !errors.Is(err, keys.ErrInvalidPurpose) {
		t.Errorf("List(audit) = %v, want ErrInvalidPurpose", err)
	}
}

// TestListIgnoresForeignEntries: backend entries outside the store's ref
// shape — another namespace's secrets, directories, junk — are not kids.
func TestListIgnoresForeignEntries(t *testing.T) {
	s, b := newStore(t)
	ctx := context.Background()
	b.vals["token/"+kid] = string(pemBody)           // ours
	b.vals["warden-cp-keys/token/PLACEHOLDER"] = "v" // another namespace's secret
	b.vals["bundle/not-a-thumbprint!"] = "v"         // not a kid
	b.vals["token/"] = "v"                           // empty kid
	kids, err := s.List(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(kids) != 1 || kids[0] != kid {
		t.Fatalf("List(token) = %v, want [%s]", kids, kid)
	}
}

// TestEmptyMaterialRefused: an empty value is a broken codec, not a key.
func TestEmptyMaterialRefused(t *testing.T) {
	s, b := newStore(t)
	if err := s.Put(context.Background(), keys.PurposeCA, kid, nil); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Put(nil) = %v, want an empty-material error", err)
	}
	if len(b.vals) != 0 {
		t.Errorf("the empty Put wrote %d backend entries", len(b.vals))
	}
}

// TestBackendOutageSurfaces: a backend outage is not a not-found — the manager
// must keep retrying instead of treating the key as absent — and the wrapped
// error never carries key material.
func TestBackendOutageSurfaces(t *testing.T) {
	s, b := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("secrets: aws call GetSecretValue: connection refused")
	b.SetDown(boom)
	if _, err := s.Get(ctx, keys.PurposeToken, kid); !errors.Is(err, boom) || errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("Get during an outage = %v, want the outage error", err)
	}
	if err := s.Put(ctx, keys.PurposeToken, "3WhD3BsvBHm3Bn-SldLao1CiCU2fAz9rbr-aJy9UGnM", pemBody); !errors.Is(err, boom) {
		t.Errorf("Put during an outage = %v, want the outage error", err)
	}
	b.SetDown(nil)
	if _, err := s.Get(ctx, keys.PurposeToken, kid); err != nil {
		t.Errorf("Get after the outage = %v; material must survive it", err)
	}
}

// TestErrorsCarryNoKeyBytes: no error text ever contains the stored bytes.
func TestErrorsCarryNoKeyBytes(t *testing.T) {
	s, b := newStore(t)
	ctx := context.Background()
	if err := s.Put(ctx, keys.PurposeToken, kid, pemBody); err != nil {
		t.Fatal(err)
	}
	b.SetDown(errors.New("backend unavailable"))
	_, err := s.Get(ctx, keys.PurposeToken, kid)
	if err == nil {
		t.Fatal("Get during an outage = nil, want an error")
	}
	if strings.Contains(err.Error(), string(pemBody)) || strings.Contains(err.Error(), "PRIVATE KEY") {
		t.Errorf("error carries key material: %v", err)
	}
}

// TestNewRejectsNilBackend: construction fails closed.
func TestNewRejectsNilBackend(t *testing.T) {
	if _, err := New(nil); err == nil || !strings.Contains(err.Error(), "backend") {
		t.Fatalf("New(nil) = %v, want a backend error", err)
	}
}
