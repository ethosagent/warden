package scenarios

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// The signing-key gate (W-P2-KEYS-02): with keys.enabled the control plane
// creates an active and a next key per purpose, a restart keeps them, and a
// key store that is down never takes the control plane with it. Workers keep
// pulling policy throughout: keys are CP-local.

func keysOpts() []harness.Option { return []harness.Option{harness.WithKeys()} }

func keysFlakyOpts() []harness.Option { return []harness.Option{harness.WithFlakyKeyStore()} }

// keyKIDs maps "purpose/state" to the kid of the row in that state.
func keyKIDs(rows []harness.KeyRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		out[r.Purpose+"/"+r.State] = r.KID
	}
	return out
}

func cpPolicyStatus(h *harness.H) int {
	return h.CP().DoWorker(http.MethodGet, "/policy", h.CP().Token(), "", "").Status
}

// keysFileStoreRestart: the file backend holds one 0600 PEM per key in 0700
// directories, the database holds public metadata only, and a restart keeps
// the same kids and creates no extra rows.
func keysFileStoreRestart(t *testing.T, h *harness.H) {
	first := h.KeyRows()
	if len(first) != 4 {
		t.Fatalf("signing_keys rows = %+v, want an active and a next for token and bundle", first)
	}
	want := keyKIDs(first)
	for _, k := range []string{"token/active", "token/next", "bundle/active", "bundle/next"} {
		if want[k] == "" {
			t.Fatalf("no %s row in %+v", k, first)
		}
	}
	for _, r := range first {
		if r.Backend != "file" || r.Alg != keys.AlgEdDSA || strings.Contains(r.PublicJWK, `"d"`) {
			t.Errorf("row = %+v, want a file-backend EdDSA row with a public-only JWK", r)
		}
		pem := filepath.Join(h.KeyStateDir(), "keys", r.Purpose, r.KID+".pem")
		fi, err := os.Stat(pem)
		if err != nil {
			t.Fatalf("no key material for %s/%s: %v", r.Purpose, r.State, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", pem, fi.Mode().Perm())
		}
		if di, _ := os.Stat(filepath.Dir(pem)); di.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", filepath.Dir(pem), di.Mode().Perm())
		}
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", status)
	}

	h.CP().Stop()
	h.CP().Start()
	second := h.KeyRows()
	if len(second) != len(first) {
		t.Fatalf("restart changed the row count: %d -> %d", len(first), len(second))
	}
	got := keyKIDs(second)
	for k, kid := range want {
		if got[k] != kid {
			t.Errorf("%s kid changed across a restart: %s -> %s", k, kid, got[k])
		}
	}
	if _, err := h.KeyManager().KeySet().Active(keys.PurposeToken); err != nil {
		t.Errorf("token signer after the restart: %v", err)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the restart = %d, want 200", status)
	}
	if strings.Contains(h.Logs(), "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
}

// keysBackendDownRecovers: rows exist but the key store is unreachable at
// startup. The control plane serves policy anyway, signing is refused with
// ErrNoActiveKey, no key or row is created, a signing_key_unavailable Finding
// is published, and signing returns when the store does — no restart.
func keysBackendDownRecovers(t *testing.T, h *harness.H) {
	before := h.KeyRows()
	if len(before) != 4 {
		t.Fatalf("rows after the first start = %d, want 4", len(before))
	}

	h.CP().Stop()
	h.KeyStore().SetDown(errors.New("secret backend unreachable"))
	h.CP().Start()

	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy with the key store down = %d, want 200", status)
	}
	mgr := h.KeyManager()
	if _, err := mgr.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("signer with the store down = %v, want ErrNoActiveKey", err)
	}
	if mgr.Ready() {
		t.Error("manager reports ready with the store down")
	}
	if got := h.KeyFindings(keys.AlertSigningKeyUnavailable); len(got) != 2 {
		t.Errorf("signing_key_unavailable findings = %d, want one per purpose", len(got))
	}
	if after := h.KeyRows(); len(after) != len(before) {
		t.Errorf("the outage created rows: %d -> %d", len(before), len(after))
	}

	h.KeyStore().SetDown(nil)
	h.Eventually("signing recovers once the store returns", func() bool {
		h.Clock().Advance(time.Minute)
		return mgr.Ready()
	})
	sg, err := mgr.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sg.Sign(context.Background(), []byte("header.payload")); err != nil {
		t.Errorf("Sign after the recovery: %v", err)
	}
	after := h.KeyRows()
	if len(after) != len(before) {
		t.Fatalf("recovery changed the row count: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].KID != after[i].KID || before[i].State != after[i].State {
			t.Errorf("row %d changed: %+v -> %+v", i, before[i], after[i])
		}
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the recovery = %d, want 200", status)
	}
}

// keysDisabledCreatesNothing: without keys.enabled (the default) the control
// plane keeps no key directory and no signing_keys table.
func keysDisabledCreatesNothing(t *testing.T, h *harness.H) {
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", status)
	}
	if h.KeysTablePresent() {
		t.Error("signing_keys exists with keys disabled")
	}
}
