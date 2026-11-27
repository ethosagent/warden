package scenarios

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/secrets"
	"github.com/ethosagent/warden/test/harness"
)

func consentStoreVaultOpts() []harness.Option {
	return []harness.Option{harness.WithPerUserSecretsVault()}
}

// consentStoreVault (W-P3-PUS-02): with perUserSecrets enabled over a Vault KV
// v2 consent.store, the control plane probes the mount with its own token and
// namespace before it serves, logs the store without the token, keeps the
// per-user block and the store off GET /policy, and fails closed on restart
// when the mount turns out to be KV v1 or missing (a 404 is never read as an
// empty store); once the mount is healthy again it comes back.
func consentStoreVault(t *testing.T, h *harness.H) {
	cp := h.CP()
	kv := h.ConsentVault()
	probe := "/v1/sys/internal/ui/mounts/" + harness.ConsentVaultMount

	probes := func() int {
		n := 0
		for _, r := range kv.Requests() {
			if r.Method == http.MethodGet && r.Path == probe {
				n++
				if r.Namespace != harness.ConsentVaultNamespace {
					t.Errorf("mount probe sent namespace %q, want %q", r.Namespace, harness.ConsentVaultNamespace)
				}
			}
		}
		return n
	}
	if probes() != 1 {
		t.Fatalf("vault requests at boot = %+v, want one mount probe", kv.Requests())
	}
	for _, r := range kv.Requests() {
		if strings.Contains(r.Path, "/data/") {
			t.Errorf("boot touched a data path: %s %s", r.Method, r.Path)
		}
	}

	logs := h.Logs()
	if !strings.Contains(logs, "control plane user credential store active") || !strings.Contains(logs, `"backend":"vault"`) {
		t.Error("the CP did not log the vault user credential store")
	}
	if !strings.Contains(logs, "control plane per-user secrets enabled") {
		t.Error("the CP did not log that per-user secrets are enabled")
	}

	pol := cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "worker-1", "")
	if pol.Status != http.StatusOK {
		t.Fatalf("GET /policy = %d %s", pol.Status, pol.Body)
	}
	for _, banned := range []string{"perUserSecrets", harness.PerUserPlaceholder, harness.PerUserDomain, harness.PerUserAgent, kv.URL(), harness.ConsentVaultNamespace, "consent"} {
		if strings.Contains(pol.Body, banned) {
			t.Errorf("GET /policy carries %q", banned)
		}
	}

	// A KV v1 mount: the restart is refused with ErrNotKV2, before serving.
	cp.Stop()
	kv.ReportMountVersion("1")
	kv1Err := cp.TryStart()
	if kv1Err == nil || !errors.Is(kv1Err, secrets.ErrNotKV2) || !strings.Contains(kv1Err.Error(), "consent.store.vault") {
		t.Fatalf("restart on a KV v1 mount = %v, want a consent.store.vault ErrNotKV2 refusal", kv1Err)
	}

	// The mount (or namespace) is gone: a 404 stops startup, never an empty store.
	kv.ReportMountVersion("2")
	kv.ForceResponse(http.MethodGet, probe, http.StatusNotFound, `{"errors":["no handler for route"]}`)
	missingErr := cp.TryStart()
	if missingErr == nil || !strings.Contains(missingErr.Error(), "status 404") {
		t.Fatalf("restart with the mount missing = %v, want a 404 refusal", missingErr)
	}
	for _, e := range []error{kv1Err, missingErr} {
		if strings.Contains(e.Error(), h.ConsentVaultToken()) {
			t.Fatal("a boot error carries the vault token")
		}
	}

	// Healthy again: the control plane comes back and probes once more.
	before := probes()
	cp.Start()
	if probes() != before+1 {
		t.Fatalf("restart probes = %d, want %d", probes(), before+1)
	}
	if got := cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "worker-1", ""); got.Status != http.StatusOK {
		t.Fatalf("GET /policy after recovery = %d", got.Status)
	}
	if strings.Contains(h.Logs(), h.ConsentVaultToken()) {
		t.Fatal("the vault token reached the logs")
	}
}
