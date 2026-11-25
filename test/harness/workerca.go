package harness

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethosagent/warden/internal/workerca"
	wcasigner "github.com/ethosagent/warden/internal/workerca/adapters/signer"
)

// The worker CA gate (W-P2-WCA-01): the control plane boots with
// workerCA.enabled and keySource keys, on a chain minted under the harness
// clock. The intermediate key is deliberately NOT imported at boot, so the
// control plane starts degraded; a scenario imports it with
// h.WorkerCAImportKey and drives the harness clock until the 30s retry loads
// it.

// WithWorkerCA boots the control plane with the workerCA block enabled (and
// keys, which keySource keys needs).
func WithWorkerCA() Option {
	return func(h *H) {
		h.wantKeys = true
		h.wantWorkerCA = true
	}
}

// WorkerCATrustDomain is the SPIFFE trust domain of the harness worker CA.
const WorkerCATrustDomain = "warden.test"

// workerCAFixture is the chain file and the intermediate key of WithWorkerCA.
type workerCAFixture struct {
	chainPath string
	key       *ecdsa.PrivateKey
}

// workerCAFixtureOnce mints the fixture on first use, valid at the harness
// clock, in the harness root (outside the CP state dir).
func (h *H) workerCAFixture() *workerCAFixture {
	if h.workerCA != nil {
		return h.workerCA
	}
	now := h.fake.Now()
	root, rootKey, err := wcasigner.NewRoot(now)
	if err != nil {
		h.tb.Fatalf("harness: worker CA root: %v", err)
	}
	key, err := wcasigner.GenerateKey()
	if err != nil {
		h.tb.Fatalf("harness: worker CA key: %v", err)
	}
	inter, err := wcasigner.NewIntermediate(root, rootKey, &key.PublicKey, WorkerCATrustDomain, now)
	if err != nil {
		h.tb.Fatalf("harness: worker CA intermediate: %v", err)
	}
	path := filepath.Join(h.root, "worker-ca-chain.pem")
	if err := os.WriteFile(path, workerca.EncodeCertsPEM(inter, root), 0o600); err != nil {
		h.tb.Fatalf("harness: write worker CA chain: %v", err)
	}
	h.workerCA = &workerCAFixture{chainPath: path, key: key}
	return h.workerCA
}

// workerCAYAML renders the workerCA block of the control plane's config.
func (h *H) workerCAYAML() string {
	if !h.wantWorkerCA {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\nworkerCA:\n  enabled: true\n  trustDomain: %s\n  certFile: %s\n  keySource: keys\n",
		WorkerCATrustDomain, h.workerCAFixture().chainPath)
	return b.String()
}

// WorkerCAKey is the intermediate key of WithWorkerCA, for a scenario to import
// through the key manager.
func (h *H) WorkerCAKey() *ecdsa.PrivateKey {
	h.tb.Helper()
	if !h.wantWorkerCA {
		h.tb.Fatal("harness: WorkerCAKey needs the WithWorkerCA option")
	}
	return h.workerCAFixture().key
}
