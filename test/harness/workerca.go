package harness

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
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
	inter     *x509.Certificate
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
	h.workerCA = &workerCAFixture{chainPath: path, key: key, inter: inter}
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
	if !h.wantStrict {
		// An echo secret store mounts /central/secrets, which a scenario proves
		// a worker certificate never opens.
		b.WriteString("\nsecretStore:\n  backend: echo\n")
	}
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

// WorkerCAStateDir is the control plane's state dir under WithWorkerCA (it
// holds warden-cp.db, the audit keys and the key store).
func (h *H) WorkerCAStateDir() string {
	h.tb.Helper()
	if !h.wantWorkerCA {
		h.tb.Fatal("harness: WorkerCAStateDir needs the WithWorkerCA option")
	}
	return filepath.Join(h.root, "cp-state")
}

// CreateEnrollToken mints a wet_ token the way `warden control-plane
// enroll-token create` does: straight on the running control plane's state
// database through the offline opener, audited as cli when admin audit is on.
// The control plane picks it up within about 2 seconds (its data_version
// poll, which runs on the harness clock). Give workerID or prefix.
func (h *H) CreateEnrollToken(workerID, prefix string, maxUses int, ttl time.Duration) string {
	h.tb.Helper()
	ctx := context.Background()
	o, err := controlplane.OpenEnrollTokensOffline(ctx, h.WorkerCAStateDir(), "", 0, 0)
	if err != nil {
		h.tb.Fatalf("harness: open the enrollment tokens: %v", err)
	}
	defer func() { _ = o.Close() }()
	res, err := o.Create(ctx, controlplane.OfflineEnrollCreate{WorkerID: workerID, WorkerIDPrefix: prefix, MaxUses: maxUses, ExpiresIn: ttl})
	if err != nil {
		h.tb.Fatalf("harness: create an enrollment token: %v", err)
	}
	return res.Plaintext
}

// Enroll posts to /control/enroll the way a worker's enroller does: no
// credential at all, a JSON body with the token, the CSR (PEM) and the
// optional suffix.
func (c *CPClient) Enroll(token, csrPEM, suffix string) (int, string) {
	c.h.tb.Helper()
	body, err := json.Marshal(map[string]string{"token": token, "csr": csrPEM, "workerIdSuffix": suffix})
	if err != nil {
		c.h.tb.Fatalf("harness: encode the enroll request: %v", err)
	}
	status, resp, err := c.Do(http.MethodPost, "/control/enroll", "", body)
	if err != nil {
		c.h.tb.Fatalf("harness: POST /control/enroll: %v", err)
	}
	return status, resp
}
