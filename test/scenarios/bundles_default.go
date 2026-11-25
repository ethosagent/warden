package scenarios

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness"
)

// The Phase 2 gate flip (#719): a control plane started with --bundles unset and
// its prerequisites present resolves to require. The workers pin its keys, so
// they apply verified bundles, and a request without the bundle Accept header (a
// worker with no pins) is refused 406 signed_bundle_required, never served the
// unsigned policy.

func bundlesDefaultOpts() []harness.Option {
	return []harness.Option{
		harness.WithBundles(controlplane.BundlesDefault),
		harness.WithBundlePins(),
	}
}

func bundlesDefaultRequires(t *testing.T, h *harness.H) {
	h.Eventually("the control plane resolved --bundles to require", func() bool {
		return strings.Contains(h.Logs(), "control plane bundles mode") && strings.Contains(h.Logs(), `"mode":"require"`)
	})
	h.Eventually("the pinned worker applies a verified bundle", func() bool {
		return strings.Contains(h.Logs(), "bundle applied") && connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
	plain := h.CP().DoWorker(http.MethodGet, "/policy", h.CP().Token(), "", "")
	if plain.Status != http.StatusNotAcceptable || !strings.Contains(plain.Body, "signed_bundle_required") {
		t.Fatalf("GET /policy without the bundle Accept header = %d %s, want 406 signed_bundle_required", plain.Status, plain.Body)
	}
	if strings.Contains(plain.Body, "allowlist") {
		t.Error("the unsigned policy was served under the default")
	}
	if got := h.CP().FetchBundle(""); got.Status != http.StatusOK || got.Header.Get("Content-Type") != harness.BundleMediaType {
		t.Errorf("GET /policy as a bundle client = %d %q, want the envelope", got.Status, got.Header.Get("Content-Type"))
	}
	if strings.Contains(h.Logs(), "bundle rejected") {
		t.Errorf("a bundle the control plane signed was rejected:\n%s", h.Logs())
	}
}
