package harness

import (
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
)

// The signed-bundle gate (W-P2-SBND-02): the control plane boots with
// --bundles=offer on the versioned policy store and the signing keys, signs
// what it serves on GET /policy with its bundle key, and serves the envelope
// to a request with the bundle Accept header. The workers do not ask for it
// yet (worker pinning is W-P2-SBND-03/04), so they keep pulling the legacy
// wire; a scenario plays the pinned worker through CP().Send.

// WithBundles boots the control plane with --bundles=mode (controlplane.
// BundlesOffer; require would refuse the harness's own workers, which do not
// send the bundle Accept header yet), which needs the versioned policy store,
// a state dir and keys.enabled: the option turns those on. Combine it with
// WithKeyRotation to drive token key rotations on the harness clock.
// In-process only.
func WithBundles(mode string) Option {
	return func(h *H) {
		h.bundleMode = mode
		h.versionedPolicy = true
		h.wantKeys = true
	}
}

func (h *H) applyBundles(p *controlplane.Params) {
	if h.bundleMode != "" {
		p.Bundles = h.bundleMode
	}
}

// BundleMediaType is the Accept header value that asks for the envelope.
const BundleMediaType = controlplane.BundleMediaType

// FetchBundle GETs /policy from the control plane as a pinned worker would
// (Accept: the bundle media type, If-None-Match etag when not empty) and
// returns the raw reply.
func (c *CPClient) FetchBundle(etag string) CPResponse {
	c.h.tb.Helper()
	hdr := http.Header{"Accept": {BundleMediaType}}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	resp, err := c.Send(http.MethodGet, "/policy", hdr, nil)
	if err != nil {
		c.h.tb.Fatalf("harness: GET /policy as a bundle client: %v", err)
	}
	return resp
}

// HoldBundle parks a long-poll GET /policy?wait=30s for the envelope behind
// etag and returns the channel its reply arrives on.
func (c *CPClient) HoldBundle(etag string) <-chan RawResponse {
	return c.HoldWorker(http.MethodGet, "/policy?wait=30s", c.token, http.Header{
		"Accept":        {BundleMediaType},
		"If-None-Match": {etag},
	})
}

// VerifyBundle verifies raw against the control plane's bundle public keys (the
// pin set a worker would be configured with) at the harness clock, with
// applied as the worker's state, and fails the test on a rejection.
func (h *H) VerifyBundle(raw []byte, applied bundle.State) bundle.Verified {
	h.tb.Helper()
	pins := h.KeyManager().KeySet().JWKS(keys.PurposeBundle).Keys
	v, err := bundle.Verify(raw, pins, applied, bundle.Options{Now: h.fake.Now(), Skew: 5 * time.Minute})
	if err != nil {
		h.tb.Fatalf("harness: the served bundle does not verify: %v", err)
	}
	return v
}
