package harness

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// The signed-bundle gate (W-P2-SBND-02): the control plane boots with
// --bundles=offer on the versioned policy store and the signing keys, signs
// what it serves on GET /policy with its bundle key, and serves the envelope
// to a request with the bundle Accept header. Workers keep pulling the legacy
// wire unless WithBundlePins pins them (W-P2-SBND-04); a pinned worker applies
// only verified bundles. A scenario can also play a pinned worker through
// CP().Send.

// WithBundles boots the control plane with --bundles=mode (controlplane.
// BundlesOffer; require would refuse the harness's own workers unless
// WithBundlePins makes them send the bundle Accept header), which needs the versioned policy store,
// a state dir and keys.enabled: the option turns those on. Combine it with
// WithKeyRotation to drive token key rotations on the harness clock.
// In-process only.
func WithBundles(mode string) Option {
	return func(h *H) {
		h.bundleMode = mode
		h.bundleModeSet = true
		h.versionedPolicy = true
		h.wantKeys = true
	}
}

// applyBundles sets --bundles for the harness control plane. An unset
// controlplane.Params.Bundles now means require (the Phase 2 default), which
// would answer the harness's unpinned workers 406, so a harness without
// WithBundles opts out explicitly with off, as a test that is not about
// bundles should. WithBundles(BundlesDefault) boots the real default.
func (h *H) applyBundles(p *controlplane.Params) {
	if !h.bundleModeSet {
		p.Bundles = controlplane.BundlesOff
		return
	}
	p.Bundles = h.bundleMode
}

// bundlePinSet says which keys the workers pin.
type bundlePinSet int

const (
	pinNone bundlePinSet = iota
	pinControlPlane
	pinControlPlaneActive
	pinUnrelated
)

// WithBundlePins pins every worker to the control plane's bundle public keys
// (controlPlane.bundleKeys), so a worker asks for the signed envelope and
// applies nothing it cannot verify. Combine it with WithBundles. In-process only.
func WithBundlePins() Option { return func(h *H) { h.bundlePins = pinControlPlane } }

// WithActiveBundlePin pins every worker to the control plane's ACTIVE bundle key
// only, as a fleet does before a staged rotation (the next key is published but
// pinned nowhere). SetWorkerBundlePins then moves one worker's pins, effective
// when that worker restarts. Combine it with WithBundles. In-process only.
func WithActiveBundlePin() Option { return func(h *H) { h.bundlePins = pinControlPlaneActive } }

// SetWorkerBundlePins sets the bundle keys worker i (0-based, as RestartWorker)
// pins, by kid, from the control plane's signing_keys rows (any key it still
// holds a public key for: active, next or retired). It takes effect when the
// worker next starts, like an operator editing controlPlane.bundleKeysFile and
// restarting it; call RestartWorker(i) after. In-process only.
func (h *H) SetWorkerBundlePins(i int, kids ...string) {
	h.tb.Helper()
	h.pinsMu.Lock()
	defer h.pinsMu.Unlock()
	if h.workerPins == nil {
		h.workerPins = map[int][]string{}
	}
	h.workerPins[i+1] = append([]string(nil), kids...)
}

// WithUnrelatedBundlePins pins every worker to a key the control plane never
// signs with: every bundle it serves is rejected, and the worker must stay
// fail-closed instead of falling back to the unsigned wire. In-process only.
func WithUnrelatedBundlePins() Option { return func(h *H) { h.bundlePins = pinUnrelated } }

// WithBundleExpiry sets controlPlane.bundleExpiry for pinned workers (keep or
// deny; the default is keep).
func WithBundleExpiry(mode config.BundleExpiry) Option {
	return func(h *H) { h.bundleExpiry = mode }
}

// applyBundlePins fills the signed-bundle fields of worker i's (1-based) policy.
func (h *H) applyBundlePins(i int, p *config.Policy) {
	var pins []keys.JWK
	switch h.bundlePins {
	case pinNone:
		return
	case pinControlPlane:
		pins = h.KeyManager().KeySet().JWKS(keys.PurposeBundle).Keys
	case pinControlPlaneActive:
		for _, r := range h.KeyManager().KeySet().Records(keys.PurposeBundle) {
			if r.State == keys.StateActive {
				pins = append(pins, r.PublicJWK)
			}
		}
	case pinUnrelated:
		sg, err := signer.GenerateLocal(keys.AlgEdDSA)
		if err != nil {
			h.tb.Fatalf("harness: generate an unrelated bundle key: %v", err)
		}
		j, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
		if err != nil {
			h.tb.Fatalf("harness: unrelated bundle key JWK: %v", err)
		}
		pins = []keys.JWK{j}
	}
	h.pinsMu.Lock()
	kids, moved := h.workerPins[i]
	h.pinsMu.Unlock()
	if moved {
		pins = pins[:0:0]
		for _, kid := range kids {
			found := false
			for _, r := range h.KeyManager().KeySet().Records(keys.PurposeBundle) {
				if r.KID == kid {
					pins, found = append(pins, r.PublicJWK), true
				}
			}
			if !found {
				h.tb.Fatalf("harness: worker %d is to pin bundle key %s, which the control plane has no row for", i, kid)
			}
		}
	}
	p.ControlPlane.BundleKeys = pins
	p.ControlPlane.BundleClockSkew = 5 * time.Minute
	p.ControlPlane.BundleExpiry = h.bundleExpiry
}

// WithBundleCache turns on the last-known-good bundle cache for pinned workers
// (W-P2-SBND-06): each worker gets its own controlPlane.stateDir under the
// harness root, with bundleCacheMaxAge 12h. Combine it with WithBundlePins.
// In-process only.
func WithBundleCache() Option { return func(h *H) { h.bundleCache = true } }

// harnessBundleCacheMaxAge is the bundleCacheMaxAge of WithBundleCache.
const harnessBundleCacheMaxAge = 12 * time.Hour

// workerStateDir is the state dir of worker-n (1-based, as in its proxy id).
func (h *H) workerStateDir(n int) string {
	return filepath.Join(h.root, fmt.Sprintf("worker-%d-state", n))
}

// applyBundleCache gives worker i its state directory and cache max age.
func (h *H) applyBundleCache(i int, p *config.Policy) {
	if !h.bundleCache {
		return
	}
	p.ControlPlane.StateDir = h.workerStateDir(i)
	p.ControlPlane.BundleCacheMaxAge = harnessBundleCacheMaxAge
}

// BundleCacheFile is the path of worker i's (0-based) bundle cache file, which
// exists once the worker has applied a bundle. It needs WithBundleCache.
func (h *H) BundleCacheFile(i int) string {
	h.tb.Helper()
	if !h.bundleCache {
		h.tb.Fatal("harness: BundleCacheFile needs WithBundleCache")
	}
	return config.BundleCachePath(h.workerStateDir(i + 1))
}

// BundleCacheMaxAge is the bundleCacheMaxAge WithBundleCache configures.
func (h *H) BundleCacheMaxAge() time.Duration { return harnessBundleCacheMaxAge }

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

// tamperProxy is a TLS reverse proxy between the workers and the control plane
// that can flip one payload byte of every signed bundle it relays. It speaks
// for the control plane's ETags: a worker sends back the ETag of the bundle it
// rejected and the proxy answers as the control plane would (304 while the
// real envelope is unchanged).
type tamperProxy struct {
	addr     string
	on       atomic.Bool
	tampered atomic.Int64
}

const tamperedETagPrefix = "tampered-"

// WithTamperingBundleProxy puts a tampering proxy between the workers and the
// control plane (their controlPlane.endpoint points at it). Switch it with
// TamperBundles. In-process only.
func WithTamperingBundleProxy() Option {
	return func(h *H) { h.bundleTamper = &tamperProxy{} }
}

// TamperBundles turns bundle tampering on or off.
func (h *H) TamperBundles(on bool) {
	h.tb.Helper()
	if h.bundleTamper == nil {
		h.tb.Fatal("harness: TamperBundles needs WithTamperingBundleProxy")
	}
	h.bundleTamper.on.Store(on)
}

// TamperedBundles is how many bundles the proxy has tampered with.
func (h *H) TamperedBundles() int64 {
	if h.bundleTamper == nil {
		return 0
	}
	return h.bundleTamper.tampered.Load()
}

// workerCPAddr is the control plane address workers dial: the tampering proxy
// when there is one.
func (h *H) workerCPAddr() string {
	tp := h.bundleTamper
	if tp == nil {
		return h.ControlPlaneAddr()
	}
	if tp.addr != "" {
		return tp.addr
	}
	cert, err := h.proxyCA.leaf("127.0.0.1")
	if err != nil {
		h.tb.Fatalf("harness: tampering proxy cert: %v", err)
	}
	target, _ := url.Parse("https://" + h.ControlPlaneAddr())
	rp := &httputil.ReverseProxy{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: h.proxyCA.pool(), MinVersion: tls.VersionTLS12}},
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			if inm := r.In.Header.Get("If-None-Match"); strings.HasPrefix(inm, `"`+tamperedETagPrefix) {
				r.Out.Header.Set("If-None-Match", `"`+strings.TrimPrefix(inm, `"`+tamperedETagPrefix))
			}
		},
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		if !tp.on.Load() || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != BundleMediaType {
			return nil
		}
		raw, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		var env bundle.Envelope
		if err := json.Unmarshal(raw, &env); err != nil || len(env.Payload) == 0 {
			return fmt.Errorf("harness: tampering proxy: not an envelope")
		}
		p := []byte(env.Payload)
		p[len(p)/2] ^= 1
		env.Payload = string(p)
		raw, _ = json.Marshal(env)
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		resp.Header.Set("Content-Length", strconv.Itoa(len(raw)))
		resp.Header.Set("ETag", `"`+tamperedETagPrefix+strings.Trim(resp.Header.Get("ETag"), `"`)+`"`)
		tp.tampered.Add(1)
		return nil
	}
	srv := httptest.NewUnstartedServer(rp)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	h.tb.Cleanup(srv.Close)
	tp.addr = strings.TrimPrefix(srv.URL, "https://")
	return tp.addr
}
