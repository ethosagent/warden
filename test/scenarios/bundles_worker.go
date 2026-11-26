package scenarios

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/test/harness"
)

// The pinned worker (W-P2-SBND-04). A worker with controlPlane.bundleKeys asks
// for the signed envelope and applies only a bundle that verifies: it enforces
// what the control plane signs, keeps enforcing it when the control plane
// goes away, never falls back to the unsigned wire (a pin that does not match
// the signer leaves it fail-closed, however good the legacy wire is), and with
// bundleExpiry=deny stops all traffic once the bundle it holds has expired
// and resumes when a valid one arrives.

func pinnedWorkerOpts(extra ...harness.Option) []harness.Option {
	return append([]harness.Option{
		harness.WithBundles(controlplane.BundlesOffer),
		harness.WithBundlePins(),
	}, extra...)
}

func pinnedWorkerEnforcesOpts() []harness.Option { return pinnedWorkerOpts() }

func pinnedWorkerDenyOpts() []harness.Option {
	return pinnedWorkerOpts(harness.WithBundleExpiry(config.BundleExpiryDeny))
}

func unrelatedPinsOpts() []harness.Option {
	return []harness.Option{harness.WithBundles(controlplane.BundlesOffer), harness.WithUnrelatedBundlePins()}
}

// saveAllowing adds host to the allowlist through the dashboard policy API
// (If-Match ifMatch), as an operator would.
func saveAllowing(t *testing.T, h *harness.H, host, ifMatch string) {
	t.Helper()
	cp := h.CP()
	get, err := cp.Send(http.MethodGet, "/dashboard/api/policy", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := json.Unmarshal(get.Body, &cur); err != nil {
		t.Fatal(err)
	}
	edit, err := json.Marshal(map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": host}),
		"denylist":  cur.Denylist,
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err := cp.Send(http.MethodPost, "/dashboard/api/policy", http.Header{"If-Match": {ifMatch}}, edit)
	if err != nil || r.Status != http.StatusOK {
		t.Fatalf("policy save = %d %s %v", r.Status, r.Body, err)
	}
}

// pinnedWorkerEnforces: the worker applies the bundle it verified, follows a
// policy save through a new bundle, and keeps the last verified policy when
// the control plane is gone.
func pinnedWorkerEnforces(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	h.Eventually("the worker applies a verified bundle", func() bool {
		return strings.Contains(h.Logs(), "bundle applied") && connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
	if connectStatus(t, h, rollbackHost+":443") != http.StatusForbidden {
		t.Fatal("a host outside the policy was reachable")
	}

	saveAllowing(t, h, rollbackHost, `"v1"`)
	h.Eventually("the worker enforces the next signed bundle", func() bool {
		return connectStatus(t, h, rollbackHost+":443") == http.StatusOK
	})

	// With the control plane gone the worker keeps enforcing what it verified.
	h.CP().Stop()
	h.Clock().Advance(time.Minute)
	if connectStatus(t, h, rollbackHost+":443") != http.StatusOK {
		t.Fatal("the worker dropped its last-known-good policy when the control plane went away")
	}
	h.CP().Start()
	if strings.Contains(h.Logs(), "bundle rejected") {
		t.Fatalf("a bundle the control plane signed was rejected:\n%s", h.Logs())
	}
}

// pinnedWorkerUnrelatedKeyFailsClosed: the control plane signs with a key the
// worker does not pin. The worker rejects every bundle and stays fail-closed,
// although the same control plane serves a perfectly good legacy wire.
func pinnedWorkerUnrelatedKeyFailsClosed(t *testing.T, h *harness.H) {
	legacy := h.CP().DoWorker(http.MethodGet, "/policy", h.CP().Token(), "", "")
	if legacy.Status != http.StatusOK || !strings.Contains(legacy.Body, "api.example.com") {
		t.Fatalf("legacy wire = %d %s", legacy.Status, legacy.Body)
	}
	h.Eventually("the worker rejects the bundle", func() bool {
		h.Clock().Advance(time.Second)
		logs := h.Logs()
		return strings.Contains(logs, "bundle rejected") && strings.Contains(logs, "unknown_kid")
	})
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT api.example.com = %d, want 403: the worker must not fall back to the unsigned wire", got)
	}
	if strings.Contains(h.Logs(), "bundle applied") {
		t.Fatal("a bundle was applied without a pinned signature")
	}
}

// pinnedWorkerExpiryDeny: bundleExpiry=deny. The control plane goes away, the
// bundle the worker holds expires, all traffic is denied, and a fresh bundle
// brings the policy back.
func pinnedWorkerExpiryDeny(t *testing.T, h *harness.H) {
	h.Eventually("the worker applies a verified bundle", func() bool {
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
	h.CP().Stop()
	h.Eventually("the expired bundle denies all traffic", func() bool {
		h.Clock().Advance(time.Hour) // the default bundle lifetime is 24h
		return connectStatus(t, h, "api.example.com:443") == http.StatusForbidden
	})
	if !strings.Contains(h.Logs(), "bundle expired") {
		t.Error("the worker did not log the expiry")
	}
	h.CP().Start()
	h.Eventually("a fresh bundle restores the policy", func() bool {
		h.Clock().Advance(5 * time.Second)
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
}

func tamperedOpts() []harness.Option {
	return pinnedWorkerOpts(harness.WithTamperingBundleProxy())
}

// pinnedWorkerTamperedBundleKeepsLastKnownGood: a path between the worker and
// the control plane flips a byte of the next bundle. The worker rejects it,
// keeps enforcing the previous policy (the new host stays blocked), does not
// re-download the bad bundle, and applies the next good one the control
// plane signs.
func pinnedWorkerTamperedBundleKeepsLastKnownGood(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	h.Eventually("the worker applies a verified bundle", func() bool {
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})

	h.TamperBundles(true)
	saveAllowing(t, h, rollbackHost, `"v1"`)
	h.Eventually("the worker rejects the tampered bundle", func() bool {
		h.Clock().Advance(time.Second)
		return h.TamperedBundles() > 0 && strings.Contains(h.Logs(), "bad_signature")
	})
	if connectStatus(t, h, rollbackHost+":443") != http.StatusForbidden {
		t.Fatal("the worker applied a tampered bundle")
	}
	if connectStatus(t, h, "api.example.com:443") != http.StatusOK {
		t.Fatal("the worker lost its last-known-good policy")
	}
	seen := h.TamperedBundles()
	for i := 0; i < 5; i++ {
		h.Clock().Advance(5 * time.Second)
	}
	if h.TamperedBundles() != seen {
		t.Fatalf("the rejected bundle was downloaded again (%d -> %d)", seen, h.TamperedBundles())
	}

	// The control plane re-signs on a timer; the next good bundle applies.
	h.TamperBundles(false)
	h.Eventually("the next good bundle is applied", func() bool {
		h.Clock().Advance(time.Hour)
		return connectStatus(t, h, rollbackHost+":443") == http.StatusOK
	})
}

// fleetWorker is the part of a /dashboard/api/workers row the bundle scenario
// reads.
type fleetWorker struct {
	ProxyID          string   `json:"proxyID"`
	Behind           bool     `json:"behind"`
	Caps             []string `json:"caps"`
	BundleSeq        int64    `json:"bundleSeq"`
	PinnedKIDs       []string `json:"pinnedKids"`
	LastRejectReason string   `json:"lastRejectReason"`
	BundleSeqAhead   bool     `json:"bundleSeqAhead"`
}

// pinnedWorkerFleetState (W-P2-SBND-05): the fleet view shows a pinned worker's
// bundle seq and its pins, and does not call it behind (its heartbeat ETag is
// the envelope's, which is never the legacy wire's ETag). A tampered bundle
// then shows as a rejection reason with the seq unchanged, the worker's
// warden_bundle_* metrics say the same, and the next good bundle clears it.
func pinnedWorkerFleetState(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	worker := func() (fleetWorker, bool) {
		var rows []fleetWorker
		if err := h.CP().GetJSON("/dashboard/api/workers", &rows); err != nil || len(rows) == 0 {
			return fleetWorker{}, false
		}
		return rows[0], true
	}
	var applied fleetWorker
	h.Eventually("the fleet view shows the pinned worker's bundle seq, not behind", func() bool {
		h.Clock().Advance(time.Second) // workers heartbeat on the fake clock
		w, ok := worker()
		applied = w
		return ok && w.BundleSeq > 0 && !w.Behind && w.LastRejectReason == ""
	})
	if !slices.Contains(applied.Caps, config.CapBundleV1) || len(applied.PinnedKIDs) == 0 || applied.BundleSeqAhead {
		t.Fatalf("pinned worker row = %+v, want cap bundle/v1, its pinned kids and not ahead", applied)
	}

	h.TamperBundles(true)
	saveAllowing(t, h, rollbackHost, `"v1"`)
	var rejected fleetWorker
	h.Eventually("the fleet view shows the rejection reason with the seq unchanged", func() bool {
		h.Clock().Advance(5 * time.Second)
		w, ok := worker()
		rejected = w
		return ok && w.LastRejectReason == "bad_signature"
	})
	if rejected.BundleSeq != applied.BundleSeq {
		t.Errorf("seq moved from %d to %d on a rejected bundle", applied.BundleSeq, rejected.BundleSeq)
	}
	if !rejected.Behind {
		t.Error("a worker that rejected the control plane's newest bundle is not shown behind")
	}
	if h.MetricsAvailable() {
		rej := harness.MetricKey("warden.bundle.rejected.total", map[string]string{"reason": "bad_signature"})
		h.Eventually("the rejection and the unchanged seq reach the worker's metrics", func() bool {
			h.Clock().Advance(5 * time.Second)
			m := h.Metrics()
			return m[rej] == 1 && m["warden.bundle.seq"] == float64(applied.BundleSeq)
		})
	}

	h.TamperBundles(false)
	h.Eventually("the next good bundle clears the rejection and the worker is current", func() bool {
		h.Clock().Advance(time.Hour)
		w, ok := worker()
		return ok && w.LastRejectReason == "" && w.BundleSeq > applied.BundleSeq && !w.Behind
	})
}
