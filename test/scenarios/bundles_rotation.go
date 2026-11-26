package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// Staged bundle key rotation (W-P2-SBND-07): the fleet pins the bundle key out
// of band, so the key moves in steps — pin the next key, stage (the control
// plane signs with both), activate (the next key signs alone, behind the
// workers' reported pins), drop the old pin. The scenario runs the whole cycle
// against two workers and proves no step made either of them reject a bundle,
// that a worker restarted mid-rotation still verifies its cache under the pins
// it holds, and that the activate gate is real.

func bundleKeyRotationOpts() []harness.Option {
	return []harness.Option{
		harness.Fleet(2),
		harness.WithBundles(controlplane.BundlesOffer),
		harness.WithActiveBundlePin(),
		harness.WithBundleCache(),
	}
}

// bundleKIDs returns the control plane's active and next bundle kids.
func bundleKIDs(h *harness.H) (active, next string) {
	got := keyKIDs(h.KeyRows())
	return got["bundle/active"], got["bundle/next"]
}

func fleetRows(t *testing.T, h *harness.H) []dashboard.WorkerView {
	t.Helper()
	var rows []dashboard.WorkerView
	if err := h.CP().GetJSON("/dashboard/api/workers", &rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// awaitFleet waits until cond holds for the fleet view. Workers heartbeat on
// the fake clock, so each poll advances it one second.
func awaitFleet(t *testing.T, h *harness.H, desc string, cond func(rows []dashboard.WorkerView) bool) []dashboard.WorkerView {
	t.Helper()
	var rows []dashboard.WorkerView
	h.Eventually(desc, func() bool {
		h.Clock().Advance(time.Second)
		var cur []dashboard.WorkerView
		if err := h.CP().GetJSON("/dashboard/api/workers", &cur); err != nil {
			return false
		}
		rows = cur
		return cond(cur)
	})
	return rows
}

// workersApplied is true when every worker named in pins is online, has applied
// a bundle, reports exactly those pinned kids and has no rejection since.
func workersApplied(rows []dashboard.WorkerView, pins map[string][]string) bool {
	seen := 0
	for _, w := range rows {
		want, ok := pins[w.ProxyID]
		if !ok {
			continue
		}
		if !w.Online || w.BundleSeq == 0 || w.LastRejectReason != "" || !slices.Equal(sortedCopy(w.PinnedKIDs), sortedCopy(want)) {
			return false
		}
		seen++
	}
	return seen == len(pins)
}

func sortedCopy(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// envelopeSignatureKIDs fetches the envelope the control plane serves and
// returns the kids that signed it.
func envelopeSignatureKIDs(t *testing.T, raw []byte) []string {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("not an envelope: %v", err)
	}
	var out []string
	for _, s := range env.Signatures {
		out = append(out, s.KID)
	}
	return out
}

// awaitSigners drives the clock until the control plane serves an envelope
// signed by exactly want (the data-version poll that carries the keys CLI's
// write into the running control plane fires on the fake clock).
func awaitSigners(t *testing.T, h *harness.H, desc string, want ...string) {
	t.Helper()
	h.Eventually(desc, func() bool {
		h.Clock().Advance(2 * time.Second)
		r := h.CP().FetchBundle("")
		return r.Status == http.StatusOK && slices.Equal(envelopeSignatureKIDs(t, r.Body), want)
	})
}

// cacheSigners reads worker i's cache file and returns the kids of the
// signatures it kept.
func cacheSigners(t *testing.T, h *harness.H, i int) []string {
	t.Helper()
	raw, err := os.ReadFile(h.BundleCacheFile(i))
	if err != nil {
		return nil
	}
	return envelopeSignatureKIDs(t, raw)
}

func restartPinned(h *harness.H, i int, kids ...string) {
	h.SetWorkerBundlePins(i, kids...)
	h.RestartWorker(i)
}

// rejectedBundles is the sum of the workers' warden_bundle_rejected_total.
func rejectedBundles(h *harness.H) float64 {
	var n float64
	for k, v := range h.Metrics() {
		if strings.HasPrefix(k, "warden.bundle.rejected.total") {
			n += v
		}
	}
	return n
}

func bundleKeyRotationStaged(t *testing.T, h *harness.H) {
	ctx := context.Background()
	h.Upstream(rollbackHost)
	oldKID, nextKID := bundleKIDs(h)
	if oldKID == "" || nextKID == "" {
		t.Fatalf("bundle keys = %q %q", oldKID, nextKID)
	}
	w1, w2 := "worker-1", "worker-2"

	// The fleet pins the active key only, and both workers enforce what it signs.
	awaitFleet(t, h, "both workers apply a bundle pinned to the old key alone", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID}, w2: {oldKID}})
	})
	// The gate is real: neither worker reports the next key yet.
	if r := controlplane.CheckBundlePins(fleetRows(t, h), nextKID); !slices.Equal(r.Missing, []string{w1, w2}) {
		t.Fatalf("pin gate before pinning = %+v, want both workers missing", r)
	}

	o, err := controlplane.OpenKeysOffline(ctx, h.KeyStateDir(), controlplane.KeysCLIOptions{Clock: h.Clock()})
	if err != nil {
		t.Fatalf("open the keys CLI: %v", err)
	}
	defer func() { _ = o.Close() }()
	workers := func(ctx context.Context) ([]dashboard.WorkerView, error) {
		var rows []dashboard.WorkerView
		return rows, h.CP().GetJSON("/dashboard/api/workers", &rows)
	}
	if _, err := o.ActivateBundle(ctx, controlplane.ActivateBundleOptions{Workers: workers}); err == nil {
		t.Fatal("activation before the stage succeeded")
	}

	// Stage: the control plane signs with both keys; staging changed nothing a
	// worker pinned to the old key can see.
	if st, err := o.StageBundle(ctx); err != nil || st.NextKID != nextKID || st.Already {
		t.Fatalf("stage = %+v, %v", st, err)
	}
	awaitSigners(t, h, "the control plane signs with both keys", oldKID, nextKID)
	awaitFleet(t, h, "the old-pin workers keep applying", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID}, w2: {oldKID}})
	})

	// One worker pins only the old key, the other only the new one: both accept
	// the dual-signed envelope.
	restartPinned(h, 0, oldKID)
	restartPinned(h, 1, nextKID)
	awaitFleet(t, h, "an old-only and a new-only worker both accept the dual-signed bundle", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID}, w2: {nextKID}})
	})
	for _, i := range []int{0, 1} {
		if got := connectStatusAt(h, i, "api.example.com:443"); got != http.StatusOK {
			t.Fatalf("worker %d CONNECT = %d, want 200 from the dual-signed bundle", i+1, got)
		}
	}
	// The cache keeps every signature, so either pin verifies it after a restart.
	h.Eventually("both workers cache the dual-signed envelope whole", func() bool {
		h.Clock().Advance(time.Second)
		return slices.Equal(cacheSigners(t, h, 0), []string{oldKID, nextKID}) && slices.Equal(cacheSigners(t, h, 1), []string{oldKID, nextKID})
	})

	// Mid-rotation, with the control plane down, both restart from their caches
	// under the pins they hold: the old-pin worker by the old signature, the
	// new-pin worker by the new one.
	h.CP().Stop()
	h.RestartWorker(0)
	h.RestartWorker(1)
	for _, i := range []int{0, 1} {
		if got := connectStatusAt(h, i, "api.example.com:443"); got != http.StatusOK {
			t.Fatalf("worker %d restarted mid-rotation with the control plane down: CONNECT = %d, want 200 from its cache", i+1, got)
		}
	}
	h.CP().Start()
	// The stage is in the database, so the restarted control plane signs with
	// both keys again.
	awaitSigners(t, h, "the restarted control plane still signs with both keys", oldKID, nextKID)

	// The gate: the old-pin worker does not report the next key.
	awaitFleet(t, h, "both workers report their pins again", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID}, w2: {nextKID}})
	})
	rows := fleetRows(t, h)
	var gate *controlplane.PinGateError
	if _, err := o.ActivateBundle(ctx, controlplane.ActivateBundleOptions{Workers: workers}); !errors.As(err, &gate) || !slices.Equal(gate.Missing, []string{w1}) {
		t.Fatalf("activation with %s still pinned to the old key alone = %v (fleet %+v), want a refusal naming it", w1, err, rows)
	}
	if a, n := bundleKIDs(h); a != oldKID || n != nextKID {
		t.Fatalf("the refused activation moved the keys: %s %s", a, n)
	}

	// Pin both keys on worker-1, then let the prepublish window pass.
	restartPinned(h, 0, oldKID, nextKID)
	awaitFleet(t, h, "every worker reports the next key", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID, nextKID}, w2: {nextKID}})
	})
	h.Clock().Advance(time.Hour + time.Minute)
	awaitFleet(t, h, "the workers are online again after the wait", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {oldKID, nextKID}, w2: {nextKID}})
	})
	res, err := o.ActivateBundle(ctx, controlplane.ActivateBundleOptions{Workers: workers})
	if err != nil || res.Forced || res.KID != nextKID || res.Previous != oldKID {
		t.Fatalf("activation = %+v, %v", res, err)
	}
	awaitSigners(t, h, "the control plane signs with the new key alone", nextKID)

	// A policy change under the new key alone reaches both workers: the one
	// pinned to both and the one pinned to the new key.
	saveAllowing(t, h, rollbackHost, `"v1"`)
	h.Eventually("both workers enforce a bundle only the new key signed", func() bool {
		h.Clock().Advance(time.Second)
		return connectStatusAt(h, 0, rollbackHost+":443") == http.StatusOK && connectStatusAt(h, 1, rollbackHost+":443") == http.StatusOK
	})

	// Drop the old pin: the worker keeps enforcing, and the retired key is no
	// longer one it trusts.
	restartPinned(h, 0, nextKID)
	awaitFleet(t, h, "the worker applies under the new pin alone", func(rows []dashboard.WorkerView) bool {
		return workersApplied(rows, map[string][]string{w1: {nextKID}, w2: {nextKID}})
	})
	if got := connectStatusAt(h, 0, rollbackHost+":443"); got != http.StatusOK {
		t.Fatalf("worker-1 under the new pin alone: CONNECT = %d, want 200", got)
	}
	if signers := keys.PublishedJWKS(h.KeyManager().KeySet().Records(keys.PurposeBundle), h.Clock().Now(), 0); len(signers.Keys) == 0 {
		t.Fatal("no bundle key published after the rotation")
	}

	// The whole cycle rejected nothing. The log scan is the oracle for the whole
	// cycle: RestartWorker starts a fresh metric reader, so the counter below only
	// covers the workers' current runs.
	if logs := h.Logs(); strings.Contains(logs, "bundle rejected") {
		t.Fatalf("a bundle was rejected during the staged rotation:\n%s", logs)
	}
	if h.MetricsAvailable() {
		if n := rejectedBundles(h); n != 0 {
			t.Errorf("warden_bundle_rejected_total = %v after the cycle, want 0", n)
		}
	}
}
