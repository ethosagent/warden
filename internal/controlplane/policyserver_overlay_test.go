package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// overlayFixture copies the golden fixture config into a temp dir so a test can
// rewrite it without touching testdata.
func overlayFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// servePolicyOnce runs one plain (no wait) GET /policy against ps.
func servePolicyOnce(t *testing.T, ps *policyServer) (body []byte, etag string) {
	t.Helper()
	rec := httptest.NewRecorder()
	ps.ServePolicy(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /policy = %d %s", rec.Code, rec.Body.String())
	}
	b, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b, rec.Header().Get("ETag")
}

// appendAllow returns an overlay that appends domain to the allowlist and
// reports fp as its fingerprint.
func appendAllow(name, domain, fp string) wireOverlay {
	return wireOverlay{name: name, apply: func(_ context.Context, w *policyWire) (string, error) {
		w.Allowlist = append(w.Allowlist, config.AllowlistEntry{Domain: domain})
		return fp, nil
	}}
}

func allowDomains(t *testing.T, body []byte) []string {
	t.Helper()
	var wire policyWire
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(wire.Allowlist))
	for _, e := range wire.Allowlist {
		out = append(out, e.Domain)
	}
	return out
}

// TestPolicyOverlayNoneIsByteIdentical pins /policy with no overlay registered
// to a golden body and ETag captured on main before the overlay seam existed.
func TestPolicyOverlayNoneIsByteIdentical(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}

	srv := New(Config{PolicyPath: filepath.Join("testdata", "policy_overlay_none.yaml")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	gotBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBody, wantBody) {
		t.Errorf("/policy body differs from golden\n got: %s\nwant: %s", gotBody, wantBody)
	}
	if got, want := resp.Header.Get("ETag"), strings.TrimSpace(string(wantETag)); got != want {
		t.Errorf("/policy ETag = %s, want golden %s", got, want)
	}
	if fps := srv.policy.overlayFingerprints(); len(fps) != 0 {
		t.Errorf("overlayFingerprints with no overlay = %v, want empty", fps)
	}
}

// TestPolicyOverlayOrder: overlays run in registration order on the base wire
// and a later overlay sees what an earlier one changed.
func TestPolicyOverlayOrder(t *testing.T) {
	ps := newPolicyServer(overlayFixture(t), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	if err := ps.addOverlay(appendAllow("first", "first.example", "f1")); err != nil {
		t.Fatal(err)
	}
	sawFirst := false
	if err := ps.addOverlay(wireOverlay{name: "second", apply: func(_ context.Context, w *policyWire) (string, error) {
		for _, e := range w.Allowlist {
			if e.Domain == "first.example" {
				sawFirst = true
			}
		}
		w.Allowlist = append(w.Allowlist, config.AllowlistEntry{Domain: "second.example"})
		return "", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()

	body, _ := servePolicyOnce(t, ps)
	got := allowDomains(t, body)
	want := []string{"api.openai.com", "api.anthropic.com", "first.example", "second.example"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("served allowlist = %v, want %v", got, want)
	}
	if !sawFirst {
		t.Error("second overlay did not see the first overlay's change")
	}
}

// TestPolicyOverlayFingerprints: overlayFingerprints returns every overlay's
// fingerprint from the last successful load, "" included, and is a copy.
func TestPolicyOverlayFingerprints(t *testing.T) {
	ps := newPolicyServer(overlayFixture(t), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	var fp atomic.Value
	fp.Store("v1")
	if err := ps.addOverlay(wireOverlay{name: "credential", apply: func(context.Context, *policyWire) (string, error) {
		return fp.Load().(string), nil
	}}); err != nil {
		t.Fatal(err)
	}
	if err := ps.addOverlay(appendAllow("empty", "x.example", "")); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()

	got := ps.overlayFingerprints()
	if len(got) != 2 || got["credential"] != "v1" {
		t.Fatalf("overlayFingerprints = %v, want credential=v1 and empty=\"\"", got)
	}
	if v, ok := got["empty"]; !ok || v != "" {
		t.Fatalf("overlayFingerprints[empty] = %q, %v; want \"\", true", v, ok)
	}
	got["credential"] = "mutated"
	if ps.overlayFingerprints()["credential"] != "v1" {
		t.Fatal("overlayFingerprints returned the stored map, not a copy")
	}

	// A fingerprint-only change (wire and ETag unchanged) is still recorded,
	// without waking long-poll waiters.
	_, etag, _, ch := ps.snapshot()
	fp.Store("v2")
	ps.Refresh()
	if got := ps.overlayFingerprints()["credential"]; got != "v2" {
		t.Errorf("fingerprint after reload = %q, want v2", got)
	}
	if _, etag2, _, _ := ps.snapshot(); etag2 != etag {
		t.Errorf("ETag changed on a fingerprint-only change: %s -> %s", etag, etag2)
	}
	select {
	case <-ch:
		t.Error("long-poll waiters woken on a fingerprint-only change")
	default:
	}
}

// TestPolicyOverlayErrorKeepsLastGood: an overlay error fails the load, so the
// served body, ETag and fingerprints stay last-known-good, waiters are not
// woken, and the log names the overlay with a bounded error and no wire content.
func TestPolicyOverlayErrorKeepsLastGood(t *testing.T) {
	path := overlayFixture(t)
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	ps := newPolicyServer(path, "", logger, NewWorkerRegistry())
	var fail atomic.Bool
	if err := ps.addOverlay(appendAllow("ok", "ok.example", "fp-ok")); err != nil {
		t.Fatal(err)
	}
	if err := ps.addOverlay(wireOverlay{name: "flaky", apply: func(context.Context, *policyWire) (string, error) {
		if fail.Load() {
			return "", errors.New("backend down: " + strings.Repeat("x", 4096))
		}
		return "fp-flaky", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()
	goodBody, goodETag := servePolicyOnce(t, ps)
	_, _, _, ch := ps.snapshot()

	// Change the base policy so a successful load would change the ETag.
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := strings.Replace(string(b), "evil.example.com", "changed.example.com", 1)
	if err := os.WriteFile(path, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	ps.Refresh()

	body, etag := servePolicyOnce(t, ps)
	if etag != goodETag || !bytes.Equal(body, goodBody) {
		t.Errorf("overlay error changed the served policy: etag %s -> %s", goodETag, etag)
	}
	select {
	case <-ch:
		t.Error("long-poll waiters woken by a failed load")
	default:
	}
	if fps := ps.overlayFingerprints(); fps["ok"] != "fp-ok" || fps["flaky"] != "fp-flaky" {
		t.Errorf("fingerprints after failed load = %v, want last good", fps)
	}

	out := logs.String()
	if !strings.Contains(out, "overlay=flaky") {
		t.Errorf("log does not name the failing overlay:\n%s", out)
	}
	if strings.Contains(out, strings.Repeat("x", maxOverlayErrLen+1)) {
		t.Error("overlay error logged unbounded")
	}
	for _, leak := range []string{"api.openai.com", "changed.example.com", "ok.example", "be careful"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaks wire content %q:\n%s", leak, out)
		}
	}

	// Recovery: once the overlay succeeds again the new policy is served.
	fail.Store(false)
	ps.Refresh()
	if _, etag := servePolicyOnce(t, ps); etag == goodETag {
		t.Error("policy not reloaded after the overlay recovered")
	}
	select {
	case <-ch:
	default:
		t.Error("waiters not woken after recovery")
	}
}

// TestPolicyOverlayNotRunPerRequest: overlays run on Refresh only, never on a
// /policy request.
func TestPolicyOverlayNotRunPerRequest(t *testing.T) {
	ps := newPolicyServer(overlayFixture(t), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	var calls atomic.Int64
	if err := ps.addOverlay(wireOverlay{name: "count", apply: func(context.Context, *policyWire) (string, error) {
		calls.Add(1)
		return "", nil
	}}); err != nil {
		t.Fatal(err)
	}
	ps.Refresh()
	if calls.Load() != 1 {
		t.Fatalf("overlay calls after one Refresh = %d, want 1", calls.Load())
	}
	for range 5 {
		servePolicyOnce(t, ps)
	}
	if calls.Load() != 1 {
		t.Errorf("overlay ran on /policy requests: calls = %d, want 1", calls.Load())
	}
}

// TestPolicyOverlayRejectsDuplicate: an empty or duplicate name, a nil apply,
// and any registration after the first Refresh or ServePolicy are errors.
func TestPolicyOverlayRejectsDuplicate(t *testing.T) {
	noop := func(context.Context, *policyWire) (string, error) { return "", nil }
	newPS := func() *policyServer {
		return newPolicyServer(overlayFixture(t), "", slog.New(slog.DiscardHandler), NewWorkerRegistry())
	}

	ps := newPS()
	if err := ps.addOverlay(wireOverlay{name: "", apply: noop}); err == nil {
		t.Error("empty overlay name accepted")
	}
	if err := ps.addOverlay(wireOverlay{name: "nilapply"}); err == nil {
		t.Error("overlay with nil apply accepted")
	}
	if err := ps.addOverlay(wireOverlay{name: "credential", apply: noop}); err != nil {
		t.Fatal(err)
	}
	if err := ps.addOverlay(wireOverlay{name: "credential", apply: noop}); err == nil {
		t.Error("duplicate overlay name accepted")
	}

	ps.Refresh()
	if err := ps.addOverlay(wireOverlay{name: "late", apply: noop}); err == nil {
		t.Error("overlay registered after the first Refresh")
	}

	ps2 := newPS()
	rec := httptest.NewRecorder()
	ps2.ServePolicy(rec, httptest.NewRequest(http.MethodGet, "/policy", nil))
	if err := ps2.addOverlay(wireOverlay{name: "late", apply: noop}); err == nil {
		t.Error("overlay registered after the first ServePolicy")
	}
}
