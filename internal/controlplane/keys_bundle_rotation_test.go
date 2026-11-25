package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
)

func bundleKIDs(t *testing.T, o *OfflineKeys) (active, next string) {
	t.Helper()
	rows, err := o.Rows(context.Background(), keys.PurposeBundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		switch r.State {
		case keys.StateActive:
			active = r.KID
		case keys.StateNext:
			next = r.KID
		}
	}
	return active, next
}

func pinnedFleet(next string, pinned ...string) WorkersSource {
	ws := make([]dashboard.WorkerView, 0, len(pinned))
	for _, id := range pinned {
		ws = append(ws, dashboard.WorkerView{ProxyID: id, Online: true, Caps: []string{config.CapBundleV1}, PinnedKIDs: []string{next}})
	}
	return func(context.Context) ([]dashboard.WorkerView, error) { return ws, nil }
}

// TestCheckBundlePins: only an online worker that verifies bundles and does
// not report the kid blocks; the pins a worker reports past the heartbeat cap
// are not seen, so a kid beyond it reads as missing.
func TestCheckBundlePins(t *testing.T) {
	cap := []string{config.CapBundleV1}
	ws := []dashboard.WorkerView{
		{ProxyID: "ok", Online: true, Caps: cap, PinnedKIDs: []string{"a", "n"}},
		{ProxyID: "b-missing", Online: true, Caps: cap, PinnedKIDs: []string{"a"}},
		{ProxyID: "a-missing", Online: true, Caps: cap},
		{ProxyID: "legacy", Online: true},
		{ProxyID: "off-missing", Online: false, Caps: cap, PinnedKIDs: []string{"a"}},
		{ProxyID: "off-ok", Online: false, Caps: cap, PinnedKIDs: []string{"n"}},
		{ProxyID: "off-legacy", Online: false},
	}
	got := CheckBundlePins(ws, "n")
	if strings.Join(got.Missing, ",") != "a-missing,b-missing" || got.Checked != 3 {
		t.Errorf("missing = %v checked %d, want a-missing and b-missing of 3 checked", got.Missing, got.Checked)
	}
	if strings.Join(got.Offline, ",") != "off-missing" || strings.Join(got.Unpinned, ",") != "legacy" {
		t.Errorf("offline = %v unpinned = %v", got.Offline, got.Unpinned)
	}
	if r := CheckBundlePins(nil, "n"); len(r.Missing) != 0 || r.Checked != 0 {
		t.Errorf("an empty fleet blocked: %+v", r)
	}
}

// TestOfflineBundleRotation: stage, then activate behind the pin gate, on the
// offline handle the CLI uses.
func TestOfflineBundleRotation(t *testing.T) {
	ctx := context.Background()
	stateDir := openKeysStateDir(t)
	o, err := OpenKeysOffline(ctx, stateDir, KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	old, next := bundleKIDs(t, o)

	// Activating before the stage is refused, whatever the pins say.
	if _, err := o.ActivateBundle(ctx, ActivateBundleOptions{Workers: pinnedFleet(next, "w1")}); !errors.Is(err, keys.ErrNotStaged) {
		t.Fatalf("unstaged activation = %v, want ErrNotStaged", err)
	}
	st, err := o.StageBundle(ctx)
	if err != nil || st.ActiveKID != old || st.NextKID != next || st.Already {
		t.Fatalf("stage = %+v, %v", st, err)
	}
	backdateNextPublish(t, stateDir, keys.PurposeBundle)

	// A worker missing the kid blocks; unreadable pins block; neither changed
	// a row.
	var gate *PinGateError
	_, err = o.ActivateBundle(ctx, ActivateBundleOptions{Workers: func(context.Context) ([]dashboard.WorkerView, error) {
		return []dashboard.WorkerView{{ProxyID: "w9", Online: true, Caps: []string{config.CapBundleV1}, PinnedKIDs: []string{old}}}, nil
	}})
	if !errors.As(err, &gate) || len(gate.Missing) != 1 || gate.Missing[0] != "w9" || gate.NextKID != next {
		t.Fatalf("gate refusal = %v, want w9 missing %s", err, next)
	}
	_, err = o.ActivateBundle(ctx, ActivateBundleOptions{})
	if !errors.As(err, &gate) || len(gate.Missing) != 0 || gate.Cause == nil {
		t.Fatalf("unreadable pins = %v, want a refusal with a cause", err)
	}
	if a, n := bundleKIDs(t, o); a != old || n != next {
		t.Fatalf("a refused activation moved the keys: %s %s", a, n)
	}

	res, err := o.ActivateBundle(ctx, ActivateBundleOptions{Workers: pinnedFleet(next, "w1", "w2")})
	if err != nil || res.KID != next || res.Previous != old || res.Forced {
		t.Fatalf("activation = %+v, %v", res, err)
	}
	if a, _ := bundleKIDs(t, o); a != next {
		t.Errorf("active = %s, want %s", a, next)
	}
}

// TestOfflineBundleEmergencyActivation: a compromise promotes the next key at
// once with no stage and no prepublish wait; the pin gate still applies.
func TestOfflineBundleEmergencyActivation(t *testing.T) {
	ctx := context.Background()
	o, err := OpenKeysOffline(ctx, openKeysStateDir(t), KeysCLIOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = o.Close() }()
	old, next := bundleKIDs(t, o)
	var gate *PinGateError
	if _, err := o.ActivateBundle(ctx, ActivateBundleOptions{Emergency: true, Workers: pinnedFleet(old, "w1")}); !errors.As(err, &gate) {
		t.Fatalf("emergency activation with an unpinned worker = %v, want the pin gate", err)
	}
	res, err := o.ActivateBundle(ctx, ActivateBundleOptions{Emergency: true, Workers: pinnedFleet(next, "w1")})
	if err != nil || !res.Emergency || res.KID != next {
		t.Fatalf("emergency activation = %+v, %v", res, err)
	}
	set, err := o.JWKS(ctx, keys.PurposeBundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range set.Keys {
		if k.Kid == old {
			t.Errorf("the revoked key %s is still in the exported pin set", old)
		}
	}
}

// TestAdminAPIWorkers: the gate reads the fleet with the key as a bearer and
// never lets the key into an error.
func TestAdminAPIWorkers(t *testing.T) {
	const key = "wak_unit_test_key"
	var gotAuth, gotPath string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		if r.Header.Get("Authorization") != "Bearer "+key {
			http.Error(w, "no", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode([]dashboard.WorkerView{{ProxyID: "w1", Online: true}})
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	src, err := AdminAPIWorkers(srv.URL+"/", key, ca)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := src(context.Background())
	if err != nil || len(ws) != 1 || ws[0].ProxyID != "w1" {
		t.Fatalf("workers = %v, %v", ws, err)
	}
	if gotAuth != "Bearer "+key || gotPath != "/dashboard/api/workers" {
		t.Errorf("request = %q %q", gotAuth, gotPath)
	}

	bad, _ := AdminAPIWorkers(srv.URL, "wak_wrong_key", ca)
	if _, err := bad(context.Background()); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "wak_wrong_key") {
		t.Errorf("a rejected key = %v, want a 403 error without the key", err)
	}
	// Without the CA the self-signed server is not trusted.
	untrusted, _ := AdminAPIWorkers(srv.URL, key, "")
	if _, err := untrusted(context.Background()); err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("untrusted server = %v, want a TLS error without the key", err)
	}
	if _, err := AdminAPIWorkers("", key, ""); err == nil {
		t.Error("an empty URL was accepted")
	}
	if _, err := AdminAPIWorkers(srv.URL, key, filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a missing CA file was accepted")
	}
	junk := filepath.Join(t.TempDir(), "junk.pem")
	_ = os.WriteFile(junk, []byte("not pem"), 0o600)
	if _, err := AdminAPIWorkers(srv.URL, key, junk); err == nil {
		t.Error("a CA file without a certificate was accepted")
	}
}
