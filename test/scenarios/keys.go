package scenarios

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// The signing-key gate (W-P2-KEYS-02): with keys.enabled the control plane
// creates an active and a next key per purpose, a restart keeps them, and a
// key store that is down never takes the control plane with it. The rotation
// gate (W-P2-KEYS-03): a token key past its interval is retired and replaced
// by the prepublished next key without a verify gap, and a restart after a
// downtime catches up on the missed rotation. Workers keep pulling policy
// throughout: keys are CP-local.

func keysOpts() []harness.Option { return []harness.Option{harness.WithKeys()} }

func keysFlakyOpts() []harness.Option { return []harness.Option{harness.WithFlakyKeyStore()} }

// keysRotationOpts drives rotation on the harness clock: a 4h interval with a
// 1h prepublish and a 2h overlap, so a scenario advances hours and watches the
// lifecycle move. The bundle purpose stays manual.
func keysRotationOpts() []harness.Option {
	return []harness.Option{harness.WithKeyRotation(4*time.Hour, time.Hour, 2*time.Hour)}
}

// keyKIDs maps "purpose/state" to the kid of the row in that state.
func keyKIDs(rows []harness.KeyRow) map[string]string {
	out := map[string]string{}
	for _, r := range rows {
		out[r.Purpose+"/"+r.State] = r.KID
	}
	return out
}

// keyStateCount counts the rows of one purpose in each state: the lifecycle
// holds exactly one active and one next key per purpose.
func keyStateCount(rows []harness.KeyRow, purpose string) map[string]int {
	out := map[string]int{}
	for _, r := range rows {
		if r.Purpose == purpose {
			out[r.State]++
		}
	}
	return out
}

// keyJWKSKids returns the kids of the token purpose's JWKS.
func keyJWKSKids(h *harness.H) []string {
	set := h.KeyManager().KeySet().JWKS(keys.PurposeToken)
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	return out
}

// sameKeySet reports whether got holds exactly the wanted kids.
func sameKeySet(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	have := make(map[string]bool, len(want))
	for _, k := range want {
		have[k] = true
	}
	for _, k := range got {
		if !have[k] {
			return false
		}
	}
	return true
}

func cpPolicyStatus(h *harness.H) int {
	return h.CP().DoWorker(http.MethodGet, "/policy", h.CP().Token(), "", "").Status
}

// keysFileStoreRestart: the file backend holds one 0600 PEM per key in 0700
// directories, the database holds public metadata only, and a restart keeps
// the same kids and creates no extra rows.
func keysFileStoreRestart(t *testing.T, h *harness.H) {
	first := h.KeyRows()
	if len(first) != 4 {
		t.Fatalf("signing_keys rows = %+v, want an active and a next for token and bundle", first)
	}
	want := keyKIDs(first)
	for _, k := range []string{"token/active", "token/next", "bundle/active", "bundle/next"} {
		if want[k] == "" {
			t.Fatalf("no %s row in %+v", k, first)
		}
	}
	for _, r := range first {
		if r.Backend != "file" || r.Alg != keys.AlgEdDSA || strings.Contains(r.PublicJWK, `"d"`) {
			t.Errorf("row = %+v, want a file-backend EdDSA row with a public-only JWK", r)
		}
		pem := filepath.Join(h.KeyStateDir(), "keys", r.Purpose, r.KID+".pem")
		fi, err := os.Stat(pem)
		if err != nil {
			t.Fatalf("no key material for %s/%s: %v", r.Purpose, r.State, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v, want 0600", pem, fi.Mode().Perm())
		}
		if di, _ := os.Stat(filepath.Dir(pem)); di.Mode().Perm() != 0o700 {
			t.Errorf("%s mode %v, want 0700", filepath.Dir(pem), di.Mode().Perm())
		}
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", status)
	}

	h.CP().Stop()
	h.CP().Start()
	second := h.KeyRows()
	if len(second) != len(first) {
		t.Fatalf("restart changed the row count: %d -> %d", len(first), len(second))
	}
	got := keyKIDs(second)
	for k, kid := range want {
		if got[k] != kid {
			t.Errorf("%s kid changed across a restart: %s -> %s", k, kid, got[k])
		}
	}
	if _, err := h.KeyManager().KeySet().Active(keys.PurposeToken); err != nil {
		t.Errorf("token signer after the restart: %v", err)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the restart = %d, want 200", status)
	}
	if strings.Contains(h.Logs(), "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
}

// keysBackendDownRecovers: rows exist but the key store is unreachable at
// startup. The control plane serves policy anyway, signing is refused with
// ErrNoActiveKey, no key or row is created, a signing_key_unavailable Finding
// is published, and signing returns when the store does — no restart.
func keysBackendDownRecovers(t *testing.T, h *harness.H) {
	before := h.KeyRows()
	if len(before) != 4 {
		t.Fatalf("rows after the first start = %d, want 4", len(before))
	}

	h.CP().Stop()
	h.KeyStore().SetDown(errors.New("secret backend unreachable"))
	h.CP().Start()

	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy with the key store down = %d, want 200", status)
	}
	mgr := h.KeyManager()
	if _, err := mgr.KeySet().Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("signer with the store down = %v, want ErrNoActiveKey", err)
	}
	if mgr.Ready() {
		t.Error("manager reports ready with the store down")
	}
	if got := h.KeyFindings(keys.AlertSigningKeyUnavailable); len(got) != 2 {
		t.Errorf("signing_key_unavailable findings = %d, want one per purpose", len(got))
	}
	if after := h.KeyRows(); len(after) != len(before) {
		t.Errorf("the outage created rows: %d -> %d", len(before), len(after))
	}

	h.KeyStore().SetDown(nil)
	h.Eventually("signing recovers once the store returns", func() bool {
		h.Clock().Advance(time.Minute)
		return mgr.Ready()
	})
	sg, err := mgr.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sg.Sign(context.Background(), []byte("header.payload")); err != nil {
		t.Errorf("Sign after the recovery: %v", err)
	}
	after := h.KeyRows()
	if len(after) != len(before) {
		t.Fatalf("recovery changed the row count: %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].KID != after[i].KID || before[i].State != after[i].State {
			t.Errorf("row %d changed: %+v -> %+v", i, before[i], after[i])
		}
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the recovery = %d, want 200", status)
	}
}

// keysDisabledCreatesNothing: without keys.enabled (the default) the control
// plane keeps no key directory and no signing_keys table.
func keysDisabledCreatesNothing(t *testing.T, h *harness.H) {
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Fatalf("GET /policy = %d, want 200", status)
	}
	if h.KeysTablePresent() {
		t.Error("signing_keys exists with keys disabled")
	}
	// The key routes do not exist: the JWKS is 404, readiness is plain 200.
	if res := jwksBody(h); res.Status != http.StatusNotFound {
		t.Errorf("GET /.well-known/jwks.json with keys disabled = %d, want 404", res.Status)
	}
	if res := h.CP().DoWorker(http.MethodGet, "/readyz", "", "", ""); res.Status != http.StatusOK {
		t.Errorf("GET /readyz with keys disabled = %d, want 200", res.Status)
	}
}

// keysRotateOnSchedule (W-P2-KEYS-03): at the end of a 4h interval the
// scheduler retires the signing key, promotes the next key that has been
// published since boot, and publishes a fresh next key. The retired key keeps
// verifying through its 2h overlap — no verify gap — while its private
// material is gone the moment it stops signing; past the overlap it is
// destroyed and leaves the JWKS. The manual bundle purpose never moves, and
// nothing pages: this is the schedule working, not failing.
func keysRotateOnSchedule(t *testing.T, h *harness.H) {
	first := keyKIDs(h.KeyRows())

	// 5h in: the rotation was due at 4h and the minute scheduler applies it on
	// its goroutine, so the scenario drives the clock in ticks until the
	// lifecycle has moved — retire, promote, publish — and the JWKS still holds
	// the retired key until 6h.
	h.Clock().Advance(5 * time.Hour)
	h.Eventually("the scheduler applies the due rotation", func() bool {
		h.Clock().Advance(time.Minute)
		st := keyStateCount(h.KeyRows(), keys.PurposeToken)
		return st[string(keys.StateActive)] == 1 && st[string(keys.StateNext)] == 1 &&
			st[string(keys.StateRetired)] == 1
	})

	rows := h.KeyRows()
	got := keyKIDs(rows)
	if states := keyStateCount(rows, keys.PurposeToken); states[string(keys.StateActive)] != 1 || states[string(keys.StateNext)] != 1 ||
		states[string(keys.StateRetired)] != 1 {
		t.Fatalf("token rows after the rotation = %+v, want one active, one next, one retired", rows)
	}
	if got["token/active"] != first["token/next"] {
		t.Errorf("the prepublished next key did not take over: %s -> %s", first["token/next"], got["token/active"])
	}
	if got["token/next"] == "" || got["token/next"] == got["token/active"] {
		t.Errorf("no fresh next key published: %+v", rows)
	}
	if got["token/retired"] != first["token/active"] {
		t.Errorf("the key that signed for the interval was not retired: %+v", rows)
	}
	if got["bundle/active"] != first["bundle/active"] || got["bundle/next"] != first["bundle/next"] {
		t.Errorf("the manual bundle purpose rotated: %+v", rows)
	}

	mgr := h.KeyManager()
	sg, err := mgr.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatalf("token signer after the rotation: %v", err)
	}
	if sg.KID() != got["token/active"] {
		t.Errorf("the manager signs with %s, want the row's active %s", sg.KID(), got["token/active"])
	}
	if _, err := sg.Sign(context.Background(), []byte("header.payload")); err != nil {
		t.Errorf("Sign with the promoted key: %v", err)
	}
	// The verifier's set: next, active and the retired key inside its overlap.
	if kids := keyJWKSKids(h); !sameKeySet(kids, got["token/active"], got["token/next"], got["token/retired"]) {
		t.Errorf("token JWKS after the rotation = %v, want active, next and the retired key", kids)
	}
	// The retired key stopped signing, so its material is gone at once.
	if _, err := os.Stat(filepath.Join(h.KeyStateDir(), "keys", keys.PurposeToken, got["token/retired"]+".pem")); !os.IsNotExist(err) {
		t.Errorf("the retired key kept its material: %v", err)
	}

	// Past the overlap the retired key is destroyed and leaves the JWKS; the
	// active key (promoted at 4h) is not due again until 8h.
	h.Clock().Advance(2*time.Hour + time.Minute)
	h.Eventually("the retired key is destroyed past its overlap", func() bool {
		h.Clock().Advance(time.Minute)
		return keyKIDs(h.KeyRows())["token/destroyed"] != ""
	})

	rows = h.KeyRows()
	got = keyKIDs(rows)
	if got["token/destroyed"] != first["token/active"] {
		t.Errorf("the retired key was not destroyed past its overlap: %+v", rows)
	}
	if kids := keyJWKSKids(h); !sameKeySet(kids, got["token/active"], got["token/next"]) {
		t.Errorf("token JWKS past the overlap = %v, want active and next only", kids)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the rotation = %d, want 200", status)
	}
	for _, rule := range []string{keys.AlertKeyRotationFailed, keys.AlertKeyOverdue, keys.AlertSigningKeyUnavailable} {
		if got := h.KeyFindings(rule); got != nil {
			t.Errorf("a working schedule raised %s: %+v", rule, got)
		}
	}
}

// keysRotateAfterDowntime (W-P2-KEYS-03): the control plane is down for 13h —
// three missed rotations on a 4h interval. The rows freeze while it is away,
// and the first pass after the restart catches up: the boot key retired, the
// prepublished next key promoted, a fresh next published — one rotation, never
// two active keys, and no page for what it healed.
func keysRotateAfterDowntime(t *testing.T, h *harness.H) {
	before := keyKIDs(h.KeyRows())

	h.CP().Stop()
	h.Clock().Advance(13 * time.Hour)
	if got := keyKIDs(h.KeyRows()); got["token/active"] != before["token/active"] {
		t.Fatalf("rows moved while the control plane was down: %+v", got)
	}

	h.CP().Start()
	// The catch-up pass runs on the manager's goroutine as the control plane
	// boots; the ticks that drive it move the fake clock in turn.
	h.Eventually("the catch-up pass rotates the overdue key", func() bool {
		h.Clock().Advance(time.Minute)
		st := keyStateCount(h.KeyRows(), keys.PurposeToken)
		return st[string(keys.StateActive)] == 1 && st[string(keys.StateNext)] == 1 &&
			keyKIDs(h.KeyRows())["token/active"] != before["token/active"]
	})

	rows := h.KeyRows()
	got := keyKIDs(rows)
	if states := keyStateCount(rows, keys.PurposeToken); states[string(keys.StateActive)] != 1 || states[string(keys.StateNext)] != 1 {
		t.Fatalf("token rows after the catch-up = %+v, want exactly one active and one next", rows)
	}
	if got["token/retired"] != before["token/active"] {
		t.Errorf("the key that signed through the downtime was not retired: %+v", rows)
	}
	if got["token/active"] != before["token/next"] {
		t.Errorf("the prepublished next key did not take over: %s -> %s", before["token/next"], got["token/active"])
	}
	if got["bundle/active"] != before["bundle/active"] || got["bundle/next"] != before["bundle/next"] {
		t.Errorf("the manual bundle purpose rotated across the downtime: %+v", rows)
	}
	mgr := h.KeyManager()
	sg, err := mgr.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatalf("token signer after the catch-up: %v", err)
	}
	if sg.KID() != got["token/active"] {
		t.Errorf("the manager signs with %s, want the row's active %s", sg.KID(), got["token/active"])
	}
	if _, err := sg.Sign(context.Background(), []byte("header.payload")); err != nil {
		t.Errorf("Sign with the promoted key: %v", err)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy after the catch-up = %d, want 200", status)
	}
	for _, rule := range []string{keys.AlertKeyRotationFailed, keys.AlertKeyOverdue, keys.AlertSigningKeyUnavailable} {
		if got := h.KeyFindings(rule); got != nil {
			t.Errorf("a caught-up restart raised %s: %+v", rule, got)
		}
	}
}

// The JWKS and readiness gate (W-P2-KEYS-04): the public token JWKS and
// /readyz need no credential, answer from memory and follow the key lifecycle.

// jwksBody fetches the public JWKS with no credential.
func jwksBody(h *harness.H) harness.RawResponse {
	return h.CP().DoWorker(http.MethodGet, "/.well-known/jwks.json", "", "", "")
}

// jwksResponseKids returns the kids in a JWKS body, failing if a member carries
// private material.
func jwksResponseKids(t *testing.T, body string) []string {
	t.Helper()
	if strings.Contains(body, `"d"`) {
		t.Fatalf("JWKS carries a private parameter: %s", body)
	}
	var doc struct {
		Keys []keys.JWK `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("JWKS is not JSON: %v", err)
	}
	out := make([]string, 0, len(doc.Keys))
	for _, k := range doc.Keys {
		out = append(out, k.Kid)
	}
	return out
}

// keysJWKSServedAndRotates: an unauthenticated verifier fetches the active and
// the next token key (never the bundle's), revalidates with the ETag, and a
// rotation moves the document: new ETag, the retired key still published.
func keysJWKSServedAndRotates(t *testing.T, h *harness.H) {
	rows := keyKIDs(h.KeyRows())
	res := jwksBody(h)
	if res.Status != http.StatusOK || res.Header.Get("Content-Type") != "application/jwk-set+json" {
		t.Fatalf("GET /.well-known/jwks.json = %d %q, want 200 application/jwk-set+json", res.Status, res.Header.Get("Content-Type"))
	}
	if got := res.Header.Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", got)
	}
	if kids := jwksResponseKids(t, res.Body); !sameKeySet(kids, rows["token/active"], rows["token/next"]) {
		t.Errorf("JWKS kids = %v, want the token active and next (never bundle keys): %+v", kids, rows)
	}
	etag := res.Header.Get("ETag")
	cond := <-h.CP().HoldWorker(http.MethodGet, "/.well-known/jwks.json", "", http.Header{"If-None-Match": {etag}})
	if cond.Status != http.StatusNotModified {
		t.Errorf("If-None-Match %s = %d, want 304", etag, cond.Status)
	}
	if post := h.CP().DoWorker(http.MethodPost, "/.well-known/jwks.json", "", "", "{}"); post.Status != http.StatusMethodNotAllowed {
		t.Errorf("POST jwks = %d, want 405", post.Status)
	}
	if ready := h.CP().DoWorker(http.MethodGet, "/readyz", "", "", ""); ready.Status != http.StatusOK {
		t.Errorf("/readyz with keys loaded = %d, want 200", ready.Status)
	}

	h.Clock().Advance(5 * time.Hour)
	h.Eventually("the JWKS follows the scheduled rotation", func() bool {
		h.Clock().Advance(time.Minute)
		next := jwksBody(h)
		return next.Status == http.StatusOK && next.Header.Get("ETag") != etag
	})
	after := keyKIDs(h.KeyRows())
	kids := jwksResponseKids(t, jwksBody(h).Body)
	if !sameKeySet(kids, after["token/active"], after["token/next"], after["token/retired"]) {
		t.Errorf("JWKS after the rotation = %v, want active, next and the retired key inside its overlap: %+v", kids, after)
	}
	if strings.Contains(h.Logs(), "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
}

// keysJWKSUnavailableUntilLoaded: with the key store down at startup the JWKS
// answers 503 signing_unavailable and /readyz 503, while /healthz and policy
// keep serving; both recover when the store returns.
func keysJWKSUnavailableUntilLoaded(t *testing.T, h *harness.H) {
	h.CP().Stop()
	h.KeyStore().SetDown(errors.New("secret backend unreachable"))
	h.CP().Start()

	// The JWKS can still be built from the persisted rows only once a signer
	// loaded, so it is unavailable, not stale.
	if res := jwksBody(h); res.Status != http.StatusServiceUnavailable || !strings.Contains(res.Body, "signing_unavailable") {
		t.Errorf("JWKS with the store down = %d %s, want 503 signing_unavailable", res.Status, res.Body)
	}
	ready := h.CP().DoWorker(http.MethodGet, "/readyz", "", "", "")
	if ready.Status != http.StatusServiceUnavailable || !strings.Contains(ready.Body, "no_active_key") {
		t.Errorf("/readyz with the store down = %d %s, want 503 no_active_key", ready.Status, ready.Body)
	}
	if health := h.CP().DoWorker(http.MethodGet, "/healthz", "", "", ""); health.Status != http.StatusOK {
		t.Errorf("/healthz with the store down = %d, want 200", health.Status)
	}
	if status := cpPolicyStatus(h); status != http.StatusOK {
		t.Errorf("GET /policy with the store down = %d, want 200", status)
	}

	h.KeyStore().SetDown(nil)
	h.Eventually("the JWKS and /readyz recover with the store", func() bool {
		h.Clock().Advance(time.Minute)
		return jwksBody(h).Status == http.StatusOK &&
			h.CP().DoWorker(http.MethodGet, "/readyz", "", "", "").Status == http.StatusOK
	})
}

// keysCLIRotatesAndResets (W-P2-KEYS-05): the offline keys CLI rotates a
// purpose straight on a running control plane's state dir — the running
// manager adopts the change within its 2-second data-version poll, the bundle
// purpose is refused with the next kid to pin, reset refuses while the
// control plane holds the instance lock and replaces the purpose once it is
// stopped, and the restarted control plane signs with the fresh key.
func keysCLIRotatesAndResets(t *testing.T, h *harness.H) {
	ctx := context.Background()
	first := keyKIDs(h.KeyRows())

	// One prepublish window in, the CLI's non-emergency rotation may promote
	// the published next key. The CLI shares the harness clock, so its
	// prepublish and overlap windows are measured on the same time as the
	// rows.
	h.Clock().Advance(time.Hour + 10*time.Minute)
	o, err := controlplane.OpenKeysOffline(ctx, h.KeyStateDir(), controlplane.KeysCLIOptions{Clock: h.Clock()})
	if err != nil {
		t.Fatalf("open the keys CLI: %v", err)
	}
	defer func() { _ = o.Close() }()
	res, err := o.Rotate(ctx, keys.PurposeToken, false)
	if err != nil {
		t.Fatalf("cli rotate: %v", err)
	}
	if res.KID != first["token/next"] {
		t.Errorf("cli rotate = %s, want the published next key %s", res.KID, first["token/next"])
	}
	rows := h.KeyRows()
	got := keyKIDs(rows)
	if got["token/active"] != res.KID || got["token/retired"] != first["token/active"] ||
		got["token/next"] == "" || got["token/next"] == res.KID {
		t.Fatalf("token rows after the cli rotation = %+v, want promote, retire and a fresh next", rows)
	}
	// The CLI rebuilds the same published set the control plane serves: next,
	// active and the retired key inside its overlap.
	set, err := o.JWKS(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.Kid)
	}
	if !sameKeySet(kids, got["token/active"], got["token/next"], got["token/retired"]) {
		t.Errorf("cli jwks = %v, want the three published kids of %+v", kids, rows)
	}

	// The running manager adopts the CLI's write through the data-version
	// poll: drive the clock in small ticks, since a big Advance returns
	// before the poll's goroutine finishes.
	h.Eventually("the running manager signs with the promoted key", func() bool {
		h.Clock().Advance(2 * time.Second)
		sg, err := h.KeyManager().KeySet().Active(keys.PurposeToken)
		return err == nil && sg.KID() == res.KID
	})

	// The bundle purpose is staged, never rotated through the CLI: the
	// refusal names the kid workers must pin.
	_, err = o.Rotate(ctx, keys.PurposeBundle, false)
	var staged *controlplane.StagedRotationError
	if !errors.As(err, &staged) || staged.NextKID != first["bundle/next"] {
		t.Errorf("cli bundle rotate = %v, want a staged refusal pinning %s", err, first["bundle/next"])
	}

	// Reset refuses while the control plane holds the state dir's lock.
	if _, err := o.Reset(ctx, keys.PurposeToken); err == nil || !strings.Contains(err.Error(), "control plane is running") {
		t.Errorf("cli reset under a running control plane = %v, want the running refusal", err)
	}

	h.CP().Stop()
	out, err := o.Reset(ctx, keys.PurposeToken)
	if err != nil {
		t.Fatalf("cli reset: %v", err)
	}
	if out.Removed != 3 || out.KID == "" {
		t.Fatalf("reset result = %+v, want the purpose's 3 rows replaced by a fresh active key", out)
	}
	after := keyKIDs(h.KeyRows())
	for _, s := range []string{"token/active", "token/next", "token/retired"} {
		if old := first[s]; old != "" && after[s] == old {
			t.Errorf("%s kid survived the reset: %s", s, old)
		}
	}
	pem := filepath.Join(h.KeyStateDir(), "keys", keys.PurposeToken, out.KID+".pem")
	if _, err := os.Stat(pem); err != nil {
		t.Errorf("no material for the fresh active key: %v", err)
	}

	// The restarted control plane loads the fresh purpose and signs with it.
	h.CP().Start()
	h.Eventually("the restarted control plane signs with the fresh key", func() bool {
		h.Clock().Advance(time.Minute)
		sg, err := h.KeyManager().KeySet().Active(keys.PurposeToken)
		return err == nil && sg.KID() == out.KID
	})
	if strings.Contains(h.Logs(), "PRIVATE KEY") {
		t.Error("logs contain PEM key material")
	}
}
