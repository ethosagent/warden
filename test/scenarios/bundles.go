package scenarios

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/test/harness"
)

// The signed-bundle serve gate (W-P2-SBND-02). With --bundles=off (the
// default) GET /policy answers a request that asks for the envelope with the
// legacy policy, untouched. With --bundles=offer the control plane signs the
// served policy with its bundle key and serves the envelope to a request with
// the bundle Accept header: a policy save and a rollback each move the seq
// forward, a token key rotation appends a token_jwks row and wakes a held
// long poll, a restart keeps the control plane id and the seq, and the
// harness's own workers, which send no Accept header yet, keep enforcing the
// legacy wire throughout.

func bundlesOffOpts() []harness.Option { return []harness.Option{harness.WithVersionedPolicyStore()} }

func bundlesOfferOpts() []harness.Option {
	return []harness.Option{
		harness.WithBundles(controlplane.BundlesOffer),
		harness.WithKeyRotation(4*time.Hour, time.Hour, 2*time.Hour),
	}
}

// bundlesOffLegacyWire: bundles off answers the bundle Accept header with the
// unchanged legacy policy and ETag.
func bundlesOffLegacyWire(t *testing.T, h *harness.H) {
	plain := h.CP().DoWorker(http.MethodGet, "/policy", h.CP().Token(), "", "")
	asked := h.CP().FetchBundle("")
	if plain.Status != http.StatusOK || asked.Status != http.StatusOK {
		t.Fatalf("GET /policy = %d and %d, want 200", plain.Status, asked.Status)
	}
	if asked.Header.Get("Content-Type") != "application/json" || string(asked.Body) != plain.Body {
		t.Errorf("with bundles off the bundle Accept header changed the reply: %q (%s)", asked.Body, asked.Header.Get("Content-Type"))
	}
	if asked.Header.Get("ETag") == "" || asked.Header.Get("ETag") != plain.Header.Get("ETag") {
		t.Errorf("ETag with the bundle Accept header = %q, want %q", asked.Header.Get("ETag"), plain.Header.Get("ETag"))
	}
	if bytes.Contains(asked.Body, []byte(`"payload"`)) {
		t.Error("an envelope was served with bundles off")
	}
	if strings.Contains(h.Logs(), "bundle signed") {
		t.Error("the control plane signed a bundle with bundles off")
	}
}

// bundleSeqOf verifies the served envelope and returns it.
func bundleSeqOf(t *testing.T, h *harness.H, resp harness.CPResponse, applied bundle.State) bundle.Verified {
	t.Helper()
	if resp.Status != http.StatusOK || resp.Header.Get("Content-Type") != harness.BundleMediaType {
		t.Fatalf("GET /policy as a bundle client = %d %q, want 200 %s", resp.Status, resp.Header.Get("Content-Type"), harness.BundleMediaType)
	}
	return h.VerifyBundle(resp.Body, applied)
}

func bundleApplied(v bundle.Verified) bundle.State {
	return bundle.State{Seq: v.Seq, ContentSHA256: v.ContentSHA256, IssuedAt: v.Bundle.IssuedAt}
}

// bundlesOfferServes drives a pinned worker's view of the control plane.
func bundlesOfferServes(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	cp := h.CP()
	send := func(method, path, ifMatch string, body []byte) harness.CPResponse {
		t.Helper()
		hdr := http.Header{}
		if ifMatch != "" {
			hdr.Set("If-Match", ifMatch)
		}
		resp, err := cp.Send(method, path, hdr, body)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	// The envelope verifies against the bundle public key, names the signing
	// key's kid and is not the legacy wire.
	first := bundleSeqOf(t, h, cp.FetchBundle(""), bundle.State{})
	rows := keyKIDs(h.KeyRows())
	if first.KID != rows["bundle/active"] {
		t.Errorf("signed by %s, want the active bundle key %s", first.KID, rows["bundle/active"])
	}
	if first.Bundle.PolicyVersion != 1 || first.Bundle.CPID == "" {
		t.Errorf("first bundle = policyVersion %d cpID %q", first.Bundle.PolicyVersion, first.Bundle.CPID)
	}
	if legacy := cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "", ""); !strings.Contains(legacy.Body, `"allowlist"`) || strings.Contains(legacy.Body, `"payload"`) {
		t.Errorf("a request without the Accept header must get the legacy wire, got %s", legacy.Body)
	}

	// A policy save moves the seq forward and workers enforce it, on the
	// legacy wire they pull.
	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := json.Unmarshal(send(http.MethodGet, "/dashboard/api/policy", "", nil).Body, &cur); err != nil {
		t.Fatal(err)
	}
	edit, err := json.Marshal(map[string]any{
		"allowlist": append(append([]map[string]any{}, cur.Allowlist...), map[string]any{"domain": rollbackHost}),
		"denylist":  cur.Denylist,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := send(http.MethodPost, "/dashboard/api/policy", `"v1"`, edit); r.Status != http.StatusOK {
		t.Fatalf("policy save = %d %s", r.Status, r.Body)
	}
	h.Eventually("workers enforce the save", func() bool { return connectStatus(t, h, rollbackHost+":443") == http.StatusOK })
	saved := bundleSeqOf(t, h, cp.FetchBundle(""), bundleApplied(first))
	if saved.Seq <= first.Seq || !strings.Contains(string(saved.Bundle.Policy), rollbackHost) {
		t.Fatalf("after the save: seq %d -> %d, policy has the host: %v", first.Seq, saved.Seq, strings.Contains(string(saved.Bundle.Policy), rollbackHost))
	}

	// A rollback is a new head version, so the seq still moves forward.
	if r := send(http.MethodPost, "/dashboard/api/policy/versions/1/rollback", `"v2"`, []byte(`{"note":"undo"}`)); r.Status != http.StatusOK {
		t.Fatalf("rollback = %d %s", r.Status, r.Body)
	}
	h.Eventually("workers enforce the rollback", func() bool { return connectStatus(t, h, rollbackHost+":443") == http.StatusForbidden })
	rolled := bundleSeqOf(t, h, cp.FetchBundle(""), bundleApplied(saved))
	if rolled.Seq <= saved.Seq || strings.Contains(string(rolled.Bundle.Policy), rollbackHost) {
		t.Fatalf("after the rollback: seq %d -> %d, host still in policy: %v", saved.Seq, rolled.Seq, strings.Contains(string(rolled.Bundle.Policy), rollbackHost))
	}

	// ETag and 304: the envelope has its own ETag, which the legacy ETag is not.
	cur304 := cp.FetchBundle("")
	etag := cur304.Header.Get("ETag")
	if r := cp.FetchBundle(etag); r.Status != http.StatusNotModified {
		t.Errorf("If-None-Match %s = %d, want 304", etag, r.Status)
	}
	if legacyETag := cp.DoWorker(http.MethodGet, "/policy", cp.Token(), "", "").Header.Get("ETag"); legacyETag == etag || cp.FetchBundle(legacyETag).Status != http.StatusOK {
		t.Errorf("the legacy ETag %q must not match the envelope's %q", legacyETag, etag)
	}

	// A token key rotation on the clock wakes a held long poll with a higher
	// seq and a new tokenJWKS section.
	held := cp.HoldBundle(etag)
	var woke harness.RawResponse
	h.Eventually("the token rotation wakes the held long poll", func() bool {
		h.Clock().Advance(time.Minute)
		select {
		case woke = <-held:
			return true
		default:
			return false
		}
	})
	if woke.Status != http.StatusOK {
		t.Fatalf("woken long poll = %d %s", woke.Status, woke.Body)
	}
	rotated := h.VerifyBundle([]byte(woke.Body), bundleApplied(rolled))
	if rotated.Seq <= rolled.Seq {
		t.Errorf("token rotation: seq %d -> %d, want higher", rolled.Seq, rotated.Seq)
	}
	if string(rotated.Bundle.Sections["tokenJWKS"]) == string(rolled.Bundle.Sections["tokenJWKS"]) || len(rotated.Bundle.Sections["tokenJWKS"]) == 0 {
		t.Error("the tokenJWKS section did not follow the token key rotation")
	}

	// A restart keeps the control plane id and the seq: the first envelope
	// after it is a refresh of the last, never a new content under an old seq.
	before := bundleSeqOf(t, h, cp.FetchBundle(""), bundle.State{})
	cp.Stop()
	h.Clock().Advance(time.Minute)
	cp.Start()
	after := bundleSeqOf(t, h, cp.FetchBundle(""), bundleApplied(before))
	if after.Bundle.CPID != before.Bundle.CPID || after.Seq != before.Seq || after.ContentSHA256 != before.ContentSHA256 || !after.Refresh {
		t.Errorf("restart: cpID %s -> %s, seq %d -> %d, refresh=%v; want the same id and seq as a refresh",
			before.Bundle.CPID, after.Bundle.CPID, before.Seq, after.Seq, after.Refresh)
	}

	// The signed payload never carries key material and the log never carries
	// the payload.
	var env bundle.Envelope
	if err := json.Unmarshal(cp.FetchBundle("").Body, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(env.Payload)
	if bytes.Contains(payload, []byte("PRIVATE")) || bytes.Contains(payload, []byte(`"d":`)) {
		t.Error("the payload carries private key material")
	}
	logs := h.Logs()
	if !strings.Contains(logs, "bundle signed") || strings.Contains(logs, env.Payload) || strings.Contains(logs, "PRIVATE KEY") {
		t.Error("logs must name bundle signed lines and never the payload or a key")
	}
	if got := h.KeyManager().KeySet().JWKS(keys.PurposeBundle); len(got.Keys) == 0 {
		t.Error("no bundle public key to pin")
	}
}
