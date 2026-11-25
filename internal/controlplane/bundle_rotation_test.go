package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// Staged bundle key rotation (W-P2-SBND-07), as the publisher sees it: the
// KeySet hands out the active signer plus, once staged, the next one, and the
// envelope carries a signature of each.

// stage adds a staged next signer and delivers the bundle transition, as the
// KeySet does when the keys CLI's stage reaches the running control plane. It
// returns the staged key's pin.
func (f *fakeBundleKeys) stage(t *testing.T) keys.JWK {
	t.Helper()
	s, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(s.Public(), s.Alg())
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.staged = s
	f.mu.Unlock()
	f.fire(keys.PurposeBundle)
	return jwk
}

// activate makes the staged key the only signer, as a rotation does.
func (f *fakeBundleKeys) activate() {
	f.mu.Lock()
	f.signer, f.staged = f.staged, nil
	f.mu.Unlock()
	f.fire(keys.PurposeBundle)
}

func pinOf(t *testing.T, s keys.Signer) keys.JWK {
	t.Helper()
	jwk, err := keys.PublicJWK(s.Public(), s.Alg())
	if err != nil {
		t.Fatal(err)
	}
	return jwk
}

func envelopeKIDs(t *testing.T, raw []byte) []string {
	t.Helper()
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range env.Signatures {
		out = append(out, s.KID)
	}
	return out
}

// verifyAs verifies raw the way a worker holding only pins does.
func (h *btHarness) verifyAs(raw []byte, pins []keys.JWK, applied bundle.State) (bundle.Verified, error) {
	return bundle.Verify(raw, pins, applied, bundle.Options{Now: h.clk.Now(), Skew: time.Minute})
}

// TestBundleStagedRotation: before the stage an envelope has one signature and
// only a worker pinning the old key accepts it; after the stage it carries two
// and a worker pinned only to the old key and one pinned only to the new key
// both accept it, at the same seq; after the activation it carries the new
// signature alone, the new-key worker still accepts and the old-key worker
// (which has not moved its pin) fails closed rather than trusting a key it
// does not hold.
func TestBundleStagedRotation(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	oldSigner, err := h.fk.Signers(keys.PurposeBundle)
	if err != nil {
		t.Fatal(err)
	}
	oldPin := []keys.JWK{pinOf(t, oldSigner[0])}
	oldKID := oldSigner[0].KID()

	before := h.bundleResp(t)
	if got := envelopeKIDs(t, before.body); len(got) != 1 || got[0] != oldKID {
		t.Fatalf("signatures before the stage = %v, want only %s", got, oldKID)
	}
	first, err := h.verifyAs(before.body, oldPin, bundle.State{})
	if err != nil {
		t.Fatalf("old-pin worker before the stage: %v", err)
	}

	newPin := []keys.JWK{h.fk.stage(t)}
	newKID := newPin[0].Kid
	var staged btResp
	btEventually(t, "the control plane re-signs with both keys", func() bool {
		staged = h.bundleResp(t)
		return len(envelopeKIDs(t, staged.body)) == 2
	})
	if got := envelopeKIDs(t, staged.body); got[0] != oldKID || got[1] != newKID {
		t.Fatalf("staged signatures = %v, want [%s %s]", got, oldKID, newKID)
	}
	for name, pins := range map[string][]keys.JWK{"old-pin": oldPin, "new-pin": newPin, "both pins": append(append([]keys.JWK{}, oldPin...), newPin...)} {
		v, err := h.verifyAs(staged.body, pins, btState(first))
		if err != nil {
			t.Fatalf("%s worker rejected the dual-signed envelope: %v", name, err)
		}
		if v.Seq != first.Seq || v.ContentSHA256 != first.ContentSHA256 || !v.Refresh {
			t.Errorf("%s worker: seq %d -> %d refresh=%v, want a refresh of the same content", name, first.Seq, v.Seq, v.Refresh)
		}
	}
	if n := len(h.publishRows(t)); n != 1 {
		t.Errorf("staging appended publish_log rows: %d, want 1 (a key change only re-signs)", n)
	}
	if h.degraded() {
		t.Error("staging degraded the publisher")
	}

	h.fk.activate()
	var active btResp
	btEventually(t, "the control plane signs with the new key alone", func() bool {
		active = h.bundleResp(t)
		return len(envelopeKIDs(t, active.body)) == 1
	})
	if got := envelopeKIDs(t, active.body); got[0] != newKID {
		t.Fatalf("signatures after the activation = %v, want only %s", got, newKID)
	}
	if _, err := h.verifyAs(active.body, newPin, btState(first)); err != nil {
		t.Fatalf("new-pin worker after the activation: %v", err)
	}
	_, err = h.verifyAs(active.body, oldPin, btState(first))
	if !errors.Is(err, bundle.ErrUnknownKid) {
		t.Fatalf("old-pin worker after the activation = %v, want unknown_kid (fail closed, not accepted)", err)
	}
}

// TestBundleStagedSignFailureKeepsLast: if a staged signer fails the whole
// envelope is withheld and the last one keeps being served, degraded: dropping
// the staged signature quietly would strand a worker pinned only to the new
// key.
func TestBundleStagedSignFailureKeepsLast(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	h.fk.stage(t)
	var dual btResp
	btEventually(t, "dual signed", func() bool {
		dual = h.bundleResp(t)
		return len(envelopeKIDs(t, dual.body)) == 2
	})

	h.fk.mu.Lock()
	h.fk.staged = failingSigner{h.fk.staged}
	h.fk.mu.Unlock()
	h.fk.fire(keys.PurposeBundle)
	btEventually(t, "the publisher reports degraded", h.degraded)
	if got := h.bundleResp(t); string(got.body) != string(dual.body) {
		t.Error("a failed staged signature replaced the last envelope")
	}
}

// TestBundleForgedBesideValidSignature: a worker pinning both keys of a staged
// rotation accepts an envelope with one valid signature (the forged one beside it
// adds nothing and costs nothing), and rejects one whose signatures are all
// forged.
func TestBundleForgedBesideValidSignature(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	oldS, _ := h.fk.Signers(keys.PurposeBundle)
	oldPin := pinOf(t, oldS[0])
	newPin := h.fk.stage(t)
	pins := []keys.JWK{oldPin, newPin}
	raw := h.bundleResp(t).body
	for len(envelopeKIDs(t, raw)) != 2 {
		raw = h.bundleResp(t).body
	}
	var env bundle.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	forge := func(kid string) bundle.Signature {
		return bundle.Signature{KID: kid, Sig: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
	}
	one := env
	one.Signatures = []bundle.Signature{forge(newPin.Kid), env.Signatures[0]}
	rawOne, _ := json.Marshal(one)
	if _, err := h.verifyAs(rawOne, pins, bundle.State{}); err != nil {
		t.Fatalf("one valid signature beside a forged one = %v, want accepted", err)
	}
	none := env
	none.Signatures = []bundle.Signature{forge(oldPin.Kid), forge(newPin.Kid)}
	rawNone, _ := json.Marshal(none)
	if _, err := h.verifyAs(rawNone, pins, bundle.State{}); !errors.Is(err, bundle.ErrBadSignature) {
		t.Fatalf("all signatures forged = %v, want bad_signature", err)
	}
}
