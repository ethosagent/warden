package controlplane

import (
	"errors"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// staticSigners hands out one fixed active signer, whatever the purpose.
type staticSigners struct{ sg keys.Signer }

func (s staticSigners) Active(string) (keys.Signer, error) { return s.sg, nil }

// setTokenKeys replaces the token JWKS the fake publishes.
func (f *fakeBundleKeys) setTokenKeys(t *testing.T, sgs ...keys.Signer) {
	t.Helper()
	set := keys.JWKS{}
	for _, sg := range sgs {
		jwk, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
		if err != nil {
			t.Fatal(err)
		}
		set.Keys = append(set.Keys, jwk)
	}
	f.mu.Lock()
	f.token = set
	f.mu.Unlock()
}

func newTokenSigner(t *testing.T) keys.Signer {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	return sg
}

// TestServedSignersBundleGuard: with signed bundles on, the active token key
// mints only when the bundle served now carries it in its tokenJWKS, so a key
// that is in the served JWKS but in no signed bundle (the first key, an
// emergency promotion, a degraded publisher) never mints.
func TestServedSignersBundleGuard(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	published := h.clk.Now().Add(-time.Hour) // the publish window long passed
	guard := func(sg keys.Signer) servedSigners {
		return servedSigners{
			inner:   staticSigners{sg},
			records: func(string) []keys.Record { return []keys.Record{{KID: sg.KID(), PublishAt: published}} },
			now:     h.clk.Now,
			bundled: h.s.servesBundleTokenKID,
		}
	}
	refused := func(t *testing.T, sg keys.Signer) {
		t.Helper()
		if _, err := guard(sg).Active(keys.PurposeToken); !errors.Is(err, keys.ErrNoActiveKey) {
			t.Fatalf("err = %v, want ErrNoActiveKey", err)
		}
	}
	allowed := func(t *testing.T, sg keys.Signer) {
		t.Helper()
		if _, err := guard(sg).Active(keys.PurposeToken); err != nil {
			t.Fatalf("err = %v, want a signer", err)
		}
	}

	first := newTokenSigner(t)
	t.Run("first key: refused until a bundle carries it", func(t *testing.T) {
		// The harness signed its bundle with a different token key.
		refused(t, first)
		h.fk.setTokenKeys(t, first)
		refused(t, first) // the key moved, no bundle signed yet
		h.fk.fire(keys.PurposeToken)
		allowed(t, first)
	})
	t.Run("emergency rotation: refused until the new bundle", func(t *testing.T) {
		next := newTokenSigner(t)
		// The emergency rotation drops the old key and promotes next.
		h.fk.setTokenKeys(t, next)
		refused(t, next)
		h.fk.fire(keys.PurposeToken)
		allowed(t, next)
	})
	t.Run("degraded publisher: the last served bundle decides", func(t *testing.T) {
		next := newTokenSigner(t)
		h.fk.mu.Lock()
		h.fk.failSign = true
		h.fk.mu.Unlock()
		h.fk.setTokenKeys(t, next)
		h.fk.fire(keys.PurposeToken)
		if !h.degraded() {
			t.Fatal("publisher not degraded")
		}
		refused(t, next)
		h.fk.mu.Lock()
		h.fk.failSign = false
		h.fk.mu.Unlock()
		h.fk.fire(keys.PurposeToken)
		allowed(t, next)
	})
	t.Run("other purposes are not guarded", func(t *testing.T) {
		g := guard(newTokenSigner(t))
		if _, err := g.Active(keys.PurposeBundle); err != nil {
			t.Fatalf("bundle purpose: %v", err)
		}
	})
}

// TestServedSignersBundleGuardNoEnvelope: bundles on but nothing signed yet is
// refused, and bundles off keeps today's behaviour.
func TestServedSignersBundleGuardNoEnvelope(t *testing.T) {
	h := newBundleHarness(t, BundlesOffer, writePolicyFile(t, "api.openai.com"), nil, nil, nil, nil)
	if !h.s.servesBundleTokenKID(h.fk.JWKS(keys.PurposeToken).Keys[0].Kid) {
		t.Fatal("the bundle signed at start carries the token key it was built with")
	}
	if h.s.servesBundleTokenKID("unknown-kid") {
		t.Fatal("a kid in no bundle must be refused")
	}
	h.ps.watch.mu.Lock()
	h.ps.watch.bundle = nil
	h.ps.watch.mu.Unlock()
	if h.s.servesBundleTokenKID(h.fk.JWKS(keys.PurposeToken).Keys[0].Kid) {
		t.Fatal("no envelope served yet must refuse")
	}

	e := newKeysEnv(t, keysEnvOpts{})
	if !e.srv.servesBundleTokenKID("anything") {
		t.Fatal("bundles off must keep today's behaviour")
	}
}
