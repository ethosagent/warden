package adminaudit

import (
	"context"
	"strings"
	"testing"
)

func TestStateHash(t *testing.T) {
	s, _ := freshStore(t)
	h1, err := s.StateHash("policy", []byte(`{"allowlist":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h1, StateHashPrefix) || len(h1) != len(StateHashPrefix)+64 || len(h1) > maxStateHashLen {
		t.Fatalf("StateHash = %q", h1)
	}
	if h2, _ := s.StateHash("policy", []byte(`{"allowlist":[]}`)); h2 != h1 {
		t.Fatal("StateHash is not deterministic")
	}
	if h3, _ := s.StateHash("settings", []byte(`{"allowlist":[]}`)); h3 == h1 {
		t.Fatal("the target is not part of the hash")
	}
	if h4, _ := s.StateHash("policy", []byte(`{"allowlist":[1]}`)); h4 == h1 {
		t.Fatal("the data is not part of the hash")
	}
	// Keyed: another key gives another hash, and it is not the actor id form.
	other := NewStore(s.db, Options{Signer: newSigner(t), HMACKey: []byte("another-key-another-key-another!")})
	if h5, _ := other.StateHash("policy", []byte(`{"allowlist":[]}`)); h5 == h1 {
		t.Fatal("StateHash does not depend on the HMAC key")
	}
	if strings.TrimPrefix(h1, StateHashPrefix) == s.actorID("policy") {
		t.Fatal("state hashes are not domain-separated from actor ids")
	}
	if _, err := NewStore(s.db, Options{}).StateHash("policy", nil); err == nil {
		t.Fatal("a store without an HMAC key hashed state")
	}
}

func TestProbe(t *testing.T) {
	s, db := freshStore(t)
	if err := s.Probe(context.Background()); err != nil {
		t.Fatalf("Probe on a healthy store: %v", err)
	}
	if seq, _, _, _ := s.Head(context.Background()); seq != 0 {
		t.Fatalf("Probe wrote rows (head seq %d)", seq)
	}
	if err := NewStore(db, Options{}).Probe(context.Background()); err == nil {
		t.Fatal("a read-only store probed healthy")
	}
	_ = db.Close()
	if err := s.Probe(context.Background()); err == nil {
		t.Fatal("Probe on a closed database succeeded")
	}
}
