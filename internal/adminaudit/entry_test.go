package adminaudit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/ethosagent/warden/internal/audit"
)

func goldenEntry() Entry {
	prev := make([]byte, 32)
	for i := range prev {
		prev[i] = byte(i)
	}
	return Entry{
		V: 1, Seq: 42, TSUnixNano: 1761566400000000000,
		ActorID: "5f2b", ActorRole: "admin", AuthMethod: AuthMethodOIDC,
		Action: "secretstore.delete", Target: "secretstore", TargetRef: "secret:OPENAI_KEY",
		Details: map[string]string{"zeta": "1", "alpha": "<b>&"},
		Outcome: OutcomeOK, HTTPStatus: 204,
		BeforeHash: "hmac:aa", AfterHash: "",
		ClientIP: "192.0.2.1", RequestID: "req-1", KeyID: "0011223344556677",
		PrevHash: prev,
	}
}

const (
	goldenCanonical = `{"v":1,"seq":42,"ts_unix_nano":1761566400000000000,"actor_id":"5f2b","actor_role":"admin",` +
		`"auth_method":"oidc","action":"secretstore.delete","target":"secretstore","target_ref":"secret:OPENAI_KEY",` +
		`"details":{"alpha":"\u003cb\u003e\u0026","zeta":"1"},"outcome":"ok","http_status":204,"before_hash":"hmac:aa",` +
		`"after_hash":"","client_ip":"192.0.2.1","request_id":"req-1","key_id":"0011223344556677",` +
		`"prev_hash":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}`
	goldenHash = "469a7c76e1373233657a0f1980cbe43440564b0423dbc20a18659884702e2097"
)

// TestCanonicalGolden pins the canonical bytes and entry_hash of a fixed
// entry: any change to field order, names or encoding breaks every existing
// chain and must fail here first.
func TestCanonicalGolden(t *testing.T) {
	e := goldenEntry()
	got, err := e.canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != goldenCanonical {
		t.Fatalf("canonical =\n%s\nwant\n%s", got, goldenCanonical)
	}
	h, err := e.entryHash()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(h) != goldenHash {
		t.Fatalf("entry_hash = %x, want %s", h, goldenHash)
	}
	// Store-derived fields are not part of the signed bytes; nil and empty
	// details encode the same.
	e.EntryHash, e.Signature = []byte{1}, []byte{2}
	if again, _ := e.canonical(); !bytes.Equal(again, got) {
		t.Fatal("entry_hash/signature changed the canonical bytes")
	}
	a, b := Entry{Details: nil}, Entry{Details: map[string]string{}}
	ca, _ := a.canonical()
	cb, _ := b.canonical()
	if !bytes.Equal(ca, cb) {
		t.Fatalf("nil details %s != empty details %s", ca, cb)
	}
}

// TestSignBytesEntryHash: the chain signs entry_hash through SignBytes; a
// receipt-style signature (Ed25519 over the bare bytes, as Sign(event) makes)
// over the same entry_hash never passes VerifyBytes.
func TestSignBytesEntryHash(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer := audit.NewSignerFromKey(priv)
	e := goldenEntry()
	h, _ := e.entryHash()
	if !audit.VerifyBytes(signer.PubKey(), h, signer.SignBytes(h)) {
		t.Fatal("SignBytes signature does not verify")
	}
	if audit.VerifyBytes(signer.PubKey(), h, ed25519.Sign(priv, h)) {
		t.Fatal("receipt-style signature verified as a SignBytes signature")
	}
}
