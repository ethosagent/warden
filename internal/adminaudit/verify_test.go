package adminaudit

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/audit"
)

// TestVerifyKeyChangeOnlyAtSegmentStart: a chain that switches keys at a
// hand-built audit.segment_start verifies across both segments and PubKeys
// lists both keys; a key_id change at any other entry fails at that seq.
func TestVerifyKeyChangeOnlyAtSegmentStart(t *testing.T) {
	t.Run("segment_start", func(t *testing.T) {
		path := dbPath(t)
		db := openDB(t, path)
		a := newStore(t, db, newSigner(t))
		record(t, a, 3) // seqs 1..4
		b := newStore(t, openDB(t, path), newSigner(t))
		seg := appendSegmentStart(t, b) // seq 5
		if seg.Seq != 5 || seg.KeyID != b.KeyID() || seg.Details["previous_key_id"] != a.KeyID() {
			t.Fatalf("segment_start = %+v", seg)
		}
		record(t, b, 3) // seqs 6..8 on key B
		if _, err := a.Record(context.Background(), input(1)); !errors.Is(err, ErrKeyIDMismatch) {
			t.Fatalf("old key after segment_start: err = %v, want ErrKeyIDMismatch", err)
		}
		res := verify(t, a, VerifyOptions{HMACKey: testHMACKey})
		if !res.OK || res.Checked != 8 {
			t.Fatalf("Verify across segments = %+v", res)
		}
		keys, err := a.PubKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		want := []KeyInfo{
			{KeyID: a.KeyID(), PublicKey: pubB64(a.signer.PubKey()), FirstSeq: 1},
			{KeyID: b.KeyID(), PublicKey: pubB64(b.signer.PubKey()), FirstSeq: 5},
		}
		if len(keys) != 2 || keys[0] != want[0] || keys[1] != want[1] {
			t.Fatalf("PubKeys = %+v, want %+v", keys, want)
		}
		// Resuming after the boundary still finds both keys in the chain.
		if res := verify(t, a, VerifyOptions{FromSeq: 7}); !res.OK || res.Checked != 2 {
			t.Fatalf("resume past segment_start = %+v", res)
		}
		if res := verify(t, a, VerifyOptions{FromSeq: 3, ToSeq: 6}); !res.OK || res.Checked != 4 || res.LastVerifiedSeq != 6 {
			t.Fatalf("range across segment_start = %+v", res)
		}
		// Removing the segment_start breaks the chain exactly there.
		exec(t, db, "DELETE FROM admin_audit WHERE seq = 5")
		if res := verify(t, a, VerifyOptions{}); res.OK || res.FirstBadSeq != 5 {
			t.Fatalf("without segment_start = %+v", res)
		}
	})

	t.Run("other_entry", func(t *testing.T) {
		path := dbPath(t)
		a := newStore(t, openDB(t, path), newSigner(t))
		record(t, a, 3)
		b := newStore(t, openDB(t, path), newSigner(t))
		e := appendUnchecked(t, b, input(1)) // seq 5, key B, not a segment_start
		res := verify(t, a, VerifyOptions{})
		if res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonKeyChange {
			t.Fatalf("Verify = %+v, want key_change at %d", res, e.Seq)
		}
	})

	t.Run("declared_key_mismatch", func(t *testing.T) {
		path := dbPath(t)
		a := newStore(t, openDB(t, path), newSigner(t))
		record(t, a, 1)
		b := newStore(t, openDB(t, path), newSigner(t))
		other := newSigner(t)
		// A segment_start that declares a key other than the one it is signed
		// with (and whose key_id it carries) is rejected.
		e, err := b.appendTx(context.Background(), func(headRow) (*Entry, *Actor, error) {
			return &Entry{
				ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
				Action: ActionSegmentStart, Target: "admin_audit", Outcome: OutcomeOK,
				Details: map[string]string{detailPublicKey: base64.StdEncoding.EncodeToString(other.PubKey())},
			}, nil, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if res := verify(t, a, VerifyOptions{}); res.OK || res.FirstBadSeq != e.Seq || res.Reason != ReasonDeclaredKey {
			t.Fatalf("Verify = %+v, want declared_key at %d", res, e.Seq)
		}
	})

	t.Run("genesis_only_at_seq_1", func(t *testing.T) {
		s, db := freshStore(t)
		record(t, s, 2)
		exec(t, db, "UPDATE admin_audit SET action = ? WHERE seq = 1", "policy.update")
		if res := verify(t, s, VerifyOptions{}); res.OK || res.FirstBadSeq != 1 || res.Reason != ReasonGenesis {
			t.Fatalf("Verify = %+v, want genesis at 1", res)
		}
		s2, db2 := freshStore(t)
		record(t, s2, 2)
		exec(t, db2, "UPDATE admin_audit SET action = ? WHERE seq = 3", ActionGenesis)
		if res := verify(t, s2, VerifyOptions{}); res.OK || res.FirstBadSeq != 3 || res.Reason != ReasonGenesis {
			t.Fatalf("Verify = %+v, want genesis at 3", res)
		}
	})
}

// TestVerifyResume: MaxRows caps one call; LastVerifiedSeq resumes it.
func TestVerifyResume(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 249) // genesis + 249 = 250 rows
	res := verify(t, s, VerifyOptions{MaxRows: 100})
	if !res.OK || res.Checked != 100 || res.LastVerifiedSeq != 100 || !res.Partial || res.HeadSeq != 250 {
		t.Fatalf("first call = %+v", res)
	}
	total := res.Checked
	for res.Partial {
		res = verify(t, s, VerifyOptions{FromSeq: res.LastVerifiedSeq + 1, MaxRows: 100})
		if !res.OK {
			t.Fatalf("resume = %+v", res)
		}
		total += res.Checked
	}
	if res.LastVerifiedSeq != 250 || total != 250 {
		t.Fatalf("final = %+v, total checked %d", res, total)
	}
	if res := verify(t, s, VerifyOptions{FromSeq: 251}); !res.OK || res.Checked != 0 {
		t.Fatalf("from past head = %+v", res)
	}
}

func TestVerifyResumeAfterDeletedPrev(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 9)
	exec(t, db, "DELETE FROM admin_audit WHERE seq = 4")
	if res := verify(t, s, VerifyOptions{FromSeq: 5}); res.OK || res.FirstBadSeq != 4 {
		t.Fatalf("Verify = %+v, want firstBadSeq=4", res)
	}
	// A deleted genesis is caught from the start too.
	s2, db2 := freshStore(t)
	record(t, s2, 2)
	exec(t, db2, "DELETE FROM admin_audit WHERE seq = 1")
	if res := verify(t, s2, VerifyOptions{}); res.OK || res.FirstBadSeq != 1 || res.Reason != ReasonSeqGap {
		t.Fatalf("Verify = %+v, want seq_gap at 1", res)
	}
}

// TestVerifyActorHMAC: with the HMAC key, a side row whose sub no longer
// matches the signed actor_id fails; without it, the side table is not checked.
func TestVerifyActorHMAC(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 3)
	exec(t, db, "UPDATE admin_audit_actor SET sub = 'mallory' WHERE seq = 3")
	if res := verify(t, s, VerifyOptions{}); !res.OK {
		t.Fatalf("without HMAC key = %+v", res)
	}
	res := verify(t, s, VerifyOptions{HMACKey: testHMACKey})
	if res.OK || res.FirstBadSeq != 3 || res.Reason != ReasonActorID {
		t.Fatalf("with HMAC key = %+v, want actor_id at 3", res)
	}
	exec(t, db, "UPDATE admin_audit_actor SET sub = '' WHERE seq = 3")
	if res := verify(t, s, VerifyOptions{HMACKey: testHMACKey}); res.OK || res.FirstBadSeq != 3 {
		t.Fatalf("emptied sub = %+v", res)
	}
}

func TestVerifyUnknownKey(t *testing.T) {
	v := newChainVerifier(nil)
	signer := newSigner(t)
	e := Entry{V: 1, Seq: 1, Action: ActionGenesis, PrevHash: make([]byte, 32), KeyID: "x"}
	// A genesis that declares no key at all.
	h, _ := e.entryHash()
	e.EntryHash, e.Signature = h, signer.SignBytes(h)
	if bad, reason := v.check(storedRow{entry: e}); bad != 1 || reason != ReasonDeclaredKey {
		t.Fatalf("check = %d %s", bad, reason)
	}
	// A regular entry whose key_id no key-defining entry declared.
	v = newChainVerifier(nil)
	v.havePrev, v.prev = true, headRow{Seq: 1, Hash: h, KeyID: "k"}
	e2 := Entry{V: 1, Seq: 2, Action: "policy.update", PrevHash: h, KeyID: "k"}
	h2, _ := e2.entryHash()
	e2.EntryHash, e2.Signature = h2, signer.SignBytes(h2)
	if bad, reason := v.check(storedRow{entry: e2}); bad != 2 || reason != ReasonUnknownKey {
		t.Fatalf("check = %d %s", bad, reason)
	}
	// A malformed row.
	if bad, reason := v.check(storedRow{entry: e2, malformed: true}); bad != 2 || reason != ReasonMalformed {
		t.Fatalf("check = %d %s", bad, reason)
	}
	// A key_id redeclared with a different key.
	v = newChainVerifier(nil)
	other := newSigner(t)
	v.keys[audit.KeyID(signer.PubKey())] = other.PubKey()
	g := Entry{V: 1, Seq: 1, Action: ActionGenesis, PrevHash: make([]byte, 32), KeyID: audit.KeyID(signer.PubKey()),
		Details: map[string]string{detailPublicKey: pubB64(signer.PubKey())}}
	hg, _ := g.entryHash()
	g.EntryHash, g.Signature = hg, signer.SignBytes(hg)
	if bad, reason := v.check(storedRow{entry: g}); bad != 1 || reason != ReasonDeclaredKey {
		t.Fatalf("check = %d %s", bad, reason)
	}
	// A wrong algorithm.
	v = newChainVerifier(nil)
	g.Details[detailAlg] = "rsa"
	hg, _ = g.entryHash()
	g.EntryHash, g.Signature = hg, signer.SignBytes(hg)
	if bad, reason := v.check(storedRow{entry: g}); bad != 1 || reason != ReasonDeclaredKey {
		t.Fatalf("check = %d %s", bad, reason)
	}
}
