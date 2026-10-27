package adminaudit

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/cpstate"
)

// TestStoreConcurrentAppend appends 1000 entries from 50 goroutines split
// across two *cpstate.DB handles on one file (two connections, as the CP and an
// offline CLI would have). BEGIN IMMEDIATE must serialise them into one chain.
func TestStoreConcurrentAppend(t *testing.T) {
	path := dbPath(t)
	signer := newSigner(t)
	s1 := newStore(t, openDB(t, path), signer)
	s2 := newStore(t, openDB(t, path), signer)

	const workers, per = 50, 20
	var wg sync.WaitGroup
	errs := make(chan error, workers*per)
	for w := range workers {
		s := s1
		if w%2 == 1 {
			s = s2
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range per {
				if _, err := s.Record(context.Background(), input(w*per+i)); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("Record: %v", err)
	}

	res := verify(t, s1, VerifyOptions{HMACKey: testHMACKey})
	if !res.OK || res.Checked != workers*per+1 || res.HeadSeq != workers*per+1 {
		t.Fatalf("Verify = %+v, want ok with checked=headSeq=%d", res, workers*per+1)
	}
	var n, maxSeq int64
	if err := s2.db.SQL().QueryRow("SELECT count(*), max(seq) FROM admin_audit").Scan(&n, &maxSeq); err != nil {
		t.Fatal(err)
	}
	if n != maxSeq || n != workers*per+1 {
		t.Fatalf("count=%d max(seq)=%d, want both %d (no gaps)", n, maxSeq, workers*per+1)
	}
	var genesis int
	if err := s1.db.SQL().QueryRow("SELECT count(*) FROM admin_audit WHERE action = ?", ActionGenesis).Scan(&genesis); err != nil {
		t.Fatal(err)
	}
	if genesis != 1 {
		t.Fatalf("genesis rows = %d, want 1", genesis)
	}
}

func TestRecordWritesGenesisAndSideRow(t *testing.T) {
	s, db := freshStore(t)
	in := input(1)
	e, err := s.Record(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if e.Seq != 2 || e.V != 1 || e.KeyID != audit.KeyID(s.signer.PubKey()) || len(e.EntryHash) != 32 || len(e.Signature) != 64 {
		t.Fatalf("entry = %+v", e)
	}
	if e.ActorID != hmacHex(testHMACKey, in.Actor.Sub) {
		t.Fatalf("actor_id = %q, want HMAC(sub)", e.ActorID)
	}
	if !audit.VerifyBytes(s.signer.PubKey(), e.EntryHash, e.Signature) {
		t.Fatal("returned signature does not verify")
	}
	items, err := s.List(context.Background(), Filter{}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("List = %d items, want 2", len(items))
	}
	g := items[1]
	if g.Seq != 1 || g.Action != ActionGenesis || g.ActorID != "system" || g.AuthMethod != AuthMethodSystem ||
		!isZero(g.PrevHash) || len(g.PrevHash) != 32 {
		t.Fatalf("genesis = %+v", g.Entry)
	}
	if g.Details[detailAlg] != "ed25519" || g.Details[detailPublicKey] != pubB64(s.signer.PubKey()) ||
		g.Details[detailActorKeyCheck] != actorKeyCheck(testHMACKey) || len(g.Details[detailActorKeyCheck]) != 16 {
		t.Fatalf("genesis details = %v", g.Details)
	}
	if items[0].Actor != in.Actor || g.Actor != (Actor{}) {
		t.Fatalf("side rows: %+v / %+v", items[0].Actor, g.Actor)
	}
	if n := rowCount(t, db, "admin_audit_actor"); n != 1 {
		t.Fatalf("side rows = %d, want 1", n)
	}

	// An empty sub is anonymous and writes no side row.
	anon := input(2)
	anon.Actor = Actor{}
	e, err = s.Record(context.Background(), anon)
	if err != nil {
		t.Fatal(err)
	}
	if e.ActorID != "anonymous" || rowCount(t, db, "admin_audit_actor") != 1 {
		t.Fatalf("anonymous actor_id = %q", e.ActorID)
	}
}

// TestStoreTamper changes one column of row N (or deletes it) and expects
// Verify to fail with firstBadSeq = N.
func TestStoreTamper(t *testing.T) {
	const n = 6
	cases := map[string]string{
		"ts_unix_nano": "UPDATE admin_audit SET ts_unix_nano = ts_unix_nano + 1 WHERE seq = ?",
		"actor_id":     "UPDATE admin_audit SET actor_id = 'someone-else' WHERE seq = ?",
		"actor_role":   "UPDATE admin_audit SET actor_role = 'viewer' WHERE seq = ?",
		"auth_method":  "UPDATE admin_audit SET auth_method = 'cli' WHERE seq = ?",
		"action":       "UPDATE admin_audit SET action = 'settings.update' WHERE seq = ?",
		"target":       "UPDATE admin_audit SET target = 'settings' WHERE seq = ?",
		"target_ref":   "UPDATE admin_audit SET target_ref = 'x' WHERE seq = ?",
		"details_json": `UPDATE admin_audit SET details_json = '{"n":"999"}' WHERE seq = ?`,
		"details_bad":  `UPDATE admin_audit SET details_json = 'not json' WHERE seq = ?`,
		"outcome":      "UPDATE admin_audit SET outcome = 'denied' WHERE seq = ?",
		"http_status":  "UPDATE admin_audit SET http_status = 403 WHERE seq = ?",
		"before_hash":  "UPDATE admin_audit SET before_hash = 'b' WHERE seq = ?",
		"after_hash":   "UPDATE admin_audit SET after_hash = 'a' WHERE seq = ?",
		"client_ip":    "UPDATE admin_audit SET client_ip = '198.51.100.1' WHERE seq = ?",
		"request_id":   "UPDATE admin_audit SET request_id = 'other' WHERE seq = ?",
		"key_id":       "UPDATE admin_audit SET key_id = '0000000000000000' WHERE seq = ?",
		"prev_hash":    "UPDATE admin_audit SET prev_hash = randomblob(32) WHERE seq = ?",
		"entry_hash":   "UPDATE admin_audit SET entry_hash = randomblob(32) WHERE seq = ?",
		"signature":    "UPDATE admin_audit SET signature = randomblob(64) WHERE seq = ?",
		"seq":          "UPDATE admin_audit SET seq = 1000 WHERE seq = ?",
		"delete":       "DELETE FROM admin_audit WHERE seq = ?",
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			s, db := freshStore(t)
			record(t, s, 10)
			if res := verify(t, s, VerifyOptions{}); !res.OK {
				t.Fatalf("untouched chain: %+v", res)
			}
			exec(t, db, q, n)
			res := verify(t, s, VerifyOptions{})
			if res.OK || res.FirstBadSeq != n {
				t.Fatalf("Verify after %s = %+v, want ok=false firstBadSeq=%d", name, res, n)
			}
			if res.LastVerifiedSeq != n-1 || res.Checked != n-1 {
				t.Fatalf("LastVerifiedSeq=%d Checked=%d, want %d", res.LastVerifiedSeq, res.Checked, n-1)
			}
		})
	}
	t.Run("genesis", func(t *testing.T) {
		s, db := freshStore(t)
		record(t, s, 3)
		exec(t, db, `UPDATE admin_audit SET details_json = '{"alg":"ed25519"}' WHERE seq = 1`)
		if res := verify(t, s, VerifyOptions{}); res.OK || res.FirstBadSeq != 1 {
			t.Fatalf("Verify = %+v, want firstBadSeq=1", res)
		}
	})
}

// TestStoreAnchor: deleting the newest row leaves a chain that verifies on its
// own, but not against the previously observed head.
func TestStoreAnchor(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 5)
	seq, hash, _, err := s.Head(context.Background())
	if err != nil || seq != 6 {
		t.Fatalf("Head = %d, %v", seq, err)
	}
	anchor := &Anchor{Seq: seq, Hash: hash}
	if res := verify(t, s, VerifyOptions{Anchor: anchor}); !res.OK {
		t.Fatalf("intact chain against its head: %+v", res)
	}
	if res := verify(t, s, VerifyOptions{Anchor: &Anchor{Seq: 3, Hash: hash}}); res.OK || res.FirstBadSeq != 3 || res.Reason != ReasonAnchorMismatch {
		t.Fatalf("wrong anchor hash: %+v", res)
	}

	exec(t, db, "DELETE FROM admin_audit WHERE seq = ?", seq)
	if res := verify(t, s, VerifyOptions{}); !res.OK || res.HeadSeq != seq-1 {
		t.Fatalf("plain Verify after tail delete = %+v, want ok", res)
	}
	res := verify(t, s, VerifyOptions{Anchor: anchor})
	if res.OK || res.FirstBadSeq != seq || res.Reason != ReasonAnchorMissing {
		t.Fatalf("anchored Verify after tail delete = %+v, want firstBadSeq=%d anchor_missing", res, seq)
	}
}

// TestAppendKeyIDMismatch: a store whose key differs from the head's refuses
// to extend the chain and writes nothing.
func TestAppendKeyIDMismatch(t *testing.T) {
	path := dbPath(t)
	db := openDB(t, path)
	a := newStore(t, db, newSigner(t))
	record(t, a, 2)
	b := newStore(t, openDB(t, path), newSigner(t))
	before := rowCount(t, db, "admin_audit")
	_, err := b.Record(context.Background(), input(9))
	if !errors.Is(err, ErrKeyIDMismatch) {
		t.Fatalf("err = %v, want ErrKeyIDMismatch", err)
	}
	for _, id := range []string{a.KeyID(), b.KeyID()} {
		if !strings.Contains(err.Error(), id) {
			t.Fatalf("error %q does not name key_id %s", err, id)
		}
	}
	if got := rowCount(t, db, "admin_audit"); got != before {
		t.Fatalf("rows = %d, want %d (nothing written)", got, before)
	}
	if got := rowCount(t, db, "admin_audit_actor"); got != 2 {
		t.Fatalf("side rows = %d, want 2", got)
	}
}

func TestEntryValidation(t *testing.T) {
	cases := []struct {
		field string
		mut   func(*Input)
	}{
		{"auth_method", func(in *Input) { in.AuthMethod = "password" }},
		{"auth_method", func(in *Input) { in.AuthMethod = "" }},
		{"outcome", func(in *Input) { in.Outcome = "maybe" }},
		{"action", func(in *Input) { in.Action = "Policy.Update" }},
		{"action", func(in *Input) { in.Action = "policy..update" }},
		{"action", func(in *Input) { in.Action = "" }},
		{"action", func(in *Input) { in.Action = strings.Repeat("a", 65) }},
		{"actor_role", func(in *Input) { in.ActorRole = "ad\nmin" }},
		{"target", func(in *Input) { in.Target = strings.Repeat("t", 65) }},
		{"target", func(in *Input) { in.Target = "\xff" }},
		{"target_ref", func(in *Input) { in.TargetRef = strings.Repeat("r", 257) }},
		{"target_ref", func(in *Input) { in.TargetRef = "secret:\x01" }},
		{"request_id", func(in *Input) { in.RequestID = "req id" }},
		{"request_id", func(in *Input) { in.RequestID = strings.Repeat("r", 65) }},
		{"before_hash", func(in *Input) { in.BeforeHash = strings.Repeat("b", 129) }},
		{"after_hash", func(in *Input) { in.AfterHash = "é" }},
		{"http_status", func(in *Input) { in.HTTPStatus = 600 }},
		{"http_status", func(in *Input) { in.HTTPStatus = -1 }},
		{"client_ip", func(in *Input) { in.ClientIP = "not-an-ip" }},
		{"details", func(in *Input) {
			in.Details = map[string]string{}
			for i := range 17 {
				in.Details[strings.Repeat("k", i+1)] = "v"
			}
		}},
		{"details", func(in *Input) { in.Details = map[string]string{strings.Repeat("k", 33): "v"} }},
		{"details", func(in *Input) { in.Details = map[string]string{"": "v"} }},
		{"details", func(in *Input) { in.Details = map[string]string{"k": strings.Repeat("v", 257)} }},
		{"details", func(in *Input) { in.Details = map[string]string{"k": "\xff"} }},
	}
	s, db := freshStore(t)
	for _, c := range cases {
		in := input(1)
		c.mut(&in)
		_, err := s.Record(context.Background(), in)
		if !errors.Is(err, ErrInvalidEntry) || !strings.Contains(err.Error(), "field "+c.field) {
			t.Errorf("%s: err = %v, want ErrInvalidEntry naming the field", c.field, err)
		}
	}
	if n := rowCount(t, db, "admin_audit"); n != 0 {
		t.Fatalf("rows = %d, want 0 (invalid entries write nothing, not even genesis)", n)
	}

	// Boundary values are accepted.
	ok := input(1)
	ok.Action = strings.Repeat("a", 64)
	ok.Target = strings.Repeat("t", 64)
	ok.TargetRef = strings.Repeat("r", 256)
	ok.RequestID = strings.Repeat("R", 64)
	ok.BeforeHash = strings.Repeat("b", 128)
	ok.HTTPStatus = 599
	ok.ClientIP = "2001:db8::1"
	ok.Details = map[string]string{strings.Repeat("k", 32): strings.Repeat("v", 256)}
	for _, m := range []string{AuthMethodBreakglass, AuthMethodCLI, AuthMethodBearer, AuthMethodNone, AuthMethodSystem} {
		ok.AuthMethod = m
		for _, o := range []string{OutcomeDenied, OutcomeRejected, OutcomeError} {
			ok.Outcome = o
			if _, err := s.Record(context.Background(), ok); err != nil {
				t.Fatalf("valid input (%s/%s): %v", m, o, err)
			}
		}
	}
	ok.ClientIP, ok.HTTPStatus, ok.RequestID = "", 0, ""
	if _, err := s.Record(context.Background(), ok); err != nil {
		t.Fatalf("empty optional fields: %v", err)
	}
	if res := verify(t, s, VerifyOptions{HMACKey: testHMACKey}); !res.OK {
		t.Fatalf("Verify = %+v", res)
	}
}

// TestNoIdentityInErrors: the actor's sub and email never appear in an error,
// nor anywhere in the signed admin_audit row (only in the side table).
func TestNoIdentityInErrors(t *testing.T) {
	const sub, email = "sub-7f3a-identity", "carol.identity@example.com"
	path := dbPath(t)
	db := openDB(t, path)
	s := newStore(t, db, newSigner(t))
	in := input(1)
	in.Actor = Actor{Sub: sub, Email: email}
	if _, err := s.Record(context.Background(), in); err != nil {
		t.Fatal(err)
	}

	var errs []error
	bad := in
	bad.Outcome = "nope"
	_, err := s.Record(context.Background(), bad)
	errs = append(errs, err)
	other := newStore(t, openDB(t, path), newSigner(t))
	_, err = other.Record(context.Background(), in)
	errs = append(errs, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.Record(ctx, in)
	errs = append(errs, err)
	closed := newStore(t, openDB(t, dbPath(t)), newSigner(t))
	_ = closed.db.Close()
	_, err = closed.Record(context.Background(), in)
	errs = append(errs, err)
	for i, err := range errs {
		if err == nil {
			t.Fatalf("case %d: want an error", i)
		}
		if strings.Contains(err.Error(), sub) || strings.Contains(err.Error(), email) {
			t.Fatalf("case %d: error leaks identity: %v", i, err)
		}
	}

	rows, err := db.SQL().Query("SELECT * FROM admin_audit")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		for i, v := range vals {
			var str string
			switch x := v.(type) {
			case string:
				str = x
			case []byte:
				str = string(x)
			}
			if strings.Contains(str, sub) || strings.Contains(str, email) {
				t.Fatalf("column %s of admin_audit holds plaintext identity", cols[i])
			}
		}
	}
}

func TestRecordNeedsSignerAndKey(t *testing.T) {
	db := openDB(t, dbPath(t))
	if _, err := NewStore(db, Options{HMACKey: testHMACKey}).Record(context.Background(), input(1)); err == nil {
		t.Fatal("no signer: want error")
	}
	if _, err := NewStore(db, Options{Signer: newSigner(t)}).Record(context.Background(), input(1)); err == nil {
		t.Fatal("no HMAC key: want error")
	}
	if n := rowCount(t, db, "admin_audit"); n != 0 {
		t.Fatalf("rows = %d", n)
	}
	// The default clock is the real one.
	s := NewStore(db, Options{Signer: newSigner(t), HMACKey: testHMACKey})
	e, err := s.Record(context.Background(), input(1))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(time.Unix(0, e.TSUnixNano)); d < 0 || d > time.Minute {
		t.Fatalf("ts = %v off from now", d)
	}
}

func TestHeadAndReadOnlyStore(t *testing.T) {
	path := dbPath(t)
	s := newStore(t, openDB(t, path), newSigner(t))
	seq, h, kid, err := s.Head(context.Background())
	if err != nil || seq != 0 || h != nil || kid != "" {
		t.Fatalf("empty Head = %d %x %q %v", seq, h, kid, err)
	}
	if res := verify(t, s, VerifyOptions{}); !res.OK || res.Checked != 0 {
		t.Fatalf("empty Verify = %+v", res)
	}
	e, err := s.Record(context.Background(), input(1))
	if err != nil {
		t.Fatal(err)
	}
	ro, err := cpstate.OpenReadOnly(context.Background(), path, Migrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close() })
	r := NewStore(ro, Options{})
	seq, h, kid, err = r.Head(context.Background())
	if err != nil || seq != 2 || !equalHash(h, e.EntryHash) || kid != s.KeyID() {
		t.Fatalf("Head = %d %x %q %v", seq, h, kid, err)
	}
	if res := verify(t, r, VerifyOptions{}); !res.OK || res.Checked != 2 || !equalHash(res.HeadHash, e.EntryHash) {
		t.Fatalf("read-only Verify = %+v", res)
	}
	if r.KeyID() != "" {
		t.Fatal("read-only store has a key id")
	}
}

func TestList(t *testing.T) {
	s, _ := freshStore(t)
	fc := s.clock.(interface{ Advance(time.Duration) })
	record(t, s, 5) // seqs 2..6 with subs user-0, 1, 2, 0, 1
	fc.Advance(time.Hour)
	denied := input(7)
	denied.Outcome, denied.Action = OutcomeDenied, "settings.update"
	if _, err := s.Record(context.Background(), denied); err != nil { // seq 7, user-1
		t.Fatal(err)
	}
	seqs := func(items []ListItem) []int64 {
		out := make([]int64, 0, len(items))
		for _, it := range items {
			out = append(out, it.Seq)
		}
		return out
	}
	ctx := context.Background()
	check := func(name string, f Filter, limit int, cursor int64, want ...int64) {
		t.Helper()
		items, err := s.List(ctx, f, limit, cursor)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := seqs(items); !slices.Equal(got, want) {
			t.Fatalf("%s: seqs = %v, want %v", name, got, want)
		}
	}
	check("all newest first", Filter{}, 0, 0, 7, 6, 5, 4, 3, 2, 1)
	check("limit", Filter{}, 2, 0, 7, 6)
	check("cursor", Filter{}, 2, 6, 5, 4)
	check("action", Filter{Action: "settings.update"}, 0, 0, 7)
	check("outcome", Filter{Outcome: OutcomeOK}, 0, 0, 6, 5, 4, 3, 2, 1)
	check("actor by sub", Filter{Actor: "user-1"}, 0, 0, 7, 6, 3)
	check("actor by id", Filter{Actor: hmacHex(testHMACKey, "user-0")}, 0, 0, 5, 2)
	check("since", Filter{Since: s.clock.Now()}, 0, 0, 7)

	items, err := s.List(ctx, Filter{Actor: "user-1"}, 0, 0)
	if err != nil || items[0].Actor.Email != "user1@example.com" {
		t.Fatalf("side identity: %+v %v", items, err)
	}

	big, _ := freshStore(t)
	record(t, big, 250)
	if items, _ := big.List(ctx, Filter{}, 1000, 0); len(items) != 200 {
		t.Fatalf("clamp: %d items, want 200", len(items))
	}
	if items, _ := big.List(ctx, Filter{}, -1, 0); len(items) != 50 {
		t.Fatalf("default: %d items, want 50", len(items))
	}
}

func TestPubKeysFromChain(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 1)
	keys, err := s.PubKeys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := KeyInfo{KeyID: audit.KeyID(s.signer.PubKey()), PublicKey: pubB64(s.signer.PubKey()), FirstSeq: 1}
	if len(keys) != 1 || keys[0] != want {
		t.Fatalf("PubKeys = %+v, want [%+v]", keys, want)
	}
}

func TestStoreErrorsOnClosedDB(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 1)
	_ = db.Close()
	ctx := context.Background()
	if _, _, _, err := s.Head(ctx); err == nil {
		t.Error("Head: want error")
	}
	if _, err := s.List(ctx, Filter{}, 0, 0); err == nil {
		t.Error("List: want error")
	}
	if _, err := s.PubKeys(ctx); err == nil {
		t.Error("PubKeys: want error")
	}
	if _, err := s.Verify(ctx, VerifyOptions{}); err == nil {
		t.Error("Verify: want error")
	}
}
