package adminaudit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/cpstate"
)

var testHMACKey = []byte("0123456789abcdef0123456789abcdef")

func dbPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "warden-cp.db")
}

func openDB(t *testing.T, path string) *cpstate.DB {
	t.Helper()
	db, err := cpstate.Open(context.Background(), path, Migrations())
	if err != nil {
		t.Fatalf("cpstate.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newSigner(t *testing.T) *audit.Signer {
	t.Helper()
	s, err := audit.NewSigner()
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func newStore(t *testing.T, db *cpstate.DB, signer *audit.Signer) *Store {
	t.Helper()
	return NewStore(db, Options{
		Signer:  signer,
		HMACKey: testHMACKey,
		Clock:   clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)),
	})
}

// freshStore opens a new DB file with a new key.
func freshStore(t *testing.T) (*Store, *cpstate.DB) {
	t.Helper()
	db := openDB(t, dbPath(t))
	return newStore(t, db, newSigner(t)), db
}

func input(i int) Input {
	return Input{
		Actor:      Actor{Sub: fmt.Sprintf("user-%d", i%3), Email: fmt.Sprintf("user%d@example.com", i%3)},
		ActorRole:  "admin",
		AuthMethod: AuthMethodOIDC,
		Action:     "policy.update",
		Target:     "policy",
		TargetRef:  fmt.Sprintf("policy@etag-%d", i),
		Details:    map[string]string{"n": fmt.Sprint(i)},
		Outcome:    OutcomeOK,
		HTTPStatus: 200,
		BeforeHash: "hmac:before",
		AfterHash:  "hmac:after",
		ClientIP:   "192.0.2.10",
		RequestID:  fmt.Sprintf("req-%d", i),
	}
}

func record(t *testing.T, s *Store, n int) {
	t.Helper()
	for i := range n {
		if _, err := s.Record(context.Background(), input(i)); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
}

func rowCount(t *testing.T, db *cpstate.DB, table string) int {
	t.Helper()
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func exec(t *testing.T, db *cpstate.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.SQL().Exec(q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func verify(t *testing.T, s *Store, opts VerifyOptions) Result {
	t.Helper()
	res, err := s.Verify(context.Background(), opts)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return res
}

// appendSegmentStart hand-builds the audit.segment_start entry W-P1-AAUD-05
// will write: signed by s's (new) key, declaring it, linked to the old head.
func appendSegmentStart(t *testing.T, s *Store) Entry {
	t.Helper()
	e, err := s.appendTx(context.Background(), func(head headRow) (*Entry, *Actor, error) {
		return &Entry{
			ActorID: actorIDSystem, ActorRole: actorIDSystem, AuthMethod: AuthMethodSystem,
			Action: ActionSegmentStart, Target: "admin_audit", Outcome: OutcomeOK,
			Details: map[string]string{
				detailAlg:         algEd25519,
				detailPublicKey:   base64.StdEncoding.EncodeToString(s.signer.PubKey()),
				"previous_key_id": head.KeyID,
			},
		}, nil, nil
	})
	if err != nil {
		t.Fatalf("append segment_start: %v", err)
	}
	return e
}

// appendUnchecked appends a regular entry with s's key, skipping the key
// discipline Record enforces (to build an illegal key change).
func appendUnchecked(t *testing.T, s *Store, in Input) Entry {
	t.Helper()
	e, err := s.appendTx(context.Background(), func(headRow) (*Entry, *Actor, error) {
		return &Entry{
			ActorID: s.actorID(in.Actor.Sub), ActorRole: in.ActorRole, AuthMethod: in.AuthMethod,
			Action: in.Action, Target: in.Target, Outcome: in.Outcome,
		}, nil, nil
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return e
}

func pubB64(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }
