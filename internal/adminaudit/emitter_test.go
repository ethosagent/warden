package adminaudit

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
)

// recordingEmitter is a fake Emitter that keeps every call.
type recordingEmitter struct {
	mu          sync.Mutex
	entries     []Entry
	who         []Identity
	checkpoints []Checkpoint
	cpCh        chan Checkpoint
}

func (r *recordingEmitter) Emit(e Entry, who Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	r.who = append(r.who, who)
}

func (r *recordingEmitter) Checkpoint(c Checkpoint) {
	r.mu.Lock()
	r.checkpoints = append(r.checkpoints, c)
	r.mu.Unlock()
	if r.cpCh != nil {
		r.cpCh <- c
	}
}

// syncBuf is a goroutine-safe bytes.Buffer for a captured slog handler.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// captureLogger returns a JSON logger at level error (so a line that obeyed
// the level would be dropped) and its buffer.
func captureLogger() (*slog.Logger, *syncBuf) {
	buf := &syncBuf{}
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelError})), buf
}

// linesWithMsg decodes every JSON line whose msg is msg.
func linesWithMsg(t *testing.T, logs, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(logs, "\n") {
		if l == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func TestSlogEmitterOneLinePerEntry(t *testing.T) {
	s, _ := freshStore(t)
	if err := s.EnsureGenesis(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger, buf := captureLogger()
	s.SetEmitter(NewSlogEmitter(logger))

	var committed []Entry
	for i := range 3 {
		e, err := s.Record(context.Background(), input(i))
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
		committed = append(committed, e)
	}
	// A failed append (validation) emits nothing.
	bad := input(9)
	bad.Outcome = "nope"
	if _, err := s.Record(context.Background(), bad); err == nil {
		t.Fatal("Record with a bad outcome = nil error")
	}

	lines := linesWithMsg(t, buf.String(), "admin_audit")
	if len(lines) != len(committed) {
		t.Fatalf("got %d admin_audit lines, want %d:\n%s", len(lines), len(committed), buf.String())
	}
	for i, l := range lines {
		e := committed[i]
		in := input(i)
		want := map[string]any{
			"schema":      SchemaV1,
			"level":       "INFO",
			"seq":         float64(e.Seq),
			"entry_hash":  hex.EncodeToString(e.EntryHash),
			"prev_hash":   hex.EncodeToString(e.PrevHash),
			"key_id":      e.KeyID,
			"actor_id":    e.ActorID,
			"actor_sub":   in.Actor.Sub,
			"actor_email": in.Actor.Email,
			"actor_role":  "admin",
			"auth_method": AuthMethodOIDC,
			"action":      "policy.update",
			"target":      "policy",
			"target_ref":  in.TargetRef,
			"outcome":     OutcomeOK,
			"http_status": float64(200),
			"before_hash": "hmac:before",
			"after_hash":  "hmac:after",
			"client_ip":   "192.0.2.10",
			"request_id":  in.RequestID,
			"ts":          time.Unix(0, e.TSUnixNano).UTC().Format(time.RFC3339Nano),
		}
		for k, v := range want {
			if l[k] != v {
				t.Errorf("line %d: %s = %v, want %v", i, k, l[k], v)
			}
		}
		d, _ := l["details"].(map[string]any)
		if d["n"] != in.Details["n"] {
			t.Errorf("line %d: details = %v, want %v", i, l["details"], in.Details)
		}
	}
}

func TestEmitterGetsEveryCommittedRowWithIdentity(t *testing.T) {
	s, _ := freshStore(t)
	rec := &recordingEmitter{}
	s.SetEmitter(rec)
	// On an empty chain the first Record also commits genesis: both rows are
	// emitted, genesis first and with no identity.
	e, err := s.Record(context.Background(), input(1))
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.entries) != 2 || rec.entries[0].Action != ActionGenesis || rec.entries[1].Seq != e.Seq {
		t.Fatalf("emitted %+v, want genesis then seq %d", rec.entries, e.Seq)
	}
	if rec.who[0] != (Identity{}) {
		t.Errorf("genesis identity = %+v, want empty", rec.who[0])
	}
	if rec.who[1] != (Identity{Sub: "user-1", Email: "user1@example.com"}) {
		t.Errorf("identity = %+v, want the recorded actor", rec.who[1])
	}
	// A no-op append (genesis already present) emits nothing.
	if err := s.EnsureGenesis(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rec.entries) != 2 {
		t.Errorf("EnsureGenesis on a non-empty chain emitted %d more entries", len(rec.entries)-2)
	}
}

func TestEmitterNotCalledOnFailedAppend(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 1)
	rec := &recordingEmitter{}
	s.SetEmitter(rec)
	// A chain head on another key refuses the append: nothing is emitted.
	other := newStore(t, db, newSigner(t))
	other.SetEmitter(rec)
	if _, err := other.Record(context.Background(), input(2)); err == nil {
		t.Fatal("Record on a foreign-key head = nil error")
	}
	if len(rec.entries) != 0 {
		t.Fatalf("emitted %d entries for a failed append", len(rec.entries))
	}
}

func TestSetEmitterTwicePanics(t *testing.T) {
	s, _ := freshStore(t)
	s.SetEmitter(&recordingEmitter{})
	defer func() {
		if recover() == nil {
			t.Fatal("second SetEmitter did not panic")
		}
	}()
	s.SetEmitter(&recordingEmitter{})
}

type panicEmitter struct{}

func (panicEmitter) Emit(Entry, Identity)  { panic("sink exploded") }
func (panicEmitter) Checkpoint(Checkpoint) { panic("sink exploded") }

func TestEmitterPanicDoesNotAffectAppend(t *testing.T) {
	logger, buf := captureLogger()
	db := openDB(t, dbPath(t))
	s := NewStore(db, Options{
		Signer: newSigner(t), HMACKey: testHMACKey, Logger: logger,
		Clock: clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err := s.EnsureGenesis(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.SetEmitter(panicEmitter{})

	e, err := s.Record(context.Background(), input(1))
	if err != nil {
		t.Fatalf("Record with a panicking emitter = %v, want nil", err)
	}
	seq, hash, _, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if seq != e.Seq || !bytes.Equal(hash, e.EntryHash) {
		t.Fatalf("head = %d, want the appended seq %d (append rolled back?)", seq, e.Seq)
	}
	if res := verify(t, s, VerifyOptions{}); !res.OK {
		t.Fatalf("Verify after a panicking emitter = %+v", res)
	}
	lines := linesWithMsg(t, buf.String(), "admin_audit emitter panicked")
	if len(lines) != 1 {
		t.Fatalf("got %d panic log lines, want exactly 1:\n%s", len(lines), buf.String())
	}
	if lines[0]["seq"] != float64(e.Seq) || lines[0]["level"] != "ERROR" {
		t.Errorf("panic line = %v, want level ERROR and seq %d", lines[0], e.Seq)
	}
	if strings.Contains(buf.String(), "user-1") || strings.Contains(buf.String(), "user1@example.com") {
		t.Error("panic log line leaks the actor sub or email")
	}
}

func TestEmitterNoSecretLeak(t *testing.T) {
	const canary = "s3cr3t-canary-123"
	s, _ := freshStore(t)
	if err := s.EnsureGenesis(context.Background()); err != nil {
		t.Fatal(err)
	}
	logger, buf := captureLogger()
	s.SetEmitter(NewSlogEmitter(logger))
	// The emitter writes only the fields of the validated Entry: a caller can
	// hand the store nothing but Input fields, so a request body or bearer
	// token (here the canary) has no way into the line. The HTTP version of
	// this check is in internal/controlplane.
	if _, err := s.Record(context.Background(), input(1)); err != nil {
		t.Fatal(err)
	}
	logs := buf.String()
	if strings.Contains(logs, canary) {
		t.Fatal("emitted line contains the canary")
	}
	lines := linesWithMsg(t, logs, "admin_audit")
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	allowed := map[string]bool{"time": true, "level": true, "msg": true, "schema": true}
	for _, k := range SlogEntryFields {
		allowed[k] = true
	}
	for k := range lines[0] {
		if !allowed[k] {
			t.Errorf("emitted line has field %q outside the Entry field list", k)
		}
	}
	for _, k := range []string{"body", "authorization", "signature"} {
		if _, ok := lines[0][k]; ok {
			t.Errorf("emitted line has a %q field", k)
		}
	}
}

func TestCheckpointInterval(t *testing.T) {
	s, _ := freshStore(t)
	record(t, s, 2)
	clk := clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	logger, buf := captureLogger()
	slogE := NewSlogEmitter(logger)
	rec := &recordingEmitter{cpCh: make(chan Checkpoint, 4)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunCheckpoints(ctx, s, multiEmitter{slogE, rec}, DefaultCheckpointInterval, clk)
	}()

	start := waitCheckpoint(t, rec.cpCh)
	if start.HeadSeq != 3 || !start.At.Equal(clk.Now()) {
		t.Fatalf("startup checkpoint = %+v, want head seq 3 at %v", start, clk.Now())
	}
	// More rows, then 4m59s: no checkpoint yet.
	record(t, s, 1)
	clk.Advance(DefaultCheckpointInterval - time.Second)
	select {
	case c := <-rec.cpCh:
		t.Fatalf("checkpoint before the interval elapsed: %+v", c)
	default:
	}
	clk.Advance(time.Second)
	tick := waitCheckpoint(t, rec.cpCh)
	seq, hash, keyID, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tick.HeadSeq != seq || !bytes.Equal(tick.HeadHash, hash) || tick.KeyID != keyID {
		t.Fatalf("tick checkpoint = %+v, want head %d %x %s", tick, seq, hash, keyID)
	}
	// The next tick is re-armed for one more interval.
	clk.Advance(DefaultCheckpointInterval)
	waitCheckpoint(t, rec.cpCh)

	cancel()
	final := waitCheckpoint(t, rec.cpCh)
	<-done
	if final.HeadSeq != seq {
		t.Errorf("shutdown checkpoint head seq = %d, want %d", final.HeadSeq, seq)
	}
	if clk.PendingTimers() != 0 {
		t.Errorf("%d timers still pending after shutdown", clk.PendingTimers())
	}

	lines := linesWithMsg(t, buf.String(), "admin_audit.checkpoint")
	if len(lines) != 4 {
		t.Fatalf("got %d checkpoint lines, want 4 (startup, 2 ticks, shutdown):\n%s", len(lines), buf.String())
	}
	l := lines[1]
	if l["schema"] != SchemaV1 || l["head_seq"] != float64(seq) || l["head_entry_hash"] != hex.EncodeToString(hash) || l["key_id"] != keyID {
		t.Errorf("checkpoint line = %v", l)
	}
}

func TestCheckpointDetectsTailDeletion(t *testing.T) {
	s, db := freshStore(t)
	record(t, s, 4)
	clk := clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	logger, buf := captureLogger()
	ctx, cancel := context.WithCancel(context.Background())
	rec := &recordingEmitter{cpCh: make(chan Checkpoint, 4)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		RunCheckpoints(ctx, s, multiEmitter{NewSlogEmitter(logger), rec}, DefaultCheckpointInterval, clk)
	}()
	waitCheckpoint(t, rec.cpCh)
	clk.Advance(DefaultCheckpointInterval)
	waitCheckpoint(t, rec.cpCh)
	cancel()
	waitCheckpoint(t, rec.cpCh)
	<-done

	// The off-host copy keeps the last checkpoint line.
	lines := linesWithMsg(t, buf.String(), "admin_audit.checkpoint")
	last := lines[len(lines)-1]
	anchorHash, err := hex.DecodeString(last["head_entry_hash"].(string))
	if err != nil {
		t.Fatal(err)
	}
	anchor := Anchor{Seq: int64(last["head_seq"].(float64)), Hash: anchorHash}

	// An attacker with the state dir drops the newest two rows (the
	// append-only rule binds Go code, not someone holding the file).
	exec(t, db, "DELETE FROM admin_audit WHERE seq > ?", anchor.Seq-2)
	exec(t, db, "DELETE FROM admin_audit_actor WHERE seq > ?", anchor.Seq-2)

	seq, _, _, err := s.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if seq == anchor.Seq {
		t.Fatal("DB head still equals the checkpoint after deletion")
	}
	// Without the anchor the shorter chain verifies; with it, it does not.
	if res := verify(t, s, VerifyOptions{}); !res.OK {
		t.Fatalf("truncated chain without anchor = %+v, want OK (that is the gap anchors close)", res)
	}
	res := verify(t, s, VerifyOptions{Anchor: &anchor})
	if res.OK || res.Reason != ReasonAnchorMissing || res.FirstBadSeq != seq+1 {
		t.Fatalf("Verify with the checkpoint anchor = %+v, want anchor_missing at seq %d", res, seq+1)
	}
}

func TestCheckpointSurvivesPanicAndHeadError(t *testing.T) {
	logger, buf := captureLogger()
	db := openDB(t, dbPath(t))
	s := NewStore(db, Options{Signer: newSigner(t), HMACKey: testHMACKey, Logger: logger})
	if err := s.EnsureGenesis(context.Background()); err != nil {
		t.Fatal(err)
	}
	clk := clocktest.NewFake(time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC))
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // startup then shutdown checkpoint, both panicking
	RunCheckpoints(ctx, s, panicEmitter{}, 0, clk)
	if n := len(linesWithMsg(t, buf.String(), "admin_audit emitter panicked")); n != 2 {
		t.Fatalf("got %d panic lines, want 2:\n%s", n, buf.String())
	}

	// A head that cannot be read is logged, not emitted.
	_ = db.Close()
	rec := &recordingEmitter{}
	RunCheckpoints(ctx, s, rec, time.Minute, clk)
	if len(rec.checkpoints) != 0 {
		t.Errorf("emitted %d checkpoints with an unreadable head", len(rec.checkpoints))
	}
	if n := len(linesWithMsg(t, buf.String(), "admin_audit checkpoint failed")); n != 2 {
		t.Errorf("got %d checkpoint failure lines, want 2", n)
	}
}

func TestNewSlogEmitterNilLogger(t *testing.T) {
	// A nil logger falls back to slog.Default rather than panicking.
	e := NewSlogEmitter(nil)
	e.Checkpoint(Checkpoint{HeadSeq: 1, HeadHash: []byte{1}, KeyID: "k", At: time.Unix(0, 0)})
}

func waitCheckpoint(t *testing.T, ch <-chan Checkpoint) Checkpoint {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a checkpoint")
		return Checkpoint{}
	}
}

// multiEmitter fans out to several emitters (test only).
type multiEmitter []Emitter

func (m multiEmitter) Emit(e Entry, who Identity) {
	for _, x := range m {
		x.Emit(e, who)
	}
}

func (m multiEmitter) Checkpoint(c Checkpoint) {
	for _, x := range m {
		x.Checkpoint(c)
	}
}
