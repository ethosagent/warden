package adminaudit

import (
	"context"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/clock"
)

// SchemaV1 is the schema value of every emitted admin audit log line.
const SchemaV1 = "warden.admin.v1"

// DefaultCheckpointInterval is how often RunCheckpoints emits the chain head.
const DefaultCheckpointInterval = 5 * time.Minute

// Log message keys of the emitted lines.
const (
	msgEntry      = "admin_audit"
	msgCheckpoint = "admin_audit.checkpoint"
)

// Emitter receives every committed entry and the periodic head checkpoints,
// so an off-host copy of what it writes anchors the chain: deleting the
// newest rows or restoring an older backup no longer matches the copy. The
// store calls Emit synchronously on the recording goroutine, after the
// append's transaction has committed and its connection is released: a slow
// sink delays that caller's return (never the append itself or other
// appends' transactions), so an implementation must be fast or hand off to
// its own buffered writer. An Emitter must not call back into the store.
// W-P1-JAUD-03 plugs auditlog.Writer in here.
type Emitter interface {
	Emit(e Entry, who Identity)
	Checkpoint(c Checkpoint)
}

// Identity is the plaintext actor of an entry. It is not part of the signed
// bytes (the chain stores only actor_id = HMAC(sub)); it is empty for entries
// the store writes itself (genesis, segment_start).
type Identity struct {
	Sub   string
	Email string
}

// Checkpoint is the chain head at instant At.
type Checkpoint struct {
	HeadSeq  int64
	HeadHash []byte
	KeyID    string
	At       time.Time
}

// SlogEntryFields are the attributes of an admin_audit line besides schema,
// in the order SlogEmitter writes them. Nothing else is ever written: a
// request body, bearer token or secret value has no field to land in.
var SlogEntryFields = []string{
	"seq", "ts", "entry_hash", "prev_hash", "key_id", "actor_id", "actor_sub", "actor_email",
	"actor_role", "auth_method", "action", "target", "target_ref", "outcome", "http_status",
	"before_hash", "after_hash", "client_ip", "request_id", "details",
}

// SlogEmitter writes warden.admin.v1 lines through a slog logger. Lines are
// written at INFO whatever the logger's level, because an anchor dropped by a
// log-level setting anchors nothing.
type SlogEmitter struct {
	h slog.Handler
}

var _ Emitter = (*SlogEmitter)(nil)

// NewSlogEmitter returns an Emitter writing to logger (slog.Default when nil).
func NewSlogEmitter(logger *slog.Logger) *SlogEmitter {
	if logger == nil {
		logger = slog.Default()
	}
	return &SlogEmitter{h: logger.Handler()}
}

// Emit writes one admin_audit line holding the fields of e plus the
// plaintext sub and email of who.
func (s *SlogEmitter) Emit(e Entry, who Identity) {
	details := e.Details
	if details == nil {
		details = map[string]string{}
	}
	ts := time.Unix(0, e.TSUnixNano).UTC()
	s.write(ts, msgEntry,
		slog.Int64("seq", e.Seq),
		slog.String("ts", ts.Format(time.RFC3339Nano)),
		slog.String("entry_hash", hex.EncodeToString(e.EntryHash)),
		slog.String("prev_hash", hex.EncodeToString(e.PrevHash)),
		slog.String("key_id", e.KeyID),
		slog.String("actor_id", e.ActorID),
		slog.String("actor_sub", who.Sub),
		slog.String("actor_email", who.Email),
		slog.String("actor_role", e.ActorRole),
		slog.String("auth_method", e.AuthMethod),
		slog.String("action", e.Action),
		slog.String("target", e.Target),
		slog.String("target_ref", e.TargetRef),
		slog.String("outcome", e.Outcome),
		slog.Int("http_status", e.HTTPStatus),
		slog.String("before_hash", e.BeforeHash),
		slog.String("after_hash", e.AfterHash),
		slog.String("client_ip", e.ClientIP),
		slog.String("request_id", e.RequestID),
		slog.Any("details", details),
	)
}

// Checkpoint writes one admin_audit.checkpoint line with the head.
func (s *SlogEmitter) Checkpoint(c Checkpoint) {
	s.write(c.At, msgCheckpoint,
		slog.Int64("head_seq", c.HeadSeq),
		slog.String("head_entry_hash", hex.EncodeToString(c.HeadHash)),
		slog.String("key_id", c.KeyID),
	)
}

func (s *SlogEmitter) write(at time.Time, msg string, attrs ...slog.Attr) {
	r := slog.NewRecord(at, slog.LevelInfo, msg, 0)
	r.AddAttrs(slog.String("schema", SchemaV1))
	r.AddAttrs(attrs...)
	_ = s.h.Handle(context.Background(), r)
}

// emitted is one committed row waiting to be handed to the emitter.
type emitted struct {
	entry Entry
	who   Identity
}

// emitterBox lets SetEmitter publish an interface value atomically.
type emitterBox struct{ e Emitter }

// SetEmitter installs the store's Emitter. Call it once at startup, before
// the store is shared; reads are safe from any goroutine. A second call
// panics: two writers would race over which sink gets the anchors.
func (s *Store) SetEmitter(e Emitter) {
	if !s.emitter.CompareAndSwap(nil, &emitterBox{e: e}) {
		panic("adminaudit: SetEmitter called twice")
	}
}

// emit hands committed rows to the emitter, if any. The rows are already
// durable: a panicking emitter is recovered and logged (never with the
// actor's sub or email) so it cannot fail or undo the append.
func (s *Store) emit(rows []emitted) {
	box := s.emitter.Load()
	if box == nil || box.e == nil {
		return
	}
	for _, r := range rows {
		s.emitOne(box.e, r)
	}
}

func (s *Store) emitOne(e Emitter, r emitted) {
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("admin_audit emitter panicked", "seq", r.entry.Seq, "action", r.entry.Action, "panic", p)
		}
	}()
	e.Emit(r.entry, r.who)
}

// RunCheckpoints emits the chain head to e once at startup, then every
// interval (DefaultCheckpointInterval when interval <= 0) on clk, and once
// more when ctx is cancelled, then returns. Head reads ignore ctx's
// cancellation (they are one short local query), so the shutdown checkpoint
// is still written. A head that cannot be read is logged and skipped; a panicking
// emitter is recovered and logged.
func RunCheckpoints(ctx context.Context, s *Store, e Emitter, interval time.Duration, clk clock.Clock) {
	if interval <= 0 {
		interval = DefaultCheckpointInterval
	}
	if clk == nil {
		clk = clock.Real()
	}
	// The timer is armed before the startup checkpoint, so a caller that has
	// seen that checkpoint knows the next one is scheduled.
	t := clk.NewTimer(interval)
	defer t.Stop()
	s.checkpoint(ctx, e, clk)
	for {
		select {
		case <-ctx.Done():
			s.checkpoint(ctx, e, clk)
			return
		case <-t.C():
			// Re-arm first, as at startup: once a checkpoint is visible the
			// next one is already scheduled.
			t.Reset(interval)
			s.checkpoint(ctx, e, clk)
		}
	}
}

func (s *Store) checkpoint(ctx context.Context, e Emitter, clk clock.Clock) {
	seq, hash, keyID, err := s.Head(context.WithoutCancel(ctx))
	if err != nil {
		s.logger.Error("admin_audit checkpoint failed", "err", err)
		return
	}
	defer func() {
		if p := recover(); p != nil {
			s.logger.Error("admin_audit emitter panicked", "checkpoint_seq", seq, "panic", p)
		}
	}()
	e.Checkpoint(Checkpoint{HeadSeq: seq, HeadHash: hash, KeyID: keyID, At: clk.Now()})
}
