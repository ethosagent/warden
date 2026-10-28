package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/auditlog"
	"github.com/ethosagent/warden/internal/config"
)

// jsonLogCloseTimeout bounds how long shutdown waits for the JSON admin
// stream to drain; the stream is best effort (the signed chain is the record),
// so a stuck output never holds the control plane up.
const jsonLogCloseTimeout = 5 * time.Second

// dropWarnInterval rate-limits the dropped-line WARN.
const dropWarnInterval = 30 * time.Second

// jsonLogOnStdout reports whether audit.jsonLog is enabled with stdout as
// its output: stdout then carries only warden.admin.v1 lines and the
// operational log moves to stderr.
func jsonLogOnStdout(c config.JSONLogConfig) bool {
	return c.Enabled && (c.Output == "" || c.Output == config.JSONLogOutputStdout)
}

// auditMeta is the per-process context of every admin line: the hostname as
// cp_id and a fresh 16-byte boot id.
func auditMeta() auditlog.Meta {
	host, _ := os.Hostname()
	b := make([]byte, 16)
	boot := "unknown"
	if _, err := rand.Read(b); err == nil {
		boot = hex.EncodeToString(b)
	}
	return auditlog.Meta{ProxyID: host, ProxyIDSource: "hostname", BootID: boot}
}

// newAuditSink opens the JSON stream sink for the control plane. The CP has
// no metrics endpoint in P1, so drops are reported by a rate-limited WARN
// (write errors are warned by the sink itself).
func newAuditSink(cfg config.JSONLogConfig, logger *slog.Logger, opts ...auditlog.Option) (*auditlog.Sink, error) {
	return auditlog.New(cfg, auditMeta(), &cpAuditMetrics{logger: logger}, logger, opts...)
}

// cpAuditMetrics is the sink's counter surface on the control plane: it
// counts nothing and warns, at most once per dropWarnInterval, that lines
// were dropped.
type cpAuditMetrics struct {
	logger   *slog.Logger
	lastWarn atomic.Int64 // unix nanos
}

func (*cpAuditMetrics) RecordAuditLogLine(string)       {}
func (*cpAuditMetrics) RecordAuditLogWriteError(string) {}

func (m *cpAuditMetrics) RecordAuditLogDropped(int) {
	now := time.Now().UnixNano()
	last := m.lastWarn.Load()
	if last != 0 && now-last < int64(dropWarnInterval) {
		return
	}
	if m.lastWarn.CompareAndSwap(last, now) {
		m.logger.Warn("audit JSON stream queue full or closed; admin lines are being dropped (the signed admin audit chain remains the record)")
	}
}

// jsonEmitter is the admin audit Emitter when audit.jsonLog is enabled: the
// default slog emitter first (the operational admin_audit line and the slog
// checkpoint anchor stay exactly as without the sink), then the same row as a
// warden.admin.v1 JSON line. Emit runs after the append committed; WriteAdmin
// only enqueues, so it is fast, and it never fails the caller.
type jsonEmitter struct {
	slog adminaudit.Emitter
	sink *auditlog.Sink
}

var _ adminaudit.Emitter = (*jsonEmitter)(nil)

// newAdminAuditEmitter returns the one emitter Run hands to the store and the
// checkpoint loop: the slog emitter, chained with sink when it is non-nil.
func newAdminAuditEmitter(logger *slog.Logger, sink *auditlog.Sink) adminaudit.Emitter {
	em := adminaudit.NewSlogEmitter(logger)
	if sink == nil {
		return em
	}
	return &jsonEmitter{slog: em, sink: sink}
}

func (j *jsonEmitter) Emit(e adminaudit.Entry, who adminaudit.Identity) {
	j.slog.Emit(e, who)
	j.sink.WriteAdmin(auditlog.AdminRecord{
		TS:         auditlog.FormatTS(time.Unix(0, e.TSUnixNano)),
		Actor:      auditlog.AdminActor{Sub: who.Sub, Email: who.Email, Role: e.ActorRole},
		AuthMethod: e.AuthMethod,
		Action:     e.Action,
		Target:     e.Target,
		TargetRef:  e.TargetRef,
		Outcome:    e.Outcome,
		BeforeHash: e.BeforeHash,
		AfterHash:  e.AfterHash,
		RequestID:  e.RequestID,
		ChainSeq:   e.Seq,
		EntryHash:  hex.EncodeToString(e.EntryHash),
		PrevHash:   hex.EncodeToString(e.PrevHash),
		KeyID:      e.KeyID,
	})
}

func (j *jsonEmitter) Checkpoint(c adminaudit.Checkpoint) {
	j.slog.Checkpoint(c)
	j.sink.WriteAdmin(auditlog.AdminRecord{
		TS:         auditlog.FormatTS(c.At),
		Action:     auditlog.ActionCheckpoint,
		Outcome:    adminaudit.OutcomeOK,
		ChainSeq:   c.HeadSeq,
		EntryHash:  hex.EncodeToString(c.HeadHash),
		KeyID:      c.KeyID,
		AuthMethod: adminaudit.AuthMethodSystem,
	})
}
