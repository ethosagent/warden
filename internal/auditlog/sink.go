package auditlog

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
)

const (
	// queueBatches is the bound of the sink's own channel, in batches.
	queueBatches = 64
	// bufSize holds several full lines; a line never exceeds MaxLineBytes, and
	// the writer flushes before a line that would not fit, so a line is always
	// handed to the output inside ONE underlying Write (never split across
	// rotated files).
	bufSize = 4 * MaxLineBytes
	// warnInterval rate-limits the write-error WARN.
	warnInterval = 30 * time.Second
	dirMode      = 0o750
)

// Write-error reasons (bounded metric label values).
const (
	reasonMarshal = "marshal"
	reasonWrite   = "write"
	reasonFlush   = "flush"
)

// Metrics is the counter surface the sink reports to. *observability.Metrics
// satisfies it (every method is nil-safe there), and a nil Metrics is allowed.
// It is declared here, not imported, because a repository package may not
// depend on another domain's repository (L7).
type Metrics interface {
	RecordAuditLogLine(schema string)
	RecordAuditLogWriteError(reason string)
	RecordAuditLogDropped(n int)
}

type noopMetrics struct{}

func (noopMetrics) RecordAuditLogLine(string)       {}
func (noopMetrics) RecordAuditLogWriteError(string) {}
func (noopMetrics) RecordAuditLogDropped(int)       {}

// Option adjusts a Sink at construction.
type Option func(*Sink)

// WithWriter replaces os.Stdout / os.Stderr as the target of the stdout and
// stderr outputs (the worker passes its own out writer; tests pass a buffer).
// It has no effect on the file output.
func WithWriter(w io.Writer) Option { return func(s *Sink) { s.override = w } }

// batch is one queue entry: a tee'd batch of decision records, or one admin
// record (never both).
type batch struct {
	recs  []Record
	admin *AdminRecord
}

func (b batch) size() int {
	if b.admin != nil {
		return 1
	}
	return len(b.recs)
}

// Sink turns tee'd analytics batches into warden.decision.v1 lines and, on the
// control plane, admin rows into warden.admin.v1 lines through the same queue. Observe runs
// on the async analytics writer's goroutine: it converts the batch, assigns seq
// and hands it to a bounded channel WITHOUT blocking; one writer goroutine
// marshals and writes. The stream is best effort: a full queue drops the whole
// batch and a write error is counted, never returned to a request.
type Sink struct {
	meta     Meta
	query    QueryMode
	metrics  Metrics
	logger   *slog.Logger
	override io.Writer

	seq atomic.Uint64

	// mu orders Observe's send against Close's channel close.
	mu     sync.RWMutex
	closed bool
	ch     chan batch

	abort     chan struct{} // closed when Close's context ends before the drain
	abortOnce sync.Once
	done      chan struct{} // closed when the writer goroutine has exited

	out    io.Writer // the unbuffered destination (also what bw wraps)
	closer io.Closer // lumberjack, nil for stdout/stderr
	bw     *bufio.Writer

	pendingDecision int          // decision lines buffered since the last successful flush
	pendingAdmin    int          // admin lines buffered since the last successful flush
	lastWarn        atomic.Int64 // unix nanos of the last write-error WARN
}

// New opens the output and starts the writer goroutine. A file path that cannot
// be opened fails here, which fails worker startup.
func New(cfg config.JSONLogConfig, meta Meta, m Metrics, logger *slog.Logger, opts ...Option) (*Sink, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if m == nil {
		m = noopMetrics{}
	}
	s := &Sink{
		meta:    meta,
		metrics: m,
		logger:  logger,
		ch:      make(chan batch, queueBatches),
		abort:   make(chan struct{}),
		done:    make(chan struct{}),
	}
	if cfg.Query == config.JSONLogQueryKeys {
		s.query = QueryKeys
	} else {
		s.query = QueryDrop
	}
	for _, o := range opts {
		o(s)
	}

	switch cfg.Output {
	case config.JSONLogOutputFile:
		lj, err := openFile(cfg)
		if err != nil {
			return nil, err
		}
		s.out, s.closer = lj, lj
	case config.JSONLogOutputStderr:
		s.out = s.override
		if s.out == nil {
			s.out = os.Stderr
		}
	default: // stdout, the config default
		s.out = s.override
		if s.out == nil {
			s.out = os.Stdout
		}
	}
	s.bw = bufio.NewWriterSize(s.out, bufSize)

	output := cfg.Output
	if output == "" {
		output = config.JSONLogOutputStdout
	}
	logger.Info("audit JSON decision stream enabled",
		"output", output, "path", cfg.Path, "schema", SchemaDecisionV1)

	go s.run()
	return s, nil
}

// openFile creates the directory (0750) and the first file with the configured
// mode before lumberjack takes over, so rotation (which copies the mode of the
// live file) keeps it, then returns the rotating writer.
func openFile(cfg config.JSONLogConfig) (*lumberjack.Logger, error) {
	if cfg.Path == "" {
		return nil, errors.New("audit.jsonLog.path: required when output is file")
	}
	mode := os.FileMode(cfg.FileMode)
	if mode == 0 {
		mode = 0o600
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Path), dirMode); err != nil {
		return nil, fmt.Errorf("audit.jsonLog.path: create directory: %w", err)
	}
	f, err := os.OpenFile(cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, mode)
	if err != nil {
		return nil, fmt.Errorf("audit.jsonLog.path: open %s: %w", cfg.Path, err)
	}
	// The create is subject to the umask; make the mode exact (a 0640 request
	// under umask 077 must still read 0640).
	if err := f.Chmod(mode); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("audit.jsonLog.path: chmod %s: %w", cfg.Path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit.jsonLog.path: close %s: %w", cfg.Path, err)
	}
	return &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSizeMB,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAgeDays,
		Compress:   cfg.Compress,
	}, nil
}

// Observe is the analytics tee (analytics.WithOnBatch). It assigns seq from a
// per-boot counter starting at 1 and converts the events on the caller's
// goroutine, so a dropped batch shows as a gap in seq, then enqueues without
// blocking: a full (or closed) channel drops the whole batch and counts it. It
// does not retain evs.
func (s *Sink) Observe(evs []analytics.Event) {
	if s == nil || len(evs) == 0 {
		return
	}
	recs := make([]Record, len(evs))
	for i := range evs {
		recs[i] = FromEvent(evs[i], s.meta, s.query)
		recs[i].Seq = s.seq.Add(1)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.metrics.RecordAuditLogDropped(len(recs))
		return
	}
	select {
	case s.ch <- batch{recs: recs}:
	default:
		s.metrics.RecordAuditLogDropped(len(recs))
	}
}

// WriteAdmin queues one warden.admin.v1 line. It shares the queue, caps, line
// limit and metrics of Observe (the schema label separates the streams) and
// never blocks or fails the caller: a full or closed queue drops the line and
// counts it. seq comes from the same per-boot counter as decision lines; a
// gap shows a dropped line.
func (s *Sink) WriteAdmin(rec AdminRecord) {
	if s == nil {
		return
	}
	rec = rec.bounded(s.meta)
	rec.Seq = s.seq.Add(1)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		s.metrics.RecordAuditLogDropped(1)
		return
	}
	select {
	case s.ch <- batch{admin: &rec}:
	default:
		s.metrics.RecordAuditLogDropped(1)
	}
}

// Close stops accepting batches, drains the queue until ctx ends, flushes and
// closes the file. If ctx ends first the remaining queued batches are abandoned
// (they are best effort; the SQLite store is the record) and ctx.Err() is
// returned. Close is idempotent.
func (s *Sink) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
	s.mu.Unlock()

	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		s.abortOnce.Do(func() { close(s.abort) })
		return ctx.Err()
	}
}

// run is the single writer goroutine.
func (s *Sink) run() {
	defer close(s.done)
	defer func() {
		s.flush()
		if s.closer != nil {
			if err := s.closer.Close(); err != nil {
				s.recordError(reasonFlush)
			}
		}
	}()
	for b := range s.ch {
		select {
		case <-s.abort:
			s.metrics.RecordAuditLogDropped(b.size())
			continue
		default:
		}
		if b.admin != nil {
			if s.writeLine(b.admin) {
				s.pendingAdmin++
			}
		}
		for i := range b.recs {
			if s.writeLine(b.recs[i]) {
				s.pendingDecision++
			}
		}
		s.flush()
	}
}

// lineMarshaler is a record the sink can write: Record or *AdminRecord.
type lineMarshaler interface{ MarshalLine() ([]byte, error) }

// writeLine marshals one record and writes it with a single Write call. It
// reports whether the line reached the buffer.
func (s *Sink) writeLine(r lineMarshaler) bool {
	line, err := r.MarshalLine()
	if err != nil {
		s.recordError(reasonMarshal)
		return false
	}
	// Flush first when the line would straddle the buffer, so the underlying
	// output never sees half a line.
	if s.bw.Available() < len(line) {
		s.flush()
	}
	if _, err := s.bw.Write(line); err != nil {
		s.recordError(reasonWrite)
		s.bw.Reset(s.out) // bufio errors are sticky; start clean for the next line
		return false
	}
	return true
}

// flush pushes the buffer to the output and credits the lines it carried.
func (s *Sink) flush() {
	nDecision, nAdmin := s.pendingDecision, s.pendingAdmin
	s.pendingDecision, s.pendingAdmin = 0, 0
	if err := s.bw.Flush(); err != nil {
		s.recordError(reasonFlush)
		s.bw.Reset(s.out)
		return
	}
	for i := 0; i < nDecision; i++ {
		s.metrics.RecordAuditLogLine(SchemaDecisionV1)
	}
	for i := 0; i < nAdmin; i++ {
		s.metrics.RecordAuditLogLine(SchemaAdminV1)
	}
}

// recordError counts a failure and logs a WARN at most once per warnInterval.
// The WARN carries the reason only, never record content or the error text
// (which could echo a path).
func (s *Sink) recordError(reason string) {
	s.metrics.RecordAuditLogWriteError(reason)
	now := time.Now().UnixNano()
	last := s.lastWarn.Load()
	if now-last < int64(warnInterval) && last != 0 {
		return
	}
	if s.lastWarn.CompareAndSwap(last, now) {
		s.logger.Warn("audit JSON stream write failed; lines are being lost (SQLite remains the record)", "reason", reason)
	}
}
