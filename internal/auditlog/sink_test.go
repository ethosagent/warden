package auditlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/observability"
)

var sinkMeta = Meta{ProxyID: "p1", ProxyIDSource: "config", AgentID: "a1", BootID: "b00t"}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func events(n int) []analytics.Event {
	evs := make([]analytics.Event, n)
	for i := range evs {
		evs[i] = analytics.Event{Timestamp: time.Unix(1700000000, 0), Domain: "api.example.com", Protocol: "https", Decision: "allow", URL: "https://api.example.com/v1/x?k=secretvalue", Method: "GET", ResponseStatus: 200}
	}
	return evs
}

func closeSink(t *testing.T, s *Sink) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// syncBuf is a goroutine-safe writer for the stdout/stderr outputs.
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

func decode(t *testing.T, data string) []Record {
	t.Helper()
	var out []Record
	for _, ln := range strings.Split(strings.TrimRight(data, "\n"), "\n") {
		if ln == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Fatalf("line is not JSON: %v: %q", err, ln)
		}
		out = append(out, r)
	}
	return out
}

func TestSinkWritesLinesWithConsecutiveSeq(t *testing.T) {
	buf := &syncBuf{}
	s, err := New(config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputStdout}, sinkMeta, nil, discardLogger(), WithWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	s.Observe(events(3))
	s.Observe(events(2))
	closeSink(t, s)

	recs := decode(t, buf.String())
	if len(recs) != 5 {
		t.Fatalf("lines = %d, want 5", len(recs))
	}
	for i, r := range recs {
		if r.Seq != uint64(i+1) || r.Schema != SchemaDecisionV1 || r.BootID != "b00t" {
			t.Errorf("line %d = seq %d schema %q boot %q", i, r.Seq, r.Schema, r.BootID)
		}
	}
	if strings.Contains(buf.String(), "secretvalue") {
		t.Error("a query value reached the line")
	}
}

func TestSinkDoesNotRetainInputSlice(t *testing.T) {
	buf := &syncBuf{}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, nil, discardLogger(), WithWriter(buf))
	if err != nil {
		t.Fatal(err)
	}
	evs := events(2)
	s.Observe(evs)
	evs[0].Domain, evs[1].Domain = "mutated.example", "mutated.example"
	closeSink(t, s)
	if strings.Contains(buf.String(), "mutated.example") {
		t.Error("sink read the caller's slice after Observe returned")
	}
}

func TestSinkNilAndEmptyAreNoOps(t *testing.T) {
	var s *Sink
	s.Observe(events(1))
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	live, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStderr}, sinkMeta, nil, nil, WithWriter(io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	live.Observe(nil)
	closeSink(t, live)
	closeSink(t, live) // idempotent
	live.Observe(events(1))
}

// errWriter always fails.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("disk on fire") }

func newMetrics(t *testing.T) (*observability.Metrics, func() string) {
	t.Helper()
	m, h, shutdown, err := observability.New(observability.Config{Enabled: true, ServiceName: "t", MetricsEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
	return m, func() string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return rec.Body.String()
	}
}

func TestFailingWriter(t *testing.T) {
	m, scrape := newMetrics(t)
	var logs syncBuf
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, m, logger, WithWriter(errWriter{}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10; i++ {
			s.Observe(events(1))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a failing writer")
	}
	closeSink(t, s)

	body := scrape()
	if !strings.Contains(body, "warden_auditlog_write_errors_total") {
		t.Errorf("write_errors not recorded\n%s", body)
	}
	if n := strings.Count(logs.String(), "write failed"); n != 1 {
		t.Errorf("WARN count = %d, want exactly 1 (rate limited)", n)
	}
	if strings.Contains(logs.String(), "disk on fire") || strings.Contains(logs.String(), "api.example.com") {
		t.Errorf("WARN carries error text or record content: %s", logs.String())
	}
}

// blockWriter blocks every Write until released.
type blockWriter struct {
	release chan struct{}
	buf     syncBuf
}

func (b *blockWriter) Write(p []byte) (int, error) {
	<-b.release
	return b.buf.Write(p)
}

func TestFullQueueDropsWithoutBlocking(t *testing.T) {
	m, scrape := newMetrics(t)
	bw := &blockWriter{release: make(chan struct{})}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, m, discardLogger(), WithWriter(bw))
	if err != nil {
		t.Fatal(err)
	}
	const batches = queueBatches + 40
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < batches; i++ {
			s.Observe(events(1))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Observe blocked on a stalled writer")
	}
	if !strings.Contains(scrape(), "warden_auditlog_dropped_total") {
		t.Error("dropped counter not recorded")
	}

	// A bounded Close gives up on the stuck writer instead of hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Close with a stuck writer = %v, want deadline exceeded", err)
	}
	close(bw.release)
	<-s.done
	if len(decode(t, bw.buf.String())) >= batches {
		t.Fatal("every batch was written despite the stall")
	}
}

// TestFullQueueDropsWithoutBlocking_SeqGap: batches dropped on a full queue leave a gap in seq that
// the next accepted line shows.
func TestFullQueueDropsWithoutBlocking_SeqGap(t *testing.T) {
	bw := &blockWriter{release: make(chan struct{})}
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputStdout}, sinkMeta, nil, discardLogger(), WithWriter(bw))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < queueBatches+20; i++ {
		s.Observe(events(1))
	}
	close(bw.release)
	// Wait for the queue to drain, then send one more accepted batch.
	deadline := time.Now().Add(5 * time.Second)
	for len(s.ch) > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.Observe(events(1))
	closeSink(t, s)

	recs := decode(t, bw.buf.String())
	gap := false
	for i := 1; i < len(recs); i++ {
		if recs[i].Seq > recs[i-1].Seq+1 {
			gap = true
		}
	}
	if !gap {
		t.Errorf("no seq gap after dropped batches: %d lines", len(recs))
	}
}

func TestRotation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "audit")
	path := filepath.Join(dir, "decisions.jsonl")
	cfg := config.JSONLogConfig{Enabled: true, Output: config.JSONLogOutputFile, Path: path, MaxSizeMB: 1, MaxBackups: 2, FileMode: 0o600}
	s, err := New(cfg, sinkMeta, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("directory = %v, %v; want mode 0750", fi, err)
	}
	// ~3.5 MB of ~400-byte lines, fed in modest batches the queue can hold.
	ev := events(1)[0]
	ev.URL = "https://api.example.com/" + strings.Repeat("p", 200)
	total := 0
	for total < 3_600_000/380 {
		batch := make([]analytics.Event, 50)
		for i := range batch {
			batch[i] = ev
		}
		deadline := time.Now().Add(10 * time.Second)
		for len(s.ch) >= queueBatches/2 {
			if time.Now().After(deadline) {
				t.Fatal("the sink's writer never drained the queue")
			}
			time.Sleep(time.Millisecond)
		}
		s.Observe(batch)
		total += len(batch)
	}
	closeSink(t, s)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 3 {
		t.Errorf("files = %d, want at most 1 active + 2 backups", len(entries))
	}
	lines := 0
	for _, e := range entries {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", e.Name(), fi.Mode().Perm())
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 0 && data[len(data)-1] != '\n' {
			t.Errorf("%s does not end on a line boundary", e.Name())
		}
		for _, ln := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			var r Record
			if err := json.Unmarshal([]byte(ln), &r); err != nil {
				t.Fatalf("%s holds a split or invalid line: %v", e.Name(), err)
			}
			lines++
		}
	}
	if len(entries) < 2 {
		t.Errorf("files = %d, rotation never happened", len(entries))
	}
	if lines == 0 {
		t.Error("no lines survived")
	}
}

func TestFileModeAndBadPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d", "x.jsonl")
	s, err := New(config.JSONLogConfig{Output: config.JSONLogOutputFile, Path: path, FileMode: 0o640}, sinkMeta, nil, discardLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.Observe(events(1))
	closeSink(t, s)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("file = %v, %v; want mode 0640", fi, err)
	}

	blocker := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(blocker, "sub", "x.jsonl"), ""} {
		_, err := New(config.JSONLogConfig{Output: config.JSONLogOutputFile, Path: p}, sinkMeta, nil, discardLogger())
		if err == nil || !strings.Contains(err.Error(), "audit.jsonLog.path") {
			t.Errorf("New(path %q) error = %v, want one naming audit.jsonLog.path", p, err)
		}
	}
}
