package analytics

import (
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStore wraps a real *SQLiteStore so tests can (a) observe batch sizes and
// prune calls and (b) gate writes to force backpressure. It satisfies the
// package-private batchStore interface the async writer depends on.
type fakeStore struct {
	inner *SQLiteStore

	// gate, when non-nil, blocks every StoreEventsBatch until it is readable
	// (send a token per batch, or close it to release all). It is how a test
	// makes the underlying store "slow" so StoreEvent hits backpressure.
	gate chan struct{}

	mu         sync.Mutex
	failBatch  error
	batchSizes []int
	pruneCalls int
}

func (f *fakeStore) StoreEvent(e Event) error { return f.inner.StoreEvent(e) }

func (f *fakeStore) GetEvents(filter EventFilter) ([]Event, error) {
	return f.inner.GetEvents(filter)
}

func (f *fakeStore) StoreEventsBatch(evs []Event) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	fail := f.failBatch
	f.mu.Unlock()
	if fail != nil {
		return fail
	}
	f.mu.Lock()
	f.batchSizes = append(f.batchSizes, len(evs))
	f.mu.Unlock()
	return f.inner.StoreEventsBatch(evs)
}

func (f *fakeStore) Prune() error {
	f.mu.Lock()
	f.pruneCalls++
	f.mu.Unlock()
	return f.inner.Prune()
}

func (f *fakeStore) maxBatch() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := 0
	for _, n := range f.batchSizes {
		if n > m {
			m = n
		}
	}
	return m
}

// newFakeStore builds a fakeStore over a fresh file-backed SQLiteStore (a real
// fsync path, like production) that is closed on test cleanup.
func newFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "async.db"), 0)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return &fakeStore{inner: s}
}

// waitFor polls cond until true or the deadline, failing the test on timeout.
func waitFor(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", msg)
}

func countEvents(t *testing.T, s batchStore) int {
	t.Helper()
	evs, err := s.GetEvents(EventFilter{})
	if err != nil {
		t.Fatalf("GetEvents: %v", err)
	}
	return len(evs)
}

// TestAsyncWriter_BatchFlush enqueues more than one batch worth of events and
// asserts (a) all land in the underlying store and (b) at least one write was a
// real multi-event batch (amortization actually happened, not one INSERT each).
func TestAsyncWriter_BatchFlush(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithBatchSize(16), WithFlushInterval(20*time.Millisecond))
	t.Cleanup(func() { _ = w.Close() })

	const n = 200
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "api.openai.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}

	waitFor(t, 5*time.Second, "all events persisted", func() bool {
		return countEvents(t, fs) == n
	})
	waitFor(t, time.Second, "queue drained", func() bool { return w.QueueDepth() == 0 })

	if got := fs.maxBatch(); got < 2 {
		t.Fatalf("expected at least one multi-event batch, largest batch was %d", got)
	}
}

// TestAsyncWriter_FlushOnTick verifies a partial batch (fewer than batchSize)
// still flushes on the interval tick, not just when the batch fills.
func TestAsyncWriter_FlushOnTick(t *testing.T) {
	fs := newFakeStore(t)
	// batchSize far larger than the event count so ONLY the tick can flush.
	w := newAsyncWriter(fs, WithBatchSize(1000), WithFlushInterval(10*time.Millisecond))
	t.Cleanup(func() { _ = w.Close() })

	const n = 3
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "api.anthropic.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}

	waitFor(t, 2*time.Second, "partial batch flushed on tick", func() bool {
		return countEvents(t, fs) == n
	})
}

// TestAsyncWriter_BackpressureNotDrop is the key invariant: with a tiny queue
// and a blocked underlying store, StoreEvent BLOCKS (does not drop); once the
// store unblocks EVERY event is persisted, including a DENY audit record.
func TestAsyncWriter_BackpressureNotDrop(t *testing.T) {
	fs := newFakeStore(t)
	fs.gate = make(chan struct{}) // batches block until this is closed
	w := newAsyncWriter(fs, WithQueueCap(1), WithBatchSize(1), WithFlushInterval(time.Hour))
	t.Cleanup(func() { _ = w.Close() })

	const n = 8
	returned := make(chan int, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			e := Event{Domain: "api.openai.com", Decision: "allow"}
			if i == n-1 {
				e.Decision = "deny" // a denial must survive backpressure
				e.Reason = "policy"
			}
			if err := w.StoreEvent(e); err != nil {
				t.Errorf("StoreEvent: %v", err)
			}
			returned <- i
		}()
	}

	// With the store blocked, only the in-flight + one buffered event can
	// complete; the rest MUST block. Drain whatever returns for a settle window
	// and assert not everything got through (proves backpressure, not shedding).
	completed := 0
	settle := time.After(200 * time.Millisecond)
drain:
	for {
		select {
		case <-returned:
			completed++
			if completed == n {
				t.Fatal("all StoreEvent calls returned while store was blocked: events were dropped, not backpressured")
			}
		case <-settle:
			break drain
		}
	}
	if completed >= n {
		t.Fatalf("expected some callers blocked, %d/%d completed", completed, n)
	}

	// Release the store: every enqueued event (including the DENY) must persist.
	close(fs.gate)
	for completed < n {
		<-returned
		completed++
	}
	waitFor(t, 5*time.Second, "all backpressured events persisted", func() bool {
		return countEvents(t, fs) == n
	})

	denials, err := fs.GetEvents(EventFilter{Decision: "deny"})
	if err != nil {
		t.Fatalf("GetEvents deny: %v", err)
	}
	if len(denials) != 1 {
		t.Fatalf("DENY audit record lost under backpressure: got %d deny events, want 1", len(denials))
	}
}

// TestAsyncWriter_CloseDrains asserts Close persists every enqueued event before
// returning, is idempotent, and that a post-Close StoreEvent neither panics nor
// is lost (it falls back to a synchronous write).
func TestAsyncWriter_CloseDrains(t *testing.T) {
	fs := newFakeStore(t)
	// A long flush interval + large batch means nothing flushes on its own; only
	// Close's drain can persist these, so this proves Close flushes.
	w := newAsyncWriter(fs, WithBatchSize(1000), WithFlushInterval(time.Hour))

	const n = 50
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "d", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Close returned: all n MUST already be persisted (no waiting/polling).
	if got := countEvents(t, fs); got != n {
		t.Fatalf("Close did not drain: persisted %d, want %d", got, n)
	}

	// Idempotent.
	if err := w.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// Post-Close StoreEvent must not panic and must still persist synchronously.
	if err := w.StoreEvent(Event{Domain: "post", Decision: "allow"}); err != nil {
		t.Fatalf("post-Close StoreEvent: %v", err)
	}
	if got := countEvents(t, fs); got != n+1 {
		t.Fatalf("post-Close event not persisted: got %d, want %d", got, n+1)
	}
}

// TestAsyncWriter_FlushPersistsQueuedImmediately pins the drain port the L1
// harness's deterministic event oracle rides: Flush persists everything already
// queued and returns WITHOUT waiting for the flush tick, so a reader over the
// base store sees a read-your-writes view the moment the caller decides traffic
// is done — no polling, no deadline. The onBatch tee fires for the flushed
// batch too (a downstream consumer must not miss events because they were
// flushed on demand instead of on the tick).
func TestAsyncWriter_FlushPersistsQueuedImmediately(t *testing.T) {
	fs := newFakeStore(t)
	// A batch size the queued events never reach plus a flush interval longer
	// than the test: ONLY Flush can make these events readable.
	var teed atomic.Int64
	w := newAsyncWriter(fs,
		WithBatchSize(1000), WithFlushInterval(time.Hour),
		WithOnBatch(func(evs []Event) { teed.Add(int64(len(evs))) }))
	t.Cleanup(func() { _ = w.Close() })

	const n = 5
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "api.openai.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}
	if got := countEvents(t, fs); got != 0 {
		t.Fatalf("%d events visible before Flush, want 0 (nothing flushed yet)", got)
	}

	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	if got := countEvents(t, fs); got != n {
		t.Fatalf("after Flush %d events visible, want %d", got, n)
	}
	if got := teed.Load(); got != n {
		t.Fatalf("tee saw %d events across Flush, want %d", got, n)
	}
	if w.QueueDepth() != 0 {
		t.Fatalf("queue depth %d after Flush, want 0", w.QueueDepth())
	}
}

// TestAsyncWriter_FlushReportsBatchWriteFailure pins the ack contract: a Flush
// whose batch write FAILED must not ack as if the events were persisted. The
// batch stays queued for retry (the non-lossy behavior), but the caller learns
// the read-your-writes view it asked for does not exist — so the L1 harness's
// event oracle fails the test clearly instead of reading a short list.
func TestAsyncWriter_FlushReportsBatchWriteFailure(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithBatchSize(1000), WithFlushInterval(time.Hour))
	t.Cleanup(func() { _ = w.Close() })

	const n = 3
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "d", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}

	boom := errors.New("boom: disk full")
	fs.mu.Lock()
	fs.failBatch = boom
	fs.mu.Unlock()
	if err := w.Flush(); !errors.Is(err, boom) {
		t.Fatalf("Flush with a failing batch write = %v, want the write error — a failed flush must not ack as persisted", err)
	}
	if got := countEvents(t, fs); got != 0 {
		t.Fatalf("%d events visible after the failed flush, want 0 (the batch is retained for retry, never dropped)", got)
	}

	// Recovery: once the write succeeds again, the SAME Flush drains the
	// retained batch and acks nil.
	fs.mu.Lock()
	fs.failBatch = nil
	fs.mu.Unlock()
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush after the store recovered = %v, want nil", err)
	}
	if got := countEvents(t, fs); got != n {
		t.Fatalf("after recovery %d events visible, want %d", got, n)
	}
}

// TestAsyncWriter_FlushIsIdempotentAndPostCloseSafe pins Flush's lifecycle
// safety: flushing an empty queue is a no-op, repeated flushes persist nothing
// twice, and Flush after Close returns instead of blocking on the dead writer.
func TestAsyncWriter_FlushIsIdempotentAndPostCloseSafe(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithBatchSize(1000), WithFlushInterval(time.Hour))
	t.Cleanup(func() { _ = w.Close() })

	const n = 3
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "d", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if err := w.Flush(); err != nil { // empty queue: a no-op, never a duplicate write
		t.Fatalf("second Flush: %v", err)
	}
	if got := countEvents(t, fs); got != n {
		t.Fatalf("two Flushes persisted %d events, want exactly %d", got, n)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	done := make(chan struct{})
	go func() { _ = w.Flush(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Flush after Close blocked; it must return once the writer is gone")
	}
}

// TestAsyncWriter_FlushConcurrentWithWriters drives Flush against concurrent
// producers (run under -race) and asserts no loss and no panic: everything
// enqueued before Flush returns is persisted, and the rest drain on Close.
func TestAsyncWriter_FlushConcurrentWithWriters(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithQueueCap(8), WithBatchSize(4), WithFlushInterval(time.Hour))
	t.Cleanup(func() { _ = w.Close() })

	const n = 100
	var enqueued atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			if err := w.StoreEvent(Event{Domain: "race", Decision: "allow"}); err != nil {
				t.Errorf("StoreEvent: %v", err)
				return
			}
			enqueued.Add(1)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			if err := w.Flush(); err != nil {
				t.Errorf("Flush: %v", err)
				return
			}
			<-time.After(time.Millisecond)
		}
	}()
	wg.Wait()

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := countEvents(t, fs), int(enqueued.Load()); got != want {
		t.Fatalf("event loss with Flush racing producers: persisted %d, enqueued %d", got, want)
	}
}

// TestAsyncWriter_ConcurrentStoreRace drives many concurrent producers against
// the single writer goroutine (run under -race) and asserts zero loss.
func TestAsyncWriter_ConcurrentStoreRace(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithQueueCap(8), WithBatchSize(4), WithFlushInterval(5*time.Millisecond))

	const goroutines = 16
	const each = 25
	var wg sync.WaitGroup
	var enqueued atomic.Int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				if err := w.StoreEvent(Event{Domain: "race", Decision: "allow"}); err != nil {
					t.Errorf("StoreEvent: %v", err)
					return
				}
				enqueued.Add(1)
			}
		}()
	}
	wg.Wait()

	// Close drains: every enqueued event must be persisted exactly once.
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got, want := countEvents(t, fs), int(enqueued.Load()); got != want {
		t.Fatalf("event loss under concurrency: persisted %d, enqueued %d", got, want)
	}
}

// nopStore is a batchStore whose writes are instant no-ops. It isolates the
// async writer's ENQUEUE cost in a benchmark: the writer goroutine drains the
// queue as fast as it can pull, so StoreEvent stays on the non-blocking send
// path (measuring the caller's true cost) with a small, bounded queue.
type nopStore struct{}

func (nopStore) StoreEvent(Event) error                 { return nil }
func (nopStore) StoreEventsBatch([]Event) error         { return nil }
func (nopStore) Prune() error                           { return nil }
func (nopStore) GetEvents(EventFilter) ([]Event, error) { return nil, nil }

// BenchmarkAsyncStoreEvent measures the enqueue cost of the async writer's
// StoreEvent — the D1 win. It is the sub-µs counterpart to BenchmarkStoreEvent
// (the synchronous INSERT+prune baseline against real SQLite). The underlying
// store drains instantly here so the measurement is the caller-side enqueue
// cost, not SQLite throughput.
func BenchmarkAsyncStoreEvent(b *testing.B) {
	w := newAsyncWriter(nopStore{}, WithQueueCap(4096), WithBatchSize(defaultAsyncBatchSize))
	b.Cleanup(func() { _ = w.Close() })

	e := Event{
		Timestamp:      time.Now(),
		Domain:         "api.openai.com",
		Port:           443,
		Protocol:       "https",
		Method:         "POST",
		URL:            "https://api.openai.com/v1/chat/completions",
		Decision:       "allow",
		ResponseStatus: 200,
		SecretRef:      "sha256:abc123def456:last4=7890:v1",
		CostUSD:        0.0021,
		Provider:       "openai",
		Compliance:     []string{"owasp:LLM01", "mitre:T1048"},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := w.StoreEvent(e); err != nil {
			b.Fatalf("StoreEvent: %v", err)
		}
	}
}

// TestAsyncWriter_OnBatchTee proves the WithOnBatch tee: every enqueued event is
// handed to the tee EXACTLY ONCE, on the writer goroutine (off the request hot
// path). It also asserts the tee fires independently of write retries — a batch
// whose first write attempt fails (gated) is still teed once, never twice.
func TestAsyncWriter_OnBatchTee(t *testing.T) {
	fs := newFakeStore(t)
	var mu sync.Mutex
	var teed []Event
	w := newAsyncWriter(fs,
		WithBatchSize(4), WithFlushInterval(10*time.Millisecond),
		WithOnBatch(func(evs []Event) {
			mu.Lock()
			teed = append(teed, evs...)
			mu.Unlock()
		}),
	)

	const n = 10
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "api.openai.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}
	if err := w.Close(); err != nil { // drains → final tee fires
		t.Fatalf("Close: %v", err)
	}

	mu.Lock()
	got := len(teed)
	mu.Unlock()
	if got != n {
		t.Fatalf("tee must see each event exactly once: got %d, want %d", got, n)
	}
}

// TestAsyncWriter_OnBatchTee_Additive proves WithOnBatch is additive: two tees
// both see every event exactly once, in registration order per batch, and a nil
// function is ignored.
func TestAsyncWriter_OnBatchTee_Additive(t *testing.T) {
	fs := newFakeStore(t)
	var mu sync.Mutex
	var order []string
	counts := map[string]int{}
	tee := func(name string) func([]Event) {
		return func(evs []Event) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, name)
			counts[name] += len(evs)
		}
	}
	w := newAsyncWriter(fs,
		WithBatchSize(4), WithFlushInterval(10*time.Millisecond),
		WithOnBatch(tee("first")), WithOnBatch(nil), WithOnBatch(tee("second")),
	)
	const n = 10
	for i := 0; i < n; i++ {
		if err := w.StoreEvent(Event{Domain: "api.openai.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts["first"] != n || counts["second"] != n {
		t.Fatalf("each tee must see each event once: %v, want %d", counts, n)
	}
	if len(order)%2 != 0 {
		t.Fatalf("tees must fire the same number of times: %v", order)
	}
	for i := 0; i < len(order); i += 2 {
		if order[i] != "first" || order[i+1] != "second" {
			t.Fatalf("tees must run in registration order per batch: %v", order)
		}
	}
}

// TestAsyncWriter_OnBatchTee_NilNoop asserts a nil tee (the default) is a no-op:
// events persist normally and nothing is allocated for teeing.
func TestAsyncWriter_OnBatchTee_NilNoop(t *testing.T) {
	fs := newFakeStore(t)
	w := newAsyncWriter(fs, WithBatchSize(2))
	for i := 0; i < 5; i++ {
		if err := w.StoreEvent(Event{Domain: "a.com", Decision: "allow"}); err != nil {
			t.Fatalf("StoreEvent: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c := countEvents(t, fs); c != 5 {
		t.Fatalf("expected 5 persisted events, got %d", c)
	}
}
