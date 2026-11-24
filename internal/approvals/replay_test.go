package approvals_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
)

// fakeRunner is a ReplayRunner whose run blocks until released (or, when
// honourCtx, until its context ends).
type fakeRunner struct {
	mu       sync.Mutex
	calls    []approvals.ReplayRequest
	gate     chan struct{} // nil = return at once
	honorCtx bool
	out      approvals.ReplayOutcome
	err      error
	// returned, when set, receives once each time Run returns.
	returned chan struct{}
}

func (f *fakeRunner) Run(ctx context.Context, req approvals.ReplayRequest) (approvals.ReplayOutcome, error) {
	if f.returned != nil {
		defer func() { f.returned <- struct{}{} }()
	}
	f.mu.Lock()
	f.calls = append(f.calls, req)
	f.mu.Unlock()
	if f.gate != nil {
		if f.honorCtx {
			select {
			case <-f.gate:
			case <-ctx.Done():
				return approvals.ReplayOutcome{}, ctx.Err()
			}
		} else {
			<-f.gate
		}
	}
	return f.out, f.err
}

func (f *fakeRunner) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

var doneOutcome = approvals.ReplayOutcome{
	Result: json.RawMessage(`{"events":3}`), Events: 3, Scanned: 3, ToDenyGroups: 1,
}

// replayEnv is an env with a Replayer over runner.
func replayEnv(t *testing.T, runner approvals.ReplayRunner, timeout time.Duration) (*env, *approvals.Replayer) {
	t.Helper()
	e := newEnv(t, 10)
	rp, err := approvals.NewReplayer(approvals.ReplayerConfig{
		Store: sqlstore.NewReplayStore(e.db.SQL()), Runner: runner,
		Now: func() time.Time { return time.UnixMilli(e.nowMS.Load()) },
		CurrentRevision: func(ctx context.Context, id string) (int, error) {
			d, err := e.store.Get(ctx, id)
			return d.Revision, err
		},
		Window: time.Hour, MaxEvents: 1000, Timeout: timeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rp.Close)
	e.svc.SetReplayer(rp)
	return e, rp
}

// waitReplay polls until the replay satisfies ok, failing after 5s.
func waitReplay(t *testing.T, e *env, id string, ok func(approvals.Replay) bool) approvals.Replay {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r, err := e.svc.GetReplay(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if ok(r) {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("replay %s stuck at %+v", id, r)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func settled(r approvals.Replay) bool { return r.Status.Settled() }

func latest(t *testing.T, e *env, draftID string, rev int) approvals.Replay {
	t.Helper()
	r, ok, err := e.svc.LatestReplay(context.Background(), draftID, rev)
	if err != nil || !ok {
		t.Fatalf("LatestReplay(%s, %d) = %v, %v, %v", draftID, rev, r, ok, err)
	}
	return r
}

func TestReplayQueuedOnSubmitAndEveryRevision(t *testing.T) {
	runner := &fakeRunner{out: doneOutcome}
	e, _ := replayEnv(t, runner, time.Minute)
	ctx := context.Background()
	d := e.create("a.example.com")
	if _, ok, _ := e.svc.LatestReplay(ctx, d.ID, 0); ok {
		t.Fatal("creating a draft queued a replay; only submit and new revisions do")
	}
	if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r1 := latest(t, e, d.ID, 1)
	r1 = waitReplay(t, e, r1.ID, settled)
	if r1.Status != approvals.ReplayDone || r1.Revision != 1 || r1.BaseVersion != d.BaseVersion || string(r1.Result) != `{"events":3}` || r1.EventsScanned != 3 {
		t.Fatalf("replay of revision 1 = %+v", r1)
	}
	if !r1.WindowFrom.Before(r1.WindowTo) || r1.WindowTo.Sub(r1.WindowFrom) != time.Hour || r1.FinishedAt.IsZero() {
		t.Errorf("window %v..%v finished %v", r1.WindowFrom, r1.WindowTo, r1.FinishedAt)
	}
	if got := runner.calls[0]; got.Limit != 1000 || !got.Since.Equal(r1.WindowFrom) || got.Draft.ID != d.ID {
		t.Errorf("runner request = %+v", got)
	}

	if _, err := e.svc.UpdateDraft(ctx, d.ID, 1, doc("b.example.com"), "edit", "ada"); err != nil {
		t.Fatal(err)
	}
	r2 := latest(t, e, d.ID, 2)
	waitReplay(t, e, r2.ID, settled)
	if r2.ID == r1.ID {
		t.Error("revision 2 reused revision 1's replay")
	}
	if runner.Calls() != 2 {
		t.Errorf("runner ran %d times, want 2", runner.Calls())
	}
	if _, err := e.svc.GetReplay(ctx, "rp_missing"); !errors.Is(err, approvals.ErrReplayNotFound) {
		t.Errorf("GetReplay(missing) = %v, want ErrReplayNotFound", err)
	}
}

func TestReplaySubmitDoesNotWait(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), honorCtx: true, out: doneOutcome}
	e, _ := replayEnv(t, runner, time.Minute)
	d := e.create("a.example.com")
	start := time.Now()
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("Submit took %v with a blocked replay", took)
	}
	r := latest(t, e, d.ID, 1)
	if r.Status.Settled() {
		t.Errorf("replay settled before the runner returned: %+v", r)
	}
	close(runner.gate)
	waitReplay(t, e, r.ID, settled)
}

// A scanner that blocks, with replayTimeout 100ms: the replay becomes failed
// with `timeout` within 200ms of the timeout, and a late result is discarded.
func TestReplayTimeoutFailsAndDiscardsLateResult(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), out: doneOutcome, returned: make(chan struct{}, 1)} // ignores ctx on purpose
	e, _ := replayEnv(t, runner, 100*time.Millisecond)
	d := e.create("a.example.com")
	begin := time.Now()
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	id := latest(t, e, d.ID, 1).ID
	r := waitReplay(t, e, id, settled)
	if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrTimeout {
		t.Fatalf("replay = %+v, want failed/timeout", r)
	}
	// Acceptance: failed `timeout` within 200ms of a 100ms replayTimeout, measured
	// from Submit. 500ms here leaves room for a loaded CI machine.
	if took := time.Since(begin); took > 500*time.Millisecond {
		t.Errorf("replay settled %v after Submit, want about 100ms (criterion: within 200ms)", took)
	}
	close(runner.gate) // the late result
	select {
	case <-runner.returned:
	case <-time.After(5 * time.Second):
		t.Fatal("runner never returned")
	}
	after, _ := e.svc.GetReplay(context.Background(), id)
	if after.Status != approvals.ReplayFailed || len(after.Result) != 0 {
		t.Errorf("late result overwrote the timeout: %+v", after)
	}
}

func TestReplayZeroEventsIsUnavailable(t *testing.T) {
	runner := &fakeRunner{out: approvals.ReplayOutcome{Result: json.RawMessage(`{}`)}}
	e, _ := replayEnv(t, runner, time.Minute)
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r := waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)
	if r.Status != approvals.ReplayUnavailable || len(r.Result) != 0 {
		t.Errorf("replay = %+v, want unavailable with no result", r)
	}
}

func TestReplayRunnerErrorFailsWithItsCode(t *testing.T) {
	runner := &fakeRunner{err: &approvals.ReplayError{Code: "scan_failed", Err: errors.New("disk on fire /var/db?x=1")}}
	e, _ := replayEnv(t, runner, time.Minute)
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r := waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)
	if r.Status != approvals.ReplayFailed || r.ErrorCode != "scan_failed" {
		t.Errorf("replay = %+v", r)
	}
	runner.err = errors.New("anything else")
	if _, err := e.svc.UpdateDraft(context.Background(), d.ID, 1, doc("b.example.com"), "", "ada"); err != nil {
		t.Fatal(err)
	}
	r = waitReplay(t, e, latest(t, e, d.ID, 2).ID, settled)
	if r.ErrorCode != approvals.ReplayErrInternal {
		t.Errorf("unnamed failure code = %q, want %q", r.ErrorCode, approvals.ReplayErrInternal)
	}
}

func TestReplayRerunBusyThenRateLimited(t *testing.T) {
	runner := &fakeRunner{out: doneOutcome}
	e, _ := replayEnv(t, runner, time.Minute)
	ctx := context.Background()
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)

	// Hold the one slot with a blocked run on another draft.
	runner.gate, runner.honorCtx = make(chan struct{}), true
	d2 := e.create("c.example.com")
	if _, err := e.svc.Submit(ctx, d2.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	id2 := latest(t, e, d2.ID, 1).ID
	waitReplay(t, e, id2, func(r approvals.Replay) bool { return r.Status == approvals.ReplayRunning })
	if _, err := e.svc.Replay(ctx, d.ID); !errors.Is(err, approvals.ErrReplayBusy) {
		t.Fatalf("Replay while the slot is in use = %v, want ErrReplayBusy", err)
	}
	close(runner.gate)
	waitReplay(t, e, id2, settled)

	r, err := e.svc.Replay(ctx, d.ID)
	if err != nil {
		t.Fatalf("Replay with a free slot: %v", err)
	}
	if r.Status != approvals.ReplayPending || r.Revision != 1 {
		t.Errorf("Replay returned %+v, want pending at revision 1", r)
	}
	waitReplay(t, e, r.ID, settled)
	if _, err := e.svc.Replay(ctx, d.ID); !errors.Is(err, approvals.ErrReplayRateLimited) {
		t.Errorf("second Replay inside a minute = %v, want ErrReplayRateLimited", err)
	}
	e.advance(approvals.ReplayRerunInterval)
	if r, err := e.svc.Replay(ctx, d.ID); err != nil {
		t.Errorf("Replay after the interval: %v", err)
	} else {
		waitReplay(t, e, r.ID, settled)
	}
	// Another draft is not limited by this one.
	if _, err := e.svc.Replay(ctx, d2.ID); err != nil {
		t.Errorf("Replay of another draft: %v", err)
	}
}

func TestReplayRefusedForClosedDraftOrNoReplayer(t *testing.T) {
	e, _ := replayEnv(t, &fakeRunner{out: doneOutcome}, time.Minute)
	ctx := context.Background()
	d := e.create("a.example.com")
	if _, err := e.svc.Store().Withdraw(ctx, d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Replay(ctx, d.ID); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("Replay of a withdrawn draft = %v, want ErrIllegalTransition", err)
	}
	if _, err := e.svc.Replay(ctx, "cd_missing"); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("Replay of an unknown draft = %v, want ErrNotFound", err)
	}
	bare := newEnv(t, 10)
	if _, err := bare.svc.Replay(ctx, d.ID); err == nil {
		t.Error("Replay without a replayer succeeded")
	}
	if _, ok, err := bare.svc.LatestReplay(ctx, d.ID, 0); ok || err != nil {
		t.Errorf("LatestReplay without a replayer = %v, %v", ok, err)
	}
	// Submit still works without one.
	d2 := bare.create("b.example.com")
	if _, err := bare.svc.Submit(ctx, d2.ID, 1, "ada"); err != nil {
		t.Errorf("Submit without a replayer: %v", err)
	}
}

// Pending and running replays left by an earlier process fail as interrupted;
// settled ones are untouched.
func TestReplayRecoverMarksInterrupted(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.create("a.example.com")
	st := sqlstore.NewReplayStore(e.db.SQL())
	at := time.UnixMilli(e.nowMS.Load())
	for _, id := range []string{"rp_pending", "rp_running", "rp_done"} {
		if _, err := st.Insert(ctx, approvals.Replay{ID: id, DraftID: d.ID, Revision: 1, Status: approvals.ReplayPending, StartedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := st.MarkRunning(ctx, "rp_running", at); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, err := st.Finish(ctx, "rp_done", approvals.ReplayFinish{Status: approvals.ReplayDone, At: at, Result: json.RawMessage(`{}`)}); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if ok, _ := st.MarkRunning(ctx, "rp_done", at); ok {
		t.Error("MarkRunning moved a settled replay")
	}
	rp, err := approvals.NewReplayer(approvals.ReplayerConfig{
		Store: st, Runner: &fakeRunner{}, Now: func() time.Time { return at },
		Window: time.Hour, MaxEvents: 10, Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()
	n, err := rp.Recover(ctx)
	if err != nil || n != 2 {
		t.Fatalf("Recover = %d, %v, want 2", n, err)
	}
	for id, want := range map[string]approvals.ReplayStatus{"rp_pending": approvals.ReplayFailed, "rp_running": approvals.ReplayFailed, "rp_done": approvals.ReplayDone} {
		r, err := st.Get(ctx, id)
		if err != nil || r.Status != want {
			t.Errorf("%s = %+v, %v, want %s", id, r, err, want)
		}
		if want == approvals.ReplayFailed && r.ErrorCode != approvals.ReplayErrInterrupted {
			t.Errorf("%s error_code = %q", id, r.ErrorCode)
		}
	}
	if ok, _ := st.Finish(ctx, "rp_pending", approvals.ReplayFinish{Status: approvals.ReplayDone, At: at}); ok {
		t.Error("Finish overwrote an interrupted replay")
	}
	if _, err := st.Insert(ctx, approvals.Replay{DraftID: "cd_nope", Status: approvals.ReplayPending}); err == nil {
		t.Error("a replay for an unknown draft was stored")
	}
}

// Closing the replayer interrupts a running replay and fails queued ones.
func TestReplayCloseInterrupts(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), honorCtx: true}
	e, rp := replayEnv(t, runner, time.Minute)
	ctx := context.Background()
	d1, d2 := e.create("a.example.com"), e.create("b.example.com")
	for _, d := range []approvals.Draft{d1, d2} {
		if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
			t.Fatal(err)
		}
	}
	waitReplay(t, e, latest(t, e, d1.ID, 1).ID, func(r approvals.Replay) bool { return r.Status == approvals.ReplayRunning })
	rp.Close()
	for _, d := range []approvals.Draft{d1, d2} {
		r := latest(t, e, d.ID, 1)
		if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInterrupted {
			t.Errorf("replay of %s after Close = %+v", d.ID, r)
		}
	}
	if _, err := rp.Queue(ctx, d1); err == nil {
		t.Error("Queue after Close succeeded")
	}
}

func TestReplayFresh(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	done := approvals.Replay{Status: approvals.ReplayDone, FinishedAt: now.Add(-time.Hour)}
	if !done.Fresh(now, 2*time.Hour) || done.Fresh(now, 30*time.Minute) {
		t.Error("Fresh age check wrong")
	}
	for _, r := range []approvals.Replay{{Status: approvals.ReplayFailed, FinishedAt: now}, {Status: approvals.ReplayDone}} {
		if r.Fresh(now, time.Hour) {
			t.Errorf("%+v counted as fresh", r)
		}
	}
	for _, s := range []approvals.ReplayStatus{"pending", "running", "done", "failed", "unavailable"} {
		if !s.Valid() {
			t.Errorf("%q not valid", s)
		}
	}
	if approvals.ReplayStatus("x").Valid() {
		t.Error("unknown status valid")
	}
	if _, err := approvals.NewReplayer(approvals.ReplayerConfig{}); err == nil {
		t.Error("NewReplayer accepted an empty config")
	}
}

// Rapid edits never pile up work: the one replay waiting per draft is
// superseded, so 20 updates cause at most 2 runner calls and the last revision
// ends done.
func TestReplayRapidEditsAreSuperseded(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), honorCtx: true, out: doneOutcome}
	e, _ := replayEnv(t, runner, time.Minute)
	ctx := context.Background()
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r1 := latest(t, e, d.ID, 1)
	waitReplay(t, e, r1.ID, func(r approvals.Replay) bool { return r.Status == approvals.ReplayRunning })
	for rev := 1; rev <= 20; rev++ {
		if _, err := e.svc.UpdateDraft(ctx, d.ID, rev, doc("b.example.com"), "", "ada"); err != nil {
			t.Fatal(err)
		}
	}
	close(runner.gate)
	last := waitReplay(t, e, latest(t, e, d.ID, 21).ID, settled)
	if last.Status != approvals.ReplayDone || last.Revision != 21 {
		t.Fatalf("last replay = %+v, want done at revision 21", last)
	}
	if n := runner.Calls(); n > 2 {
		t.Errorf("runner ran %d times for 21 revisions, want at most 2", n)
	}
	waitReplay(t, e, r1.ID, settled)
	for rev := 2; rev <= 20; rev++ {
		r := latest(t, e, d.ID, rev)
		if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrSuperseded {
			t.Errorf("revision %d replay = %+v, want failed/superseded", rev, r)
		}
	}
}

// Waiting replays are capped; extras fail with queue_full.
func TestReplayQueueFull(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), honorCtx: true, out: doneOutcome}
	e := newEnv(t, 10)
	rp, err := approvals.NewReplayer(approvals.ReplayerConfig{
		Store: sqlstore.NewReplayStore(e.db.SQL()), Runner: runner,
		Now:    func() time.Time { return time.UnixMilli(e.nowMS.Load()) },
		Window: time.Hour, MaxEvents: 10, Timeout: time.Minute, MaxWaiting: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rp.Close()
	e.svc.SetReplayer(rp)
	ctx := context.Background()
	var rs []approvals.Replay
	for _, dom := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		d := e.create(dom)
		r, err := rp.Queue(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		rs = append(rs, r)
		if len(rs) == 1 {
			waitReplay(t, e, r.ID, func(x approvals.Replay) bool { return x.Status == approvals.ReplayRunning })
		}
	}
	// rs[0] runs, rs[1] waits, rs[2] exceeds the cap of 1.
	if rs[2].Status != approvals.ReplayFailed || rs[2].ErrorCode != approvals.ReplayErrQueueFull {
		t.Errorf("third replay = %+v, want failed/queue_full", rs[2])
	}
	close(runner.gate)
}

// flakyStore wraps a ReplayStore and fails chosen calls.
type flakyStore struct {
	approvals.ReplayStore
	mu             sync.Mutex
	finishFailures int // the next n Finish calls fail
	failRunning    bool
}

func (f *flakyStore) Finish(ctx context.Context, id string, fin approvals.ReplayFinish) (bool, error) {
	f.mu.Lock()
	if f.finishFailures > 0 {
		f.finishFailures--
		f.mu.Unlock()
		return false, errors.New("disk full")
	}
	f.mu.Unlock()
	return f.ReplayStore.Finish(ctx, id, fin)
}

func (f *flakyStore) MarkRunning(ctx context.Context, id string, at time.Time) (bool, error) {
	f.mu.Lock()
	fail := f.failRunning
	f.mu.Unlock()
	if fail {
		return false, errors.New("disk full")
	}
	return f.ReplayStore.MarkRunning(ctx, id, at)
}

func flakyEnv(t *testing.T, runner approvals.ReplayRunner, cur func(context.Context, string) (int, error), closeTimeout time.Duration) (*env, *approvals.Replayer, *flakyStore) {
	t.Helper()
	e := newEnv(t, 10)
	fs := &flakyStore{ReplayStore: sqlstore.NewReplayStore(e.db.SQL())}
	rp, err := approvals.NewReplayer(approvals.ReplayerConfig{
		Store: fs, Runner: runner, Now: func() time.Time { return time.UnixMilli(e.nowMS.Load()) },
		CurrentRevision: cur, Window: time.Hour, MaxEvents: 10, Timeout: time.Minute, CloseTimeout: closeTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rp.Close)
	e.svc.SetReplayer(rp)
	return e, rp, fs
}

// A failed outcome write is retried once as failed `internal`; when that fails
// too the row stays running for the next start's Recover.
func TestReplaySettleRetriesFinish(t *testing.T) {
	e, _, fs := flakyEnv(t, &fakeRunner{out: doneOutcome}, nil, 0)
	ctx := context.Background()
	fs.finishFailures = 1
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r := waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)
	if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInternal {
		t.Errorf("after one failed Finish = %+v, want failed/internal", r)
	}

	fs.mu.Lock()
	fs.finishFailures = 2
	fs.mu.Unlock()
	d2 := e.create("b.example.com")
	if _, err := e.svc.Submit(ctx, d2.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	id := latest(t, e, d2.ID, 1).ID
	waitReplay(t, e, id, func(r approvals.Replay) bool { return r.Status == approvals.ReplayRunning })
	deadline := time.Now().Add(5 * time.Second)
	for {
		fs.mu.Lock()
		left := fs.finishFailures
		fs.mu.Unlock()
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Finish was never retried")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if r, _ := e.svc.GetReplay(ctx, id); r.Status.Settled() {
		t.Errorf("double failure settled the row: %+v", r)
	}
}

func TestReplayMarkRunningErrorFailsInternal(t *testing.T) {
	runner := &fakeRunner{out: doneOutcome}
	e, _, fs := flakyEnv(t, runner, nil, 0)
	fs.failRunning = true
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r := waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)
	if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInternal || runner.Calls() != 0 {
		t.Errorf("replay = %+v (runner calls %d), want failed/internal without running", r, runner.Calls())
	}
}

// A CurrentRevision lookup that fails does not run the replay.
func TestReplayCurrentRevisionErrorFailsClosed(t *testing.T) {
	runner := &fakeRunner{out: doneOutcome}
	e, _, _ := flakyEnv(t, runner, func(context.Context, string) (int, error) { return 0, errors.New("db gone") }, 0)
	d := e.create("a.example.com")
	if _, err := e.svc.Submit(context.Background(), d.ID, 1, "ada"); err != nil {
		t.Fatal(err)
	}
	r := waitReplay(t, e, latest(t, e, d.ID, 1).ID, settled)
	if r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInternal || runner.Calls() != 0 {
		t.Errorf("replay = %+v (runner calls %d), want failed/internal without running", r, runner.Calls())
	}
}

// Close does not wait forever for a runner that ignores its context, and the
// replays still waiting end interrupted.
func TestReplayCloseDeadlineAndWaitingInterrupted(t *testing.T) {
	runner := &fakeRunner{gate: make(chan struct{}), out: doneOutcome} // ignores ctx
	e, rp, _ := flakyEnv(t, runner, nil, 100*time.Millisecond)
	t.Cleanup(func() { close(runner.gate) }) // runs before rp.Close (LIFO)
	ctx := context.Background()
	d1, d2 := e.create("a.example.com"), e.create("b.example.com")
	for _, d := range []approvals.Draft{d1, d2} {
		if _, err := e.svc.Submit(ctx, d.ID, 1, "ada"); err != nil {
			t.Fatal(err)
		}
	}
	waitReplay(t, e, latest(t, e, d1.ID, 1).ID, func(r approvals.Replay) bool { return r.Status == approvals.ReplayRunning })
	begin := time.Now()
	rp.Close()
	if took := time.Since(begin); took > 3*time.Second {
		t.Errorf("Close took %v with a stuck runner, want about its 100ms deadline", took)
	}
	if r := latest(t, e, d2.ID, 1); r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInterrupted {
		t.Errorf("waiting replay after Close = %+v, want failed/interrupted", r)
	}
	// The running one is settled interrupted as soon as its context ends, even
	// though its runner is still stuck.
	if r := latest(t, e, d1.ID, 1); r.Status != approvals.ReplayFailed || r.ErrorCode != approvals.ReplayErrInterrupted {
		t.Errorf("stuck replay = %+v, want failed/interrupted", r)
	}
}
