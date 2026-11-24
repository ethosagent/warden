package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ReplayStatus is where a replay is in its life.
type ReplayStatus string

const (
	// ReplayPending: queued, waiting for the one replay slot.
	ReplayPending ReplayStatus = "pending"
	// ReplayRunning: scanning events and comparing.
	ReplayRunning ReplayStatus = "running"
	// ReplayDone: finished with a result.
	ReplayDone ReplayStatus = "done"
	// ReplayFailed: did not finish; ErrorCode says why.
	ReplayFailed ReplayStatus = "failed"
	// ReplayUnavailable: finished, but the window held no events to compare.
	ReplayUnavailable ReplayStatus = "unavailable"
)

// Valid reports whether s is a known status.
func (s ReplayStatus) Valid() bool {
	switch s {
	case ReplayPending, ReplayRunning, ReplayDone, ReplayFailed, ReplayUnavailable:
		return true
	}
	return false
}

// Settled reports whether the replay has finished, one way or another.
func (s ReplayStatus) Settled() bool {
	return s == ReplayDone || s == ReplayFailed || s == ReplayUnavailable
}

// Replay error codes (the error_code column).
const (
	// ReplayErrTimeout: the run outlived replayTimeout; a late result is
	// discarded.
	ReplayErrTimeout = "timeout"
	// ReplayErrInterrupted: the control plane stopped while the replay was
	// queued or running.
	ReplayErrInterrupted = "interrupted"
	// ReplayErrInternal: the runner failed for a reason it did not name.
	ReplayErrInternal = "internal"
	// ReplayErrNoEvents: not an error code but the reason of an unavailable
	// replay: the window held no events.
	ReplayErrNoEvents = "no_events"
)

// ReplayError is a runner failure with a stable, value-free code (stored as
// error_code). Msg is logged only, never stored or shown.
type ReplayError struct {
	Code string
	Err  error
}

func (e *ReplayError) Error() string { return fmt.Sprintf("replay %s: %v", e.Code, e.Err) }
func (e *ReplayError) Unwrap() error { return e.Err }

// Replay is one comparison of a draft revision against its base, over recent
// fleet events. Result is the runner's JSON (for a policy: policyeval's
// CompareResult), which holds no URL, path, query, header or group list.
type Replay struct {
	ID          string
	DraftID     string
	Revision    int
	BaseVersion int64
	Status      ReplayStatus
	// WindowFrom and WindowTo bound the events read.
	WindowFrom, WindowTo time.Time
	EventsScanned        int
	// Truncated is true when the event cap was reached before the window ended.
	Truncated  bool
	Result     json.RawMessage
	ErrorCode  string
	StartedAt  time.Time
	FinishedAt time.Time
}

// Fresh reports whether the replay is done and finished no longer than maxAge
// before now: the evidence an approval may cite.
func (r Replay) Fresh(now time.Time, maxAge time.Duration) bool {
	return r.Status == ReplayDone && !r.FinishedAt.IsZero() && now.Sub(r.FinishedAt) <= maxAge
}

// ReplayFinish is how a replay ended.
type ReplayFinish struct {
	Status        ReplayStatus
	EventsScanned int
	Truncated     bool
	Result        json.RawMessage
	ErrorCode     string
	At            time.Time
}

// ReplayStore persists replays (the draft_replays table).
type ReplayStore interface {
	// Insert stores a new pending replay, assigning its ID when r.ID is empty,
	// and returns it.
	Insert(ctx context.Context, r Replay) (Replay, error)
	// MarkRunning moves a pending replay to running. It reports false (and
	// writes nothing) when the replay is no longer pending.
	MarkRunning(ctx context.Context, id string, at time.Time) (bool, error)
	// Finish settles a pending or running replay. It reports false (and writes
	// nothing) when the replay was already settled, so a late result can never
	// overwrite a timeout.
	Finish(ctx context.Context, id string, f ReplayFinish) (bool, error)
	// Get returns the replay or ErrReplayNotFound.
	Get(ctx context.Context, id string) (Replay, error)
	// Latest returns the newest replay of the draft at revision (0 = any
	// revision); ok is false when there is none.
	Latest(ctx context.Context, draftID string, revision int) (r Replay, ok bool, err error)
	// FailUnsettled marks every pending and running replay failed with code and
	// returns how many it moved (startup recovery).
	FailUnsettled(ctx context.Context, code string, at time.Time) (int, error)
}

// ErrReplayNotFound: no replay has the id.
var ErrReplayNotFound = errors.New("approvals: replay not found")

// ErrReplayBusy: another replay holds the one replay slot, or the draft's own
// replay is still in flight.
var ErrReplayBusy = errors.New("approvals: a replay is already running")

// ErrReplayRateLimited: the draft was re-run less than a minute ago.
var ErrReplayRateLimited = errors.New("approvals: replay was re-run too recently")

// ReplayRerunInterval is the least time between two re-runs of one draft.
const ReplayRerunInterval = time.Minute

// ReplayRequest is what a ReplayRunner is asked to compare.
type ReplayRequest struct {
	Draft Draft
	// Since is the start of the event window; Limit caps the events read.
	Since time.Time
	Limit int
}

// ReplayOutcome is what a ReplayRunner found.
type ReplayOutcome struct {
	// Result is the stored JSON.
	Result json.RawMessage
	// Events is how many events were compared; Scanned how many were read.
	Events, Scanned int
	// Truncated is true when Limit stopped the scan.
	Truncated bool
	// ToAllowGroups and ToDenyGroups are counts only, for the run log.
	ToAllowGroups, ToDenyGroups int
}

// ReplayRunner compares a draft with its base over fleet events. It must stop
// when ctx ends. It lives in the control plane, which owns the fleet store and
// the policy decoder.
type ReplayRunner interface {
	Run(ctx context.Context, req ReplayRequest) (ReplayOutcome, error)
}

// Replay error codes added by the queue.
const (
	// ReplayErrSuperseded: a newer revision of the draft was queued, or the
	// draft moved on, before this replay started.
	ReplayErrSuperseded = "superseded"
	// ReplayErrQueueFull: too many replays were already waiting.
	ReplayErrQueueFull = "queue_full"
)

// DefaultMaxWaitingReplays caps replays waiting for the one slot when
// ReplayerConfig.MaxWaiting is zero.
const DefaultMaxWaitingReplays = 200

// ReplayerConfig wires a Replayer.
type ReplayerConfig struct {
	Store  ReplayStore
	Runner ReplayRunner
	Now    func() time.Time
	// CurrentRevision returns a draft's current revision; a waiting replay of
	// an older revision is skipped as superseded. Nil disables the check.
	CurrentRevision func(ctx context.Context, draftID string) (int, error)
	// Window, MaxEvents and Timeout are console.approvals.replayWindow,
	// replayMaxEvents and replayTimeout.
	Window    time.Duration
	MaxEvents int
	Timeout   time.Duration
	// MaxWaiting caps replays waiting for the slot (0 = DefaultMaxWaitingReplays);
	// extras fail with queue_full.
	MaxWaiting int
	Logger     *slog.Logger
}

// Replayer queues and runs replays: one at a time on one worker goroutine,
// each bounded by Timeout. A draft has at most one waiting replay (a newer
// revision supersedes it) and the waiting set is capped, so edits never pile up
// work. Queueing never waits for a run.
type Replayer struct {
	cfg ReplayerConfig
	// baseCtx ends at Close; a running replay then fails as interrupted.
	baseCtx context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	wake    chan struct{}

	mu sync.Mutex
	// waiting holds the replays not yet started, by draft id, and order their
	// draft ids oldest first.
	waiting map[string]queuedReplay
	order   []string
	// running is the draft id being replayed ("" = the worker is idle).
	running string
	// manual is when each draft was last re-run by hand.
	manual map[string]time.Time
	closed bool
}

type queuedReplay struct {
	rp Replay
	d  Draft
}

// NewReplayer validates cfg, starts the worker and returns a Replayer.
func NewReplayer(cfg ReplayerConfig) (*Replayer, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("approvals: replayer needs a store")
	case cfg.Runner == nil:
		return nil, errors.New("approvals: replayer needs a runner")
	case cfg.Now == nil:
		return nil, errors.New("approvals: replayer needs a clock")
	case cfg.Window <= 0, cfg.MaxEvents <= 0, cfg.Timeout <= 0:
		return nil, errors.New("approvals: replayer needs a positive window, event cap and timeout")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.MaxWaiting <= 0 {
		cfg.MaxWaiting = DefaultMaxWaitingReplays
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Replayer{
		cfg: cfg, baseCtx: ctx, cancel: cancel, wake: make(chan struct{}, 1),
		waiting: map[string]queuedReplay{}, manual: map[string]time.Time{},
	}
	r.wg.Add(1)
	go r.worker()
	return r, nil
}

// Recover marks the replays a previous process left pending or running as
// failed with `interrupted`. Call it once at startup, before queueing.
func (r *Replayer) Recover(ctx context.Context) (int, error) {
	return r.cfg.Store.FailUnsettled(ctx, ReplayErrInterrupted, r.cfg.Now())
}

// Close stops accepting replays, interrupts the running one, fails the waiting
// ones as interrupted and waits for the worker. It is safe to call twice.
func (r *Replayer) Close() {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	r.cancel()
	r.wg.Wait()
	r.mu.Lock()
	rest := r.drainLocked()
	r.mu.Unlock()
	for _, q := range rest {
		r.settle(q.rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInterrupted}, time.Time{}, ReplayOutcome{}, nil)
	}
}

func (r *Replayer) drainLocked() []queuedReplay {
	out := make([]queuedReplay, 0, len(r.waiting))
	for _, id := range r.order {
		if q, ok := r.waiting[id]; ok {
			out = append(out, q)
		}
	}
	r.waiting = map[string]queuedReplay{}
	r.order = nil
	return out
}

// Queue stores a pending replay of d's current revision and returns at once;
// the worker runs it when the slot is free. It is what submit and every new
// revision call. A replay of the same draft still waiting is superseded.
func (r *Replayer) Queue(ctx context.Context, d Draft) (Replay, error) {
	return r.enqueue(ctx, d, false)
}

// Rerun queues a replay of the draft's current revision when allowed: at most
// one per ReplayRerunInterval per draft (ErrReplayRateLimited), and only while
// the slot is free and nothing waits (ErrReplayBusy).
func (r *Replayer) Rerun(ctx context.Context, d Draft) (Replay, error) {
	return r.enqueue(ctx, d, true)
}

func (r *Replayer) enqueue(ctx context.Context, d Draft, manual bool) (Replay, error) {
	now := r.cfg.Now()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Replay{}, errors.New("approvals: replayer is closed")
	}
	if manual {
		if r.running != "" || len(r.waiting) > 0 {
			r.mu.Unlock()
			return Replay{}, ErrReplayBusy
		}
		if last, ok := r.manual[d.ID]; ok && now.Sub(last) < ReplayRerunInterval {
			r.mu.Unlock()
			return Replay{}, ErrReplayRateLimited
		}
	}
	r.mu.Unlock()

	rp, err := r.cfg.Store.Insert(ctx, Replay{
		DraftID: d.ID, Revision: d.Revision, BaseVersion: d.BaseVersion,
		Status: ReplayPending, WindowFrom: now.Add(-r.cfg.Window), WindowTo: now, StartedAt: now,
	})
	if err != nil {
		return Replay{}, err
	}

	var drop []queuedReplay
	var full bool
	r.mu.Lock()
	switch {
	case r.closed:
		r.mu.Unlock()
		r.settle(rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInterrupted}, time.Time{}, ReplayOutcome{}, nil)
		return Replay{}, errors.New("approvals: replayer is closed")
	default:
		if old, ok := r.waiting[d.ID]; ok {
			drop = append(drop, old)
			delete(r.waiting, d.ID)
			r.removeOrderLocked(d.ID)
		}
		if len(r.waiting) >= r.cfg.MaxWaiting {
			full = true
		} else {
			r.waiting[d.ID] = queuedReplay{rp: rp, d: d}
			r.order = append(r.order, d.ID)
		}
		if manual {
			r.manual[d.ID] = now
		}
	}
	r.mu.Unlock()

	for _, q := range drop {
		r.settle(q.rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrSuperseded}, time.Time{}, ReplayOutcome{}, nil)
	}
	if full {
		r.settle(rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrQueueFull}, time.Time{}, ReplayOutcome{}, nil)
		rp.Status, rp.ErrorCode = ReplayFailed, ReplayErrQueueFull
		return rp, nil
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return rp, nil
}

func (r *Replayer) removeOrderLocked(id string) {
	for i, o := range r.order {
		if o == id {
			r.order = append(r.order[:i], r.order[i+1:]...)
			return
		}
	}
}

// next pops the oldest waiting replay and marks it running.
func (r *Replayer) next() (queuedReplay, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for len(r.order) > 0 {
		id := r.order[0]
		r.order = r.order[1:]
		if q, ok := r.waiting[id]; ok {
			delete(r.waiting, id)
			r.running = id
			return q, true
		}
	}
	return queuedReplay{}, false
}

func (r *Replayer) worker() {
	defer r.wg.Done()
	for {
		for {
			q, ok := r.next()
			if !ok || r.baseCtx.Err() != nil {
				if ok {
					r.settle(q.rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInterrupted}, time.Time{}, ReplayOutcome{}, nil)
					r.clearRunning()
				}
				break
			}
			r.run(q)
			r.clearRunning()
		}
		select {
		case <-r.wake:
		case <-r.baseCtx.Done():
			return
		}
	}
}

func (r *Replayer) clearRunning() {
	r.mu.Lock()
	r.running = ""
	r.mu.Unlock()
}

type replayRun struct {
	out ReplayOutcome
	err error
}

// run executes one replay on the worker. The slot (the worker) is held until
// the runner returns, even after a timeout, so a runner that ignores its
// context cannot pile up behind its successors.
func (r *Replayer) run(q queuedReplay) {
	rp, d := q.rp, q.d
	ctx0 := context.WithoutCancel(r.baseCtx)
	if r.cfg.CurrentRevision != nil {
		if cur, err := r.cfg.CurrentRevision(ctx0, d.ID); err == nil && cur != d.Revision {
			r.settle(rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrSuperseded}, time.Time{}, ReplayOutcome{}, nil)
			return
		}
	}
	started := r.cfg.Now()
	ok, err := r.cfg.Store.MarkRunning(ctx0, rp.ID, started)
	if err != nil {
		r.settle(rp, ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInternal}, started, ReplayOutcome{}, err)
		return
	}
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.baseCtx, r.cfg.Timeout)
	defer cancel()
	ch := make(chan replayRun, 1)
	go func() {
		out, rerr := r.cfg.Runner.Run(ctx, ReplayRequest{Draft: d, Since: rp.WindowFrom, Limit: r.cfg.MaxEvents})
		ch <- replayRun{out, rerr}
	}()
	var res replayRun
	select {
	case res = <-ch:
		// A result that arrives after the deadline is discarded.
		if ctx.Err() != nil {
			res = replayRun{err: ctx.Err()}
		}
	case <-ctx.Done():
		res = replayRun{err: ctx.Err()}
		r.settle(rp, r.finishFor(res), started, ReplayOutcome{}, res.err)
		<-ch // hold the slot until the runner unwinds
		return
	}
	r.settle(rp, r.finishFor(res), started, res.out, res.err)
}

// finishFor maps a run result to how the replay ended.
func (r *Replayer) finishFor(res replayRun) ReplayFinish {
	switch {
	case errors.Is(res.err, context.DeadlineExceeded):
		return ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrTimeout}
	case errors.Is(res.err, context.Canceled):
		return ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInterrupted}
	case res.err != nil:
		code := ReplayErrInternal
		var re *ReplayError
		if errors.As(res.err, &re) && re.Code != "" {
			code = re.Code
		}
		return ReplayFinish{Status: ReplayFailed, ErrorCode: code}
	case res.out.Events == 0:
		return ReplayFinish{Status: ReplayUnavailable, ErrorCode: ReplayErrNoEvents, EventsScanned: res.out.Scanned, Truncated: res.out.Truncated}
	}
	return ReplayFinish{Status: ReplayDone, EventsScanned: res.out.Scanned, Truncated: res.out.Truncated, Result: res.out.Result}
}

// settle stores the outcome (once more as failed `internal` if the store write
// fails) and logs the run: identifiers, status, code and counts only, never a
// domain or a user. cause is the runner's error, logged for the operator.
func (r *Replayer) settle(rp Replay, f ReplayFinish, started time.Time, out ReplayOutcome, cause error) {
	now := r.cfg.Now()
	f.At = now
	wctx := context.WithoutCancel(r.baseCtx)
	ok, err := r.cfg.Store.Finish(wctx, rp.ID, f)
	if err != nil {
		r.cfg.Logger.Error("change_draft_replay: cannot store the replay outcome", "draft_id", rp.DraftID, "error", err)
		f = ReplayFinish{Status: ReplayFailed, ErrorCode: ReplayErrInternal, At: now}
		if ok, err = r.cfg.Store.Finish(wctx, rp.ID, f); err != nil {
			r.cfg.Logger.Error("change_draft_replay: cannot store the failure either; startup recovery will settle it", "draft_id", rp.DraftID, "error", err)
			return
		}
	}
	if !ok {
		return
	}
	var ms int64
	if !started.IsZero() {
		ms = now.Sub(started).Milliseconds()
	}
	attrs := []any{
		"draft_id", rp.DraftID, "status", string(f.Status), "events", out.Events, "duration_ms", ms,
		"changed_to_allow_groups", out.ToAllowGroups, "changed_to_deny_groups", out.ToDenyGroups,
	}
	if f.ErrorCode != "" {
		attrs = append(attrs, "error_code", f.ErrorCode)
	}
	if cause != nil {
		attrs = append(attrs, "error", cause.Error())
	}
	r.cfg.Logger.Info("change_draft_replay", attrs...)
}
