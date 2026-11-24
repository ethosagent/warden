package approvals_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

const rawSecret = "AKIA-raw-secret-access-key-value"

// syncBuf is a goroutine-safe log sink.
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

type env struct {
	t      *testing.T
	path   string
	db     *cpstate.DB
	store  *sqlstore.Store
	svc    *approvals.Service
	logs   *syncBuf
	nowMS  atomic.Int64
	apply  *fakeApplier
	maxOpn int
}

// fakeApplier stands in for the control plane's policy Applier.
type fakeApplier struct {
	// enter and release, when set, pause Apply mid-publish: it signals enter,
	// then waits for release.
	enter   chan struct{}
	release chan struct{}
	mu      sync.Mutex
	calls   int
	version int64
	err     error
}

func (f *fakeApplier) Apply(_ context.Context, _ approvals.Draft) (int64, error) {
	if f.enter != nil {
		f.enter <- struct{}{}
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	f.version++
	return f.version, nil
}

func (f *fakeApplier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// redact mirrors controlplane.RedactCredentials for the fields the tests set.
func redact(d approvals.Doc) approvals.Doc {
	if d.Settings == nil || d.Settings.Secrets == nil || d.Settings.Secrets.SecretAccessKey == "" {
		return d
	}
	s := *d.Settings
	sec := *s.Secrets
	sec.SecretAccessKey = "sha256:0123456789abcdef"
	s.Secrets = &sec
	d.Settings = &s
	return d
}

func newEnv(t *testing.T, maxOpen int) *env {
	t.Helper()
	e := &env{t: t, logs: &syncBuf{}, apply: &fakeApplier{}, maxOpn: maxOpen}
	e.nowMS.Store(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC).UnixMilli())
	e.path = filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(context.Background(), e.path, cpstate.Enable(sqlstore.Migrations(), sqlstore.EnabledMigrationIDs()...))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	now := func() time.Time { return time.UnixMilli(e.nowMS.Load()) }
	logger := slog.New(slog.NewTextHandler(e.logs, nil))
	e.store = sqlstore.New(db.SQL(), now, logger)
	e.svc, err = approvals.NewService(approvals.ServiceConfig{
		Store:    e.store,
		Appliers: map[approvals.Target]approvals.Applier{approvals.TargetPolicy: e.apply},
		Redact:   redact, Now: now, DraftTTL: 24 * time.Hour, MaxOpenDrafts: maxOpen, Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) advance(d time.Duration) { e.nowMS.Add(d.Milliseconds()) }

func doc(domain string) approvals.Doc {
	return approvals.Doc{Allowlist: []config.AllowlistEntry{{Domain: domain}}, Denylist: []config.DenylistEntry{}}
}

var ada = approvals.Author{Iss: "https://idp", Sub: "ada", Email: "ada@example.com", Kind: "oidc"}

func (e *env) create(domain string) approvals.Draft {
	e.t.Helper()
	d, err := e.svc.CreateDraft(context.Background(), approvals.TargetPolicy, doc(domain), ada, approvals.Provenance{Message: "add " + domain}, 3)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func (e *env) pending(domain string) approvals.Draft {
	e.t.Helper()
	d := e.create(domain)
	d, err := e.store.Submit(context.Background(), d.ID, d.Revision, "ada")
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func decision(d approvals.Draft, sub string, dec approvals.Decision) approvals.DecisionInput {
	return approvals.DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: dec,
		Approver:     approvals.Author{Iss: "https://idp", Sub: sub, Email: sub + "@example.com", Kind: "oidc"},
		ApproverRole: "editor",
	}
}

func TestDraftStoreCreateGet(t *testing.T) {
	e := newEnv(t, 10)
	d := e.create("a.example.com")
	if d.State != approvals.StateDraft || d.Revision != 1 || d.BaseVersion != 3 || d.Target != approvals.TargetPolicy {
		t.Fatalf("draft = %+v", d)
	}
	if d.Source != approvals.SourceConsole || d.Message != "add a.example.com" || d.Author != ada {
		t.Errorf("draft source/message/author = %s %q %+v", d.Source, d.Message, d.Author)
	}
	if want := time.UnixMilli(e.nowMS.Load()).Add(24 * time.Hour); !d.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want now+draftTTL %v", d.ExpiresAt, want)
	}
	got, err := e.store.Get(context.Background(), d.ID)
	if err != nil {
		t.Fatal(err)
	}
	pd, err := got.PolicyDoc()
	if err != nil || len(pd.Allowlist) != 1 || pd.Allowlist[0].Domain != "a.example.com" {
		t.Fatalf("PolicyDoc = %+v, %v", pd, err)
	}
	if _, err := e.store.Get(context.Background(), "cd_missing"); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("Get(missing) = %v, want ErrNotFound", err)
	}
	if _, err := e.svc.CreateDraft(context.Background(), approvals.TargetAgents, doc("x"), ada, approvals.Provenance{}, 0); !errors.Is(err, approvals.ErrUnsupportedTarget) {
		t.Errorf("agents target = %v, want ErrUnsupportedTarget", err)
	}
	if _, err := e.svc.CreateDraft(context.Background(), approvals.TargetPolicy, doc("x"), approvals.Author{}, approvals.Provenance{}, 0); err == nil {
		t.Error("a draft without an author sub was accepted")
	}
}

func TestDraftStoreTooManyDrafts(t *testing.T) {
	e := newEnv(t, 2)
	d1 := e.create("1.example.com")
	e.create("2.example.com")
	if _, err := e.svc.CreateDraft(context.Background(), approvals.TargetPolicy, doc("3.example.com"), ada, approvals.Provenance{}, 0); !errors.Is(err, approvals.ErrTooManyDrafts) {
		t.Fatalf("third draft = %v, want ErrTooManyDrafts", err)
	}
	// A closed draft frees its slot.
	if _, err := e.store.Withdraw(context.Background(), d1.ID, d1.Revision, "ada"); err != nil {
		t.Fatal(err)
	}
	e.create("3.example.com")
}

// TestDraftStoreIllegalOnApplied: Submit, Update and Withdraw on an applied
// draft return ErrIllegalTransition and leave the row as it was.
func TestDraftStoreIllegalOnApplied(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	applied, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob")
	if err != nil {
		t.Fatal(err)
	}
	if applied.State != approvals.StateApplied || applied.AppliedVersion != 1 {
		t.Fatalf("applied = %+v", applied)
	}
	before := e.row(d.ID)
	in := approvals.UpdateInput{ExpectedRevision: d.Revision, DocJSON: json.RawMessage(`{}`), DocSHA256: "x"}
	_, errSubmit := e.store.Submit(ctx, d.ID, d.Revision, "ada")
	_, errUpdate := e.store.Update(ctx, d.ID, in, "ada")
	_, errWithdraw := e.store.Withdraw(ctx, d.ID, d.Revision, "ada")
	_, errRebase := e.store.Rebase(ctx, d.ID, in, "ada")
	_, _, errDecide := e.store.RecordDecision(ctx, d.ID, decision(d, "bob", approvals.DecisionApprove))
	for name, err := range map[string]error{"submit": errSubmit, "update": errUpdate, "withdraw": errWithdraw, "rebase": errRebase, "decision": errDecide} {
		if !errors.Is(err, approvals.ErrIllegalTransition) {
			t.Errorf("%s on an applied draft = %v, want ErrIllegalTransition", name, err)
		}
	}
	if after := e.row(d.ID); after != before {
		t.Errorf("row changed by illegal transitions:\n before %q\n after  %q", before, after)
	}
}

// row is a stable dump of one change_drafts row for before/after comparison.
func (e *env) row(id string) string {
	e.t.Helper()
	var s string
	err := e.db.SQL().QueryRow(`SELECT state||'|'||revision||'|'||base_version||'|'||doc_sha256||'|'||updated_at||'|'||last_error||'|'||applied_version
		FROM change_drafts WHERE id = ?`, id).Scan(&s)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

// TestDraftStoreCASRace: 20 goroutines race RecordDecision(reject) and Withdraw
// on one pending draft; exactly one state change wins and the rest fail.
func TestDraftStoreCASRace(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var err error
			if i%2 == 0 {
				_, _, err = e.store.RecordDecision(ctx, d.ID, decision(d, fmt.Sprintf("rev%d", i), approvals.DecisionReject))
			} else {
				_, err = e.store.Withdraw(ctx, d.ID, d.Revision, "ada")
			}
			if err == nil {
				wins.Add(1)
				return
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	if wins.Load() != 1 {
		t.Fatalf("%d goroutines changed the state, want exactly 1", wins.Load())
	}
	for err := range errs {
		if !errors.Is(err, approvals.ErrIllegalTransition) && !errors.Is(err, approvals.ErrStateChanged) {
			t.Errorf("loser error = %v, want ErrIllegalTransition or ErrStateChanged", err)
		}
	}
	got, err := e.store.Get(ctx, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != approvals.StateRejected && got.State != approvals.StateWithdrawn {
		t.Errorf("final state = %s", got.State)
	}
	// Exactly one transition line for the pending draft's single change.
	if n := strings.Count(e.logs.String(), "state_from=pending"); n != 1 {
		t.Errorf("%d transitions logged out of pending, want 1", n)
	}
}

// TestDraftStoreRevisionVoidsApprovals: an edit creates revision n+1 and the
// approvals of revision n no longer count; a reviewer who saw revision n cannot
// approve revision n+1 with the old digest.
func TestDraftStoreRevisionVoidsApprovals(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	_, n, err := e.store.RecordDecision(ctx, d.ID, decision(d, "bob", approvals.DecisionApprove))
	if err != nil || n != 1 {
		t.Fatalf("first approval = %d, %v", n, err)
	}
	if _, _, err := e.store.RecordDecision(ctx, d.ID, decision(d, "bob", approvals.DecisionApprove)); !errors.Is(err, approvals.ErrDuplicateDecision) {
		t.Fatalf("same approver twice = %v, want ErrDuplicateDecision", err)
	}
	_, n, err = e.store.RecordDecision(ctx, d.ID, decision(d, "cy", approvals.DecisionApprove))
	if err != nil || n != 2 {
		t.Fatalf("second approver = %d, %v", n, err)
	}

	d2, err := e.svc.UpdateDraft(ctx, d.ID, d.Revision, doc("b.example.com"), "", "ada")
	if err != nil {
		t.Fatal(err)
	}
	if d2.Revision != 2 || d2.State != approvals.StatePending || d2.DocSHA256 == d.DocSHA256 || d2.Message != d.Message {
		t.Fatalf("after update = rev %d state %s sha-changed=%v message %q", d2.Revision, d2.State, d2.DocSHA256 != d.DocSHA256, d2.Message)
	}
	// The stale reviewer's decision on the old revision is refused.
	if _, _, err := e.store.RecordDecision(ctx, d.ID, decision(d, "dee", approvals.DecisionApprove)); !errors.Is(err, approvals.ErrStateChanged) {
		t.Errorf("approving the old revision = %v, want ErrStateChanged", err)
	}
	// A right revision with the wrong digest is refused too.
	bad := decision(d2, "dee", approvals.DecisionApprove)
	bad.DocSHA256 = d.DocSHA256
	if _, _, err := e.store.RecordDecision(ctx, d.ID, bad); !errors.Is(err, approvals.ErrStateChanged) {
		t.Errorf("approving with the old digest = %v, want ErrStateChanged", err)
	}
	// Bob approves revision 2 afresh: only that approval counts.
	_, n, err = e.store.RecordDecision(ctx, d.ID, decision(d2, "bob", approvals.DecisionApprove))
	if err != nil || n != 1 {
		t.Fatalf("bob on revision 2 = %d, %v; want 1 (revision 1's approvals are void)", n, err)
	}
	rows, err := e.store.Approvals(ctx, d.ID)
	if err != nil || len(rows) != 3 {
		t.Fatalf("approvals = %d rows, %v; want the 3 append-only rows", len(rows), err)
	}
	if rows[0].Revision != 1 || rows[2].Revision != 2 || rows[0].Decision != approvals.DecisionApprove {
		t.Errorf("approval rows = %+v", rows)
	}
	// Stale expected revision on update.
	if _, err := e.svc.UpdateDraft(ctx, d.ID, d.Revision, doc("c.example.com"), "", "ada"); !errors.Is(err, approvals.ErrStateChanged) {
		t.Errorf("update from revision 1 = %v, want ErrStateChanged", err)
	}
}

func TestDraftStoreApprovalsAppendOnly(t *testing.T) {
	e := newEnv(t, 10)
	d := e.pending("a.example.com")
	if _, _, err := e.store.RecordDecision(context.Background(), d.ID, decision(d, "bob", approvals.DecisionApprove)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.SQL().Exec("UPDATE change_approvals SET comment = 'x'"); err == nil {
		t.Error("change_approvals accepted an UPDATE")
	}
	if _, err := e.db.SQL().Exec("DELETE FROM change_approvals"); err == nil {
		t.Error("change_approvals accepted a DELETE")
	}
}

func TestDraftStoreRejectAndRebaseFlow(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	rej, _, err := e.store.RecordDecision(ctx, d.ID, decision(d, "bob", approvals.DecisionReject))
	if err != nil || rej.State != approvals.StateRejected {
		t.Fatalf("reject = %+v, %v", rej, err)
	}

	// Stale base: apply moves the draft to needs_rebase; rebase brings it back.
	d = e.pending("b.example.com")
	e.apply.err = fmt.Errorf("head moved: %w", approvals.ErrRebaseRequired)
	nd, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob")
	if !errors.Is(err, approvals.ErrRebaseRequired) || nd.State != approvals.StateNeedsRebase || nd.LastError == "" {
		t.Fatalf("stale apply = %+v, %v", nd, err)
	}
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("apply of a needs_rebase draft = %v, want ErrIllegalTransition", err)
	}
	if _, err := e.svc.UpdateDraft(ctx, d.ID, d.Revision, doc("x"), "", "ada"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("update of a needs_rebase draft = %v, want ErrIllegalTransition (rebase is the edit)", err)
	}
	rb, err := e.svc.RebaseDraft(ctx, d.ID, d.Revision, 9, doc("b.example.com"), "", "ada")
	if err != nil || rb.State != approvals.StatePending || rb.Revision != d.Revision+1 || rb.BaseVersion != 9 || rb.LastError != "" {
		t.Fatalf("rebase = %+v, %v", rb, err)
	}
}

func TestDraftStoreRecordErrorKeepsPending(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	e.apply.err = errors.New("invalid policy: bad entry")
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); err == nil || !strings.Contains(err.Error(), "invalid policy") {
		t.Fatalf("apply = %v, want the validation error", err)
	}
	got, _ := e.store.Get(ctx, d.ID)
	if got.State != approvals.StatePending || got.LastError != "invalid policy: bad entry" {
		t.Fatalf("after a failed apply = %s %q, want pending with last_error", got.State, got.LastError)
	}
	// Outside applying, FailApply is illegal.
	if _, err := e.store.FailApply(ctx, d.ID, d.Revision, "x", "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("FailApply on a pending draft = %v, want ErrIllegalTransition", err)
	}
}

// TestDraftStoreWithdrawRacesApply: while an Apply is publishing, withdraw,
// update, reject and expiry are all refused, so the draft cannot be withdrawn
// after its version went out.
func TestDraftStoreWithdrawRacesApply(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	e.apply.enter, e.apply.release = make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); done <- err }()
	<-e.apply.enter // the Applier is running: the draft is claimed

	got, _ := e.store.Get(ctx, d.ID)
	if got.State != approvals.StateApplying {
		t.Fatalf("state during the publish = %s, want applying", got.State)
	}
	in := approvals.UpdateInput{ExpectedRevision: d.Revision, DocJSON: json.RawMessage(`{}`), DocSHA256: "x"}
	_, errW := e.store.Withdraw(ctx, d.ID, d.Revision, "ada")
	_, errU := e.store.Update(ctx, d.ID, in, "ada")
	_, _, errR := e.store.RecordDecision(ctx, d.ID, decision(d, "cy", approvals.DecisionReject))
	_, errB := e.store.BeginApply(ctx, d.ID, d.Revision, "bob")
	e.advance(48 * time.Hour)
	expired, errE := e.store.ExpireDue(ctx, time.UnixMilli(e.nowMS.Load()))
	for name, err := range map[string]error{"withdraw": errW, "update": errU, "reject": errR, "second apply": errB} {
		if !errors.Is(err, approvals.ErrIllegalTransition) {
			t.Errorf("%s during apply = %v, want ErrIllegalTransition", name, err)
		}
	}
	if errE != nil || len(expired) != 0 {
		t.Errorf("expiry during apply = %d drafts, %v; want none", len(expired), errE)
	}
	close(e.apply.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got, _ = e.store.Get(ctx, d.ID)
	if got.State != approvals.StateApplied || got.AppliedVersion != 1 || e.apply.Calls() != 1 {
		t.Errorf("after the publish = %s v%d, %d calls", got.State, got.AppliedVersion, e.apply.Calls())
	}
}

// TestDraftStoreReconcile: drafts a crash left in applying become applied when
// a version names them and return to pending when none does.
func TestDraftStoreReconcile(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	published := e.pending("p.example.com")
	lost := e.pending("l.example.com")
	for _, d := range []approvals.Draft{published, lost} {
		if _, err := e.store.BeginApply(ctx, d.ID, d.Revision, "bob"); err != nil { // then the process "dies"
			t.Fatal(err)
		}
	}
	find := func(_ context.Context, id string, rev int) (int64, bool, error) {
		return 7, id == published.ID && rev == published.Revision, nil
	}
	n, err := e.svc.Reconcile(ctx, find)
	if err != nil || n != 2 {
		t.Fatalf("Reconcile = %d, %v; want 2", n, err)
	}
	if got, _ := e.store.Get(ctx, published.ID); got.State != approvals.StateApplied || got.AppliedVersion != 7 {
		t.Errorf("published draft = %s v%d, want applied v7", got.State, got.AppliedVersion)
	}
	got, _ := e.store.Get(ctx, lost.ID)
	if got.State != approvals.StatePending || got.LastError == "" || got.AppliedVersion != 0 {
		t.Errorf("unpublished draft = %s %q v%d, want pending with last_error", got.State, got.LastError, got.AppliedVersion)
	}
	if n, err := e.svc.Reconcile(ctx, find); err != nil || n != 0 {
		t.Errorf("second Reconcile = %d, %v; want 0", n, err)
	}
}

func TestDraftServiceMessageCap(t *testing.T) {
	e := newEnv(t, 10)
	long := strings.Repeat("é", 600)
	d, err := e.svc.CreateDraft(context.Background(), approvals.TargetPolicy, doc("a.example.com"), ada, approvals.Provenance{Message: long}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(d.Message)); n != 512 {
		t.Errorf("message = %d runes, want capped at 512", n)
	}
	d, err = e.svc.UpdateDraft(context.Background(), d.ID, d.Revision, doc("b.example.com"), long, "ada")
	if err != nil || len([]rune(d.Message)) != 512 {
		t.Errorf("updated message = %d runes, %v", len([]rune(d.Message)), err)
	}
}

func TestDraftStoreApplyOnce(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	d := e.pending("a.example.com")
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision+1, "bob"); !errors.Is(err, approvals.ErrStateChanged) {
		t.Errorf("apply at the wrong revision = %v, want ErrStateChanged", err)
	}
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("second apply = %v, want ErrIllegalTransition", err)
	}
	if e.apply.Calls() != 1 {
		t.Errorf("applier called %d times, want 1", e.apply.Calls())
	}
	if _, err := e.svc.Apply(ctx, "cd_nope", 1, "bob"); !errors.Is(err, approvals.ErrNotFound) {
		t.Errorf("apply of a missing draft = %v", err)
	}
	// A draft in state draft is not applicable either.
	dd := e.create("z.example.com")
	if _, err := e.svc.Apply(ctx, dd.ID, dd.Revision, "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("apply of an unsubmitted draft = %v, want ErrIllegalTransition", err)
	}
	unsupported, err := approvals.NewService(approvals.ServiceConfig{Store: e.store, Redact: redact, Now: time.Now, DraftTTL: time.Hour, MaxOpenDrafts: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unsupported.Apply(ctx, d.ID, d.Revision, "bob"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("service without an applier on an applied draft = %v", err)
	}
	p2 := e.pending("y.example.com")
	if _, err := unsupported.Apply(ctx, p2.ID, p2.Revision, "bob"); !errors.Is(err, approvals.ErrUnsupportedTarget) {
		t.Errorf("service without an applier = %v, want ErrUnsupportedTarget", err)
	}
}

// TestDraftStoreNoRawSecret: a raw secretAccessKey never reaches change_drafts
// or the database file, including its WAL.
func TestDraftStoreNoRawSecret(t *testing.T) {
	e := newEnv(t, 10)
	in := doc("a.example.com")
	in.Settings = &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws", SecretAccessKey: rawSecret}}
	d, err := e.svc.CreateDraft(context.Background(), approvals.TargetPolicy, in, ada, approvals.Provenance{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(d.DocJSON), rawSecret) || !strings.Contains(string(d.DocJSON), "sha256:0123456789abcdef") {
		t.Fatalf("doc_json = %s", d.DocJSON)
	}
	d, err = e.svc.UpdateDraft(context.Background(), d.ID, d.Revision, in, "", "ada")
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := e.db.SQL().QueryRow("SELECT doc_json FROM change_drafts WHERE id = ?", d.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, rawSecret) {
		t.Fatalf("stored doc_json holds the raw secret: %s", stored)
	}
	if _, err := e.db.SQL().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{e.path, e.path + "-wal"} {
		b, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(rawSecret)) {
			t.Errorf("%s contains the raw secret", filepath.Base(f))
		}
	}
	if strings.Contains(e.logs.String(), rawSecret) {
		t.Error("logs contain the raw secret")
	}
}

func TestDraftStoreList(t *testing.T) {
	e := newEnv(t, 50)
	ctx := context.Background()
	var ids []string
	for i := range 5 {
		d := e.create(fmt.Sprintf("%d.example.com", i))
		ids = append(ids, d.ID)
		e.advance(time.Second)
	}
	if _, err := e.store.Submit(ctx, ids[0], 1, "ada"); err != nil {
		t.Fatal(err)
	}
	var seen []string
	cursor := ""
	for {
		page, next, err := e.store.List(ctx, approvals.Filter{Target: approvals.TargetPolicy}, cursor, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range page {
			if len(d.DocJSON) != 0 {
				t.Errorf("List returned DocJSON for %s", d.ID)
			}
			seen = append(seen, d.ID)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(seen) != 5 || seen[0] != ids[4] || seen[4] != ids[0] {
		t.Errorf("paged order = %v, want newest first over %v", seen, ids)
	}
	pend, _, err := e.store.List(ctx, approvals.Filter{State: approvals.StatePending}, "", 0)
	if err != nil || len(pend) != 1 || pend[0].ID != ids[0] {
		t.Errorf("pending filter = %v, %v", pend, err)
	}
	none, _, _ := e.store.List(ctx, approvals.Filter{AuthorSub: "nobody"}, "", 10)
	if len(none) != 0 {
		t.Errorf("author filter matched %d", len(none))
	}
	if _, _, err := e.store.List(ctx, approvals.Filter{}, "garbage", 10); err == nil {
		t.Error("malformed cursor accepted")
	}
}

// TestDraftExpiry: the sweeper moves open drafts past expires_at to expired and
// leaves closed and fresh ones alone.
func TestDraftExpiry(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	old := e.create("old.example.com")
	oldPending := e.pending("oldp.example.com")
	applied := e.pending("applied.example.com")
	if _, err := e.svc.Apply(ctx, applied.ID, applied.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	e.advance(25 * time.Hour)
	fresh := e.create("fresh.example.com")

	n, err := e.svc.Sweep(ctx)
	if err != nil || n != 2 {
		t.Fatalf("Sweep = %d, %v; want 2", n, err)
	}
	for _, id := range []string{old.ID, oldPending.ID} {
		if got, _ := e.store.Get(ctx, id); got.State != approvals.StateExpired {
			t.Errorf("draft %s = %s, want expired", id, got.State)
		}
	}
	if got, _ := e.store.Get(ctx, fresh.ID); got.State != approvals.StateDraft {
		t.Errorf("fresh draft = %s", got.State)
	}
	if got, _ := e.store.Get(ctx, applied.ID); got.State != approvals.StateApplied {
		t.Errorf("applied draft = %s", got.State)
	}
	if n, err := e.svc.Sweep(ctx); err != nil || n != 0 {
		t.Errorf("second Sweep = %d, %v; want 0", n, err)
	}
	if _, err := e.store.Withdraw(ctx, old.ID, old.Revision, "ada"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("withdraw of an expired draft = %v", err)
	}
}

// TestDraftStoreTransitionLog: each transition logs one change_draft_transition
// line with ids and states, never the doc or settings values.
func TestDraftStoreTransitionLog(t *testing.T) {
	e := newEnv(t, 10)
	ctx := context.Background()
	in := doc("secret-looking-host.example.com")
	in.Settings = &config.SettingsWire{Secrets: &config.SecretsSettings{SecretAccessKey: rawSecret}}
	d, err := e.svc.CreateDraft(ctx, approvals.TargetPolicy, in, ada, approvals.Provenance{Message: "do not log me"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Submit(ctx, d.ID, d.Revision, "ada"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Apply(ctx, d.ID, d.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	logs := e.logs.String()
	if n := strings.Count(logs, "msg=change_draft_transition"); n != 4 {
		t.Fatalf("%d transition lines, want 4 (create, submit, claim, apply):\n%s", n, logs)
	}
	for _, want := range []string{
		"draft_id=" + d.ID, "revision=1", "target=policy", "state_from=draft", "state_to=pending",
		"state_from=pending", "state_to=applying", "state_from=applying", "state_to=applied", "actor_sub=bob",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	for _, leak := range []string{"secret-looking-host", rawSecret, "do not log me", "allowlist"} {
		if strings.Contains(logs, leak) {
			t.Errorf("logs leak %q", leak)
		}
	}
}

// TestDraftStoreMigrationOptional: without Enable, the approvals migration
// creates no table but the downgrade guard still knows its id.
func TestDraftStoreMigrationOptional(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warden-cp.db")
	db, err := cpstate.Open(context.Background(), path, sqlstore.Migrations())
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.SQL().QueryRow("SELECT count(*) FROM sqlite_master WHERE name LIKE 'change_%'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("tables without Enable = %d, %v; want none", n, err)
	}
	_ = db.Close()
	db, err = cpstate.Open(context.Background(), path, cpstate.Enable(sqlstore.Migrations(), sqlstore.EnabledMigrationIDs()...))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'change_drafts_%' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var idx []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		idx = append(idx, s)
	}
	if strings.Join(idx, ",") != "change_drafts_author_sub,change_drafts_state_target" {
		t.Errorf("indexes = %v", idx)
	}
}
