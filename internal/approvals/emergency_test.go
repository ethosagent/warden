package approvals_test

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
)

// The break-glass emergency apply (W-P2-APPR-07) at the Gate and Service level,
// over the real SQLite store and a fake Applier that records what it was given.

var (
	bgActor = approvals.Author{Iss: "warden-breakglass", Sub: "breakglass:ops", Email: "ops@example.com", Kind: approvals.AuthorKindBreakglass}
	oidcAdm = approvals.Author{Iss: "https://idp", Sub: "root", Email: "root@example.com", Kind: "oidc"}

	reason     = "dex is down and the payments vendor is blocked"
	reviewNote = "checked with the vendor"
)

// emApplier is an Applier and EmergencyApplier that records every call and the
// Clearance it received. A nil enter means it never pauses.
type emApplier struct {
	mu      sync.Mutex
	events  *[]string
	calls   int
	clrs    []approvals.Clearance
	actors  []approvals.Author
	version int64
	err     error
}

func (a *emApplier) Apply(context.Context, approvals.Draft) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.version++
	return a.version, a.err
}

func (a *emApplier) ApplyEmergency(_ context.Context, _ approvals.Draft, clr approvals.Clearance, actor approvals.Author) (int64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls++
	*a.events = append(*a.events, "publish")
	a.clrs = append(a.clrs, clr)
	a.actors = append(a.actors, actor)
	if a.err != nil {
		return 0, a.err
	}
	a.version++
	return a.version, nil
}

func (a *emApplier) setErr(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

func (a *emApplier) count() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// emEnv is an env whose service allows emergency applies and classifies drafts
// against an empty base, so every added allow entry is widening.
type emEnv struct {
	*env
	gate   *approvals.Gate
	em     *emApplier
	events []string
	hook   func(ctx context.Context, d approvals.Draft) error
	// repaired receives Reconcile's emergency repair callbacks.
	repaired func(d approvals.Draft, actorSub string)
}

func newEmEnv(t *testing.T, allow bool) *emEnv {
	t.Helper()
	e := newEnv(t, 50)
	x := &emEnv{env: e}
	x.em = &emApplier{events: &x.events}
	x.hook = func(_ context.Context, d approvals.Draft) error {
		x.events = append(x.events, "audit:"+d.ID)
		return nil
	}
	now := func() time.Time { return time.UnixMilli(e.nowMS.Load()) }
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:    e.store,
		Appliers: map[approvals.Target]approvals.Applier{approvals.TargetPolicy: x.em},
		Redact:   redact, Now: now, DraftTTL: 24 * time.Hour, MaxOpenDrafts: 50,
		AllowEmergencyApply: allow,
		OnEmergencyRepaired: func(d approvals.Draft, a string) {
			if x.repaired != nil {
				x.repaired(d, a)
			}
		},
		BaseDoc: func(context.Context, int64) (approvals.Doc, error) { return approvals.Doc{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	x.gate = approvals.NewGate(true, svc)
	return x
}

func (x *emEnv) input(d approvals.Draft) approvals.EmergencyInput {
	return approvals.EmergencyInput{ID: d.ID, Actor: bgActor, Reason: reason, BeforePublish: func(ctx context.Context, dd approvals.Draft) error { return x.hook(ctx, dd) }}
}

// pendingClassified is a submitted, classified draft adding domain.
func (x *emEnv) pendingClassified(domain string) approvals.Draft {
	x.t.Helper()
	d := x.create(domain)
	if d.RequiredRole == "" {
		x.t.Fatal("the draft was not classified")
	}
	d, err := x.store.Submit(context.Background(), d.ID, d.Revision, "ada")
	if err != nil {
		x.t.Fatal(err)
	}
	return d
}

func (x *emEnv) stored(d approvals.Draft) approvals.Draft {
	x.t.Helper()
	got, err := x.store.Get(context.Background(), d.ID)
	if err != nil {
		x.t.Fatal(err)
	}
	return got
}

// TestEmergencyApply: the happy path, step by step. The audit hook and the
// durable emergency row both exist before the publish, the Clearance covers
// exactly this doc, and the draft waits for review.
func TestEmergencyApply(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("vendor.example.com")

	got, err := x.gate.EmergencyApply(ctx, x.input(d))
	if err != nil {
		t.Fatalf("EmergencyApply = %v", err)
	}
	if got.State != approvals.StateAppliedUnreviewed || got.AppliedVersion != 1 {
		t.Errorf("draft = %s v%d, want applied_unreviewed v1", got.State, got.AppliedVersion)
	}
	if want := []string{"audit:" + d.ID, "publish"}; strings.Join(x.events, ",") != strings.Join(want, ",") {
		t.Errorf("events = %v, want the audit hook before the publish: %v", x.events, want)
	}
	if len(x.em.clrs) != 1 || !x.em.clrs[0].Valid() || x.em.clrs[0].Reason() != "emergency" {
		t.Fatalf("clearances = %+v, want one emergency clearance", x.em.clrs)
	}
	dd, _ := d.PolicyDoc()
	if !x.em.clrs[0].Covers(dd) {
		t.Error("the clearance does not cover the claimed draft's doc")
	}
	if x.em.clrs[0].Covers(doc("other.example.com")) {
		t.Error("the clearance covers another doc")
	}
	if x.em.actors[0].Sub != bgActor.Sub {
		t.Errorf("publish actor = %+v, want the break-glass session", x.em.actors[0])
	}
	rows, err := x.store.Approvals(ctx, d.ID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("approvals = %+v, %v", rows, err)
	}
	r := rows[0]
	if r.Decision != approvals.DecisionEmergency || r.Comment != reason || r.AuthMethod != approvals.AuthorKindBreakglass ||
		r.ApproverRole != "admin" || r.DocSHA256 != d.DocSHA256 || r.Revision != d.Revision {
		t.Errorf("emergency row = %+v", r)
	}
	// An applied_unreviewed draft is closed to every other transition.
	if _, err := x.store.Withdraw(ctx, d.ID, d.Revision, "ada"); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("withdraw of an applied_unreviewed draft = %v, want ErrIllegalTransition", err)
	}
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("a second emergency apply = %v, want ErrIllegalTransition", err)
	}
	if x.em.count() != 1 {
		t.Errorf("publishes = %d, want 1", x.em.count())
	}
}

// TestEmergencyApplyNeedsRebaseDraft: a needs_rebase draft can be applied too.
func TestEmergencyApplyNeedsRebaseDraft(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("rb.example.com")
	if _, err := x.store.BeginApply(ctx, d.ID, d.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := x.store.MarkNeedsRebase(ctx, d.ID, d.Revision, "head moved", "bob"); err != nil {
		t.Fatal(err)
	}
	got, err := x.gate.EmergencyApply(ctx, x.input(d))
	if err != nil || got.State != approvals.StateAppliedUnreviewed {
		t.Fatalf("EmergencyApply of a needs_rebase draft = %+v, %v", got, err)
	}
}

// TestEmergencyApplyRefusals: every refusal publishes nothing, writes no
// emergency row and leaves the draft as it was.
func TestEmergencyApplyRefusals(t *testing.T) {
	ctx := context.Background()
	type tc struct {
		name string
		want error
		run  func(x *emEnv, d approvals.Draft) error
	}
	cases := []tc{
		{"a nil gate", approvals.ErrGateUnavailable, func(x *emEnv, d approvals.Draft) error {
			_, err := (*approvals.Gate)(nil).EmergencyApply(ctx, x.input(d))
			return err
		}},
		{"a disabled gate", approvals.ErrGateUnavailable, func(x *emEnv, d approvals.Draft) error {
			_, err := approvals.NewGate(false, x.svc).EmergencyApply(ctx, x.input(d))
			return err
		}},
		{"an enabled gate with no service", approvals.ErrGateUnavailable, func(x *emEnv, d approvals.Draft) error {
			_, err := approvals.NewGate(true, nil).EmergencyApply(ctx, x.input(d))
			return err
		}},
		{"an OIDC admin", approvals.ErrBreakglassRequired, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Actor = oidcAdm
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a forged break-glass subject on an oidc author", approvals.ErrBreakglassRequired, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Actor = approvals.Author{Iss: "https://idp", Sub: "breakglass:ops", Kind: "oidc"}
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a break-glass actor with no subject", approvals.ErrBreakglassRequired, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Actor.Sub = " "
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a 9 character reason", approvals.ErrEmergencyReason, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Reason = "123456789"
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a reason of spaces", approvals.ErrEmergencyReason, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Reason = strings.Repeat(" ", 30)
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a 513 character reason", approvals.ErrEmergencyReason, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Reason = strings.Repeat("é", 513)
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"no audit hook", approvals.ErrEmergencyAudit, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.BeforePublish = nil
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"a stale revision", approvals.ErrRevisionChanged, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.Revision = d.Revision + 1
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"another doc digest", approvals.ErrRevisionChanged, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.DocSHA256 = strings.Repeat("0", 64)
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"an unknown draft", approvals.ErrNotFound, func(x *emEnv, d approvals.Draft) error {
			in := x.input(d)
			in.ID = "cd_missing"
			_, err := x.gate.EmergencyApply(ctx, in)
			return err
		}},
		{"an expired draft", approvals.ErrDraftExpired, func(x *emEnv, d approvals.Draft) error {
			x.advance(25 * time.Hour)
			_, err := x.gate.EmergencyApply(ctx, x.input(d))
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newEmEnv(t, true)
			d := x.pendingClassified("r.example.com")
			if err := c.run(x, d); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if got := x.stored(d); got.State != approvals.StatePending {
				t.Errorf("draft = %s, want it left pending", got.State)
			}
			if rows, _ := x.store.Approvals(ctx, d.ID); len(rows) != 0 {
				t.Errorf("a refusal wrote approval rows: %+v", rows)
			}
			if x.em.count() != 0 || len(x.events) != 0 {
				t.Errorf("a refusal published or audited: calls %d events %v", x.em.count(), x.events)
			}
		})
	}
}

// TestEmergencyApplyOffByDefault: allowEmergencyApply false refuses every call.
func TestEmergencyApplyOffByDefault(t *testing.T) {
	x := newEmEnv(t, false)
	d := x.pendingClassified("off.example.com")
	if _, err := x.gate.EmergencyApply(context.Background(), x.input(d)); !errors.Is(err, approvals.ErrEmergencyDisabled) {
		t.Fatalf("EmergencyApply = %v, want ErrEmergencyDisabled", err)
	}
	if x.em.count() != 0 || x.stored(d).State != approvals.StatePending {
		t.Error("a disabled emergency apply changed something")
	}
}

// TestEmergencyApplyStates: only pending and needs_rebase drafts qualify, and
// an unclassified draft never does.
func TestEmergencyApplyStates(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	draft := x.create("st1.example.com") // still draft
	if _, err := x.gate.EmergencyApply(ctx, x.input(draft)); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("a draft-state draft = %v, want ErrIllegalTransition", err)
	}
	rej := x.pendingClassified("st2.example.com")
	if _, _, err := x.store.RecordDecision(ctx, rej.ID, decision(rej, "bob", approvals.DecisionReject)); err != nil {
		t.Fatal(err)
	}
	if _, err := x.gate.EmergencyApply(ctx, x.input(rej)); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("a rejected draft = %v, want ErrIllegalTransition", err)
	}
	// A service with no BaseDoc leaves drafts unclassified: fail closed.
	u := newEnv(t, 5)
	now := func() time.Time { return time.UnixMilli(u.nowMS.Load()) }
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:    u.store,
		Appliers: map[approvals.Target]approvals.Applier{approvals.TargetPolicy: x.em},
		Redact:   redact, Now: now, DraftTTL: time.Hour, MaxOpenDrafts: 5, AllowEmergencyApply: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	u.svc = svc
	un := u.pending("un.example.com")
	_, err = approvals.NewGate(true, svc).EmergencyApply(ctx, approvals.EmergencyInput{
		ID: un.ID, Actor: bgActor, Reason: reason, BeforePublish: func(context.Context, approvals.Draft) error { return nil },
	})
	if !errors.Is(err, approvals.ErrUnclassified) {
		t.Errorf("an unclassified draft = %v, want ErrUnclassified", err)
	}
}

// TestEmergencyApplyUnsupportedApplier: a target whose Applier cannot publish
// an emergency clearance is refused before anything is claimed.
func TestEmergencyApplyUnsupportedApplier(t *testing.T) {
	x := newEmEnv(t, true)
	plain := &fakeApplier{}
	now := func() time.Time { return time.UnixMilli(x.nowMS.Load()) }
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:    x.store,
		Appliers: map[approvals.Target]approvals.Applier{approvals.TargetPolicy: plain},
		Redact:   redact, Now: now, DraftTTL: time.Hour, MaxOpenDrafts: 50, AllowEmergencyApply: true,
		BaseDoc: func(context.Context, int64) (approvals.Doc, error) { return approvals.Doc{}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	d := x.pendingClassified("plain.example.com")
	_, err = approvals.NewGate(true, svc).EmergencyApply(context.Background(), x.input(d))
	if !errors.Is(err, approvals.ErrUnsupportedTarget) || plain.Calls() != 0 || x.stored(d).State != approvals.StatePending {
		t.Fatalf("EmergencyApply = %v (calls %d, state %s), want ErrUnsupportedTarget and an untouched draft", err, plain.Calls(), x.stored(d).State)
	}
}

// TestEmergencyApplyFailures: a refused publish, a moved head and a failed
// audit write each leave the draft usable, publish at most once, and keep the
// emergency row of an attempt that got as far as the claim.
func TestEmergencyApplyFailures(t *testing.T) {
	ctx := context.Background()
	t.Run("a refused publish returns the draft to pending and a retry succeeds", func(t *testing.T) {
		x := newEmEnv(t, true)
		d := x.pendingClassified("f1.example.com")
		x.em.setErr(errors.New("validation failed"))
		if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err == nil || !strings.Contains(err.Error(), "validation failed") {
			t.Fatalf("EmergencyApply = %v", err)
		}
		got := x.stored(d)
		if got.State != approvals.StatePending || !strings.Contains(got.LastError, "validation failed") || got.AppliedVersion != 0 {
			t.Errorf("draft = %s %q v%d, want pending with last_error", got.State, got.LastError, got.AppliedVersion)
		}
		if rows, _ := x.store.Approvals(ctx, d.ID); len(rows) != 1 || rows[0].Decision != approvals.DecisionEmergency {
			t.Errorf("rows = %+v, want the attempt's emergency row kept", rows)
		}
		x.em.setErr(nil)
		got, err := x.gate.EmergencyApply(ctx, x.input(d))
		if err != nil || got.State != approvals.StateAppliedUnreviewed {
			t.Fatalf("retry = %+v, %v", got, err)
		}
		if rows, _ := x.store.Approvals(ctx, d.ID); len(rows) != 1 {
			t.Errorf("rows after the retry = %d, want the one original row", len(rows))
		}
	})
	t.Run("a moved head makes the draft needs_rebase", func(t *testing.T) {
		x := newEmEnv(t, true)
		d := x.pendingClassified("f2.example.com")
		x.em.setErr(approvals.ErrRebaseRequired)
		got, err := x.gate.EmergencyApply(ctx, x.input(d))
		if !errors.Is(err, approvals.ErrRebaseRequired) || got.State != approvals.StateNeedsRebase {
			t.Fatalf("EmergencyApply = %+v, %v; want needs_rebase and ErrRebaseRequired", got, err)
		}
	})
	t.Run("a failed audit write publishes nothing", func(t *testing.T) {
		x := newEmEnv(t, true)
		d := x.pendingClassified("f3.example.com")
		x.hook = func(context.Context, approvals.Draft) error { return errors.New("audit store down") }
		_, err := x.gate.EmergencyApply(ctx, x.input(d))
		if !errors.Is(err, approvals.ErrEmergencyAudit) {
			t.Fatalf("EmergencyApply = %v, want ErrEmergencyAudit", err)
		}
		if x.em.count() != 0 || x.stored(d).State != approvals.StatePending {
			t.Errorf("a failed audit write published (calls %d, state %s)", x.em.count(), x.stored(d).State)
		}
	})
	t.Run("the claim blocks a concurrent withdraw while publishing", func(t *testing.T) {
		x := newEmEnv(t, true)
		d := x.pendingClassified("f4.example.com")
		x.hook = func(ctx context.Context, dd approvals.Draft) error {
			if _, err := x.store.Withdraw(ctx, dd.ID, dd.Revision, "ada"); !errors.Is(err, approvals.ErrIllegalTransition) {
				t.Errorf("withdraw while claimed = %v, want ErrIllegalTransition", err)
			}
			return nil
		}
		if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err != nil {
			t.Fatal(err)
		}
	})
}

// TestEmergencyApplyRateLimit: five claims in ten minutes, then a refusal that
// writes nothing; the window slides.
func TestEmergencyApplyRateLimit(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	for i := range 5 {
		d := x.pendingClassified("rl" + string(rune('a'+i)) + ".example.com")
		if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err != nil {
			t.Fatalf("apply %d = %v", i, err)
		}
	}
	d := x.pendingClassified("rlz.example.com")
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); !errors.Is(err, approvals.ErrEmergencyRateLimited) {
		t.Fatalf("sixth apply = %v, want ErrEmergencyRateLimited", err)
	}
	if rows, _ := x.store.Approvals(ctx, d.ID); len(rows) != 0 || x.stored(d).State != approvals.StatePending {
		t.Error("a rate-limited call claimed the draft")
	}
	x.advance(11 * time.Minute)
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err != nil {
		t.Errorf("apply after the window = %v", err)
	}
}

// TestEmergencyReview: an admin closes the loop; a break-glass session, an
// editor and a draft with nothing to review are refused.
func TestEmergencyReview(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("rv.example.com")
	if _, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: oidcAdm, Role: config.RoleAdmin, Comment: reviewNote}); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("review of a pending draft = %v, want ErrIllegalTransition", err)
	}
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		in   approvals.ReviewInput
		want any
	}{
		{"a break-glass session", approvals.ReviewInput{ID: d.ID, Reviewer: bgActor, Role: config.RoleAdmin, Comment: reviewNote}, approvals.ErrBreakglassReviewer},
		{"an editor", approvals.ReviewInput{ID: d.ID, Reviewer: oidcAdm, Role: config.RoleEditor, Comment: reviewNote}, &approvals.RoleRequiredError{}},
		{"no reviewer", approvals.ReviewInput{ID: d.ID, Role: config.RoleAdmin, Comment: reviewNote}, nil},
		{"a stale revision", approvals.ReviewInput{ID: d.ID, Revision: 9, Reviewer: oidcAdm, Role: config.RoleAdmin, Comment: reviewNote}, approvals.ErrRevisionChanged},
		{"another doc digest", approvals.ReviewInput{ID: d.ID, DocSHA256: "x", Reviewer: oidcAdm, Role: config.RoleAdmin, Comment: reviewNote}, approvals.ErrRevisionChanged},
	} {
		_, err := x.svc.Review(ctx, c.in)
		var rr *approvals.RoleRequiredError
		switch w := c.want.(type) {
		case *approvals.RoleRequiredError:
			if !errors.As(err, &rr) || rr.Need != config.RoleAdmin {
				t.Errorf("%s: err = %v, want a RoleRequiredError for admin", c.name, err)
			}
		case error:
			if !errors.Is(err, w) {
				t.Errorf("%s: err = %v, want %v", c.name, err, w)
			}
		default:
			if err == nil {
				t.Errorf("%s: want an error", c.name)
			}
		}
		if got := x.stored(d); got.State != approvals.StateAppliedUnreviewed {
			t.Fatalf("%s: draft = %s, want it still applied_unreviewed", c.name, got.State)
		}
	}
	got, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: oidcAdm, Role: config.RoleAdmin, Comment: "checked the change with the vendor"})
	if err != nil || got.State != approvals.StateApplied || got.AppliedVersion != 1 {
		t.Fatalf("Review = %+v, %v", got, err)
	}
	rows, _ := x.store.Approvals(ctx, d.ID)
	if len(rows) != 2 || rows[1].Decision != approvals.DecisionPostReview || rows[1].ApproverSub != oidcAdm.Sub ||
		rows[1].Comment != "checked the change with the vendor" || rows[1].ApproverRole != "admin" {
		t.Errorf("rows = %+v, want the emergency row then a post_review row", rows)
	}
	if _, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: oidcAdm, Role: config.RoleAdmin, Comment: reviewNote}); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("a second review = %v, want ErrIllegalTransition", err)
	}
	// An emergency apply cannot be repeated on a reviewed draft either.
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("emergency apply of an applied draft = %v, want ErrIllegalTransition", err)
	}
}

// TestEmergencyReconcile: a crash after the publish settles an interrupted
// emergency apply as applied_unreviewed, never as an ordinary applied draft.
func TestEmergencyReconcile(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	em := x.pendingClassified("rc1.example.com")
	plain := x.pendingClassified("rc2.example.com")
	// The emergency claim, then the process "dies" before the outcome.
	if _, err := x.store.BeginEmergency(ctx, em.ID, approvals.DecisionInput{
		Revision: em.Revision, DocSHA256: em.DocSHA256, Decision: approvals.DecisionEmergency,
		Approver: bgActor, ApproverRole: "admin", Comment: reason,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := x.store.BeginApply(ctx, plain.ID, plain.Revision, "bob"); err != nil {
		t.Fatal(err)
	}
	n, err := x.svc.Reconcile(ctx, func(context.Context, string, int) (int64, bool, error) { return 9, true, nil })
	if err != nil || n != 2 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if got := x.stored(em); got.State != approvals.StateAppliedUnreviewed || got.AppliedVersion != 9 {
		t.Errorf("emergency draft = %s v%d, want applied_unreviewed v9", got.State, got.AppliedVersion)
	}
	if got := x.stored(plain); got.State != approvals.StateApplied {
		t.Errorf("ordinary draft = %s, want applied", got.State)
	}
}

// TestStoreEmergencyGuards: the store refuses what the Gate would never send.
func TestStoreEmergencyGuards(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("sg.example.com")
	in := approvals.DecisionInput{Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: approvals.DecisionEmergency, Approver: bgActor, ApproverRole: "admin", Comment: reason}
	bad := in
	bad.Decision = approvals.DecisionApprove
	if _, err := x.store.BeginEmergency(ctx, d.ID, bad); err == nil {
		t.Error("BeginEmergency accepted an approve decision")
	}
	bad = in
	bad.DocSHA256 = "other"
	if _, err := x.store.BeginEmergency(ctx, d.ID, bad); !errors.Is(err, approvals.ErrStateChanged) {
		t.Errorf("BeginEmergency with another digest = %v, want ErrStateChanged", err)
	}
	if got := x.stored(d); got.State != approvals.StatePending {
		t.Errorf("a refused claim left the draft %s", got.State)
	}
	// The same actor already rejected this revision: that is not an emergency retry.
	rej := x.pendingClassified("sg2.example.com")
	rin := in
	rin.Revision, rin.DocSHA256 = rej.Revision, rej.DocSHA256
	rd := rin
	rd.Decision = approvals.DecisionReject
	if _, _, err := x.store.RecordDecision(ctx, rej.ID, rd); err != nil {
		t.Fatal(err)
	}
	if _, err := x.store.BeginEmergency(ctx, rej.ID, rin); err == nil {
		t.Error("BeginEmergency of a rejected draft succeeded")
	}
	rv := in
	rv.Decision = approvals.DecisionApprove
	if _, err := x.store.MarkReviewed(ctx, d.ID, rv); err == nil {
		t.Error("MarkReviewed accepted an approve decision")
	}
	rv.Decision = approvals.DecisionPostReview
	if _, err := x.store.MarkReviewed(ctx, d.ID, rv); !errors.Is(err, approvals.ErrIllegalTransition) {
		t.Errorf("MarkReviewed of a pending draft = %v, want ErrIllegalTransition", err)
	}
}

// mintSites maps each Clearance kind to the one function in gate.go that may
// mint it. Any other reference to a kind constant, a Clearance literal with
// fields, an assignment or increment of a .kind, a conversion to or alias of
// Clearance, or a new caller of clearEmergency is a new route to a Clearance and
// fails TestClearanceMintedOnlyInGate.
var mintSites = map[string]string{
	"clearDisabled":  "Clear",
	"clearNarrowing": "Clear",
	"clearApplied":   "ClearApplied",
	"clearEmergency": "clearEmergency",
}

// mintViolations parses src files (name -> source) and reports every way a
// Clearance could be minted outside gate.go's allow list.
func mintViolations(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	fset := token.NewFileSet()
	var out []string
	bad := func(name, fn, what string) {
		out = append(out, fmt.Sprintf("%s: %s: %s", name, fn, what))
	}
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			// reflect is allowed only in settings_rules.go, and there only for
			// reflect.DeepEqual (checked below); unsafe is never allowed.
			if p := strings.Trim(imp.Path.Value, `"`); p == "unsafe" || (p == "reflect" && name != "settings_rules.go") {
				bad(name, "imports", "imports "+p+", which could forge a Clearance")
			}
		}
		inGate := name == "gate.go"
		var visit func(fn string) func(ast.Node) bool
		visit = func(fn string) func(ast.Node) bool {
			return func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if id, ok := x.X.(*ast.Ident); ok && id.Name == "reflect" && x.Sel.Name != "DeepEqual" {
						bad(name, fn, "uses reflect."+x.Sel.Name+"; only reflect.DeepEqual is allowed")
					}
					// A selector's field or method name is not a reference to a
					// package-level constant.
					ast.Inspect(x.X, visit(fn))
					return false
				case *ast.Ident:
					if _, isKind := mintSites[x.Name]; isKind && (!inGate || (fn != "Reason" && mintSites[x.Name] != fn)) {
						bad(name, fn, "references kind constant "+x.Name)
					}
				case *ast.CompositeLit:
					hasKind := false
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "kind" {
								hasKind = true
							}
						}
					}
					if hasKind && x.Type == nil {
						bad(name, fn, "an elided-type literal sets kind")
					}
					if isClearanceLit(x) && len(x.Elts) > 0 && (!inGate || !isMintFunc(fn)) {
						bad(name, fn, "mints a Clearance literal")
					}
				case *ast.AssignStmt:
					for _, l := range x.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "kind" {
							bad(name, fn, "assigns a .kind")
						}
					}
				case *ast.IncDecStmt:
					if sel, ok := x.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "kind" {
						bad(name, fn, "increments a .kind")
					}
				case *ast.TypeSpec:
					if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Clearance" {
						bad(name, fn, "declares a type "+x.Name.Name+" of Clearance")
					}
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.Ident:
						if fun.Name == "Clearance" && len(x.Args) > 0 {
							bad(name, fn, "converts a value to Clearance")
						}
						if fun.Name == "clearEmergency" {
							bad(name, fn, "calls clearEmergency")
						}
					case *ast.SelectorExpr:
						if fun.Sel.Name == "clearEmergency" && (!inGate || fn != "EmergencyApply") {
							bad(name, fn, "calls clearEmergency outside EmergencyApply")
						}
					}
				}
				return true
			}
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Type != nil {
					ast.Inspect(d.Type, visit(d.Name.Name))
				}
				if d.Body != nil {
					ast.Inspect(d.Body, visit(d.Name.Name))
				}
			case *ast.GenDecl:
				if d.Tok != token.CONST { // the const block declares the kinds
					ast.Inspect(d, visit(""))
				}
			}
		}
	}
	return out
}

func isMintFunc(fn string) bool {
	for _, f := range mintSites {
		if f == fn {
			return true
		}
	}
	return false
}

func isClearanceLit(x *ast.CompositeLit) bool {
	id, ok := x.Type.(*ast.Ident)
	return ok && id.Name == "Clearance"
}

func litKind(x *ast.CompositeLit) string {
	for _, e := range x.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok {
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "kind" {
				if v, ok := kv.Value.(*ast.Ident); ok {
					return v.Name
				}
			}
		}
	}
	return "?"
}

// TestClearanceMintedOnlyInGate is the source-level pin of the narrowness of
// every mint path, on the AST: kind constants are referenced only by the one
// gate.go function allowed for each (and Reason), Clearance literals appear
// only there, nothing assigns, increments, converts or aliases a Clearance, the
// package imports neither unsafe nor reflect, and clearEmergency is called only
// from EmergencyApply.
func TestClearanceMintedOnlyInGate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	srcs := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs[f] = string(b)
	}
	if v := mintViolations(t, srcs); len(v) != 0 {
		t.Fatalf("Clearance minted outside the allow list:\n%s", strings.Join(v, "\n"))
	}
	// Every kind is still minted exactly where the map says (the guard is not
	// vacuous, and a renamed function cannot silently drop one), and
	// clearEmergency has exactly one caller.
	seen := map[string]bool{}
	callers := 0
	f, err := parser.ParseFile(token.NewFileSet(), "gate.go", srcs["gate.go"], 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if isClearanceLit(x) && len(x.Elts) > 0 {
				seen[litKind(x)] = true
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "clearEmergency" {
				callers++
			}
		}
		return true
	})
	for kind := range mintSites {
		if !seen[kind] {
			t.Errorf("gate.go no longer mints %s; update mintSites", kind)
		}
	}
	if callers != 1 {
		t.Errorf("clearEmergency has %d callers, want 1 (EmergencyApply)", callers)
	}
}

// TestClearanceMintGuardCatchesScratchMints proves the guard fails on each way
// of minting outside the allow list, and passes a legal one.
func TestClearanceMintGuardCatchesScratchMints(t *testing.T) {
	const pkg = "package approvals\n"
	for name, srcs := range map[string]map[string]string{
		"another file":       {"scratch.go": pkg + "func Sneak() Clearance { return Clearance{kind: clearEmergency, docSHA: \"x\"} }\n"},
		"wrong function":     {"gate.go": pkg + "func Hold() Clearance { return Clearance{kind: clearEmergency} }\n"},
		"wrong kind":         {"gate.go": pkg + "func ClearApplied() Clearance { return Clearance{kind: clearEmergency} }\n"},
		"assignment":         {"scratch.go": pkg + "func Sneak(c Clearance) Clearance { c.kind = clearApplied; return c }\n"},
		"package level":      {"scratch.go": pkg + "var Sneaky = Clearance{kind: clearApplied}\n"},
		"increment":          {"scratch.go": pkg + "func Sneak(c Clearance) Clearance { c.kind++; return c }\n"},
		"type alias":         {"scratch.go": pkg + "type Forged = Clearance\n"},
		"defined type":       {"scratch.go": pkg + "type Forged Clearance\n"},
		"elided literal":     {"scratch.go": pkg + "func Sneak() []Clearance { return []Clearance{{kind: 3}} }\n"},
		"conversion":         {"scratch.go": pkg + "func Sneak(x struct{ kind clearanceKind; draftID, docSHA string }) Clearance { return Clearance(x) }\n"},
		"kind reference":     {"scratch.go": pkg + "func Sneak() clearanceKind { return clearEmergency }\n"},
		"new caller":         {"scratch.go": pkg + "func Sneak(g *Gate) { _, _ = g.clearEmergency(nil, Draft{}, Author{}) }\n"},
		"new caller in gate": {"gate.go": pkg + "func Hold(g *Gate) { _, _ = g.clearEmergency(nil, Draft{}, Author{}) }\n"},
		"unsafe":             {"scratch.go": pkg + "import \"unsafe\"\nvar _ unsafe.Pointer\n"},
		"reflect":            {"scratch.go": pkg + "import \"reflect\"\nvar _ = reflect.TypeOf\n"},
		"reflect elsewhere":  {"gate.go": pkg + "import \"reflect\"\nvar _ = reflect.TypeOf\n"},
		"reflect misuse":     {"settings_rules.go": pkg + "import \"reflect\"\nvar _ = reflect.ValueOf\n"},
	} {
		if v := mintViolations(t, srcs); len(v) == 0 {
			t.Errorf("%s: the guard did not flag the scratch mint", name)
		}
	}
	ok := map[string]string{"gate.go": pkg + "func ClearApplied() Clearance { return Clearance{kind: clearApplied} }\nfunc Other() Clearance { return Clearance{} }\nfunc EmergencyApply(g *Gate) { _, _ = g.clearEmergency(nil, Draft{}, Author{}) }\nfunc (c Clearance) Reason() string { switch c.kind { case clearEmergency: return \"e\" }; return \"\" }\n"}
	if v := mintViolations(t, ok); len(v) != 0 {
		t.Errorf("the guard flagged a legal mint: %v", v)
	}
}

// TestEmergencyReviewIndependence: the draft's author cannot review it, and the
// comment is the closing record of the bypass (10 characters or more).
func TestEmergencyReviewIndependence(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("ind.example.com")
	if _, err := x.gate.EmergencyApply(ctx, x.input(d)); err != nil {
		t.Fatal(err)
	}
	author := approvals.Author{Iss: ada.Iss, Sub: ada.Sub, Kind: "oidc"}
	if _, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: author, Role: config.RoleAdmin, Comment: reviewNote}); !errors.Is(err, approvals.ErrSelfReview) {
		t.Errorf("review by the author = %v, want ErrSelfReview", err)
	}
	// Same sub under another issuer is a different person.
	other := approvals.Author{Iss: "https://other-idp", Sub: ada.Sub, Kind: "oidc"}
	for _, c := range []string{"", "too short", strings.Repeat(" ", 20) + "x"} {
		if _, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: other, Role: config.RoleAdmin, Comment: c}); !errors.Is(err, approvals.ErrReviewComment) {
			t.Errorf("comment %q = %v, want ErrReviewComment", c, err)
		}
	}
	if got := x.stored(d); got.State != approvals.StateAppliedUnreviewed {
		t.Fatalf("state = %s, want applied_unreviewed", got.State)
	}
	if _, err := x.svc.Review(ctx, approvals.ReviewInput{ID: d.ID, Reviewer: other, Role: config.RoleAdmin, Comment: "  0123456789  "}); err != nil {
		t.Errorf("a trimmed 10 character comment = %v", err)
	}
}

// breakOutcomeWrite makes every move of a draft into applied_unreviewed fail,
// as a store that went away right after the publish would.
func breakOutcomeWrite(t *testing.T, x *emEnv) {
	t.Helper()
	if _, err := x.db.SQL().Exec(`CREATE TRIGGER no_unreviewed BEFORE UPDATE OF state ON change_drafts
		WHEN NEW.state = 'applied_unreviewed' BEGIN SELECT RAISE(ABORT, 'store gone'); END`); err != nil {
		t.Fatal(err)
	}
}

// TestEmergencyPublishedButNotRecorded: when the version is live but the outcome
// cannot be written, the caller still learns the version (to alert on), and
// Reconcile then settles the draft as applied_unreviewed and reports the bypass.
func TestEmergencyPublishedButNotRecorded(t *testing.T) {
	x := newEmEnv(t, true)
	ctx := context.Background()
	d := x.pendingClassified("lost.example.com")
	breakOutcomeWrite(t, x)
	got, err := x.gate.EmergencyApply(ctx, x.input(d))
	var pub *approvals.EmergencyPublishedError
	if !errors.As(err, &pub) || pub.Version != 1 || got.ID != d.ID || got.AppliedVersion != 1 {
		t.Fatalf("EmergencyApply = %+v, %v; want the draft and an EmergencyPublishedError at v1", got, err)
	}
	if x.stored(d).State != approvals.StateApplying {
		t.Fatalf("state = %s, want applying until reconcile", x.stored(d).State)
	}
	if _, err := x.db.SQL().Exec("DROP TRIGGER no_unreviewed"); err != nil {
		t.Fatal(err)
	}
	var repaired []string
	x.repaired = func(rd approvals.Draft, actor string) {
		repaired = append(repaired, rd.ID+":"+actor+":"+string(rd.State))
	}
	n, err := x.svc.Reconcile(ctx, func(context.Context, string, int) (int64, bool, error) { return 1, true, nil })
	if err != nil || n != 1 {
		t.Fatalf("Reconcile = %d, %v", n, err)
	}
	if want := d.ID + ":" + bgActor.Sub + ":applied_unreviewed"; len(repaired) != 1 || repaired[0] != want {
		t.Errorf("repair callbacks = %v, want [%s]", repaired, want)
	}
	if st := x.stored(d); st.State != approvals.StateAppliedUnreviewed {
		t.Errorf("state = %s", st.State)
	}
}
