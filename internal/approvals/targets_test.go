package approvals_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
)

// A non-policy target (W-P2-APPR-08) over the real SQLite store, with a fake
// Classifier that calls a doc widening when it says so.

type fakeClassifier struct{ err error }

func (f fakeClassifier) Classify(_ context.Context, ref string, doc json.RawMessage) (approvals.Classification, error) {
	if f.err != nil {
		return approvals.Classification{}, f.err
	}
	var reasons []approvals.Reason
	if strings.Contains(string(doc), "widen") {
		reasons = append(reasons, approvals.Reason{Code: approvals.CodeBlockRemoved, Path: "t:" + ref, Detail: "widens"})
	}
	return approvals.TargetClassification(reasons), nil
}

func newTargetEnv(t *testing.T, cl approvals.Classifier) (*emEnv, *approvals.Service) {
	t.Helper()
	x := newEmEnv(t, true)
	now := func() time.Time { return time.UnixMilli(x.nowMS.Load()) }
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store: x.store,
		Appliers: map[approvals.Target]approvals.Applier{
			approvals.TargetPolicy: x.em, approvals.TargetBlockedUsers: x.em,
		},
		Classifiers: map[approvals.Target]approvals.Classifier{approvals.TargetBlockedUsers: cl},
		Redact:      redact, Now: now, DraftTTL: time.Hour, MaxOpenDrafts: 50, AllowEmergencyApply: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	x.svc, x.gate = svc, approvals.NewGate(true, svc)
	return x, svc
}

func targetDraft(doc string) approvals.TargetDraft {
	return approvals.TargetDraft{Target: approvals.TargetBlockedUsers, Ref: "bu_1", Doc: json.RawMessage(doc), Author: ada}
}

func TestCreateTargetDraft(t *testing.T) {
	_, svc := newTargetEnv(t, fakeClassifier{})
	ctx := context.Background()

	d, err := svc.CreateTargetDraft(ctx, targetDraft(`{"id":"bu_1","widen":true}`))
	if err != nil {
		t.Fatal(err)
	}
	c, cerr := approvals.DecodeClassification(d)
	if d.Target != approvals.TargetBlockedUsers || d.TargetRef != "bu_1" || d.RequiredRole != "admin" || d.State != approvals.StateDraft ||
		d.DocSHA256 != approvals.DocSHA256Of(d.DocJSON) || cerr != nil || !c.Widening || c.Reasons[0].Code != approvals.CodeBlockRemoved {
		t.Fatalf("draft = %+v (%+v, %v)", d, c, cerr)
	}
	if _, err := d.PolicyDoc(); !errors.Is(err, approvals.ErrUnsupportedTarget) {
		t.Errorf("PolicyDoc of a block draft = %v, want ErrUnsupportedTarget", err)
	}

	bad := map[string]func(*approvals.TargetDraft){
		"policy target":  func(td *approvals.TargetDraft) { td.Target = approvals.TargetPolicy },
		"unknown target": func(td *approvals.TargetDraft) { td.Target = "nope" },
		"no applier":     func(td *approvals.TargetDraft) { td.Target = approvals.TargetAgents },
		"no author":      func(td *approvals.TargetDraft) { td.Author.Sub = " " },
		"no ref":         func(td *approvals.TargetDraft) { td.Ref = "" },
		"negative base":  func(td *approvals.TargetDraft) { td.Base = -1 },
		"doc not JSON":   func(td *approvals.TargetDraft) { td.Doc = json.RawMessage(`{`) },
		"unknown source": func(td *approvals.TargetDraft) { td.Prov.Source = "elsewhere" },
	}
	for name, mutate := range bad {
		td := targetDraft(`{"id":"bu_1"}`)
		mutate(&td)
		if _, err := svc.CreateTargetDraft(ctx, td); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	// A classifier failure fails the create.
	_, fsvc := newTargetEnv(t, fakeClassifier{err: errors.New("boom")})
	if _, err := fsvc.CreateTargetDraft(ctx, targetDraft(`{"id":"bu_1"}`)); err == nil {
		t.Error("a classifier error did not fail the create")
	}
}

func TestGateTargets(t *testing.T) {
	x, _ := newTargetEnv(t, fakeClassifier{})
	ctx := context.Background()
	ch := approvals.Change{Target: approvals.TargetBlockedUsers, TargetRef: "bu_1", TargetDoc: json.RawMessage(`{"id":"bu_1"}`), Author: ada}

	// A change that does not widen is cleared whatever allowSelfApproveNarrowing says.
	clr, err := x.gate.Clear(ctx, ch)
	if err != nil || !clr.Valid() || clr.Reason() != "narrowing" {
		t.Fatalf("narrowing Clear = %+v, %v", clr, err)
	}
	ch.TargetDoc = json.RawMessage(`{"id":"bu_1","widen":true}`)
	if _, err := x.gate.Clear(ctx, ch); !errors.Is(err, approvals.ErrApprovalRequired) {
		t.Fatalf("widening Clear = %v, want ErrApprovalRequired", err)
	}
	// Disabled: cleared; no Service: fails closed; unclassifiable: refused.
	if clr, err := approvals.NewGate(false, nil).Clear(ctx, ch); err != nil || clr.Reason() != "disabled" {
		t.Errorf("disabled Clear = %+v, %v", clr, err)
	}
	if _, err := approvals.NewGate(true, nil).Clear(ctx, ch); !errors.Is(err, approvals.ErrGateUnavailable) {
		t.Errorf("Clear with no service = %v, want ErrGateUnavailable", err)
	}
	ch.Target = approvals.TargetAgents
	if _, err := x.gate.Clear(ctx, ch); !errors.Is(err, approvals.ErrUnsupportedTarget) {
		t.Errorf("Clear of a target with no classifier = %v, want ErrUnsupportedTarget", err)
	}

	// Hold stores a pending draft of the target.
	ch.Target = approvals.TargetBlockedUsers
	d, err := x.gate.Hold(ctx, ch)
	if err != nil || d.State != approvals.StatePending || d.Target != approvals.TargetBlockedUsers || d.TargetRef != "bu_1" {
		t.Fatalf("Hold = %+v, %v", d, err)
	}
}

// TestApproveTarget: the two-person rule, the evidence rule and the apply of a
// non-policy draft; then an emergency apply of another.
func TestApproveTarget(t *testing.T) {
	x, svc := newTargetEnv(t, fakeClassifier{})
	ctx := context.Background()
	hold := func() approvals.Draft {
		d, err := x.gate.Hold(ctx, approvals.Change{
			Target: approvals.TargetBlockedUsers, TargetRef: "bu_1", TargetDoc: json.RawMessage(`{"id":"bu_1","widen":true}`), Author: ada,
		})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := hold()
	ben := approvals.Author{Iss: "https://idp", Sub: "ben", Kind: "oidc"}
	in := approvals.ApproveInput{ID: d.ID, Revision: d.Revision, DocSHA256: d.DocSHA256, Approver: ben, Role: config.RoleAdmin}

	if _, err := svc.Approve(ctx, in); !errors.Is(err, approvals.ErrReplayRequired) {
		t.Fatalf("approve without evidence = %v, want ErrReplayRequired", err)
	}
	in.AcknowledgeNoReplay = true
	in.Role = config.RoleEditor
	var rr *approvals.RoleRequiredError
	if _, err := svc.Approve(ctx, in); !errors.As(err, &rr) || rr.Need != config.RoleAdmin {
		t.Fatalf("editor approval = %v, want role admin required", err)
	}
	in.Role = config.RoleAdmin
	self := in
	self.Approver = ada
	if _, err := svc.Approve(ctx, self); !errors.Is(err, approvals.ErrSelfApproval) {
		t.Fatalf("self approval = %v", err)
	}
	res, err := svc.Approve(ctx, in)
	if err != nil || !res.Applied || res.Draft.State != approvals.StateApplied {
		t.Fatalf("approve = %+v, %v", res, err)
	}

	// An emergency apply publishes a held target draft past the second person.
	d2 := hold()
	x.events = nil
	got, err := x.gate.EmergencyApply(ctx, approvals.EmergencyInput{
		ID: d2.ID, Actor: bgActor, Reason: reason,
		BeforePublish: func(context.Context, approvals.Draft) error { return nil },
	})
	if err != nil || got.State != approvals.StateAppliedUnreviewed {
		t.Fatalf("EmergencyApply = %+v, %v", got, err)
	}
}

// TestApproveTargetClassifierDown: when the live classification cannot be
// computed at approve time the stored role still governs (the Applier refuses a
// moved entity itself).
func TestApproveTargetClassifierDown(t *testing.T) {
	cl := &flakyClassifier{}
	x, svc := newTargetEnv(t, cl)
	ctx := context.Background()
	d, err := x.gate.Hold(ctx, approvals.Change{
		Target: approvals.TargetBlockedUsers, TargetRef: "bu_1", TargetDoc: json.RawMessage(`{"id":"bu_1","widen":true}`), Author: ada,
	})
	if err != nil {
		t.Fatal(err)
	}
	cl.down = true
	res, err := svc.Approve(ctx, approvals.ApproveInput{
		ID: d.ID, Revision: d.Revision, DocSHA256: d.DocSHA256, AcknowledgeNoReplay: true, Role: config.RoleAdmin,
		Approver: approvals.Author{Iss: "https://idp", Sub: "ben", Kind: "oidc"},
	})
	if err != nil || !res.Applied {
		t.Fatalf("approve = %+v, %v", res, err)
	}
}

type flakyClassifier struct{ down bool }

func (f *flakyClassifier) Classify(ctx context.Context, ref string, doc json.RawMessage) (approvals.Classification, error) {
	if f.down {
		return approvals.Classification{}, errors.New("down")
	}
	return fakeClassifier{}.Classify(ctx, ref, doc)
}
