package keys_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

// Staged bundle rotation (W-P2-SBND-07). Workers pin bundle keys out of band,
// so the control plane first signs with both the active and the next key
// (stage), and only later does the next key become the only signer (rotate).

var opsActor = keys.Actor{Subject: "ops@example.com", AuthMethod: "cli"}

func signerKIDs(t *testing.T, m *keys.Manager, purpose string) []string {
	t.Helper()
	sgs, err := m.KeySet().Signers(purpose)
	if err != nil {
		t.Fatalf("Signers(%s): %v", purpose, err)
	}
	out := make([]string, 0, len(sgs))
	for _, sg := range sgs {
		out = append(out, sg.KID())
	}
	return out
}

// TestStageBundleSignsWithBoth: before the stage the control plane signs with
// the active key only; after it, with the active key and then the staged next
// key, both of which verify against the published set. Staging again changes
// nothing.
func TestStageBundleSignsWithBoth(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	active := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	next := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 1 || got[0] != active {
		t.Fatalf("signers before the stage = %v, want only the active %s", got, active)
	}

	e.clk.Advance(30 * time.Minute)
	res, err := m.StageBundle(ctx, opsActor)
	if err != nil {
		t.Fatalf("StageBundle: %v", err)
	}
	if res.ActiveKID != active || res.NextKID != next || res.Already || res.Created {
		t.Fatalf("stage result = %+v, want active %s next %s", res, active, next)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 2 || got[0] != active || got[1] != next {
		t.Fatalf("signers after the stage = %v, want [%s %s]", got, active, next)
	}
	sgs, _ := m.KeySet().Signers(keys.PurposeBundle)
	set := m.KeySet().JWKS(keys.PurposeBundle)
	for _, sg := range sgs {
		sig, err := sg.Sign(ctx, []byte("input"))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyInSet(set, sg.KID(), []byte("input"), sig); err != nil {
			t.Errorf("%s does not verify against the published set: %v", sg.KID(), err)
		}
	}
	// The stage restarts publish_at (the prepublish window counts from the
	// moment both keys signed) and marks the row.
	for _, r := range rowsFor(e.rows(), keys.PurposeBundle) {
		if r.KID != next {
			continue
		}
		if !r.PublishAt.Equal(e.clk.Now().Truncate(time.Second)) || r.ActivateAt.IsZero() {
			t.Errorf("staged row = %+v, want publish_at and activate_at at the stage time", r)
		}
	}
	if got := actionsFor(e.audit.events(), keys.PurposeBundle); got[len(got)-1] != keys.ActionStaged {
		t.Errorf("audit actions = %v, want the last to be %s", got, keys.ActionStaged)
	}

	again, err := m.StageBundle(ctx, opsActor)
	if err != nil || !again.Already || again.NextKID != next {
		t.Fatalf("second stage = %+v, %v, want Already for %s", again, err, next)
	}
	// The token purpose is never dual-signed.
	if got := signerKIDs(t, m, keys.PurposeToken); len(got) != 1 {
		t.Errorf("token signers = %v, want one", got)
	}
}

// TestStageBundleCreatesMissingNext: with no next key the stage generates one.
func TestStageBundleCreatesMissingNext(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	old := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)
	if ok, err := e.meta.UpdateState(ctx, old, keys.StateNext, keys.StateDestroyed, e.clk.Now()); err != nil || !ok {
		t.Fatalf("remove the next key: %v %v", ok, err)
	}
	res, err := m.StageBundle(ctx, opsActor)
	if err != nil {
		t.Fatalf("StageBundle: %v", err)
	}
	if !res.Created || res.NextKID == "" || res.NextKID == old {
		t.Fatalf("stage result = %+v, want a freshly created next key", res)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 2 || got[1] != res.NextKID {
		t.Fatalf("signers = %v, want the active key and the new next %s", got, res.NextKID)
	}
}

// TestStageBundleRefusesUnloadableMaterial: a next key whose material cannot be
// read is not staged, and no row changes: the control plane must never sign
// with a key it cannot, or claim a signature it does not carry.
func TestStageBundleRefusesUnloadableMaterial(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	before := e.rows()
	e.store.failGet.Store(true)
	if _, err := m.StageBundle(ctx, opsActor); err == nil {
		t.Fatal("StageBundle with an unreadable next key succeeded")
	}
	e.store.failGet.Store(false)
	after := e.rows()
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("a refused stage changed a row: %+v -> %+v", before[i], after[i])
		}
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 1 {
		t.Errorf("signers = %v, want the active key only", got)
	}
}

// TestStagedKeyReloads: the stage is in the database, so a restart loads both
// signers; and a restart whose staged material is gone does not come up signing
// with the active key alone (a worker pinned only to the staged key would
// reject every bundle) — the load fails closed.
func TestStagedKeyReloads(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	if _, err := m.StageBundle(ctx, opsActor); err != nil {
		t.Fatal(err)
	}
	active := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	next := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)

	m2 := e.manager()
	m2.Init(ctx)
	if got := signerKIDs(t, m2, keys.PurposeBundle); len(got) != 2 || got[0] != active || got[1] != next {
		t.Fatalf("restarted signers = %v, want [%s %s]", got, active, next)
	}

	if err := e.store.Delete(ctx, keys.PurposeBundle, next); err != nil {
		t.Fatal(err)
	}
	m3 := e.manager()
	m3.Init(ctx)
	if _, err := m3.KeySet().Signers(keys.PurposeBundle); !errors.Is(err, keys.ErrNoActiveKey) {
		t.Fatalf("signers with a lost staged key = %v, want ErrNoActiveKey", err)
	}
	if m3.LastError(keys.PurposeBundle) == "" {
		t.Error("the lost staged key raised no unavailable state")
	}
}

// TestStagePeerAdopted: a stage the keys CLI writes (another process on the
// same database) reaches the running control plane's signer set through the
// data-version poll.
func TestStagePeerAdopted(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m1 := e.manager()
	m1.Init(ctx)
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		m1.Run(runCtx)
	}()
	t.Cleanup(func() { cancel(); <-done })

	peer := e.managerOn(e.anotherMeta())
	res, err := peer.StageBundle(ctx, opsActor)
	if err != nil {
		t.Fatalf("the peer could not stage: %v", err)
	}
	e.pollAdvance(t, func() bool {
		sgs, err := m1.KeySet().Signers(keys.PurposeBundle)
		return err == nil && len(sgs) == 2 && sgs[1].KID() == res.NextKID
	})
}

// TestBundleRotationAfterStage: the rotation needs the stage (an emergency does
// not), waits a prepublish window counted from the stage, and leaves the next
// key as the only signer with the old key published for its overlap.
func TestBundleRotationAfterStage(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	// Long after the keys were created: only the stage can reset the clock.
	e.clk.Advance(10 * time.Hour)
	old := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	next := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)

	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true}); !errors.Is(err, keys.ErrNotStaged) {
		t.Fatalf("unstaged rotation = %v, want ErrNotStaged", err)
	}
	if _, err := m.StageBundle(ctx, opsActor); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(30 * time.Minute)
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true}); !errors.Is(err, keys.ErrNotPrepublished) {
		t.Fatalf("rotation 30m after the stage = %v, want ErrNotPrepublished (counted from the stage, not from creation)", err)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 2 {
		t.Fatalf("a refused rotation changed the signers: %v", got)
	}

	e.clk.Advance(31 * time.Minute)
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true, Actor: opsActor}); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 1 || got[0] != next {
		t.Fatalf("signers after the rotation = %v, want only %s", got, next)
	}
	rows := e.rows()
	if kidInState(t, rows, keys.PurposeBundle, keys.StateRetired) != old {
		t.Errorf("the old key %s is not retired", old)
	}
	fresh := kidInState(t, rows, keys.PurposeBundle, keys.StateNext)
	if r := rowFor(t, rows, fresh); !r.ActivateAt.IsZero() {
		t.Errorf("the fresh next key arrives staged: %+v", r)
	}
	// Retired inside its overlap: still published, so a worker's cache signed
	// by it keeps verifying until the operator drops the pin.
	if !sameKids(kidsInSet(m.KeySet().JWKS(keys.PurposeBundle)), []string{old, next, fresh}) {
		t.Errorf("published set = %v, want old, new and the fresh next", kidsInSet(m.KeySet().JWKS(keys.PurposeBundle)))
	}
}

// TestEmergencyBundleRotationNeedsNoStage: after a compromise the operator
// cannot wait for a stage; the emergency promotes at once and the revoked key
// leaves the published set.
func TestEmergencyBundleRotationNeedsNoStage(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	old := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	next := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true, Emergency: true, Actor: opsActor}); err != nil {
		t.Fatalf("emergency Rotate: %v", err)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 1 || got[0] != next {
		t.Fatalf("signers = %v, want only %s", got, next)
	}
	for _, k := range kidsInSet(m.KeySet().JWKS(keys.PurposeBundle)) {
		if k == old {
			t.Errorf("the revoked key %s is still published", old)
		}
	}
}

// TestSchedulerNeverRotatesBundle: with the token interval elapsed on the fake
// clock the token key rotates and the bundle key does not, staged or not.
func TestSchedulerNeverRotatesBundle(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	tokenActive := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	bundleActive := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	if _, err := m.StageBundle(ctx, opsActor); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		e.clk.Advance(5 * time.Hour) // past keys.token.rotationInterval each time
		mustSchedule(t, m)
	}
	rows := e.rows()
	if got := kidInState(t, rows, keys.PurposeToken, keys.StateActive); got == tokenActive {
		t.Fatal("the token key did not rotate after its interval")
	}
	if got := kidInState(t, rows, keys.PurposeBundle, keys.StateActive); got != bundleActive {
		t.Fatalf("the scheduler rotated the bundle key: %s -> %s", bundleActive, got)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 2 || got[0] != bundleActive {
		t.Errorf("bundle signers = %v, want the staged pair untouched", got)
	}
}

// TestUnstageBundle: unstaging takes the second signature away and leaves a
// plain next key that can be staged again; unstaging nothing is a no-op.
func TestUnstageBundle(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	if res, err := m.UnstageBundle(ctx, opsActor); err != nil || !res.Already {
		t.Fatalf("unstage of nothing = %+v, %v, want Already", res, err)
	}
	st, err := m.StageBundle(ctx, opsActor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.UnstageBundle(ctx, opsActor)
	if err != nil || res.NextKID != st.NextKID || res.Dropped || res.Already {
		t.Fatalf("unstage = %+v, %v", res, err)
	}
	if got := signerKIDs(t, m, keys.PurposeBundle); len(got) != 1 {
		t.Fatalf("signers after the unstage = %v, want the active key alone", got)
	}
	if r := rowFor(t, e.rows(), st.NextKID); r.State != keys.StateNext || !r.ActivateAt.IsZero() {
		t.Errorf("unstaged row = %+v, want a plain next key", r)
	}
	if got := actionsFor(e.audit.events(), keys.PurposeBundle); got[len(got)-1] != keys.ActionUnstaged {
		t.Errorf("audit actions = %v, want the last to be %s", got, keys.ActionUnstaged)
	}
	if again, err := m.StageBundle(ctx, opsActor); err != nil || again.NextKID != st.NextKID || again.Already {
		t.Fatalf("restage after the unstage = %+v, %v", again, err)
	}
}

// TestStagedKeyLostRecoversByUnstage: a control plane that boots with the
// staged key's material gone says so in its own words (not "no active key"),
// raises its own Finding, and recovers once the stage is dropped — without the
// lost material, which unstaging never reads.
func TestStagedKeyLostRecoversByUnstage(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	st, err := m.StageBundle(ctx, opsActor)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Delete(ctx, keys.PurposeBundle, st.NextKID); err != nil {
		t.Fatal(err)
	}

	boot := e.manager()
	boot.Init(ctx)
	if boot.Ready() {
		t.Fatal("a manager whose staged key is lost reports ready")
	}
	if got := boot.NotReadyReason(); got != "staged_key_unavailable" {
		t.Errorf("NotReadyReason = %q, want staged_key_unavailable", got)
	}
	if msg := boot.LastError(keys.PurposeBundle); !strings.Contains(msg, "staged next bundle key is unavailable") || !strings.Contains(msg, "--unstage") {
		t.Errorf("LastError = %q, want the distinct staged-key error naming the fix", msg)
	}
	if n := alertsByRule(e.alerts.alerts(), keys.AlertStagedKeyUnavailable); n != 1 {
		t.Errorf("staged_key_unavailable findings = %d, want 1", n)
	}
	if n := alertsByRule(e.alerts.alerts(), keys.AlertSigningKeyUnavailable); n != 0 {
		t.Errorf("a lost staged key raised signing_key_unavailable %d times", n)
	}

	// The CLI's manager never loads: it unstages without the material.
	res, err := e.manager().UnstageBundle(ctx, opsActor)
	if err != nil || !res.Dropped || res.NextKID != st.NextKID {
		t.Fatalf("unstage = %+v, %v, want the lost key dropped", res, err)
	}
	if err := boot.LoadKeySet(ctx, keys.PurposeBundle); err != nil {
		t.Fatalf("reload after the unstage: %v", err)
	}
	if !boot.Ready() || boot.LastError(keys.PurposeBundle) != "" {
		t.Fatal("the manager did not recover after the unstage")
	}
	if got := signerKIDs(t, boot, keys.PurposeBundle); len(got) != 1 {
		t.Errorf("signers after recovery = %v, want the active key alone", got)
	}
	// A fresh next key is staged from scratch.
	again, err := boot.StageBundle(ctx, opsActor)
	if err != nil || !again.Created || again.NextKID == st.NextKID {
		t.Fatalf("stage after the recovery = %+v, %v, want a freshly created key", again, err)
	}
}

// TestRotateExpectsTheCheckedNextKey: a rotation asked to promote one next key
// refuses when another (or none) is there, emergency or not, and changes
// nothing.
func TestRotateExpectsTheCheckedNextKey(t *testing.T) {
	e := newEnv(t)
	e.timings = manualTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	if _, err := m.StageBundle(ctx, opsActor); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(2 * time.Hour)
	active := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)
	next := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateNext)
	for _, emergency := range []bool{false, true} {
		err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true, Emergency: emergency, ExpectNextKID: "some-other-kid"})
		if !errors.Is(err, keys.ErrNextKeyChanged) {
			t.Fatalf("emergency=%v rotation of an unexpected next key = %v, want ErrNextKeyChanged", emergency, err)
		}
	}
	if kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive) != active {
		t.Fatal("a refused rotation moved the active key")
	}
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true, ExpectNextKID: next}); err != nil {
		t.Fatalf("rotation of the expected next key: %v", err)
	}
}
