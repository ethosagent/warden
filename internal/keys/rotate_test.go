package keys_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/filestore"
)

// Rotation (W-P2-KEYS-03), on the fake clock: the timings below make one
// interval 4h with a 1h prepublish and a 2h overlap, so a whole lifecycle fits
// in a handful of advances. The bundle purpose stays manual (interval 0), as it
// ships. Schedule is called directly here — the exported pass the Run loop and
// a restart's catch-up both run — so the planner is driven synchronously; the
// tests that exercise the loops themselves say so.

// fastTimings is a schedule a test can walk in hours: rotate every 4h,
// prepublish 1h, retire after 2h more. The bundle purpose is manual.
func fastTimings() map[string]keys.Timing {
	return map[string]keys.Timing{
		keys.PurposeToken:  {Interval: 4 * time.Hour, Prepublish: time.Hour, Overlap: 2 * time.Hour},
		keys.PurposeBundle: {Prepublish: time.Hour, Overlap: 2 * time.Hour},
	}
}

// manualTimings rotates nothing on a schedule.
func manualTimings() map[string]keys.Timing {
	return map[string]keys.Timing{
		keys.PurposeToken:  {Prepublish: time.Hour, Overlap: 2 * time.Hour},
		keys.PurposeBundle: {Prepublish: time.Hour, Overlap: 2 * time.Hour},
	}
}

func mustSchedule(t *testing.T, m *keys.Manager) {
	t.Helper()
	if err := m.Schedule(context.Background()); err != nil {
		t.Fatalf("Schedule: %v", err)
	}
}

func rowsFor(rows []keys.Record, purpose string) []keys.Record {
	var out []keys.Record
	for _, r := range rows {
		if r.Purpose == purpose {
			out = append(out, r)
		}
	}
	return out
}

// kidInState returns the one row of purpose in st, failing on any other count.
func kidInState(t *testing.T, rows []keys.Record, purpose string, st keys.State) string {
	t.Helper()
	kids := kidsByState(rows, purpose, st)
	if len(kids) != 1 {
		t.Fatalf("%s has %d %s rows (%+v), want exactly 1", purpose, len(kids), st, rows)
	}
	return kids[0]
}

func activeKID(t *testing.T, m *keys.Manager, purpose string) string {
	t.Helper()
	sg, err := m.KeySet().Active(purpose)
	if err != nil {
		t.Fatalf("Active(%s): %v", purpose, err)
	}
	return sg.KID()
}

// signWithActive signs payload with purpose's active key and returns the kid
// the signature verifies under.
func signWithActive(t *testing.T, m *keys.Manager, purpose string, payload []byte) (string, []byte) {
	t.Helper()
	sg, err := m.KeySet().Active(purpose)
	if err != nil {
		t.Fatalf("Active(%s): %v", purpose, err)
	}
	sig, err := sg.Sign(context.Background(), payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return sg.KID(), sig
}

// verifyInSet verifies sig as a signature of payload with the set's key kid —
// what a verifier that fetched the set does. A kid that is not in the set
// fails: that is the gap these tests guard against.
func verifyInSet(set keys.JWKS, kid string, payload, sig []byte) error {
	for _, k := range set.Keys {
		if k.Kid == kid {
			return keys.Verify(k, k.Alg, payload, sig)
		}
	}
	return fmt.Errorf("kid %s is not in the set", kid)
}

func kidsInSet(set keys.JWKS) []string {
	out := make([]string, 0, len(set.Keys))
	for _, k := range set.Keys {
		out = append(out, k.Kid)
	}
	sort.Strings(out)
	return out
}

// sameKids compares two kid lists as sets.
func sameKids(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	w := append([]string(nil), want...)
	sort.Strings(w)
	return strings.Join(got, ",") == strings.Join(w, ",")
}

// alertsByRule counts the alerts raised for one rule.
func alertsByRule(alerts []keys.Alert, rule string) int {
	n := 0
	for _, a := range alerts {
		if a.Rule == rule {
			n++
		}
	}
	return n
}

// actionsFor returns the audit actions of one purpose, in order.
func actionsFor(evs []keys.AuditEvent, purpose string) []string {
	var out []string
	for _, ev := range evs {
		if ev.Purpose == purpose {
			out = append(out, ev.Action)
		}
	}
	return out
}

// pollAdvance advances the fake clock past whatever timer the running loops
// have armed, until cond holds. The loops' polls fire on the fake clock; the
// real-time bound only covers a slow machine.
func (e *env) pollAdvance(t *testing.T, cond func() bool) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("the running manager never reached the expected state on the fake clock")
		}
		if e.clk.PendingTimers() > 0 {
			e.clk.Advance(keys.DataVersionInterval + time.Second)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestRotationSchedule: over two scheduled rotations the token purpose keeps
// exactly one active and one next key, the old key retires with its private
// material deleted at once, stays in the JWKS for its overlap and is destroyed
// after it, and the manual bundle purpose never moves on its own.
func TestRotationSchedule(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)

	t0 := e.clk.Now()
	a0 := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	n0 := kidInState(t, e.rows(), keys.PurposeToken, keys.StateNext)
	b0 := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)

	// 3h in: below the interval, nothing is due and nothing moved.
	e.clk.Advance(3 * time.Hour)
	mustSchedule(t, m)
	if got := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive); got != a0 {
		t.Fatalf("active kid changed before the interval elapsed: %s -> %s", a0, got)
	}

	// 4h: rotation due. A0 retires (material deleted at once), N0 activates, a
	// fresh next key is published.
	e.clk.Advance(time.Hour)
	mustSchedule(t, m)
	rows := e.rows()
	if got := kidInState(t, rows, keys.PurposeToken, keys.StateActive); got != n0 {
		t.Fatalf("the next key did not take over: active = %s, want %s", got, n0)
	}
	n1 := kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	if n1 == a0 || n1 == n0 {
		t.Fatalf("no fresh next key was published: %s", n1)
	}
	var retired keys.Record
	for _, r := range rowsFor(rows, keys.PurposeToken) {
		if r.KID == a0 {
			retired = r
		}
	}
	if retired.State != keys.StateRetired || !retired.RetireAt.Equal(t0.Add(4*time.Hour)) {
		t.Fatalf("the old key after the rotation: %+v, want retired at t0+4h", retired)
	}
	if _, err := e.store.Get(ctx, keys.PurposeToken, a0); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("a retired key's material survived: %v", err)
	}
	// The JWKS serves the retired key for its overlap, plus the active and the
	// next key.
	if got := kidsInSet(m.KeySet().JWKS(keys.PurposeToken)); !sameKids(got, []string{a0, n0, n1}) {
		t.Errorf("JWKS after the rotation = %v, want the retired, active and next keys", got)
	}
	// The manual bundle purpose did not move.
	if got := kidInState(t, rows, keys.PurposeBundle, keys.StateActive); got != b0 {
		t.Errorf("the bundle rotated without an operator: %s -> %s", b0, got)
	}

	// 6h: the overlap ends; the row is destroyed and leaves the JWKS.
	e.clk.Advance(2 * time.Hour)
	mustSchedule(t, m)
	rows = e.rows()
	destroyed := false
	for _, r := range rowsFor(rows, keys.PurposeToken) {
		if r.KID == a0 {
			if r.State != keys.StateDestroyed {
				t.Errorf("the old key = %s, want destroyed", r.State)
			}
			destroyed = true
		}
	}
	if !destroyed {
		t.Fatalf("the old key's row vanished instead of being destroyed: %+v", rows)
	}
	if got := kidsInSet(m.KeySet().JWKS(keys.PurposeToken)); !sameKids(got, []string{n0, n1}) {
		t.Errorf("JWKS after the overlap = %v, want the active and next keys", got)
	}

	// 8h: the second rotation, same invariants.
	e.clk.Advance(2 * time.Hour)
	mustSchedule(t, m)
	rows = e.rows()
	if got := kidInState(t, rows, keys.PurposeToken, keys.StateActive); got != n1 {
		t.Fatalf("second rotation: active = %s, want %s", got, n1)
	}
	kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyOverdue); got != 0 {
		t.Errorf("key_overdue alerts = %d, want 0 on a working schedule", got)
	}
}

// TestRotationNoVerifyGap: at no instant does a token stop verifying against
// the JWKS the control plane serves. The next key is in the set a whole
// interval before it signs, and a retired key stays in it for its overlap;
// only past the overlap does the old key's signature stop verifying.
func TestRotationNoVerifyGap(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	m := e.manager()
	m.Init(context.Background())

	payload0 := []byte("header.payload0")
	setAtStart := m.KeySet().JWKS(keys.PurposeToken)
	kid0, sig0 := signWithActive(t, m, keys.PurposeToken, payload0)
	if err := verifyInSet(setAtStart, kid0, payload0, sig0); err != nil {
		t.Fatalf("a token does not verify against the set it was signed under: %v", err)
	}

	// 4h: rotation.
	e.clk.Advance(4 * time.Hour)
	mustSchedule(t, m)

	// The token signed before the rotation still verifies against the set
	// served now: its key is retired, not unpublished.
	payload1 := []byte("header.payload1")
	kid1, sig1 := signWithActive(t, m, keys.PurposeToken, payload1)
	if err := verifyInSet(m.KeySet().JWKS(keys.PurposeToken), kid0, payload0, sig0); err != nil {
		t.Fatalf("the pre-rotation token stopped verifying inside the overlap: %v", err)
	}
	// The no-gap property: the key that signs now was already in the set a
	// verifier fetched before the rotation, because it was published as the
	// next key when the previous key took over.
	if err := verifyInSet(setAtStart, kid1, payload1, sig1); err != nil {
		t.Fatalf("the new active key was not prepublished: %v", err)
	}

	// 5h: still inside the overlap; 6h: past it, the old key is gone.
	e.clk.Advance(time.Hour)
	mustSchedule(t, m)
	if err := verifyInSet(m.KeySet().JWKS(keys.PurposeToken), kid0, payload0, sig0); err != nil {
		t.Fatalf("the old key left the JWKS before its overlap ended: %v", err)
	}
	e.clk.Advance(time.Hour)
	mustSchedule(t, m)
	if err := verifyInSet(m.KeySet().JWKS(keys.PurposeToken), kid0, payload0, sig0); err == nil {
		t.Error("a destroyed key is still in the JWKS")
	}
	if err := verifyInSet(m.KeySet().JWKS(keys.PurposeToken), kid1, payload1, sig1); err != nil {
		t.Fatalf("the current key left the JWKS: %v", err)
	}
}

// TestBundleManualRotation: the bundle purpose never rotates on a schedule, a
// bare Rotate is refused until the operator confirms the workers' pins, and a
// confirmed rotation is audited as theirs.
func TestBundleManualRotation(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	b0 := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive)

	// However far the clock runs, the scheduler never moves a manual purpose.
	e.clk.Advance(100 * time.Hour)
	mustSchedule(t, m)
	if got := kidInState(t, e.rows(), keys.PurposeBundle, keys.StateActive); got != b0 {
		t.Fatalf("the scheduler rotated the manual bundle purpose: %s -> %s", b0, got)
	}
	if n := len(rowsFor(e.rows(), keys.PurposeBundle)); n != 2 {
		t.Fatalf("bundle rows = %d, want the initial 2", n)
	}

	// A bare Rotate is a refusal, not a Finding: nothing failed.
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{}); !errors.Is(err, keys.ErrBundleNotPinned) {
		t.Fatalf("Rotate(bundle) without confirmation = %v, want ErrBundleNotPinned", err)
	}
	if n := len(e.alerts.alerts()); n != 0 {
		t.Errorf("the refusal raised %d alerts: %+v", n, e.alerts.alerts())
	}

	// Confirmed: the operator rotates, and the audit trail names them.
	actor := keys.Actor{Subject: "ops@example.com", AuthMethod: "oidc"}
	if err := m.Rotate(ctx, keys.PurposeBundle, keys.RotateOpts{ConfirmPinned: true, Actor: actor}); err != nil {
		t.Fatalf("Rotate(bundle, confirmed): %v", err)
	}
	rows := e.rows()
	b1 := kidInState(t, rows, keys.PurposeBundle, keys.StateActive)
	if b1 == b0 {
		t.Fatal("the bundle rotation did not change the active key")
	}
	kidInState(t, rows, keys.PurposeBundle, keys.StateNext)
	for _, r := range rowsFor(rows, keys.PurposeBundle) {
		if r.KID == b0 && r.State != keys.StateRetired {
			t.Errorf("the old bundle key = %s, want retired", r.State)
		}
	}
	if _, err := e.store.Get(ctx, keys.PurposeBundle, b0); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("the retired bundle key's material survived: %v", err)
	}
	// A manual purpose's next key has no activate_at: nothing schedules it.
	for _, r := range rowsFor(rows, keys.PurposeBundle) {
		if r.State == keys.StateNext && !r.ActivateAt.IsZero() {
			t.Errorf("a manual purpose's next key has activate_at %+v", r)
		}
	}
	// The transitions are the operator's, in order.
	evs := e.audit.events()
	if got, want := actionsFor(evs[len(evs)-3:], keys.PurposeBundle),
		[]string{keys.ActionRetired, keys.ActionActivated, keys.ActionGenerated}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("bundle rotation audit = %v, want %v", got, want)
	}
	for _, ev := range evs[len(evs)-3:] {
		if ev.Actor != actor {
			t.Errorf("audit event %+v is not the operator's", ev)
		}
	}
	// The signing slot switched at once.
	if got := activeKID(t, m, keys.PurposeBundle); got != b1 {
		t.Errorf("KeySet bundle active = %s, want %s", got, b1)
	}
}

// TestRotateGuards: Rotate refuses what it must — a purpose it does not
// rotate, a next key that has not been published long enough, and no next key
// at all — without raising a Finding or touching a row.
func TestRotateGuards(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	before := e.rows()

	if err := m.Rotate(ctx, keys.PurposeCA, keys.RotateOpts{ConfirmPinned: true}); !errors.Is(err, keys.ErrInvalidPurpose) {
		t.Errorf("Rotate(ca) = %v, want ErrInvalidPurpose", err)
	}
	// 30m in: the next key has been published for half its prepublish window.
	e.clk.Advance(30 * time.Minute)
	if err := m.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{}); !errors.Is(err, keys.ErrNotPrepublished) {
		t.Fatalf("Rotate before the prepublish window = %v, want ErrNotPrepublished", err)
	}
	// No next key to promote.
	next := kidInState(t, before, keys.PurposeToken, keys.StateNext)
	if ok, err := e.meta.UpdateState(ctx, next, keys.StateNext, keys.StateDestroyed, e.clk.Now()); err != nil || !ok {
		t.Fatalf("destroy the next row: %v %v", ok, err)
	}
	if err := m.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{}); !errors.Is(err, keys.ErrNoNextKey) {
		t.Fatalf("Rotate with no next key = %v, want ErrNoNextKey", err)
	}
	if n := len(e.alerts.alerts()); n != 0 {
		t.Errorf("the refusals raised %d alerts: %+v", n, e.alerts.alerts())
	}
	// Only the row the test itself destroyed changed.
	after := e.rows()
	if len(after) != len(before) {
		t.Fatalf("rows %d -> %d across refused rotations", len(before), len(after))
	}
	if got, want := kidInState(t, after, keys.PurposeToken, keys.StateActive), kidInState(t, before, keys.PurposeToken, keys.StateActive); got != want {
		t.Errorf("a refused rotation changed the active key: %s -> %s", want, got)
	}
}

// TestRotateCAS: the scheduler, the console and a second process rotating the
// same state directory concurrently cannot fork the lifecycle — exactly one
// promotion lands, the losers fail on the compare-and-swap, and the purpose
// ends with one active key, one next key and material only for the keys that
// still need it.
func TestRotateCAS(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m1 := e.manager()
	m1.Init(ctx)
	m2 := e.managerOn(e.anotherMeta())

	// 5h in: the rotation is due and the next key is prepublished.
	e.clk.Advance(5 * time.Hour)

	const calls = 12
	var wg sync.WaitGroup
	errs := make([]error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch {
			case i%2 == 0:
				errs[i] = m1.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{})
			case i%3 == 0:
				errs[i] = m2.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{})
			default:
				errs[i] = m1.Schedule(ctx)
			}
		}()
	}
	wg.Wait()

	// Every caller either won or lost benignly; nothing else is acceptable.
	for i, err := range errs {
		switch {
		case err == nil:
		case errors.Is(err, keys.ErrConflict), errors.Is(err, keys.ErrNotPrepublished), errors.Is(err, keys.ErrNoNextKey):
		default:
			t.Errorf("call %d failed unexpectedly: %v", i, err)
		}
	}
	rows := e.rows()
	active := kidInState(t, rows, keys.PurposeToken, keys.StateActive)
	next := kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	// The storm's winner may be m2, and m1's own calls may all have finished
	// before the winning write landed: one scheduler pass adopts the final rows,
	// the way the data-version poll does within 2s of any other writer.
	if err := m1.Schedule(ctx); err != nil {
		t.Fatalf("converging pass: %v", err)
	}
	// Exactly one promotion landed, however many callers raced.
	if got := actionsFor(e.audit.events(), keys.PurposeToken); strings.Count(strings.Join(got, ","), keys.ActionActivated) != 1 {
		t.Fatalf("keys.activated audit events for token = %v, want exactly one", got)
	}
	// The losers' generated material is gone; the survivors' is all there is.
	files := map[string]bool{}
	for _, p := range listPEMs(t, filepath.Join(e.dir, keys.PurposeToken)) {
		files[strings.TrimSuffix(filepath.Base(p), ".pem")] = true
	}
	if !files[active] || !files[next] {
		t.Errorf("the active or next key lost its material; on disk: %v", files)
	}
	if len(files) != 2 {
		t.Errorf("token material on disk = %v, want exactly the active and next keys", files)
	}
	// The snapshots agree, signing works, nothing paged.
	if got := activeKID(t, m1, keys.PurposeToken); got != active {
		t.Errorf("the manager signs with %s, want the row's active %s", got, active)
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyRotationFailed); got != 0 {
		t.Errorf("a lost race raised key_rotation_failed: %+v", e.alerts.alerts())
	}
	if n := len(rowsFor(rows, keys.PurposeToken)); n != 3 {
		t.Errorf("token rows = %d, want 3 (retired, active, next)", n)
	}
}

// TestReloadOnDataVersion: a write another process made — here rotations by a
// second manager on its own connection — is picked up by the data-version poll
// within one poll interval, and a reload that fails keeps the last good set
// signing until the store returns and the poll retries.
func TestReloadOnDataVersion(t *testing.T) {
	e := newEnv(t)
	// The running manager is manual: it never rotates the token itself, so any
	// change it sees came from the other process.
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
	firstActive := activeKID(t, m1, keys.PurposeToken)

	// The other process, on its own schedule and its own handles, rotates at
	// 5h; the running manager adopts the write within one poll.
	e.clk.Advance(5 * time.Hour)
	e.timings = fastTimings()
	peerStore, err := filestore.New(e.dir)
	if err != nil {
		t.Fatal(err)
	}
	m2 := e.managerWith(e.anotherMeta(), peerStore)
	if err := m2.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{}); err != nil {
		t.Fatalf("the other process could not rotate: %v", err)
	}
	rotatedTo := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	if rotatedTo == firstActive {
		t.Fatal("the other process did not change the active key")
	}
	e.pollAdvance(t, func() bool { return activeKID(t, m1, keys.PurposeToken) == rotatedTo })

	// 9h: the other process rotates again while this one's key store is down.
	// The failed reload keeps the last good set signing.
	e.store.failGet.Store(true)
	e.clk.Advance(4 * time.Hour)
	if err := m2.Schedule(ctx); err != nil {
		t.Fatalf("the other process could not rotate again: %v", err)
	}
	e.pollAdvance(t, func() bool { return m1.LastError(keys.PurposeToken) != "" })
	if got := activeKID(t, m1, keys.PurposeToken); got != rotatedTo {
		t.Fatalf("a failed reload switched the active key to %s, want the last good %s", got, rotatedTo)
	}
	sg, err := m1.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sg.Sign(ctx, []byte("header.payload")); err != nil {
		t.Errorf("signing failed while a reload was failing: %v", err)
	}
	// The store returns; the poll retries the same version and adopts it.
	e.store.failGet.Store(false)
	second := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	e.pollAdvance(t, func() bool { return activeKID(t, m1, keys.PurposeToken) == second })
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyRotationFailed); got != 0 {
		t.Errorf("a failed reload raised key_rotation_failed: %+v", e.alerts.alerts())
	}
}

// TestCatchUp: a restart after a downtime applies the missed transitions in
// order and lands on exactly one active and one next key — however many
// rotations the downtime spanned — and a restart into an interrupted rotation
// (old key retired, promotion lost) completes it.
func TestCatchUp(t *testing.T) {
	// Part 1: 13h of downtime over a 4h interval (three rotations were due).
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	e.manager().Init(ctx)
	t0 := e.clk.Now()
	a0 := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	n0 := kidInState(t, e.rows(), keys.PurposeToken, keys.StateNext)

	e.clk.Set(t0.Add(13 * time.Hour))
	m := e.manager() // the restarted process
	m.Init(ctx)
	rows := e.rows()
	if got := kidInState(t, rows, keys.PurposeToken, keys.StateActive); got != n0 {
		t.Fatalf("the catch-up pass did not promote the published key: active = %s, want %s", got, n0)
	}
	kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	for _, r := range rowsFor(rows, keys.PurposeToken) {
		if r.KID == a0 && (r.State != keys.StateRetired || !r.RetireAt.Equal(t0.Add(13*time.Hour))) {
			t.Errorf("the old key = %+v, want retired at the restart instant", r)
		}
	}
	// One promote, not three: the missed rotations collapse into the state
	// they imply, and the restarted process does not page about the key it
	// just rotated.
	if got := actionsFor(e.audit.events(), keys.PurposeToken); strings.Count(strings.Join(got, ","), keys.ActionActivated) != 1 {
		t.Fatalf("keys.activated audit events for token = %v, want exactly one", got)
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyOverdue); got != 0 {
		t.Errorf("the catch-up pass raised key_overdue: %+v", e.alerts.alerts())
	}
	if got, want := len(kidsInSet(m.KeySet().JWKS(keys.PurposeToken))), 3; got != want {
		t.Errorf("JWKS after the catch-up has %d keys, want %d (the retired key is inside its overlap)", got, want)
	}
	if got := activeKID(t, m, keys.PurposeToken); got != n0 {
		t.Errorf("the restarted process signs with %s, want %s", got, n0)
	}

	// The timeline continues from the restart: the overlap ends, the next
	// interval rotates again.
	e.clk.Advance(2 * time.Hour) // 15h
	mustSchedule(t, m)
	if r := rowFor(t, e.rows(), a0); r.State != keys.StateDestroyed {
		t.Errorf("the retired key = %s at the end of its overlap, want destroyed", r.State)
	}
	e.clk.Advance(2 * time.Hour) // 17h
	mustSchedule(t, m)
	rows = e.rows()
	kidInState(t, rows, keys.PurposeToken, keys.StateActive)
	kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	if got := actionsFor(e.audit.events(), keys.PurposeToken); strings.Count(strings.Join(got, ","), keys.ActionActivated) != 2 {
		t.Fatalf("keys.activated audit events for token = %v, want two", got)
	}

	// Part 2: an interrupted rotation — the old key retired, the promotion
	// never landed — is completed by the restart's catch-up pass.
	e2 := newEnv(t)
	e2.timings = fastTimings()
	e2.manager().Init(ctx)
	a1 := kidInState(t, e2.rows(), keys.PurposeToken, keys.StateActive)
	n1 := kidInState(t, e2.rows(), keys.PurposeToken, keys.StateNext)
	if ok, err := e2.meta.UpdateState(ctx, a1, keys.StateActive, keys.StateRetired, e2.clk.Now()); err != nil || !ok {
		t.Fatalf("interrupt: %v %v", ok, err)
	}
	e2.clk.Advance(time.Hour) // the next key's prepublish elapses
	m2 := e2.manager()
	m2.Init(ctx)
	rows2 := e2.rows()
	if got := kidInState(t, rows2, keys.PurposeToken, keys.StateActive); got != n1 {
		t.Fatalf("the interrupted rotation was not completed: active = %s, want %s", got, n1)
	}
	kidInState(t, rows2, keys.PurposeToken, keys.StateNext)
	// The interrupted key's material, retired out from under the manager, was
	// reaped, and the restart raised nothing.
	if _, err := e2.store.Get(ctx, keys.PurposeToken, a1); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("the interrupted key's material survived: %v", err)
	}
	if n := len(e2.alerts.alerts()); n != 0 {
		t.Errorf("the restart raised %d alerts: %+v", n, e2.alerts.alerts())
	}
	if !m2.Ready() {
		t.Error("the restarted manager is not ready")
	}
}

// rowFor returns the row of one kid.
func rowFor(t *testing.T, rows []keys.Record, kid string) keys.Record {
	t.Helper()
	for _, r := range rows {
		if r.KID == kid {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", kid, rows)
	return keys.Record{}
}

// TestEmergencyRotation: an emergency rotation promotes a next key inside its
// prepublish window and revokes the old key instead of retiring it — out of
// the JWKS at once, material deleted, its signatures unverifiable from now on.
func TestEmergencyRotation(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	a0 := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)
	payload := []byte("header.payload")
	_, sig := signWithActive(t, m, keys.PurposeToken, payload)

	// 30m in: a normal rotation refuses; an emergency does not wait.
	e.clk.Advance(30 * time.Minute)
	if err := m.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{}); !errors.Is(err, keys.ErrNotPrepublished) {
		t.Fatalf("a normal rotation jumped the prepublish window: %v", err)
	}
	cli := keys.Actor{Subject: "ops@example.com", AuthMethod: "cli"}
	if err := m.Rotate(ctx, keys.PurposeToken, keys.RotateOpts{Emergency: true, Actor: cli}); err != nil {
		t.Fatalf("emergency rotation: %v", err)
	}

	rows := e.rows()
	newActive := kidInState(t, rows, keys.PurposeToken, keys.StateActive)
	if newActive == a0 {
		t.Fatal("the emergency rotation did not change the active key")
	}
	if r := rowFor(t, rows, a0); r.State != keys.StateRevoked {
		t.Errorf("the old key = %s, want revoked", r.State)
	}
	if _, err := e.store.Get(ctx, keys.PurposeToken, a0); !errors.Is(err, keys.ErrKeyNotFound) {
		t.Errorf("the revoked key's material survived: %v", err)
	}
	set := m.KeySet().JWKS(keys.PurposeToken)
	if err := verifyInSet(set, a0, payload, sig); err == nil {
		t.Error("a revoked key is still in the JWKS")
	}
	if got := len(set.Keys); got != 2 {
		t.Errorf("JWKS after the emergency = %d keys, want the active and next only", got)
	}
	// The revocation and the promotion are the operator's, reason emergency.
	if got, want := actionsFor(e.audit.events(), keys.PurposeToken),
		[]string{keys.ActionGenerated, keys.ActionGenerated, keys.ActionRevoked, keys.ActionActivated, keys.ActionGenerated}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("emergency audit = %v, want %v", got, want)
	}
	if logs := e.logs.String(); !strings.Contains(logs, "reason=emergency") {
		t.Errorf("no keys_transition line names the emergency:\n%s", logs)
	}
	// Signing continues under the new key.
	kid1, sig1 := signWithActive(t, m, keys.PurposeToken, payload)
	if err := verifyInSet(set, kid1, payload, sig1); err != nil {
		t.Errorf("the new key does not verify against the set: %v", err)
	}
}

// TestRotationAudit: every transition is one audit event and one counted
// transition, with the actor; the counters and gauges are labelled by purpose
// and state only, and a signing failure is counted per purpose.
func TestRotationAudit(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	m := e.manager()
	m.Init(context.Background())

	// 4h: the scheduled rotation retires, activates and generates, in order.
	e.clk.Advance(4 * time.Hour)
	mustSchedule(t, m)
	if got, want := actionsFor(e.audit.events(), keys.PurposeToken),
		[]string{keys.ActionGenerated, keys.ActionGenerated, keys.ActionRetired, keys.ActionActivated, keys.ActionGenerated}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("token audit = %v, want %v", got, want)
	}
	for _, ev := range e.audit.events() {
		if ev.Actor != keys.SystemActor {
			t.Errorf("a scheduled transition is not the system's: %+v", ev)
		}
	}
	if logs := e.logs.String(); !strings.Contains(logs, "reason=scheduled") {
		t.Errorf("no keys_transition line names the schedule:\n%s", logs)
	}

	// The counters are labelled by purpose and the state reached — never kid.
	// The first key of an empty purpose reaches active by generation, so it
	// counts here too; that is the only activation that is not a rotation.
	snap := m.Metrics()
	wantTransitions := map[keys.TransitionSeries]int64{
		{Purpose: keys.PurposeToken, To: keys.StateNext}:    2,
		{Purpose: keys.PurposeToken, To: keys.StateActive}:  2,
		{Purpose: keys.PurposeToken, To: keys.StateRetired}: 1,
		{Purpose: keys.PurposeBundle, To: keys.StateNext}:   1,
		{Purpose: keys.PurposeBundle, To: keys.StateActive}: 1,
	}
	for series, want := range wantTransitions {
		if got := snap.Transitions[series]; got != want {
			t.Errorf("transitions[%v] = %d, want %d", series, got, want)
		}
	}
	if len(snap.Transitions) != len(wantTransitions) {
		t.Errorf("transitions = %v, want exactly %v", snap.Transitions, wantTransitions)
	}
	// The active-age gauge: the token key just rotated, the bundle key has
	// been signing since t0.
	if got := snap.ActiveAge[keys.PurposeToken]; got != 0 {
		t.Errorf("token active age = %s, want 0 (it activated now)", got)
	}
	if got := snap.ActiveAge[keys.PurposeBundle]; got != 4*time.Hour {
		t.Errorf("bundle active age = %s, want 4h", got)
	}

	// 6h: the destroy is audited and counted.
	e.clk.Advance(2 * time.Hour)
	mustSchedule(t, m)
	snap = m.Metrics()
	if got := snap.Transitions[keys.TransitionSeries{Purpose: keys.PurposeToken, To: keys.StateDestroyed}]; got != 1 {
		t.Errorf("token destroys = %d, want 1", got)
	}
	last := e.audit.events()
	if got := last[len(last)-1]; got.Action != keys.ActionDestroyed || got.Purpose != keys.PurposeToken {
		t.Errorf("destroy audit = %+v", got)
	}

	// A signing failure is counted per purpose.
	failCtx, cancel := context.WithCancel(context.Background())
	cancel()
	sg, err := m.KeySet().Active(keys.PurposeToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sg.Sign(failCtx, []byte("header.payload")); err == nil {
		t.Fatal("Sign on a cancelled context succeeded")
	}
	if got := m.Metrics().SignErrors[keys.PurposeToken]; got != 1 {
		t.Errorf("token sign errors = %d, want 1", got)
	}
	if got := len(m.Metrics().SignErrors); got != 1 {
		t.Errorf("sign errors = %v, want the failed purpose only", m.Metrics().SignErrors)
	}
}

// TestKeySetJWKSAndSubscribe: the version moves and the subscribers fire once
// per transition, not once per load; the JWKS holds the next and active keys
// always and a retired key inside its overlap, and nothing for a purpose that
// was never loaded.
func TestKeySetJWKSAndSubscribe(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	v0 := m.KeySet().Version() // one install per purpose

	var mu sync.Mutex
	var fired []string
	m.KeySet().Subscribe(func(purpose string) {
		mu.Lock()
		defer mu.Unlock()
		fired = append(fired, purpose)
	})

	// A quiet pass and a reload of unchanged rows change nothing.
	mustSchedule(t, m)
	if err := m.LoadKeySet(ctx, keys.PurposeToken); err != nil {
		t.Fatal(err)
	}
	if got := m.KeySet().Version(); got != v0 {
		t.Errorf("version moved without a transition: %d -> %d", v0, got)
	}
	mu.Lock()
	n := len(fired)
	mu.Unlock()
	if n != 0 {
		t.Errorf("subscribers fired %d times without a transition", n)
	}

	// One rotation is one transition: one bump, one notification.
	e.clk.Advance(4 * time.Hour)
	mustSchedule(t, m)
	if got := m.KeySet().Version(); got != v0+1 {
		t.Errorf("version = %d after one transition, want %d", got, v0+1)
	}
	mu.Lock()
	got := append([]string(nil), fired...)
	mu.Unlock()
	if strings.Join(got, ",") != keys.PurposeToken {
		t.Errorf("subscribers fired %v, want exactly [%s]", got, keys.PurposeToken)
	}

	// JWKS membership: next and active always, retired inside its overlap.
	set := m.KeySet().JWKS(keys.PurposeToken)
	if len(set.Keys) != 3 {
		t.Fatalf("JWKS = %d keys, want next, active and the retired one inside its overlap", len(set.Keys))
	}
	states := map[string]bool{}
	for _, r := range m.KeySet().Records(keys.PurposeToken) {
		states[string(r.State)] = true
	}
	if !states[string(keys.StateRetired)] || !states[string(keys.StateActive)] || !states[string(keys.StateNext)] {
		t.Fatalf("the snapshot lacks a lifecycle state: %v", states)
	}
	if got := m.KeySet().JWKS(keys.PurposeCA); got.Keys != nil {
		t.Errorf("JWKS(ca) = %v, want empty: the purpose is never loaded", got.Keys)
	}
}

// TestRotationFailedFinding: a rotation that cannot be applied — the key store
// cannot write the new key — keeps the current key signing, raises
// key_rotation_failed once for the episode, and recovers on a later pass.
func TestRotationFailedFinding(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)
	active := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive)

	// The store stops writing just as the rotation comes due. The pass reports
	// the failure (and raises the Finding); the rows do not move.
	e.clk.Advance(4 * time.Hour)
	e.store.failPut.Store(true)
	if err := m.Schedule(ctx); err == nil {
		t.Fatal("Schedule succeeded although the store cannot write")
	}
	if got := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive); got != active {
		t.Fatalf("a failed rotation changed the active key: %s -> %s", active, got)
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyRotationFailed); got != 1 {
		t.Fatalf("key_rotation_failed alerts = %d, want 1", got)
	}
	// The next passes retry but do not re-raise: one episode.
	e.clk.Advance(time.Hour)
	if err := m.Schedule(ctx); err == nil {
		t.Fatal("Schedule succeeded although the store cannot write")
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyRotationFailed); got != 1 {
		t.Fatalf("the failing episode re-raised: %d alerts", got)
	}
	if _, err := m.KeySet().Active(keys.PurposeToken); err != nil {
		t.Fatalf("signing stopped during a failing rotation: %v", err)
	}
	// The store returns; a later pass rotates and the episode can open again.
	e.store.failPut.Store(false)
	e.clk.Advance(time.Hour)
	mustSchedule(t, m)
	if got := kidInState(t, e.rows(), keys.PurposeToken, keys.StateActive); got == active {
		t.Fatal("the rotation was not applied once the store returned")
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyRotationFailed); got != 1 {
		t.Errorf("recovery changed the episode's alert count: %d", got)
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertSigningKeyUnavailable); got != 0 {
		t.Errorf("a failing rotation raised signing_key_unavailable: %+v", e.alerts.alerts())
	}
}

// TestOverdueFinding: an active key past twice its interval with the rotation
// failing raises key_overdue, and the pass that finally rotates clears the
// condition.
func TestOverdueFinding(t *testing.T) {
	e := newEnv(t)
	e.timings = fastTimings()
	ctx := context.Background()
	m := e.manager()
	m.Init(ctx)

	// 9h in with the store unwritable since 4h: the rotation that was due at
	// 4h has been failing for more than another interval (2x4h).
	e.clk.Advance(4 * time.Hour)
	e.store.failPut.Store(true)
	if err := m.Schedule(ctx); err == nil {
		t.Fatal("Schedule succeeded although the store cannot write")
	}
	e.clk.Advance(5 * time.Hour)
	if err := m.Schedule(ctx); err == nil {
		t.Fatal("Schedule succeeded although the store cannot write")
	}
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyOverdue); got != 1 {
		t.Fatalf("key_overdue alerts = %d, want 1", got)
	}
	// The store returns; the pass that rotates also ends the overdue episode,
	// so later passes raise nothing new.
	e.store.failPut.Store(false)
	mustSchedule(t, m)
	rows := e.rows()
	kidInState(t, rows, keys.PurposeToken, keys.StateActive)
	kidInState(t, rows, keys.PurposeToken, keys.StateNext)
	e.clk.Advance(time.Hour)
	mustSchedule(t, m)
	if got := alertsByRule(e.alerts.alerts(), keys.AlertKeyOverdue); got != 1 {
		t.Errorf("key_overdue alerts after recovery = %d, want the original one only", got)
	}
}
