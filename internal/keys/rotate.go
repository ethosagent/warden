package keys

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Scheduler cadence. Rotations are planned in hours, so a minute between
// passes is fine-grained; a pass that finds several missed transitions applies
// them in one go, which is how a restart catches up after a downtime. The
// data-version poll is what picks up another process's writes (the keys CLI)
// within a few seconds.
const (
	// ScheduleInterval is how often the rotation planner runs.
	ScheduleInterval = time.Minute
	// DataVersionInterval is how often the manager looks for another
	// process's writes.
	DataVersionInterval = 2 * time.Second
)

// Timing is one purpose's rotation schedule, resolved from the keys config by
// assembly. The manager does not default it: the config layer owns the
// defaults, and a manager built without a schedule has no schedule.
type Timing struct {
	// Interval is how long a key signs before the next one takes over. 0 is
	// the manual mode: only Rotate moves the purpose.
	Interval time.Duration
	// Prepublish is how long a next key must have been published before it may
	// activate, so every verifier already holds it.
	Prepublish time.Duration
	// Overlap is how long a retired key stays published after it stops
	// signing, so the tokens it signed keep verifying.
	Overlap time.Duration
}

// valid enforces the structural invariant the rotation relies on: both windows
// are positive, and an interval that is not manual is long enough for a key to
// be prepublished and retired inside one interval. The config layer holds the
// floors (10m, 20m); this is the manager's own guard against a schedule it
// cannot honour.
func (t Timing) valid() error {
	if t.Prepublish <= 0 {
		return fmt.Errorf("prepublish %s must be positive", t.Prepublish)
	}
	if t.Overlap <= 0 {
		return fmt.Errorf("overlap %s must be positive", t.Overlap)
	}
	if t.Interval == 0 {
		return nil // manual
	}
	if min := t.Prepublish + t.Overlap; t.Interval < min {
		return fmt.Errorf("rotationInterval %s must be 0 (manual) or at least prepublish+overlap (%s)", t.Interval, min)
	}
	return nil
}

// Transition actions recorded through the AuditSink, one per state a key can
// reach. Generation is ActionGenerated (manager.go).
const (
	// ActionActivated is a next key promoted to the signing slot.
	ActionActivated = "keys.activated"
	// ActionRetired is an active key that stopped signing but stays published
	// for its overlap.
	ActionRetired = "keys.retired"
	// ActionRevoked is an active key withdrawn by an emergency rotation: out
	// of every key set at once.
	ActionRevoked = "keys.revoked"
	// ActionDestroyed is a retired key past its overlap: only the row remains.
	ActionDestroyed = "keys.destroyed"
)

// Alerts beyond AlertSigningKeyUnavailable.
const (
	// AlertKeyRotationFailed is the rule id of the Finding raised when a
	// rotation could not be applied: the current key keeps signing and the
	// scheduler retries.
	AlertKeyRotationFailed = "key_rotation_failed"
	// AlertKeyOverdue is the rule id of the Finding raised when an active key
	// has been signing for more than twice its interval: rotation is failing,
	// not merely late.
	AlertKeyOverdue = "key_overdue"
)

// Rotation errors. None carries key material.
var (
	// ErrBundleNotPinned is returned by Rotate for the bundle purpose without
	// ConfirmPinned: workers pin bundle keys out of band, so a bundle rotation
	// is a staged operator action (W-P2-SBND-07), never a bare call.
	ErrBundleNotPinned = errors.New("keys: bundle keys are pinned on workers; confirm the pins before rotating")
	// ErrNoNextKey is returned when there is no next key to promote. The
	// scheduler publishes one; until then the current key keeps signing.
	ErrNoNextKey = errors.New("keys: no next key to promote")
	// ErrNotPrepublished is returned when the next key has not been published
	// for its prepublish window, so promoting it would hand verifiers a key
	// they may not hold yet.
	ErrNotPrepublished = errors.New("keys: next key has not been published long enough")
)

// RotateOpts is how a rotation is requested.
type RotateOpts struct {
	// Emergency promotes the next key at once, inside its prepublish window if
	// it must, and revokes the old key instead of retiring it: the old kid is
	// out of the JWKS and the next bundle immediately, and its material is
	// deleted. Tokens the old key signed fail once verifiers refresh.
	Emergency bool
	// ConfirmPinned is the operator's assertion that every worker holds the
	// next key. Only the bundle purpose requires it (W-P2-SBND-07's --activate
	// sets it after checking the heartbeat pins).
	ConfirmPinned bool
	// Actor is who asked for the rotation. The zero value is the system.
	Actor Actor
}

// Rotate promotes purpose's next key to active, moves the old active key to
// retired (revoked in an emergency) with its private material deleted, and
// publishes a fresh next key. The next key is never promoted before
// publish_at + prepublish unless opts.Emergency is set. An emergency with no
// next key to promote revokes the compromised key anyway — no signing is
// better than signing with a leaked key — and generates a fresh one into the
// vacant slot. A scheduled rotation writes the new next key's material before
// any state changes, so a failing backend leaves the current key signing; an
// emergency promotes first, and a publishing failure afterwards leaves the
// rotation standing with an empty next slot, which the error says plainly.
// The retire and the promotion are one compare-and-swap transaction, so the
// scheduler, the console and the CLI cannot fork the lifecycle, and a peer
// reading between the writes never sees the purpose without an active key.
func (m *Manager) Rotate(ctx context.Context, purpose string, opts RotateOpts) error {
	if purpose != PurposeToken && purpose != PurposeBundle {
		return fmt.Errorf("%w: %q is not rotated through the manager", ErrInvalidPurpose, purpose)
	}
	if purpose == PurposeBundle && !opts.ConfirmPinned {
		return ErrBundleNotPinned
	}
	actor := opts.Actor
	if actor == (Actor{}) {
		actor = SystemActor
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.rotateLocked(ctx, purpose, actor, opts.Emergency); err != nil {
		// A request error or a lost race is not a system failure: the current
		// key keeps signing and the caller learns what to fix. Everything else
		// (store and database failures) is a Finding the operator must see.
		if !requestErr(err) {
			m.rotationFailed(ctx, purpose, err)
			return err
		}
		// The rows moved without this call — another writer won the CAS, or the
		// next key is simply not due — so adopt them: the snapshot must not keep
		// treating a key the database has retired as the signing slot until the
		// data-version poll happens to run. A load failure is noted and the
		// last good snapshot stays.
		_ = m.adoptLocked(ctx, purpose)
		return err
	}
	// Switch the signing slot at once, like the scheduler does. The rotation
	// stands even if this load fails — the poll retries and the old key is
	// inside its overlap either way.
	_ = m.adoptLocked(ctx, purpose)
	m.clearAlert(purpose, AlertKeyRotationFailed)
	return nil
}

// requestErr reports whether err is the caller's mistake or somebody else
// winning the write, rather than a rotation that could not be applied.
func requestErr(err error) bool {
	return errors.Is(err, ErrNoNextKey) || errors.Is(err, ErrNotPrepublished) ||
		errors.Is(err, ErrBundleNotPinned) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrInvalidPurpose)
}

// rotateLocked is Rotate's body plus the scheduler's rotation: the caller holds
// mu and has already validated the purpose. emergency revokes the old key
// instead of retiring it and skips the prepublish check.
func (m *Manager) rotateLocked(ctx context.Context, purpose string, actor Actor, emergency bool) error {
	rows, err := m.rows(ctx, purpose)
	if err != nil {
		return err
	}
	now := m.cfg.Now()
	next, hasNext := nextRow(rows)
	if !hasNext {
		if emergency {
			// Fail closed: with no next key to promote, the compromised key is
			// revoked anyway and a fresh key is generated into the vacant slot.
			return m.emergencyVacantLocked(ctx, purpose, rows, actor)
		}
		return fmt.Errorf("%w: %s", ErrNoNextKey, purpose)
	}
	if !emergency && !publishedLongEnough(now, next, m.cfg.Timings[purpose]) {
		return fmt.Errorf("%w: %s key %s was published %s ago, needs %s",
			ErrNotPrepublished, purpose, next.KID, now.Sub(next.PublishAt), m.cfg.Timings[purpose].Prepublish)
	}
	old, hasOld := activeRow(rows)
	retireTo := StateRetired
	if emergency {
		retireTo = StateRevoked
	}
	return m.promoteLocked(ctx, purpose, next, old, hasOld, retireTo, actor, emergency)
}

// promoteLocked moves purpose's next key into the signing slot and publishes a
// fresh next key. old is the key that leaves the slot (hasOld false when it is
// already empty — an interrupted rotation). The retire and the promote are one
// compare-and-swap transaction, so a peer polling between the writes never
// sees the purpose without an active key, and a transaction somebody else beat
// us to (ErrConflict) leaves the work to the winner with nothing half-applied.
//
// A scheduled rotation writes the fresh next key's material before anything
// changes, so a failing store leaves the current key signing and nothing
// half-rotated. An emergency cannot afford that: the compromised key must stop
// signing at the earliest instant, so the promotion transaction runs first and
// the fresh next key is published only after it — a publishing failure there
// leaves an active key and an empty next slot (the scheduler's heal pass
// republishes one), never a leaked key still signing.
func (m *Manager) promoteLocked(ctx context.Context, purpose string, next, old Record, hasOld bool, retireTo State, actor Actor, emergency bool) error {
	now := m.cfg.Now()
	oldKID := ""
	if hasOld {
		oldKID = old.KID
	}
	var rec Record
	generated := false
	if !emergency {
		r, err := m.generateKeyLocked(ctx, purpose, now, actor)
		if err != nil {
			return err
		}
		rec, generated = r, true
	}
	abandon := func(err error) error {
		if generated {
			m.discard(ctx, purpose, rec.KID)
		}
		return err
	}
	// One transaction: old retires (is revoked) and next activates together,
	// or not at all — a lost race wrote nothing, and an error rolled
	// everything back.
	changed, err := m.cfg.Meta.Promote(ctx, purpose, oldKID, retireTo, next.KID, now)
	if err != nil {
		return abandon(err)
	}
	if !changed {
		return abandon(fmt.Errorf("%w: the %s keys moved before the promotion committed", ErrConflict, purpose))
	}
	if hasOld {
		// The pair committed, so the old key no longer signs: its material goes
		// at once. Its public key stays published until the overlap ends
		// (retired) or never again (revoked).
		m.discard(ctx, purpose, old.KID)
		m.noteTransition(ctx, purpose, old.KID, retireTo, actor, emergencyReason(emergency))
	}
	m.noteTransition(ctx, purpose, next.KID, StateActive, actor, emergencyReason(emergency))
	if !generated {
		// The emergency's fresh next key. A failure here undoes nothing: the
		// rows are adopted so the snapshot switches at once, and the error
		// says the rotation stood.
		if err := m.publishNextLocked(ctx, purpose, actor); err != nil {
			_ = m.adoptLocked(ctx, purpose)
			return rotationStoodErr(purpose, oldKID, next.KID, err)
		}
		return nil
	}
	if err := m.cfg.Meta.Insert(ctx, rec); err != nil {
		// The rotation stands; the purpose has no next key until the scheduler
		// heals it. Nothing is left half-written: the material is gone and the
		// row was never inserted.
		return abandon(err)
	}
	m.noteGenerated(ctx, rec, actor)
	return nil
}

// rotationStoodErr reports an emergency rotation whose promotion committed but
// whose fresh next key could not be published: the compromised key is revoked
// and the next key signs, so the error must not read as an emergency that did
// not happen. The empty next slot is the scheduler's heal pass's to fill.
func rotationStoodErr(purpose, oldKID, nextKID string, err error) error {
	if oldKID == "" {
		return fmt.Errorf("keys: the %s emergency rotation activated %s, but publishing its next key failed; the scheduler's heal pass republishes one: %w",
			purpose, nextKID, err)
	}
	return fmt.Errorf("keys: the %s emergency rotation revoked %s and activated %s, but publishing its next key failed; the scheduler's heal pass republishes one: %w",
		purpose, oldKID, nextKID, err)
}

// emergencyVacantLocked is an emergency rotation of a purpose whose next slot
// is empty: nothing can be promoted, but no signing is better than signing
// with a leaked key, so the active key is revoked regardless and a fresh key
// is generated straight into the vacant signing slot (the first key of a
// purpose activates at once — createInitial's precedent). If the replacement
// cannot be written the purpose is left with no active key — the snapshot is
// installed without a signer, so signing stops at once — and the returned
// error names the empty slot; it is not a request error, so Rotate reports it
// as a rotation failure. The caller holds mu.
func (m *Manager) emergencyVacantLocked(ctx context.Context, purpose string, rows []Record, actor Actor) error {
	now := m.cfg.Now()
	old, hasOld := activeRow(rows)
	if hasOld {
		changed, err := m.cfg.Meta.UpdateState(ctx, old.KID, StateActive, StateRevoked, now)
		if err != nil {
			return err
		}
		if !changed {
			return fmt.Errorf("%w: the %s active key moved before it could be revoked", ErrConflict, purpose)
		}
		// The revocation stands whatever happens next: a compromised key never
		// signs again, even when its replacement cannot be written.
		m.discard(ctx, purpose, old.KID)
		m.noteTransition(ctx, purpose, old.KID, StateRevoked, actor, "emergency")
	}
	rec, err := m.generateKeyLocked(ctx, purpose, now, actor)
	if err == nil {
		rec.State = StateActive
		rec.ActivateAt = now
		if err = m.cfg.Meta.Insert(ctx, rec); err != nil {
			m.discard(ctx, purpose, rec.KID)
		}
	}
	if err != nil {
		if fresh, rerr := m.rows(ctx, purpose); rerr == nil {
			m.set.install(purpose, nil, fresh, m.cfg.Timings[purpose].Overlap)
		}
		if hasOld {
			return fmt.Errorf("keys: %s has no active key: the emergency rotation revoked %s and could not write a replacement: %w",
				purpose, old.KID, err)
		}
		return fmt.Errorf("keys: %s has no active key and the emergency rotation could not write one: %w", purpose, err)
	}
	m.noteGenerated(ctx, rec, actor)
	return nil
}

func emergencyReason(emergency bool) string {
	if emergency {
		return "emergency"
	}
	return "scheduled"
}

// due is what the planner decided is due for one purpose at one instant.
type due struct {
	// promote moves the next key into the signing slot and publishes a new
	// next key.
	promote bool
	// heal is set when the purpose has an active key but no next key: the
	// missing key is published so the next rotation has something to promote
	// (an interrupted rotation or a failed generation leaves this).
	heal bool
	// destroys are the retired keys past retire_at + overlap.
	destroys []Record
}

// plan derives what is due at now from the rows the database holds and the
// purpose's timing. It is pure — no clock, no store, no writes — so the
// scheduler's periodic pass, a restart's catch-up pass and Rotate all decide
// the same thing from the same rows, and a downtime's missed rotations collapse
// into one pass that leaves exactly one active and one next key.
//
// A rotation is due when the active key has been signing for the interval and
// the next key has been published for its prepublish window (a valid interval
// is at least prepublish+overlap, so a next key published at the last rotation
// is always eligible by the time its turn comes). A purpose whose interval is 0
// never rotates here: that is the manual mode.
func plan(now time.Time, rows []Record, t Timing) due {
	var d due
	var active, next *Record
	for i := range rows {
		switch rows[i].State {
		case StateActive:
			active = &rows[i]
		case StateNext:
			next = &rows[i]
		case StateRetired:
			// The public key stays published until retire_at + overlap, then
			// the row is destroyed. A row with no retire_at is not the
			// planner's to move.
			if !rows[i].RetireAt.IsZero() && !now.Before(rows[i].RetireAt.Add(t.Overlap)) {
				d.destroys = append(d.destroys, rows[i])
			}
		}
	}
	switch {
	case active != nil && next != nil:
		if t.Interval > 0 && !active.ActivateAt.IsZero() &&
			!now.Before(active.ActivateAt.Add(t.Interval)) &&
			publishedLongEnough(now, *next, t) {
			d.promote = true
		}
	case active == nil && next != nil:
		// No key is signing but one is published: an interrupted rotation (the
		// old key retired, the promotion never landed) or rows written by
		// hand. The next key takes the empty slot as soon as it has been
		// published long enough.
		if publishedLongEnough(now, *next, t) {
			d.promote = true
		}
	case active != nil:
		d.heal = true
	}
	return d
}

// overdue reports whether purpose's active key has been signing for more than
// twice its interval: rotation is failing, not merely late. The scheduler
// checks this on the rows as they stand after applying a pass's transitions, so
// a restart that catches up does not page for the key it just rotated.
func overdue(rows []Record, now time.Time, t Timing) bool {
	if t.Interval <= 0 {
		return false
	}
	active, ok := activeRow(rows)
	return ok && !active.ActivateAt.IsZero() && !now.Before(active.ActivateAt.Add(2*t.Interval))
}

// publishedLongEnough reports whether next may activate at now: never before
// publish_at + prepublish, so verifiers hold the key before it signs.
func publishedLongEnough(now time.Time, next Record, t Timing) bool {
	return !next.PublishAt.IsZero() && !now.Before(next.PublishAt.Add(t.Prepublish))
}

// Schedule runs one scheduler pass: for every loadable purpose it derives the
// due transitions from the stored timestamps, applies them as compare-and-swap
// writes, adopts the rows into the KeySet when the snapshot has fallen behind
// them (its own transitions or another writer's), and deletes material that
// keys in a terminal state still hold. Run calls it
// every ScheduleInterval and once at start — that first pass is how a restart
// catches up on the transitions a downtime made due. It is exported so tooling
// and tests can drive the planner deterministically; it is safe to call
// concurrently with Run.
func (m *Manager) Schedule(ctx context.Context) error {
	var firstErr error
	for _, p := range loadPurposes {
		if err := m.schedulePurpose(ctx, p); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.reapMaterial(ctx); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// schedulePurpose is one purpose's pass. A failure is logged, raised as a
// Finding and returned, never fatal: the current key keeps signing and the next
// pass retries. A write another process beat us to (the keys CLI rotating the
// same state dir) is not a failure: the CAS lost, the winner's rows stand, and
// the reload below picks them up.
func (m *Manager) schedulePurpose(ctx context.Context, purpose string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows, err := m.rows(ctx, purpose)
	if err != nil {
		return err
	}
	t := m.cfg.Timings[purpose]
	d := plan(m.cfg.Now(), rows, t)
	var failErr error
	applied := false
	if d.heal {
		if err := m.publishNextLocked(ctx, purpose, SystemActor); err != nil && !errors.Is(err, ErrConflict) {
			m.rotationFailed(ctx, purpose, err)
			failErr = err
		} else {
			applied = true
		}
	}
	if failErr == nil && d.promote {
		next, _ := nextRow(rows) // plan only promotes when a next row exists
		old, hasOld := activeRow(rows)
		if err := m.promoteLocked(ctx, purpose, next, old, hasOld, StateRetired, SystemActor, false); err != nil && !errors.Is(err, ErrConflict) {
			m.rotationFailed(ctx, purpose, err)
			failErr = err
		} else {
			applied = true
		}
	}
	if failErr == nil {
		for _, r := range d.destroys {
			if err := m.destroyLocked(ctx, r, SystemActor); err != nil {
				m.rotationFailed(ctx, purpose, err)
				failErr = err
				break
			}
			applied = true
		}
	}
	if applied && failErr == nil {
		// The transitions landed; re-read so the overdue check below and the
		// reload see the rows as they now stand.
		if rows, err = m.rows(ctx, purpose); err != nil {
			return err
		}
	}
	// The overdue Finding runs on the rows as they stand after this pass,
	// whether or not the pass could apply them: a restart that just caught up
	// does not page for the key it rotated, while a rotation that keeps
	// failing does — that is what overdue means.
	if overdue(rows, m.cfg.Now(), t) {
		m.alertOnce(ctx, purpose, AlertKeyOverdue,
			fmt.Sprintf("active key has been signing for more than 2x %s; rotation is failing, not merely late", t.Interval))
	} else {
		m.clearAlert(purpose, AlertKeyOverdue)
	}
	if failErr == nil {
		// Adopt the rows as they now stand so signing switches key at once: this
		// pass's transitions, or another writer's — a pass that applied nothing
		// still adopts rows the snapshot has not seen. A load failure keeps the
		// last good snapshot (the reload backoff retries) and fails the pass.
		if err := m.adoptLocked(ctx, purpose); err != nil {
			failErr = err
		} else {
			// Nothing failed and the snapshot tracks the rows: the
			// rotation-failure episode, if one was open, is over — this pass
			// applied the transition or another writer did.
			m.clearAlert(purpose, AlertKeyRotationFailed)
		}
	}
	return failErr
}

// destroyLocked destroys a retired key past its overlap. Only the row's state
// changes: the material went at retirement.
func (m *Manager) destroyLocked(ctx context.Context, r Record, actor Actor) error {
	changed, err := m.cfg.Meta.UpdateState(ctx, r.KID, StateRetired, StateDestroyed, m.cfg.Now())
	if err != nil {
		return err
	}
	if !changed {
		return nil // another writer already destroyed it
	}
	m.noteTransition(ctx, r.Purpose, r.KID, StateDestroyed, actor, "overlap")
	return nil
}

// reapMaterial deletes private material that rows in a terminal state still
// hold: a retired, revoked or destroyed key never signs again, so its material
// must not survive a failed delete or a crash between the state change and the
// delete. Material whose kid has no row at all is deliberately left alone — a
// concurrent creator may be between its Put and its insert, and the startup
// sweep owns that case.
func (m *Manager) reapMaterial(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.cfg.Meta.List(ctx)
	if err != nil {
		return fmt.Errorf("keys: list signing keys: %w", err)
	}
	terminal := make(map[[2]string]bool, len(all))
	for _, r := range all {
		switch r.State {
		case StateRetired, StateRevoked, StateDestroyed:
			terminal[[2]string{r.Purpose, r.KID}] = true
		}
	}
	if len(terminal) == 0 {
		return nil
	}
	var reaped int
	for _, purpose := range Purposes() {
		kids, err := m.cfg.Store.List(ctx, purpose)
		if err != nil {
			return fmt.Errorf("keys: list %s key material: %w", purpose, err)
		}
		for _, kid := range kids {
			if !terminal[[2]string{purpose, kid}] {
				continue
			}
			if err := m.cfg.Store.Delete(ctx, purpose, kid); err != nil {
				return storeErr("reap", purpose, kid, err)
			}
			m.log.Warn("keys_material_deleted", "purpose", purpose, "kid", kid, "reason", "terminal_state")
			reaped++
		}
	}
	if reaped > 0 {
		m.log.Warn("keys_material_reaped", "count", reaped)
	}
	return nil
}

// rotationFailed records a rotation that could not be applied: the current key
// keeps signing, the Finding is raised once per episode (the scheduler retries
// every pass) and clears when a pass succeeds.
func (m *Manager) rotationFailed(ctx context.Context, purpose string, err error) {
	m.log.Error("keys_rotation_failed", "purpose", purpose, "error", err)
	m.alertOnce(ctx, purpose, AlertKeyRotationFailed, err.Error())
}

// alertOnce raises a Finding for purpose once per episode; a pass that finds
// the condition gone calls clearAlert. Without a sink the episode is still
// tracked, so a sink attached later does not replay old episodes.
func (m *Manager) alertOnce(ctx context.Context, purpose, rule, detail string) {
	key := rule + ":" + purpose
	if _, open := m.episodes[key]; open {
		return
	}
	m.episodes[key] = detail
	if m.cfg.Alerts != nil {
		m.cfg.Alerts.Raise(ctx, Alert{Rule: rule, Purpose: purpose, Detail: detail})
	}
}

func (m *Manager) clearAlert(purpose, rule string) {
	delete(m.episodes, rule+":"+purpose)
}
