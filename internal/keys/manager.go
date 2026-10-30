package keys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Reload backoff bounds: a purpose whose active key cannot be loaded is
// retried after 1s, doubling to a 60s ceiling.
const (
	minReloadBackoff = time.Second
	maxReloadBackoff = time.Minute
)

// Actions recorded through the AuditSink.
const (
	// ActionGenerated is a key the manager created.
	ActionGenerated = "keys.generated"
	// ActionImported is key material created elsewhere and stored through
	// ImportKey.
	ActionImported = "keys.imported"
)

// AlertSigningKeyUnavailable is the rule id of the Finding raised when a
// purpose has rows but its active key cannot be loaded.
const AlertSigningKeyUnavailable = "signing_key_unavailable"

// Actor is who caused a key change, for created_by and the admin audit trail.
type Actor struct {
	// Subject is the principal: a user, "system" or "cli".
	Subject string
	// AuthMethod is how it authenticated: system, oidc, breakglass or cli.
	AuthMethod string
}

// SystemActor is the manager acting on its own (startup generation, the
// scheduler).
var SystemActor = Actor{Subject: "system", AuthMethod: "system"}

// AuditEvent is one key lifecycle entry for the admin audit trail. It names
// the key by purpose and kid; it never carries key material.
type AuditEvent struct {
	Action  string
	Purpose string
	KID     string
	Actor   Actor
}

// AuditSink receives AuditEvents. It is optional: the control plane adapts the
// admin audit Recorder to it, and a control plane without admin audit passes
// none. A failure is logged, never fatal — the key already exists.
type AuditSink interface {
	RecordKeyEvent(ctx context.Context, ev AuditEvent) error
}

// Alert is a condition the operator must see.
type Alert struct {
	// Rule is the rule id, for example AlertSigningKeyUnavailable.
	Rule    string
	Purpose string
	// Detail is human text; it never carries key material.
	Detail string
}

// AlertSink publishes Alerts (the control plane maps them to Findings). It is
// optional.
type AlertSink interface {
	Raise(ctx context.Context, a Alert)
}

// ManagerConfig wires a Manager. Store, Meta, Codec, Algs and Timings are
// required.
type ManagerConfig struct {
	Store PrivateKeyStore
	Meta  MetaStore
	Codec KeyCodec
	// Backend names Store's backend ("file"); it is recorded in each row's
	// store_backend.
	Backend string
	// Algs maps each loadable purpose (token, bundle) to its algorithm.
	Algs map[string]string
	// Timings maps each loadable purpose to its rotation schedule: interval 0
	// is the manual mode (bundle by default). The config layer resolves the
	// defaults; a manager built without a schedule has none.
	Timings map[string]Timing
	// Now is the time source and Wait the sleep the reload backoff and the
	// scheduler use: it returns false if ctx ended first. Both are required
	// (assembly adapts the control plane's clock), so key timing is
	// deterministic in tests.
	Now    func() time.Time
	Wait   func(ctx context.Context, d time.Duration) bool
	Logger *slog.Logger
	// Audit and Alerts are optional.
	Audit  AuditSink
	Alerts AlertSink
}

// Manager owns the signing keys: it creates them, loads them into the KeySet,
// rotates them and hands out the stored CA key. Private keys live only in the
// PrivateKeyStore and, once loaded, in the KeySet's in-memory signers; the
// database holds public metadata only.
type Manager struct {
	cfg ManagerConfig
	log *slog.Logger
	set *KeySet
	// metrics holds the in-memory counters behind Metrics.
	metrics metrics

	// mu serialises every store-and-database sequence in this process: first
	// key creation, the orphan sweep, loads, imports and rotations. Across
	// processes the database's atomic writes (InsertIfEmpty, Insert,
	// UpdateState) are the guard.
	mu sync.Mutex
	// degraded records why each purpose is currently unavailable (nil map
	// entry when it is not), for LastError.
	degraded map[string]string
	// episodes records the alerts already raised for a rule and purpose, so a
	// Finding fires once per episode, not once per retry or per pass.
	episodes map[string]string
	// dataVersion is the metadata store's version as this manager last saw it:
	// a change means another process wrote (the keys CLI).
	dataVersion int64
}

// NewManager validates cfg and returns a Manager that has loaded nothing: call
// Init, then run Run.
func NewManager(cfg ManagerConfig) (*Manager, error) {
	if cfg.Store == nil || cfg.Meta == nil || cfg.Codec == nil {
		return nil, errors.New("keys: manager needs a Store, Meta and Codec")
	}
	if cfg.Now == nil || cfg.Wait == nil {
		return nil, errors.New("keys: manager needs Now and Wait")
	}
	for _, p := range loadPurposes {
		switch cfg.Algs[p] {
		case AlgEdDSA, AlgES256:
		default:
			return nil, fmt.Errorf("%w: purpose %s has algorithm %q", ErrUnsupportedAlg, p, cfg.Algs[p])
		}
		t, ok := cfg.Timings[p]
		if !ok {
			return nil, fmt.Errorf("keys: manager needs a Timing for purpose %s", p)
		}
		if err := t.valid(); err != nil {
			return nil, fmt.Errorf("keys: purpose %s: %w", p, err)
		}
	}
	if cfg.Algs[PurposeBundle] != AlgEdDSA {
		return nil, fmt.Errorf("%w: bundle keys must be %s", ErrUnsupportedAlg, AlgEdDSA)
	}
	m := &Manager{
		cfg: cfg, log: cfg.Logger,
		degraded: map[string]string{}, episodes: map[string]string{},
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	m.set = newKeySet(cfg.Now, m.metrics.signError, m.log)
	return m, nil
}

// KeySet returns the in-memory snapshot signers read. Sign paths use it and
// never touch the database or the store.
func (m *Manager) KeySet() *KeySet { return m.set }

// Init sweeps orphaned key material, runs one scheduler pass — applying the
// transitions a downtime made due, including the catch-up promote of an
// interrupted rotation — and loads the token and bundle purposes, creating the
// first active and next key for a purpose that has no rows. A purpose that
// cannot be loaded stays unavailable (Sign returns ErrNoActiveKey), a Finding
// is raised, and Run retries it. The control plane keeps serving either way.
func (m *Manager) Init(ctx context.Context) {
	if n, err := m.Sweep(ctx); err != nil {
		m.log.Warn("keys_sweep_failed", "error", err)
	} else if n > 0 {
		m.log.Warn("keys_orphans_swept", "count", n)
	}
	// Catch up before loading: a restart that lands mid-lifecycle (an
	// interrupted rotation, a downtime's missed transitions) applies them here,
	// so the loads below see the rows as they now stand instead of failing on
	// them and raising a Finding the same pass then heals.
	if err := m.Schedule(ctx); err != nil && ctx.Err() == nil {
		m.log.Warn("keys_schedule_failed", "error", err)
	}
	for _, p := range loadPurposes {
		_ = m.LoadKeySet(ctx, p) // the outcome is logged, alerted and retried
	}
	if v, err := m.cfg.Meta.DataVersion(ctx); err == nil {
		m.dataVersion = v // a first poll that sees only our own writes reloads nothing
	}
}

// Ready reports whether every loadable purpose has an active key in the
// snapshot.
func (m *Manager) Ready() bool {
	for _, p := range loadPurposes {
		if !m.set.Loaded(p) {
			return false
		}
	}
	return true
}

// Run starts the manager's background loops and returns when ctx is done: the
// reload backoff for purposes that cannot be loaded, and the scheduler — one
// rotation pass every ScheduleInterval (plus the data-version poll that
// reloads another process's writes within DataVersionInterval). Nothing here
// is required for correctness on a quiet system: the keys are loaded, and a
// rotation is due only when the clock reaches it. Returning also ends every
// subscriber's delivery goroutine.
func (m *Manager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); m.runReload(ctx) }()
	go func() { defer wg.Done(); m.runSchedule(ctx) }()
	wg.Wait()
	m.set.stopSubscriptions()
}

// runReload retries, with 1s to 60s backoff, every purpose whose active key is
// not loaded. With everything loaded it only waits.
func (m *Manager) runReload(ctx context.Context) {
	backoff := minReloadBackoff
	for {
		var pending []string
		for _, p := range loadPurposes {
			if !m.set.Loaded(p) {
				pending = append(pending, p)
			}
		}
		if len(pending) == 0 {
			// Nothing to retry. Poll slowly so a purpose unloaded later is
			// picked up.
			backoff = minReloadBackoff
			if !m.wait(ctx, maxReloadBackoff) {
				return
			}
			continue
		}
		if !m.wait(ctx, backoff) {
			return
		}
		failed := false
		for _, p := range pending {
			if m.LoadKeySet(ctx, p) != nil {
				failed = true
			}
		}
		if failed {
			backoff = min(backoff*2, maxReloadBackoff)
		} else {
			backoff = minReloadBackoff
		}
	}
}

// runSchedule is the scheduler loop: a pass at start (the catch-up Init
// already ran one; this one is a cheap no-op on a quiet system), then a pass
// every ScheduleInterval, with a data-version poll every DataVersionInterval
// in between. One wait covers both deadlines, so a clock that jumps a whole
// interval (a restart, a fake clock) lands in a single pass that applies every
// transition that became due.
func (m *Manager) runSchedule(ctx context.Context) {
	m.tick(ctx)
	now := m.cfg.Now()
	nextTick := now.Add(ScheduleInterval)
	nextPoll := now.Add(DataVersionInterval)
	for ctx.Err() == nil {
		now = m.cfg.Now()
		due := nextTick
		if nextPoll.Before(due) {
			due = nextPoll
		}
		if d := due.Sub(now); d > 0 && !m.wait(ctx, d) {
			return
		}
		now = m.cfg.Now()
		if !now.Before(nextPoll) {
			m.pollOthers(ctx)
			nextPoll = now.Add(DataVersionInterval)
		}
		if !now.Before(nextTick) {
			m.tick(ctx)
			nextTick = now.Add(ScheduleInterval)
		}
	}
}

// tick is one scheduler pass; a failure is logged and retried next tick.
func (m *Manager) tick(ctx context.Context) {
	if err := m.Schedule(ctx); err != nil && ctx.Err() == nil {
		m.log.Warn("keys_schedule_failed", "error", err)
	}
}

// pollOthers reloads every loadable purpose when another process wrote to the
// metadata store — the keys CLI rotating or resetting the same state dir. A
// read error keeps the last good set and is retried on the next poll; so does a
// reload that fails: the version is only adopted once every purpose loaded, so
// a transiently failing store cannot strand the new rows until the next tick.
func (m *Manager) pollOthers(ctx context.Context) {
	v, err := m.cfg.Meta.DataVersion(ctx)
	if err != nil {
		if ctx.Err() == nil {
			m.log.Warn("keys_data_version_unreadable", "error", err)
		}
		return
	}
	m.mu.Lock()
	same := v == m.dataVersion
	m.mu.Unlock()
	if same {
		return
	}
	for _, p := range loadPurposes {
		if err := m.LoadKeySet(ctx, p); err != nil {
			return // the last good snapshot stays; the next poll retries
		}
	}
	m.mu.Lock()
	m.dataVersion = v
	m.mu.Unlock()
}

// wait sleeps d and reports false if ctx ended first.
func (m *Manager) wait(ctx context.Context, d time.Duration) bool { return m.cfg.Wait(ctx, d) }

// LoadKeySet loads purpose (token or bundle) into the KeySet. A purpose with
// no rows gets its first active key and a next key. A purpose with rows never
// gets a new key: if its active material is missing or unparsable the load
// fails, Sign keeps returning ErrNoActiveKey, a Finding is raised and the
// caller (Run) retries.
func (m *Manager) LoadKeySet(ctx context.Context, purpose string) error {
	if purpose != PurposeToken && purpose != PurposeBundle {
		return fmt.Errorf("%w: %q is not loaded into a KeySet", ErrInvalidPurpose, purpose)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.loadLocked(ctx, purpose)
	m.noteLoad(ctx, purpose, err)
	return err
}

func (m *Manager) loadLocked(ctx context.Context, purpose string) error {
	rows, err := m.rows(ctx, purpose)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if err := m.createInitial(ctx, purpose, SystemActor); err != nil {
			return err
		}
		// Re-read: another process may have won the insert, and its rows are
		// the ones to load.
		if rows, err = m.rows(ctx, purpose); err != nil {
			return err
		}
	}
	active, ok := activeRow(rows)
	if !ok {
		return fmt.Errorf("%w: %s has %d rows and none is active", ErrNoActiveKey, purpose, len(rows))
	}
	sg, err := m.loadSigner(ctx, active)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNoActiveKey, err)
	}
	if m.set.install(purpose, sg, rows, m.cfg.Timings[purpose].Overlap) {
		m.log.Info("keys_loaded", "purpose", purpose, "alg", active.Alg, "active_kid", active.KID, "rows", len(rows))
	}
	return nil
}

// adoptLocked reloads purpose into the KeySet when the snapshot does not
// already hold the database's rows — after a rotation this process applied, or
// one it lost to another writer. A purpose with no rows is LoadKeySet's to
// create, not the adopter's, and a snapshot that already holds the rows is left
// alone: a key store that is down while the snapshot still signs must not raise
// an unavailable Finding. The caller holds mu. A load failure is noted (the
// last good snapshot stays) and returned.
func (m *Manager) adoptLocked(ctx context.Context, purpose string) error {
	rows, err := m.rows(ctx, purpose)
	if err != nil || len(rows) == 0 || m.set.holds(purpose, rows) {
		return err
	}
	if err := m.loadLocked(ctx, purpose); err != nil {
		m.noteLoad(ctx, purpose, err)
		return err
	}
	m.noteLoad(ctx, purpose, nil)
	return nil
}

// noteLoad records a load's outcome: the unavailable Finding fires once per
// episode and clears when the purpose loads again. The caller holds mu.
func (m *Manager) noteLoad(ctx context.Context, purpose string, err error) {
	if err == nil {
		delete(m.degraded, purpose)
		m.clearAlert(purpose, AlertSigningKeyUnavailable)
		return
	}
	m.log.Error("keys_load_failed", "purpose", purpose, "error", err)
	m.degraded[purpose] = err.Error()
	m.alertOnce(ctx, purpose, AlertSigningKeyUnavailable, err.Error())
}

// LastError returns why purpose is unavailable, or "" when it is loaded or has
// not failed.
func (m *Manager) LastError(purpose string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.degraded[purpose]
}

// rows returns the rows of one purpose.
func (m *Manager) rows(ctx context.Context, purpose string) ([]Record, error) {
	all, err := m.cfg.Meta.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("keys: list signing keys: %w", err)
	}
	var out []Record
	for _, r := range all {
		if r.Purpose == purpose {
			out = append(out, r)
		}
	}
	return out, nil
}

func activeRow(rows []Record) (Record, bool) {
	for _, r := range rows {
		if r.State == StateActive {
			return r, true
		}
	}
	return Record{}, false
}

func nextRow(rows []Record) (Record, bool) {
	for _, r := range rows {
		if r.State == StateNext {
			return r, true
		}
	}
	return Record{}, false
}

// loadSigner reads and parses row's material and proves it is the key the row
// describes: a file swapped for another key must not sign under the old kid.
func (m *Manager) loadSigner(ctx context.Context, row Record) (Signer, error) {
	pem, err := m.cfg.Store.Get(ctx, row.Purpose, row.KID)
	if err != nil {
		return nil, storeErr("read", row.Purpose, row.KID, err)
	}
	defer clear(pem)
	sg, err := m.cfg.Codec.Parse(pem)
	if err != nil {
		return nil, storeErr("parse", row.Purpose, row.KID, err)
	}
	if sg.KID() != row.KID || sg.Alg() != row.Alg {
		return nil, fmt.Errorf("keys: %s key %s: stored material does not match its row (kid %s, alg %s)",
			row.Purpose, row.KID, sg.KID(), sg.Alg())
	}
	return sg, nil
}

// newKey generates a key, stores it, reads it back and checks the public key
// survived the round trip. Any failure after the Put deletes the material.
func (m *Manager) newKey(ctx context.Context, purpose, alg string, priv crypto.Signer) (Signer, error) {
	sg, err := m.cfg.Codec.NewSigner(priv)
	if err != nil {
		return nil, err
	}
	pem, err := m.cfg.Codec.Marshal(priv)
	if err != nil {
		return nil, err
	}
	defer clear(pem)
	kid := sg.KID()
	if err := m.cfg.Store.Put(ctx, purpose, kid, pem); err != nil {
		// An existing file is not ours to delete.
		return nil, storeErr("store", purpose, kid, err)
	}
	back, err := m.loadSigner(ctx, Record{KID: kid, Purpose: purpose, Alg: alg})
	if err != nil {
		m.discard(ctx, purpose, kid)
		return nil, err
	}
	if !samePublic(sg, back) {
		m.discard(ctx, purpose, kid)
		return nil, fmt.Errorf("keys: %s key %s: stored material does not match the generated public key", purpose, kid)
	}
	return sg, nil
}

func samePublic(a, b Signer) bool {
	ja, errA := PublicJWK(a.Public(), a.Alg())
	jb, errB := PublicJWK(b.Public(), b.Alg())
	return errA == nil && errB == nil && ja == jb
}

// discard deletes material best-effort; the orphan sweep catches a failure.
func (m *Manager) discard(ctx context.Context, purpose, kid string) {
	if err := m.cfg.Store.Delete(context.WithoutCancel(ctx), purpose, kid); err != nil {
		m.log.Warn("keys_discard_failed", "purpose", purpose, "kid", kid, "error", err)
	}
}

// createInitial generates a purpose's first active key and its next key, in
// the write order generate, Put, Get back and compare, then INSERT. When the
// INSERT loses to a concurrent creator, or fails, the material is deleted.
func (m *Manager) createInitial(ctx context.Context, purpose string, actor Actor) error {
	now := m.cfg.Now()
	next, err := m.generateKeyLocked(ctx, purpose, now, actor)
	if err != nil {
		return err
	}
	active, err := m.generateKeyLocked(ctx, purpose, now, actor)
	if err != nil {
		m.discard(ctx, purpose, next.KID)
		return err
	}
	// The first active key activates at once: activate_at is where the planner
	// measures the interval from.
	active.State = StateActive
	active.ActivateAt = now
	inserted, err := m.cfg.Meta.InsertIfEmpty(ctx, purpose, []Record{active, next})
	if err != nil || !inserted {
		m.discard(ctx, purpose, active.KID)
		m.discard(ctx, purpose, next.KID)
		if err != nil {
			return fmt.Errorf("keys: record %s keys: %w", purpose, err)
		}
		return nil // lost the race: the winner's rows are loaded next
	}
	m.noteGenerated(ctx, active, actor)
	m.noteGenerated(ctx, next, actor)
	return nil
}

// generateKeyLocked generates purpose's next key and returns its uninserted
// next row. The material is written, read back and compared before any state
// changes, so a store failure leaves nothing behind — no row, and no material
// (the caller discards it on failure; the sweep catches a crash between the Put
// and the INSERT). activate_at is the key's turn: now + interval when the
// purpose rotates on a schedule, 0 in the manual mode (it activates when an
// operator rotates the purpose). The caller holds mu.
func (m *Manager) generateKeyLocked(ctx context.Context, purpose string, now time.Time, actor Actor) (Record, error) {
	alg := m.cfg.Algs[purpose]
	priv, err := m.cfg.Codec.Generate(alg)
	if err != nil {
		return Record{}, fmt.Errorf("keys: generate %s key: %w", purpose, err)
	}
	sg, err := m.newKey(ctx, purpose, alg, priv)
	if err != nil {
		return Record{}, err
	}
	jwk, err := PublicJWK(sg.Public(), alg)
	if err != nil {
		m.discard(ctx, purpose, sg.KID())
		return Record{}, err
	}
	rec := Record{
		KID: sg.KID(), Purpose: purpose, Alg: alg, State: StateNext, PublicJWK: jwk,
		StoreBackend: m.cfg.Backend, CreatedAt: now, PublishAt: now, CreatedBy: actor.Subject,
	}
	if t := m.cfg.Timings[purpose]; t.Interval > 0 {
		rec.ActivateAt = now.Add(t.Interval)
	}
	return rec, nil
}

// publishNextLocked generates and records purpose's next key. The caller holds
// mu and has checked the slot is empty: Insert's unique index would reject a
// second next row anyway, and the failure would be indistinguishable from a
// lost race.
func (m *Manager) publishNextLocked(ctx context.Context, purpose string, actor Actor) error {
	rec, err := m.generateKeyLocked(ctx, purpose, m.cfg.Now(), actor)
	if err != nil {
		return err
	}
	if err := m.cfg.Meta.Insert(ctx, rec); err != nil {
		m.discard(ctx, purpose, rec.KID)
		return fmt.Errorf("keys: record %s key %s: %w", purpose, rec.KID, err)
	}
	m.noteGenerated(ctx, rec, actor)
	return nil
}

// noteTransition logs, audits and counts one lifecycle transition. The caller
// holds mu and the row is already written.
func (m *Manager) noteTransition(ctx context.Context, purpose, kid string, to State, actor Actor, reason string) {
	m.log.Info("keys_transition", "purpose", purpose, "kid", kid, "state", string(to), "reason", reason)
	m.audit(ctx, AuditEvent{Action: actionFor(to), Purpose: purpose, KID: kid, Actor: actor})
	m.metrics.countTransition(purpose, to)
}

// noteGenerated is noteTransition for a key the manager just generated: the
// audit action is keys.generated even when the key starts active (the first key
// of an empty purpose), because nothing was promoted.
func (m *Manager) noteGenerated(ctx context.Context, rec Record, actor Actor) {
	m.log.Info("keys_transition", "purpose", rec.Purpose, "kid", rec.KID, "state", string(rec.State), "reason", "generated")
	m.audit(ctx, AuditEvent{Action: ActionGenerated, Purpose: rec.Purpose, KID: rec.KID, Actor: actor})
	m.metrics.countTransition(rec.Purpose, rec.State)
}

// actionFor maps the state a key reached to its audit action.
func actionFor(to State) string {
	switch to {
	case StateActive:
		return ActionActivated
	case StateRetired:
		return ActionRetired
	case StateRevoked:
		return ActionRevoked
	case StateDestroyed:
		return ActionDestroyed
	default:
		return ActionGenerated
	}
}

func (m *Manager) audit(ctx context.Context, ev AuditEvent) {
	if m.cfg.Audit == nil {
		return
	}
	if err := m.cfg.Audit.RecordKeyEvent(ctx, ev); err != nil {
		m.log.Warn("keys_audit_failed", "action", ev.Action, "purpose", ev.Purpose, "kid", ev.KID, "error", err)
	}
}

// Sweep deletes key material that has no signing_keys row — what a crash
// between Put and INSERT, or a failed best-effort delete, leaves behind. It
// logs kid and purpose only and returns how many files it removed. Run it
// before loading, never concurrently with a writer in another process.
func (m *Manager) Sweep(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	all, err := m.cfg.Meta.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("keys: list signing keys: %w", err)
	}
	known := make(map[[2]string]bool, len(all))
	for _, r := range all {
		known[[2]string{r.Purpose, r.KID}] = true
	}
	swept := 0
	for _, purpose := range Purposes() {
		kids, err := m.cfg.Store.List(ctx, purpose)
		if err != nil {
			return swept, fmt.Errorf("keys: list %s key material: %w", purpose, err)
		}
		for _, kid := range kids {
			if known[[2]string{purpose, kid}] {
				continue
			}
			if err := m.cfg.Store.Delete(ctx, purpose, kid); err != nil {
				return swept, storeErr("sweep", purpose, kid, err)
			}
			m.log.Warn("keys_orphan_swept", "purpose", purpose, "kid", kid)
			swept++
		}
	}
	return swept, nil
}

// ImportKey stores externally created private key material under purpose with
// an active signing_keys row — the worker CA's intermediate key, created by
// `ca init|csr` (W-P2-WCA-01). Only the ca purpose is importable: token and
// bundle keys are generated here. A purpose that already has an active key is
// ErrConflict and leaves the store as it was. It returns the key's kid.
func (m *Manager) ImportKey(ctx context.Context, purpose string, priv crypto.Signer, actor Actor) (string, error) {
	if purpose != PurposeCA {
		return "", fmt.Errorf("%w: only %q keys are imported", ErrInvalidPurpose, PurposeCA)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sg, err := m.cfg.Codec.NewSigner(priv)
	if err != nil {
		return "", err
	}
	if _, err := m.newKey(ctx, purpose, sg.Alg(), priv); err != nil {
		return "", err
	}
	jwk, err := PublicJWK(sg.Public(), sg.Alg())
	if err != nil {
		m.discard(ctx, purpose, sg.KID())
		return "", err
	}
	now := m.cfg.Now()
	rec := Record{
		KID: sg.KID(), Purpose: purpose, Alg: sg.Alg(), State: StateActive, PublicJWK: jwk,
		StoreBackend: m.cfg.Backend, CreatedAt: now, PublishAt: now, ActivateAt: now, CreatedBy: actor.Subject,
	}
	if err := m.cfg.Meta.Insert(ctx, rec); err != nil {
		m.discard(ctx, purpose, rec.KID)
		return "", fmt.Errorf("keys: record %s key %s: %w", purpose, rec.KID, err)
	}
	m.log.Info("keys_transition", "purpose", purpose, "kid", rec.KID, "state", string(rec.State), "reason", "imported")
	m.audit(ctx, AuditEvent{Action: ActionImported, Purpose: purpose, KID: rec.KID, Actor: actor})
	return rec.KID, nil
}

// Signer loads the active key of purpose from the store and returns its
// Signer — the way the ca purpose, which has no KeySet, is used. It does not
// cache: the caller decides how long to hold the signer. No active row is
// ErrNoActiveKey.
func (m *Manager) Signer(ctx context.Context, purpose string) (Signer, error) {
	if !ValidPurpose(purpose) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidPurpose, purpose)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rows, err := m.rows(ctx, purpose)
	if err != nil {
		return nil, err
	}
	active, ok := activeRow(rows)
	if !ok {
		return nil, fmt.Errorf("%w: %s has no active key", ErrNoActiveKey, purpose)
	}
	sg, err := m.loadSigner(ctx, active)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoActiveKey, err)
	}
	return sg, nil
}

// TransitionSeries is one cell of the transitions counter: a purpose and the
// state its key reached.
type TransitionSeries struct {
	Purpose string
	To      State
}

// MetricsSnapshot is the manager's counters and gauges at one instant, kept in
// memory for the later /metrics export (W-P5-RETN-06):
// warden_cp_key_transitions_total{purpose,to} (Transitions),
// warden_cp_key_sign_errors_total{purpose} (SignErrors) and
// warden_cp_key_active_age_seconds{purpose} (ActiveAge). Labels carry purpose
// and the state reached only, never kid.
type MetricsSnapshot struct {
	Transitions map[TransitionSeries]int64
	SignErrors  map[string]int64
	ActiveAge   map[string]time.Duration
}

// metrics holds the manager's in-memory counters. They are internal: Metrics
// returns a copy, so no consumer can race a counter.
type metrics struct {
	mu          sync.Mutex
	transitions map[TransitionSeries]int64
	signErrors  map[string]int64
}

// countTransition counts one lifecycle transition, including generation (the
// state a generated key starts in).
func (mt *metrics) countTransition(purpose string, to State) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	if mt.transitions == nil {
		mt.transitions = map[TransitionSeries]int64{}
	}
	mt.transitions[TransitionSeries{Purpose: purpose, To: to}]++
}

// signError counts one signing failure of a loaded active key.
func (mt *metrics) signError(purpose string) {
	mt.mu.Lock()
	defer mt.mu.Unlock()
	if mt.signErrors == nil {
		mt.signErrors = map[string]int64{}
	}
	mt.signErrors[purpose]++
}

// Metrics returns a snapshot of the in-memory counters and gauges.
func (m *Manager) Metrics() MetricsSnapshot {
	snap := MetricsSnapshot{
		Transitions: map[TransitionSeries]int64{},
		SignErrors:  map[string]int64{},
		ActiveAge:   map[string]time.Duration{},
	}
	m.metrics.mu.Lock()
	for k, v := range m.metrics.transitions {
		snap.Transitions[k] = v
	}
	for k, v := range m.metrics.signErrors {
		snap.SignErrors[k] = v
	}
	m.metrics.mu.Unlock()
	now := m.cfg.Now()
	for _, p := range loadPurposes {
		for _, r := range m.set.Records(p) {
			if r.State == StateActive && !r.ActivateAt.IsZero() && !now.Before(r.ActivateAt) {
				snap.ActiveAge[p] = now.Sub(r.ActivateAt)
			}
		}
	}
	return snap
}

// KeySet is the in-memory snapshot of the loaded signing keys. Readers take an
// atomic pointer to an immutable snapshot, so signing never touches the
// database or the key store and a backend outage after loading blocks nothing
// but rotation.
type KeySet struct {
	mu   sync.Mutex // serialises writers; readers use cur
	cur  atomic.Pointer[map[string]*loaded]
	zero map[string]*loaded
	// now times the overlap window in JWKS, so a snapshot answers with the
	// injected clock, not time.Now.
	now func() time.Time
	// onSignErr counts a signing failure per purpose (Metrics).
	onSignErr func(purpose string)
	// ver counts the installs that changed a purpose's snapshot.
	ver atomic.Uint64
	// subMu guards subs.
	subMu sync.Mutex
	// subs are the subscriptions, signalled after a purpose's snapshot changed.
	subs []*subscription
	// log reports subscriber panics.
	log *slog.Logger
}

// loaded is one purpose's immutable snapshot.
type loaded struct {
	active Signer
	rows   []Record
	// overlap is the purpose's configured overlap: how long a retired key stays
	// in the JWKS.
	overlap time.Duration
}

func newKeySet(now func() time.Time, onSignErr func(string), log *slog.Logger) *KeySet {
	if log == nil {
		log = slog.Default()
	}
	ks := &KeySet{zero: map[string]*loaded{}, now: now, onSignErr: onSignErr, log: log}
	ks.cur.Store(&ks.zero)
	return ks
}

// install replaces purpose's snapshot copy-on-write. A load that finds the same
// rows and the same active key changes nothing — no version bump, no
// subscribers, no keys_loaded line — so the version moves once per transition,
// not once per poll. It reports whether the snapshot changed.
func (ks *KeySet) install(purpose string, active Signer, rows []Record, overlap time.Duration) bool {
	ks.mu.Lock()
	old := *ks.cur.Load()
	if l := old[purpose]; l != nil && l.overlap == overlap && sameRecords(l.rows, rows) &&
		kidOf(l.active) == kidOf(active) {
		ks.mu.Unlock()
		return false
	}
	next := make(map[string]*loaded, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	if active != nil && ks.onSignErr != nil {
		active = countingSigner{Signer: active, purpose: purpose, onErr: ks.onSignErr}
	}
	next[purpose] = &loaded{active: active, rows: append([]Record(nil), rows...), overlap: overlap}
	ks.cur.Store(&next)
	ks.ver.Add(1)
	ks.mu.Unlock()
	ks.notify(purpose)
	return true
}

// holds reports whether purpose's snapshot already holds exactly rows — the
// active row's kid as its signer and every row equal — so a reload would change
// nothing. Callers use it to skip a reload that would touch the key store for no
// change: a store that is down while the snapshot still signs is a rotation
// failure, not an unavailable one.
func (ks *KeySet) holds(purpose string, rows []Record) bool {
	l := (*ks.cur.Load())[purpose]
	if l == nil || !sameRecords(l.rows, rows) {
		return false
	}
	a, _ := activeRow(rows)
	return a.KID != "" && kidOf(l.active) == a.KID
}

func kidOf(sg Signer) string {
	if sg == nil {
		return ""
	}
	return sg.KID()
}

func sameRecords(a, b []Record) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// notify signals every subscription for purpose, after its snapshot changed.
// It never runs subscriber code: install's callers hold Manager.mu (a load, a
// rotation, the scheduler), and a subscriber that blocks or panics there would
// stall the whole manager. Signalling is non-blocking, so a wedged mailbox
// delays only its own subscriber.
func (ks *KeySet) notify(purpose string) {
	ks.subMu.Lock()
	defer ks.subMu.Unlock()
	for _, s := range ks.subs {
		s.signal(purpose)
	}
}

// subscription is one Subscribe callback with its own delivery goroutine and
// mailbox, so subscribers are isolated from each other and from the manager:
// neither a blocking nor a panicking subscriber can reach the scheduler.
type subscription struct {
	fn func(purpose string)
	// log reports a contained panic.
	log *slog.Logger
	// wake is the coalescing signal: capacity 1, because a delivery already
	// pending will pick this change up too. Closing it ends the delivery
	// goroutine.
	wake chan struct{}
	// mu guards pend.
	mu sync.Mutex
	// pend is the purposes that changed but were not delivered yet. A set, not
	// a queue: while fn is busy, further transitions of the same purpose
	// coalesce into the one delivery that is still to come, but a different
	// purpose's signal is never dropped.
	pend map[string]bool
	// once makes shutdown idempotent: the holder's unsubscribe and the KeySet's
	// own shutdown can both run.
	once sync.Once
}

// signal marks purpose as changed and wakes the delivery goroutine. It never
// blocks: a wake already queued carries this change too.
func (s *subscription) signal(purpose string) {
	s.mu.Lock()
	s.pend[purpose] = true
	s.mu.Unlock()
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// deliver is the subscription's goroutine: it swaps out the pending purposes
// and hands each to fn. A panic in fn is contained here — logged, and delivery
// continues — because the goroutine that changed the snapshot must never see
// it.
func (s *subscription) deliver() {
	for range s.wake {
		s.mu.Lock()
		pending := s.pend
		s.pend = map[string]bool{}
		s.mu.Unlock()
		var purposes []string
		for p := range pending {
			purposes = append(purposes, p)
		}
		sort.Strings(purposes)
		for _, p := range purposes {
			s.call(p)
		}
	}
}

func (s *subscription) call(purpose string) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("keys_subscriber_panicked", "purpose", purpose, "panic", fmt.Sprint(r))
		}
	}()
	s.fn(purpose)
}

// shutdown closes wake, ending the delivery goroutine once it has drained the
// mailbox. The caller has already removed the subscription from the KeySet's
// list under subMu — signal only sends inside that lock — so no signal can
// meet the closed channel. Idempotent.
func (s *subscription) shutdown() { s.once.Do(func() { close(s.wake) }) }

// Subscribe registers fn, called with the purpose after every change to that
// purpose's snapshot. Delivery is asynchronous, on a goroutine of the
// subscription's own: fn is called once per transition, but transitions that
// land while a delivery is still pending coalesce into one call, so fn must
// re-read the KeySet (JWKS, Version) instead of assuming it saw each change.
// fn may block — a slow subscriber delays only itself — and may panic, which
// is contained and logged. Subscribe returns at once; deliveries never run on
// the caller's goroutine. The returned function unsubscribes — removes the
// subscription and ends its goroutine — and is safe to call more than once;
// every subscription also ends when the manager's Run returns.
func (ks *KeySet) Subscribe(fn func(purpose string)) (unsubscribe func()) {
	s := &subscription{fn: fn, log: ks.log, wake: make(chan struct{}, 1), pend: map[string]bool{}}
	ks.subMu.Lock()
	ks.subs = append(ks.subs, s)
	ks.subMu.Unlock()
	go s.deliver()
	return func() {
		ks.subMu.Lock()
		for i, cur := range ks.subs {
			if cur == s {
				ks.subs = append(ks.subs[:i], ks.subs[i+1:]...)
				break
			}
		}
		ks.subMu.Unlock()
		s.shutdown()
	}
}

// stopSubscriptions ends every subscription's goroutine; Run calls it when its
// context ends, so a stopped manager leaves no delivery goroutines behind. A
// Subscribe after this one still delivers until its own unsubscribe.
func (ks *KeySet) stopSubscriptions() {
	ks.subMu.Lock()
	subs := ks.subs
	ks.subs = nil
	ks.subMu.Unlock()
	for _, s := range subs {
		s.shutdown()
	}
}

// Version returns how many times a purpose's snapshot changed. It never
// decreases and is what a JWKS client can compare to skip refetching.
func (ks *KeySet) Version() uint64 { return ks.ver.Load() }

// JWKS returns the public keys a verifier of purpose needs: the active key and
// the next key always — the next one so the prepublish window works, a
// verifier that fetches now already holds the key that signs next — and a
// retired key until its overlap ends, so tokens signed before the rotation keep
// verifying. Revoked and destroyed keys are never returned: an emergency
// rotation takes the key out of the set at once. A purpose with nothing loaded
// has an empty set.
func (ks *KeySet) JWKS(purpose string) JWKS {
	l := (*ks.cur.Load())[purpose]
	if l == nil {
		return JWKS{}
	}
	return PublishedJWKS(l.rows, ks.now(), l.overlap)
}

// countingSigner wraps the snapshot's active signer so a signing failure is
// counted per purpose. Signer is embedded, so KID, Alg and any string or log
// form describe the real key.
type countingSigner struct {
	Signer
	purpose string
	onErr   func(purpose string)
}

func (c countingSigner) Sign(ctx context.Context, signingInput []byte) ([]byte, error) {
	sig, err := c.Signer.Sign(ctx, signingInput)
	if err != nil {
		c.onErr(c.purpose)
	}
	return sig, err
}

// Active returns the signer of purpose's active key, or ErrNoActiveKey when
// that purpose has none loaded. The returned Signer is safe for concurrent use.
func (ks *KeySet) Active(purpose string) (Signer, error) {
	if l := (*ks.cur.Load())[purpose]; l != nil && l.active != nil {
		return l.active, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrNoActiveKey, purpose)
}

// Loaded reports whether purpose has an active key in the snapshot.
func (ks *KeySet) Loaded(purpose string) bool {
	_, err := ks.Active(purpose)
	return err == nil
}

// Records returns a copy of the metadata rows loaded for purpose.
func (ks *KeySet) Records(purpose string) []Record {
	l := (*ks.cur.Load())[purpose]
	if l == nil {
		return nil
	}
	return append([]Record(nil), l.rows...)
}
