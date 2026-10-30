package keys

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
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

// ManagerConfig wires a Manager. Store, Meta, Codec and Algs are required.
type ManagerConfig struct {
	Store PrivateKeyStore
	Meta  MetaStore
	Codec KeyCodec
	// Backend names Store's backend ("file"); it is recorded in each row's
	// store_backend.
	Backend string
	// Algs maps each loadable purpose (token, bundle) to its algorithm.
	Algs map[string]string
	// Now is the time source and Wait the sleep the reload backoff uses: it
	// returns false if ctx ended first. Both are required (assembly adapts the
	// control plane's clock), so key timing is deterministic in tests.
	Now    func() time.Time
	Wait   func(ctx context.Context, d time.Duration) bool
	Logger *slog.Logger
	// Audit and Alerts are optional.
	Audit  AuditSink
	Alerts AlertSink
}

// Manager owns the signing keys: it creates them, loads them into the KeySet
// and hands out the stored CA key. Private keys live only in the
// PrivateKeyStore and, once loaded, in the KeySet's in-memory signers; the
// database holds public metadata only.
type Manager struct {
	cfg ManagerConfig
	log *slog.Logger
	set *KeySet

	// mu serialises every store-and-database sequence in this process: first
	// key creation, the orphan sweep, loads and imports. Across processes the
	// database's atomic writes (InsertIfEmpty, Insert) are the guard.
	mu sync.Mutex
	// degraded records the purposes currently in an unavailable episode, so
	// the Finding is raised once per episode, not once per retry.
	degraded map[string]string
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
	}
	if cfg.Algs[PurposeBundle] != AlgEdDSA {
		return nil, fmt.Errorf("%w: bundle keys must be %s", ErrUnsupportedAlg, AlgEdDSA)
	}
	m := &Manager{cfg: cfg, log: cfg.Logger, set: newKeySet(), degraded: map[string]string{}}
	if m.log == nil {
		m.log = slog.Default()
	}
	return m, nil
}

// KeySet returns the in-memory snapshot signers read. Sign paths use it and
// never touch the database or the store.
func (m *Manager) KeySet() *KeySet { return m.set }

// Init sweeps orphaned key material and loads the token and bundle purposes,
// creating the first active and next key for a purpose that has no rows. It
// never fails the caller: a purpose that cannot be loaded stays unavailable
// (Sign returns ErrNoActiveKey), a Finding is raised, and Run retries it. The
// control plane keeps serving either way.
func (m *Manager) Init(ctx context.Context) {
	if n, err := m.Sweep(ctx); err != nil {
		m.log.Warn("keys_sweep_failed", "error", err)
	} else if n > 0 {
		m.log.Warn("keys_orphans_swept", "count", n)
	}
	for _, p := range loadPurposes {
		_ = m.LoadKeySet(ctx, p) // the outcome is logged, alerted and retried
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

// Run retries, with 1s to 60s backoff, every purpose whose active key is not
// loaded, and returns when ctx is done. With everything loaded it only waits.
func (m *Manager) Run(ctx context.Context) {
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
			// picked up; the rotation scheduler (W-P2-KEYS-03) extends this loop.
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
		if err := m.createInitial(ctx, purpose); err != nil {
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
	m.set.install(purpose, sg, rows)
	m.log.Info("keys_loaded", "purpose", purpose, "alg", active.Alg, "active_kid", active.KID, "rows", len(rows))
	return nil
}

// noteLoad raises the Finding once per unavailable episode and clears the
// episode when the purpose loads.
func (m *Manager) noteLoad(ctx context.Context, purpose string, err error) {
	if err == nil {
		delete(m.degraded, purpose)
		return
	}
	m.log.Error("keys_load_failed", "purpose", purpose, "error", err)
	if _, already := m.degraded[purpose]; already {
		return
	}
	m.degraded[purpose] = err.Error()
	if m.cfg.Alerts != nil {
		m.cfg.Alerts.Raise(ctx, Alert{Rule: AlertSigningKeyUnavailable, Purpose: purpose, Detail: err.Error()})
	}
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
func (m *Manager) createInitial(ctx context.Context, purpose string) error {
	alg := m.cfg.Algs[purpose]
	now := m.cfg.Now()
	states := []State{StateActive, StateNext}
	recs := make([]Record, 0, len(states))
	for _, st := range states {
		priv, err := m.cfg.Codec.Generate(alg)
		if err != nil {
			m.discardAll(ctx, purpose, recs)
			return fmt.Errorf("keys: generate %s key: %w", purpose, err)
		}
		sg, err := m.newKey(ctx, purpose, alg, priv)
		if err != nil {
			m.discardAll(ctx, purpose, recs)
			return err
		}
		jwk, err := PublicJWK(sg.Public(), alg)
		if err != nil {
			m.discard(ctx, purpose, sg.KID())
			m.discardAll(ctx, purpose, recs)
			return err
		}
		rec := Record{
			KID: sg.KID(), Purpose: purpose, Alg: alg, State: st, PublicJWK: jwk,
			StoreBackend: m.cfg.Backend, CreatedAt: now, PublishAt: now,
			CreatedBy: SystemActor.Subject,
		}
		if st == StateActive {
			rec.ActivateAt = now
		}
		recs = append(recs, rec)
	}
	inserted, err := m.cfg.Meta.InsertIfEmpty(ctx, purpose, recs)
	if err != nil || !inserted {
		m.discardAll(ctx, purpose, recs)
		if err != nil {
			return fmt.Errorf("keys: record %s keys: %w", purpose, err)
		}
		return nil // lost the race: the winner's rows are loaded next
	}
	for _, r := range recs {
		m.log.Info("keys_transition", "purpose", purpose, "kid", r.KID, "state", string(r.State), "reason", "generated")
		m.audit(ctx, AuditEvent{Action: ActionGenerated, Purpose: purpose, KID: r.KID, Actor: SystemActor})
	}
	return nil
}

func (m *Manager) discardAll(ctx context.Context, purpose string, recs []Record) {
	for _, r := range recs {
		m.discard(ctx, purpose, r.KID)
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

// KeySet is the in-memory snapshot of the loaded signing keys. Readers take an
// atomic pointer to an immutable snapshot, so signing never touches the
// database or the key store and a backend outage after loading blocks nothing
// but rotation.
type KeySet struct {
	mu   sync.Mutex // serialises writers; readers use cur
	cur  atomic.Pointer[map[string]*loaded]
	zero map[string]*loaded
}

// loaded is one purpose's immutable snapshot.
type loaded struct {
	active Signer
	rows   []Record
}

func newKeySet() *KeySet {
	ks := &KeySet{zero: map[string]*loaded{}}
	ks.cur.Store(&ks.zero)
	return ks
}

// install replaces purpose's snapshot copy-on-write.
func (ks *KeySet) install(purpose string, active Signer, rows []Record) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	old := *ks.cur.Load()
	next := make(map[string]*loaded, len(old)+1)
	for k, v := range old {
		next[k] = v
	}
	next[purpose] = &loaded{active: active, rows: append([]Record(nil), rows...)}
	ks.cur.Store(&next)
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
