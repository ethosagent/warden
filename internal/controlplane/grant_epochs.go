package controlplane

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/secrets"
)

// Per-user revocation epochs (W-P3-PUS-08). A worker caches the access token it
// minted for a user for at most workerCacheTTL. The signed-bundle section
// userGrantEpochs {userKey: epoch} is how a revoke or an offboarding reaches
// every worker within one long-poll: EpochStore.Bump appends a `user_grant` row
// to the publish log and records the row's seq as the user's epoch, so the
// value only ever grows (a seq never goes backwards) and the bundle that
// carries it has a seq of its own. The section is keyed by secrets.UserKey, so
// no subject or email is on the wire, and it holds no token.
//
// The table keeps an entry only as long as a worker could still hold a token
// minted before it: rows older than 2 x workerCacheTTL are pruned by the
// retention ticker (PruneBefore), which appends no publish-log row, so the
// section stays bounded.

// ErrInvalidGrantUserKey is returned by Bump for a user key that is not a
// secrets.UserKey value (32 lowercase hex characters). Refusing anything else
// keeps a subject or an email off the wire.
var ErrInvalidGrantUserKey = errors.New("controlplane: user grant epoch needs a secrets.UserKey value")

// ErrEpochNotPublished is returned by Bump when the epoch was recorded but the
// signed bundle carrying it could not be published (the publisher is degraded).
// The caller should surface it: workers have not been told yet. Calling Bump
// again is safe and yields a larger epoch.
var ErrEpochNotPublished = errors.New("controlplane: user grant epoch recorded but the signed bundle could not be published")

const (
	// epochPruneInterval is how often the retention ticker prunes the table.
	epochPruneInterval = time.Minute
	// stateGrantSection is "<seq>:<userGrantEpochs section JSON>" of the newest
	// envelope signed with the section: the bytes a seq was signed with are
	// frozen, so a re-sign or a restart under the same seq signs the same
	// content even after a prune (a worker hashes every section byte).
	stateGrantSection = "user_grant_section"
	// maxBumpAttempts bounds the retries of a Bump whose head moved under it.
	maxBumpAttempts = 3
)

// GrantEpochMigrations is the cpstate migration of the epoch table. It is NOT
// Optional: the control plane can enable perUserSecrets at runtime (a served
// config edit), so the table must exist whatever the flag says. The state
// database's schema_version therefore grows by one on every control plane that
// runs this build, with the feature on or off, and a backup taken here cannot
// be restored on the previous binary (the downgrade guard refuses it).
func GrantEpochMigrations() []cpstate.Migration {
	return []cpstate.Migration{{
		ID: "bundles/0002",
		SQL: `CREATE TABLE user_grant_epochs (
	user_key  TEXT    PRIMARY KEY,
	epoch     INTEGER NOT NULL,
	bumped_at INTEGER NOT NULL
);`,
	}}
}

// grantEpochTable reads and writes user_grant_epochs.
type grantEpochTable struct{ db *sql.DB }

// all returns every entry as {userKey: epoch}.
func (t grantEpochTable) all(ctx context.Context) (map[string]int64, error) {
	rows, err := t.db.QueryContext(ctx, `SELECT user_key, epoch FROM user_grant_epochs`)
	if err != nil {
		return nil, fmt.Errorf("grant epochs: read: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var k string
		var e int64
		if err := rows.Scan(&k, &e); err != nil {
			return nil, fmt.Errorf("grant epochs: scan: %w", err)
		}
		out[k] = e
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grant epochs: read: %w", err)
	}
	return out, nil
}

// put records epoch for userKey (never lowering an existing one).
func (t grantEpochTable) put(ctx context.Context, userKey string, epoch int64, at time.Time) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("grant epochs: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO user_grant_epochs (user_key, epoch, bumped_at) VALUES (?, ?, ?)
		 ON CONFLICT(user_key) DO UPDATE SET epoch = MAX(epoch, excluded.epoch), bumped_at = excluded.bumped_at`,
		userKey, epoch, at.UnixMilli()); err != nil {
		return fmt.Errorf("grant epochs: write: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("grant epochs: commit: %w", err)
	}
	return nil
}

// pruneBefore deletes entries bumped before cutoff and returns how many.
func (t grantEpochTable) pruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := t.db.ExecContext(ctx, `DELETE FROM user_grant_epochs WHERE bumped_at < ?`, cutoff.UnixMilli())
	if err != nil {
		return 0, fmt.Errorf("grant epochs: prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// validGrantUserKey reports whether k has the shape of a secrets.UserKey.
func validGrantUserKey(k string) bool {
	if len(k) != secrets.UserKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// EpochStore bumps the per-user revocation epochs the signed bundle carries in
// its userGrantEpochs section. The consent portal's revoke (W-P3-PORT-02) and
// offboarding call Bump; this package provides the method.
type EpochStore struct {
	srv *Server
}

// GrantEpochs returns the epoch store, or nil when this control plane serves
// no signed bundles (nothing could carry an epoch to a worker).
func (s *Server) GrantEpochs() *EpochStore {
	if s.policy.bundles == nil {
		return nil
	}
	return &EpochStore{srv: s}
}

// Bump records a revocation of userKey: it appends a `user_grant` row to the
// publish log, sets the user's epoch to that row's seq and signs a bundle that
// carries it, which wakes the long-poll waiters. It returns the epoch. The
// epoch is a publish-log seq, so a later Bump always returns a larger one, also
// after the entry was pruned.
//
// With per-user secrets off (nothing serves the sections) Bump does nothing and
// returns 0, so a caller need not know whether the feature is on. A failed Bump
// returns an error and the caller must not report the revocation as delivered:
// ErrEpochNotPublished means the epoch is recorded but workers are not told yet.
func (e *EpochStore) Bump(ctx context.Context, userKey string) (int64, error) {
	if !validGrantUserKey(userKey) {
		return 0, ErrInvalidGrantUserKey
	}
	ps := e.srv.policy
	ps.refreshMu.Lock()
	defer ps.refreshMu.Unlock()
	b := ps.bundles
	if b == nil || !b.active || b.pu.raw == nil {
		return 0, nil
	}
	if !ps.loaded {
		return 0, errors.New("controlplane: user grant epoch: no policy loaded")
	}
	var entry PublishEntry
	var err error
	for attempt := 0; ; attempt++ {
		entry, err = ps.versions.AppendMarker(ctx, ps.lastHead, ps.lastETag, publishReasonUserGrant, publishActorBundle)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrConflict) || attempt+1 >= maxBumpAttempts {
			return 0, fmt.Errorf("controlplane: user grant epoch: append publish row: %s", boundedErr(err))
		}
		// The policy head moved since the last load: reload, then retry.
		ps.refreshLocked(ctx, false)
	}
	if err := (grantEpochTable{db: b.state.db}).put(ctx, userKey, entry.Seq, e.srv.cfg.Clock.Now()); err != nil {
		return 0, fmt.Errorf("controlplane: user grant epoch: %s", boundedErr(err))
	}
	ps.publishBundle(ctx, ps.lastWire, ps.lastETag, ps.lastHead, false)
	if b.cur == nil || b.cur.seq < entry.Seq {
		return entry.Seq, ErrEpochNotPublished
	}
	b.logger.Info("user grant epoch bumped", "seq", entry.Seq, "reason", publishReasonUserGrant)
	return entry.Seq, nil
}

// Prune deletes the entries older than 2 x MaxPerUserWorkerCacheTTL at now and
// returns how many. It uses the longest allowed TTL, not the current one, so
// lowering workerCacheTTL cannot drop an epoch a partitioned worker, still
// holding a token cached under the old TTL, needs. It appends no publish-log
// row and signs nothing: the next seq's bundle simply carries fewer entries
// (the bytes already signed for the current seq are frozen).
func (e *EpochStore) Prune(ctx context.Context, now time.Time) (int64, error) {
	ps := e.srv.policy
	ps.refreshMu.Lock()
	db := ps.bundles.state.db
	ps.refreshMu.Unlock()
	return (grantEpochTable{db: db}).pruneBefore(ctx, now.Add(-2*config.MaxPerUserWorkerCacheTTL))
}

// runEpochPrune prunes the epoch table once at start and then every
// epochPruneInterval on the control plane's clock until ctx is done.
func (s *Server) runEpochPrune(ctx context.Context) {
	e := s.GrantEpochs()
	if e == nil {
		return
	}
	go func() {
		for {
			if _, err := e.Prune(ctx, s.cfg.Clock.Now()); err != nil && ctx.Err() == nil {
				s.cfg.Logger.Warn("control plane: user grant epoch prune failed", "error", boundedErr(err))
			}
			t := s.cfg.Clock.NewTimer(epochPruneInterval)
			select {
			case <-ctx.Done():
				t.Stop()
				return
			case <-t.C():
			}
		}
	}()
}

// epochSection encodes the entries as the userGrantEpochs section.
func epochSection(entries map[string]int64) (json.RawMessage, error) {
	raw, err := json.Marshal(entries) // a map marshals with sorted keys
	if err != nil {
		return nil, fmt.Errorf("encode userGrantEpochs: %w", err)
	}
	return raw, nil
}
