package sqlstore

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
)

// ReplayStore is the approvals.ReplayStore over the draft_replays table (the
// approvals/0002 migration).
type ReplayStore struct {
	db *sql.DB
}

var _ approvals.ReplayStore = (*ReplayStore)(nil)

// NewReplayStore builds a ReplayStore over db (cpstate.DB.SQL()).
func NewReplayStore(db *sql.DB) *ReplayStore { return &ReplayStore{db: db} }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// zeroMS stores a zero time as 0, so it reads back as a zero time.
func zeroMS(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return ms(t)
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v)
}

// Insert implements approvals.ReplayStore.
func (st *ReplayStore) Insert(ctx context.Context, r approvals.Replay) (approvals.Replay, error) {
	if r.ID == "" {
		b := make([]byte, 12)
		if _, err := rand.Read(b); err != nil {
			return approvals.Replay{}, fmt.Errorf("approvals store: replay id: %w", err)
		}
		r.ID = "rp_" + hex.EncodeToString(b)
	}
	_, err := st.db.ExecContext(ctx,
		`INSERT INTO draft_replays (id, draft_id, revision, base_version, status, window_from, window_to,
		   events_scanned, truncated, result_json, error_code, started_at, finished_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, r.DraftID, r.Revision, r.BaseVersion, string(r.Status), zeroMS(r.WindowFrom), zeroMS(r.WindowTo),
		r.EventsScanned, b2i(r.Truncated), string(r.Result), r.ErrorCode, zeroMS(r.StartedAt), zeroMS(r.FinishedAt))
	if err != nil {
		return approvals.Replay{}, fmt.Errorf("approvals store: insert replay: %w", err)
	}
	return r, nil
}

// MarkRunning implements approvals.ReplayStore.
func (st *ReplayStore) MarkRunning(ctx context.Context, id string, at time.Time) (bool, error) {
	res, err := st.db.ExecContext(ctx,
		`UPDATE draft_replays SET status = 'running', started_at = ? WHERE id = ? AND status = 'pending'`, ms(at), id)
	if err != nil {
		return false, fmt.Errorf("approvals store: start replay: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Finish implements approvals.ReplayStore.
func (st *ReplayStore) Finish(ctx context.Context, id string, f approvals.ReplayFinish) (bool, error) {
	if !f.Status.Settled() {
		return false, fmt.Errorf("approvals store: replay status %q is not a final one", f.Status)
	}
	res, err := st.db.ExecContext(ctx,
		`UPDATE draft_replays SET status = ?, events_scanned = ?, truncated = ?, result_json = ?, error_code = ?, finished_at = ?
		 WHERE id = ? AND status IN ('pending','running')`,
		string(f.Status), f.EventsScanned, b2i(f.Truncated), string(f.Result), f.ErrorCode, ms(f.At), id)
	if err != nil {
		return false, fmt.Errorf("approvals store: finish replay: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

const replayCols = `id, draft_id, revision, base_version, status, window_from, window_to, events_scanned, truncated, result_json, error_code, started_at, finished_at`

func scanReplay(r rowScanner) (approvals.Replay, error) {
	var (
		rp                          approvals.Replay
		status, result              string
		from, to, started, finished int64
		truncated                   int
	)
	if err := r.Scan(&rp.ID, &rp.DraftID, &rp.Revision, &rp.BaseVersion, &status, &from, &to,
		&rp.EventsScanned, &truncated, &result, &rp.ErrorCode, &started, &finished); err != nil {
		return approvals.Replay{}, err
	}
	rp.Status = approvals.ReplayStatus(status)
	rp.WindowFrom, rp.WindowTo = fromMS(from), fromMS(to)
	rp.Truncated = truncated != 0
	rp.StartedAt, rp.FinishedAt = fromMS(started), fromMS(finished)
	if result != "" {
		rp.Result = json.RawMessage(result)
	}
	return rp, nil
}

// Get implements approvals.ReplayStore.
func (st *ReplayStore) Get(ctx context.Context, id string) (approvals.Replay, error) {
	rp, err := scanReplay(st.db.QueryRowContext(ctx, "SELECT "+replayCols+" FROM draft_replays WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return approvals.Replay{}, approvals.ErrReplayNotFound
	}
	if err != nil {
		return approvals.Replay{}, fmt.Errorf("approvals store: read replay %s: %w", id, err)
	}
	return rp, nil
}

// Latest implements approvals.ReplayStore. rowid order is insert order.
func (st *ReplayStore) Latest(ctx context.Context, draftID string, revision int) (approvals.Replay, bool, error) {
	q := "SELECT " + replayCols + " FROM draft_replays WHERE draft_id = ?"
	args := []any{draftID}
	if revision > 0 {
		q += " AND revision = ?"
		args = append(args, revision)
	}
	rp, err := scanReplay(st.db.QueryRowContext(ctx, q+" ORDER BY rowid DESC LIMIT 1", args...))
	if errors.Is(err, sql.ErrNoRows) {
		return approvals.Replay{}, false, nil
	}
	if err != nil {
		return approvals.Replay{}, false, fmt.Errorf("approvals store: read latest replay of %s: %w", draftID, err)
	}
	return rp, true, nil
}

// FailUnsettled implements approvals.ReplayStore.
func (st *ReplayStore) FailUnsettled(ctx context.Context, code string, at time.Time) (int, error) {
	res, err := st.db.ExecContext(ctx,
		`UPDATE draft_replays SET status = 'failed', error_code = ?, finished_at = ? WHERE status IN ('pending','running')`, code, ms(at))
	if err != nil {
		return 0, fmt.Errorf("approvals store: fail unsettled replays: %w", err)
	}
	n, err := res.RowsAffected()
	return int(n), err
}
