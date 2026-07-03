package analytics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

// RemoteStore is the interface for the central analytics store.
type RemoteStore interface {
	SendBatch(events []Event) error
}

// SyncWorker batches local events to a remote store and prunes after confirmation.
type SyncWorker struct {
	local     *SQLiteStore
	remote    RemoteStore
	proxyID   string
	batchSize int
	bufferCap int
	interval  time.Duration
}

// NewSyncWorker creates a SyncWorker that forwards events from local to remote.
// proxyID is this worker's fleet identifier (the same value HTTPRemoteStore
// sends in the X-Warden-Proxy-ID header); when non-empty each outgoing event is
// stamped with a stable dedup UID derived from it (see eventUID).
func NewSyncWorker(local *SQLiteStore, remote RemoteStore, proxyID string, batchSize, bufferCap int, interval time.Duration) *SyncWorker {
	return &SyncWorker{
		local:     local,
		remote:    remote,
		proxyID:   proxyID,
		batchSize: batchSize,
		bufferCap: bufferCap,
		interval:  interval,
	}
}

// eventUID derives the stable dedup identifier for a local event: a truncated
// SHA-256 over the worker's proxy id and the event's local rowid (NUL-separated
// so the two inputs can never ambiguously concatenate). The local events table
// uses an AUTOINCREMENT primary key, so rowids are never reused after deletion
// and survive process restarts — re-reading the same event always yields the
// same UID (retry-stable), and distinct events always yield distinct UIDs even
// when their semantic fields (timestamp/domain/method) are identical.
func eventUID(proxyID string, rowID int64) string {
	sum := sha256.Sum256([]byte(proxyID + "\x00" + strconv.FormatInt(rowID, 10)))
	return hex.EncodeToString(sum[:12]) // 24 hex chars: plenty for per-fleet uniqueness
}

// Start runs the sync loop in a goroutine. It calls SyncOnce immediately, then
// every interval until ctx is cancelled.
func (w *SyncWorker) Start(ctx context.Context) {
	go func() {
		_ = w.SyncOnce()

		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = w.SyncOnce()
			}
		}
	}()
}

// SyncOnce performs one sync cycle: fetch a batch from local, send to remote,
// and prune on success. On failure the events are preserved, but if the local
// store exceeds bufferCap the oldest events are pruned to stay within cap.
func (w *SyncWorker) SyncOnce() error {
	ids, events, err := w.local.GetOldestEventIDs(w.batchSize)
	if err != nil || len(events) == 0 {
		return err
	}

	// Stamp each event with its stable dedup UID BEFORE the send, derived from
	// the local rowid — so a batch that was stored server-side but whose ack was
	// lost re-sends with identical UIDs and the control plane drops the
	// duplicates. Skipped when no proxy id is configured: two anonymous workers
	// would derive colliding UIDs from the same rowids and the CP would silently
	// drop legitimate events — duplicates-on-retry is the safer failure mode.
	if w.proxyID != "" {
		for i := range events {
			events[i].UID = eventUID(w.proxyID, ids[i])
		}
	}

	if err := w.remote.SendBatch(events); err != nil {
		// Remote failed — check buffer cap.
		n, countErr := w.local.count()
		if countErr == nil && n > w.bufferCap {
			excess := n - w.bufferCap
			excessIDs, _, _ := w.local.GetOldestEventIDs(excess)
			_ = w.local.DeleteEventsByID(excessIDs)
		}
		return err
	}

	// Success — prune the events we just sent.
	return w.local.DeleteEventsByID(ids)
}
