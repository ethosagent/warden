package analytics

import (
	"context"
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
	batchSize int
	bufferCap int
	interval  time.Duration
}

// NewSyncWorker creates a SyncWorker that forwards events from local to remote.
func NewSyncWorker(local *SQLiteStore, remote RemoteStore, batchSize, bufferCap int, interval time.Duration) *SyncWorker {
	return &SyncWorker{
		local:     local,
		remote:    remote,
		batchSize: batchSize,
		bufferCap: bufferCap,
		interval:  interval,
	}
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
