package integration

import (
	"log/slog"
	"sync"
)

// Bus is the single producer entrypoint. Detectors call PublishFinding; in M1
// the bus just forwards Findings to the AlertManager. The raw-event
// (EventStreamer) path is defined but unwired (M2).
type Bus struct {
	mu     sync.RWMutex
	am     *AlertManager
	logger *slog.Logger
}

// NewBus returns a Bus with no target yet. Call SetAlertManager to wire it.
func NewBus() *Bus {
	return &Bus{logger: slog.Default()}
}

// SetAlertManager wires the AlertManager the bus forwards Findings to.
func (b *Bus) SetAlertManager(am *AlertManager) {
	b.mu.Lock()
	b.am = am
	b.mu.Unlock()
}

// PublishFinding forwards a Finding to the AlertManager. It is safe to call
// before a manager is wired: the finding is dropped with a log line rather than
// panicking (fail-open producer path).
func (b *Bus) PublishFinding(f Finding) {
	b.mu.RLock()
	am := b.am
	b.mu.RUnlock()
	if am == nil {
		b.logger.Warn("integration: bus has no alert manager; dropping finding", "rule", f.RuleID, "dedupKey", f.DedupKey)
		return
	}
	am.Ingest(f)
}
