package integration

import (
	"testing"
	"time"
)

func TestBusPublishNilAlertManagerDrops(t *testing.T) {
	b := NewBus()
	b.logger = quietLogger()
	// No AlertManager wired: must not panic, just drop.
	b.PublishFinding(Finding{DedupKey: "k:x"})
}

func TestBusPublishForwardsToAlertManager(t *testing.T) {
	seq := 0
	store := &seqStore{seq: &seq}
	router := &seqRouter{seq: &seq}
	am := &AlertManager{store: store, router: router, logger: quietLogger(), now: func() time.Time { return time.UnixMilli(1) }}

	b := NewBus()
	b.logger = quietLogger()
	b.SetAlertManager(am)

	b.PublishFinding(Finding{DedupKey: "error_rate:x", Severity: SevHigh, Summary: "s"})
	if store.calls != 1 || router.calls != 1 {
		t.Errorf("bus should forward to alert manager: store=%d router=%d", store.calls, router.calls)
	}
}
