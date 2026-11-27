package proxy

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/denyreason"
)

// Event timestamps come from Config.Now (the injected clock), not time.Now, so
// the UTC day an event books to agrees with the cost ledger's clock.
func TestEventTimestampUsesInjectedClock(t *testing.T) {
	p := bindProxy(t, &bindVerifier{})
	fixed := time.Date(2031, 5, 6, 23, 59, 0, 0, time.UTC)
	p.evNow = func() time.Time { return fixed }
	s := stageScope(connIdentity{})
	p.emitDeny(s, denyreason.UserCostLimited)
	st := p.cfg.Analytics.(*syncStore)
	if len(st.events) != 1 {
		t.Fatalf("%d events, want 1", len(st.events))
	}
	if got := st.events[0].Timestamp; !got.Equal(fixed) {
		t.Fatalf("deny timestamp = %v, want the injected %v", got, fixed)
	}
	if d := time.Since((&Proxy{}).eventNow()); d < 0 || d > time.Minute {
		t.Fatalf("default event clock is not time.Now: %v", d)
	}
}
