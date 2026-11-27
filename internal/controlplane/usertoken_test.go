package controlplane

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/integration"
)

// TestUserTokenWritebackFinding: the finding is high severity and its DedupKey
// and evidence hold only the opaque user key and the provider id.
func TestUserTokenWritebackFinding(t *testing.T) {
	pub := &recFindings{}
	s := &Server{findings: pub}
	now := time.Unix(1_800_000_000, 0)
	writebackAlerter{s: s, now: func() time.Time { return now }}.WritebackFailed("0123456789abcdef0123456789abcdef", "google")

	got := pub.byRule("user_token_writeback_failed")
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	f := got[0]
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if want := "user_token_writeback_failed:0123456789abcdef0123456789abcdef:google"; f.DedupKey != want {
		t.Errorf("DedupKey = %q, want %q", f.DedupKey, want)
	}
	if strings.Contains(string(f.Evidence)+f.Summary, "@") {
		t.Errorf("finding names an email: %q %q", f.Summary, f.Evidence)
	}
	if !f.Ts.Equal(now) {
		t.Errorf("Ts = %v", f.Ts)
	}
}
