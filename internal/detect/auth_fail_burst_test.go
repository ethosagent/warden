package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/integration"
)

func feedAuthFails(d *authFailBurstDetector, n, status int) {
	for i := 0; i < n; i++ {
		d.Observe(mkEvent(base, testDomain, status))
	}
}

func TestAuthFailBurstTripsAtThreshold(t *testing.T) {
	d := newAuthFailBurstDetector(DefaultAuthFailBurstConfig(), 16)
	feedAuthFails(d, 14, 401)
	f, ok := findByRule(d.Evaluate(base), "auth_fail_burst")
	if !ok {
		t.Fatal("expected auth_fail_burst finding")
	}
	if f.Category != "security" {
		t.Errorf("category = %q, want security", f.Category)
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("severity = %v, want high", f.Severity)
	}
	if f.DedupKey != "auth_fail_burst:"+testDomain {
		t.Errorf("dedupKey = %q", f.DedupKey)
	}
	if f.Subject.Domain != testDomain || f.Subject.Worker != testWorker {
		t.Errorf("subject = %+v", f.Subject)
	}
	for _, want := range []string{"14 auth failures", "5m", testDomain} {
		if !strings.Contains(f.Summary, want) {
			t.Errorf("summary %q missing %q", f.Summary, want)
		}
	}
	assertFindingClean(t, f)
}

func TestAuthFailBurstCounts403(t *testing.T) {
	d := newAuthFailBurstDetector(DefaultAuthFailBurstConfig(), 16)
	feedAuthFails(d, 10, 403)
	if _, ok := findByRule(d.Evaluate(base), "auth_fail_burst"); !ok {
		t.Fatal("expected 403 responses to count toward the burst")
	}
}

func TestAuthFailBurstBelowThresholdDoesNotTrip(t *testing.T) {
	d := newAuthFailBurstDetector(DefaultAuthFailBurstConfig(), 16)
	feedAuthFails(d, 9, 401) // threshold is 10
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected no finding below threshold, got %v", fs)
	}
}

func TestAuthFailBurstIgnoresNonAuthStatus(t *testing.T) {
	d := newAuthFailBurstDetector(DefaultAuthFailBurstConfig(), 16)
	feedAuthFails(d, 50, 200)
	feedAuthFails(d, 50, 500)
	if fs := d.Evaluate(base); len(fs) != 0 {
		t.Fatalf("expected only 401/403 to count, got %v", fs)
	}
}

func TestAuthFailBurstWindowExpiry(t *testing.T) {
	cfg := DefaultAuthFailBurstConfig()
	d := newAuthFailBurstDetector(cfg, 16)
	feedAuthFails(d, 14, 401)
	if _, ok := findByRule(d.Evaluate(base), "auth_fail_burst"); !ok {
		t.Fatal("expected initial trip")
	}
	later := base.Add(cfg.Window + time.Second)
	if fs := d.Evaluate(later); len(fs) != 0 {
		t.Fatalf("expected the aged-out burst to stop tripping, got %v", fs)
	}
}
