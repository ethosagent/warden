package scenarios

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness"
)

// TestScenarios runs every catalog entry against its own in-process harness.
func TestScenarios(t *testing.T) {
	for _, s := range All {
		t.Run(s.Name, func(t *testing.T) {
			h := harness.New(t, append([]harness.Option{harness.Local()}, s.Opts...)...)
			s.Run(t, h)
		})
	}
}

// TestAll_Catalog pins the catalog's shape: unique, non-empty names (#351 and
// the coverage list key on them) and a runnable body.
func TestAll_Catalog(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range All {
		if s.Name == "" || s.Run == nil {
			t.Errorf("scenario %+v needs a Name and a Run", s)
		}
		if seen[s.Name] {
			t.Errorf("duplicate scenario name %q", s.Name)
		}
		seen[s.Name] = true
	}
	for _, want := range []string{"allow_with_swap", "default_deny", "swap_in_body", "dashboard_traffic_api",
		"events_recorded", "refresh_secrets", "healthz", "fail_closed_at_boot"} {
		if !seen[want] {
			t.Errorf("catalog is missing scenario %q", want)
		}
	}
	for _, name := range []string{"allow_with_swap", "default_deny"} {
		for _, s := range All {
			if s.Name == name && !s.L2 {
				t.Errorf("%s must be L2 (runs on compose)", name)
			}
		}
	}
	for _, row := range canaryRows {
		if row.echo {
			continue // EchoHeaders is an in-process fault: L1 only
		}
		for _, s := range All {
			if s.Name == row.name() && !s.L2 {
				t.Errorf("%s must be L2 (runs on compose)", s.Name)
			}
		}
	}
}

// recorder captures expectKnown's verdict.
type recorder struct {
	failed string
	logged []string
}

func (r *recorder) Helper() {}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
}
func (r *recorder) Logf(format string, args ...any) {
	r.logged = append(r.logged, fmt.Sprintf(format, args...))
}

// TestExpectKnown pins the known-issue contract: a violation that still
// happens passes quietly; one that stopped happening fails naming the marker;
// a plain (unmarked) assertion that does not hold fails.
func TestExpectKnown(t *testing.T) {
	r := &recorder{}
	expectKnown(r, "#388", false, "h2 body swap")
	if r.failed != "" || len(r.logged) != 1 {
		t.Errorf("a still-present known violation must pass and log once; failed=%q logged=%v", r.failed, r.logged)
	}

	r = &recorder{}
	expectKnown(r, "#388", true, "h2 body swap")
	if !strings.Contains(r.failed, "appears fixed: remove knownIssue") || !strings.Contains(r.failed, "#388") {
		t.Errorf("a fixed known violation must fail with the marker, got %q", r.failed)
	}

	r = &recorder{}
	expectKnown(r, "", false, "h1 body swap")
	if r.failed == "" {
		t.Error("an unmarked assertion that does not hold must fail")
	}

	r = &recorder{}
	expectKnown(r, "", true, "h1 body swap")
	if r.failed != "" || len(r.logged) != 0 {
		t.Errorf("an unmarked assertion that holds must be silent; failed=%q logged=%v", r.failed, r.logged)
	}
}
