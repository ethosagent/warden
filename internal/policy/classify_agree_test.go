package policy_test

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policy"
)

// These tests run base and draft through the real evaluator and require the
// approvals classifier to agree: whenever the draft admits more traffic than
// the base, Classify must say Widening. Rated unscoped entries share one
// bucket per normalised domain and port, so the entries cannot be judged one
// at a time.

const (
	agreeSteps   = 70
	agreeStepDur = 2 * time.Minute
	agreeCap     = 15
)

func rated(domain string, port int, method, rl string) config.AllowlistEntry {
	e := config.AllowlistEntry{Domain: domain, Port: port, RateLimit: rl}
	if method != "" {
		e.Methods = []string{method}
	}
	return e
}

// throughput counts the requests of method target the evaluator admits over
// agreeSteps steps of agreeStepDur, after an optional opener request each step
// (the opener may open the shared bucket and set its window).
func throughput(entries []config.AllowlistEntry, opener, target string) int {
	now := time.Date(2024, 1, 1, 10, 0, 0, 0, time.Local)
	start := now
	e := policy.NewEvaluator(config.Policy{Allowlist: entries})
	e.SetNowForTest(func() time.Time { return now })
	req := func(m string) policy.RequestVerdict {
		return e.EvaluateFor(policy.RequestContext{Domain: "d.com", Port: 443, Scheme: policy.SchemeHTTPS, Method: m, Path: "/a"})
	}
	total := 0
	for s := 0; s < agreeSteps; s++ {
		now = start.Add(time.Duration(s) * agreeStepDur)
		if opener != "" {
			req(opener)
		}
		for k := 0; k < agreeCap; k++ {
			if req(target).Decision != policy.Allow {
				break
			}
			total++
		}
	}
	return total
}

func evaluatorWidens(base, draft []config.AllowlistEntry) bool {
	for _, opener := range []string{"", "GET", "POST"} {
		for _, target := range []string{"GET", "POST"} {
			if throughput(draft, opener, target) > throughput(base, opener, target) {
				return true
			}
		}
	}
	return false
}

func TestClassifyAgreesWithEvaluatorOnSharedBuckets(t *testing.T) {
	tests := []struct {
		name        string
		base, draft []config.AllowlistEntry
	}{
		{"POST rate tightened, GET shares the bucket",
			[]config.AllowlistEntry{rated("d.com", 443, "POST", "60/hour"), rated("d.com", 443, "GET", "60/hour")},
			[]config.AllowlistEntry{rated("d.com", 443, "POST", "1/minute"), rated("d.com", 443, "GET", "60/hour")}},
		{"unlimited-method entry removed",
			[]config.AllowlistEntry{rated("d.com", 443, "", "3/hour"), rated("d.com", 443, "GET", "2/minute")},
			[]config.AllowlistEntry{rated("d.com", 443, "GET", "2/minute")}},
		{"double charge disappears",
			[]config.AllowlistEntry{rated("d.com", 443, "", "1/minute"), rated("d.com", 443, "", "3/minute")},
			[]config.AllowlistEntry{rated("d.com", 443, "", "3/minute")}},
		{"port 0 shares with 443",
			[]config.AllowlistEntry{rated("d.com", 0, "POST", "60/hour"), rated("d.com", 443, "GET", "60/hour")},
			[]config.AllowlistEntry{rated("d.com", 0, "POST", "1/minute"), rated("d.com", 443, "GET", "60/hour")}},
		{"domain case shares a bucket",
			[]config.AllowlistEntry{rated("D.com", 443, "POST", "60/hour"), rated("d.com", 443, "GET", "60/hour")},
			[]config.AllowlistEntry{rated("D.com", 443, "POST", "1/minute"), rated("d.com", 443, "GET", "60/hour")}},
		{"port 0 double charge removed",
			[]config.AllowlistEntry{rated("d.com", 0, "", "1/minute"), rated("d.com", 443, "", "3/minute")},
			[]config.AllowlistEntry{rated("d.com", 443, "", "3/minute")}},
		{"domain case double charge removed",
			[]config.AllowlistEntry{rated("D.com", 443, "", "1/minute"), rated("d.com", 443, "", "3/minute")},
			[]config.AllowlistEntry{rated("d.com", 443, "", "3/minute")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !evaluatorWidens(tc.base, tc.draft) {
				t.Fatal("test premise: the draft must admit more traffic in the evaluator")
			}
			got := approvals.Classify(approvals.Doc{Allowlist: tc.base}, approvals.Doc{Allowlist: tc.draft})
			if !got.Widening {
				t.Fatalf("evaluator admits more but Classify says narrowing: %+v", got)
			}
		})
	}
}

func TestClassifyAgreesWithEvaluatorOnSimpleTightening(t *testing.T) {
	base := []config.AllowlistEntry{rated("d.com", 443, "", "10/minute")}
	draft := []config.AllowlistEntry{rated("d.com", 443, "", "5/minute")}
	if evaluatorWidens(base, draft) {
		t.Fatal("test premise: tightening must not admit more")
	}
	if got := approvals.Classify(approvals.Doc{Allowlist: base}, approvals.Doc{Allowlist: draft}); got.Widening {
		t.Fatalf("tightening flagged: %+v", got)
	}
}
