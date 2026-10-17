package policy

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

// #409: a policy deny must say WHY. Every explicit Deny carries a bounded
// reason from the declared set (internal/denyreason); the caller turns a NoMatch
// default-deny into policy_no_match itself (NoMatch is not a deny in policy
// terms — it is judge-eligible).

func TestEvaluateRequest_DenylistCarriesReason(t *testing.T) {
	e := NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.example.com", Port: 443}},
		Denylist:  []config.DenylistEntry{{Domain: "api.example.com", Port: 443}},
	})
	v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/x")
	if v.Decision != Deny {
		t.Fatalf("denylist hit = %v, want Deny", v.Decision)
	}
	if string(v.Reason) != string(denyreason.PolicyDenylist) {
		t.Fatalf("denylist reason = %q, want %q", v.Reason, denyreason.PolicyDenylist)
	}
	// Destination-only (CONNECT) form says the same thing.
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "", ""); v.Decision != Deny || string(v.Reason) != string(denyreason.PolicyDenylist) {
		t.Fatalf("CONNECT denylist = %v/%q, want Deny/%q", v.Decision, v.Reason, denyreason.PolicyDenylist)
	}
}

func TestEvaluateRequest_TimeWindowCarriesReason(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com", TimeWindow: "9-17"})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) } // outside 9-17
	v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/x")
	if v.Decision != Deny {
		t.Fatalf("outside window = %v, want Deny", v.Decision)
	}
	if string(v.Reason) != string(denyreason.TimeWindow) {
		t.Fatalf("time-window reason = %q, want %q", v.Reason, denyreason.TimeWindow)
	}
	// The CONNECT gate peeks constraints and denies with the same reason.
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "", ""); v.Decision != Deny || string(v.Reason) != string(denyreason.TimeWindow) {
		t.Fatalf("CONNECT time-window = %v/%q, want Deny/%q", v.Decision, v.Reason, denyreason.TimeWindow)
	}
}

func TestEvaluateRequest_RateLimitCarriesReason(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com", RateLimit: "1/hour"})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/x"); v.Decision != Allow {
		t.Fatalf("first request = %v, want Allow", v.Decision)
	}
	v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/x")
	if v.Decision != Deny {
		t.Fatalf("second request = %v, want Deny", v.Decision)
	}
	if string(v.Reason) != string(denyreason.RateLimited) {
		t.Fatalf("rate-limit reason = %q, want %q", v.Reason, denyreason.RateLimited)
	}
	// The CONNECT gate peeks (never consumes) but must still name the guard.
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "", ""); v.Decision != Deny || string(v.Reason) != string(denyreason.RateLimited) {
		t.Fatalf("CONNECT rate-limit = %v/%q, want Deny/%q", v.Decision, v.Reason, denyreason.RateLimited)
	}
}

func TestEvaluateRequest_NoMatchStaysUnreasoned(t *testing.T) {
	// NoMatch is NOT a policy deny — the proxy default-denies it and names it
	// policy_no_match at the gate. Policy must not pre-empt that naming.
	e := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com"})
	v := e.EvaluateRequest("other.example.com", 443, SchemeHTTPS, "GET", "/x")
	if v.Decision != NoMatch {
		t.Fatalf("unlisted host = %v, want NoMatch", v.Decision)
	}
	if v.Reason != "" {
		t.Fatalf("NoMatch reason = %q, want empty (the gate names it policy_no_match)", v.Reason)
	}
}

// TestEvaluateRequest_EveryDenyCarriesDeclaredReason sweeps every deny-producing
// shape and requires a non-empty reason from the declared set. A deny without a
// reason is a #409 regression.
func TestEvaluateRequest_EveryDenyCarriesDeclaredReason(t *testing.T) {
	cases := []struct {
		name    string
		e       *Evaluator
		method  string
		path    string
		nowHour int
	}{
		{"denylist", NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{{Domain: "h.test"}},
			Denylist:  []config.DenylistEntry{{Domain: "h.test"}},
		}), "GET", "/x", 10},
		{"time window", func() *Evaluator {
			e := reqEvalFor(config.AllowlistEntry{Domain: "h.test", TimeWindow: "9-17"})
			e.now = func() time.Time { return time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) }
			return e
		}(), "GET", "/x", 20},
		{"rate limit", func() *Evaluator {
			e := reqEvalFor(config.AllowlistEntry{Domain: "h.test", RateLimit: "1/hour"})
			e.now = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }
			_ = e.EvaluateRequest("h.test", 443, SchemeHTTPS, "GET", "/x") // consume the slot
			return e
		}(), "GET", "/x", 10},
		{"method constraint", reqEvalFor(config.AllowlistEntry{Domain: "h.test", Methods: []string{"GET"}}), "POST", "/x", 10},
		{"path constraint", reqEvalFor(config.AllowlistEntry{Domain: "h.test", Paths: []string{"/ok/*"}}), "GET", "/no/x", 10},
		{"non-canonical path", reqEvalFor(config.AllowlistEntry{Domain: "h.test", Paths: []string{"/ok/*"}}), "GET", "/ok/../evil", 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.e.EvaluateRequest("h.test", 443, SchemeHTTPS, tc.method, tc.path)
			if v.Decision != Deny {
				t.Fatalf("%s = %v/%q, want Deny", tc.name, v.Decision, v.Reason)
			}
			if v.Reason == "" {
				t.Fatalf("%s deny carries no reason (#409)", tc.name)
			}
			if !denyreason.Reason(v.Reason).Declared() {
				t.Fatalf("%s reason %q is not in the declared set", tc.name, v.Reason)
			}
		})
	}
}
