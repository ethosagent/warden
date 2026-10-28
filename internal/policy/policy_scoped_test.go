package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
)

func subj(groups ...string) *identity.Subject {
	return &identity.Subject{Sub: "u-123", Email: "alice@corp.example", EmailVerified: true, Groups: groups}
}

func ctx(domain string, method string, s *identity.Subject) RequestContext {
	return RequestContext{Domain: domain, Port: 443, Scheme: SchemeHTTPS, Method: method, Path: "/x", Subject: s}
}

func wantVerdict(t *testing.T, got RequestVerdict, d Decision, r denyreason.Reason) {
	t.Helper()
	if got.Decision != d || got.Reason != r {
		t.Fatalf("verdict = {%v %q}, want {%v %q}", got.Decision, got.Reason, d, r)
	}
}

func TestEvaluateFor_Scoped(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.github.com", Groups: []string{"eng"}})
	v := e.EvaluateFor(ctx("api.github.com", "GET", subj("eng")))
	wantVerdict(t, v, Allow, "")
	if !v.Scoped {
		t.Error("Scoped = false on an allow through a scoped entry")
	}
	wantVerdict(t, e.EvaluateFor(ctx("api.github.com", "GET", subj("sales"))), Deny, denyreason.GroupNotAllowed)
	wantVerdict(t, e.EvaluateFor(ctx("api.github.com", "GET", nil)), Conditional, denyreason.IdentityRequired)
	wantVerdict(t, e.EvaluateFor(ctx("api.github.com", "", nil)), Conditional, denyreason.IdentityRequired)
	if d := e.Evaluate("api.github.com", 443, SchemeHTTPS); d != Deny {
		t.Fatalf("Evaluate on scoped host = %v, want Deny", d)
	}
	if v := e.EvaluateFor(ctx("other.example.com", "GET", subj("eng"))); v.Decision != NoMatch || v.Scoped {
		t.Fatalf("unrelated host = %+v, want NoMatch unscoped", v)
	}
}

func TestEvaluateFor_UsersAndVerifiedEmail(t *testing.T) {
	e := evalFor(
		config.AllowlistEntry{Domain: "mail.example.com", Users: []string{"alice@corp.example"}},
		config.AllowlistEntry{Domain: "sub.example.com", Users: []string{"u-123"}},
	)
	s := subj()
	s.EmailVerified = false
	wantVerdict(t, e.EvaluateFor(ctx("mail.example.com", "GET", s)), Deny, denyreason.GroupNotAllowed)
	s.EmailVerified = true
	wantVerdict(t, e.EvaluateFor(ctx("mail.example.com", "GET", s)), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("sub.example.com", "GET", s)), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("sub.example.com", "GET", &identity.Subject{Sub: "u-124"})), Deny, denyreason.GroupNotAllowed)
}

func TestEvaluateFor_TruncatedGroups(t *testing.T) {
	e := evalFor(
		config.AllowlistEntry{Domain: "g.example.com", Groups: []string{"eng"}},
		config.AllowlistEntry{Domain: "both.example.com", Groups: []string{"eng"}, Users: []string{"u-123"}},
		config.AllowlistEntry{Domain: "u.example.com", Users: []string{"u-999"}},
	)
	trunc := func(groups ...string) *identity.Subject { s := subj(groups...); s.GroupsTruncated = true; return s }
	wantVerdict(t, e.EvaluateFor(ctx("g.example.com", "GET", trunc("eng"))), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("g.example.com", "GET", trunc("sales"))), Deny, denyreason.IdentityGroupsTruncated)
	wantVerdict(t, e.EvaluateFor(ctx("both.example.com", "GET", trunc("sales"))), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("g.example.com", "GET", subj("sales"))), Deny, denyreason.GroupNotAllowed)
	// A users-only entry is unaffected by truncation.
	wantVerdict(t, e.EvaluateFor(ctx("u.example.com", "GET", trunc("sales"))), Deny, denyreason.GroupNotAllowed)
}

func TestEvaluateFor_ConstraintsAfterPrincipal(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "d.example.com", Groups: []string{"eng"}, Methods: []string{"GET"}, Paths: []string{"/ok"}})
	wantVerdict(t, e.EvaluateFor(ctx("d.example.com", "POST", subj("eng"))), Deny, denyreason.MethodNotAllowed)
	wantVerdict(t, e.EvaluateFor(ctx("d.example.com", "POST", subj("sales"))), Deny, denyreason.GroupNotAllowed)
	wantVerdict(t, e.EvaluateFor(ctx("d.example.com", "POST", nil)), Conditional, denyreason.IdentityRequired)
	rc := ctx("d.example.com", "GET", subj("eng"))
	rc.Path = "/nope"
	wantVerdict(t, e.EvaluateFor(rc), Deny, denyreason.PathNotAllowed)
	rc.Path = "/ok"
	wantVerdict(t, e.EvaluateFor(rc), Allow, "")
	// CONNECT form: constraints could-match, principal still decides.
	wantVerdict(t, e.EvaluateFor(ctx("d.example.com", "", subj("eng"))), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("d.example.com", "", subj("sales"))), Deny, denyreason.GroupNotAllowed)
}

func TestEvaluateFor_MixedScopedUnscoped(t *testing.T) {
	e := evalFor(
		config.AllowlistEntry{Domain: "h.example.com", Groups: []string{"eng"}},
		config.AllowlistEntry{Domain: "h.example.com", Methods: []string{"GET"}},
	)
	v := e.EvaluateFor(ctx("h.example.com", "GET", nil))
	wantVerdict(t, v, Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("h.example.com", "GET", subj("sales"))), Allow, "")
	// Unscoped entry rejects POST, scoped entry skipped for nil: identity could still help.
	wantVerdict(t, e.EvaluateFor(ctx("h.example.com", "POST", nil)), Conditional, denyreason.IdentityRequired)
	// Eng member POSTs: scoped entry admits (no constraints).
	wantVerdict(t, e.EvaluateFor(ctx("h.example.com", "POST", subj("eng"))), Allow, "")
	// Non-member POST: the unscoped entry's guard reason wins over group_not_allowed.
	wantVerdict(t, e.EvaluateFor(ctx("h.example.com", "POST", subj("sales"))), Deny, denyreason.MethodNotAllowed)
}

func TestEvaluateFor_DenylistWins(t *testing.T) {
	e := evalWithDenylist(
		[]config.AllowlistEntry{{Domain: "bad.example.com", Groups: []string{"eng"}}},
		[]config.DenylistEntry{{Domain: "bad.example.com"}},
	)
	v := e.EvaluateFor(ctx("bad.example.com", "GET", subj("eng")))
	wantVerdict(t, v, Deny, denyreason.PolicyDenylist)
}

func TestEvaluateFor_ScopedRateBuckets(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "r.example.com", Groups: []string{"eng"}, RateLimit: "1/minute"})
	for i := 0; i < 3; i++ {
		wantVerdict(t, e.EvaluateFor(ctx("r.example.com", "GET", subj("sales"))), Deny, denyreason.GroupNotAllowed)
		wantVerdict(t, e.EvaluateFor(ctx("r.example.com", "GET", nil)), Conditional, denyreason.IdentityRequired)
	}
	wantVerdict(t, e.EvaluateFor(ctx("r.example.com", "GET", subj("eng"))), Allow, "")
	wantVerdict(t, e.EvaluateFor(ctx("r.example.com", "GET", subj("eng"))), Deny, denyreason.RateLimited)

	// Scoped and unscoped entries for one host keep separate counters.
	e2 := evalFor(
		config.AllowlistEntry{Domain: "r.example.com", Groups: []string{"eng"}, RateLimit: "1/minute"},
		config.AllowlistEntry{Domain: "r.example.com", Methods: []string{"POST"}, RateLimit: "1/minute"},
	)
	wantVerdict(t, e2.EvaluateFor(ctx("r.example.com", "POST", subj("eng"))), Allow, "")
	wantVerdict(t, e2.EvaluateFor(ctx("r.example.com", "POST", nil)), Allow, "")
	if len(e2.counters) != 2 {
		t.Fatalf("counters = %d, want 2 distinct buckets", len(e2.counters))
	}
}

func TestPeekFor_NoCharge(t *testing.T) {
	e := evalFor(
		config.AllowlistEntry{Domain: "r.example.com", Groups: []string{"eng"}, RateLimit: "1/minute"},
		config.AllowlistEntry{Domain: "u.example.com", RateLimit: "1/minute"},
	)
	for _, d := range []string{"r.example.com", "u.example.com"} {
		for _, m := range []string{"GET", ""} {
			for i := 0; i < 5; i++ {
				wantVerdict(t, e.PeekFor(ctx(d, m, subj("eng"))), Allow, "")
			}
		}
		wantVerdict(t, e.EvaluateFor(ctx(d, "GET", subj("eng"))), Allow, "")
		wantVerdict(t, e.PeekFor(ctx(d, "GET", subj("eng"))), Deny, denyreason.RateLimited)
	}
}

func TestEvaluate_NeverConditional(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "s.example.com", Groups: []string{"eng"}})
	if d := e.Evaluate("s.example.com", 443, SchemeHTTPS); d != Deny {
		t.Fatalf("Evaluate = %v, want Deny", d)
	}
}

func TestEvaluateRequest_ScopedCollapsesToDeny(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "s.example.com", Groups: []string{"eng"}})
	for _, m := range []string{"", "GET"} {
		v := e.EvaluateRequest("s.example.com", 443, SchemeHTTPS, m, "/x")
		wantVerdict(t, v, Deny, denyreason.IdentityRequired)
	}
}

func TestDecision_ConditionalString(t *testing.T) {
	if Conditional.String() != "conditional" || Conditional <= NoMatch {
		t.Fatalf("Conditional = %d %q", Conditional, Conditional.String())
	}
	if Deny != 0 || Allow != 1 || NoMatch != 2 {
		t.Fatal("existing Decision values changed")
	}
}

// Baselines measured on EvaluateRequest before this change (50 unscoped
// entries, last one matched): destination-only 0 allocs, per-request 1.
const (
	baselineAllocsConnect = 0
	baselineAllocsRequest = 1
)

func TestEvaluateFor_NoScopedAllocs(t *testing.T) {
	var es []config.AllowlistEntry
	for i := 0; i < 50; i++ {
		es = append(es, config.AllowlistEntry{Domain: fmt.Sprintf("h%d.example.com", i), Methods: []string{"GET"}})
	}
	e := evalFor(es...)
	for _, c := range []struct {
		method string
		want   float64
	}{{"", baselineAllocsConnect}, {"GET", baselineAllocsRequest}} {
		rc := ctx("h49.example.com", c.method, nil)
		if got := testing.AllocsPerRun(100, func() { e.EvaluateFor(rc) }); got != c.want {
			t.Errorf("EvaluateFor(method=%q) allocs = %v, want baseline %v", c.method, got, c.want)
		}
	}
}

func TestEvaluateFor_ConcurrentReplace(t *testing.T) {
	scoped := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "c.example.com", Groups: []string{"eng"}, RateLimit: "100/minute"}}}
	plain := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "c.example.com"}, {Domain: "d.example.com", Users: []string{"u-123"}}}}
	e := NewEvaluator(scoped)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				e.EvaluateFor(ctx("c.example.com", "GET", subj("eng")))
				e.PeekFor(ctx("d.example.com", "", nil))
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			e.Replace(plain)
		} else {
			e.Replace(scoped)
		}
	}
	close(stop)
	wg.Wait()
}

func TestCurrentPolicy_ClonesPrincipals(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "c.example.com", Groups: []string{"eng"}, Users: []string{"u-1"}})
	p := e.CurrentPolicy()
	p.Allowlist[0].Groups[0] = "x"
	p.Allowlist[0].Users[0] = "x"
	q := e.CurrentPolicy()
	if q.Allowlist[0].Groups[0] != "eng" || q.Allowlist[0].Users[0] != "u-1" {
		t.Fatal("CurrentPolicy aliases live principals")
	}
}
