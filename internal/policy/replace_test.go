package policy

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// TestEvaluatorReplace verifies a control-plane-style hot swap: a destination
// that was NoMatch becomes Allow and the prior Allow becomes an explicit Deny,
// without constructing a new evaluator. Default-deny is preserved throughout.
func TestEvaluatorReplace(t *testing.T) {
	ev := NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "a.com"}},
	})
	if got := ev.Evaluate("a.com", 443, SchemeHTTPS); got != Allow {
		t.Fatalf("a.com before replace: got %v, want Allow", got)
	}
	if got := ev.Evaluate("b.com", 443, SchemeHTTPS); got != NoMatch {
		t.Fatalf("b.com before replace: got %v, want NoMatch", got)
	}

	ev.Replace(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "b.com"}},
		Denylist:  []config.DenylistEntry{{Domain: "a.com"}},
	})

	if got := ev.Evaluate("b.com", 443, SchemeHTTPS); got != Allow {
		t.Fatalf("b.com after replace: got %v, want Allow", got)
	}
	if got := ev.Evaluate("a.com", 443, SchemeHTTPS); got != Deny {
		t.Fatalf("a.com after replace: got %v, want Deny", got)
	}
	if got := ev.Evaluate("c.com", 443, SchemeHTTPS); got != NoMatch {
		t.Fatalf("c.com after replace: got %v, want NoMatch", got)
	}
}

// TestEvaluatorCurrentPolicy verifies CurrentPolicy reflects the live policy
// after a Replace (so the dashboard can show what is actually enforced).
func TestEvaluatorCurrentPolicy(t *testing.T) {
	ev := NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}})
	cur := ev.CurrentPolicy()
	if len(cur.Allowlist) != 1 || cur.Allowlist[0].Domain != "a.com" {
		t.Fatalf("initial CurrentPolicy = %+v", cur.Allowlist)
	}

	ev.Replace(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "b.com"}},
		Denylist:  []config.DenylistEntry{{Domain: "c.com"}},
	})
	cur = ev.CurrentPolicy()
	if len(cur.Allowlist) != 1 || cur.Allowlist[0].Domain != "b.com" {
		t.Fatalf("post-replace allowlist = %+v", cur.Allowlist)
	}
	if len(cur.Denylist) != 1 || cur.Denylist[0].Domain != "c.com" {
		t.Fatalf("post-replace denylist = %+v", cur.Denylist)
	}
}

// TestEvaluatorReplaceConcurrent ensures Replace is safe to call while Evaluate
// runs concurrently (race detector catches data races here).
func TestEvaluatorReplaceConcurrent(t *testing.T) {
	ev := NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			ev.Evaluate("a.com", 443, SchemeHTTPS)
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		ev.Replace(config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}})
	}
	<-done
}
