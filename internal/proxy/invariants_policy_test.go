package proxy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/llmpolicy"
)

// Default-deny: whatever spelling the agent uses, a destination that is not on
// the allowlist (or is on the denylist) gets no tunnel, and the refusal is
// recorded with a reason.
func TestInvariants_DefaultDeny(t *testing.T) {
	policyOpts := invOpts{
		allow: []config.AllowlistEntry{
			{Domain: "allowed.test", Port: 443},
			{Domain: "*.wild.test", Port: 443},
		},
		denylist: []config.DenylistEntry{{Domain: "denied.test", Port: 443}},
	}
	denied := []struct{ name, target string }{
		{"unlisted host", "unlisted.test:443"},
		{"allowed host on another port", "allowed.test:8443"},
		{"allowed host on port 80", "allowed.test:80"},
		{"ipv4 literal", "203.0.113.7:443"},
		{"loopback literal", "127.0.0.1:443"},
		{"ipv6 literal", "[2001:db8::1]:443"},
		{"ipv6 loopback", "[::1]:443"},
		{"ipv4-mapped ipv6", "[::ffff:127.0.0.1]:443"},
		{"decimal ipv4", "2130706433:443"},
		{"hex ipv4", "0x7f.0.0.1:443"},
		{"mixed case unlisted", "UnListed.Test:443"},
		{"trailing dot unlisted", "unlisted.test.:443"},
		{"mixed case and trailing dot", "UNLISTED.Test.:443"},
		{"denylisted host", "denied.test:443"},
		{"denylisted mixed case", "DENIED.Test:443"},
		{"denylisted trailing dot", "denied.test.:443"},
		{"denylisted mixed case and trailing dot", "Denied.TEST.:443"},
		{"denylisted two trailing dots", "denied.test..:443"},
		{"denylisted three trailing dots", "denied.test...:443"},
		{"denylisted four trailing dots", "denied.test....:443"},
		{"wildcard apex", "wild.test:443"},
		{"wildcard lookalike", "evil-wild.test:443"},
		{"wildcard suffix smuggled", "x.wild.test.evil.test:443"},
		{"allowed host as subdomain of attacker", "allowed.test.evil.test:443"},
		{"no port", "allowed.test"},
		{"non-numeric port", "allowed.test:https"},
		{"empty host", ":443"},
	}
	for _, c := range denied {
		t.Run("deny/"+c.name, func(t *testing.T) {
			t.Parallel()
			e := newInvEnv(t, policyOpts)
			_, _, status, _ := e.connectRaw(c.target)
			if strings.Contains(status, "200") {
				t.Fatalf("CONNECT %s must be refused, got %q", c.target, strings.TrimSpace(status))
			}
			e.settle()
			var denyEvents int
			for _, ev := range e.store.snapshot() {
				if ev.Decision == "deny" {
					denyEvents++
				}
				if ev.Decision == "allow" {
					t.Errorf("CONNECT %s produced an allow event: %+v", c.target, ev)
				}
			}
			if denyEvents != 1 {
				t.Errorf("CONNECT %s: want exactly one deny event, got %d", c.target, denyEvents)
			}
			var reason string
			for _, m := range e.metrics.snapshot() {
				if r, ok := strings.CutPrefix(m, "blocked reason="); ok {
					reason = r
				}
			}
			if reason == "" {
				t.Errorf("CONNECT %s: refusal carries no blocked reason; metrics=%v", c.target, e.metrics.snapshot())
			}
			if e.backend.upstreamSawCanary() || len(e.backend.requests()) > 0 {
				t.Errorf("CONNECT %s reached the upstream", c.target)
			}
		})
	}

	// A denylisted host must stay denied even when a permissive judge is wired in:
	// the judge only sees NoMatch destinations, so a spelling that slips past the
	// denylist match (NoMatch instead of Deny) would be judged and allowed.
	// 3+ trailing dots do that today (#397); the rows flip when it is fixed.
	allowAll := &fakeJudge{verdict: Verdict{Decision: "allow", Reason: "invariants: judge says yes"}}
	for _, dots := range []int{1, 2, 3, 4} {
		known := ""
		if dots >= 3 {
			known = "#397"
		}
		target := "denied.test" + strings.Repeat(".", dots) + ":443"
		t.Run(fmt.Sprintf("deny/denylisted %d trailing dot(s) with permissive judge", dots), func(t *testing.T) {
			t.Parallel()
			o := policyOpts
			o.judge = allowAll
			e := newInvEnv(t, o)
			_, _, status, _ := e.connectRaw(target)
			refused := !strings.Contains(status, "200")
			switch {
			case known == "" && !refused:
				t.Fatalf("CONNECT %s must be refused, got %q", target, strings.TrimSpace(status))
			case known != "" && refused:
				t.Fatalf("%s appears fixed: CONNECT %s is now refused; remove the known-issue branch", known, target)
			case known != "":
				t.Logf("known issue %s still reproduces: CONNECT %s was allowed", known, target)
			}
		})
	}

	// Controls: the same spellings of an allowlisted host are allowed, so the
	// denies above are about policy and not a broken harness.
	for _, target := range []string{"allowed.test:443", "ALLOWED.Test.:443", "a.wild.test:443"} {
		t.Run("allow/"+target, func(t *testing.T) {
			t.Parallel()
			e := newInvEnv(t, policyOpts)
			_, _, status, err := e.connectRaw(target)
			if err != nil || !strings.Contains(status, "200") {
				t.Fatalf("CONNECT %s should be allowed, got %q (%v)", target, status, err)
			}
		})
	}
}

// stubLLM is the judge's model: it returns a canned reply, an error, or hangs.
type stubLLM struct {
	reply string
	err   error
	hang  time.Duration
}

func (s stubLLM) Evaluate(string) (string, error) {
	if s.hang > 0 {
		time.Sleep(s.hang)
	}
	return s.reply, s.err
}

// realJudge adapts the production llmpolicy judge to the proxy's Judge seam.
type realJudge struct{ j *llmpolicy.Judge }

func (r realJudge) Evaluate(agentID, method, url, host, ct string, hasAuth bool) Verdict {
	v := r.j.Evaluate(agentID, method, url, host, ct, hasAuth)
	return Verdict{Decision: v.Decision, Reason: v.Reason}
}

// fixedVerdictJudge returns whatever Verdict it is given, including malformed ones.
type fixedVerdictJudge struct{ v Verdict }

func (f fixedVerdictJudge) Evaluate(_, _, _, _, _ string, _ bool) Verdict { return f.v }

func newRealJudge(llm stubLLM, timeout time.Duration) Judge {
	return realJudge{llmpolicy.NewJudge(llm, map[string]string{"default": "allow reads"},
		llmpolicy.JudgeOptions{Timeout: timeout})}
}

// Fail-closed: when the judge errors, times out, answers garbage or is switched
// off between CONNECT and the request, the request is denied and never reaches
// the upstream. The control row proves a healthy judge still allows.
func TestInvariants_JudgeFailClosed(t *testing.T) {
	allowReply := `{"decision":"allow","reason":"ok"}`
	cases := []struct {
		name      string
		judge     Judge
		wantAllow bool
	}{
		{"control: judge allows", newRealJudge(stubLLM{reply: allowReply}, time.Second), true},
		{"judge errors", newRealJudge(stubLLM{err: errors.New("llm down")}, time.Second), false},
		{"judge times out", newRealJudge(stubLLM{reply: allowReply, hang: 2 * time.Second}, 100*time.Millisecond), false},
		{"judge answers garbage", newRealJudge(stubLLM{reply: "sure, go ahead"}, time.Second), false},
		{"judge answers deny", newRealJudge(stubLLM{reply: `{"decision":"deny","reason":"no"}`}, time.Second), false},
		{"verdict is empty", fixedVerdictJudge{Verdict{}}, false},
		{"verdict is not exactly allow", fixedVerdictJudge{Verdict{Decision: "ALLOW"}}, false},
		{"verdict is an error string", fixedVerdictJudge{Verdict{Decision: "error", Reason: "boom"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newInvEnv(t, invOpts{judge: c.judge})
			view, status, err := e.doHTTP1(invReq{host: invJudgedHost, path: "/ok", header: bearer()})
			e.settle()
			if c.wantAllow {
				if status != 200 {
					t.Fatalf("healthy judge should allow, got status %d (%v)", status, err)
				}
				return
			}
			if status != 403 {
				t.Fatalf("judge failure must deny with 403, got %d (%v)", status, err)
			}
			if n := len(e.backend.requests()); n != 0 {
				t.Fatalf("denied request reached the upstream (%d request(s))", n)
			}
			for _, l := range e.leaks(view) {
				t.Error(l)
			}
		})
	}

	t.Run("judge disabled mid-session", func(t *testing.T) {
		t.Parallel()
		e := newInvEnv(t, invOpts{judge: newRealJudge(stubLLM{reply: allowReply}, time.Second)})
		tc, err := e.connectTLS(invJudgedHost)
		if err != nil {
			t.Fatal(err)
		}
		e.p.SetJudge(nil) // control plane turns the judge off after CONNECT
		view, status, err := e.doHTTP1On(tc, invReq{host: invJudgedHost, path: "/ok", header: bearer()})
		e.settle()
		if status != 403 {
			t.Fatalf("request with the judge disabled must be denied, got %d (%v)", status, err)
		}
		if n := len(e.backend.requests()); n != 0 {
			t.Fatalf("denied request reached the upstream (%d request(s))", n)
		}
		for _, l := range e.leaks(view) {
			t.Error(l)
		}
	})

	t.Run("judge disabled before CONNECT", func(t *testing.T) {
		t.Parallel()
		e := newInvEnv(t, invOpts{judge: newRealJudge(stubLLM{reply: allowReply}, time.Second)})
		e.p.SetJudge(nil)
		_, _, status, _ := e.connectRaw(invJudgedHost + ":443")
		if strings.Contains(status, "200") {
			t.Fatalf("NoMatch with no judge must be default-denied, got %q", strings.TrimSpace(status))
		}
	})
}
