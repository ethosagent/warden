package policy

import (
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// trailingDotEvaluator is the shared policy for the #397 tables: one exact,
// one wildcard and one regex entry on each side of the fence.
func trailingDotEvaluator() *Evaluator {
	return NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: "api.openai.com"},
			{Domain: "*.githubusercontent.com"},
			{Domain: `~^api\d+\.llm\.example\.com$`},
		},
		Denylist: []config.DenylistEntry{
			{Domain: "bad.corp.test"},
			{Domain: "*.malware.net"},
			{Domain: `~^blocked\.corp\.example$`},
		},
	})
}

// trailingDotForms returns the host with 0 to 5 trailing dots appended.
func trailingDotForms(host string) []string {
	forms := make([]string, 0, 12)
	for _, dots := range []string{"", ".", "..", "...", "....", "....."} {
		forms = append(forms, host+dots, strings.ToUpper(host)+dots)
	}
	return forms
}

// TestEvaluate_TrailingDots pins #397: rule matching must not depend on the
// number of trailing dots (or the case) of the CONNECT host. Every entry
// dialect — exact, wildcard, regex, on both the deny and the allow side —
// matches its host for any number of trailing dots.
func TestEvaluate_TrailingDots(t *testing.T) {
	e := trailingDotEvaluator()
	bases := []struct {
		host string
		want Decision
	}{
		{"bad.corp.test", Deny},              // exact deny
		{"x.malware.net", Deny},              // wildcard deny
		{"blocked.corp.example", Deny},       // regex deny
		{"api.openai.com", Allow},            // exact allow
		{"raw.githubusercontent.com", Allow}, // wildcard allow
		{"api2.llm.example.com", Allow},      // regex allow
	}
	for _, b := range bases {
		for _, host := range trailingDotForms(b.host) {
			if got := e.Evaluate(host, 443, SchemeHTTPS); got != b.want {
				t.Errorf("Evaluate(%q) = %v, want %v", host, got, b.want)
			}
			if got := e.EvaluateRequest(host, 443, SchemeHTTPS, "GET", "/x").Decision; got != b.want {
				t.Errorf("EvaluateRequest(%q, GET, /x) = %v, want %v", host, got, b.want)
			}
		}
	}
	// Control: an unlisted host must stay NoMatch — the trailing-dot fix makes
	// listed hosts match reliably, it must not make everything a deny.
	if got := e.Evaluate("unrelated.test...", 443, SchemeHTTPS); got != NoMatch {
		t.Errorf("Evaluate(unlisted host with dots) = %v, want NoMatch", got)
	}
}

// TestEvaluate_DottedPatterns pins the pattern side of #397: a configured entry
// that itself carries trailing dots matches its bare host.
func TestEvaluate_DottedPatterns(t *testing.T) {
	e := NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "allowed.rule.test.."}},
		Denylist:  []config.DenylistEntry{{Domain: "bad.rule.test..."}},
	})
	if got := e.Evaluate("bad.rule.test", 443, SchemeHTTPS); got != Deny {
		t.Errorf("dotted deny pattern vs bare host = %v, want Deny", got)
	}
	if got := e.Evaluate("allowed.rule.test", 443, SchemeHTTPS); got != Allow {
		t.Errorf("dotted allow pattern vs bare host = %v, want Allow", got)
	}
	if got := e.Evaluate("allowed.rule.test..", 443, SchemeHTTPS); got != Allow {
		t.Errorf("dotted allow pattern vs dotted host = %v, want Allow", got)
	}
}

// TestEvaluate_DotsOnlyHostDenied pins the fail-closed half of #397: a host
// that is only dots — or empty — normalises to nothing and is denied outright,
// never matched against a rule. Even an allow-everything regex must not admit
// it, and the outcome is an explicit Deny (not NoMatch), so it can never reach
// the judge.
func TestEvaluate_DotsOnlyHostDenied(t *testing.T) {
	policies := map[string]config.Policy{
		"allow-everything regex": {Allowlist: []config.AllowlistEntry{{Domain: `~.*`}}},
		"allow-everything regex anchored": {
			Allowlist: []config.AllowlistEntry{{Domain: `~^.*$`}},
		},
		"wildcard": {Allowlist: []config.AllowlistEntry{{Domain: "*.corp.test"}}},
		"exact":    {Allowlist: []config.AllowlistEntry{{Domain: "api.openai.com"}}},
	}
	for name, p := range policies {
		e := NewEvaluator(p)
		for _, host := range []string{"", ".", "..", "..."} {
			if got := e.Evaluate(host, 443, SchemeHTTPS); got != Deny {
				t.Errorf("%s: Evaluate(%q) = %v, want Deny (fail closed)", name, host, got)
			}
		}
	}
}

// TestMatchDomain_TrailingDots pins the shared matcher dialect for every caller
// outside the evaluator (DLP `to`, secret-scoping matchHosts, auth matches):
// both sides are normalised the same way, and an empty or dots-only host never
// matches anything.
func TestMatchDomain_TrailingDots(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		// Exact: any number of trailing dots on either side.
		{"bad.corp.test", "bad.corp.test", true},
		{"bad.corp.test", "bad.corp.test.", true},
		{"bad.corp.test", "bad.corp.test..", true},
		{"bad.corp.test", "bad.corp.test...", true},
		{"bad.corp.test", "BAD.CORP.TEST....", true},
		{"bad.corp.test...", "bad.corp.test", true},
		{"bad.corp.test", "bad.corp.test.evil.test", false},

		// Wildcard.
		{"*.malware.net", "x.malware.net.....", true},
		{"*.malware.net", "MALWARE.NET..", false}, // apex stays unmatched
		{"*.malware.net", "x.malware.net.evil.test...", false},

		// Regex.
		{`~^blocked\.corp\.example$`, "blocked.corp.example.....", true},
		{`~^blocked\.corp\.example$`, "blocked.corp.example.evil.test...", false},

		// A host that is only dots — or empty — matches nothing, whatever the
		// pattern would otherwise admit.
		{"*.corp.test", "...", false},
		{`~.*`, "...", false},
		{"bad.corp.test", "", false},
		{"bad.corp.test...", "", false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// TestEvaluate_RegexEntriesDifferingOnlyByTrailingDot pins the regex half of
// #397: in a "~regex" PATTERN a trailing '.' is the "any one char"
// metacharacter, not a DNS trailing dot, so normalisation must never touch it.
// Normalising merged two entries that differ only by that dot onto one regex
// cache key, and the later compile silently replaced the earlier regex — the
// first entry stopped matching its own host.
func TestEvaluate_RegexEntriesDifferingOnlyByTrailingDot(t *testing.T) {
	t.Run("allowlist", func(t *testing.T) {
		e := NewEvaluator(config.Policy{
			Allowlist: []config.AllowlistEntry{
				{Domain: `~^api\.openai\.com`},  // matches api.openai.com itself
				{Domain: `~^api\.openai\.com.`}, // needs one char after "com"
			},
		})
		if got := e.Evaluate("api.openai.com", 443, SchemeHTTPS); got != Allow {
			t.Errorf("Evaluate(api.openai.com) = %v, want Allow (the dotted sibling must not shadow this entry's regex)", got)
		}
		if got := e.Evaluate("api.openai.comX", 443, SchemeHTTPS); got != Allow {
			t.Errorf("Evaluate(api.openai.comX) = %v, want Allow", got)
		}
	})
	t.Run("denylist", func(t *testing.T) {
		e := NewEvaluator(config.Policy{
			Denylist: []config.DenylistEntry{
				{Domain: `~^bad\.corp\.test`},  // matches bad.corp.test itself
				{Domain: `~^bad\.corp\.test.`}, // needs one char after "test"
			},
		})
		if got := e.Evaluate("bad.corp.test", 443, SchemeHTTPS); got != Deny {
			t.Errorf("Evaluate(bad.corp.test) = %v, want Deny (the dotted sibling must not shadow this entry's regex)", got)
		}
	})
}

// TestEvaluate_RegexEntriesRateLimitsStayDistinct extends the distinctness pin
// to rate-limit buckets: two "~regex" entries differing only by a trailing '.'
// must not share one bucket just because normalisation maps their patterns to
// the same string — otherwise one entry's traffic exhausts the other's budget.
func TestEvaluate_RegexEntriesRateLimitsStayDistinct(t *testing.T) {
	e := NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{
			{Domain: `~^api\.openai\.com.`, RateLimit: "1/minute"},
			{Domain: `~^api\.openai\.com`, RateLimit: "1/minute"},
		},
	})
	const host = "api.openai.comX"
	if got := e.Evaluate(host, 443, SchemeHTTPS); got != Allow {
		t.Fatalf("Evaluate(%s) #1 = %v, want Allow", host, got)
	}
	if got := e.Evaluate(host, 443, SchemeHTTPS); got != Allow {
		t.Errorf("Evaluate(%s) #2 = %v, want Allow (the second entry has its own budget)", host, got)
	}
	if got := e.Evaluate(host, 443, SchemeHTTPS); got != Deny {
		t.Errorf("Evaluate(%s) #3 = %v, want Deny (both budgets of 1 are spent)", host, got)
	}
}

// TestEvaluate_RegexEndingInDotIsMetachar pins policy semantics for a regex
// that ENDS in '.': the raw source is compiled and matched against the
// NORMALISED host, so the trailing dot keeps its "any one char" meaning.
func TestEvaluate_RegexEndingInDotIsMetachar(t *testing.T) {
	e := NewEvaluator(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: `~^api\.openai\.com.`}},
	})
	if got := e.Evaluate("api.openai.comX", 443, SchemeHTTPS); got != Allow {
		t.Errorf("Evaluate(api.openai.comX) = %v, want Allow (the trailing '.' matches one char)", got)
	}
	if got := e.Evaluate("api.openai.com.evil.test...", 443, SchemeHTTPS); got != Allow {
		t.Errorf("Evaluate(api.openai.com.evil.test...) = %v, want Allow", got)
	}
	if got := e.Evaluate("api.openai.com...", 443, SchemeHTTPS); got != NoMatch {
		t.Errorf("Evaluate(api.openai.com...) = %v, want NoMatch (normalised host has no char left for the metachar)", got)
	}
}

// TestMatchDomain_RegexTrailingDotIsMetachar pins the shared matcher dialect
// for a regex that ends in '.': compiled from the RAW source (so the trailing
// dot stays a metacharacter and an escaped '\.' is not left dangling) against
// the NORMALISED host.
func TestMatchDomain_RegexTrailingDotIsMetachar(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{`~^api\.openai\.com.`, "api.openai.comX", true},
		{`~^api\.openai\.com.`, "api.openai.com.evil.test", true},
		{`~^api\.openai\.com.`, "api.openai.com", false},     // nothing left for the metachar
		{`~^api\.openai\.com.`, "api.openai.com....", false}, // normalised host: same
		{`~^x\.`, "x.y", true},                               // escaped dot survives: it is not a DNS trailing dot
		{`~^x\.`, "xy", false},
	}
	for _, c := range cases {
		if got := MatchDomain(c.pattern, c.host); got != c.want {
			t.Errorf("MatchDomain(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}
