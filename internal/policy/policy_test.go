package policy

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
)

func evalFor(entries ...config.AllowlistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: entries})
}

func evalWithDenylist(allow []config.AllowlistEntry, deny []config.DenylistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: allow, Denylist: deny})
}

// Invariant: default-deny — a non-allowlisted destination does not match. It
// returns NoMatch (not Allow), so callers comparing against Allow still block.
func TestEvaluate_DefaultDeny(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.openai.com"})
	if d := e.Evaluate("evil.example.com", 443, SchemeHTTPS); d != NoMatch {
		t.Fatalf("non-allowlisted host = %v, want NoMatch", d)
	}
}

func TestEvaluate_Allow(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.openai.com"})
	if d := e.Evaluate("api.openai.com", 443, SchemeHTTPS); d != Allow {
		t.Fatalf("allowlisted host = %v, want Allow", d)
	}
}

func TestEvaluate_PortInferenceHTTPS(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.openai.com"}) // no port → 443
	if d := e.Evaluate("api.openai.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("inferred 443 = %v, want Allow", d)
	}
	if d := e.Evaluate("api.openai.com", 8443, SchemeHTTPS); d != NoMatch {
		t.Errorf("port 8443 against inferred-443 entry = %v, want NoMatch", d)
	}
}

func TestEvaluate_PortInferenceHTTP(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "plain.example.com"}) // no port → 80 under HTTP
	if d := e.Evaluate("plain.example.com", 80, SchemeHTTP); d != Allow {
		t.Errorf("inferred 80 = %v, want Allow", d)
	}
	if d := e.Evaluate("plain.example.com", 443, SchemeHTTP); d != NoMatch {
		t.Errorf("443 against inferred-80 entry = %v, want NoMatch", d)
	}
}

func TestEvaluate_ExplicitPort(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "svc.internal", Port: 8443})
	if d := e.Evaluate("svc.internal", 8443, SchemeHTTPS); d != Allow {
		t.Errorf("explicit port match = %v, want Allow", d)
	}
	if d := e.Evaluate("svc.internal", 443, SchemeHTTPS); d != NoMatch {
		t.Errorf("wrong port = %v, want NoMatch", d)
	}
}

func TestEvaluate_Wildcard(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "*.internal.company.com"})
	if d := e.Evaluate("api.internal.company.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("wildcard subdomain = %v, want Allow", d)
	}
	if d := e.Evaluate("a.b.internal.company.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("wildcard nested subdomain = %v, want Allow", d)
	}
	// Apex must not match a "*." wildcard.
	if d := e.Evaluate("internal.company.com", 443, SchemeHTTPS); d != NoMatch {
		t.Errorf("apex against wildcard = %v, want NoMatch", d)
	}
}

func TestEvaluate_CaseInsensitiveAndTrailingDot(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "API.OpenAI.com"})
	if d := e.Evaluate("api.openai.com.", 443, SchemeHTTPS); d != Allow {
		t.Errorf("case/trailing-dot normalization = %v, want Allow", d)
	}
}

func TestDecisionString(t *testing.T) {
	if Allow.String() != "allow" || Deny.String() != "deny" || NoMatch.String() != "no-match" {
		t.Errorf("decision strings: %q / %q / %q", Allow.String(), Deny.String(), NoMatch.String())
	}
}

func TestEvaluate_RegexDomain(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "~^api\\.(openai|anthropic)\\.com$"})
	if d := e.Evaluate("api.openai.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("regex match openai = %v, want Allow", d)
	}
	if d := e.Evaluate("api.anthropic.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("regex match anthropic = %v, want Allow", d)
	}
	if d := e.Evaluate("api.evil.com", 443, SchemeHTTPS); d != NoMatch {
		t.Errorf("regex no match = %v, want NoMatch", d)
	}
}

func TestEvaluate_RateLimit_UnderLimit(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.example.com", RateLimit: "2/minute"})
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("request 1 = %v, want Allow", d)
	}
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("request 2 = %v, want Allow", d)
	}
}

func TestEvaluate_RateLimit_OverLimit(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.example.com", RateLimit: "2/minute"})
	e.Evaluate("api.example.com", 443, SchemeHTTPS)
	e.Evaluate("api.example.com", 443, SchemeHTTPS)
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("request 3 over limit = %v, want Deny", d)
	}
}

func TestEvaluate_RateLimit_WindowReset(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.example.com", RateLimit: "1/minute"})
	baseTime := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return baseTime }

	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("request 1 = %v, want Allow", d)
	}
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("request 2 within window = %v, want Deny", d)
	}

	// Advance past the 1-minute window.
	e.now = func() time.Time { return baseTime.Add(2 * time.Minute) }
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("request after window reset = %v, want Allow", d)
	}
}

func TestEvaluate_TimeWindow_Inside(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.example.com", TimeWindow: "9-17"})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("inside window (hour 10) = %v, want Allow", d)
	}
}

func TestEvaluate_TimeWindow_Outside(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.example.com", TimeWindow: "9-17"})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) }
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("outside window (hour 20) = %v, want Deny", d)
	}
}

func TestEvaluate_Denylist_BlocksEvenIfAllowlisted(t *testing.T) {
	e := evalWithDenylist(
		[]config.AllowlistEntry{{Domain: "evil.example.com"}},
		[]config.DenylistEntry{{Domain: "evil.example.com"}},
	)
	if d := e.Evaluate("evil.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("denylist precedence = %v, want Deny", d)
	}
}

func TestEvaluate_Denylist_Wildcard(t *testing.T) {
	e := evalWithDenylist(
		[]config.AllowlistEntry{{Domain: "*.malware.net"}},
		[]config.DenylistEntry{{Domain: "*.malware.net"}},
	)
	if d := e.Evaluate("x.malware.net", 443, SchemeHTTPS); d != Deny {
		t.Errorf("wildcard denylist = %v, want Deny", d)
	}
}

func TestEvaluate_Denylist_Regex(t *testing.T) {
	e := evalWithDenylist(
		[]config.AllowlistEntry{{Domain: "~^.*\\.example\\.com$"}},
		[]config.DenylistEntry{{Domain: "~^evil\\.example\\.com$"}},
	)
	if d := e.Evaluate("evil.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("regex denylist = %v, want Deny", d)
	}
	if d := e.Evaluate("good.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("regex allowlist = %v, want Allow", d)
	}
}

func TestEvaluate_Combined_AllowRateLimitTimeWindow(t *testing.T) {
	e := evalFor(config.AllowlistEntry{
		Domain:     "api.example.com",
		RateLimit:  "1/hour",
		TimeWindow: "9-17",
	})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }

	// Inside window, under rate limit.
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("inside window + under limit = %v, want Allow", d)
	}
	// Inside window, over rate limit.
	if d := e.Evaluate("api.example.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("inside window + over limit = %v, want Deny", d)
	}
}

// --- Per-request method/path constraints (#371) ---

func reqEvalFor(entries ...config.AllowlistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: entries})
}

// Entries without methods/paths keep today's behaviour for every request.
func TestEvaluateRequest_UnconstrainedEntryAnyMethodPath(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com"})
	for _, m := range []string{"GET", "POST", "DELETE", "PATCH"} {
		if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, m, "/anything"); v.Decision != Allow {
			t.Errorf("%s /anything = %v, want Allow", m, v.Decision)
		}
	}
}

func TestEvaluateRequest_MethodConstraint(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "github.com", Methods: []string{"GET", "HEAD"}})
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "GET", "/x"); v.Decision != Allow {
		t.Errorf("GET = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "HEAD", "/x"); v.Decision != Allow {
		t.Errorf("HEAD = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "POST", "/x"); v.Decision != Deny {
		t.Errorf("POST = %v, want Deny", v.Decision)
	} else if v.Reason != denyreason.MethodNotAllowed {
		t.Errorf("POST reason = %q, want %q", v.Reason, denyreason.MethodNotAllowed)
	}
	// HTTP methods are case-sensitive: the match is against the method as sent.
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "get", "/x"); v.Decision != Deny {
		t.Errorf("lowercase get = %v, want Deny (case-sensitive match)", v.Decision)
	}
}

func TestEvaluateRequest_PathConstraints(t *testing.T) {
	cases := []struct {
		name    string
		paths   []string
		path    string
		want    Decision
		wantRea denyreason.Reason
	}{
		{"trailing star matches the path itself", []string{"/acme/app/*"}, "/acme/app", Allow, ""},
		{"trailing star matches under", []string{"/acme/app/*"}, "/acme/app/x/y", Allow, ""},
		{"trailing star segment-aligned", []string{"/acme/app/*"}, "/acme/appx", Deny, denyreason.PathNotAllowed},
		{"second pattern matches", []string{"/acme/app/*", "/acme/app.git/*"}, "/acme/app.git/info/refs", Allow, ""},
		{"outside every pattern", []string{"/acme/app/*", "/acme/app.git/*"}, "/acme/evil/x", Deny, denyreason.PathNotAllowed},
		{"exact path", []string{"/v1/chat"}, "/v1/chat", Allow, ""},
		{"exact path no extension", []string{"/v1/chat"}, "/v1/chatted", Deny, denyreason.PathNotAllowed},
		{"segment star", []string{"/acme/*/x"}, "/acme/foo/x", Allow, ""},
		{"segment star one segment only", []string{"/acme/*/x"}, "/acme/a/b/x", Deny, denyreason.PathNotAllowed},
		{"case-sensitive", []string{"/v1/Chat"}, "/v1/chat", Deny, denyreason.PathNotAllowed},
		{"root pattern", []string{"/"}, "/", Allow, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := reqEvalFor(config.AllowlistEntry{Domain: "github.com", Paths: c.paths})
			v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "GET", c.path)
			if v.Decision != c.want {
				t.Fatalf("path %q = %v, want %v", c.path, v.Decision, c.want)
			}
			if v.Reason != c.wantRea {
				t.Fatalf("path %q reason = %q, want %q", c.path, v.Reason, c.wantRea)
			}
		})
	}
}

// A path-confused raw path must be denied whenever the destination has ANY
// paths-constrained entry — even when another entry for the same host would
// have allowed the string (any-match-wins must not leak a normalisation trick).
func TestEvaluateRequest_NonCanonicalPathDenied(t *testing.T) {
	e := reqEvalFor(
		config.AllowlistEntry{Domain: "github.com", Methods: []string{"POST"}, Paths: []string{"/acme/app/*"}},
		config.AllowlistEntry{Domain: "github.com"},
	)
	for _, p := range []string{
		"/acme/app/../evil/x",
		"/acme/%2e%2e/evil",
		"/acme/app%2f../evil",
		"/acme//app",
		"/acme/app\\..\\x",
		// Matrix parameters: Java servers (Tomcat, Jetty, Spring) strip
		// ";params" per segment, so "/v1/..;/admin" reaches them as
		// "/v1/../admin" — traversal through a matching string (#371 review).
		"/v1/..;/admin",
		"/v1/.;/admin",
		"/v1/some;x",
		"/v1/..%3b/y",
		"/v1/x%3B",
	} {
		if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "GET", p); v.Decision != Deny || v.Reason != denyreason.PathNotCanonical {
			t.Errorf("path %q = %v/%q, want Deny/%s", p, v.Decision, v.Reason, denyreason.PathNotCanonical)
		}
	}
}

// Hosts with no paths-constrained entry keep plain string semantics: a
// non-canonical path is NOT a policy concern there (nothing to confuse).
func TestEvaluateRequest_NonCanonicalPathUnconstrainedHost(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "github.com"})
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "GET", "/a/../b"); v.Decision != Allow {
		t.Errorf("unconstrained host = %v, want Allow", v.Decision)
	}
	// ...and the same non-canonical path on a DIFFERENT host than the
	// constrained entry is unaffected by it.
	e2 := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com", Paths: []string{"/v1/*"}})
	if v := e2.EvaluateRequest("other.example.com", 443, SchemeHTTPS, "GET", "/a/../b"); v.Decision != NoMatch {
		t.Errorf("unrelated host = %v, want NoMatch", v.Decision)
	}
}

// Any-match-wins: a request is allowed when ANY entry's own constraints are
// satisfied. The documented sharp edge: an unconstrained entry for the same
// domain makes a constrained entry useless.
func TestEvaluateRequest_AnyMatchWins(t *testing.T) {
	e := reqEvalFor(
		config.AllowlistEntry{Domain: "github.com", Methods: []string{"GET", "HEAD"}},
		config.AllowlistEntry{Domain: "github.com", Methods: []string{"POST", "PATCH", "PUT", "DELETE"}, Paths: []string{"/acme/app/*", "/acme/app.git/*"}},
	)
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "GET", "/anything"); v.Decision != Allow {
		t.Errorf("read anywhere = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "POST", "/acme/app/pulls"); v.Decision != Allow {
		t.Errorf("write under app = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "POST", "/acme/other"); v.Decision != Deny {
		t.Errorf("write outside app = %v, want Deny", v.Decision)
	}

	// Sharp edge: an unconstrained twin swallows the constrained entry.
	sharp := reqEvalFor(
		config.AllowlistEntry{Domain: "github.com", Methods: []string{"POST"}, Paths: []string{"/acme/app/*"}},
		config.AllowlistEntry{Domain: "github.com"},
	)
	if v := sharp.EvaluateRequest("github.com", 443, SchemeHTTPS, "POST", "/anywhere"); v.Decision != Allow {
		t.Errorf("unconstrained twin = %v, want Allow (documented sharp edge)", v.Decision)
	}
}

// A request that matched a destination but violated its constraints is an
// explicit Deny, never NoMatch — it must not become judge-eligible.
func TestEvaluateRequest_ConstraintViolationNotNoMatch(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "github.com", Methods: []string{"GET"}})
	if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "DELETE", "/x"); v.Decision != Deny {
		t.Errorf("DELETE = %v, want Deny (not NoMatch)", v.Decision)
	}
}

// The destination-only form (CONNECT gate) keeps could-match semantics: it
// ignores method/path constraints and PEEKS at the rate limit without
// consuming a slot — the authoritative count happens per request.
func TestEvaluateRequest_DestinationOnlyCouldMatch(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "github.com", Methods: []string{"GET"}, Paths: []string{"/v1/*"}})
	for i := 0; i < 3; i++ {
		if v := e.EvaluateRequest("github.com", 443, SchemeHTTPS, "", ""); v.Decision != Allow {
			t.Fatalf("CONNECT-time evaluation %d = %v, want Allow", i, v.Decision)
		}
	}
}

// The CONNECT gate's rate-limit PEEK must not consume budget: N destination-only
// admissions (method == "") leave the first real request's budget intact, and
// only real requests count against the window. Guards `count := true` for the
// connect mode, which would make tunnel admissions silently eat a rule's limit.
func TestEvaluateRequest_ConnectPeekDoesNotConsumeRateLimit(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "api.example.com", RateLimit: "1/minute"})
	base := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return base }

	for i := 0; i < 3; i++ {
		if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "", ""); v.Decision != Allow {
			t.Fatalf("CONNECT admission %d = %v, want Allow", i, v.Decision)
		}
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/a"); v.Decision != Allow {
		t.Fatalf("first request after 3 CONNECT admissions = %v, want Allow", v.Decision)
	}
	// Exactly one slot was consumed — by the real request, not the admissions.
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/b"); v.Decision != Deny {
		t.Fatalf("second request = %v, want Deny (1/minute exhausted)", v.Decision)
	}
}

// A rule's rate limit counts only requests that match the rule's own
// method/path constraints (#371 owner decision).
func TestEvaluateRequest_RateLimitCountsOnlyMatchingRequests(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{
		Domain:    "api.example.com",
		Methods:   []string{"POST"},
		Paths:     []string{"/v1/*"},
		RateLimit: "2/minute",
	})
	base := time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return base }

	// Denied-by-constraint requests must not consume budget.
	for i := 0; i < 5; i++ {
		if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/x"); v.Decision != Deny {
			t.Fatalf("GET %d = %v, want Deny", i, v.Decision)
		}
		if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "POST", "/other"); v.Decision != Deny {
			t.Fatalf("POST /other %d = %v, want Deny", i, v.Decision)
		}
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "POST", "/v1/a"); v.Decision != Allow {
		t.Fatalf("matching POST 1 = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "POST", "/v1/b"); v.Decision != Allow {
		t.Fatalf("matching POST 2 = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "POST", "/v1/c"); v.Decision != Deny {
		t.Fatalf("matching POST 3 = %v, want Deny (rate limit)", v.Decision)
	}
}

// Constraints, rate limit and time window compose on one entry.
func TestEvaluateRequest_ConstraintsWithRateLimitAndTimeWindow(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{
		Domain:     "api.example.com",
		Methods:    []string{"GET"},
		Paths:      []string{"/v1/*"},
		RateLimit:  "1/hour",
		TimeWindow: "9-17",
	})
	e.now = func() time.Time { return time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC) }

	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/a"); v.Decision != Allow {
		t.Errorf("in window, under limit = %v, want Allow", v.Decision)
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/b"); v.Decision != Deny {
		t.Errorf("in window, over limit = %v, want Deny", v.Decision)
	}
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "POST", "/v1/a"); v.Decision != Deny {
		t.Errorf("disallowed method = %v, want Deny", v.Decision)
	}
	// Outside the window even a constraint-satisfying request is denied — and
	// it must not consume rate-limit budget either.
	e.now = func() time.Time { return time.Date(2024, 1, 1, 20, 0, 0, 0, time.UTC) }
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/c"); v.Decision != Deny {
		t.Errorf("outside window = %v, want Deny", v.Decision)
	}
	e.now = func() time.Time { return time.Date(2024, 1, 2, 9, 0, 0, 0, time.UTC) }
	if v := e.EvaluateRequest("api.example.com", 443, SchemeHTTPS, "GET", "/v1/d"); v.Decision != Allow {
		t.Errorf("next window = %v, want Allow (denied request did not consume budget)", v.Decision)
	}
}

// The legacy destination-only Evaluate is unchanged by #371: constraints are
// could-match and the rate limit still counts (tunnel-level) — the exact
// behaviour the existing tests above pin.
func TestEvaluate_MethodConstraintStillCouldMatch(t *testing.T) {
	e := reqEvalFor(config.AllowlistEntry{Domain: "github.com", Methods: []string{"GET"}})
	if d := e.Evaluate("github.com", 443, SchemeHTTPS); d != Allow {
		t.Errorf("Evaluate = %v, want Allow (constraints could-match)", d)
	}
}
