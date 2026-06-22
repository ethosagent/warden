package policy

import (
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

func evalFor(entries ...config.AllowlistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: entries})
}

func evalWithDenylist(allow []config.AllowlistEntry, deny []config.DenylistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: allow, Denylist: deny})
}

// Invariant: default-deny — a non-allowlisted destination is blocked.
func TestEvaluate_DefaultDeny(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "api.openai.com"})
	if d := e.Evaluate("evil.example.com", 443, SchemeHTTPS); d != Deny {
		t.Fatalf("non-allowlisted host = %v, want Deny", d)
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
	if d := e.Evaluate("api.openai.com", 8443, SchemeHTTPS); d != Deny {
		t.Errorf("port 8443 against inferred-443 entry = %v, want Deny", d)
	}
}

func TestEvaluate_PortInferenceHTTP(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "plain.example.com"}) // no port → 80 under HTTP
	if d := e.Evaluate("plain.example.com", 80, SchemeHTTP); d != Allow {
		t.Errorf("inferred 80 = %v, want Allow", d)
	}
	if d := e.Evaluate("plain.example.com", 443, SchemeHTTP); d != Deny {
		t.Errorf("443 against inferred-80 entry = %v, want Deny", d)
	}
}

func TestEvaluate_ExplicitPort(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "svc.internal", Port: 8443})
	if d := e.Evaluate("svc.internal", 8443, SchemeHTTPS); d != Allow {
		t.Errorf("explicit port match = %v, want Allow", d)
	}
	if d := e.Evaluate("svc.internal", 443, SchemeHTTPS); d != Deny {
		t.Errorf("wrong port = %v, want Deny", d)
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
	if d := e.Evaluate("internal.company.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("apex against wildcard = %v, want Deny", d)
	}
}

func TestEvaluate_CaseInsensitiveAndTrailingDot(t *testing.T) {
	e := evalFor(config.AllowlistEntry{Domain: "API.OpenAI.com"})
	if d := e.Evaluate("api.openai.com.", 443, SchemeHTTPS); d != Allow {
		t.Errorf("case/trailing-dot normalization = %v, want Allow", d)
	}
}

func TestDecisionString(t *testing.T) {
	if Allow.String() != "allow" || Deny.String() != "deny" {
		t.Errorf("decision strings: %q / %q", Allow.String(), Deny.String())
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
	if d := e.Evaluate("api.evil.com", 443, SchemeHTTPS); d != Deny {
		t.Errorf("regex no match = %v, want Deny", d)
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
