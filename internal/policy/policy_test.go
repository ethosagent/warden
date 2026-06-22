package policy

import (
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

func evalFor(entries ...config.AllowlistEntry) *Evaluator {
	return NewEvaluator(config.Policy{Allowlist: entries})
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
