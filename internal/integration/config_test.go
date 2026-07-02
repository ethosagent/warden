package integration

import (
	"testing"
)

func TestConfigDecode(t *testing.T) {
	c := Config{Name: "x", Raw: map[string]any{"url": "http://example.com", "n": 3}}
	var dst struct {
		URL string `json:"url"`
		N   int    `json:"n"`
	}
	if err := c.Decode(&dst); err != nil {
		t.Fatalf("Decode error: %v", err)
	}
	if dst.URL != "http://example.com" || dst.N != 3 {
		t.Errorf("decoded = %+v", dst)
	}

	// Decode into a non-pointer fails.
	if err := c.Decode(struct{}{}); err == nil {
		t.Error("Decode into non-pointer should error")
	}
}

func alertWith(sev Severity, category, domain, dedupKey string) Alert {
	return Alert{
		Severity: sev,
		Category: category,
		Subject:  Subject{Domain: domain},
		DedupKey: dedupKey,
	}
}

func TestMatchClauseANDKeys(t *testing.T) {
	a := alertWith(SevHigh, "security", "api.foo.com", "error_rate:api.foo.com")

	// All keys match ⇒ true.
	if !(MatchClause{Severity: "high", Category: "security", Domain: "api.foo.com", Rule: "error_rate"}).matches(a) {
		t.Error("all-keys-match clause should match")
	}
	// One key mismatches ⇒ false (AND).
	if (MatchClause{Severity: "high", Category: "cost"}).matches(a) {
		t.Error("clause with mismatched category should not match")
	}
	if (MatchClause{Domain: "other.com"}).matches(a) {
		t.Error("clause with mismatched domain should not match")
	}
	if (MatchClause{Rule: "auth_fail"}).matches(a) {
		t.Error("clause with mismatched rule should not match")
	}
	// Case-insensitivity for severity/category.
	if !(MatchClause{Severity: "HIGH", Category: "Security"}).matches(a) {
		t.Error("severity/category match should be case-insensitive")
	}
}

func TestMatchClauseEmptyMatchesNothing(t *testing.T) {
	a := alertWith(SevHigh, "security", "api.foo.com", "error_rate:x")
	if (MatchClause{}).matches(a) {
		t.Error("all-empty clause must match NOTHING (default-deny), not everything")
	}
}

func TestMatchAnyOR(t *testing.T) {
	a := alertWith(SevHigh, "security", "api.foo.com", "error_rate:x")

	// Empty list ⇒ match-none.
	if matchAny(nil, a) {
		t.Error("empty clause list must be match-none")
	}

	// OR across entries: second entry matches.
	clauses := []MatchClause{
		{Severity: "low"},      // no
		{Category: "security"}, // yes
	}
	if !matchAny(clauses, a) {
		t.Error("matchAny should be true when any entry matches")
	}

	// None match.
	if matchAny([]MatchClause{{Severity: "low"}, {Domain: "no.com"}}, a) {
		t.Error("matchAny should be false when no entry matches")
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("WARDEN_TEST_WEBHOOK", "https://hooks.example.com/abc")
	if got := expandEnv("${WARDEN_TEST_WEBHOOK}"); got != "https://hooks.example.com/abc" {
		t.Errorf("expandEnv = %q", got)
	}
	// Unset expands to empty (best-effort, no hard-fail).
	if got := expandEnv("${WARDEN_TEST_UNSET_XYZ}"); got != "" {
		t.Errorf("unset var should expand to empty, got %q", got)
	}
	// Plain value passes through.
	if got := expandEnv("plain"); got != "plain" {
		t.Errorf("plain value changed: %q", got)
	}
}
