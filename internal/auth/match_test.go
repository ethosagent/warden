package auth

import "testing"

// TestMatchedTransformer_TrailingDots pins #397 for auth match entries: a
// credential is injected for its intended host regardless of how many trailing
// dots the CONNECT host carried, and a dots-only host never matches. A missed
// match here silently forwards the request WITHOUT its credential.
func TestMatchedTransformer_TrailingDots(t *testing.T) {
	exact, err := NewMatchedTransformer("api.stripe.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := NewMatchedTransformer("*.stripe.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	regex, err := NewMatchedTransformer(`~^api\d+\.stripe\.com$`, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		m    *MatchedTransformer
		host string
		want bool
	}{
		{exact, "api.stripe.com", true},
		{exact, "api.stripe.com.", true},
		{exact, "api.stripe.com...", true},
		{exact, "API.STRIPE.COM....", true},
		{exact, "api.stripe.com.evil.test...", false},
		{wildcard, "pay.stripe.com.....", true},
		{wildcard, "stripe.com...", false}, // apex stays unmatched
		{regex, "api1.stripe.com....", true},
		{exact, "", false},
		{exact, "...", false},
		{wildcard, "...", false},
		{regex, "...", false},
	}
	for _, c := range cases {
		if got := c.m.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestMatchedTransformer_NormalisedPattern pins the PATTERN side of #397: the
// configured pattern is normalised exactly like the host, so an entry written
// "API.Stripe.com.." still injects its credential for api.stripe.com. A missed
// match here silently forwards the request WITHOUT its credential.
func TestMatchedTransformer_NormalisedPattern(t *testing.T) {
	exact, err := NewMatchedTransformer("API.Stripe.com..", nil)
	if err != nil {
		t.Fatal(err)
	}
	wildcard, err := NewMatchedTransformer("*.STRIPE.com.", nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		m    *MatchedTransformer
		host string
		want bool
	}{
		{exact, "api.stripe.com", true},
		{exact, "api.stripe.com...", true},
		{exact, "API.STRIPE.COM", true},
		{exact, "api.stripe.com.evil.test", false},
		{wildcard, "pay.stripe.com", true},
		{wildcard, "pay.stripe.com...", true},
		{wildcard, "stripe.com", false}, // apex stays unmatched
	}
	for _, c := range cases {
		if got := c.m.Matches(c.host); got != c.want {
			t.Errorf("Matches(pattern %q, host %q) = %v, want %v", c.m.Pattern, c.host, got, c.want)
		}
	}
}

// TestMatchedTransformer_RegexTrailingDotIsMetachar pins the regex dialect of
// #397 for auth: a "~regex" pattern is compiled and matched VERBATIM — a
// trailing '.' keeps its "any one char" meaning and is never trimmed as a DNS
// trailing dot — while the host side is still normalised before the match.
func TestMatchedTransformer_RegexTrailingDotIsMetachar(t *testing.T) {
	dotted, err := NewMatchedTransformer(`~^api\.stripe\.com.`, nil)
	if err != nil {
		t.Fatal(err)
	}
	escaped, err := NewMatchedTransformer(`~^api\d+\.stripe\.com\.`, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		m    *MatchedTransformer
		host string
		want bool
	}{
		{dotted, "api.stripe.com2", true},            // the trailing '.' matches one char
		{dotted, "api.stripe.com.evil.test", true},   // ...including a dot
		{dotted, "api.stripe.com", false},            // no char left for the metachar
		{dotted, "api.stripe.com....", false},        // host normalised: same
		{escaped, "api1.stripe.com.evil.test", true}, // escaped dot: compiles raw, matches the next label's dot
		{escaped, "api1.stripe.com", false},
	}
	for _, c := range cases {
		if got := c.m.Matches(c.host); got != c.want {
			t.Errorf("Matches(pattern %q, host %q) = %v, want %v", c.m.Pattern, c.host, got, c.want)
		}
	}
}
