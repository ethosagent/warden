package policy

import "testing"

func TestHostMatcher(t *testing.T) {
	m, err := NewHostMatcher([]string{"github.com", "*.githubusercontent.com", `~^api\d+\.llm\.example\.com$`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"github.com":                  true,
		"GitHub.com.":                 true,
		"raw.githubusercontent.com":   true,
		"githubusercontent.com":       false,
		"evil-github.com":             false,
		"api2.llm.example.com":        true,
		"api2.llm.example.com.evil.x": false,
		"other.test":                  false,
	}
	for host, want := range cases {
		if got := m.Matches(host); got != want {
			t.Errorf("Matches(%q) = %v, want %v", host, got, want)
		}
	}
	var nilM *HostMatcher
	if nilM.Matches("github.com") {
		t.Error("nil matcher must match nothing")
	}
	if _, err := NewHostMatcher([]string{"~("}); err == nil {
		t.Error("expected error for invalid regex")
	}
}

// TestHostMatcher_RegexTrailingDotIsMetachar pins #397 for a regex that ends in
// '.': it is compiled from the RAW source — the trailing dot stays the "any one
// char" metacharacter, and an escaped '\.' is not left dangling — and matched
// against the NORMALISED host. Normalising the pattern compiled a different
// regex (or none at all: '~^x\.' became the invalid '~^x\').
func TestHostMatcher_RegexTrailingDotIsMetachar(t *testing.T) {
	m, err := NewHostMatcher([]string{`~^api\.openai\.com.`, `~^x\.`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"api.openai.comX":          true,
		"api.openai.com.evil.test": true,
		"api.openai.com":           false, // nothing left for the metachar
		"api.openai.com....":       false,
		"x.y":                      true, // escaped dot survived
		"xy":                       false,
	}
	for host, want := range cases {
		if got := m.Matches(host); got != want {
			t.Errorf("Matches(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestHostMatcher_TrailingDots pins #397 for secret-scoping (#373): a scoped
// placeholder still swaps on its intended host no matter how many trailing
// dots the CONNECT host carried, and a dots-only host never matches.
func TestHostMatcher_TrailingDots(t *testing.T) {
	m, err := NewHostMatcher([]string{"github.com", "*.githubusercontent.com", `~^api\d+\.llm\.example\.com$`})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"github.com....":               true,
		"GitHub.COM..":                 true,
		"raw.githubusercontent.com...": true,
		"api1.llm.example.com.....":    true,
		"evil-github.com...":           false,
		"github.com.evil.test...":      false,
		"...":                          false,
		"":                             false,
	}
	for host, want := range cases {
		if got := m.Matches(host); got != want {
			t.Errorf("Matches(%q) = %v, want %v", host, got, want)
		}
	}
}
