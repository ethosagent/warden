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
