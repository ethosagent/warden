package config

import "testing"

func TestParse_DLPWardenTokens(t *testing.T) {
	const base = "policy:\n  allowlist:\n    - domain: api.openai.com\n"
	for name, tc := range map[string]struct {
		yaml string
		want bool
	}{
		"absent block": {base, false},
		"absent key":   {base + "dlp:\n  mode: monitor\n", false},
		"explicit off": {base + "dlp:\n  mode: monitor\n  wardenTokens: false\n", false},
		"explicit on":  {base + "dlp:\n  mode: enforce\n  wardenTokens: true\n", true},
	} {
		p, err := parse([]byte(tc.yaml))
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		pol, _ := p.GetPolicy()
		if pol.DLP.WardenTokens != tc.want {
			t.Errorf("%s: WardenTokens = %v, want %v", name, pol.DLP.WardenTokens, tc.want)
		}
	}
}

func TestParse_DLPWardenTokensNotABool(t *testing.T) {
	const y = "policy:\n  allowlist:\n    - domain: api.openai.com\ndlp:\n  mode: monitor\n  wardenTokens: maybe\n"
	if _, err := parse([]byte(y)); err == nil {
		t.Fatal("a non-boolean dlp.wardenTokens must fail to parse")
	}
}
