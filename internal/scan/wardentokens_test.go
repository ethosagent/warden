package scan

import (
	"strings"
	"testing"
)

// Synthetic, shape-correct values (not minted credentials): the all-"a" secret is
// valid lowercase base32 of the right length.
var (
	testWAK = "wak_0123456789abcdef_" + strings.Repeat("a", 52)
	testWWT = "wwt_" + strings.Repeat("b", 52)
)

func wardenPatternNames(dets []Detection) map[string]Detection {
	out := map[string]Detection{}
	for _, d := range dets {
		if d.Pattern == "warden_api_key" || d.Pattern == "warden_worker_token" {
			out[d.Pattern] = d
		}
	}
	return out
}

func TestWardenTokenPatterns(t *testing.T) {
	body := []byte(`{"k":"` + testWAK + `","w":"` + testWWT + `"}`)

	on := NewScanner(WithWardenTokens(true), WithEvidence(true)).ScanResponse(body)
	got := wardenPatternNames(on)
	for _, name := range []string{"warden_api_key", "warden_worker_token"} {
		d, ok := got[name]
		if !ok {
			t.Fatalf("%s not detected with WithWardenTokens(true): %+v", name, on)
		}
		if d.Category != "credential_leak" || d.Severity != "high" {
			t.Errorf("%s = %s/%s, want credential_leak/high", name, d.Category, d.Severity)
		}
		if len(d.Classes) != 1 || d.Classes[0] != ClassCredentials {
			t.Errorf("%s classes = %v, want [credentials]", name, d.Classes)
		}
		if strings.Contains(d.Evidence, "0123456789abcdef") || strings.Contains(d.Evidence, strings.Repeat("a", 20)) || strings.Contains(d.Evidence, strings.Repeat("b", 20)) {
			t.Errorf("%s evidence is not masked: %q", name, d.Evidence)
		}
		if !strings.Contains(d.Evidence, "(len ") {
			t.Errorf("%s evidence = %q, want a masked sample", name, d.Evidence)
		}
	}

	for name, s := range map[string]Scanner{
		"default":  NewScanner(),
		"explicit": NewScanner(WithWardenTokens(false)),
	} {
		if off := wardenPatternNames(s.ScanResponse(body)); len(off) != 0 {
			t.Errorf("%s scanner detected Warden tokens: %+v", name, off)
		}
	}
}

func TestWardenTokenPatterns_NearMisses(t *testing.T) {
	s := NewScanner(WithWardenTokens(true))
	secret := strings.Repeat("a", 52)
	for name, v := range map[string]string{
		"wak short secret":    "wak_0123456789abcdef_" + secret[:51],
		"wak short id":        "wak_0123456789abcde_" + secret,
		"wak uppercase id":    "wak_0123456789ABCDEF_" + secret,
		"wak uppercase body":  "wak_0123456789abcdef_" + strings.Repeat("A", 52),
		"wak digit 1 in body": "wak_0123456789abcdef_" + strings.Repeat("1", 52),
		"wak no separator":    "wak_0123456789abcdef" + secret,
		"wwt short":           "wwt_" + secret[:51],
		"wwt uppercase":       "wwt_" + strings.Repeat("B", 52),
		"wwt digit 8":         "wwt_" + strings.Repeat("8", 52),
		"wwt wrong prefix":    "wxt_" + secret,
	} {
		if got := wardenPatternNames(s.ScanResponse([]byte(v))); len(got) != 0 {
			t.Errorf("%s: matched %v", name, got)
		}
	}
}

// Appending or prepending characters must not evade detection: the patterns are
// unanchored on purpose, so a longer run still flags on its valid prefix.
func TestWardenTokenPatterns_LongerStillFlags(t *testing.T) {
	s := NewScanner(WithWardenTokens(true))
	for name, tc := range map[string]struct{ v, pattern string }{
		"wak 53 chars": {testWAK + "a", "warden_api_key"},
		"wwt 53 chars": {testWWT + "b", "warden_worker_token"},
		"xwak prefix":  {"x" + testWAK, "warden_api_key"},
		"xwwt prefix":  {"x" + testWWT, "warden_worker_token"},
	} {
		if _, ok := wardenPatternNames(s.ScanResponse([]byte(tc.v)))[tc.pattern]; !ok {
			t.Errorf("%s: %s not flagged", name, tc.pattern)
		}
	}
}
