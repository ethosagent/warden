package approvals

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

func allow(domain string, port int) config.AllowlistEntry {
	return config.AllowlistEntry{Domain: domain, Port: port}
}

func scopedAllow(domain string, groups, users []string) config.AllowlistEntry {
	e := allow(domain, 443)
	e.Groups, e.Users = groups, users
	return e
}

func withRate(e config.AllowlistEntry, rl string) config.AllowlistEntry { e.RateLimit = rl; return e }
func withTime(e config.AllowlistEntry, tw string) config.AllowlistEntry { e.TimeWindow = tw; return e }

func docA(es ...config.AllowlistEntry) Doc { return Doc{Allowlist: es} }

func toggle(on bool) *config.ToggleSetting { return &config.ToggleSetting{Enabled: on} }

func codes(c Classification) []string {
	var out []string
	for _, r := range c.Reasons {
		out = append(out, r.Code)
	}
	return out
}

func TestClassifyWidening(t *testing.T) {
	base := func(es ...config.AllowlistEntry) Doc { return docA(es...) }
	tests := []struct {
		name        string
		base, draft Doc
		code        string
		path        string // expected reason path ("" = not checked)
		role        config.Role
	}{
		{"allow entry added", base(allow("a.com", 443)), base(allow("a.com", 443), allow("b.com", 443)), CodeAllowAdded, "allowlist:b.com:443", config.RoleEditor},
		{"exact replaced by wildcard", base(allow("a.com", 443)), base(allow("*.a.com", 443)), CodeAllowAdded, "allowlist:*.a.com:443", config.RoleEditor},
		{"regex changed", base(allow("~^a\\.com$", 443)), base(allow("~^.*\\.com$", 443)), CodeAllowAdded, "", config.RoleEditor},
		{"port changed", base(allow("a.com", 443)), base(allow("a.com", 8443)), CodeAllowAdded, "allowlist:a.com:8443", config.RoleEditor},
		{"deny removed", Doc{Denylist: []config.DenylistEntry{{Domain: "x.com", Port: 443}}}, Doc{}, CodeDenyRemoved, "denylist:x.com:443", config.RoleEditor},
		{"deny changed", Doc{Denylist: []config.DenylistEntry{{Domain: "x.com", Port: 443}}}, Doc{Denylist: []config.DenylistEntry{{Domain: "x.com", Port: 80}}}, CodeDenyRemoved, "denylist:x.com:443", config.RoleEditor},
		{"groups removed from scoped entry", base(scopedAllow("a.com", []string{"eng"}, nil)), base(allow("a.com", 443)), CodeAllowScopeWide, "allowlist:a.com:443", config.RoleEditor},
		{"scoped to other group", base(scopedAllow("a.com", []string{"eng"}, nil)), base(scopedAllow("a.com", []string{"eng", "ops"}, nil)), CodeAllowScopeWide, "", config.RoleEditor},
		{"scope switches to users", base(scopedAllow("a.com", []string{"eng"}, nil)), base(scopedAllow("a.com", nil, []string{"x@y.com"})), CodeAllowScopeWide, "", config.RoleEditor},
		{"rateLimit raised", base(withRate(allow("a.com", 443), "10/minute")), base(withRate(allow("a.com", 443), "20/minute")), CodeAllowRateRelaxed, "", config.RoleEditor},
		{"rateLimit removed", base(withRate(allow("a.com", 443), "10/minute")), base(allow("a.com", 443)), CodeAllowRateRelaxed, "", config.RoleEditor},
		{"burst grows: 2/minute to 120/hour", base(withRate(allow("a.com", 443), "2/minute")), base(withRate(allow("a.com", 443), "120/hour")), CodeAllowRateRelaxed, "", config.RoleEditor},
		{"rateLimit unparseable", base(withRate(allow("a.com", 443), "10/minute")), base(withRate(allow("a.com", 443), "lots")), CodeAllowRateRelaxed, "", config.RoleEditor},
		{"rateLimit new unparseable", base(allow("a.com", 443)), base(withRate(allow("a.com", 443), "lots")), CodeAllowRateRelaxed, "", config.RoleEditor},
		{"timeWindow widened", base(withTime(allow("a.com", 443), "9-17")), base(withTime(allow("a.com", 443), "8-18")), CodeAllowTimeRelaxed, "", config.RoleEditor},
		{"timeWindow removed", base(withTime(allow("a.com", 443), "9-17")), base(allow("a.com", 443)), CodeAllowTimeRelaxed, "", config.RoleEditor},
		{"timeWindow unparseable", base(allow("a.com", 443)), base(withTime(allow("a.com", 443), "25-99")), CodeAllowTimeRelaxed, "", config.RoleEditor},
		{"methods unrestricted", base(config.AllowlistEntry{Domain: "a.com", Port: 443, Methods: []string{"GET"}}), base(allow("a.com", 443)), CodeAllowConstraint, "", config.RoleEditor},
		{"paths widened", base(config.AllowlistEntry{Domain: "a.com", Port: 443, Paths: []string{"/a"}}), base(config.AllowlistEntry{Domain: "a.com", Port: 443, Paths: []string{"/a", "/b"}}), CodeAllowConstraint, "", config.RoleEditor},
		{"advisory on to off", Doc{Settings: &config.SettingsWire{Advisory: toggle(true)}}, Doc{Settings: &config.SettingsWire{Advisory: toggle(false)}}, CodeSettingsChanged, "advisory.enabled", config.RoleEditor},
		{"llmProviders entry added", Doc{}, Doc{Settings: &config.SettingsWire{LLMProviders: []config.LLMProviderSettings{{Name: "p"}}}}, CodeSettingsChanged, "llmProviders", config.RoleAdmin},
		{"judge changed", Doc{Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "a"}}}, Doc{Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "b"}}}, CodeSettingsChanged, "judge.model", config.RoleAdmin},
		{"dlp mode changed", Doc{Settings: &config.SettingsWire{DLP: &config.DLPSettings{Mode: "enforce"}}}, Doc{Settings: &config.SettingsWire{DLP: &config.DLPSettings{Mode: "off"}}}, CodeSettingsChanged, "dlp.mode", config.RoleEditor},
		{"agents changed", Doc{}, Doc{Settings: &config.SettingsWire{Agents: []config.AgentSettings{{ID: "a"}}}}, CodeSettingsChanged, "agents", config.RoleEditor},
		{"secrets removed", Doc{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws"}}}, Doc{}, CodeSettingsChanged, "secrets.backend", config.RoleAdmin},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.base, tc.draft)
			if !got.Widening {
				t.Fatalf("not widening: %+v", got)
			}
			found := false
			for _, r := range got.Reasons {
				if r.Code == tc.code && (tc.path == "" || r.Path == tc.path) {
					found = true
				}
			}
			if !found {
				t.Fatalf("want %s at %q, got %+v", tc.code, tc.path, got.Reasons)
			}
			if got.RequiredRole != tc.role {
				t.Fatalf("role = %v, want %v", got.RequiredRole, tc.role)
			}
		})
	}
}

func TestClassifyNarrowing(t *testing.T) {
	scopedBase := scopedAllow("a.com", []string{"eng", "ops"}, []string{"a@x.com", "b@x.com"})
	tests := []struct {
		name        string
		base, draft Doc
	}{
		{"deny added", Doc{}, Doc{Denylist: []config.DenylistEntry{{Domain: "x.com", Port: 443}}}},
		{"allow removed", docA(allow("a.com", 443), allow("b.com", 443)), docA(allow("a.com", 443))},
		{"groups added to unscoped", docA(allow("a.com", 443)), docA(scopedAllow("a.com", []string{"eng"}, nil))},
		{"users added to unscoped", docA(allow("a.com", 443)), docA(scopedAllow("a.com", nil, []string{"a@x.com"}))},
		{"scoped shrinks", docA(scopedBase), docA(scopedAllow("a.com", []string{"eng"}, []string{"a@x.com"}))},
		{"scoped drops users", docA(scopedBase), docA(scopedAllow("a.com", []string{"eng", "ops"}, nil))},
		{"rate tightened", docA(withRate(allow("a.com", 443), "10/minute")), docA(withRate(allow("a.com", 443), "5/minute"))},
		{"rate tightened across units", docA(withRate(allow("a.com", 443), "100/hour")), docA(withRate(allow("a.com", 443), "50/hour"))},
		{"rate lower and longer window", docA(withRate(allow("a.com", 443), "10/minute")), docA(withRate(allow("a.com", 443), "5/hour"))},
		{"rate added", docA(allow("a.com", 443)), docA(withRate(allow("a.com", 443), "5/minute"))},
		{"time added", docA(allow("a.com", 443)), docA(withTime(allow("a.com", 443), "9-17"))},
		{"time narrowed", docA(withTime(allow("a.com", 443), "8-18")), docA(withTime(allow("a.com", 443), "9-17"))},
		{"time narrowed wrap", docA(withTime(allow("a.com", 443), "22-6")), docA(withTime(allow("a.com", 443), "23-5"))},
		{"methods added", docA(allow("a.com", 443)), docA(config.AllowlistEntry{Domain: "a.com", Port: 443, Methods: []string{"GET"}})},
		{"advisory off to on", Doc{Settings: &config.SettingsWire{Advisory: toggle(false)}}, Doc{Settings: &config.SettingsWire{Advisory: toggle(true)}}},
		{"compliance added on", Doc{}, Doc{Settings: &config.SettingsWire{Compliance: toggle(true)}}},
		{"logging changed", Doc{Settings: &config.SettingsWire{Logging: &config.LoggingSettings{Level: "info"}}}, Doc{Settings: &config.SettingsWire{Logging: &config.LoggingSettings{Level: "debug", Format: "json"}}}},
		{"cache ttl changed", Doc{Settings: &config.SettingsWire{CacheTTLSeconds: intp(5)}}, Doc{Settings: &config.SettingsWire{CacheTTLSeconds: intp(500)}}},
		{"nil vs empty settings", Doc{}, Doc{Settings: &config.SettingsWire{}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.base, tc.draft)
			if got.Widening || len(got.Reasons) != 0 {
				t.Fatalf("widening: %+v", got)
			}
			if got.RequiredRole != config.RoleEditor {
				t.Fatalf("role = %v", got.RequiredRole)
			}
		})
	}
}

func intp(n int) *int { return &n }

func TestClassifyPairedReasonsHaveCodesAndNoValues(t *testing.T) {
	base := docA(withTime(withRate(scopedAllow("a.com", []string{"secret-group"}, nil), "5/minute"), "9-17"))
	draft := docA(withTime(withRate(allow("a.com", 443), "50/minute"), "0-23"))
	got := Classify(base, draft)
	want := []string{CodeAllowRateRelaxed, CodeAllowScopeWide, CodeAllowTimeRelaxed}
	if !reflect.DeepEqual(codes(got), want) {
		t.Fatalf("codes = %v, want %v", codes(got), want)
	}
	for _, r := range got.Reasons {
		for _, s := range []string{r.Path, r.Detail} {
			if strings.Contains(s, "secret-group") || strings.Contains(s, "50/minute") {
				t.Fatalf("reason leaks a value: %+v", r)
			}
		}
	}
}

func TestClassifySettingsChangedPathAndRole(t *testing.T) {
	base := Doc{Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "gpt-secret-model"}}}
	draft := Doc{Settings: &config.SettingsWire{Judge: &config.JudgeSettings{Model: "other-model"}}}
	got := Classify(base, draft)
	if len(got.Reasons) != 1 || got.Reasons[0].Code != CodeSettingsChanged || got.Reasons[0].Path != "judge.model" {
		t.Fatalf("reasons = %+v", got.Reasons)
	}
	if strings.Contains(got.Reasons[0].Detail, "model-") || strings.Contains(got.Reasons[0].Detail, "gpt-secret") {
		t.Fatalf("detail leaks a value: %q", got.Reasons[0].Detail)
	}
}

func TestClassifyAgentIdentityNeedsAdmin(t *testing.T) {
	mk := func(identity string, policy string) Doc {
		return Doc{Settings: &config.SettingsWire{Agents: []config.AgentSettings{{ID: "a1", Identity: identity, Policy: policy}}}}
	}
	if got := Classify(mk("x", "p1"), mk("x", "p2")); got.RequiredRole != config.RoleEditor || !got.Widening {
		t.Fatalf("policy change: %+v", got)
	}
	if got := Classify(mk("x", "p"), mk("y", "p")); got.RequiredRole != config.RoleAdmin {
		t.Fatalf("identity change role = %v", got.RequiredRole)
	}
}

func TestDiffSettingsEnabledToggles(t *testing.T) {
	tests := []struct {
		name        string
		base, draft map[string]any
		wantPaths   []string
	}{
		{"dlp.enabled true to false", map[string]any{"dlp": map[string]any{"enabled": true}}, map[string]any{"dlp": map[string]any{"enabled": false}}, []string{"dlp.enabled"}},
		{"dlp.enabled false to true", map[string]any{"dlp": map[string]any{"enabled": false}}, map[string]any{"dlp": map[string]any{"enabled": true}}, nil},
		{"dlp.enabled absent to true", map[string]any{}, map[string]any{"dlp": map[string]any{"enabled": true}}, nil},
		{"dlp.enabled removed", map[string]any{"dlp": map[string]any{"enabled": true}}, map[string]any{}, []string{"dlp.enabled"}},
		{"unknown field", map[string]any{}, map[string]any{"newField": 1}, []string{"newField"}},
		{"unknown nested enabled", map[string]any{"judge": map[string]any{"enabled": false}}, map[string]any{"judge": map[string]any{"enabled": true}}, []string{"judge.enabled"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			changes, _ := diffSettings(tc.base, tc.draft)
			var got []string
			for _, c := range changes {
				got = append(got, c.Path)
			}
			if !reflect.DeepEqual(got, tc.wantPaths) {
				t.Fatalf("paths = %v, want %v", got, tc.wantPaths)
			}
		})
	}
}

func TestClassifyIdenticalAndShuffled(t *testing.T) {
	d := bigDoc(200, 0)
	got := Classify(d, d)
	if got.Widening || len(got.Reasons) != 0 {
		t.Fatalf("identical docs widening: %+v", got)
	}

	base, draft := bigDoc(200, 0), bigDoc(200, 7)
	want := Classify(base, draft)
	if !want.Widening {
		t.Fatal("expected widening")
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		b, dr := shuffled(base, rng), shuffled(draft, rng)
		if got := Classify(b, dr); !reflect.DeepEqual(got, want) {
			t.Fatalf("shuffle changed output:\n%+v\n%+v", got, want)
		}
	}
}

func shuffled(d Doc, rng *rand.Rand) Doc {
	out := Doc{Allowlist: append([]config.AllowlistEntry(nil), d.Allowlist...), Denylist: append([]config.DenylistEntry(nil), d.Denylist...), Settings: d.Settings}
	rng.Shuffle(len(out.Allowlist), func(i, j int) { out.Allowlist[i], out.Allowlist[j] = out.Allowlist[j], out.Allowlist[i] })
	rng.Shuffle(len(out.Denylist), func(i, j int) { out.Denylist[i], out.Denylist[j] = out.Denylist[j], out.Denylist[i] })
	return out
}

// bigDoc builds n allow and deny entries; shift moves the domain numbering so
// two docs overlap but differ.
func bigDoc(n, shift int) Doc {
	d := Doc{}
	for i := 0; i < n; i++ {
		e := allow(fmt.Sprintf("host%d.example.com", i+shift), 443)
		if i%3 == 0 {
			e.Groups = []string{"g1", "g2"}
		}
		if i%5 == 0 {
			e.RateLimit = "10/minute"
		}
		d.Allowlist = append(d.Allowlist, e)
		d.Denylist = append(d.Denylist, config.DenylistEntry{Domain: fmt.Sprintf("bad%d.example.com", i+shift), Port: 443})
	}
	return d
}

func TestClassifyFiveThousandEntriesUnderBudget(t *testing.T) {
	base, draft := bigDoc(5000, 0), bigDoc(5000, 50)
	start := time.Now()
	got := Classify(base, draft)
	elapsed := time.Since(start)
	if !got.Widening {
		t.Fatal("expected widening")
	}
	// The ticket budget is 50ms; allow headroom for -race and loaded CI hosts
	// while still catching an accidental quadratic pass (seconds).
	if elapsed > 2*time.Second {
		t.Fatalf("Classify took %v for 5000 entries per side", elapsed)
	}
}

func BenchmarkClassify(b *testing.B) {
	base, draft := bigDoc(5000, 0), bigDoc(5000, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Classify(base, draft)
	}
}

func FuzzClassify(f *testing.F) {
	f.Add([]byte("a.com"), uint8(0), []byte("10/minute"), []byte("9-17"), true)
	f.Add([]byte("~^x$"), uint8(7), []byte("lots"), []byte("25-1"), false)
	f.Fuzz(func(t *testing.T, domain []byte, flags uint8, rate, tw []byte, dlpOn bool) {
		e := config.AllowlistEntry{Domain: string(domain), Port: int(flags % 3), RateLimit: string(rate), TimeWindow: string(tw)}
		if flags&1 != 0 {
			e.Groups = []string{string(rate)}
		}
		if flags&2 != 0 {
			e.Users = []string{string(tw)}
		}
		d := Doc{
			Allowlist: []config.AllowlistEntry{e, e},
			Denylist:  []config.DenylistEntry{{Domain: string(domain), Port: int(flags % 2)}},
			Settings:  &config.SettingsWire{DLP: &config.DLPSettings{Mode: string(rate)}, Advisory: toggle(dlpOn)},
		}
		got := Classify(d, d)
		if got.Widening || len(got.Reasons) != 0 {
			t.Fatalf("Classify(x, x) widening: %+v", got)
		}
		if got.RequiredRole != config.RoleEditor {
			t.Fatalf("role = %v", got.RequiredRole)
		}
	})
}

func TestClassifyRateLimitSplitting(t *testing.T) {
	r10 := func(e config.AllowlistEntry) config.AllowlistEntry { return withRate(e, "10/minute") }
	eng := scopedAllow("a.com", []string{"eng"}, nil)
	ops := scopedAllow("a.com", []string{"ops"}, nil)
	get := func(e config.AllowlistEntry, m ...string) config.AllowlistEntry { e.Methods = m; return e }

	tests := []struct {
		name        string
		base, draft Doc
		widening    bool
	}{
		{"one rated entry split by methods", docA(r10(eng)), docA(r10(get(eng, "GET")), r10(get(eng, "GET", "POST"))), true},
		{"unscoped rated split by groups", docA(r10(allow("a.com", 443))), docA(r10(eng), r10(ops)), true},
		{"unscoped rated gains one scope", docA(r10(allow("a.com", 443))), docA(r10(eng)), true},
		{"one rated entry narrowed 1:1", docA(r10(eng)), docA(r10(get(eng, "GET"))), false},
		{"two rated entries each narrowed 1:1", docA(r10(eng), r10(ops)), docA(r10(get(eng, "GET")), r10(get(ops, "GET"))), false},
		{"unlimited base split into rated entries", docA(allow("a.com", 443)), docA(r10(eng), r10(ops)), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.base, tc.draft)
			if got.Widening != tc.widening {
				t.Fatalf("widening = %v: %+v", got.Widening, got)
			}
			if tc.widening && !slicesContains(codes(got), CodeAllowRateRelaxed) {
				t.Fatalf("want %s: %+v", CodeAllowRateRelaxed, got.Reasons)
			}
		})
	}
}

func slicesContains(vs []string, s string) bool {
	for _, v := range vs {
		if v == s {
			return true
		}
	}
	return false
}

func TestClassifyRemovedToJudge(t *testing.T) {
	constrained := []struct {
		name string
		e    config.AllowlistEntry
	}{
		{"groups", scopedAllow("a.com", []string{"eng"}, nil)},
		{"users", scopedAllow("a.com", nil, []string{"a@x.com"})},
		{"methods", config.AllowlistEntry{Domain: "a.com", Port: 443, Methods: []string{"GET"}}},
		{"paths", config.AllowlistEntry{Domain: "a.com", Port: 443, Paths: []string{"/v1/*"}}},
		{"rateLimit", withRate(allow("a.com", 443), "10/minute")},
		{"timeWindow", withTime(allow("a.com", 443), "9-17")},
	}
	for _, tc := range constrained {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(docA(tc.e), Doc{})
			if !got.Widening || !slicesContains(codes(got), CodeAllowRemovedToJudge) {
				t.Fatalf("not flagged: %+v", got)
			}
			if got.RequiredRole != config.RoleEditor {
				t.Fatalf("role = %v", got.RequiredRole)
			}
			// Still narrowing in effect when another entry keeps the destination.
			if got := Classify(docA(tc.e, allow("a.com", 443)), docA(allow("a.com", 443))); slicesContains(codes(got), CodeAllowRemovedToJudge) {
				t.Fatalf("flagged though destination remains: %+v", got)
			}
		})
	}
	if got := Classify(docA(allow("a.com", 443)), Doc{}); got.Widening {
		t.Fatalf("plain entry removal widening: %+v", got)
	}
}

func TestClassificationJSONStable(t *testing.T) {
	raw, err := json.Marshal(Classify(Doc{}, Doc{}))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"widening":false,"reasons":[],"requiredRole":"editor"}` {
		t.Fatalf("json = %s", raw)
	}
	adm := Classify(Doc{}, Doc{Settings: &config.SettingsWire{Secrets: &config.SecretsSettings{Backend: "aws"}}})
	raw, _ = json.Marshal(adm)
	var back Classification
	if err := json.Unmarshal(raw, &back); err != nil || back.RequiredRole != config.RoleAdmin || !strings.Contains(string(raw), `"requiredRole":"admin"`) {
		t.Fatalf("round trip %s: %+v %v", raw, back, err)
	}
}

func FuzzClassifyNewKeyWidens(f *testing.F) {
	f.Add([]byte("new.example.com"), uint8(1), []byte("10/minute"), []byte("9-17"))
	f.Add([]byte("~^x$"), uint8(7), []byte(""), []byte(""))
	f.Fuzz(func(t *testing.T, domain []byte, flags uint8, rate, tw []byte) {
		base := bigDoc(3, 0)
		e := config.AllowlistEntry{Domain: "fuzz-" + string(domain), Port: int(flags % 4), RateLimit: string(rate), TimeWindow: string(tw)}
		if flags&4 != 0 {
			e.Groups = []string{"g"}
		}
		draft := Doc{Allowlist: append(append([]config.AllowlistEntry(nil), base.Allowlist...), e), Denylist: base.Denylist}
		got := Classify(base, draft)
		if !got.Widening || !slicesContains(codes(got), CodeAllowAdded) {
			t.Fatalf("new key not widening: %+v", got)
		}
	})
}
