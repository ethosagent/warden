package config

import (
	"fmt"
	"strings"
	"testing"
)

func okMatch() UserLimitMatch { return UserLimitMatch{Groups: []string{"eng"}} }

func okRule(name string) UserLimit {
	return UserLimit{Name: name, RateLimit: "10/minute", Match: okMatch()}
}

func TestValidateUserLimits(t *testing.T) {
	tooMany := make([]UserLimit, MaxUserLimits+1)
	for i := range tooMany {
		tooMany[i] = okRule(fmt.Sprintf("r%d", i))
	}
	cases := []struct {
		name    string
		p       Policy
		wantErr string // empty: must pass
	}{
		{"valid rate only", Policy{UserLimits: []UserLimit{okRule("a")}}, ""},
		{"valid cost only", Policy{UserLimits: []UserLimit{{Name: "a", DailyCostUSD: 5, Match: okMatch()}}}, ""},
		{"bad rate period", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "10/fortnight", Match: okMatch()}}}, "policy.userLimits[0].rateLimit"},
		{"bad rate on second rule", Policy{UserLimits: []UserLimit{okRule("a"), {Name: "b", RateLimit: "x", Match: okMatch()}}}, "policy.userLimits[1].rateLimit"},
		{"neither limit", Policy{UserLimits: []UserLimit{okRule("a"), {Name: "b", Match: okMatch()}}}, "policy.userLimits[1]"},
		{"duplicate name", Policy{UserLimits: []UserLimit{okRule("a"), okRule("a")}}, "policy.userLimits[1].name"},
		{"reserved default", Policy{UserLimits: []UserLimit{okRule("default")}}, "policy.userLimits[0].name"},
		{"reserved anonymous", Policy{UserLimits: []UserLimit{okRule("x"), okRule("anonymous")}}, "policy.userLimits[1].name"},
		{"missing name", Policy{UserLimits: []UserLimit{{RateLimit: "1/second", Match: okMatch()}}}, "policy.userLimits[0].name"},
		{"bad name charset", Policy{UserLimits: []UserLimit{okRule("a b")}}, "policy.userLimits[0].name"},
		{"negative cost", Policy{UserLimits: []UserLimit{{Name: "a", DailyCostUSD: -1, Match: okMatch()}}}, "policy.userLimits[0].dailyCostUSD"},
		{"huge cost", Policy{UserLimits: []UserLimit{{Name: "a", DailyCostUSD: 1e6 + 1, Match: okMatch()}}}, "policy.userLimits[0].dailyCostUSD"},
		{"max cost", Policy{UserLimits: []UserLimit{{Name: "a", DailyCostUSD: 1e6, Match: okMatch()}}}, ""},
		{"too many rules", Policy{UserLimits: tooMany}, "policy.userLimits"},
		{"no match", Policy{UserLimits: []UserLimit{okRule("a"), {Name: "b", RateLimit: "1/second"}}}, "policy.userLimits[1].match"},
		{"domains-only match", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Domains: []string{"api.openai.com"}}}}}, "policy.userLimits[0].match"},
		{"agents-only match ok", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Agents: []string{"ag"}, Domains: []string{"api.openai.com"}}}}}, ""},
		{"empty user", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Users: []string{" "}}}}}, "policy.userLimits[0].match.users[0]"},
		{"empty group", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Groups: []string{""}}}}}, "policy.userLimits[0].match.groups[0]"},
		{"bad agent", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Agents: []string{"a b"}}}}}, "policy.userLimits[0].match.agents[0]"},
		{"bad domain wildcard", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Domains: []string{"api.*.com"}}}}}, "policy.userLimits[0].match.domains[0]"},
		{"bad domain regex", Policy{UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Domains: []string{"~("}}}}}, "policy.userLimits[0].match.domains[0]"},
		{"default ok", Policy{DefaultUserLimit: &UserLimit{RateLimit: "5/minute"}}, ""},
		{"default with match", Policy{DefaultUserLimit: &UserLimit{RateLimit: "5/minute", Match: UserLimitMatch{Groups: []string{"g"}}}}, "policy.defaultUserLimit.match"},
		{"default wrong name", Policy{DefaultUserLimit: &UserLimit{Name: "x", RateLimit: "5/minute"}}, "policy.defaultUserLimit.name"},
		{"default no limits", Policy{DefaultUserLimit: &UserLimit{}}, "policy.defaultUserLimit"},
		{"anonymous bad rate", Policy{AnonymousLimit: &UserLimit{RateLimit: "0/minute"}}, "policy.anonymousLimit.rateLimit"},
		{"anonymous with match", Policy{AnonymousLimit: &UserLimit{RateLimit: "5/minute", Match: UserLimitMatch{Agents: []string{"a"}}}}, "policy.anonymousLimit.match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := fmt.Sprintf("%+v", tc.p.UserLimits)
			err := ValidateUserLimits(tc.p)
			if after := fmt.Sprintf("%+v", tc.p.UserLimits); after != before {
				t.Fatalf("ValidateUserLimits mutated its input:\n%s\n%s", before, after)
			}
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestValidateUserLimits_NormalizesAndNamesSingles(t *testing.T) {
	p := Policy{
		UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{
			Users:   []string{" Bob@Example.com ", "sub-1", "bob@example.com"},
			Groups:  []string{"eng", "eng", "ops"},
			Agents:  []string{"z", "a", "a"},
			Domains: []string{"API.OpenAI.com", "*.Example.com", "api.openai.com"},
		}}},
		DefaultUserLimit: &UserLimit{RateLimit: "1/second"},
		AnonymousLimit:   &UserLimit{Name: "anonymous", RateLimit: "1/second"},
	}
	if err := NormalizeUserLimits(&p); err != nil {
		t.Fatal(err)
	}
	m := p.UserLimits[0].Match
	for _, c := range []struct {
		got, want []string
	}{
		{m.Users, []string{"bob@example.com", "sub-1"}},
		{m.Groups, []string{"eng", "ops"}},
		{m.Agents, []string{"a", "z"}},
		{m.Domains, []string{"*.example.com", "api.openai.com"}},
	} {
		if strings.Join(c.got, ",") != strings.Join(c.want, ",") {
			t.Errorf("got %v, want %v", c.got, c.want)
		}
	}
	if p.DefaultUserLimit.Name != "default" || p.AnonymousLimit.Name != "anonymous" {
		t.Errorf("single rules not named: %q %q", p.DefaultUserLimit.Name, p.AnonymousLimit.Name)
	}
}

func TestValidateCostBlockedUsers(t *testing.T) {
	good := CostBlockedUser{Sub: "sub-1", Rule: "eng-llm", Day: "2026-11-27"}
	over := make([]CostBlockedUser, MaxCostBlockedUsers+1)
	for i := range over {
		over[i] = good
	}
	cases := []struct {
		name    string
		list    []CostBlockedUser
		wantErr string
	}{
		{"nil", nil, ""},
		{"good", []CostBlockedUser{good}, ""},
		{"reserved rule names", []CostBlockedUser{{Sub: "s", Rule: "default", Day: "2026-01-01"}, {Sub: "anon:a", Rule: "anonymous", Day: "2026-01-01"}}, ""},
		{"at limit", over[:MaxCostBlockedUsers], ""},
		{"over limit", over, "costBlockedUsers"},
		{"bad month", []CostBlockedUser{good, {Sub: "s", Rule: "r", Day: "2026-13-01"}}, "costBlockedUsers[1].day"},
		{"unpadded day", []CostBlockedUser{{Sub: "s", Rule: "r", Day: "2026-1-1"}}, "costBlockedUsers[0].day"},
		{"empty sub", []CostBlockedUser{{Rule: "r", Day: "2026-01-01"}}, "costBlockedUsers[0].sub"},
		{"long sub", []CostBlockedUser{{Sub: strings.Repeat("x", 256), Rule: "r", Day: "2026-01-01"}}, "costBlockedUsers[0].sub"},
		{"control char sub", []CostBlockedUser{{Sub: "a\nb", Rule: "r", Day: "2026-01-01"}}, "costBlockedUsers[0].sub"},
		{"bad rule", []CostBlockedUser{{Sub: "s", Rule: "a b", Day: "2026-01-01"}}, "costBlockedUsers[0].rule"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCostBlockedUsers(tc.list)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			case err != nil && strings.Contains(err.Error(), "sub-1"):
				t.Fatalf("error names a sub: %v", err)
			}
		})
	}
}

// A bad costBlockedUsers row fails the pull whole, so the worker keeps its
// last good policy.
func TestValidateCostBlockedUsers_RemoteRejects(t *testing.T) {
	const base = `"allowlist":[{"domain":"a.com"}],"denylist":[]`
	if _, _, err := parseRemotePolicy([]byte(`{` + base + `,"costBlockedUsers":[{"sub":"s","rule":"r","day":"2026-13-01"}]}`)); err == nil || !strings.Contains(err.Error(), "costBlockedUsers[0].day") {
		t.Fatalf("bad day: err = %v", err)
	}
	var b strings.Builder
	b.WriteString(`{` + base + `,"costBlockedUsers":[`)
	for i := 0; i <= MaxCostBlockedUsers; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"sub":"s","rule":"r","day":"2026-01-01"}`)
	}
	b.WriteString(`]}`)
	if _, _, err := parseRemotePolicy([]byte(b.String())); err == nil {
		t.Fatal("5001 entries accepted")
	}
	p, _, err := parseRemotePolicy([]byte(`{` + base + `,"costBlockedUsers":[{"sub":"s","rule":"r","day":"2026-01-01"}]}`))
	if err != nil || len(p.CostBlockedUsers) != 1 {
		t.Fatalf("good list: %v %+v", err, p)
	}
}

func TestDeepCopy_UserLimitsNotAliased(t *testing.T) {
	orig := Policy{
		UserLimits: []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{
			Users: []string{"u"}, Groups: []string{"g"}, Agents: []string{"ag"}, Domains: []string{"d.com"}}}},
		DefaultUserLimit: &UserLimit{Name: "default", RateLimit: "1/second"},
		AnonymousLimit:   &UserLimit{Name: "anonymous", RateLimit: "1/second"},
		CostBlockedUsers: []CostBlockedUser{{Sub: "s", Rule: "a", Day: "2026-01-01"}},
	}
	cp := orig.DeepCopy()
	cp.UserLimits[0].Match.Groups[0] = "X"
	cp.UserLimits[0].Match.Users[0] = "X"
	cp.UserLimits[0].Match.Agents[0] = "X"
	cp.UserLimits[0].Match.Domains[0] = "X"
	cp.UserLimits[0].Name = "X"
	cp.DefaultUserLimit.RateLimit = "X"
	cp.AnonymousLimit.RateLimit = "X"
	cp.CostBlockedUsers[0].Sub = "X"
	m := orig.UserLimits[0].Match
	if m.Groups[0] != "g" || m.Users[0] != "u" || m.Agents[0] != "ag" || m.Domains[0] != "d.com" || orig.UserLimits[0].Name != "a" {
		t.Fatalf("original mutated through the copy: %+v", orig.UserLimits[0])
	}
	if orig.DefaultUserLimit.RateLimit != "1/second" || orig.AnonymousLimit.RateLimit != "1/second" || orig.CostBlockedUsers[0].Sub != "s" {
		t.Fatal("original pointers or cost blocks mutated through the copy")
	}
	if got := (Policy{}).DeepCopy(); got.UserLimits != nil || got.DefaultUserLimit != nil || got.CostBlockedUsers != nil {
		t.Fatalf("empty policy gained fields: %+v", got)
	}
}

// Rate limits are enforced (W-P3-PUL-09) and load; a daily cost cap is not
// enforced until W-P3-PUL-04, so any rule that sets one is still refused.
func TestUserLimitsGuard_NotYetEnforced(t *testing.T) {
	for name, y := range map[string]string{
		"userLimits":       "policy:\n  allowlist: [{domain: a.com}]\n  userLimits: [{name: a, match: {groups: [g]}, rateLimit: 1/minute}, {name: b, match: {groups: [h]}, rateLimit: 1/minute, dailyCostUSD: 2}]\n",
		"defaultUserLimit": "policy:\n  allowlist: [{domain: a.com}]\n  defaultUserLimit: {rateLimit: 1/minute, dailyCostUSD: 1}\n",
		"anonymousLimit":   "policy:\n  allowlist: [{domain: a.com}]\n  anonymousLimit: {dailyCostUSD: 3}\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewLocalYAMLProvider(writeTemp(t, y))
			if err == nil || !strings.Contains(err.Error(), "dailyCostUSD: not yet enforced") {
				t.Fatalf("err = %v, want dailyCostUSD not yet enforced", err)
			}
		})
	}
	// Rate-only rules in all three keys load.
	prov, err := NewLocalYAMLProvider(writeTemp(t, "policy:\n  allowlist: [{domain: a.com}]\n"+
		"  userLimits: [{name: a, match: {groups: [g]}, rateLimit: 1/minute}]\n"+
		"  defaultUserLimit: {rateLimit: 10/minute}\n  anonymousLimit: {rateLimit: 2/minute}\n"))
	if err != nil {
		t.Fatalf("rate-only rules refused: %v", err)
	}
	if pol, _ := prov.GetPolicy(); len(pol.UserLimits) != 1 || pol.DefaultUserLimit == nil || pol.AnonymousLimit == nil {
		t.Fatalf("policy = %+v", pol)
	}
	// An invalid rule reports its own error before the guard.
	_, err = NewLocalYAMLProvider(writeTemp(t, "policy:\n  allowlist: [{domain: a.com}]\n  userLimits: [{name: a, match: {groups: [g]}, rateLimit: 10/fortnight}]\n"))
	if err == nil || !strings.Contains(err.Error(), "policy.userLimits[0].rateLimit") {
		t.Fatalf("err = %v", err)
	}
	// Absent keys load as before.
	p, err := NewLocalYAMLProvider(writeTemp(t, "policy:\n  allowlist: [{domain: a.com}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if pol, _ := p.GetPolicy(); pol.UserLimits != nil || pol.DefaultUserLimit != nil || pol.AnonymousLimit != nil || pol.CostBlockedUsers != nil {
		t.Fatalf("absent keys produced %+v", pol)
	}
}

// With the guard lifted by the test hook, the rules load from YAML and
// round-trip through the wire decoder.
func TestUserLimits_LoadAndWireRoundTrip(t *testing.T) {
	allowUnenforcedUserLimits = true
	t.Cleanup(func() { allowUnenforcedUserLimits = false })

	prov, err := NewLocalYAMLProvider(writeTemp(t, `
policy:
  allowlist: [{domain: a.com}]
  userLimits:
    - name: eng-llm
      match: {groups: [eng], domains: [api.openai.com]}
      perAgent: true
      rateLimit: 60/minute
      dailyCostUSD: 5
  defaultUserLimit: {rateLimit: 600/hour}
  anonymousLimit: {rateLimit: 5/minute}
`))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := prov.GetPolicy()
	if len(pol.UserLimits) != 1 || !pol.UserLimits[0].PerAgent || pol.UserLimits[0].DailyCostUSD != 5 || pol.DefaultUserLimit.Name != "default" {
		t.Fatalf("policy = %+v", pol)
	}

	wire := `{"allowlist":[{"domain":"a.com"}],"denylist":[],` +
		`"userLimits":[{"name":"eng-llm","match":{"groups":["eng"]},"rateLimit":"60/minute"}],` +
		`"anonymousLimit":{"rateLimit":"5/minute"},` +
		`"costBlockedUsers":[{"sub":"s","rule":"eng-llm","day":"2026-11-27"}]}`
	got, _, err := parseRemotePolicy([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	if got.UserLimits[0].Name != "eng-llm" || got.AnonymousLimit.Name != "anonymous" || got.CostBlockedUsers[0].Rule != "eng-llm" {
		t.Fatalf("wire policy = %+v", got)
	}
	// A bad rule on the wire rejects the pull.
	if _, _, err := parseRemotePolicy([]byte(`{"allowlist":[{"domain":"a.com"}],"userLimits":[{"name":"a","match":{"groups":["g"]},"rateLimit":"10/fortnight"}]}`)); err == nil || !strings.Contains(err.Error(), "policy.userLimits[0].rateLimit") {
		t.Fatalf("err = %v", err)
	}
	// With the guard back on, the rate-only wire still loads and a wire that
	// sets a daily cost cap is refused whole.
	allowUnenforcedUserLimits = false
	if _, _, err := parseRemotePolicy([]byte(wire)); err != nil {
		t.Fatalf("rate-only wire refused: %v", err)
	}
	costWire := `{"allowlist":[{"domain":"a.com"}],"denylist":[],` +
		`"userLimits":[{"name":"eng-llm","match":{"groups":["eng"]},"rateLimit":"60/minute","dailyCostUSD":5}]}`
	if _, _, err := parseRemotePolicy([]byte(costWire)); err == nil || !strings.Contains(err.Error(), "not yet enforced") {
		t.Fatalf("guard not applied on the wire: %v", err)
	}
}

func TestLintUserLimits(t *testing.T) {
	if got := LintUserLimits(Policy{}); got != nil {
		t.Fatalf("no limits: %v", got)
	}
	p := Policy{
		UserLimits: []UserLimit{
			{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Groups: []string{"eng"}}},
			{Name: "b", RateLimit: "1/second", Match: UserLimitMatch{Groups: []string{"eng", "ops"}, Domains: []string{"api.openai.com"}}},
			{Name: "c", RateLimit: "1/second", Match: UserLimitMatch{Groups: []string{"sales"}}},
			{Name: "d", DailyCostUSD: 2, Match: UserLimitMatch{Users: []string{"u"}}},
			{Name: "e", RateLimit: "1/second", Match: UserLimitMatch{Users: []string{"u"}, Domains: []string{"*.example.com"}}},
			{Name: "f", RateLimit: "1/second", Match: UserLimitMatch{Users: []string{"v"}}},
		},
		Agents: []AgentPolicy{{ID: "strict", Identity: IdentityModeRequire}, {ID: "loose", Identity: IdentityModeAttribute}},
	}
	got := strings.Join(LintUserLimits(p), "\n")
	for _, want := range []string{
		`"a" and "b" overlap in the groups tier`,
		`"d" and "e" overlap in the users tier`,
		`"d" sets dailyCostUSD but no CA`,
		`agent "loose" has identity mode "attribute"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing warning %q in:\n%s", want, got)
		}
	}
	for _, bad := range []string{`"c"`, `"f"`, `"strict"`, `"eng"`, `"sales"`} {
		if strings.Contains(got, bad) {
			t.Errorf("unexpected %s in:\n%s", bad, got)
		}
	}
	p.TLS.CACert = "ca.pem"
	if strings.Contains(strings.Join(LintUserLimits(p), "\n"), "no CA") {
		t.Error("CA warning with a CA configured")
	}
}

// Normalization happens at the load sites on copies: a copied policy loads
// normalized, and the policy it was copied from is left as it was.
func TestNormalizeUserLimits_DeepCopyThenLoad(t *testing.T) {
	orig := Policy{
		UserLimits:     []UserLimit{{Name: "a", RateLimit: "1/second", Match: UserLimitMatch{Groups: []string{"b", "a", "a"}}}},
		AnonymousLimit: &UserLimit{RateLimit: "1/second"},
	}
	cp := orig.DeepCopy()
	if err := NormalizeUserLimits(&cp); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cp.UserLimits[0].Match.Groups, ","); got != "a,b" || cp.AnonymousLimit.Name != "anonymous" {
		t.Fatalf("copy not normalized: %+v", cp.UserLimits[0])
	}
	if got := strings.Join(orig.UserLimits[0].Match.Groups, ","); got != "b,a,a" || orig.AnonymousLimit.Name != "" {
		t.Fatalf("original mutated: %+v", orig.UserLimits[0])
	}
	// The YAML loader and the wire decoder both produce the normalized form.
	allowUnenforcedUserLimits = true
	t.Cleanup(func() { allowUnenforcedUserLimits = false })
	prov, err := NewLocalYAMLProvider(writeTemp(t, "policy:\n  allowlist: [{domain: a.com}]\n  userLimits: [{name: a, rateLimit: 1/second, match: {groups: [b, a, a]}}]\n  anonymousLimit: {rateLimit: 1/second}\n"))
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := prov.GetPolicy()
	if got := strings.Join(pol.UserLimits[0].Match.Groups, ","); got != "a,b" || pol.AnonymousLimit.Name != "anonymous" {
		t.Fatalf("YAML load not normalized: %+v", pol.UserLimits[0])
	}
	w, _, err := parseRemotePolicy([]byte(`{"allowlist":[{"domain":"a.com"}],"userLimits":[{"name":"a","rateLimit":"1/second","match":{"groups":["b","a"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(w.UserLimits[0].Match.Groups, ","); got != "a,b" {
		t.Fatalf("wire load not normalized: %v", got)
	}
}
