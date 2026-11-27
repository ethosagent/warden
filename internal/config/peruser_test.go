package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// perUserYAML wraps a mappings list (YAML lines indented under mappings:) into
// an enabled perUserSecrets block.
func perUserYAML(mappings string) string {
	return baseAllow + "perUserSecrets:\n  enabled: true\n  mappings:\n" + mappings
}

const gmailMapping = `    - placeholder: GOOGLE_USER
      provider: google
      scopes: [https://www.googleapis.com/auth/gmail.readonly]
      domains: [gmail.googleapis.com]
      agents: [support-bot]
`

func loadPerUser(t *testing.T, doc string) (PerUserSecretsConfig, error) {
	t.Helper()
	p, err := NewLocalYAMLProvider(writeTemp(t, doc))
	if err != nil {
		return PerUserSecretsConfig{}, err
	}
	pol, _ := p.GetPolicy()
	return pol.PerUserSecrets, nil
}

// TestPerUserSecretsDefaults: an absent block is the zero value (disabled, no
// default filled in, so Policy is unchanged); a present block gets
// workerCacheTTL 5m and in [header]; domains are lowercased.
func TestPerUserSecretsDefaults(t *testing.T) {
	got, err := loadPerUser(t, baseAllow)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, PerUserSecretsConfig{}) {
		t.Fatalf("absent block = %+v, want the zero value", got)
	}

	got, err = loadPerUser(t, perUserYAML(`    - placeholder: GOOGLE_USER
      provider: google
      domains: [Gmail.GoogleAPIs.com]
      agents: [support-bot]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := PerUserSecretsConfig{Enabled: true, WorkerCacheTTL: DefaultPerUserWorkerCacheTTL, Mappings: []PerUserMapping{{
		Placeholder: "GOOGLE_USER", Provider: "google", Domains: []string{"gmail.googleapis.com"},
		In: []string{PerUserInHeader}, Agents: []string{"support-bot"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed = %+v\nwant %+v", got, want)
	}

	got, err = loadPerUser(t, baseAllow+"perUserSecrets:\n  enabled: false\n")
	if err != nil || got.Enabled || got.WorkerCacheTTL != DefaultPerUserWorkerCacheTTL {
		t.Fatalf("disabled block = %+v, %v", got, err)
	}
}

// TestPerUserSecretsValid: a full mapping parses as written.
func TestPerUserSecretsValid(t *testing.T) {
	got, err := loadPerUser(t, baseAllow+`perUserSecrets:
  enabled: true
  workerCacheTTL: 90s
  mappings:
    - placeholder: "{{GITHUB_USER_TOKEN}}"
      provider: github
      scopes: [repo, read:user]
      domains: [api.github.com, "*.githubusercontent.com", "~^uploads\\.github\\.com$"]
      in: [header, query]
      agents: [support-bot, triage.bot]
`+gmailMapping)
	if err != nil {
		t.Fatal(err)
	}
	if got.WorkerCacheTTL != 90*time.Second || len(got.Mappings) != 2 {
		t.Fatalf("parsed = %+v", got)
	}
	m := got.Mappings[0]
	if m.Placeholder != "{{GITHUB_USER_TOKEN}}" || !reflect.DeepEqual(m.In, []string{"header", "query"}) || !reflect.DeepEqual(m.Scopes, []string{"repo", "read:user"}) || len(m.Domains) != 3 {
		t.Fatalf("mapping = %+v", m)
	}
}

// TestPerUserSecretsValidation: every rule fails naming its key.
func TestPerUserSecretsValidation(t *testing.T) {
	mapping := func(placeholder, provider, extra string) string {
		return "    - placeholder: " + placeholder + "\n      provider: " + provider + "\n" + extra
	}
	okRest := "      domains: [gmail.googleapis.com]\n      agents: [support-bot]\n"
	cases := []struct {
		name, doc, wantErr string
	}{
		{"no domains", perUserYAML(mapping("GOOGLE_USER", "google", "      agents: [support-bot]\n")), "perUserSecrets.mappings[0].domains is required"},
		{"empty domains", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: []\n      agents: [support-bot]\n")), "perUserSecrets.mappings[0].domains is required"},
		{"bad domain wildcard", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: [\"gmail.*.com\"]\n      agents: [support-bot]\n")), "perUserSecrets.mappings[0].domains[0]"},
		{"bad domain regex", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: [\"~(\"]\n      agents: [support-bot]\n")), "perUserSecrets.mappings[0].domains[0]"},
		{"reserved provider id", perUserYAML(mapping("GOOGLE_USER", "_idp", okRest)), "perUserSecrets.mappings[0].provider \"_idp\" is not a valid provider id"},
		{"uppercase provider", perUserYAML(mapping("GOOGLE_USER", "Google", okRest)), "perUserSecrets.mappings[0].provider"},
		{"no provider", perUserYAML("    - placeholder: GOOGLE_USER\n" + okRest), "perUserSecrets.mappings[0].provider is required"},
		{"in body", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      in: [body]\n")), "perUserSecrets.mappings[0].in[0] \"body\" is invalid"},
		{"in duplicate", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      in: [header, header]\n")), "perUserSecrets.mappings[0].in has duplicate"},
		{"bad agent", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: [gmail.googleapis.com]\n      agents: [\"-bad\"]\n")), "perUserSecrets.mappings[0].agents[0]"},
		{"no agents", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: [gmail.googleapis.com]\n")), "perUserSecrets.mappings[0].agents is required"},
		{"duplicate agent", perUserYAML(mapping("GOOGLE_USER", "google", "      domains: [gmail.googleapis.com]\n      agents: [a1, a1]\n")), "perUserSecrets.mappings[0].agents has duplicate"},
		{"scope with space", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      scopes: [\"a b\"]\n")), "perUserSecrets.mappings[0].scopes[0]"},
		{"empty scope", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      scopes: [\"\"]\n")), "perUserSecrets.mappings[0].scopes[0]"},
		{"duplicate scope", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      scopes: [repo, repo]\n")), "perUserSecrets.mappings[0].scopes has duplicate"},
		{"short placeholder", perUserYAML(mapping("SHORT", "google", okRest)), "perUserSecrets.mappings[0].placeholder must be 8-128"},
		{"long placeholder", perUserYAML(mapping(strings.Repeat("A", 129), "google", okRest)), "perUserSecrets.mappings[0].placeholder must be 8-128"},
		{"placeholder charset", perUserYAML(mapping("\"GOOGLE.USER\"", "google", okRest)), "perUserSecrets.mappings[0].placeholder must be 8-128"},
		{"placeholder slash", perUserYAML(mapping("\"users/GOOGLE\"", "google", okRest)), "perUserSecrets.mappings[0].placeholder must be 8-128"},
		{"no placeholder", perUserYAML("    - provider: google\n" + okRest), "perUserSecrets.mappings[0].placeholder is required"},
		{"ttl too short", baseAllow + "perUserSecrets:\n  enabled: true\n  workerCacheTTL: 10s\n", "perUserSecrets.workerCacheTTL 10s must be between 30s and 15m0s"},
		{"ttl too long", baseAllow + "perUserSecrets:\n  enabled: true\n  workerCacheTTL: 16m\n", "perUserSecrets.workerCacheTTL"},
		{"ttl not a duration", baseAllow + "perUserSecrets:\n  enabled: true\n  workerCacheTTL: soon\n", "perUserSecrets.workerCacheTTL \"soon\" is not a valid duration"},
		{"unknown key", baseAllow + "perUserSecrets:\n  enabled: true\n  token: x\n", "field token not found"},
		{"value field in mapping", perUserYAML(mapping("GOOGLE_USER", "google", okRest+"      value: ya29.secret\n")), "field value not found"},
		{"second mapping named", perUserYAML(gmailMapping + mapping("GITHUB_USER", "github", "      agents: [support-bot]\n")), "perUserSecrets.mappings[1].domains is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadPerUser(t, tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestPerUserSecretsDisabledNotValidated: a disabled block is parsed but not
// validated, so a half-written served copy cannot stop a start that does not
// use it (the settings writer that enables it re-validates).
func TestPerUserSecretsDisabledNotValidated(t *testing.T) {
	got, err := loadPerUser(t, baseAllow+"perUserSecrets:\n  enabled: false\n  workerCacheTTL: 1s\n  mappings:\n    - placeholder: X\n      provider: _idp\n")
	if err != nil || got.Enabled || len(got.Mappings) != 1 {
		t.Fatalf("disabled block = %+v, %v", got, err)
	}
}

// TestPerUserSecretsPlaceholderConflicts: a per-user placeholder must not
// equal, contain or be contained in a static secrets[] placeholder or another
// mapping's, because the static swap replaces substrings.
func TestPerUserSecretsPlaceholderConflicts(t *testing.T) {
	static := func(ph string) string { return "secrets:\n  - placeholder: " + ph + "\n    envVar: X\n" }
	mapping := func(ph string) string {
		return "    - placeholder: " + ph + "\n      provider: google\n      domains: [gmail.googleapis.com]\n      agents: [support-bot]\n"
	}
	for _, tc := range []struct {
		name, doc, wantErr string
	}{
		{"static contained in per-user", perUserYAML(mapping("GOOGLE_USER")) + static("GOOGLE"),
			`perUserSecrets.mappings[0].placeholder "GOOGLE_USER" overlaps secrets[0].placeholder "GOOGLE"`},
		{"per-user contained in static", perUserYAML(mapping("GOOGLE_USER")) + static("MY_GOOGLE_USER_KEY"),
			`overlaps secrets[0].placeholder "MY_GOOGLE_USER_KEY"`},
		{"equal to static", perUserYAML(mapping("GOOGLE_USER")) + static("GOOGLE_USER"),
			`overlaps secrets[0].placeholder "GOOGLE_USER"`},
		{"equal mappings", perUserYAML(mapping("GOOGLE_USER") + mapping("GOOGLE_USER")),
			`perUserSecrets.mappings[0].placeholder "GOOGLE_USER" overlaps perUserSecrets.mappings[1].placeholder "GOOGLE_USER"`},
		{"nested mappings", perUserYAML(mapping("GOOGLE_USER_MAIL") + mapping("GOOGLE_USER")),
			`perUserSecrets.mappings[0].placeholder "GOOGLE_USER_MAIL" overlaps perUserSecrets.mappings[1].placeholder "GOOGLE_USER"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadPerUser(t, tc.doc)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
	// Disjoint placeholders pass.
	if _, err := loadPerUser(t, perUserYAML(mapping("GOOGLE_USER")+mapping("GITHUB_USER"))+static("OPENAI_API_KEY")); err != nil {
		t.Fatalf("disjoint placeholders: %v", err)
	}
}

// TestPerUserSecretsEncodeRoundTrip: EncodePerUserSecretsNode then parse gives
// the same config, and the encoding carries no value-bearing key.
func TestPerUserSecretsEncodeRoundTrip(t *testing.T) {
	in, err := loadPerUser(t, baseAllow+`perUserSecrets:
  enabled: true
  workerCacheTTL: 2m
  mappings:
    - placeholder: GITHUB_USER
      provider: github
      scopes: [repo]
      domains: [api.github.com]
      in: [query, header]
      agents: [a1, a2]
`+gmailMapping)
	if err != nil {
		t.Fatal(err)
	}
	node, err := EncodePerUserSecretsNode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(&node)
	if err != nil {
		t.Fatal(err)
	}
	var raw rawPerUserSecrets
	dec := yaml.NewDecoder(strings.NewReader(string(out)))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("decode %s: %v", out, err)
	}
	back, err := parsePerUserSecrets(&raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, in) {
		t.Fatalf("round trip = %+v\nwant %+v\nyaml:\n%s", back, in, out)
	}
	for _, bad := range []string{"value", "token", "secret"} {
		if strings.Contains(strings.ToLower(string(out)), bad+":") {
			t.Fatalf("encoding has a %q key:\n%s", bad, out)
		}
	}
	// The zero value encodes to enabled: false with nothing else.
	node, err = EncodePerUserSecretsNode(PerUserSecretsConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := yaml.Marshal(&node); strings.TrimSpace(string(out)) != "enabled: false" {
		t.Fatalf("zero encoding = %q", out)
	}
}

// TestPerUserSecretsDeepCopy: Policy.DeepCopy does not share mapping slices.
func TestPerUserSecretsDeepCopy(t *testing.T) {
	p := Policy{PerUserSecrets: PerUserSecretsConfig{Enabled: true, Mappings: []PerUserMapping{{
		Placeholder: "GOOGLE_USER", Scopes: []string{"s"}, Domains: []string{"d"}, In: []string{"header"}, Agents: []string{"a"},
	}}}}
	c := p.DeepCopy()
	c.PerUserSecrets.Mappings[0].Domains[0] = "evil.example"
	c.PerUserSecrets.Mappings[0].Agents[0] = "other"
	c.PerUserSecrets.Mappings[0].Placeholder = "X"
	if m := p.PerUserSecrets.Mappings[0]; m.Domains[0] != "d" || m.Agents[0] != "a" || m.Placeholder != "GOOGLE_USER" {
		t.Fatalf("DeepCopy shares mapping state: %+v", m)
	}
}

// TestPerUserSecretsServedExample: the commented example in
// configs/config.cp-served.yaml parses and validates once uncommented.
func TestPerUserSecretsServedExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "configs", "config.cp-served.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var block []string
	in := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "# perUserSecrets:") {
			in = true
		}
		if !in {
			continue
		}
		if !strings.HasPrefix(line, "# ") {
			break
		}
		block = append(block, strings.TrimPrefix(line, "# "))
	}
	if len(block) < 5 {
		t.Fatalf("no perUserSecrets example found (%d lines)", len(block))
	}
	got, err := loadPerUser(t, baseAllow+strings.Join(block, "\n")+"\n")
	if err != nil {
		t.Fatalf("example: %v", err)
	}
	if !got.Enabled || len(got.Mappings) != 1 || got.Mappings[0].Provider != "google" || got.Mappings[0].Agents[0] != "support-bot" || got.Mappings[0].Domains[0] != "gmail.googleapis.com" {
		t.Fatalf("example parsed as %+v", got)
	}
}
