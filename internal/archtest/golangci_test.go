package archtest

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// golangciArch is the architecture the renderer tests run against: one rule
// per generated-config shape (class-scoped, zone-filtered, global, carve-outs)
// plus L6, whose import ban must stay out of the golangci config because its
// checker is archtest.
const golangciArch = `
version: 1
classes:
  - id: assembly
    layer: assembly
    imported-by: ["cmd/**"]
    paths: ["cmd/**"]
  - id: engine
    layer: engine
    paths: ["eng"]
  - id: decision
    layer: decision
    paths: ["dpkg"]
  - id: domain
    layer: domain
    paths: ["web/**", "wpkg", "one/*"]
zones:
  control: ["web/**", "wpkg", "dpkg", "cmd/**"]
  data: ["eng"]
  shared: ["sh"]
rules:
  - id: L3
    checker: golangci+archtest
    fix: inject the I/O
    banned-imports: [net/http, os]
    banned-calls: ["time.Now"]
    applies-to-classes: [domain, decision]
    # no references-too: assigning time.Now is the sanctioned clock injection
  - id: L4
    checker: golangci+archtest
    fix: adapter it
    banned-imports: [os/exec]
    applies-to-classes: [domain]
    zone-filter: control
  - id: X8
    checker: golangci+archtest
    fix: inject randomness
    banned-imports: [math/rand]
    except-tests: true
  - id: X1
    checker: golangci+archtest
    fix: sign in the signer adapter
    banned-calls: ["crypto/ed25519.Sign"]
    references-too: true
    signer-paths: ["web/**/signer/**"]
  - id: X7
    checker: golangci+archtest
    fix: use the structured logger
    banned-calls: ["fmt.Println"]
    references-too: true
    applies-to-paths: ["internal/**"]
  - id: L6
    checker: archtest
    fix: call a domain service
    banned-imports: [database/sql]
  - id: C1
    checker: golangci+archtest
    fix: move it into internal/
    banned-imports: [database/sql]
    applies-to-paths: ["cmd/**"]
  - id: C2
    checker: golangci+archtest
    fix: use the pure-Go driver
    blocked-modules:
      - module: github.com/mattn/go-sqlite3
        reason: CGo SQLite is banned
modules:
  direct:
    - module: example.com/dep
      layers: [repository]
  indirect: [example.com/ind]
`

const golangciBase = `
version: "2"
linters:
  enable:
    - staticcheck
  exclusions:
    rules:
      - path: _test\.go
        linters: [errcheck]
formatters:
  enable: [gofmt]
`

// TestGenerateGolangCI checks the merged config the renderer produces: the
// base config survives, the three architecture linters are added, and every
// generated entry carries its rule ID.
func TestGenerateGolangCI(t *testing.T) {
	arch, err := LoadArchitecture([]byte(golangciArch))
	if err != nil {
		t.Fatal(err)
	}
	base, err := LoadBaseline([]byte("baseline:\n  - rule: L3\n    package: web/thing\n    why: legacy\n"), arch)
	if err != nil {
		t.Fatal(err)
	}
	out, err := GenerateGolangCI(arch, []byte(golangciBase), base)
	if err != nil {
		t.Fatal(err)
	}

	var cfg genConfig
	if err := yaml.NewDecoder(bytes.NewReader(out)).Decode(&cfg); err != nil {
		t.Fatalf("generated config is not valid YAML: %v\n%s", err, out)
	}
	if cfg.Version != "2" {
		t.Errorf("version = %q, want the base's \"2\"", cfg.Version)
	}
	if cfg.Formatters == nil {
		t.Error("formatters section lost in the merge")
	}
	// Path rendering must not depend on how golangci-lint was invoked: the
	// exclusions and depguard globs are module-root anchored, so the mode is
	// pinned to the module (go.mod) directory.
	if cfg.Run.RelativePathMode != "gomod" {
		t.Errorf("run.relative-path-mode = %q, want gomod (paths anchored to the module root)", cfg.Run.RelativePathMode)
	}

	// enable: the base's linters stay, the three architecture linters join.
	wantEnable := []string{"staticcheck", "depguard", "forbidigo", "gomodguard_v2"}
	if strings.Join(cfg.Linters.Enable, ",") != strings.Join(wantEnable, ",") {
		t.Errorf("enable = %v, want %v", cfg.Linters.Enable, wantEnable)
	}

	// depguard: one rule per golangci-checked banned-imports rule. L6's ban is
	// archtest-only and must not appear.
	deprules := cfg.Linters.Settings.Depguard.Rules
	if _, ok := deprules["L6"]; ok {
		t.Error("L6 is archtest-checked but appears in depguard")
	}
	for _, id := range []string{"L3", "L4", "X8", "C1"} {
		if _, ok := deprules[id]; !ok {
			t.Errorf("depguard has no rule %s", id)
		}
	}
	l3 := deprules["L3"]
	// domain+decision file globs; L4 additionally excludes the data and shared
	// zones (its zone-filter is control); every list skips test files.
	wantL3Files := []string{"${base-path}/web/**", "${base-path}/wpkg/**", "${base-path}/one/*/*.go", "${base-path}/dpkg/**", "!${base-path}/cmd/**", "!${base-path}/eng/**", "!**/*_test.go"}
	if strings.Join(l3.Files, ",") != strings.Join(wantL3Files, ",") {
		t.Errorf("L3 files = %v, want %v", l3.Files, wantL3Files)
	}
	wantL4Files := []string{"${base-path}/web/**", "${base-path}/wpkg/**", "${base-path}/one/*/*.go", "!${base-path}/cmd/**", "!${base-path}/eng/**", "!${base-path}/dpkg/**", "!${base-path}/sh/**", "!**/*_test.go"}
	if got := deprules["L4"].Files; strings.Join(got, ",") != strings.Join(wantL4Files, ",") {
		t.Errorf("L4 files = %v, want %v", got, wantL4Files)
	}
	wantX8Files := []string{"!**/*_test.go"}
	if got := deprules["X8"].Files; strings.Join(got, ",") != strings.Join(wantX8Files, ",") {
		t.Errorf("X8 files = %v, want %v", got, wantX8Files)
	}
	wantC1Files := []string{"${base-path}/cmd/**", "!**/*_test.go"}
	if got := deprules["C1"].Files; strings.Join(got, ",") != strings.Join(wantC1Files, ",") {
		t.Errorf("C1 files = %v, want %v", got, wantC1Files)
	}
	if len(l3.Deny) != 2 {
		t.Fatalf("L3 deny = %v, want one entry per banned import", l3.Deny)
	}
	if l3.Deny[0].Pkg != "net/http" || !strings.HasPrefix(l3.Deny[0].Desc, "L3:") {
		t.Errorf("L3 deny[0] = %v, want net/http with an L3-prefixed desc", l3.Deny[0])
	}

	// forbidigo: type-analyzed patterns, every message carrying the rule ID.
	fb := cfg.Linters.Settings.Forbidigo
	if !fb.AnalyzeTypes {
		t.Error("forbidigo analyze-types is off — an import alias would evade the ban")
	}
	var patterns []string
	for _, f := range fb.Forbid {
		patterns = append(patterns, f.Pattern)
		if !strings.HasPrefix(f.Msg, "X") && !strings.HasPrefix(f.Msg, "L") {
			t.Errorf("forbid pattern %q has no rule ID in msg %q", f.Pattern, f.Msg)
		}
	}
	wantPatterns := []string{"^ed25519\\.Sign$", "^fmt\\.Println$"}
	if strings.Join(patterns, ",") != strings.Join(wantPatterns, ",") {
		t.Errorf("forbid patterns = %v, want %v", patterns, wantPatterns)
	}
	// The package regexp pins the name to its import path.
	for _, f := range fb.Forbid {
		if f.Pkg == "" {
			t.Errorf("forbid pattern %q has no pkg regexp", f.Pattern)
		}
	}
	if fb.Forbid[0].Pkg != "^crypto/ed25519$" {
		t.Errorf("ed25519.Sign pkg = %q, want ^crypto/ed25519$", fb.Forbid[0].Pkg)
	}

	// gomodguard_v2: the manifest is the allowlist, C2's modules the blocklist.
	gmg := cfg.Linters.Settings.GomodguardV2
	if len(gmg.Allowed) != 1 || gmg.Allowed[0].Module != "example.com/dep" {
		t.Errorf("gomodguard allowed = %v, want the manifest", gmg.Allowed)
	}
	if len(gmg.Blocked) != 1 || gmg.Blocked[0].Module != "github.com/mattn/go-sqlite3" || gmg.Blocked[0].Reason == "" {
		t.Errorf("gomodguard blocked = %v, want C2's module with its reason", gmg.Blocked)
	}

	// exclusions: the base's own rule survives, then the architecture's.
	// L3 has no references-too, so it contributes no forbidigo pattern and no
	// scope exclusion of its own.
	rules := cfg.Linters.Exclusions.Rules
	if len(rules) != 5 {
		t.Fatalf("exclusions.rules = %d entries, want 5:\n%s", len(rules), out)
	}
	find := func(text string) exclusionRule {
		t.Helper()
		for _, r := range rules {
			if r.Text == text {
				return r
			}
		}
		t.Fatalf("no exclusion with text %q in %+v", text, rules)
		return exclusionRule{}
	}
	var errcheck, testfiles int
	for _, r := range rules {
		if r.Text == "" && r.Path == `_test\.go` {
			errcheck++ // the base config's own rule
		}
		if r.Text == "" && r.Path == `_test\.go$` {
			testfiles++
		}
	}
	if errcheck != 1 || testfiles != 1 {
		t.Errorf("base errcheck rule kept %d×, forbidigo test-file exclusion %d×, want 1 each", errcheck, testfiles)
	}
	signer := find("X1:")
	if signer.Path != `^web/.*/signer(/.*)?/[^/]*\.go$` || signer.PathExcept != "" {
		t.Errorf("X1 signer exclusion = %+v", signer)
	}
	x7 := find("X7:")
	if x7.PathExcept != `^internal(/.*)?/[^/]*\.go$` {
		t.Errorf("X7 exclusion = %+v, want path-except internal/**", x7)
	}
	// One L3: entry — the baseline suppression of a single package. Its scope
	// exclusion must not exist: L3 bans no golangci-checked references.
	for _, r := range rules {
		if r.Text == "L3:" && r.PathExcept != "" {
			t.Errorf("L3 has no forbidigo patterns but has a scope exclusion %+v", r)
		}
	}
	if bl := find("L3:"); bl.Path != `^web/thing/[^/]*\.go$` || strings.Join(bl.Linters, ",") != "depguard,forbidigo" {
		t.Errorf("baseline exclusion = %+v, want the baselined package with depguard+forbidigo", bl)
	}
}

// TestAnyPathRegexpFileScope pins the scope regexps to FILE paths with the
// engine's package semantics: a plain class path covers exactly that package's
// files (not its subpackages, which classify separately), a ** tree covers the
// files of the whole subtree.
func TestAnyPathRegexpFileScope(t *testing.T) {
	re := regexp.MustCompile(anyPathRegexp([]string{"dpkg", "internal/mcp", "web/**"}))
	for _, hit := range []string{"dpkg/scan.go", "internal/mcp/protocol.go", "web/thing/thing.go", "web/deep/thing.go"} {
		if !re.MatchString(hit) {
			t.Errorf("%s: regexp %s does not match %q", "in scope", re, hit)
		}
	}
	for _, miss := range []string{"dpkg/sub/x.go", "internal/mcp/gateway/x.go", "webx.go", "dpkg", "wpkg/scan.go"} {
		if re.MatchString(miss) {
			t.Errorf("%s: regexp %s matches %q", "out of scope", re, miss)
		}
	}
}

// TestGenerateGolangCIMinimal: nothing golangci-checked and no baseline — the
// base config must come through untouched (no empty linters sections).
func TestGenerateGolangCIMinimal(t *testing.T) {
	arch, err := LoadArchitecture([]byte(`
version: 1
classes:
  - id: domain
    layer: domain
    paths: ["a"]
zones:
  shared: ["a"]
rules:
  - id: L1
    checker: archtest
    fix: depend on the port
modules:
  direct:
    - module: example.com/dep
      layers: [repository]
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := GenerateGolangCI(arch, []byte(golangciBase), nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg genConfig
	if err := yaml.NewDecoder(bytes.NewReader(out)).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Linters.Enable) != 1 || cfg.Linters.Enable[0] != "staticcheck" {
		t.Errorf("enable = %v, want the base's list untouched", cfg.Linters.Enable)
	}
	if s := cfg.Linters.Settings; len(s.Depguard.Rules) != 0 || len(s.Forbidigo.Forbid) != 0 ||
		len(s.GomodguardV2.Allowed) != 0 || len(s.GomodguardV2.Blocked) != 0 {
		t.Errorf("settings = %+v, want none", s)
	}
	if len(cfg.Linters.Exclusions.Rules) != 1 {
		t.Errorf("exclusions.rules = %+v, want the base's entry only", cfg.Linters.Exclusions.Rules)
	}
}

// genConfig mirrors the parts of the generated config the tests assert on.
type genConfig struct {
	Version    string `yaml:"version"`
	Formatters map[string]any
	Run        struct {
		RelativePathMode string `yaml:"relative-path-mode"`
	} `yaml:"run"`
	Linters struct {
		Enable     []string `yaml:"enable"`
		Settings   genSettings
		Exclusions struct {
			Rules []exclusionRule `yaml:"rules"`
		} `yaml:"exclusions"`
	} `yaml:"linters"`
}

type genSettings struct {
	Depguard     depguardSettings   `yaml:"depguard"`
	Forbidigo    forbidigoSettings  `yaml:"forbidigo"`
	GomodguardV2 gomodguardSettings `yaml:"gomodguard_v2"`
}
