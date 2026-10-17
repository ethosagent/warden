package archtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testArchYAML = `
version: 1
classes:
  - id: assembly
    layer: assembly
    imported-by: ["cmd/**"]
    paths: ["cmd/**"]
  - id: domain
    layer: domain
    paths: ["internal/*"]
zones:
  data: ["internal/scan"]
  shared: ["internal/*"]
modules:
  direct:
    - module: golang.org/x/net
      layers: [engine]
  indirect:
    - github.com/kr/text
rules:
  - id: L3
    title: no I/O
    checker: golangci+archtest
    fix: inject it
    banned-imports: [net, net/http]
  - id: S1
    title: backends are validated
    checker: proxy
    test: internal/config/secretstore_test.go
    fix: validate the key
  - id: X6
    title: reasons are constants
    checker: planned
    reason: no reasons file exists
`

func TestLoadArchitecture(t *testing.T) {
	arch, err := LoadArchitecture([]byte(testArchYAML))
	if err != nil {
		t.Fatalf("LoadArchitecture: %v", err)
	}
	if arch.Version != 1 {
		t.Errorf("Version = %d, want 1", arch.Version)
	}
	if len(arch.Classes) != 2 {
		t.Fatalf("Classes = %d, want 2", len(arch.Classes))
	}
	if arch.Classes[0].ID != "assembly" || arch.Classes[0].Layer != "assembly" {
		t.Errorf("class 0 = %+v", arch.Classes[0])
	}
	if len(arch.Classes[0].ImportedBy) != 1 || arch.Classes[0].ImportedBy[0] != "cmd/**" {
		t.Errorf("ImportedBy = %v, want [cmd/**]", arch.Classes[0].ImportedBy)
	}
	l3 := arch.Rule("L3")
	if l3 == nil {
		t.Fatal("Rule(L3) = nil")
	}
	if len(l3.BannedImports) != 2 || l3.BannedImports[0] != "net" {
		t.Errorf("L3.BannedImports = %v", l3.BannedImports)
	}
	if len(arch.Modules.Direct) != 1 || arch.Modules.Direct[0].Module != "golang.org/x/net" {
		t.Errorf("Modules.Direct = %+v", arch.Modules.Direct)
	}
	if len(arch.Modules.Indirect) != 1 || arch.Modules.Indirect[0] != "github.com/kr/text" {
		t.Errorf("Modules.Indirect = %+v", arch.Modules.Indirect)
	}
}

func TestLoadArchitectureValidation(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string // substring of the error
	}{
		{"bad-version", strings.Replace(testArchYAML, "version: 1", "version: 2", 1), "version"},
		{"duplicate-rule", testArchYAML + "  - id: L3\n    title: again\n    checker: archtest\n    fix: x\n", "duplicate rule L3"},
		{"duplicate-class", strings.Replace(testArchYAML, "zones:", "  - id: assembly\n    layer: domain\n    paths: [\"other/**\"]\nzones:", 1), "duplicate class assembly"},
		{"unknown-checker", strings.Replace(testArchYAML, "checker: golangci+archtest", "checker: vibes", 1), "unknown checker"},
		{"proxy-needs-test", strings.Replace(testArchYAML, "    test: internal/config/secretstore_test.go\n", "", 1), "proxy rule S1 needs test"},
		{"planned-needs-reason", testArchYAML + "  - id: Y9\n    title: t\n    checker: planned\n", "planned rule Y9 needs reason"},
		{"enforced-needs-fix", strings.Replace(testArchYAML, "    fix: inject it\n", "", 1), "rule L3 needs fix"},
		{"unknown-applies-class", strings.Replace(testArchYAML, "banned-imports: [net, net/http]", "banned-imports: [net]\n    applies-to-classes: [engine]", 1), "unknown class engine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadArchitecture([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("LoadArchitecture succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestLoadArchitectureNotYAML(t *testing.T) {
	if _, err := LoadArchitecture([]byte("\tbroken: [")); err == nil {
		t.Fatal("LoadArchitecture succeeded on broken YAML")
	}
}

// TestArchitectureYAMLIsValid loads the repository's real architecture.yaml, so
// a typo there fails this package's tests and not just the checks it feeds.
func TestArchitectureYAMLIsValid(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "architecture.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	arch, err := LoadArchitecture(data)
	if err != nil {
		t.Fatalf("architecture.yaml does not parse: %v", err)
	}
	if got := len(arch.Rules); got < 30 {
		t.Errorf("architecture.yaml declares %d rules, want the full issue #349 set (>= 30)", got)
	}
	for _, id := range []string{"L1", "L2", "L3", "L4", "L4a", "L4b", "L5", "L6", "L7", "L8",
		"S1", "S2", "S3", "S4", "S5", "Z1", "Z2", "Z3", "Z4",
		"X1", "X2", "X3", "X4", "X5", "X6", "X7", "X8", "X9", "C1", "C2", "C3", "C4"} {
		if arch.Rule(id) == nil {
			t.Errorf("architecture.yaml is missing rule %s", id)
		}
	}
}

func TestMatcher(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"internal/*", "internal/policy", true},
		{"internal/*", "internal/policy/sub", false},
		{"internal/*", "internal", false},
		{"internal/proxy/**", "internal/proxy", true},
		{"internal/proxy/**", "internal/proxy/safedial.go", true},
		{"internal/proxy/**", "internal/proxy/sub/x.go", true},
		{"internal/proxy/**", "internal/policy", false},
		{"cmd/**", "cmd/proxy", true},
		{"cmd/**", "cmd", true},
		{"cmd/**", "cmdx/proxy", false},
		{"internal/*/adapters/**", "internal/policy/adapters/store", true},
		{"internal/*/adapters/**", "internal/policy/adapters/store/sub", true},
		{"internal/*/adapters/**", "internal/policy", false},
		{"**", "anything/at/all", true},
		{"internal/*/http/**", "internal/admin/http/api", true},
		{"test/**", "test/fakes", true},
		{"test/**", "testing", false},
	}
	var m matcher
	for _, tc := range cases {
		if got := m.match(tc.glob, tc.path); got != tc.want {
			t.Errorf("match(%q, %q) = %v, want %v", tc.glob, tc.path, got, tc.want)
		}
	}
}
