package archtest

import (
	"strings"
	"testing"
)

func TestLoadBaseline(t *testing.T) {
	data := `
# architecture.baseline.yaml
baseline:
  - rule: L2
    package: internal/controlplane
    why: mounts the worker assembly today
    allow: [example.com/x/internal/worker]

  - rule: X3
    package: cmd/proxy
    why: the MCP spawn is still in cmd/
`
	b, err := LoadBaseline([]byte(data), mustArch(t, testArch))
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("Entries = %d, want 2", len(b.Entries))
	}
	e := b.Entries[0]
	if e.Rule != "L2" || e.Package != "internal/controlplane" || !strings.Contains(e.Why, "worker assembly") {
		t.Errorf("entry 0 = %+v", e)
	}
	if want := []string{"example.com/x/internal/worker"}; len(e.Allow) != 1 || e.Allow[0] != want[0] {
		t.Errorf("entry 0 allow = %v, want %v", e.Allow, want)
	}
	// Line numbers point at the entry's rule key, so a stale entry can be
	// reported with a location in the baseline file itself.
	if e.Line != 4 {
		t.Errorf("entry 0 line = %d, want 4", e.Line)
	}
	if b.Entries[1].Line != 9 {
		t.Errorf("entry 1 line = %d, want 9", b.Entries[1].Line)
	}
	if b.find("L2", "internal/controlplane") == nil {
		t.Error("find(L2, internal/controlplane) = nil")
	}
	if b.find("L2", "internal/worker") != nil {
		t.Error("find(L2, internal/worker) is not nil")
	}
}

func TestLoadBaselineValidation(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
	}{
		{"missing-rule", "baseline:\n  - package: internal/x\n", "needs rule"},
		{"missing-package", "baseline:\n  - rule: L2\n", "needs package"},
		{"unknown-rule", "baseline:\n  - rule: NOPE\n    package: internal/x\n", "rule NOPE is not declared in architecture.yaml"},
		{"duplicate-entry", "baseline:\n  - rule: L2\n    package: internal/x\n  - rule: L2\n    package: internal/x\n", "duplicate entry (L2, internal/x)"},
		{"empty-allow-item", "baseline:\n  - rule: L2\n    package: internal/x\n    allow: [\"\"]\n", "empty allow item"},
		{"broken-yaml", "baseline:\n  - [", "baseline.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadBaseline([]byte(tc.data), mustArch(t, testArch))
			if err == nil {
				t.Fatalf("LoadBaseline succeeded, want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// mustArch parses archYAML or fails the test.
func mustArch(t *testing.T, archYAML string) *Architecture {
	t.Helper()
	arch, err := LoadArchitecture([]byte(archYAML))
	if err != nil {
		t.Fatalf("architecture: %v", err)
	}
	return arch
}
