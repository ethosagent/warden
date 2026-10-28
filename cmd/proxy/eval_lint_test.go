package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvalCmd_LintWarnings: a scoped entry shadowed by an unscoped wildcard
// prints a "warning:" line before the replay report, exits 0, and the warning
// carries no group or user value.
func TestEvalCmd_LintWarnings(t *testing.T) {
	candidate := writeTempConfig(t, `
policy:
  allowlist:
    - domain: "*.github.com"
    - domain: api.github.com
      groups: [secret-group]
      users: [victim@corp.example]
logging:
  level: error
  format: json
`)
	var out bytes.Buffer
	root := newRootCmd()
	root.SetArgs([]string{"policy", "eval", "--candidate", candidate, "--db", filepath.Join(t.TempDir(), "warden.db")})
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("eval must exit 0 on warnings: %v", err)
	}
	s := out.String()
	want := "warning: allowlist[1] (api.github.com, groups+users) is shadowed by allowlist[0] (*.github.com), which admits everyone"
	w, r := strings.Index(s, want), strings.Index(s, "Policy Evaluation Report")
	if w < 0 || r < 0 || w > r {
		t.Fatalf("want warning before the report, got:\n%s", s)
	}
	if strings.Contains(s, "secret-group") || strings.Contains(s, "victim@") {
		t.Errorf("output leaks a principal value:\n%s", s)
	}
}
