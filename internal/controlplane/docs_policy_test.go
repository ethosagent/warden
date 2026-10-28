package controlplane

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// The Policy history section of docs/control-plane.md (W-P1-PVER-12) names the
// flag, the CLI commands, the routes and the audit actions of the versioned
// policy store. These tests keep it from drifting from the code: every name the
// section must mention is resolved against the source or the authz table, and
// then looked up in the section (not the whole doc: the role matrix above it
// lists the routes too).

const (
	policyDocHeading = "## Policy history"
	cmdProxyDir      = "../../cmd/proxy/"
)

// policyHistoryDoc returns the Policy history section: from its heading to
// the next level-2 heading.
func policyHistoryDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(authzDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", authzDocPath, err)
	}
	doc := string(raw)
	start := strings.Index(doc, "\n"+policyDocHeading)
	if start < 0 {
		t.Fatalf("%s has no %q section", authzDocPath, policyDocHeading)
	}
	section := doc[start+1:]
	if end := strings.Index(section[len(policyDocHeading):], "\n## "); end >= 0 {
		section = section[:len(policyDocHeading)+end]
	}
	return section
}

// sourceContains reports whether the Go file at path holds every snippet.
func sourceContains(t *testing.T, path string, snippets ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, s := range snippets {
		if !strings.Contains(string(raw), s) {
			t.Errorf("%s no longer contains %q: update the Policy history docs and this test", path, s)
		}
	}
}

func TestPolicyHistoryDocsMentionSurface(t *testing.T) {
	doc := policyHistoryDoc(t)

	// The flag and its values exist in code.
	if PolicyStoreFile != "file" || PolicyStoreVersioned != "versioned" {
		t.Fatalf("--policy-store values are %q|%q; update the docs", PolicyStoreFile, PolicyStoreVersioned)
	}
	sourceContains(t, cmdProxyDir+"controlplane.go", `String("policy-store"`, `String("state-dir"`)
	// warden policy import|export: subcommands of the policy command.
	sourceContains(t, cmdProxyDir+"policy_import.go", `Use:   "import"`, `Use:   "export"`, `Int64("expected-head"`)
	sourceContains(t, cmdProxyDir+"root.go", "newPolicyImportCmd()", "newPolicyExportCmd()")

	// The history routes exist in the authz table (which TestAuthzRouteCoverage
	// ties to the dashboard's routes).
	table := authzTable()
	routes := []routeKey{
		{http.MethodGet, "/dashboard/api/policy/versions"},
		{http.MethodGet, "/dashboard/api/policy/versions/{v}"},
		{http.MethodGet, "/dashboard/api/policy/versions/{v}/diff"},
		{http.MethodPost, "/dashboard/api/policy/versions/{v}/rollback"},
	}
	for _, k := range routes {
		if _, ok := table[k]; !ok {
			t.Errorf("route %s %s is not in authzTable(); update the docs", k.Method, k.Path)
		}
	}

	for _, want := range []string{
		"--policy-store=file|versioned",
		"--state-dir",
		"`--policy-store=versioned`",
		"`--policy-store=file`",
		"warden policy import",
		"warden policy export",
		"--expected-head",
		"/dashboard/api/policy/versions",
		"/dashboard/api/policy/versions/{v}/diff",
		"/dashboard/api/policy/versions/{v}/rollback",
		"X-Warden-Policy-Version",
		"X-Warden-Policy-Message",
		`If-Match: "v<N>"`,
		"409",
		"428",
		"policy_conflict",
		"precondition_required",
		"drift",
		"policyVersion",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the Policy history section does not mention %q", want)
		}
	}

	// The three release-plan statements.
	for _, want := range []string{
		"**Release N** (the first release with policy history) ships the versioned\n  store only behind `--policy-store=versioned`; the default stays `file`.",
		"**Release N+1** flips the default to `versioned`. `--policy-store=file` stays\n  as an explicit opt-out, and a control plane started without `--state-dir`\n  keeps file mode with a startup WARN.",
		"**Release N+2** removes YAML as a policy source: `--policy-store=file` is\n  removed, the served YAML is only the write-through mirror of head, and hand\n  edits are never served",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the Policy history section lacks the release-plan statement %q", want)
		}
	}
}

func TestPolicyHistoryDocsAudit(t *testing.T) {
	doc := policyHistoryDoc(t)
	rollback := authzTable()[routeKey{http.MethodPost, "/dashboard/api/policy/versions/{v}/rollback"}].Action
	for _, action := range []string{actionPolicyInitialImport, rollback, actionPolicyImport, actionConfigExternalChange, "policy.write"} {
		if action == "" {
			t.Fatal("an audit action resolved to empty")
		}
		if !strings.Contains(doc, "`"+action+"`") {
			t.Errorf("the Policy history section does not name the audit action %q", action)
		}
	}
	if actionPolicyInitialImport != "policy.initial_import" || rollback != "policy.rollback" ||
		actionConfigExternalChange != "config.external_change" {
		t.Errorf("audit actions are %q, %q, %q; update the docs", actionPolicyInitialImport, rollback, actionConfigExternalChange)
	}
	for _, want := range []string{
		"Credentials appear in history only as\nfingerprints",
		"`sha256:<16 hex>`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the Policy history section does not state %q", want)
		}
	}
}

// blockListDoc returns the Block list section of docs/control-plane.md.
func blockListDoc(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(authzDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", authzDocPath, err)
	}
	const heading = "\n## Block list"
	start := strings.Index(string(raw), heading)
	if start < 0 {
		t.Fatalf("%s has no Block list section", authzDocPath)
	}
	section := string(raw)[start+1:]
	if end := strings.Index(section[len(heading)-1:], "\n## "); end >= 0 {
		section = section[:len(heading)-1+end]
	}
	return section
}

// TestBlockListDocsMentionBounds keeps the Block list section stating the cut
// semantics, the propagation bound, the gaps and the degraded modes.
func TestBlockListDocsMentionBounds(t *testing.T) {
	doc := blockListDoc(t)
	for _, want := range []string{
		"user_blocked",
		"arrived", "cut when the change is applied", "interrupts active streams",
		"about 1 s", "2 s", "15 s", "longPollWait",
		"No token, no match", "require",
		"Transparent mode", "X-Warden-Identity",
		"unreachable", "last list", "break-glass", "state_dir_required",
		"warden_blocklist_entries", "warden_blocklist_sessions_closed_total",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("Block list section does not mention %q", want)
		}
	}
}
