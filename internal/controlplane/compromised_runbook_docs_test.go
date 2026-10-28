package controlplane

import (
	"os"
	"strings"
	"testing"
)

// The compromised-token runbook in docs/control-plane.md (W-P1-WTOK-06, the
// review addendum on #236) names the revoke route and command, the symptoms a
// revoked worker shows, the replacement command and the fleet field that spots
// a leak. The test keeps each of those from drifting from the code.
func TestCompromisedTokenRunbookDocs(t *testing.T) {
	raw, err := os.ReadFile(authzDocPath)
	if err != nil {
		t.Fatalf("read %s: %v", authzDocPath, err)
	}
	doc := string(raw)
	const heading = "### Compromised-token runbook"
	start := strings.Index(doc, "\n"+heading)
	if start < 0 {
		t.Fatalf("%s has no %q section", authzDocPath, heading)
	}
	section := doc[start+1:]
	if end := strings.Index(section[len(heading):], "\n#"); end >= 0 {
		section = section[:len(heading)+end]
	}

	section = strings.Join(strings.Fields(section), " ") // the list items wrap
	for _, want := range []string{
		"DELETE /dashboard/api/worker-tokens/{id}",
		"warden control-plane token revoke",
		"`/policy`",
		"`/control/heartbeat`",
		"`401`",
		"last-known-good",
		"default-deny",
		"warden control-plane token create",
		"At most 2 tokens may be active per proxy id",
		"tokenLastUsed",
		"last_used_at",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("runbook lacks %q", want)
		}
	}

	// What the runbook names exists in the code.
	sourceContains(t, cmdProxyDir+"controlplane_token.go", `Use:   "revoke"`, `Use:   "create"`)
	sourceContains(t, "authz.go", `{del, "/dashboard/api/worker-tokens/{id}"`)
	sourceContains(t, "../dashboard/dashboard.go", `json:"tokenLastUsed,omitempty"`)
}
