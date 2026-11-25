package apikeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestScopesDocumented pins docs/control-plane.md to the registry: the "API key
// scopes" table in the API keys section has one row per registered P2 scope,
// naming the scope's minimum console role, and no row for a scope that is not
// registered. A new scope fails here until its row is written.
func TestScopesDocumented(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "control-plane.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, after, ok := strings.Cut(string(raw), "<!-- api-key-scopes:start -->")
	if !ok {
		t.Fatal("docs/control-plane.md has no api-key-scopes table")
	}
	table, _, ok := strings.Cut(after, "<!-- api-key-scopes:end -->")
	if !ok {
		t.Fatal("docs/control-plane.md api-key-scopes table is not closed")
	}
	rows := map[Scope]string{}
	for _, line := range strings.Split(table, "\n") {
		cells := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		if len(cells) < 3 || !strings.HasPrefix(strings.TrimSpace(cells[0]), "`") {
			continue
		}
		rows[Scope(strings.Trim(strings.TrimSpace(cells[0]), "`"))] = strings.TrimSpace(cells[1])
	}
	reg := NewP2Registry()
	for _, s := range reg.Registered() {
		role, _ := reg.Lookup(s)
		got, ok := rows[s]
		if !ok {
			t.Errorf("scope %s is registered but has no row in the docs scope table", s)
			continue
		}
		if got != role.String() {
			t.Errorf("scope %s documented at role %q, registered at %q", s, got, role)
		}
		delete(rows, s)
	}
	for s := range rows {
		t.Errorf("docs scope table lists %s, which is not registered", s)
	}
}
