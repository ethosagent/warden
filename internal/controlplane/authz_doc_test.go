package controlplane

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

var updateAuthzDoc = flag.Bool("update", false, "rewrite the role matrix in docs/control-plane.md from authzTable()")

const (
	authzDocPath  = "../../docs/control-plane.md"
	authzDocStart = "<!-- authz-matrix:start -->"
	authzDocEnd   = "<!-- authz-matrix:end -->"
)

// renderAuthzMatrix renders the role matrix section of docs/control-plane.md:
// one row per authz table entry (sorted by path, then GET, POST, PUT, DELETE),
// then the per-field settings rules and the query/generate rate limit. It is
// the single generator; TestAuthzMatrixDoc compares the doc against it.
func renderAuthzMatrix(table map[routeKey]authzRow) string {
	methodOrder := map[string]int{http.MethodGet: 0, http.MethodPost: 1, http.MethodPut: 2, http.MethodPatch: 3, http.MethodDelete: 4}
	keys := make([]routeKey, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Path != keys[j].Path {
			return keys[i].Path < keys[j].Path
		}
		return methodOrder[keys[i].Method] < methodOrder[keys[j].Method]
	})
	code := func(s string) string { return "`" + s + "`" }
	codes := func(ss []string) string {
		out := make([]string, len(ss))
		for i, s := range ss {
			out[i] = code(s)
		}
		return strings.Join(out, ", ")
	}

	var b strings.Builder
	b.WriteString("<!-- Generated from authzTable() and internal/config/settings_roles.go; do not edit by hand.\n")
	b.WriteString("     Regenerate: go test ./internal/controlplane -run TestAuthzMatrixDoc -update -->\n\n")
	b.WriteString("| Route | Method | Minimum role | Action |\n|---|---|---|---|\n")
	for _, k := range keys {
		r := table[k]
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", code(k.Path), k.Method, r.MinRole, code(r.Action))
	}
	b.WriteString("\nA method and path with no row is refused (`403`) for every role, `GET` included.\n\n")
	b.WriteString("Settings writes (`POST`/`PUT /dashboard/api/settings`) are then checked per changed field:\n\n")
	fmt.Fprintf(&b, "- An editor may change only %s.\n", codes(config.EditorSettingsFields()))
	fmt.Fprintf(&b, "- Inside those, these subfields still need admin (list elements are matched by `id`): %s.\n", codes(config.AdminSettingsSubfields()))
	b.WriteString("- Every other field needs admin, including any field added later.\n\n")
	fmt.Fprintf(&b, "`POST %s` is limited to %d calls a minute per console session (`429` past it).\n", queryGeneratePath, queryGenerateLimit)
	return b.String()
}

// docMatrix returns the text between the authz-matrix markers in doc, trimmed
// of the newline after the start marker.
func docMatrix(t *testing.T, doc string) (string, int, int) {
	t.Helper()
	a, b := strings.Index(doc, authzDocStart), strings.Index(doc, authzDocEnd)
	if a < 0 || b < a {
		t.Fatalf("%s: %s / %s markers not found", authzDocPath, authzDocStart, authzDocEnd)
	}
	a += len(authzDocStart)
	return strings.TrimPrefix(doc[a:b], "\n"), a, b
}

// TestAuthzMatrixDoc keeps the role matrix in docs/control-plane.md equal to
// the one generated from authzTable() and the settings field rules. Run with
// -update to rewrite it after changing the table.
func TestAuthzMatrixDoc(t *testing.T) {
	raw, err := os.ReadFile(authzDocPath)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	want := renderAuthzMatrix(authzTable())
	got, a, b := docMatrix(t, doc)

	if *updateAuthzDoc && got != want {
		doc = doc[:a] + "\n" + want + doc[b:]
		if err := os.WriteFile(authzDocPath, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		got = want
	}
	if got != want {
		t.Errorf("%s role matrix is stale; run: go test ./internal/controlplane -run TestAuthzMatrixDoc -update\n--- doc\n%s\n--- generated\n%s", authzDocPath, got, want)
	}

	// The check is not vacuous: one more row in the table changes the output.
	t.Run("added_row_is_detected", func(t *testing.T) {
		table := authzTable()
		table[routeKey{http.MethodPost, "/dashboard/api/new-thing"}] = authzRow{MinRole: config.RoleAdmin, Action: "new.write"}
		if renderAuthzMatrix(table) == got {
			t.Fatal("adding a row to the authz table did not change the generated matrix")
		}
	})
	// Every table row appears in the doc.
	for k, r := range authzTable() {
		row := fmt.Sprintf("| `%s` | %s | %s | `%s` |", k.Path, k.Method, r.MinRole, r.Action)
		if !strings.Contains(got, row) {
			t.Errorf("doc matrix missing row %s", row)
		}
	}
}
