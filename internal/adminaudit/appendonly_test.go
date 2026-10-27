package adminaudit

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoUpdateOrDeleteStatements enforces the append-only rule: no non-test
// file in this package issues UPDATE or DELETE on admin_audit or
// admin_audit_actor. (P5 retention is the only later writer allowed to
// delete, and it will change this test explicitly.)
func TestNoUpdateOrDeleteStatements(t *testing.T) {
	banned := regexp.MustCompile(`(?i)(UPDATE\s+admin_audit|DELETE\s+FROM\s+admin_audit|REPLACE\s+INTO\s+admin_audit|INSERT\s+OR\s+REPLACE)`)
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	scanned := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if m := banned.Find(b); m != nil {
			t.Errorf("%s contains %q: the admin audit tables are append-only", f, m)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source files")
	}
}
