package identity_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var providerWord = regexp.MustCompile(`(?i)\bdex\b`)

// scanProvider returns "file:line" for every line of a non-test .go file under
// root/dirs that names one specific identity provider as a whole word.
func scanProvider(root string, dirs ...string) []string {
	var hits []string
	for _, d := range dirs {
		_ = filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if e.IsDir() {
				if e.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			for i, line := range strings.Split(string(b), "\n") {
				if providerWord.MatchString(line) {
					rel, _ := filepath.Rel(root, p)
					hits = append(hits, fmt.Sprintf("%s:%d", rel, i+1))
				}
			}
			return nil
		})
	}
	return hits
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func TestNoProviderSpecificCode(t *testing.T) {
	if hits := scanProvider(repoRoot(t), "internal", "cmd"); len(hits) > 0 {
		t.Fatalf("provider-specific name in non-test code (code must stay IdP-neutral):\n%s", strings.Join(hits, "\n"))
	}
}

func TestNoProviderSpecificCodeDetects(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "x")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "package x\n\n// talk to Dex\nvar dexClient = 1\nvar s = \"DEX\"\nvar index = 2\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	hits := scanProvider(root, "internal")
	if len(hits) != 2 {
		t.Fatalf("hits = %v, want lines 3 and 5", hits)
	}
}
