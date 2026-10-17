package archtest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestFixtures runs the per-acceptance-criterion fixtures under
// testdata/cases. Each directory is a miniature module: its Go files are the
// violation (or the allowed shape), and archtest.json names the exact rule,
// file and line the gate must report — plus any class/zone overrides, skipped
// rules and baseline entries the case needs.
func TestFixtures(t *testing.T) {
	entries, err := os.ReadDir("testdata/cases")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			runFixture(t, filepath.Join("testdata/cases", e.Name()))
		})
	}
}

// caseSpec is the archtest.json of one fixture case.
type caseSpec struct {
	// X2 keeps the test architecture's structs entry; cases that do not ship
	// the w/cfgx package must drop it — a structs entry whose package is not
	// in the run is a hard gate-input error by design.
	X2        bool `json:"x2"`
	Overrides map[string]struct {
		Class  string `json:"class"`
		Zone   string `json:"zone"`
		Domain string `json:"domain"`
	} `json:"overrides"`
	Baseline []struct {
		Rule    string   `json:"rule"`
		Package string   `json:"package"`
		Why     string   `json:"why"`
		Allow   []string `json:"allow"`
	} `json:"baseline"`
	Want []struct {
		Rule string `json:"rule"`
		File string `json:"file"`
		Line int    `json:"line"`
	} `json:"want"`
}

func runFixture(t *testing.T, dir string) {
	t.Helper()
	specData, err := os.ReadFile(filepath.Join(dir, "archtest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec caseSpec
	if err := json.Unmarshal(specData, &spec); err != nil {
		t.Fatalf("archtest.json: %v", err)
	}

	// Lay the case out as its own module (fixtures import fixture/...), so go
	// list sees exactly what the case ships.
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module fixture\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == "archtest.json" {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}

	archYAML := testArchNoX2
	if spec.X2 {
		archYAML = testArch
	}
	arch, err := LoadArchitecture([]byte(archYAML))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	var base *Baseline
	if len(spec.Baseline) > 0 {
		var buf bytes.Buffer
		buf.WriteString("baseline:\n")
		for _, e := range spec.Baseline {
			fmt.Fprintf(&buf, "  - rule: %s\n    package: %s\n", e.Rule, e.Package)
			if e.Why != "" {
				fmt.Fprintf(&buf, "    why: %s\n", strconv.Quote(e.Why))
			}
			if len(e.Allow) > 0 {
				fmt.Fprintf(&buf, "    allow: [%s]\n", strings.Join(e.Allow, ", "))
			}
		}
		if base, err = LoadBaseline(buf.Bytes(), arch); err != nil {
			t.Fatal(err)
		}
	}
	eng := NewEngine(arch, "fixture", base)
	eng.SkipRules = map[string]bool{"C3": true} // fixture packages do not all carry tests
	eng.Overrides = map[string]Override{}
	for path, o := range spec.Overrides {
		eng.Overrides[path] = Override{Class: o.Class, Zone: o.Zone, Domain: o.Domain}
	}
	var wants []want
	for _, w := range spec.Want {
		wants = append(wants, want{w.Rule, w.File, w.Line})
	}
	assertFindings(t, eng.Run(pkgs), wants...)
}
