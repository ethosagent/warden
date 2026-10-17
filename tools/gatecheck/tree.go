package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Tree is one checked-out version of the repository (the PR's base or head).
// Paths are repo-relative and slash-separated.
type Tree interface {
	Files() ([]string, error)
	Read(name string) ([]byte, error)
}

// dirTree is a Tree over a directory on disk.
type dirTree struct{ root string }

// skipDirs are never part of the comparison.
var skipDirs = map[string]bool{".git": true, "node_modules": true, "vendor": true}

func (d dirTree) Files() ([]string, error) {
	var out []string
	err := filepath.WalkDir(d.root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if skipDirs[e.Name()] && p != d.root {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.Type().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(d.root, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(out)
	return out, err
}

func (d dirTree) Read(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(d.root, filepath.FromSlash(name)))
}

// view caches reads of one tree and answers the questions the detectors ask.
type view struct {
	t     Tree
	files []string
	cache map[string]string
	// helpers memoises envHelpers per directory
	helpers map[string]map[string]bool
}

func newView(t Tree) (*view, error) {
	files, err := t.Files()
	if err != nil {
		return nil, err
	}
	return &view{t: t, files: files, cache: map[string]string{}}, nil
}

// text returns a file's content and whether the file exists.
func (v *view) text(name string) (string, bool) {
	if s, ok := v.cache[name]; ok {
		return s, true
	}
	if !v.has(name) {
		return "", false
	}
	b, err := v.t.Read(name)
	if err != nil {
		return "", false
	}
	v.cache[name] = string(b)
	return v.cache[name], true
}

func (v *view) has(name string) bool {
	i := sort.SearchStrings(v.files, name)
	return i < len(v.files) && v.files[i] == name
}

// match lists files for which keep returns true.
func (v *view) match(keep func(string) bool) []string {
	var out []string
	for _, f := range v.files {
		if keep(f) {
			out = append(out, f)
		}
	}
	return out
}

func isGoTest(f string) bool { return strings.HasSuffix(f, "_test.go") }
func isGo(f string) bool     { return strings.HasSuffix(f, ".go") }

func isWorkflow(f string) bool {
	return strings.HasPrefix(f, ".github/workflows/") && (strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml"))
}

// isCIFile is a workflow or a composite action: a file in which CI can override
// a gate setting or run the gate.
func isCIFile(f string) bool {
	yml := strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml")
	return yml && (strings.HasPrefix(f, ".github/workflows/") || strings.HasPrefix(f, ".github/actions/"))
}

func isGolangci(f string) bool {
	return strings.HasPrefix(f, ".golangci") && (strings.HasSuffix(f, ".yml") || strings.HasSuffix(f, ".yaml"))
}
