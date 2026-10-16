package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Package is one Go package as the rules see it: its import graph entry (from
// go list) plus the parsed ASTs of its files. Path is module-relative — the
// form architecture.yaml's globs use.
type Package struct {
	ImportPath string
	Path       string // module-relative
	Dir        string // absolute
	Name       string
	Imports    []string // import paths of the non-test files, sorted

	Files     []*File // non-test files
	TestFiles []*File // in-package and external test files

	// Classification, filled in by the engine: the matched class, the matched
	// zone name, and the package's domain root (for the own-domain carve-outs).
	Class  *Class
	Zone   string
	Domain string

	// Fset backs the position of every File AST.
	Fset *token.FileSet
}

// File is one parsed source file. Imports maps the local name the file's code
// uses for each import (alias, or the last path segment when unaliased) to the
// import path, so a selector like sign.Sign resolves to crypto/ed25519 no
// matter what the alias is.
type File struct {
	Name       string // repo-relative, /-separated
	AST        *ast.File
	Line       int // line of the package clause
	Imports    map[string]string
	DotImports []string // import paths imported with "."
	Test       bool
}

// listedPkg is the slice of `go list -json` the loader consumes.
type listedPkg struct {
	ImportPath   string
	Dir          string
	Name         string
	Imports      []string
	GoFiles      []string
	TestGoFiles  []string
	XTestGoFiles []string
	Error        *struct {
		Err string
	}
}

// LoadPackages lists the given package directories with the go tool and parses
// their files. Test files are included: the checker also wants the imports and
// code inside _test.go (testutil guards, os.Environ). Dirs may be absolute or
// relative to root; "./..." style patterns are passed through to go list.
func LoadPackages(root string, dirs ...string) ([]*Package, error) {
	if abs, err := filepath.Abs(root); err == nil {
		root = abs // file names are reported relative to the module root
	}
	module, err := moduleOf(root)
	if err != nil {
		return nil, err
	}
	args := append([]string{
		"list", "-e", "-tags=integration",
		"-json=ImportPath,Dir,Name,Imports,GoFiles,TestGoFiles,XTestGoFiles",
		"--",
	}, dirs...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("go list: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	var pkgs []*Package
	fset := token.NewFileSet()
	for {
		var lp listedPkg
		if err := dec.Decode(&lp); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("go list output: %w", err)
		}
		p, err := newPackage(root, module, fset, &lp)
		if err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Path < pkgs[j].Path })
	return pkgs, nil
}

func newPackage(root, module string, fset *token.FileSet, lp *listedPkg) (*Package, error) {
	// go list -e still prints an entry for a package it cannot load, but with
	// no Dir and no files. (An unresolvable import — a banned third-party
	// module in a fixture — keeps Dir and GoFiles, and the AST checks below
	// still see the import, so those are tolerated on purpose.)
	if lp.Dir == "" {
		if lp.Error != nil {
			return nil, fmt.Errorf("go list: %s", lp.Error.Err)
		}
		return nil, fmt.Errorf("go list: cannot load %q", lp.ImportPath)
	}
	p := &Package{
		ImportPath: lp.ImportPath,
		Path:       strings.TrimPrefix(strings.TrimPrefix(lp.ImportPath, module), "/"),
		Dir:        lp.Dir,
		Name:       lp.Name,
		Imports:    append([]string{}, lp.Imports...),
		Fset:       fset,
	}
	sort.Strings(p.Imports)
	add := func(names []string, test bool) error {
		for _, name := range names {
			abs := filepath.Join(lp.Dir, name)
			af, err := parser.ParseFile(fset, abs, nil, parser.SkipObjectResolution)
			if af == nil {
				return fmt.Errorf("parse %s: %w", abs, err)
			}
			f := &File{Name: filepath.ToSlash(strings.TrimPrefix(strings.TrimPrefix(abs, root), "/")),
				AST: af, Line: fset.Position(af.Package).Line, Test: test}
			f.Imports = map[string]string{}
			for _, imp := range af.Imports {
				path := unquote(imp.Path.Value)
				local := path[strings.LastIndex(path, "/")+1:]
				if imp.Name != nil {
					local = imp.Name.Name
					if local == "." {
						f.DotImports = append(f.DotImports, path)
						continue
					}
				}
				f.Imports[local] = path
			}
			if test {
				p.TestFiles = append(p.TestFiles, f)
			} else {
				p.Files = append(p.Files, f)
			}
		}
		return nil
	}
	if err := add(lp.GoFiles, false); err != nil {
		return nil, err
	}
	if err := add(append(append([]string{}, lp.TestGoFiles...), lp.XTestGoFiles...), true); err != nil {
		return nil, err
	}
	return p, nil
}

func unquote(s string) string {
	s = strings.TrimPrefix(s, `"`)
	return strings.TrimSuffix(s, `"`)
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+(\S+)`)

// moduleOf returns the module path declared in root/go.mod.
func moduleOf(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	m := moduleLine.FindSubmatch(b)
	if m == nil {
		return "", fmt.Errorf("no module line in %s/go.mod", root)
	}
	return string(m[1]), nil
}
