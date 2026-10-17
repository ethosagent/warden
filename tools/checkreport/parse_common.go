package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// parseCtx is what parsers need to turn tool-reported locations into
// repo-relative ones.
type parseCtx struct {
	Root   string // absolute repo root the tools ran in
	Module string // Go module path from go.mod
}

// relPath makes p repo-relative when it lies under Root; relative paths are just
// cleaned. Paths outside the repo (GOROOT, module cache) are returned unchanged.
func (c parseCtx) relPath(p string) string {
	if filepath.IsAbs(p) {
		if rel, err := filepath.Rel(c.Root, p); err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return filepath.ToSlash(rel)
		}
		return p
	}
	return path.Clean(filepath.ToSlash(p))
}

// inRepo reports whether an absolute path is inside the repo.
func (c parseCtx) inRepo(p string) bool {
	return filepath.IsAbs(p) && c.relPath(p) != filepath.ToSlash(p)
}

// pkgDir maps an import path (possibly "pkg [pkg.test]") to its repo-relative dir.
func (c parseCtx) pkgDir(importPath string) string {
	importPath, _, _ = strings.Cut(importPath, " ")
	switch {
	case importPath == c.Module:
		return "."
	case c.Module != "" && strings.HasPrefix(importPath, c.Module+"/"):
		return strings.TrimPrefix(importPath, c.Module+"/")
	}
	return importPath
}

// joinDir joins a package dir and a file name.
func joinDir(dir, file string) string {
	if dir == "." || dir == "" {
		return file
	}
	return dir + "/" + file
}

// loc formats file:line for a fix message.
func loc(file string, line int) string {
	if file == "" {
		return "the reported location"
	}
	if line == 0 {
		return file
	}
	return fmt.Sprintf("%s:%d", file, line)
}

var compileLine = regexp.MustCompile(`^(\S+?\.go):(\d+)(?::(\d+))?: (.+)$`)

// parseCompileLines turns compiler output ("file.go:3:9: message") into
// build/compile-error findings. Lines that are not diagnostics are ignored.
func parseCompileLines(text string, c parseCtx) []Finding {
	var out []Finding
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	for sc.Scan() {
		m := compileLine.FindStringSubmatch(strings.TrimSpace(sc.Text()))
		if m == nil {
			continue
		}
		line, _ := strconv.Atoi(m[2])
		col, _ := strconv.Atoi(m[3])
		f := Finding{
			Rule: "build/compile-error", Severity: sevError,
			File: c.relPath(m[1]), Line: line, Col: col, Message: m[4],
		}
		f.Fix = compileFix(f)
		if k := fmt.Sprint(f.File, f.Line, f.Col, f.Message); !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

// compileFix says what to do about a compiler error, by its most common shapes.
func compileFix(f Finding) string {
	at := loc(f.File, f.Line)
	var what string
	switch {
	case strings.HasPrefix(f.Message, "undefined:"):
		what = "declare or import the undefined identifier, or fix its spelling"
	case strings.Contains(f.Message, "declared and not used"):
		what = "use the variable or remove it"
	case strings.Contains(f.Message, "imported and not used"):
		what = "remove the unused import"
	case strings.HasPrefix(f.Message, "cannot use"):
		what = "fix the type mismatch: convert the value or change the declared type"
	default:
		what = "fix the compile error"
	}
	pkg := "./..."
	if d := path.Dir(f.File); f.File != "" && d != "." {
		pkg = "./" + d
	}
	return fmt.Sprintf("%s at `%s`, then rerun `go build %s`", what, at, pkg)
}

// buildEvent is one line of `go build -json` / the build half of `go test -json`.
type buildEvent struct {
	ImportPath string
	Action     string
	Output     string
}

// buildFindings extracts compile errors from build-output events in a JSON-lines
// stream (go build -json, or go test -json which interleaves them).
func buildFindings(data []byte, c parseCtx) []Finding {
	var order []string
	text := map[string]*strings.Builder{}
	forEachJSONLine(data, func(raw []byte) {
		var ev buildEvent
		if json.Unmarshal(raw, &ev) != nil || ev.Action != "build-output" {
			return
		}
		b, ok := text[ev.ImportPath]
		if !ok {
			b = &strings.Builder{}
			text[ev.ImportPath] = b
			order = append(order, ev.ImportPath)
		}
		b.WriteString(ev.Output)
	})
	var out []Finding
	for _, p := range order {
		out = append(out, parseCompileLines(text[p].String(), c)...)
	}
	return out
}

// forEachJSONLine calls fn for every line that looks like a JSON object.
func forEachJSONLine(data []byte, fn func([]byte)) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) > 0 && line[0] == '{' {
			fn(line)
		}
	}
}

// parseBuild parses `go build -json` output.
func parseBuild(data []byte, c parseCtx) []Finding { return buildFindings(data, c) }

// newLineScanner scans data line by line with a buffer big enough for
// `go test -json` lines carrying large outputs.
func newLineScanner(data []byte) *bufio.Scanner {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	return sc
}
