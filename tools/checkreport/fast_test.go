package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo builds a throwaway module with a small import graph, commits it on
// main and points origin/main at that commit:
//
//	a        (no imports)
//	b -> a
//	c -> b       (so c reaches a only through b)
//	d            (independent)
//	e            (code independent; its test imports a)
//	f            (its test imports c, which reaches a through b)
func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/fx\n\ngo 1.24\n")
	write("a/a.go", "package a\n\nfunc A() int { return 1 }\n")
	write("b/b.go", "package b\n\nimport \"example.com/fx/a\"\n\nfunc B() int { return a.A() }\n")
	write("c/c.go", "package c\n\nimport \"example.com/fx/b\"\n\nfunc C() int { return b.B() }\n")
	write("d/d.go", "package d\n\nfunc D() int { return 4 }\n")
	write("e/e.go", "package e\n\nfunc E() int { return 5 }\n")
	write("e/e_test.go", "package e\n\nimport (\n\t\"testing\"\n\n\t\"example.com/fx/a\"\n)\n\nfunc TestE(t *testing.T) { _ = a.A() }\n")
	write("f/f.go", "package f\n\nfunc F() int { return 6 }\n")
	write("f/f_test.go", "package f\n\nimport (\n\t\"testing\"\n\n\t\"example.com/fx/c\"\n)\n\nfunc TestF(t *testing.T) { _ = c.C() }\n")
	write("docs/README.md", "docs\n")
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "base")
	git(t, dir, "update-ref", "refs/remotes/origin/main", "HEAD")
	return dir
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func planFor(t *testing.T, dir string) FastPlan {
	t.Helper()
	r := &runner{cfg: config{Root: dir}, ctx: parseCtx{Root: dir, Module: "example.com/fx"}, exec: osExec}
	return r.fastPlan()
}

func reasons(p FastPlan) map[string]string {
	out := map[string]string{}
	for _, pk := range p.Packages {
		out[strings.TrimPrefix(pk.Package, "example.com/fx/")] = pk.Reason
	}
	return out
}

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFastPlan(t *testing.T) {
	t.Run("nothing changed", func(t *testing.T) {
		p := planFor(t, gitRepo(t))
		if p.Full || len(p.Packages) != 0 {
			t.Fatalf("clean tree should plan nothing, got %+v", p)
		}
	})

	t.Run("changed package plus importers, code and tests", func(t *testing.T) {
		dir := gitRepo(t)
		writeFile(t, dir, "a/a.go", "package a\n\nfunc A() int { return 2 }\n")
		got := reasons(planFor(t, dir))
		want := map[string]string{
			"a": "changed: a/a.go",
			"b": "imports a",
			"c": "imports a", // through b
			"e": "test imports a",
			"f": "test imports c (which imports a)",
		}
		if len(got) != len(want) {
			t.Fatalf("packages = %v, want %v", got, want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("package %s: reason %q, want %q (all: %v)", k, got[k], v, got)
			}
		}
		if _, ok := got["d"]; ok {
			t.Error("d does not depend on a and must not be checked")
		}
	})

	t.Run("a leaf change checks only the leaf", func(t *testing.T) {
		dir := gitRepo(t)
		writeFile(t, dir, "d/d.go", "package d\n\nfunc D() int { return 40 }\n")
		got := reasons(planFor(t, dir))
		if len(got) != 1 || got["d"] == "" {
			t.Fatalf("want just d, got %v", got)
		}
	})

	t.Run("test-only and testdata changes do not ripple to importers", func(t *testing.T) {
		dir := gitRepo(t)
		writeFile(t, dir, "a/a_test.go", "package a\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) {}\n")
		writeFile(t, dir, "a/testdata/fuzz/FuzzA/seed", "x")
		got := reasons(planFor(t, dir))
		if len(got) != 1 || got["a"] == "" {
			t.Fatalf("want just a, got %v", got)
		}
	})

	t.Run("committed, staged and untracked changes all count", func(t *testing.T) {
		dir := gitRepo(t)
		writeFile(t, dir, "d/d.go", "package d\n\nfunc D() int { return 41 }\n")
		git(t, dir, "commit", "-q", "-am", "committed on the branch")
		writeFile(t, dir, "e/e.go", "package e\n\nfunc E() int { return 51 }\n")
		git(t, dir, "add", "e/e.go")
		writeFile(t, dir, "b/new.go", "package b\n\nfunc New() {}\n") // untracked
		got := reasons(planFor(t, dir))
		for _, p := range []string{"d", "e", "b", "c", "f"} {
			if got[p] == "" {
				t.Errorf("package %s missing from %v", p, got)
			}
		}
		if got["b"] != "changed: b/new.go" {
			t.Errorf("untracked file reason = %q", got["b"])
		}
	})

	t.Run("files outside packages are listed, not checked", func(t *testing.T) {
		dir := gitRepo(t)
		writeFile(t, dir, "docs/README.md", "changed\n")
		p := planFor(t, dir)
		if len(p.Packages) != 0 || len(p.Ignored) != 1 || p.Ignored[0] != "docs/README.md" {
			t.Fatalf("plan = %+v", p)
		}
	})

	for _, f := range []string{"go.mod", "go.sum", ".golangci.yml"} {
		t.Run(f+" widens to the full gate", func(t *testing.T) {
			dir := gitRepo(t)
			writeFile(t, dir, f, "module example.com/fx\n\ngo 1.24\n// changed\n")
			p := planFor(t, dir)
			if !p.Full || !strings.Contains(p.Why, f) {
				t.Fatalf("plan = %+v", p)
			}
		})
	}

	t.Run("missing origin/main falls back to the full gate", func(t *testing.T) {
		dir := gitRepo(t)
		git(t, dir, "update-ref", "-d", "refs/remotes/origin/main")
		p := planFor(t, dir)
		if !p.Full || !strings.Contains(p.Why, "origin/main") || !strings.Contains(p.summary(), "FULL gate") {
			t.Fatalf("plan = %+v", p)
		}
	})

	t.Run("no merge base falls back to the full gate", func(t *testing.T) {
		dir := gitRepo(t)
		git(t, dir, "checkout", "-q", "--orphan", "unrelated")
		git(t, dir, "commit", "-q", "--allow-empty", "-m", "unrelated history")
		p := planFor(t, dir)
		if !p.Full || !strings.Contains(p.Why, "merge base") {
			t.Fatalf("plan = %+v", p)
		}
	})

	t.Run("not a git repo falls back to the full gate", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, dir, "go.mod", "module example.com/fx\n\ngo 1.24\n")
		if p := planFor(t, dir); !p.Full {
			t.Fatalf("plan = %+v", p)
		}
	})
}
