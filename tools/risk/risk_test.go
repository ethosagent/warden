package risk

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"internal/proxy/**", "internal/proxy/tls.go", true},
		{"internal/proxy/**", "internal/proxy/sub/deep/x.go", true},
		{"internal/proxy/**", "internal/proxyx/x.go", false},
		{"internal/proxy/**", "internal/other/proxy/x.go", false},
		{"deploy/k8s/networkpolicy*.yaml", "deploy/k8s/networkpolicy-strict.yaml", true},
		{"deploy/k8s/networkpolicy*.yaml", "deploy/k8s/sub/networkpolicy.yaml", false},
		{"*.md", "README.md", true},
		{"*.md", "internal/proxy/README.md", true}, // no slash: file name at any depth
		{"*.md", "docs/x.txt", false},
		{"Dockerfile", "Dockerfile", true},
		{"Dockerfile", "examples/demo/Dockerfile", true},
		{"scripts/check.sh", "scripts/check.sh", true},
		{"scripts/check.sh", "scripts/check.sh.bak", false},
		{".github/**", ".github/workflows/ci.yml", true},
		{"a/**/z.go", "a/z.go", true},
		{"a/**/z.go", "a/b/c/z.go", true},
		{"a/**/z.go", "a/b/c/y.go", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.path); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.path, got, c.want)
		}
	}
}

const sample = `
version: 1
tiers:
  critical: [internal/proxy/**, Dockerfile]
  gates: [scripts/check.sh, .github/**]
  normal: [internal/**, cmd/**, test/**, go.mod]
  low: [docs/**, "*.md"]
agent-accounts: [Claude-Agent]
`

func mustLoad(t *testing.T, doc string) *Map {
	t.Helper()
	m, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestClassifyFixtureDiffs(t *testing.T) {
	m := mustLoad(t, sample)
	cases := []struct {
		name  string
		files []string
		want  Tier
	}{
		{"docs only", []string{"docs/setup-guide.md", "README.md"}, Low},
		{"tests only is normal", []string{"internal/policy_test.go", "internal/dlp/dlp_test.go"}, Normal},
		{"proxy change is critical", []string{"docs/x.md", "internal/proxy/proxy.go"}, Critical},
		{"check.sh is gates", []string{"scripts/check.sh"}, Gates},
		{"gates over normal", []string{"internal/dlp/dlp.go", ".github/workflows/ci.yml"}, Gates},
		{"critical over gates", []string{"scripts/check.sh", "internal/proxy/a.go"}, Critical},
		{"unmatched is normal, never low", []string{"Makefile"}, Normal},
		{"unmatched with docs stays normal", []string{"Makefile", "docs/a.md"}, Normal},
		{"empty diff is low", nil, Low},
		{"dot-slash and dotdot are cleaned", []string{"./scripts/../scripts/check.sh"}, Gates},
	}
	for _, c := range cases {
		res := m.Classify(c.files)
		if res.Tier != c.want {
			t.Errorf("%s: tier = %s, want %s (%+v)", c.name, res.Tier, c.want, res.Files)
		}
	}
}

func TestClassifyExplainsEachFile(t *testing.T) {
	res := mustLoad(t, sample).Classify([]string{"scripts/check.sh", "Makefile"})
	if len(res.Files) != 2 || res.Files[0].Pattern != "scripts/check.sh" || res.Files[1].Pattern != "" || res.Files[1].Tier != Normal {
		t.Fatalf("files = %+v", res.Files)
	}
	if got := res.Protected(); len(got) != 1 || got[0] != "scripts/check.sh" {
		t.Fatalf("Protected() = %v", got)
	}
}

func TestIsAgent(t *testing.T) {
	m := mustLoad(t, sample)
	for login, want := range map[string]bool{
		"claude-agent":      true, // listed, case-insensitive
		"dependabot[bot]":   true,
		"someone":           false,
		"Mitesh":            false,
		"renovate[BOT]":     true,
		"":                  false,
		"claude-agent-copy": false,
	} {
		if got := m.IsAgent(login, "User"); got != want {
			t.Errorf("IsAgent(%q, User) = %v, want %v", login, got, want)
		}
	}
	if !m.IsAgent("anything", "Bot") {
		t.Error("an account of type Bot is always an agent")
	}
}

func TestParseRejectsUnsafeMaps(t *testing.T) {
	for name, doc := range map[string]string{
		"empty gates":    "version: 1\ntiers: {critical: [a], gates: [], normal: [b], low: [c]}",
		"missing tier":   "version: 1\ntiers: {critical: [a], gates: [g], normal: [b]}",
		"unknown tier":   "version: 1\ntiers: {critical: [a], gates: [g], normal: [b], low: [c], extra: [d]}",
		"bad pattern":    "version: 1\ntiers: {critical: [a], gates: ['[x'], normal: [b], low: [c]}",
		"bad version":    "version: 2\ntiers: {critical: [a], gates: [g], normal: [b], low: [c]}",
		"not yaml":       "tiers: [",
		"unknown key":    "version: 1\nbogus: 1\ntiers: {critical: [a], gates: [g], normal: [b], low: [c]}",
		"empty pattern":  "version: 1\ntiers: {critical: [''], gates: [g], normal: [b], low: [c]}",
		"absolute match": "version: 1\ntiers: {critical: ['/etc/x'], gates: [g], normal: [b], low: [c]}",
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The real file must load: a typo in .agents/risk.yaml would otherwise be found
// only by the CI job that depends on it.
func TestRepoRiskMapLoads(t *testing.T) {
	b, err := os.ReadFile("../../.agents/risk.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	for file, want := range map[string]Tier{
		"internal/proxy/proxy.go":               Critical,
		"internal/secrets/aws.go":               Critical,
		"Dockerfile":                            Critical,
		"scripts/check.sh":                      Gates,
		"scripts/gen-certs.sh":                  Critical,
		".github/workflows/ci.yml":              Gates,
		".golangci.yml":                         Gates,
		".golangci.arch.yml":                    Gates,
		".agents/risk.yaml":                     Gates,
		"architecture.yaml":                     Gates,
		"architecture.baseline.yaml":            Gates,
		"tools/gatecheck/main.go":               Gates,
		"internal/archtest/rules.go":            Gates,
		"internal/dlp/dlp.go":                   Normal,
		"internal/dlp/dlp_test.go":              Normal,
		"go.mod":                                Normal,
		"docs/setup-guide.md":                   Low,
		"README.md":                             Low,
		"something/unmatched.txt":               Normal,
		"deploy/k8s/networkpolicy-default.yaml": Critical,
	} {
		if got := m.Classify([]string{file}).Tier; got != want {
			t.Errorf("%s: tier = %s, want %s", file, got, want)
		}
	}
	if strings.TrimSpace(Critical.Label()) != "risk:critical" {
		t.Errorf("label = %q", Critical.Label())
	}
}

// One test against real git, to pin the exact diff the tool asks for: three dots
// (what the PR changes, not what main did meanwhile) and no rename detection (a
// file moved out of a protected path still counts as touching it).
func TestGitDiffNames(t *testing.T) {
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"}
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git("init", "-q", "-b", "main")
	write("scripts/check.sh", "echo gate\n")
	write("README.md", "x\n")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	git("checkout", "-q", "-b", "pr")
	git("mv", "scripts/check.sh", "scripts/moved.sh")
	git("commit", "-q", "-m", "pr")
	git("checkout", "-q", "main")
	write("other.txt", "main moved on\n")
	git("add", ".")
	git("commit", "-q", "-m", "main")

	got, err := DiffNames(dir, "main", "pr")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "scripts/check.sh,scripts/moved.sh" {
		t.Fatalf("names = %v", got)
	}
}

// A fork's clone may not have the base commit (the fork is stale), so DiffNames
// must run in a checkout of the BASE repository with the PR head fetched into
// it as a ref, which is what .github/workflows/gates.yml does.
func TestDiffNamesNeedsTheBaseCommit(t *testing.T) {
	root := t.TempDir()
	git := func(dir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + root, "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t"}
		b, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, b)
		}
		return strings.TrimSpace(string(b))
	}
	commit := func(dir, name, msg string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		git(dir, "add", ".")
		git(dir, "commit", "-q", "-m", msg)
	}
	up := filepath.Join(root, "upstream")
	if err := os.Mkdir(up, 0o755); err != nil {
		t.Fatal(err)
	}
	git(up, "init", "-q", "-b", "main")
	commit(up, "a.txt", "first")
	fork := filepath.Join(root, "fork")
	git(root, "clone", "-q", up, fork) // the fork, cloned before the base moved on
	commit(up, "b.txt", "base moved on")
	baseSHA := git(up, "rev-parse", "HEAD")
	git(fork, "checkout", "-q", "-b", "pr")
	commit(fork, "scripts.sh", "the PR")

	if _, err := DiffNames(fork, baseSHA, "pr"); err == nil {
		t.Fatal("the stale fork clone does not have the base commit: the diff must fail there")
	}
	basecopy := filepath.Join(root, "base")
	git(root, "clone", "-q", up, basecopy)
	git(basecopy, "fetch", "-q", "--no-tags", fork, "+refs/heads/pr:refs/remotes/pr/head")
	got, err := DiffNames(basecopy, baseSHA, "refs/remotes/pr/head")
	if err != nil || strings.Join(got, ",") != "scripts.sh" {
		t.Fatalf("names = %v, err = %v; want only what the PR changed", got, err)
	}
}
