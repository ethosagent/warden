// Package risk reads .agents/risk.yaml, the single source of risk tiers by path
// glob (#354), and classifies a list of changed files. tools/riskmap and
// tools/gatecheck both use it. It is developer tooling; no Warden package may
// import it.
package risk

import (
	"bytes"
	"fmt"
	"os/exec"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Tier is a risk tier. The order of Tiers is the order of severity.
type Tier string

const (
	Low      Tier = "low"
	Normal   Tier = "normal"
	Gates    Tier = "gates"
	Critical Tier = "critical"
)

// Tiers lists every tier, lowest first.
var Tiers = []Tier{Low, Normal, Gates, Critical}

func (t Tier) rank() int {
	for i, x := range Tiers {
		if x == t {
			return i
		}
	}
	return -1
}

// Label is the GitHub label a PR of this tier carries.
func (t Tier) Label() string { return "risk:" + string(t) }

// Map is a parsed risk.yaml.
type Map struct {
	tiers  map[Tier][]string
	agents map[string]bool
}

type file struct {
	Version       int                 `yaml:"version"`
	Tiers         map[string][]string `yaml:"tiers"`
	AgentAccounts []string            `yaml:"agent-accounts"`
}

// Parse validates and loads a risk map. It is strict on purpose: an unknown key,
// a missing tier, an empty gates tier or a malformed glob would silently shrink
// what is protected.
func Parse(b []byte) (*Map, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("risk map: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("risk map: version must be 1, got %d", f.Version)
	}
	m := &Map{tiers: map[Tier][]string{}, agents: map[string]bool{}}
	for name, patterns := range f.Tiers {
		t := Tier(name)
		if t.rank() < 0 {
			return nil, fmt.Errorf("risk map: unknown tier %q", name)
		}
		for _, p := range patterns {
			if err := checkPattern(p); err != nil {
				return nil, fmt.Errorf("risk map: tier %s: %w", name, err)
			}
		}
		m.tiers[t] = patterns
	}
	for _, t := range Tiers {
		if _, ok := f.Tiers[string(t)]; !ok {
			return nil, fmt.Errorf("risk map: tier %q is missing", t)
		}
	}
	if len(m.tiers[Gates]) == 0 {
		return nil, fmt.Errorf("risk map: the gates tier must not be empty")
	}
	for _, a := range f.AgentAccounts {
		m.agents[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return m, nil
}

func checkPattern(p string) error {
	if p == "" || strings.HasPrefix(p, "/") {
		return fmt.Errorf("pattern %q must be a non-empty repo-relative glob", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if _, err := path.Match(seg, "x"); err != nil {
			return fmt.Errorf("pattern %q: %w", p, err)
		}
	}
	return nil
}

// Match reports whether a repo-relative, slash-separated path matches a glob. A
// pattern without a slash matches the file name at any depth; otherwise it is
// matched segment by segment, `*` inside one segment and `**` across any number.
func Match(pattern, name string) bool {
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(name))
		return ok
	}
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegs(pat, name []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			for i := 0; i <= len(name); i++ {
				if matchSegs(pat[1:], name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], name[0]); !ok {
			return false
		}
		pat, name = pat[1:], name[1:]
	}
	return len(name) == 0
}

// FileTier is one changed file with the tier and the pattern that decided it.
// Pattern is empty for a path that matched nothing (and so is Normal).
type FileTier struct {
	Path    string `json:"path"`
	Tier    Tier   `json:"tier"`
	Pattern string `json:"pattern,omitempty"`
}

// Result is the classification of a whole change.
type Result struct {
	Tier  Tier
	Files []FileTier
}

// Protected returns the changed files in the gates tier: the ones that define
// what green means, whatever the PR's overall tier is.
func (r Result) Protected() []string {
	var out []string
	for _, f := range r.Files {
		if f.Tier == Gates {
			out = append(out, f.Path)
		}
	}
	return out
}

// Classify returns the tier of every file and the highest of them. Unmatched
// paths are Normal, never Low; an empty change is Low.
func (m *Map) Classify(files []string) Result {
	res := Result{Tier: Low}
	for _, raw := range files {
		name := clean(raw)
		ft := m.fileTier(name)
		res.Files = append(res.Files, ft)
		if ft.Tier.rank() > res.Tier.rank() {
			res.Tier = ft.Tier
		}
	}
	return res
}

// fileTier takes the highest tier whose pattern matches; ties go to the first
// pattern in file order.
func (m *Map) fileTier(name string) FileTier {
	best := FileTier{Path: name, Tier: Normal}
	bestRank := -1
	for _, t := range Tiers {
		for _, p := range m.tiers[t] {
			if Match(p, name) && t.rank() > bestRank {
				best, bestRank = FileTier{Path: name, Tier: t, Pattern: p}, t.rank()
			}
		}
	}
	return best
}

func clean(p string) string {
	p = path.Clean(strings.ReplaceAll(p, "\\", "/"))
	return strings.TrimPrefix(p, "./")
}

// IsAgent reports whether an account counts as a bot or agent: any GitHub
// account of type Bot, any login ending in [bot], or a login in agent-accounts.
func (m *Map) IsAgent(login, accountType string) bool {
	l := strings.ToLower(login)
	return strings.EqualFold(accountType, "Bot") || strings.HasSuffix(l, "[bot]") || (l != "" && m.agents[l])
}

// DiffNames lists the files a PR changes in the repository at dir: three dots
// (against the merge base, so main moving on does not count) and --no-renames
// (a file moved out of a protected path shows under both names).
func DiffNames(dir, base, head string) ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", "--no-renames", "-z", base+"..."+head)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	var files []string
	for _, f := range strings.Split(out.String(), "\x00") {
		if f != "" {
			files = append(files, f)
		}
	}
	return files, nil
}
