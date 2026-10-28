package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

// The operator docs of the break-glass and backup feature (W-P1-OPS1-03) are
// checked against the real command tree and config structs, so a renamed flag
// or key fails here instead of misleading an operator at 3 a.m.

const (
	runbookBackup     = "../../docs/runbooks/backup-restore.md"
	runbookBreakGlass = "../../docs/runbooks/break-glass.md"
	readinessDoc      = "../../docs/production-readiness.md"
	controlPlaneDoc   = "../../docs/control-plane.md"
	readmeFile        = "../../README.md"
	composeCPFile     = "../../deploy/compose/docker-compose.control-plane.yml"
)

func readDoc(t testing.TB, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// docInvocations returns the argv (after "warden" or after "go run
// ./cmd/proxy") of every `warden control-plane ...` line inside a fenced block
// of doc. A backslash continues a line; an invocation ends at a shell
// operator. Square brackets (optional parts in a synopsis) are dropped.
func docInvocations(doc string) [][]string {
	var out [][]string
	inFence := false
	var pending string
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence, pending = !inFence, ""
			continue
		}
		if !inFence || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if pending != "" {
			trimmed = pending + " " + trimmed
			pending = ""
		}
		if strings.HasSuffix(trimmed, "\\") {
			pending = strings.TrimSuffix(trimmed, "\\")
			continue
		}
		for _, marker := range []string{"go run ./cmd/proxy control-plane", "warden control-plane"} {
			i := strings.Index(trimmed, marker)
			if i < 0 {
				continue
			}
			rest := trimmed[i:]
			for _, op := range []string{"|", "&&", ";", ">", "<", ")"} {
				if j := strings.Index(rest, op); j >= 0 {
					rest = rest[:j]
				}
			}
			rest = strings.NewReplacer("[", " ", "]", " ").Replace(rest)
			f := strings.Fields(rest)
			skip := 1 // "warden"
			if marker[0] == 'g' {
				skip = 3 // "go run ./cmd/proxy"
			}
			out = append(out, f[skip:])
			break
		}
	}
	return out
}

// lintDocCommands checks every `warden control-plane ...` invocation in doc
// against the cobra tree and returns one message per problem: an unknown
// subcommand or a --flag that the resolved command does not have.
func lintDocCommands(doc string) []string {
	var issues []string
	for _, args := range docInvocations(doc) {
		line := "warden " + strings.Join(args, " ")
		root := newRootCmd()
		cmd, _, err := root.Find(args[:1])
		if err != nil || cmd.Name() != "control-plane" {
			issues = append(issues, fmt.Sprintf("%s: not the control-plane command", line))
			continue
		}
		i := 1
		for i < len(args) && !strings.HasPrefix(args[i], "-") && len(cmd.Commands()) > 0 {
			var next *cobra.Command
			for _, c := range cmd.Commands() {
				if c.Name() == args[i] || c.HasAlias(args[i]) {
					next = c
				}
			}
			if next == nil {
				issues = append(issues, fmt.Sprintf("%s: unknown subcommand %q of %s", line, args[i], cmd.CommandPath()))
				cmd = nil
				break
			}
			cmd, i = next, i+1
		}
		if cmd == nil {
			continue
		}
		for _, a := range args[i:] {
			if !strings.HasPrefix(a, "--") {
				continue
			}
			name := strings.TrimPrefix(strings.SplitN(a, "=", 2)[0], "--")
			if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil {
				issues = append(issues, fmt.Sprintf("%s: %s has no flag --%s", line, cmd.CommandPath(), name))
			}
		}
	}
	return issues
}

func TestRunbookCommandsMatchCLI(t *testing.T) {
	for _, path := range []string{runbookBackup, runbookBreakGlass, readinessDoc} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			doc := readDoc(t, path)
			if len(docInvocations(doc)) == 0 {
				t.Fatalf("%s shows no fenced `warden control-plane` command", path)
			}
			for _, issue := range lintDocCommands(doc) {
				t.Error(issue)
			}
		})
	}

	t.Run("lint catches a bad flag and a bad subcommand", func(t *testing.T) {
		bad := "```sh\nwarden control-plane backup --state-dir /data --no-such-flag x\n```\n"
		got := lintDocCommands(bad)
		if len(got) != 1 || !strings.Contains(got[0], "--no-such-flag") {
			t.Errorf("issues = %q, want one naming --no-such-flag", got)
		}
		bad = "```sh\ngo run ./cmd/proxy control-plane nosuchcmd --state-dir /data\n```\n"
		got = lintDocCommands(bad)
		if len(got) != 1 || !strings.Contains(got[0], "nosuchcmd") {
			t.Errorf("issues = %q, want one naming nosuchcmd", got)
		}
		good := "```sh\nwarden control-plane backup --state-dir /data \\\n  --backup-dir /backups [--backup-include cp,alerts]\n```\n"
		if got := lintDocCommands(good); len(got) != 0 {
			t.Errorf("good lines flagged: %q", got)
		}
	})
}

var (
	backtickRe = regexp.MustCompile("`([^`\n]+)`")
	longFlagRe = regexp.MustCompile(`^--[a-z][a-z0-9-]*$`)
	dottedKey  = regexp.MustCompile(`^[a-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)+$`)
)

// hasFlag reports whether cmd or any command below it has the long flag name.
func hasFlag(cmd *cobra.Command, name string) bool {
	if cmd.Flags().Lookup(name) != nil || cmd.PersistentFlags().Lookup(name) != nil {
		return true
	}
	for _, c := range cmd.Commands() {
		if hasFlag(c, name) {
			return true
		}
	}
	return false
}

// configKeyKnown reports whether the dotted key names a field of the config
// file. internal/config keeps its on-disk structs private, so it asks the real
// strict loader (KnownFields on, the yaml tags of those structs) instead: a
// file that sets only that key as null loads unless the decoder reports the
// key as "not found in type".
func configKeyKnown(t testing.TB, key string) bool {
	t.Helper()
	parts := strings.Split(key, ".")
	var b strings.Builder
	for i, p := range parts {
		b.WriteString(strings.Repeat("  ", i) + p + ":")
		if i == len(parts)-1 {
			b.WriteString(" null")
		}
		b.WriteString("\n")
	}
	path := filepath.Join(t.TempDir(), "probe.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := config.NewLocalYAMLProvider(path)
	return err == nil || !strings.Contains(err.Error(), "not found in type")
}

func TestProductionReadinessKeysExist(t *testing.T) {
	doc := readDoc(t, readinessDoc)

	cp, run := newControlPlaneCmd(), newRunCmd()

	var nFlags, nKeys int
	for _, m := range backtickRe.FindAllStringSubmatch(doc, -1) {
		tok := strings.TrimSpace(m[1])
		if f := strings.SplitN(tok, "=", 2)[0]; longFlagRe.MatchString(f) {
			nFlags++
			if name := strings.TrimPrefix(f, "--"); !hasFlag(cp, name) && !hasFlag(run, name) && name != "config" { // config: the root's persistent flag
				t.Errorf("%s names flag %s, which is on neither the control-plane nor the run command", readinessDoc, f)
			}
			continue
		}
		if !dottedKey.MatchString(tok) {
			continue
		}
		if !configKeyKnown(t, strings.Split(tok, ".")[0]) {
			continue // not a config key (an audit action, a schema name, a file)
		}
		nKeys++
		if !configKeyKnown(t, tok) {
			t.Errorf("%s names config key %q, which is not a field of the config file", readinessDoc, tok)
		}
	}
	if nFlags < 8 || nKeys < 6 {
		t.Errorf("only %d flags and %d config keys found in %s; the checklist must cite them in backticks", nFlags, nKeys, readinessDoc)
	}

	t.Run("a made-up key does not resolve", func(t *testing.T) {
		if !configKeyKnown(t, "console.breakGlass.passwordHashFile") {
			t.Error("console.breakGlass.passwordHashFile did not resolve")
		}
		if configKeyKnown(t, "console.breakGlassTypo") || configKeyKnown(t, "console.breakGlass.passwordHash") {
			t.Error("a made-up key resolved")
		}
	})
}

func TestRunbooksHaveNoRealSecrets(t *testing.T) {
	jwt := regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}`)
	for _, path := range []string{runbookBackup, runbookBreakGlass, readinessDoc} {
		for n, line := range strings.Split(readDoc(t, path), "\n") {
			low := strings.ToLower(line)
			if (strings.Contains(line, "--password") || strings.Contains(line, "$argon2id$")) && !strings.Contains(low, "placeholder") {
				t.Errorf("%s:%d mentions --password or an argon2id hash without the word placeholder: %.80s", path, n+1, line)
			}
			if jwt.MatchString(line) || regexp.MustCompile(`wwt_[a-z0-9]{40,}`).MatchString(line) {
				t.Errorf("%s:%d looks like a real token", path, n+1)
			}
		}
	}
}

func TestComposeControlPlaneBackupVolume(t *testing.T) {
	raw := readDoc(t, composeCPFile)
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
		Volumes map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("%s does not parse as YAML: %v", composeCPFile, err)
	}
	var found bool
	for _, v := range doc.Services["control-plane"].Volumes {
		name, rest, ok := strings.Cut(v, ":")
		if _, declared := doc.Volumes[name]; ok && declared && strings.HasPrefix(rest, "/backups") {
			found = true
		}
	}
	if !found {
		t.Error("the control-plane service mounts no declared named volume at /backups")
	}
	var commented bool
	for _, line := range strings.Split(raw, "\n") {
		if tl := strings.TrimSpace(line); strings.HasPrefix(tl, "#") && strings.Contains(tl, "--backup-dir") {
			commented = true
		}
	}
	if !commented {
		t.Error("no commented --backup-dir line")
	}
}

func TestControlPlaneDocLinksRunbooks(t *testing.T) {
	doc := readDoc(t, controlPlaneDoc)
	for _, link := range []string{"(runbooks/backup-restore.md", "(runbooks/break-glass.md", "(production-readiness.md"} {
		if !strings.Contains(doc, link) {
			t.Errorf("docs/control-plane.md has no link %s...)", link)
		}
	}
	if !strings.Contains(readDoc(t, readmeFile), "docs/production-readiness.md") {
		t.Error("README.md docs index does not link docs/production-readiness.md")
	}
}

// TestRunbooksNameDrillTests: the runbooks point at the tests that execute the
// drills, and those tests exist.
func TestRunbooksNameDrillTests(t *testing.T) {
	cases := []struct{ doc, name, file string }{
		{runbookBackup, "TestControlPlaneRestore_RoundTrip", "restore_test.go"},
		{runbookBreakGlass, "TestControlPlaneBreakGlassDegraded", "controlplane_breakglass_test.go"},
		{runbookBreakGlass, "TestBreakGlassDexDown", "../../test/e2e/identity/breakglass_test.go"},
	}
	for _, c := range cases {
		if !strings.Contains(readDoc(t, c.doc), c.name) {
			t.Errorf("%s does not name %s", c.doc, c.name)
		}
		if !strings.Contains(readDoc(t, c.file), "func "+c.name+"(") {
			t.Errorf("%s has no func %s", c.file, c.name)
		}
	}
	if !strings.Contains(readDoc(t, runbookBreakGlass), "make e2e-identity-scenario NAME=TestBreakGlassDexDown") {
		t.Error("break-glass runbook lacks the make e2e-identity-scenario command")
	}
}
