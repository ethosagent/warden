package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/identityclient"
)

// contractDoc is the harness-builder contract (W-P1-IDC-01). Every
// `warden identity` command line it shows in a fenced block must parse against
// the real cobra tree, so a renamed or removed flag fails here.
const contractDoc = "../../docs/identity-contract.md"

// docCommandLines returns every `warden identity ...` invocation inside a
// fenced block of doc, as argv without the leading "warden". An invocation
// ends at a shell operator, so `eval "$(warden identity env ...)"` and a
// pipeline yield only the warden part.
func docCommandLines(doc string) [][]string {
	var out [][]string
	inFence := false
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") {
			inFence = !inFence
			continue
		}
		if !inFence || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		rest := line
		for {
			i := strings.Index(rest, "warden identity")
			if i < 0 {
				break
			}
			rest = rest[i:]
			end := len(rest)
			for _, op := range []string{")", "|", "&&", ";", "<", ">", "\""} {
				if j := strings.Index(rest, op); j >= 0 && j < end {
					end = j
				}
			}
			out = append(out, strings.Fields(rest[:end])[1:])
			rest = rest[end:]
		}
	}
	return out
}

func TestContractDocCommands(t *testing.T) {
	b, err := os.ReadFile(contractDoc)
	if err != nil {
		t.Fatalf("read %s: %v", contractDoc, err)
	}
	doc := string(b)
	lines := docCommandLines(doc)
	if len(lines) == 0 {
		t.Fatal("the contract doc shows no `warden identity` command in a fenced block")
	}

	shown := map[string]bool{}
	t.Run("commands parse", func(t *testing.T) {
		for _, args := range lines {
			line := "warden " + strings.Join(args, " ")
			root := newRootCmd() // fresh per line: parsed flag values persist on a tree
			c, rest, err := root.Find(args)
			if err != nil || c.Parent() == nil || c.Parent().Name() != "identity" {
				t.Errorf("%s: not a `warden identity` subcommand (found %q, err %v)", line, c.CommandPath(), err)
				continue
			}
			shown[c.Name()] = true
			if err := c.ParseFlags(rest); err != nil {
				t.Errorf("%s: %v", line, err)
				continue
			}
			if err := c.ValidateRequiredFlags(); err != nil {
				t.Errorf("%s: %v", line, err)
			}
			if err := c.ValidateArgs(c.Flags().Args()); err != nil {
				t.Errorf("%s: %v", line, err)
			}
		}
	})

	t.Run("every subcommand shown", func(t *testing.T) {
		for _, c := range newIdentityCmd().Commands() {
			if !shown[c.Name()] {
				t.Errorf("the contract doc shows no `warden identity %s` example", c.Name())
			}
		}
	})

	t.Run("exec flags shown", func(t *testing.T) {
		// The exec section explains these flags in prose; each must be in an
		// example too, so the commands check covers it.
		for _, f := range []string{"--worker", "--ca", "--env"} {
			found := false
			for _, args := range lines {
				if len(args) > 1 && args[1] == "exec" && strings.Contains(" "+strings.Join(args, " ")+" ", " "+f+" ") {
					found = true
				}
			}
			if !found {
				t.Errorf("no `warden identity exec` example uses %s", f)
			}
		}
	})

	t.Run("exec environment", func(t *testing.T) {
		for _, n := range identityclient.ChildEnvAllowlist {
			if !strings.Contains(doc, "`"+n+"`") {
				t.Errorf("the contract doc does not list the exec allowlist variable %s", n)
			}
		}
		for _, n := range identityclient.CAVars("ca.pem") {
			if !strings.Contains(doc, "`"+n.Name+"`") {
				t.Errorf("the contract doc does not list the --ca variable %s", n.Name)
			}
		}
		for _, want := range []string{
			"per-run credential (user `" + identityclient.ProxyClientUser + "`)",
			`base64("` + identityclient.ProxyUser + `:"+token)`,
			"`--env NAME=VALUE`",
			"`WARDEN_IDENTITY_*`",
		} {
			if !strings.Contains(doc, want) {
				t.Errorf("the contract doc does not state %q", want)
			}
		}
	})

	t.Run("exit codes", func(t *testing.T) {
		for _, code := range []int{exitLoginRequired, exitIssuerUnreachable} {
			if !strings.Contains(doc, fmt.Sprintf("| `%d` |", code)) {
				t.Errorf("the contract doc's exit-code table has no row for %d", code)
			}
		}
	})
}
