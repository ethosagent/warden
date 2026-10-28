//go:build e2e

package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness/compose"
)

// docBlock is one fenced block of docs/identity-dex.md.
type docBlock struct {
	info string // the whole info string, for example "sh run"
	body string
	line int
}

func parseDocBlocks(doc string) []docBlock {
	var out []docBlock
	var cur *docBlock
	var body []string
	for i, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case !strings.HasPrefix(trimmed, "```"):
			if cur != nil {
				body = append(body, line)
			}
		case cur == nil:
			cur = &docBlock{info: strings.TrimSpace(strings.TrimPrefix(trimmed, "```")), line: i + 1}
			body = nil
		default:
			cur.body = strings.Join(body, "\n") + "\n"
			out = append(out, *cur)
			cur = nil
		}
	}
	return out
}

// TestDexDocRunBlocks executes every `sh run` block of docs/identity-dex.md, in
// order, from the repository root against the identity stack. Each block must
// exit 0; when a `text` block follows it directly, its stdout must equal that
// text. The blocks hold no secrets: they load the dev placeholders from
// deploy/compose/dex/.env.example themselves, and print claims only.
func TestDexDocRunBlocks(t *testing.T) {
	requireStack(t)
	root, err := compose.RepoRoot()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "identity-dex.md"))
	if err != nil {
		t.Fatal(err)
	}
	blocks := parseDocBlocks(string(raw))

	// The blocks use the host-side issuer, so a caller's DEX_URL must not leak in.
	env := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); k != "DEX_URL" {
			env = append(env, kv)
		}
	}

	ran, compared := 0, 0
	for i, b := range blocks {
		if b.info != "sh run" {
			continue
		}
		ran++
		res := compose.RunEnv(root, env, compose.ComposeDeadline, "bash", "-eo", "pipefail", "-c", b.body)
		if res.Exit != 0 {
			t.Errorf("run block at docs/identity-dex.md:%d exited %d\nstderr: %s", b.line, res.Exit, firstLine(res.Stderr))
			continue
		}
		if i+1 < len(blocks) && blocks[i+1].info == "text" {
			compared++
			if got, want := strings.TrimSpace(res.Stdout), strings.TrimSpace(blocks[i+1].body); got != want {
				t.Errorf("run block at docs/identity-dex.md:%d printed\n%s\nthe doc shows\n%s", b.line, got, want)
			}
		}
	}
	if ran < 4 || compared < 4 {
		t.Errorf("the doc has %d run blocks (%d with shown output); want at least 4 and 4", ran, compared)
	}
}
