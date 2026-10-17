package compose

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// guardedPorts are the container ports that serve a dashboard or an admin API:
// the control plane's 7070 (fleet dashboard + policy/secret writers) and the
// worker's 9090 (--admin-listen: worker dashboard, its secret-store / detection /
// integrations writers, /metrics). Nothing else Warden ships serves one; the other
// published ports are the agents' own UIs and the e2e request recorder.
var guardedPorts = map[string]bool{"7070": true, "9090": true}

var (
	// short form: [ip:]host:container[/proto], optionally quoted.
	shortPublish = regexp.MustCompile(`^\s*-\s*["']?(?:(\d+\.\d+\.\d+\.\d+):)?(\d+):(\d+)(?:/\w+)?["']?`)
	targetLine   = regexp.MustCompile(`^(\s*)(?:-\s+)?target:\s*["']?(\d+)`)
	hostIPLine   = regexp.MustCompile(`^\s*(?:-\s+)?host_ip:\s*["']?([\d.]+)`)
)

// nonLoopbackPublishes returns a description of every published mapping of a
// guarded container port that is not bound to 127.0.0.1, in both the short
// ("9090:9090") and the long-form (target:/published:/host_ip:) syntax.
func nonLoopbackPublishes(name, content string) []string {
	var bad []string
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if m := shortPublish.FindStringSubmatch(line); m != nil && guardedPorts[m[3]] && m[1] != "127.0.0.1" {
			bad = append(bad, fmt.Sprintf("%s:%d publishes %s beyond loopback: %q", name, i+1, m[3], strings.TrimSpace(line)))
			continue
		}
		m := targetLine.FindStringSubmatch(line)
		if m == nil || !guardedPorts[m[2]] {
			continue
		}
		// The long-form item: contiguous lines at this indentation, up to the next
		// list entry. A "- target:" line opens the item; otherwise walk back to it.
		lo, hi := i, i
		for lo > 0 && !strings.HasPrefix(strings.TrimSpace(lines[lo]), "- ") {
			lo--
		}
		for hi+1 < len(lines) && strings.TrimSpace(lines[hi+1]) != "" && !strings.HasPrefix(strings.TrimSpace(lines[hi+1]), "- ") {
			hi++
		}
		ip := ""
		published := false
		for _, l := range lines[lo : hi+1] {
			if h := hostIPLine.FindStringSubmatch(l); h != nil {
				ip = h[1]
			}
			if strings.Contains(l, "published:") {
				published = true
			}
		}
		if published && ip != "127.0.0.1" {
			bad = append(bad, fmt.Sprintf("%s:%d publishes %s beyond loopback (long form, host_ip %q)", name, i+1, m[2], ip))
		}
	}
	return bad
}

func TestNonLoopbackPublishes_Syntax(t *testing.T) {
	cases := []struct {
		name, in string
		want     int
	}{
		{"short open", "    ports:\n      - \"9090:9090\"\n", 1},
		{"short open 7070", "    ports:\n      - 7070:7070\n", 1},
		{"short all-interfaces", "      - \"0.0.0.0:9090:9090\"\n", 1},
		{"short loopback", "      - \"127.0.0.1:9091:9090\"  # ok\n", 0},
		{"short other port", "      - \"3000:3000\"\n", 0},
		{"long open", "    ports:\n      - target: 9090\n        published: \"9090\"\n", 1},
		{"long loopback", "    ports:\n      - target: 7070\n        published: \"7070\"\n        host_ip: 127.0.0.1\n", 0},
		{"long published first", "    ports:\n      - published: 7070\n        target: 7070\n", 1},
		{"long unpublished (expose only)", "    ports:\n      - target: 9090\n", 0},
	}
	for _, c := range cases {
		if got := nonLoopbackPublishes("x.yml", c.in); len(got) != c.want {
			t.Errorf("%s: got %d findings %v, want %d", c.name, len(got), got, c.want)
		}
	}
}

// TestComposeFiles_AdminPortsAreLoopbackOnly: no compose file may publish a
// dashboard or admin port (CP 7070, worker 9090) beyond 127.0.0.1 (#422). The
// dashboard APIs can rewrite the guardrail, and the worker's has no token guard.
func TestComposeFiles_AdminPortsAreLoopbackOnly(t *testing.T) {
	var files []string
	for _, pat := range []string{"compose*.y*ml", "docker-compose*.y*ml"} {
		m, err := filepath.Glob("../../../deploy/compose/" + pat)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no compose files found")
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, msg := range nonLoopbackPublishes(f, string(raw)) {
			t.Error(msg)
		}
	}
}
