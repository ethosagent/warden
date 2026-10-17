package compose

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestComposeFiles_ControlPlanePortIsLoopbackOnly: no compose file may publish the
// control plane's 7070 on all interfaces (#422); the dashboard API can rewrite the
// fleet policy, so the host publish must be 127.0.0.1-only.
func TestComposeFiles_ControlPlanePortIsLoopbackOnly(t *testing.T) {
	files, err := filepath.Glob("../../../deploy/compose/docker-compose*.yml")
	if err != nil || len(files) == 0 {
		t.Fatalf("no compose files found: %v", err)
	}
	publish := regexp.MustCompile(`^\s*-\s*"?([^"#\s]*:)?7070:7070"?`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if m := publish.FindStringSubmatch(line); m != nil && m[1] != "127.0.0.1:" {
				t.Errorf("%s:%d publishes 7070 beyond loopback: %q", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
