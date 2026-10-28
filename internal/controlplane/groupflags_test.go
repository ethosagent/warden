package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

const scopedPolicyYAML = "policy:\n  allowlist:\n    - domain: plain.example.com\n    - domain: secret-groupname-host.example.com\n      groups: [top-secret-group]\n"

func writeScopedPolicy(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type fleetRow struct {
	ProxyID             string `json:"proxyID"`
	NoGroupPolicy       bool   `json:"noGroupPolicy"`
	NoIdentityChallenge bool   `json:"noIdentityChallenge"`
}

func fleetRows(t *testing.T, url string) map[string]bool {
	t.Helper()
	resp, err := http.Get(url + "/dashboard/api/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var rows []fleetRow
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.ProxyID] = r.NoGroupPolicy
	}
	return out
}

func TestHeartbeat_FlagsWorkersWithoutGroupPolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy string
		want   map[string]bool
	}{
		{"scoped rules", scopedPolicyYAML, map[string]bool{"new": false, "other": true, "legacy": true}},
		{"no scoped rules", "policy:\n  allowlist:\n    - domain: plain.example.com\n", map[string]bool{"new": false, "other": false, "legacy": false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := New(Config{PolicyPath: writeScopedPolicy(t, tc.policy)})
			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			postHeartbeat(t, ts.URL, "new", `{"policyETag":"x","caps":["grouppolicy/v1"]}`)
			postHeartbeat(t, ts.URL, "other", `{"policyETag":"x","caps":["blocklist/v1"]}`)
			postHeartbeat(t, ts.URL, "legacy", `{"policyETag":"x"}`)
			got := fleetRows(t, ts.URL)
			for id, want := range tc.want {
				if got[id] != want {
					t.Errorf("%s noGroupPolicy = %v, want %v", id, got[id], want)
				}
			}
		})
	}
}

func TestHeartbeat_GroupPolicyCapsBounded(t *testing.T) {
	srv := New(Config{PolicyPath: writeScopedPolicy(t, scopedPolicyYAML)})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	caps := []string{`"grouppolicy/v1"`}
	for i := 0; i < 20; i++ {
		caps = append(caps, fmt.Sprintf(`"z%02d"`, i))
	}
	if c := postHeartbeat(t, ts.URL, "w", `{"policyETag":"x","caps":[`+strings.Join(caps, ",")+`]}`); c != http.StatusNoContent {
		t.Fatalf("status %d, want 204", c)
	}
	got := workerCaps(t, ts.URL, "w")
	if len(got) != maxCaps {
		t.Errorf("stored %d caps, want %d", len(got), maxCaps)
	}
	if got[0] != "grouppolicy/v1" {
		t.Errorf("caps = %v, want grouppolicy/v1 kept (sorts first)", got)
	}
	if fleetRows(t, ts.URL)["w"] {
		t.Error("worker advertising grouppolicy/v1 flagged")
	}
}

func TestWorkerLacksGroupPolicyLogOnce(t *testing.T) {
	buf := &lockedBuf{}
	path := writeScopedPolicy(t, scopedPolicyYAML)
	srv := New(Config{PolicyPath: path, Logger: slog.New(slog.NewTextHandler(buf, nil))})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	count := func() int { return strings.Count(buf.String(), "msg=worker_lacks_grouppolicy") }

	for i := 0; i < 3; i++ {
		postHeartbeat(t, ts.URL, "old", `{"policyETag":"x"}`)
	}
	postHeartbeat(t, ts.URL, "ok", `{"caps":["grouppolicy/v1"]}`)
	if n := count(); n != 1 {
		t.Fatalf("log lines = %d, want 1\n%s", n, buf.String())
	}
	out := buf.String()
	if !strings.Contains(out, "proxy_id=old") || !strings.Contains(out, "scoped_entries=1") {
		t.Errorf("missing fields: %s", out)
	}
	for _, leak := range []string{"top-secret-group", "secret-groupname-host"} {
		if strings.Contains(out, leak) {
			t.Errorf("log leaks %q: %s", leak, out)
		}
	}

	// A new ETag logs again, once.
	if err := os.WriteFile(path, []byte(scopedPolicyYAML+"    - domain: more.example.com\n      users: [a@example.com]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv.policy.Refresh()
	for i := 0; i < 2; i++ {
		postHeartbeat(t, ts.URL, "old", `{"policyETag":"x"}`)
	}
	if n := count(); n != 2 {
		t.Fatalf("after new etag log lines = %d, want 2\n%s", n, buf.String())
	}
	if !strings.Contains(buf.String(), "scoped_entries=2") {
		t.Errorf("want scoped_entries=2: %s", buf.String())
	}
}

func TestScopedEntryCount(t *testing.T) {
	if n := scopedEntryCount(projectScoped(scopedMCPWire(nil))); n != 0 {
		t.Errorf("unscoped = %d", n)
	}
	w := scopedMCPWire(&config.MCPToolCondition{Groups: []string{"eng"}})
	w.Allowlist = append(w.Allowlist, scopedEntry("b.example.com", "eng"))
	if n := scopedEntryCount(w); n != 2 {
		t.Errorf("raw = %d, want 2", n)
	}
	if n := scopedEntryCount(projectScoped(w)); n != 2 {
		t.Errorf("projected = %d, want 2", n)
	}
}
