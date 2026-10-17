package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func run(t *testing.T, diff func(base, head string) ([]string, error), args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := realMain(args, &out, &errb, diff)
	return code, out.String(), errb.String()
}

func fixedDiff(files ...string) func(string, string) ([]string, error) {
	return func(string, string) ([]string, error) { return files, nil }
}

type doc struct {
	Schema string `json:"schema"`
	OK     bool   `json:"ok"`
	Stages []struct {
		Name    string         `json:"name"`
		Metrics map[string]any `json:"metrics"`
	} `json:"stages"`
}

func TestTierForFixtureDiffs(t *testing.T) {
	cases := []struct {
		name  string
		files []string
		tier  string
		e2e   bool
	}{
		{"docs only", []string{"docs/testing-guide.md", "README.md"}, "low", false},
		{"tests only", []string{"internal/dlp/dlp_test.go"}, "normal", false},
		{"internal/proxy", []string{"internal/proxy/proxy.go"}, "critical", true},
		{"check.sh", []string{"scripts/check.sh"}, "gates", false},
		{"unmatched", []string{"Makefile"}, "normal", false},
	}
	for _, c := range cases {
		code, out, errs := run(t, fixedDiff(c.files...), "-risk", "../../.agents/risk.yaml", "-base", "b", "-head", "h")
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", c.name, code, errs)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, out)
		}
		m := d.Stages[0].Metrics
		if d.Schema != "warden.check.v1" || !d.OK || m["tier"] != c.tier || m["label"] != "risk:"+c.tier || m["e2eRequired"] != c.e2e {
			t.Errorf("%s: doc = %+v", c.name, d)
		}
	}
}

func TestFailsClosedOnBadInput(t *testing.T) {
	if code, _, _ := run(t, fixedDiff(), "-risk", "does-not-exist.yaml", "-base", "b", "-head", "h"); code == 0 {
		t.Error("a missing risk map must fail")
	}
	bad := func(string, string) ([]string, error) { return nil, os.ErrNotExist }
	if code, _, errs := run(t, bad, "-risk", "../../.agents/risk.yaml", "-base", "b", "-head", "h"); code == 0 || !strings.Contains(errs, "git diff") {
		t.Errorf("a failing git diff must fail: %d %q", code, errs)
	}
	if code, _, _ := run(t, fixedDiff(), "-risk", "../../.agents/risk.yaml"); code != 2 {
		t.Errorf("missing -base/-head must be a usage error, got %d", code)
	}
}
