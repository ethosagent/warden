package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// minimalConfig is a valid default-deny worker/control-plane config with every
// optional block off — enough to load and serve.
const minimalConfig = `
policy:
  allowlist:
    - domain: api.openai.com
logging:
  level: error
  format: json
`

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return p
}

// executeRoot runs the root command with args under a context cancelled after a
// short delay, so subcommands that bind sockets (run, control-plane) start, serve,
// and shut down cleanly. It returns Execute's error.
func executeRoot(t *testing.T, args ...string) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()
	defer cancel()
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetContext(ctx)
	return root.Execute()
}

// TestParseDuration covers the human-friendly "Nd" day form, its error branch, and
// the fallback to time.ParseDuration.
func TestParseDuration(t *testing.T) {
	if d, err := parseDuration("7d"); err != nil || d != 7*24*time.Hour {
		t.Errorf("7d = %v, %v; want 168h", d, err)
	}
	if d, err := parseDuration("24h"); err != nil || d != 24*time.Hour {
		t.Errorf("24h = %v, %v", d, err)
	}
	if _, err := parseDuration("xd"); err == nil {
		t.Error("expected error for a non-numeric day duration")
	}
	if _, err := parseDuration("bogus"); err == nil {
		t.Error("expected error for an unparseable duration")
	}
}

// TestToInstanceConfigs verifies the CP-local integration config maps onto the
// integration package's InstanceConfig, carrying match clauses through untouched.
func TestToInstanceConfigs(t *testing.T) {
	if got := toInstanceConfigs(nil); got != nil {
		t.Errorf("nil input should map to nil, got %v", got)
	}
	insts := []config.IntegrationInstance{{
		Type:   "webhook",
		Name:   "alerts",
		Config: map[string]any{"url": "https://hooks.example/x"},
		Match:  []config.IntegrationMatch{{Severity: "high", Category: "leak", Domain: "api.x.com", Rule: "r1"}},
	}}
	got := toInstanceConfigs(insts)
	if len(got) != 1 {
		t.Fatalf("got %d instance configs, want 1", len(got))
	}
	ic := got[0]
	if ic.Type != "webhook" || ic.Name != "alerts" {
		t.Errorf("type/name not carried: %+v", ic)
	}
	if len(ic.Match) != 1 || ic.Match[0].Severity != "high" || ic.Match[0].Domain != "api.x.com" {
		t.Errorf("match clause not carried: %+v", ic.Match)
	}
	if ic.Config["url"] != "https://hooks.example/x" {
		t.Errorf("opaque config not passed through: %+v", ic.Config)
	}
}

// TestRunSubcommand exercises the `run` command's flag wiring end-to-end: it parses
// the flags into worker.Params and starts the worker, which binds ephemeral ports
// and shuts down on ctx cancel.
func TestRunSubcommand(t *testing.T) {
	cfg := writeTempConfig(t, minimalConfig)
	db := filepath.Join(t.TempDir(), "warden.db")
	err := executeRoot(t, "run",
		"--config", cfg,
		"--listen", "127.0.0.1:0",
		"--admin-listen", "127.0.0.1:0",
		"--db", db,
		"--local-only",
	)
	if err != nil {
		t.Fatalf("run subcommand returned error on clean shutdown: %v", err)
	}
}

// TestControlPlaneSubcommand_InPlace covers runControlPlane serving the config in
// place (no --state-dir): config validation, analytics store build, HTTP server
// bind on an ephemeral port, and a clean ctx-driven shutdown.
func TestControlPlaneSubcommand_InPlace(t *testing.T) {
	dir := t.TempDir()
	cfg := writeTempConfig(t, minimalConfig)
	err := executeRoot(t, "control-plane",
		"--config", cfg,
		"--listen", "127.0.0.1:0",
		"--analytics-db", filepath.Join(dir, "fleet.db"),
		"--alerts-db", filepath.Join(dir, "alerts.db"),
	)
	if err != nil {
		t.Fatalf("control-plane (in place) returned error on clean shutdown: %v", err)
	}
}

// TestControlPlaneSubcommand_StateDir covers the writable-copy path: --state-dir
// seeds a served config from --config, defaults the fleet + alert DB paths under
// the state dir, and serves an ephemeral listener until ctx cancel.
func TestControlPlaneSubcommand_StateDir(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	cfg := writeTempConfig(t, minimalConfig)
	err := executeRoot(t, "control-plane",
		"--config", cfg,
		"--listen", "127.0.0.1:0",
		"--state-dir", stateDir,
		"--token-env", "WARDEN_CP_TOKEN_UNSET",
	)
	if err != nil {
		t.Fatalf("control-plane (state-dir) returned error on clean shutdown: %v", err)
	}
	// The served config was seeded into the state dir.
	if _, err := os.Stat(filepath.Join(stateDir, "config.yaml")); err != nil {
		t.Errorf("served config not seeded into state dir: %v", err)
	}
}

// TestControlPlaneSubcommand_CAFlagMismatch covers the guard that both --ca-cert and
// --ca-key must be provided together.
func TestControlPlaneSubcommand_CAFlagMismatch(t *testing.T) {
	cfg := writeTempConfig(t, minimalConfig)
	err := executeRoot(t, "control-plane",
		"--config", cfg,
		"--listen", "127.0.0.1:0",
		"--state-dir", t.TempDir(),
		"--ca-cert", "only-cert.pem",
	)
	if err == nil {
		t.Fatal("expected an error when only --ca-cert is set")
	}
}

// TestControlPlaneSubcommand_BadConfig verifies a missing config surfaces a load
// error before the server binds.
func TestControlPlaneSubcommand_BadConfig(t *testing.T) {
	err := executeRoot(t, "control-plane",
		"--config", filepath.Join(t.TempDir(), "missing.yaml"),
		"--listen", "127.0.0.1:0",
		"--state-dir", t.TempDir(),
	)
	if err == nil {
		t.Fatal("expected an error for a missing config file")
	}
}

// TestSuggestSubcommand runs `policy suggest` against an empty analytics DB: no
// events yields empty suggestions, exercising the RunE flag parse + store open +
// build + format path without any network.
func TestSuggestSubcommand(t *testing.T) {
	db := filepath.Join(t.TempDir(), "warden.db")
	var out bytes.Buffer
	root := newRootCmd()
	root.SetArgs([]string{"policy", "suggest", "--db", db, "--since", "1d"})
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("suggest: %v", err)
	}
}

// TestSuggestSubcommand_BadSince covers the invalid-duration error branch.
func TestSuggestSubcommand_BadSince(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"policy", "suggest", "--since", "notaduration"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil {
		t.Fatal("expected an error for a bad --since value")
	}
}

// TestEvalSubcommand runs `policy eval` with a candidate policy against an empty DB,
// exercising the RunE: candidate load, store open, evaluate, and report print.
func TestEvalSubcommand(t *testing.T) {
	candidate := writeTempConfig(t, minimalConfig)
	db := filepath.Join(t.TempDir(), "warden.db")
	var out bytes.Buffer
	root := newRootCmd()
	root.SetArgs([]string{"policy", "eval", "--candidate", candidate, "--db", db, "--since", "30d"})
	root.SetOut(&out)
	root.SetErr(&out)
	if err := root.Execute(); err != nil {
		t.Fatalf("eval: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("Policy Evaluation Report")) {
		t.Errorf("eval report missing header, got: %q", out.String())
	}
}

// TestEvalSubcommand_BadCandidate covers the candidate-load error branch.
func TestEvalSubcommand_BadCandidate(t *testing.T) {
	root := newRootCmd()
	root.SetArgs([]string{"policy", "eval", "--candidate", filepath.Join(t.TempDir(), "missing.yaml"), "--since", "1d"})
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	if err := root.Execute(); err == nil {
		t.Fatal("expected an error for a missing candidate policy")
	}
}

// TestAdviseSubcommand_Errors covers the advise RunE error branches that need no
// LLM: an invalid --since, and a config whose judge block is not configured for the
// advisor.
func TestAdviseSubcommand_Errors(t *testing.T) {
	cfg := writeTempConfig(t, minimalConfig)

	t.Run("bad since", func(t *testing.T) {
		root := newRootCmd()
		root.SetArgs([]string{"advise", "--config", cfg, "--since", "notaduration"})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		if err := root.Execute(); err == nil {
			t.Fatal("expected an error for a bad --since value")
		}
	})

	t.Run("advisor not configured", func(t *testing.T) {
		root := newRootCmd()
		root.SetArgs([]string{"advise", "--config", cfg, "--since", "1d"})
		root.SetOut(io.Discard)
		root.SetErr(io.Discard)
		if err := root.Execute(); err == nil {
			t.Fatal("expected an error when judge/advisor is not configured")
		}
	})
}
