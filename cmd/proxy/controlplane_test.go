package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func parseCPFlags(t *testing.T, args ...string) (*cobra.Command, error) {
	t.Helper()
	cp := newControlPlaneCmd()
	root := &cobra.Command{Use: "warden"}
	root.PersistentFlags().String("config", "x.yaml", "")
	root.AddCommand(cp)
	return cp, cp.ParseFlags(args)
}

// TestControlPlaneAuthFlags: the worker-auth flags reach controlplane.Params,
// --token-env stays as a deprecated alias, and the validation that lives in
// controlplane.Run (rule C1) surfaces through the command before it listens.
func TestControlPlaneAuthFlags(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cp, err := parseCPFlags(t)
		if err != nil {
			t.Fatal(err)
		}
		p, err := controlPlaneParams(cp)
		if err != nil {
			t.Fatal(err)
		}
		if p.LegacyTokenEnv != "" || p.TokenEnv != "" || p.RequireWorkerTokens || p.AllowInsecureWorkerAuth {
			t.Errorf("defaults changed behaviour: %+v", p)
		}
	})
	t.Run("all set", func(t *testing.T) {
		cp, err := parseCPFlags(t, "--legacy-token-env", "L", "--require-worker-tokens", "--allow-insecure-worker-auth", "--token-env", "T")
		if err != nil {
			t.Fatal(err)
		}
		p, _ := controlPlaneParams(cp)
		if p.LegacyTokenEnv != "L" || p.TokenEnv != "T" || !p.RequireWorkerTokens || !p.AllowInsecureWorkerAuth {
			t.Errorf("params = %+v", p)
		}
	})
	t.Run("token-env is a deprecated alias", func(t *testing.T) {
		cp, _ := parseCPFlags(t)
		f := cp.Flags().Lookup("token-env")
		if f == nil || !strings.Contains(f.Deprecated, "--legacy-token-env") {
			t.Fatalf("--token-env deprecation = %+v", f)
		}
		if cp.Flags().Lookup("legacy-token-env").Deprecated != "" {
			t.Error("--legacy-token-env must not be deprecated")
		}
	})
	cfg := writeTempConfig(t, minimalConfig)
	state := t.TempDir()
	fail := map[string]struct {
		args []string
		want string
	}{
		"different names":    {[]string{"--token-env", "A", "--legacy-token-env", "B"}, "--legacy-token-env"},
		"strict no state":    {[]string{"--require-worker-tokens", "--allow-insecure-worker-auth"}, "--state-dir"},
		"strict with legacy": {[]string{"--require-worker-tokens", "--state-dir", state, "--legacy-token-env", "L", "--allow-insecure-worker-auth"}, "--legacy-token-env"},
		"strict with alias":  {[]string{"--require-worker-tokens", "--state-dir", state, "--token-env", "L", "--allow-insecure-worker-auth"}, "--token-env"},
		"strict no tls":      {[]string{"--require-worker-tokens", "--state-dir", state}, "--allow-insecure-worker-auth"},
	}
	for name, c := range fail {
		t.Run(name, func(t *testing.T) {
			args := append([]string{"control-plane", "--config", cfg, "--listen", "127.0.0.1:0",
				"--analytics-db", filepath.Join(t.TempDir(), "f.db")}, c.args...)
			err := executeRoot(t, args...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one naming %s", err, c.want)
			}
		})
	}
	t.Run("strict starts", func(t *testing.T) {
		d := t.TempDir()
		err := executeRoot(t, "control-plane", "--config", cfg, "--listen", "127.0.0.1:0",
			"--analytics-db", filepath.Join(d, "f.db"), "--alerts-db", filepath.Join(d, "a.db"),
			"--state-dir", filepath.Join(d, "state"), "--require-worker-tokens", "--allow-insecure-worker-auth")
		if err != nil {
			t.Fatalf("strict start: %v", err)
		}
	})
}
