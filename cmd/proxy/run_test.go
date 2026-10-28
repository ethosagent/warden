package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
)

// TestExplicitListenFlags: only flags set on the command line are returned, so a
// flag default never shadows a config value.
func TestExplicitListenFlags(t *testing.T) {
	cmd := newRunCmd()
	l, c, k, a, err := explicitListenFlags(cmd)
	if err != nil || l != "" || c != "" || k != "" || a != "" {
		t.Fatalf("unset flags must be empty: %q %q %q %q %v", l, c, k, a, err)
	}
	if err := cmd.ParseFlags([]string{"--listen", "127.0.0.1:1", "--ca-key", "k"}); err != nil {
		t.Fatal(err)
	}
	l, c, k, a, err = explicitListenFlags(cmd)
	if err != nil || l != "127.0.0.1:1" || c != "" || k != "k" || a != "" {
		t.Fatalf("got %q %q %q %q %v", l, c, k, a, err)
	}
}

// TestRunParams_ConfigListenWinsOverFlagDefault drives the real RunE param
// building: an unset --listen must not shadow config `listen:`, and a set flag
// must still win.
func TestRunParams_ConfigListenWinsOverFlagDefault(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "warden.yaml")
	yaml := "listen: \"127.0.0.1:18443\"\nadminListen: \"127.0.0.1:19191\"\npolicy:\n  allowlist:\n    - domain: example.com\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, err := config.NewLocalYAMLProvider(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(args ...string) config.Resolved {
		t.Helper()
		root := &cobra.Command{Use: "warden"}
		root.PersistentFlags().String("config", cfgPath, "")
		run := newRunCmd()
		root.AddCommand(run)
		if err := run.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		p, err := runParams(run)
		if err != nil {
			t.Fatal(err)
		}
		r, err := config.ResolveListen(pol, config.ListenFlags{
			Listen: p.ListenAddr, AdminListen: p.AdminAddr, CACert: p.CACert, CAKey: p.CAKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	r := resolve()
	if r.Listen.Value != "127.0.0.1:18443" || r.Listen.Source != "config listen:" ||
		r.AdminListen.Value != "127.0.0.1:19191" || r.AdminListen.Source != "config adminListen:" {
		t.Fatalf("config must apply when flags are unset: %+v", r)
	}
	r = resolve("--listen", "127.0.0.1:17070")
	if r.Listen.Value != "127.0.0.1:17070" || r.Listen.Source != "flag --listen" ||
		r.AdminListen.Source != "config adminListen:" {
		t.Fatalf("flag must win: %+v", r)
	}
}

// TestRunParams_AdminTokenEnvFlag: --admin-token-env reaches worker.Params; unset is empty.
func TestRunParams_AdminTokenEnvFlag(t *testing.T) {
	for args, want := range map[string]string{"": "", "WARDEN_ADMIN_TOKEN": "WARDEN_ADMIN_TOKEN"} {
		root := &cobra.Command{Use: "warden"}
		root.PersistentFlags().String("config", "x.yaml", "")
		run := newRunCmd()
		root.AddCommand(run)
		var argv []string
		if args != "" {
			argv = []string{"--admin-token-env", args}
		}
		if err := run.ParseFlags(argv); err != nil {
			t.Fatal(err)
		}
		p, err := runParams(run)
		if err != nil {
			t.Fatal(err)
		}
		if p.AdminTokenEnv != want {
			t.Errorf("flag %q: AdminTokenEnv = %q, want %q", args, p.AdminTokenEnv, want)
		}
	}
}

// TestControlPlaneAdminTokenFlag: the control plane's --admin-token-env reaches
// controlplane.Params.AdminTokenEnv; unset is empty, and --token-env stays a
// separate field.
func TestControlPlaneAdminTokenFlag(t *testing.T) {
	for args, want := range map[string]string{"": "", "WARDEN_CP_ADMIN_TOKEN": "WARDEN_CP_ADMIN_TOKEN"} {
		root := &cobra.Command{Use: "warden"}
		root.PersistentFlags().String("config", "x.yaml", "")
		cp := newControlPlaneCmd()
		root.AddCommand(cp)
		argv := []string{"--token-env", "WARDEN_CP_TOKEN"}
		if args != "" {
			argv = append(argv, "--admin-token-env", args)
		}
		if err := cp.ParseFlags(argv); err != nil {
			t.Fatal(err)
		}
		p, err := controlPlaneParams(cp)
		if err != nil {
			t.Fatal(err)
		}
		if p.AdminTokenEnv != want || p.TokenEnv != "WARDEN_CP_TOKEN" {
			t.Errorf("flag %q: AdminTokenEnv = %q, TokenEnv = %q; want %q, WARDEN_CP_TOKEN", args, p.AdminTokenEnv, p.TokenEnv, want)
		}
	}
}
