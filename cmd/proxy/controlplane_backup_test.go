package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
)

// parseCP runs the control-plane flag parsing the way RunE does, without
// starting the server.
func parseCP(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newControlPlaneCmd()
	cmd.Flags().String("config", "", "") // a root persistent flag in the real binary
	if err := cmd.ParseFlags(append([]string{"--config", "c.yaml"}, args...)); err != nil {
		t.Fatal(err)
	}
	p, err := controlPlaneParams(cmd)
	if err != nil {
		return "", err
	}
	return p.Backup.Dir, nil
}

func TestControlPlaneBackupFlags(t *testing.T) {
	root := t.TempDir()
	state, backups := filepath.Join(root, "state"), filepath.Join(root, "backups")

	for _, c := range []struct {
		name string
		args []string
		flag string // "" = accepted
	}{
		{"off", nil, ""},
		{"off with state dir", []string{"--state-dir", state}, ""},
		{"on", []string{"--state-dir", state, "--backup-dir", backups}, ""},
		{"all values", []string{"--state-dir", state, "--backup-dir", backups, "--backup-interval", "1h", "--backup-keep", "1", "--backup-include", "cp,fleet"}, ""},
		{"dir without state dir", []string{"--backup-dir", backups}, "--backup-dir"},
		{"dir equals state dir", []string{"--state-dir", state, "--backup-dir", state}, "--backup-dir"},
		{"dir inside state dir", []string{"--state-dir", state, "--backup-dir", filepath.Join(state, "backups")}, "--backup-dir"},
		{"interval 30m", []string{"--state-dir", state, "--backup-dir", backups, "--backup-interval", "30m"}, "--backup-interval"},
		{"keep 0", []string{"--state-dir", state, "--backup-dir", backups, "--backup-keep", "0"}, "--backup-keep"},
		{"include bogus", []string{"--state-dir", state, "--backup-dir", backups, "--backup-include", "bogus"}, "--backup-include"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseCP(t, c.args...)
			switch {
			case c.flag == "" && err != nil:
				t.Fatalf("rejected: %v", err)
			case c.flag != "" && (err == nil || !strings.Contains(err.Error(), c.flag)):
				t.Fatalf("err = %v, want one naming %s", err, c.flag)
			}
		})
	}
}

func TestControlPlaneBackupFlagDefaults(t *testing.T) {
	cmd := newControlPlaneCmd()
	cmd.Flags().String("config", "", "")
	if err := cmd.ParseFlags([]string{"--config", "c.yaml"}); err != nil {
		t.Fatal(err)
	}
	p, err := controlPlaneParams(cmd)
	if err != nil {
		t.Fatal(err)
	}
	b := p.Backup
	if b.Dir != "" || b.Interval != 24*time.Hour || b.Keep != 7 || strings.Join(b.Include, ",") != "cp,alerts,config" {
		t.Fatalf("defaults = %+v", b)
	}
	if p.Version != version {
		t.Errorf("Version = %q, want the build version", p.Version)
	}
}

// TestBundleGateDefaults: the CLI half of the Phase 2 gate flip (#719). With no
// --bundles flag the control plane gets controlplane.BundlesDefault, which Run
// resolves to require when --state-dir, --policy-store=versioned and keys.enabled
// are present; --bundles=off and offer pass through as the explicit opt-outs.
func TestBundleGateDefaults(t *testing.T) {
	flag := newControlPlaneCmd().Flags().Lookup("bundles")
	if flag == nil {
		t.Fatal("no --bundles flag")
	}
	if flag.DefValue != controlplane.BundlesDefault {
		t.Errorf("--bundles default = %q, want the unset default %q (require when the prerequisites are present)", flag.DefValue, controlplane.BundlesDefault)
	}
	for _, want := range []string{"require", "offer", "off", "WARN"} {
		if !strings.Contains(flag.Usage, want) {
			t.Errorf("--bundles usage does not mention %q: %s", want, flag.Usage)
		}
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, controlplane.BundlesDefault},
		{[]string{"--bundles", "off"}, controlplane.BundlesOff},
		{[]string{"--bundles=offer"}, controlplane.BundlesOffer},
		{[]string{"--bundles=require"}, controlplane.BundlesRequire},
	} {
		cmd := newControlPlaneCmd()
		cmd.Flags().String("config", "", "")
		if err := cmd.ParseFlags(append([]string{"--config", "c.yaml"}, tc.args...)); err != nil {
			t.Fatal(err)
		}
		p, err := controlPlaneParams(cmd)
		if err != nil {
			t.Fatal(err)
		}
		if p.Bundles != tc.want {
			t.Errorf("args %v: Params.Bundles = %q, want %q", tc.args, p.Bundles, tc.want)
		}
	}
}
