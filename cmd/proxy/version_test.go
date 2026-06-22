package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionCommandOutput(t *testing.T) {
	cmd := newVersionCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, version) {
		t.Errorf("version output %q does not contain version %q", got, version)
	}
	if !strings.HasPrefix(got, "warden ") {
		t.Errorf("version output %q does not start with %q", got, "warden ")
	}
}

func TestRootCommandHasSubcommands(t *testing.T) {
	root := newRootCmd()

	want := map[string]bool{"run": false, "version": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("root command missing subcommand %q", name)
		}
	}

	if root.PersistentFlags().Lookup("config") == nil {
		t.Error("root command missing persistent --config flag")
	}
}
