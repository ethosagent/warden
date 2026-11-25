package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestNoTestHooksInBinary proves the shipped commands cannot reach the test
// seams, name-free, two ways:
//  1. every pointer, func, interface, map, chan or slice field of the params
//     `warden run` and `warden control-plane` build from their flags is zero
//     (bar a short justified allowlist), so a seam added later is covered
//     without anyone listing its name;
//  2. no non-test file in cmd/proxy imports reflect, so nothing can reach a
//     seam field by computed name.
//
// The type-based guard that no YAML key can map to a seam is the configurability
// test in internal/worker (internal/worker/overrides_test.go, named after the
// seam struct); it is deliberately not duplicated here by field name, and this
// file must not spell that struct's name, which that guard forbids in cmd/proxy.
func TestNoTestHooksInBinary(t *testing.T) {
	t.Run("run params", func(t *testing.T) {
		cmd := subcommand(t, "run")
		if err := cmd.ParseFlags([]string{"--config", "unused.yaml"}); err != nil {
			t.Fatal(err)
		}
		p, err := runParams(cmd)
		if err != nil {
			t.Fatal(err)
		}
		requireSeamsZero(t, reflect.ValueOf(p), "worker.Params", "", nil)
	})

	t.Run("control-plane params", func(t *testing.T) {
		cmd := subcommand(t, "control-plane")
		if err := cmd.ParseFlags([]string{"--config", "unused.yaml"}); err != nil {
			t.Fatal(err)
		}
		p, err := controlPlaneParams(cmd)
		if err != nil {
			t.Fatal(err)
		}
		requireSeamsZero(t, reflect.ValueOf(p), "controlplane.Params", "", cpAllowedNonScalar)
	})

	t.Run("cmd/proxy sources never import reflect", func(t *testing.T) {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				if imp.Path.Value == `"reflect"` {
					t.Errorf("%s imports reflect; the binary must not reach Params fields by computed name", e.Name())
				}
			}
		}
	})
}

// subcommand returns the named subcommand of the real root command, so the
// persistent flags (--config) are defined exactly as in the shipped binary.
func subcommand(t *testing.T, name string) *cobra.Command {
	t.Helper()
	cmd, _, err := newRootCmd().Find([]string{name})
	if err != nil || cmd.Name() != name {
		t.Fatalf("subcommand %q not found: %v", name, err)
	}
	return cmd
}

// cpAllowedNonScalar lists, by path, the non-scalar controlplane.Params fields
// the control-plane flags legitimately set. Backup.Include is the []string of
// paths from the repeatable --backup-include flag: plain data, not a collaborator
// or callback. Everything else in Backup is scalar, and a func or interface
// added anywhere (Backup included) still fails.
var cpAllowedNonScalar = map[string]bool{"Backup.Include": true}

// requireSeamsZero fails if any pointer, func, interface, map, chan or slice
// field of a params struct (recursing into nested structs) is set, except the
// named allowlist. It never names a seam, so a new seam is covered on arrival.
func requireSeamsZero(t *testing.T, v reflect.Value, label, path string, allowed map[string]bool) {
	t.Helper()
	rt := v.Type()
	for i := 0; i < rt.NumField(); i++ {
		name := rt.Field(i).Name
		fpath := strings.TrimPrefix(path+"."+name, ".")
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Pointer, reflect.Func, reflect.Interface, reflect.Map, reflect.Chan, reflect.Slice:
			if allowed[fpath] {
				continue
			}
			if !f.IsZero() {
				t.Errorf("%s.%s is set by the shipped command's flag parsing; test seams must stay nil outside Go tests", label, fpath)
			}
		case reflect.Struct:
			requireSeamsZero(t, f, label, fpath, allowed)
		}
	}
}
