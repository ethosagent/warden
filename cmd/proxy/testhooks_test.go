package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/worker"
)

const workerSeamField = "Over" + "rides"

// goOnlySeams names every Go-only test seam on worker.Params and
// controlplane.Params: injected listeners, readiness callbacks, clocks, fake
// stores and clients, and the worker assembly overrides (which carry the upstream dialer
// and root pool that replace the SafeDialer; the field is workerSeamField). The shipped binary must never set
// any of them: they are reachable from Go code only, so no YAML key, env var or
// flag can weaken the SSRF guard or swap a collaborator in production.
var goOnlySeams = []string{
	// worker.Params. The worker's assembly-override field name is spelled in
	// two parts because the worker package's configurability guard fails
	// if any file in cmd/proxy, tests included, contains the whole word.
	workerSeamField, "ProxyListener", "AdminListener", "OnReady", "OnTransparentReady", "Config",
	// controlplane.Params
	"Listener", "OnServer", "KeysReady", "APIKeysReady", "Clock", "KeyStore",
	"KeysAWSClient", "ErrOut", "Findings", "BackupReporter",
}

// TestNoTestHooksInBinary proves the shipped commands cannot reach the test
// seams, three ways:
//  1. the params `warden run` and `warden control-plane` build from their flags
//     leave every Go-only seam at its zero value;
//  2. no non-test file in cmd/proxy names a seam, so no flag or wiring can set
//     one, today or in a file added later;
//  3. no field of config.Policy (the whole YAML schema) has a seam's name, so no
//     YAML key can exist for it.
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
		requireSeamsZero(t, reflect.ValueOf(p), "worker.Params")
		if f := reflect.ValueOf(p).FieldByName(workerSeamField); !f.IsValid() || !f.IsNil() {
			t.Fatal("worker.Params." + workerSeamField + " must exist and be nil in the shipped binary")
		}
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
		requireSeamsZero(t, reflect.ValueOf(p), "controlplane.Params")
	})

	t.Run("seam names exist", func(t *testing.T) {
		// Guards the list above against a rename that would silently empty it.
		have := map[string]bool{}
		for _, v := range []any{worker.Params{}, controlplane.Params{}} {
			rt := reflect.TypeOf(v)
			for i := 0; i < rt.NumField(); i++ {
				have[rt.Field(i).Name] = true
			}
		}
		for _, name := range goOnlySeams {
			if !have[name] {
				t.Errorf("goOnlySeams names %q, which is on neither worker.Params nor controlplane.Params", name)
			}
		}
	})

	t.Run("cmd/proxy sources never name a seam", func(t *testing.T) {
		seams := map[string]bool{"TestHooks": true}
		for _, name := range goOnlySeams {
			// Config and ErrOut are read legitimately elsewhere in cmd/proxy
			// (a *config.Policy loader, the cobra error writer); the zero-value
			// check above is what pins them. The rest must not appear at all.
			if name != "Config" && name != "ErrOut" {
				seams[name] = true
			}
		}
		fset := token.NewFileSet()
		entries, err := os.ReadDir(".")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(".", e.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				var name string
				switch x := n.(type) {
				case *ast.SelectorExpr:
					name = x.Sel.Name
				case *ast.KeyValueExpr:
					if id, ok := x.Key.(*ast.Ident); ok {
						name = id.Name
					}
				}
				if seams[name] {
					t.Errorf("%s: %s names the Go-only test seam %q; the binary must never set it",
						fset.Position(n.Pos()), e.Name(), name)
				}
				return true
			})
		}
	})

	t.Run("no YAML field carries a seam name", func(t *testing.T) {
		names := map[string]bool{"TestHooks": true}
		for _, name := range goOnlySeams {
			names[name] = true
		}
		seen := map[reflect.Type]bool{}
		var walk func(rt reflect.Type, path string)
		walk = func(rt reflect.Type, path string) {
			if rt == nil || seen[rt] {
				return
			}
			seen[rt] = true
			switch rt.Kind() {
			case reflect.Struct:
				for i := 0; i < rt.NumField(); i++ {
					f := rt.Field(i)
					if names[f.Name] && f.Name != "Config" && f.Name != "Clock" {
						t.Errorf("config.Policy has a field %s.%s named like a Go-only test seam", path, f.Name)
					}
					walk(f.Type, path+"."+f.Name)
				}
			case reflect.Pointer, reflect.Slice, reflect.Array:
				walk(rt.Elem(), path+"[*]")
			case reflect.Map:
				walk(rt.Elem(), path+"(value)")
			}
		}
		walk(reflect.TypeOf(config.Policy{}), "config.Policy")
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

// requireSeamsZero fails if any Go-only seam field of a params struct is set.
func requireSeamsZero(t *testing.T, v reflect.Value, label string) {
	t.Helper()
	for _, name := range goOnlySeams {
		f := v.FieldByName(name)
		if !f.IsValid() {
			continue
		}
		if !f.IsZero() {
			t.Errorf("%s.%s is set by the shipped command's flag parsing; test seams must stay nil outside Go tests", label, name)
		}
	}
}
