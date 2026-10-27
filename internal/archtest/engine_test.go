package archtest

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// testArch exercises the whole rule set against a synthetic module. Every
// package lands in a class and a zone, so only the deliberate violations are
// reported.
const testArch = `
version: 1
classes:
  - id: assembly
    layer: assembly
    imported-by: ["cmd/**"]
    paths: ["w/asm"]
  - id: transport
    layer: transport
    paths: ["w/trans", "w/routes", "w/runner"]
  - id: engine
    layer: engine
    paths: ["w/eng"]
  - id: decision
    layer: decision
    paths: ["w/pure"]
  - id: repository
    layer: repository
    paths: ["**/adapters/**", "w/repo", "w/adapter", "w/httpctor"]
  - id: domain
    layer: domain
    paths: ["w/dom", "w/domx", "w/other", "w/ctl"]
  - id: testutil
    layer: testutil
    paths: ["w/fakes", "w/conv"]
  # catch-all for the single-directory helper packages of this module
  - id: misc
    layer: transport
    paths: ["w/*"]
zones:
  data: ["w/eng", "w/pure", "w/cross", "w/httpctor"]
  control: ["w/asm", "w/trans", "w/runner", "w/routes", "w/ctl", "w/dom", "w/domx", "w/other", "w/repo", "w/adapter", "w/sign", "w/state", "w/app", "w/keys", "w/httpc", "w/cfgx", "w/svc", "w/envtest", "w/notest", "w/mux", "w/with", "w/cgo", "w/dom/adapters/store"]
  shared: ["w/fakes", "w/conv"]
rules:
  - id: L1
    title: imports point down
    checker: archtest
    fix: depend on the port
  - id: L2
    title: nothing imports assembly
    checker: archtest
    fix: invert the dependency
  - id: L3
    title: pure code does no I/O
    checker: archtest
    fix: inject it
    banned-imports: [net, net/http, os]
    banned-calls: ["time.Now"]
    applies-to-classes: [domain, decision]
  - id: L4a
    title: only the engine handles proxied traffic
    checker: archtest
    fix: depend on the side-call port
    banned-imports: [database/sql]
    applies-to-classes: [engine, decision]
  - id: L5
    title: a domain never imports its own adapters
    checker: archtest
    fix: move the port into the domain
  - id: L6
    title: transport never imports repositories
    checker: archtest
    fix: call a domain service
  - id: S2
    title: production code never imports test packages
    checker: archtest
    fix: move the import behind a port
  - id: S4
    title: no package-level mutable state
    checker: archtest
    fix: build it in a constructor
  - id: S5
    title: use the domain API, not its adapters
    checker: archtest
    fix: import the domain package
  - id: Z2
    title: the planes never cross
    checker: archtest
    fix: depend on shared
  - id: Z4
    title: only the engine opens sockets
    checker: archtest
    fix: dial through the shared constructor
  - id: C2
    title: no CGo sqlite
    checker: golangci+archtest
    fix: use the pure-Go driver
    blocked-modules:
      - module: github.com/mattn/go-sqlite3
        reason: CGo SQLite is banned
  - id: C3
    title: every package has tests
    checker: archtest
    fix: add a test
  - id: X1
    title: signing only in signer adapters
    checker: archtest
    fix: move signing into the signer adapter
    banned-calls: ["crypto/ed25519.Sign"]
    signer-paths: ["**/adapters/signer/**"]
  - id: X2
    title: control-plane config is json:"-"
    checker: archtest
    fix: tag the field
    structs:
      - package: w/cfgx
        type: Leaked
  - id: X3
    title: os.Environ banned; exec only in adapters
    checker: archtest
    fix: pass an explicit env
    exec-allowed-in: [repository, devtool]
  - id: X4
    title: no bare outbound clients
    checker: archtest
    fix: use the shared constructor
    banned-calls: ["net/http.Get"]
    client-constructors: ["w/httpctor/ctor.go"]
  - id: X5
    title: key prefixes only via the builder
    checker: archtest
    fix: call the builder
    prefixes:
      - prefix: "warden/"
        builder: the key builder
        owner-packages: [w/keys-owner]
  - id: X9
    title: routes live in routes.go
    checker: archtest
    fix: move the registration into routes.go
    route-files: ["routes.go"]
  - id: L8
    title: every package has a class
    checker: archtest
    fix: classify the package in architecture.yaml
  - id: Z1
    title: every package has a zone
    checker: archtest
    fix: assign the package to a zone
modules:
  direct:
    - module: golang.org/x/net
      layers: [engine]
  indirect: [github.com/kr/text]
`

// testArchNoX2 drops the X2 structs entry: a structs entry whose package is
// not part of the run is a hard gate-input error by design, so tests that load
// only a subset of the module must not carry it.
var testArchNoX2 = strings.Replace(testArch,
	"    structs:\n      - package: w/cfgx\n        type: Leaked\n", "", 1)

// writeModule lays out a synthetic module for the engine to check.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// want is the (rule, file, line) triple a test expects.
type want struct {
	rule, file string
	line       int
}

func assertFindings(t *testing.T, got []Finding, wants ...want) {
	t.Helper()
	var actual []want
	for _, f := range got {
		if f.Fix == "" {
			t.Errorf("finding %v has an empty fix", f)
		}
		if f.Message == "" {
			t.Errorf("finding %v has an empty message", f)
		}
		actual = append(actual, want{f.Rule, f.File, f.Line})
	}
	less := func(a, b want) bool {
		return a.rule < b.rule || a.rule == b.rule &&
			(a.file < b.file || a.file == b.file && a.line < b.line)
	}
	sort.Slice(actual, func(i, j int) bool { return less(actual[i], actual[j]) })
	sort.Slice(wants, func(i, j int) bool { return less(wants[i], wants[j]) })
	if len(actual) != len(wants) {
		t.Fatalf("findings = %v, want %d findings", actual, len(wants))
	}
	for i := range wants {
		if actual[i] != wants[i] {
			t.Errorf("finding %d = %v, want %v", i, actual[i], wants[i])
		}
	}
}

// TestEngineRules is the core rule check: a synthetic module with one or more
// violations per rule, and the exact findings the engine must report.
func TestEngineRules(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": "module example.com/tiny\n\ngo 1.24\n",
		// L2 — a non-cmd package imports assembly.
		"w/app/app.go":      "package app\n\nimport _ \"example.com/tiny/w/asm\"\n",
		"w/app/app_test.go": "package app\n",
		"w/asm/asm.go":      "package asm\n",
		"w/asm/asm_test.go": "package asm\n",
		// L5 — a domain imports its own adapter.
		"w/dom/dom.go":                       "package dom\n\nimport _ \"example.com/tiny/w/dom/adapters/store\"\n",
		"w/dom/dom_test.go":                  "package dom\n",
		"w/dom/adapters/store/store.go":      "package store\n\ntype Store struct{}\n",
		"w/dom/adapters/store/store_test.go": "package store\n",
		// S5 — another domain imports that adapter.
		"w/other/other.go":      "package other\n\nimport _ \"example.com/tiny/w/dom/adapters/store\"\n",
		"w/other/other_test.go": "package other\n",
		// L1 — a domain imports a repository directly.
		"w/domx/domx.go":      "package domx\n\nimport _ \"example.com/tiny/w/repo\"\n",
		"w/domx/domx_test.go": "package domx\n",
		"w/repo/repo.go":      "package repo\n",
		"w/repo/repo_test.go": "package repo\n",
		// L6 — transport imports a repository.
		"w/trans/trans.go":      "package trans\n\nimport _ \"example.com/tiny/w/repo\"\n",
		"w/trans/trans_test.go": "package trans\n",
		// L4a — the engine imports a repository and pulls in database/sql.
		"w/eng/eng.go":      "package eng\n\nimport (\n\t_ \"database/sql\"\n\n\t_ \"example.com/tiny/w/repo\"\n)\n",
		"w/eng/eng_test.go": "package eng\n",
		// L3 — a decision stage does I/O: an import and a call.
		"w/pure/pure.go":      "package pure\n\nimport (\n\t\"net/http\"\n\t\"time\"\n)\n\nvar _ = http.StatusOK\n\nfunc Check() bool { return time.Now().Before(time.Time{}) }\n",
		"w/pure/pure_test.go": "package pure\n",
		// S2 — production code imports a test-support package.
		"w/fakes/fakes.go":  "package fakes\n",
		"w/svc/svc.go":      "package svc\n\nimport _ \"example.com/tiny/w/fakes\"\n",
		"w/svc/svc_test.go": "package svc\n",
		// Z2 — a data-plane package imports a control-plane one.
		"w/ctl/ctl.go":          "package ctl\n",
		"w/ctl/ctl_test.go":     "package ctl\n",
		"w/cross/cross.go":      "package cross\n\nimport _ \"example.com/tiny/w/ctl\"\n",
		"w/cross/cross_test.go": "package cross\n",
		// X1 — signing through an alias, outside a signer adapter. A matcher
		// keyed on the text "ed25519.Sign" cannot see "signed.Sign".
		"w/sign/sign.go":      "package sign\n\nimport signed \"crypto/ed25519\"\n\nfunc Sign(k signed.PrivateKey, m []byte) []byte { return signed.Sign(k, m) }\n",
		"w/sign/sign_test.go": "package sign\n",
		// X4 — three shapes of a bare outbound client.
		"w/httpc/httpc.go":      "package httpc\n\nimport \"net/http\"\n\nfunc Get() { http.Get(\"https://x\") }\n\nfunc Do() { http.DefaultClient.Do(nil) }\n\nfunc New() *http.Client { return &http.Client{} }\n",
		"w/httpc/httpc_test.go": "package httpc\n",
		// X4/Z4 — the client-constructors exemption is per file, not per package.
		"w/httpctor/ctor.go":      "package httpctor\n\nimport (\n\t_ \"crypto/tls\"\n\t_ \"net\"\n\t\"net/http\"\n)\n\nfunc New() *http.Client { return &http.Client{} }\n\nfunc Get() { http.Get(\"https://x\") }\n",
		"w/httpctor/other.go":     "package httpctor\n\nimport (\n\t\"net\"\n\t\"net/http\"\n)\n\nvar _ net.Conn\n\nfunc Other() *http.Client { return &http.Client{} }\n",
		"w/httpctor/ctor_test.go": "package httpctor\n",
		// X5 — the reserved key prefix formatted by hand.
		"w/keys/keys.go":      "package keys\n\nvar K = \"warden/thing\"\n",
		"w/keys/keys_test.go": "package keys\n",
		// X9 — a route registered inside routes.go is allowed...
		"w/routes/routes.go":      "package routes\n\nimport \"net/http\"\n\nfunc Reg() *http.ServeMux {\n\tm := http.NewServeMux()\n\tm.HandleFunc(\"/x\", nil)\n\treturn m\n}\n",
		"w/routes/routes_test.go": "package routes\n",
		// ...and one registered anywhere else is the violation.
		"w/mux/mux.go":      "package mux\n\nimport \"net/http\"\n\nfunc Reg() *http.ServeMux {\n\tm := http.NewServeMux()\n\tm.HandleFunc(\"/y\", nil)\n\treturn m\n}\n",
		"w/mux/mux_test.go": "package mux\n",
		// S4 — init() and a mutated package-level map.
		"w/state/state.go":      "package state\n\nvar Table = map[string]int{}\n\nfunc init() {}\n\nfunc Bump(k string) { Table[k]++ }\n",
		"w/state/state_test.go": "package state\n",
		// X2 — a control-plane struct with an untagged field.
		"w/cfgx/cfgx.go":      "package cfgx\n\ntype Leaked struct {\n\tSecret string `json:\"-\"`\n\tPlain  string\n}\n",
		"w/cfgx/cfgx_test.go": "package cfgx\n",
		// X3 — exec outside an adapter, and in an adapter without env.
		"w/runner/runner.go":      "package runner\n\nimport \"os/exec\"\n\nfunc R() { exec.Command(\"ls\").Run() }\n",
		"w/runner/runner_test.go": "package runner\n",
		"w/adapter/run.go":        "package adapter\n\nimport \"os/exec\"\n\nfunc WithEnv() {\n\tcmd := exec.Command(\"ls\")\n\tcmd.Env = []string{\"A=B\"}\n\t_ = cmd\n}\n\nfunc WithoutEnv() { exec.Command(\"ls\").Run() }\n",
		"w/adapter/run_test.go":   "package adapter\n",
		// X3 — os.Environ in a test file is still banned.
		"w/envtest/env.go":      "package envtest\n",
		"w/envtest/env_test.go": "package envtest\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestEnv(t *testing.T) { _ = os.Environ() }\n",
		// C2 — a blocked module in the import graph.
		"w/cgo/cgo.go":      "package cgo\n\nimport _ \"github.com/mattn/go-sqlite3\"\n",
		"w/cgo/cgo_test.go": "package cgo\n",
		// C3 — no test file (covered by TestEngineC3, so skipped here).
		"w/notest/notest.go": "package notest\n",
	})

	arch, err := LoadArchitecture([]byte(testArch))
	if err != nil {
		t.Fatalf("test architecture: %v", err)
	}
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(arch, "example.com/tiny", nil)
	e.SkipRules = map[string]bool{"C3": true}
	assertFindings(t, e.Run(pkgs),
		want{"L2", "w/app/app.go", 3},
		want{"L5", "w/dom/dom.go", 3},
		want{"S5", "w/other/other.go", 3},
		want{"L1", "w/domx/domx.go", 3},
		want{"L6", "w/trans/trans.go", 3},
		want{"L4a", "w/eng/eng.go", 4},
		want{"L4a", "w/eng/eng.go", 6},
		want{"L3", "w/pure/pure.go", 4},
		want{"L3", "w/pure/pure.go", 10},
		want{"S2", "w/svc/svc.go", 3},
		want{"C2", "w/cgo/cgo.go", 3},
		want{"Z2", "w/cross/cross.go", 3},
		want{"Z2", "w/eng/eng.go", 6}, // the engine's repository import is also a plane crossing
		want{"X1", "w/sign/sign.go", 5},
		want{"X4", "w/httpc/httpc.go", 5},
		want{"X4", "w/httpc/httpc.go", 7},
		want{"X4", "w/httpc/httpc.go", 9},
		want{"X4", "w/httpctor/ctor.go", 11},
		want{"X4", "w/httpctor/other.go", 10},
		want{"Z4", "w/httpctor/other.go", 4},
		want{"X5", "w/keys/keys.go", 3},
		want{"X9", "w/mux/mux.go", 7},
		want{"S4", "w/state/state.go", 3},
		want{"S4", "w/state/state.go", 5},
		want{"X2", "w/cfgx/cfgx.go", 5},
		want{"X3", "w/runner/runner.go", 5},
		want{"X3", "w/adapter/run.go", 11},
		want{"X3", "w/envtest/env_test.go", 8},
	)
}

// TestEngineOverrides pins the fixture-harness mechanism: an override decides
// a package's class, zone and domain (or deliberately removes them, for L8/Z1).
func TestEngineOverrides(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":         "module example.com/tiny\n\ngo 1.24\n",
		"case/a.go":      "package casepkg\n\nimport _ \"net/http\"\n",
		"case/a_test.go": "package casepkg\n",
	})
	arch, err := LoadArchitecture([]byte(testArchNoX2))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/case")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(arch, "example.com/tiny", nil)
	e.SkipRules = map[string]bool{"C3": true}
	// The package path "case" matches no class in the test architecture; the
	// override classifies it as decision in the data zone, which turns its
	// net/http import into an L3 violation.
	e.Overrides = map[string]Override{"case": {Class: "decision", Zone: "data"}}
	assertFindings(t, e.Run(pkgs),
		want{"L3", "case/a.go", 3},
	)
	// Removing the class entirely is L8 (and Z1 when the zone goes too).
	e2 := NewEngine(arch, "example.com/tiny", nil)
	e2.SkipRules = map[string]bool{"C3": true}
	e2.Overrides = map[string]Override{"case": {}}
	assertFindings(t, e2.Run(pkgs),
		want{"L8", "case/a.go", 1},
		want{"Z1", "case/a.go", 1},
	)
}

// TestEngineC3 pins the tests-per-package rule, which the other tests skip.
func TestEngineC3(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"w/notest/notest.go":  "package notest\n",
		"w/with/with.go":      "package with\n",
		"w/with/with_test.go": "package with\n",
	})
	arch, err := LoadArchitecture([]byte(testArchNoX2))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	assertFindings(t, NewEngine(arch, "example.com/tiny", nil).Run(pkgs),
		want{"C3", "w/notest/notest.go", 1},
	)
}

// TestEngineBaseline checks both halves of the baseline contract: an entry
// whose allow list records the violation silences the finding, and an entry
// nothing matches any more is itself a finding.
func TestEngineBaseline(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"w/pure/pure.go":      "package pure\n\nimport _ \"net/http\"\n",
		"w/pure/pure_test.go": "package pure\n",
	})
	arch := mustArch(t, testArchNoX2)
	base, err := LoadBaseline([]byte("baseline:\n  - rule: L3\n    package: w/pure\n    why: today\n    allow: [net/http]\n  - rule: L3\n    package: gone\n    why: fixed already\n"), arch)
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	got := NewEngine(arch, "example.com/tiny", base).Run(pkgs)
	assertFindings(t, got,
		want{"baseline", "architecture.baseline.yaml", 6}, // the stale "gone" entry
	)
}

// TestEngineBaselineRatchet pins the item-level ratchet: a baseline entry
// records the exact violation items (here: the banned imports) a package may
// have, so a package that GAINS a violation item its entry does not list fails
// the gate even though (rule, package) is baselined, and an item that
// disappears is reported stale.
func TestEngineBaselineRatchet(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"w/pure/pure.go":      "package pure\n\nimport (\n\t_ \"net/http\"\n\t_ \"os\"\n)\n",
		"w/pure/pure_test.go": "package pure\n",
	})
	arch := mustArch(t, testArchNoX2)
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	base := func(allow string) *Baseline {
		t.Helper()
		data := "baseline:\n  - rule: L3\n    package: w/pure\n    why: today\n" + allow
		b, err := LoadBaseline([]byte(data), arch)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("exact-set-passes", func(t *testing.T) {
		// The entry records exactly today's items: nothing is reported.
		assertFindings(t, NewEngine(arch, "example.com/tiny", base("    allow: [net/http, os]\n")).Run(pkgs))
	})

	t.Run("existing-item-passes", func(t *testing.T) {
		// A listed item stays suppressed even when a sibling item is new.
		got := NewEngine(arch, "example.com/tiny", base("    allow: [os]\n")).Run(pkgs)
		for _, f := range got {
			if f.Rule == "L3" && f.Item == "os" {
				t.Errorf("allowed item os was reported: %v", f)
			}
		}
	})

	t.Run("new-item-fails", func(t *testing.T) {
		// net/http is not in the entry's allow list: the new violation fires.
		assertFindings(t, NewEngine(arch, "example.com/tiny", base("    allow: [os]\n")).Run(pkgs),
			want{"L3", "w/pure/pure.go", 4},
		)
	})

	t.Run("removed-item-stale", func(t *testing.T) {
		// database/sql no longer occurs: the recorded item is stale.
		got := NewEngine(arch, "example.com/tiny", base("    allow: [net/http, os, database/sql]\n")).Run(pkgs)
		assertFindings(t, got,
			want{"baseline", "architecture.baseline.yaml", 2},
		)
		for _, f := range got {
			if f.Rule == "baseline" && !strings.Contains(f.Message, "database/sql") {
				t.Errorf("stale-item finding names the wrong item: %v", f)
			}
		}
	})
}

// TestEngineX2UnknownStruct pins the hard-error half of X2 (the #349 review
// blocker): a structs entry naming a type that does not exist must fail the
// gate — before the fix it silently checked nothing — and no baseline entry
// may suppress it.
func TestEngineX2UnknownStruct(t *testing.T) {
	files := map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"w/cfgx/cfgx.go":      "package cfgx\n\ntype Leaked struct {\n\tHeld string `json:\"-\"`\n}\n",
		"w/cfgx/cfgx_test.go": "package cfgx\n",
	}
	root := writeModule(t, files)
	arch := mustArch(t, strings.Replace(testArch, "        type: Leaked", "        type: Absent", 1))
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	assertFindings(t, NewEngine(arch, "example.com/tiny", nil).Run(pkgs),
		want{"X2", "architecture.yaml", 0},
	)

	// Even an entry for the same (rule, package) must not mask the hard error:
	// it reports a defect in the gate's inputs, not a known violation. The
	// entry is also reported stale — it suppressed nothing, so it can never
	// earn its place in the baseline.
	base, err := LoadBaseline([]byte("baseline:\n  - rule: X2\n    package: w/cfgx\n    why: covering up\n"), arch)
	if err != nil {
		t.Fatal(err)
	}
	assertFindings(t, NewEngine(arch, "example.com/tiny", base).Run(pkgs),
		want{"X2", "architecture.yaml", 0},
		want{"baseline", "architecture.baseline.yaml", 2},
	)
}

// TestEngineRuleTestPointers pins the proxy-pointer validation: every
// Test…/Benchmark… name a rule's test field mentions must be a real function
// in the repo, and a stage must be a declared check.sh stage — never free text.
func TestEngineRuleTestPointers(t *testing.T) {
	// An undeclared stage fails at load, before anything is checked.
	badStage := strings.Replace(testArchNoX2, "rules:\n", "rules:\n"+
		"  - id: S6\n    title: vibes are not a stage\n    checker: proxy\n    stage: vibes\n", 1)
	if _, err := LoadArchitecture([]byte(badStage)); err == nil {
		t.Fatal("LoadArchitecture accepted an undeclared stage")
	} else if !strings.Contains(err.Error(), "unknown stage") {
		t.Errorf("error = %q, want it to contain %q", err, "unknown stage")
	}

	pointerArch := strings.Replace(testArchNoX2, "rules:\n", "rules:\n"+
		"  - id: S1\n    title: covers dom\n    checker: proxy\n    test: w/dom/dom_test.go (TestDomCovers covers it)\n"+
		"  - id: S6\n    title: dangling pointer\n    checker: proxy\n    test: the rename broke TestAbsent\n"+
		"  - id: S7\n    title: declared stage\n    checker: proxy\n    stage: benchmark\n", 1)
	arch := mustArch(t, pointerArch)
	root := writeModule(t, map[string]string{
		"go.mod":                "module example.com/tiny\n\ngo 1.24\n",
		"w/dom/dom.go":          "package dom\n",
		"w/dom/dom_test.go":     "package dom\n\nfunc TestDomCovers(t *testing.T) {}\n",
		"w/other/other.go":      "package other\n",
		"w/other/other_test.go": "package other\n",
	})
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	// S1's token resolves (green); S6's TestAbsent does not exist — the rule
	// would be silently unchecked, so the gate itself must fail. S7 declares
	// its stage and contributes no pointer.
	assertFindings(t, NewEngine(arch, "example.com/tiny", nil).Run(pkgs),
		want{"S6", "architecture.yaml", 0},
	)
}

// TestEngineS4Conventions pins what S4 allows: compile-time constants by
// convention stay silent even though they are package-level, and test-only
// writes do not count as mutation.
func TestEngineS4Conventions(t *testing.T) {
	root := writeModule(t, map[string]string{
		"go.mod": "module example.com/tiny\n\ngo 1.24\n",
		"w/conv/conv.go": `package conv

import (
	"errors"
	"regexp"
)

var ErrMissing = errors.New("missing")

var version = "1.2.3"

var table = []string{"a", "b"}

var header = regexp.MustCompile("^a")

//go:embed conv.go
var embedded []byte

var _ interface{ Bar() } = (*foo)(nil)

type foo struct{}

func (foo) Bar() string {
	return version + table[0] + header.String() + ErrMissing.Error() + string(embedded)
}
`,
		"w/conv/conv_test.go": `package conv

func init() { table = nil } // test-only setup is allowed
`,
	})
	arch, err := LoadArchitecture([]byte(testArchNoX2))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/...")
	if err != nil {
		t.Fatal(err)
	}
	// conv has a test file, so C3 stays quiet and S4 finds nothing.
	assertFindings(t, NewEngine(arch, "example.com/tiny", nil).Run(pkgs))
}

// TestEngineL7SharedRepositories pins L7's shared-repositories list: a
// repository may import a listed infrastructure repository from another
// domain, and any other cross-domain repository import still fails.
func TestEngineL7SharedRepositories(t *testing.T) {
	const arch = `
version: 1
classes:
  - id: assembly
    layer: assembly
    imported-by: ["cmd/**"]
    paths: ["cmd/**"]
  - id: repository
    layer: repository
    paths: ["w/*"]
zones:
  control: ["w/*"]
rules:
  - id: L7
    title: repositories import no other domain
    checker: archtest
    fix: depend on your own domain only
    shared-repositories: [w/store]
modules:
  direct:
    - module: golang.org/x/net
      layers: [repository]
`
	root := writeModule(t, map[string]string{
		"go.mod":              "module example.com/tiny\n\ngo 1.24\n",
		"w/feat/feat.go":      "package feat\n\nimport (\n\t_ \"example.com/tiny/w/other\"\n\t_ \"example.com/tiny/w/store\"\n)\n",
		"w/feat/feat_test.go": "package feat\n",
		"w/store/store.go":    "package store\n",
		"w/store/s_test.go":   "package store\n",
		"w/other/other.go":    "package other\n",
		"w/other/o_test.go":   "package other\n",
	})
	a, err := LoadArchitecture([]byte(arch))
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := LoadPackages(root, root+"/w/feat", root+"/w/store", root+"/w/other")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(a, "example.com/tiny", nil)
	e.SkipRules = map[string]bool{"C3": true}
	// Only the import of w/other fires; w/store is listed as shared.
	assertFindings(t, e.Run(pkgs), want{"L7", "w/feat/feat.go", 4})
}

// TestLoadArchitectureSharedRepositoriesValidation: a shared-repositories
// entry is an exact package path, never empty and never a glob.
func TestLoadArchitectureSharedRepositoriesValidation(t *testing.T) {
	for _, entry := range []string{`""`, `"internal/*"`, `"internal/**"`} {
		doc := "version: 1\nclasses:\n  - id: repository\n    layer: repository\n    paths: [\"w/*\"]\nzones:\n  control: [\"w/*\"]\nrules:\n  - id: L7\n    title: t\n    checker: archtest\n    fix: f\n    shared-repositories: [" + entry + "]\nmodules:\n  direct:\n    - module: golang.org/x/net\n      layers: [repository]\n"
		if _, err := LoadArchitecture([]byte(doc)); err == nil || !strings.Contains(err.Error(), "shared-repositories") {
			t.Errorf("entry %s: err = %v, want a shared-repositories error", entry, err)
		}
	}
	// The list only means something on L7; anywhere else it is refused.
	doc := "version: 1\nclasses:\n  - id: repository\n    layer: repository\n    paths: [\"w/*\"]\nzones:\n  control: [\"w/*\"]\nrules:\n  - id: L6\n    title: t\n    checker: archtest\n    fix: f\n    shared-repositories: [w/store]\nmodules:\n  direct:\n    - module: golang.org/x/net\n      layers: [repository]\n"
	if _, err := LoadArchitecture([]byte(doc)); err == nil || !strings.Contains(err.Error(), "shared-repositories") {
		t.Errorf("shared-repositories on L6: err = %v, want a shared-repositories error", err)
	}
}
