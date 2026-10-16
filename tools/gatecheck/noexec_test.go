package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethosagent/warden/tools/approval"
)

// The head checkout is the PR author's code. `gatecheck weakened` holds a
// token, so it must only ever READ the head tree: a head check.sh (or a Go
// source it would build) that runs is a pwn request (#354).
func TestWeakenedNeverExecutesHeadCode(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	base := goodRepo()
	head := base.clone()
	trap := "#!/usr/bin/env bash\necho ran > " + marker + "\n" + head["scripts/check.sh"]
	head["scripts/check.sh"] = trap
	head["tools/checkreport/main.go"] = "package main\n\nimport \"os\"\n\nfunc init() { os.WriteFile(\"" + marker + "\", []byte(\"built\"), 0o644) }\n\nfunc main() {}\n"
	headDir := writeTree(t, filepath.Join(t.TempDir(), "head"), head)
	baseDir := writeTree(t, filepath.Join(t.TempDir(), "base"), base)
	if err := os.Chmod(filepath.Join(headDir, "scripts", "check.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	d := productionDeps()
	d.github = func(string) approval.GitHub { return botPR() }
	realMain([]string{"weakened", "-base", baseDir, "-head", headDir}, &out, &errb, d)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("gatecheck weakened executed code from the head tree")
	}
}
