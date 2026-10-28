package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/controlplane"
)

// runHashPassword executes `control-plane hash-password args...` with stdin.
func runHashPassword(t *testing.T, stdin string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	root := newRootCmd()
	root.SetArgs(append([]string{"control-plane", "hash-password"}, args...))
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errb)
	err = root.Execute()
	return out.String(), errb.String(), err
}

func TestHashPasswordCmd(t *testing.T) {
	const pw = "sixteen-char-pass"
	t.Run("stdin ok", func(t *testing.T) {
		out, errOut, err := runHashPassword(t, pw+"\r\n", "--stdin")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(out, "\n") != 1 || !strings.HasSuffix(out, "\n") {
			t.Fatalf("stdout is not exactly one line: %q", out)
		}
		p, err := controlplane.ParsePHC(strings.TrimSuffix(out, "\n"))
		if err != nil || !p.Verify(pw) {
			t.Fatalf("output does not verify: %v", err)
		}
		if strings.Contains(out+errOut, pw) {
			t.Error("password leaked")
		}
	})
	t.Run("no trailing newline", func(t *testing.T) {
		out, _, err := runHashPassword(t, pw, "--stdin")
		if err != nil {
			t.Fatal(err)
		}
		if p, err := controlplane.ParsePHC(strings.TrimSpace(out)); err != nil || !p.Verify(pw) {
			t.Fatalf("bad output: %v", err)
		}
	})
	t.Run("only first line", func(t *testing.T) {
		out, _, err := runHashPassword(t, pw+"\nsecond-line-ignored\n", "--stdin")
		if err != nil {
			t.Fatal(err)
		}
		if p, _ := controlplane.ParsePHC(strings.TrimSpace(out)); !p.Verify(pw) {
			t.Error("first line not used")
		}
	})
	t.Run("15 chars", func(t *testing.T) {
		short := strings.Repeat("s", 15)
		out, errOut, err := runHashPassword(t, short+"\n", "--stdin")
		if err == nil || out != "" {
			t.Fatalf("err=%v out=%q", err, out)
		}
		if exitCode(err) == 0 || strings.Contains(err.Error()+errOut, short) {
			t.Errorf("exit %d or password in error: %v", exitCode(err), err)
		}
	})
	t.Run("too long", func(t *testing.T) {
		long := strings.Repeat("l", 1025)
		out, _, err := runHashPassword(t, long+"\n", "--stdin")
		if !errors.Is(err, controlplane.ErrPasswordTooLong) || out != "" || strings.Contains(err.Error(), long) {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})
	t.Run("password flag unknown", func(t *testing.T) {
		out, _, err := runHashPassword(t, "", "--password", pw)
		if err == nil || out != "" || !strings.Contains(err.Error(), "unknown flag") || strings.Contains(err.Error(), pw) {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})
	t.Run("not a terminal", func(t *testing.T) {
		out, _, err := runHashPassword(t, pw+"\n")
		if err == nil || out != "" || err.Error() != "stdin is not a terminal; use --stdin" {
			t.Fatalf("err=%v out=%q", err, out)
		}
	})
	t.Run("positional arg refused", func(t *testing.T) {
		if _, _, err := runHashPassword(t, pw, "--stdin", pw); err == nil {
			t.Fatal("positional password accepted")
		}
	})
}
