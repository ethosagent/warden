//go:build linux

package identityclient

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestRunAsCredential pins what the runtime applies: setgroups with an empty
// list (never skipped), then the gid and uid; a Start that fails any step
// fails closed.
func TestRunAsCredential(t *testing.T) {
	c := RunAs{UID: 1234, GID: 5678}.Credential()
	if c.Uid != 1234 || c.Gid != 5678 {
		t.Errorf("credential = %+v", c)
	}
	if c.NoSetGroups {
		t.Error("NoSetGroups is set: the child would keep the parent's supplementary groups")
	}
	if c.Groups == nil || len(c.Groups) != 0 {
		t.Errorf("Groups = %#v, want an explicit empty list", c.Groups)
	}
	cmd := exec.Command("true")
	if err := (RunAs{UID: 1, GID: 2}).Apply(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Credential.Uid != 1 {
		t.Errorf("Apply left SysProcAttr = %+v", cmd.SysProcAttr)
	}
	if cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Errorf("Pdeathsig = %v, want SIGKILL so an orphaned child dies with exec", cmd.SysProcAttr.Pdeathsig)
	}
}

func TestCheckRunAsAccess(t *testing.T) {
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	dir := t.TempDir()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	private := mk("private", 0o600)
	groupRead := mk("group", 0o640)
	worldRead := mk("world", 0o604)
	other := RunAs{UID: uid + 1, GID: gid + 1}

	for _, tc := range []struct {
		name string
		r    RunAs
		path string
		want string // empty: accepted
	}{
		{"owner uid matches", RunAs{UID: uid, GID: gid + 1}, private, "owned by uid"},
		{"private and foreign", other, private, ""},
		{"group matches and readable", RunAs{UID: uid + 1, GID: gid}, groupRead, "readable by gid"},
		{"group matches but private", RunAs{UID: uid + 1, GID: gid}, private, ""},
		{"world readable", other, worldRead, "readable by everyone"},
		{"missing path is skipped", other, filepath.Join(dir, "absent"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckRunAsAccess(tc.r, []AccessPath{{What: "agent key file", Path: tc.path}}, nil)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("err = %v, want none", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	// A path that cannot be examined fails closed.
	boom := errors.New("boom")
	err := CheckRunAsAccess(other, []AccessPath{{What: "x", Path: "/p"}}, func(string) (fs.FileInfo, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Errorf("stat failure: err = %v, want it refused", err)
	}
	// Directories are checked too: a cache directory owned by the run-as uid.
	if err := CheckRunAsAccess(RunAs{UID: uid, GID: gid + 1}, []AccessPath{{What: "login cache directory", Path: dir}}, nil); err == nil {
		t.Error("a directory owned by the run-as uid was accepted")
	}
}
