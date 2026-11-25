//go:build linux

package identityclient

import (
	"os/exec"
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
}
