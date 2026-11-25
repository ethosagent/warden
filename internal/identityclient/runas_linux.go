//go:build linux

package identityclient

import (
	"os/exec"
	"syscall"
)

// RunAsSupported reports whether this platform can start a child under
// another uid.
const RunAsSupported = true

// Credential is the syscall.Credential for r: the uid and gid, and an explicit
// empty supplementary group list. NoSetGroups stays false, so the runtime
// calls setgroups(0) first, then setgid, then setuid, and fails the Start when
// any step fails: a child is never left running with the parent's groups or as
// root.
func (r RunAs) Credential() *syscall.Credential {
	return &syscall.Credential{Uid: r.UID, Gid: r.GID, Groups: []uint32{}, NoSetGroups: false}
}

// Apply makes cmd start under r.
func (r RunAs) Apply(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = r.Credential()
	return nil
}
