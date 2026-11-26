//go:build linux

package identityclient

import (
	"io/fs"
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

// Apply makes cmd start under r, and be killed (SIGKILL) if the supervisor
// dies, so a crashed exec does not leave an orphan running unsupervised with
// the forwarder's credential. Pdeathsig fires when the OS thread that started
// the child exits, so the caller must keep that goroutine locked to its thread
// until the child has been waited for (runtime.LockOSThread).
//
// Follow-ups, not done here: set PR_SET_NO_NEW_PRIVS so a setuid binary the
// child can run gains nothing, and clear the inheritable and ambient
// capability sets.
func (r RunAs) Apply(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = r.Credential()
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return nil
}

// fileOwner returns the owning uid and gid of fi.
func fileOwner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}
