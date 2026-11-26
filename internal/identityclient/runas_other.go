//go:build !linux

package identityclient

import (
	"errors"
	"io/fs"
	"os/exec"
)

// RunAsSupported reports whether this platform can start a child under
// another uid.
const RunAsSupported = false

// Apply always fails: --run-as is Linux only.
func (RunAs) Apply(*exec.Cmd) error {
	return errors.New("--run-as is supported on Linux only")
}

// fileOwner is unavailable off Linux; --run-as is refused there before it is used.
func fileOwner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }
