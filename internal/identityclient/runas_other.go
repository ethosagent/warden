//go:build !linux

package identityclient

import (
	"errors"
	"os/exec"
)

// RunAsSupported reports whether this platform can start a child under
// another uid.
const RunAsSupported = false

// Apply always fails: --run-as is Linux only.
func (RunAs) Apply(*exec.Cmd) error {
	return errors.New("--run-as is supported on Linux only")
}
