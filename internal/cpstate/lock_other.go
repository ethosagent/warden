//go:build !unix

package cpstate

import (
	"fmt"
	"runtime"
)

// AcquireDirLock is unsupported off unix: a control plane started with
// --state-dir refuses to run rather than run unlocked.
func AcquireDirLock(dir string) (release func() error, err error) {
	return nil, fmt.Errorf("cpstate: state dir locking is not supported on %s; cannot use state dir %s", runtime.GOOS, dir)
}
