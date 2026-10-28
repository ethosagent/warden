//go:build unix

package controlplane

import "syscall"

// diskFree reports the bytes available to an unprivileged process on the
// filesystem holding dir.
func diskFree(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}
