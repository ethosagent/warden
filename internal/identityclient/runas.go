package identityclient

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// RunAs is the numeric identity `identity exec --run-as uid:gid` gives the
// child. The child gets exactly this uid, this gid and no supplementary groups.
type RunAs struct {
	UID, GID uint32
}

// ErrRunAsNotRoot is returned when --run-as is used by a process that cannot
// change uid: the child would start as the parent's own user, which is what
// --run-as exists to avoid, so exec refuses instead.
var ErrRunAsNotRoot = errors.New("--run-as needs exec to run as root (effective uid 0) so it can start the command under another uid; run exec with sudo, or drop --run-as and accept that a same-uid command can read the agent key and login cache")

// ParseRunAs parses "uid:gid" (decimal numbers only; names are not resolved,
// because a lookup would consult nsswitch and could be redirected). Both ids
// must be non-zero: uid 0 or gid 0 would hand the child root's files or
// root-group access, so a typo can never leave the child privileged.
func ParseRunAs(spec string) (RunAs, error) {
	u, g, ok := strings.Cut(spec, ":")
	if !ok || u == "" || g == "" || strings.Contains(g, ":") {
		return RunAs{}, fmt.Errorf("--run-as %q: want uid:gid, both numbers", spec)
	}
	uid, err := parseID(u)
	if err != nil {
		return RunAs{}, fmt.Errorf("--run-as %q: uid: %w", spec, err)
	}
	gid, err := parseID(g)
	if err != nil {
		return RunAs{}, fmt.Errorf("--run-as %q: gid: %w", spec, err)
	}
	if uid == 0 || gid == 0 {
		return RunAs{}, fmt.Errorf("--run-as %q: uid and gid must not be 0, which would leave the command with root's access", spec)
	}
	return RunAs{UID: uid, GID: gid}, nil
}

func parseID(s string) (uint32, error) {
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("must be a decimal number")
		}
	}
	n, err := strconv.ParseUint(s, 10, 32)
	// 1<<32-1 is the "unchanged" marker of setuid(2).
	if err != nil || n == 1<<32-1 {
		return 0, errors.New("out of range")
	}
	return uint32(n), nil
}

// EffectiveUID reads the effective uid; tests replace it.
type EffectiveUID func() int

// ResolveRunAs parses spec and refuses it unless the platform supports it and
// the process is root. euid nil selects os.Geteuid. It does nothing else, so a
// refusal happens before any listener, login or child exists.
func ResolveRunAs(spec string, euid EffectiveUID) (RunAs, error) {
	if euid == nil {
		euid = os.Geteuid
	}
	if !RunAsSupported {
		return RunAs{}, errors.New("--run-as is supported on Linux only")
	}
	r, err := ParseRunAs(spec)
	if err != nil {
		return RunAs{}, err
	}
	if euid() != 0 {
		return RunAs{}, ErrRunAsNotRoot
	}
	return r, nil
}
