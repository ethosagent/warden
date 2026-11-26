package identityclient

import (
	"errors"
	"fmt"
	"io/fs"
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

// AccessPath names a file or directory the --run-as child must not reach.
type AccessPath struct {
	// What names it in an error ("agent key file", "login cache directory").
	What string
	Path string
}

// CheckRunAsAccess refuses --run-as when the child could read one of paths
// through its new identity: the path belongs to the run-as uid, belongs to the
// run-as gid and is group readable, or is readable by anyone. A path that does
// not exist is skipped (nothing to protect yet); a path that cannot be examined
// is refused. stat nil selects os.Stat.
func CheckRunAsAccess(r RunAs, paths []AccessPath, stat func(string) (fs.FileInfo, error)) error {
	if stat == nil {
		stat = os.Stat
	}
	for _, p := range paths {
		if p.Path == "" {
			continue
		}
		fi, err := stat(p.Path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("--run-as: cannot check the %s %s: %w", p.What, p.Path, err)
		}
		uid, gid, ok := fileOwner(fi)
		if !ok {
			return fmt.Errorf("--run-as: cannot determine the owner of the %s %s", p.What, p.Path)
		}
		perm := fi.Mode().Perm()
		switch {
		case uid == r.UID:
			return fmt.Errorf("--run-as: the %s %s is owned by uid %d, the uid the command would run as, so it could read it; it must belong to another user (for example root)", p.What, p.Path, r.UID)
		case gid == r.GID && perm&0o040 != 0:
			return fmt.Errorf("--run-as: the %s %s is readable by gid %d (mode %04o), the gid the command would run as; chmod it to 0600 or 0700 or use another gid", p.What, p.Path, r.GID, perm)
		case perm&0o004 != 0:
			return fmt.Errorf("--run-as: the %s %s is readable by everyone (mode %04o), so the command could read it; chmod it to 0600 or 0700", p.What, p.Path, perm)
		}
	}
	return nil
}
