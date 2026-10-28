package cpstate

import "errors"

// LockFileName is the advisory lock file AcquireDirLock holds inside a state
// dir. It is never deleted, so there is no unlink race between holders.
const LockFileName = "warden-cp.lock"

// ErrLocked means another process (or another open file description in this
// one) holds the state-dir lock. AcquireDirLock wraps it with the dir and the
// lock path; match it with errors.Is.
var ErrLocked = errors.New("locked by another process")
