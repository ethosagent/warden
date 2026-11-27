package oauthbroker

import "context"

// EpochBumper records that a user's cached per-user tokens must be dropped:
// the control plane implements it over its epoch store (W-P3-PUS-08) so this
// package never imports the control plane. userKey is a secrets.UserKey value,
// never a sub. A returned error means the workers were not told (or not yet:
// the control plane's ErrEpochNotPublished records the epoch, and a retry gets a
// larger one), so the caller reports the revoke as partial and must retry.
type EpochBumper interface {
	Bump(ctx context.Context, userKey string) error
}

// WorkerCapsReader lists the ids of the connected workers that do not advertise
// cap in their heartbeat. The registry bounds and sorts the list.
type WorkerCapsReader interface {
	WorkersWithoutCap(cap string) []string
}

// Epoch step outcomes, the revoke response's steps.epoch values.
const (
	EpochOK      = "ok"
	EpochFailed  = "failed"
	EpochSkipped = "skipped" // no bumper wired: nothing could tell a worker
)

// EpochOutcome is the epoch step of a revoke: its status, the error (never
// shown to the user verbatim) and the connected workers that could still serve
// a cached token because they lack the usersecrets/v1 capability.
type EpochOutcome struct {
	Status            string
	Err               error
	WorkersWithoutCap []string
}

// Partial reports whether the revoke is only partly delivered: the epoch bump
// failed, so a worker may serve a cached token until its cache TTL ends.
func (o EpochOutcome) Partial() bool { return o.Status == EpochFailed }

// BumpGrantEpoch runs the epoch step of a revoke for userKey: it bumps the
// user's epoch through b and lists, through caps, the workers lacking
// capUserSecretsV1. The error is returned in the outcome, never swallowed; the
// revoke continues with the provider step either way (the secret is already
// deleted, so a later mint finds nothing). A nil b is skipped; a nil caps
// leaves the worker list empty.
func BumpGrantEpoch(ctx context.Context, b EpochBumper, caps WorkerCapsReader, capUserSecretsV1, userKey string) EpochOutcome {
	var out EpochOutcome
	if caps != nil {
		out.WorkersWithoutCap = caps.WorkersWithoutCap(capUserSecretsV1)
	}
	if b == nil {
		out.Status = EpochSkipped
		return out
	}
	if err := b.Bump(ctx, userKey); err != nil {
		out.Status, out.Err = EpochFailed, err
		return out
	}
	out.Status = EpochOK
	return out
}
