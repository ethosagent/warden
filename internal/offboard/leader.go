package offboard

import "context"

// Leader says whether this control plane runs the refresh job now. SQLite
// mode has one control plane, so AlwaysLeader; p5-postgres-ha plugs in an
// advisory-lock implementation. It is asked at the start of every run.
type Leader interface {
	IsLeader(ctx context.Context) bool
}

// AlwaysLeader is the single-replica Leader.
type AlwaysLeader struct{}

// IsLeader is always true.
func (AlwaysLeader) IsLeader(context.Context) bool { return true }
