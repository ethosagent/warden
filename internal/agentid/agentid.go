// Package agentid identifies which agent a connection belongs to. Phase 1 uses
// port-binding (one proxy per agent, so the listening port identifies the
// agent); header/query-based identification arrives in later milestones. The
// proxy is otherwise agent-agnostic: it knows what is being done, not which
// agent — identity here exists only for one-proxy-per-agent bookkeeping.
package agentid

import (
	"errors"
	"fmt"
)

// Identifier resolves an agent identity for a connection. Phase 1 is
// port-binding; later milestones add header/query strategies behind this
// interface.
type Identifier interface {
	// Identify returns a stable agent identity for the given local listener
	// port.
	Identify(localPort int) string
}

// PortBindingIdentifier derives identity from the listener port (one proxy per
// agent).
type PortBindingIdentifier struct {
	prefix string
}

var _ Identifier = (*PortBindingIdentifier)(nil)

// NewPortBindingIdentifier constructs a port-binding identifier. prefix labels
// the deployment (e.g. "agent"); empty defaults to "agent".
func NewPortBindingIdentifier(prefix string) *PortBindingIdentifier {
	if prefix == "" {
		prefix = "agent"
	}
	return &PortBindingIdentifier{prefix: prefix}
}

// Identify returns a stable identity string for the listener port.
func (p *PortBindingIdentifier) Identify(localPort int) string {
	return fmt.Sprintf("%s:%d", p.prefix, localPort)
}

// MaxIDLen is the longest valid registered agent id, in bytes.
const MaxIDLen = 64

// ErrInvalidID is returned by ValidID. It never carries the id itself: ids
// reach logs and audit rows, and a rejected one may be attacker-chosen.
var ErrInvalidID = errors.New("agentid: invalid agent id")

// ValidID reports whether id is a valid registered agent id: it matches
// ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$, compared case-sensitively and exactly
// (no trimming, no folding). It accepts "agent:<port>" from
// PortBindingIdentifier and rejects the P1 sentinel "!identity-scoped".
func ValidID(id string) error {
	if id == "" || len(id) > MaxIDLen {
		return fmt.Errorf("%w: length must be 1 to %d bytes", ErrInvalidID, MaxIDLen)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return fmt.Errorf("%w: byte %d is not allowed there", ErrInvalidID, i)
		}
	}
	return nil
}
