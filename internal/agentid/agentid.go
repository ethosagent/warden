// Package agentid identifies which agent a connection belongs to. Phase 1 uses
// port-binding (one proxy per agent, so the listening port identifies the
// agent); header/query-based identification arrives in later milestones. The
// proxy is otherwise agent-agnostic: it knows what is being done, not which
// agent — identity here exists only for one-proxy-per-agent bookkeeping.
package agentid

import "fmt"

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
