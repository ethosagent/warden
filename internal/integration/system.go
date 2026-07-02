package integration

// system is the v1 System implementation: a reserved inbound seam with ZERO
// methods. Mutating "act on the system" actions (block domain, mute, set mode)
// land in a later milestone; adding them will not change Integration.Start's
// signature, only widen the System interface.
type system struct{}

// newSystem returns the reserved System handle passed to each integration.
func newSystem() System { return system{} }
