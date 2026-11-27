package dashboard

import (
	"context"
	"net/http"
)

// forceKey carries the caller's ?force=true through the writer seams.
type forceKey struct{}

// withForce returns ctx marked with the request's force=true query parameter
// (W-P2-WBND-07). A request without it gets ctx unchanged. The marker is only
// a request: the control plane decides whether the caller may force.
func withForce(ctx context.Context, r *http.Request) context.Context {
	if r.URL.Query().Get("force") == "true" {
		return WithForce(ctx)
	}
	return ctx
}

// WithForce returns ctx marked as a force=true request.
func WithForce(ctx context.Context) context.Context {
	return context.WithValue(ctx, forceKey{}, true)
}

// ForceFrom reports whether the request that produced ctx carried force=true.
func ForceFrom(ctx context.Context) bool {
	v, _ := ctx.Value(forceKey{}).(bool)
	return v
}

// WorkersLackCapabilityError is returned by a settings writer that refuses to
// set require mode while connected workers lack identity/require-v1. The
// dashboard answers it with 409 {"error":"workers_lack_capability",
// "workers":[ids]}; a forced write by an admin skips the check.
type WorkersLackCapabilityError struct {
	// Workers are the proxy ids of the connected workers lacking the capability.
	Workers []string
	// Capability names the missing capability. Empty for the identity
	// require-mode guard, whose 409 body predates the field and stays as it
	// was; set (e.g. userlimits/v1) by later guards, and then on the body.
	Capability string
}

func (e *WorkersLackCapabilityError) Error() string {
	if e.Capability != "" {
		return "workers_lack_capability: connected workers lack " + e.Capability + "; upgrade them or retry with force=true as an admin"
	}
	return "workers_lack_capability: connected workers do not support identity require mode; upgrade them or retry with force=true as an admin"
}

// workersLackResponse is the 409 body for a WorkersLackCapabilityError.
type workersLackResponse struct {
	Error      string   `json:"error"`
	Capability string   `json:"capability,omitempty"`
	Workers    []string `json:"workers"`
}
