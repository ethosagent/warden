package harness

import "github.com/ethosagent/warden/internal/controlplane"

// WithStrictWorkerAuth boots the control plane with --require-worker-tokens
// (W-P1-WTOK-04): no shared token is configured, so the harness's workers, which
// keep presenting the shared token, are refused with 401 and only tokens a
// scenario mints out of process (ControlPlaneStateDB) authenticate. It implies
// WithWorkerTokens (the state dir and the fake clock) and gives the control
// plane an echo secret store, so /central/secrets exists unless strict mode
// unmounts it. Combine with WithControlPlaneAdminToken for the admin bearer.
// In-process only.
func WithStrictWorkerAuth() Option {
	return func(h *H) { h.wantWorkerTokens, h.wantStrict = true, true }
}

func (h *H) applyStrict(p *controlplane.Params) {
	if !h.wantStrict {
		return
	}
	p.TokenEnv, p.LegacyTokenEnv = "", ""
	p.RequireWorkerTokens = true
}

// strictYAML adds the echo secret store to the control plane's config.
func (h *H) strictYAML() string {
	if !h.wantStrict {
		return ""
	}
	return "\nsecretStore:\n  backend: echo\n"
}
