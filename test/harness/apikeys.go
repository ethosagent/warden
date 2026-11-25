package harness

import "github.com/ethosagent/warden/internal/controlplane"

// Scoped API keys (W-P2-APIK-02): the control plane boots with
// console.apiKeys.enabled on the oidc console, so its API key store and Index
// run on the harness's fake clock (the Index polls the database every 2s of it).
// A scenario mints and revokes keys through a second handle on the state
// database, exactly as the offline CLI does, and presents them with
// CP().SendBearer. Keys are owned by a member of ConsoleAdminGroup unless the
// scenario says otherwise.

// APIKeyAuthCounts is warden_cp_apikey_auth_total by outcome, as the running
// control plane counts it (empty before it is ready).
func (h *H) APIKeyAuthCounts() map[string]int64 {
	h.apiKeyMu.Lock()
	fn := h.apiKeyCounts
	h.apiKeyMu.Unlock()
	if fn == nil {
		return map[string]int64{}
	}
	return fn()
}

func (h *H) applyAPIKeys(p *controlplane.Params) {
	if !h.wantAPIKeys {
		return
	}
	p.APIKeysReady = func(fn func() map[string]int64) {
		h.apiKeyMu.Lock()
		h.apiKeyCounts = fn
		h.apiKeyMu.Unlock()
	}
}

// WithAPIKeys enables console.apiKeys. It implies WithConsoleOIDC (API keys
// need the oidc console and a state dir) and combines with WithAdminAudit.
// In-process only.
func WithAPIKeys() Option {
	return func(h *H) {
		h.wantIssuer = true
		h.wantConsole = true
		h.wantAPIKeys = true
	}
}
