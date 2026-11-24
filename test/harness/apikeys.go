package harness

// Scoped API keys (W-P2-APIK-02): the control plane boots with
// console.apiKeys.enabled on the oidc console, so its API key store and Index
// run on the harness's fake clock (the Index polls the database every 2s of it).
// A scenario mints and revokes keys through a second handle on the state
// database, exactly as the offline CLI does, and presents them with
// CP().SendBearer. Keys are owned by a member of ConsoleAdminGroup unless the
// scenario says otherwise.

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
