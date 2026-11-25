package dashboard

// The API Keys console tab (W-P2-APIK-04). The management routes themselves
// (/dashboard/api/api-keys...) are served by the control plane; this file only
// carries the facts the page needs to build its create dialog, through the same
// bootstrap payload (/dashboard/api/setup) the other console facts use, so no
// new public route exists. The server stays the authority: the page filters the
// scope list by the signed-in role for convenience, and the create route
// re-checks every scope against the caller's current role.

// APIKeyScope is one grantable scope and the minimum console role (viewer,
// editor or admin) its holder needs.
type APIKeyScope struct {
	Name    string `json:"name"`
	MinRole string `json:"minRole"`
}

// APIKeySettings is what the create dialog needs. TTLs are whole seconds.
type APIKeySettings struct {
	Scopes     []APIKeyScope `json:"scopes"`
	DefaultTTL int64         `json:"defaultTTLSeconds"`
	MaxTTL     int64         `json:"maxTTLSeconds"`
}

// APIKeySource supplies APIKeySettings. Only the control plane sets one, and
// only when console.apiKeys.enabled; without one the tab stays hidden.
type APIKeySource interface {
	APIKeySettings() APIKeySettings
}

// SetAPIKeys enables the API Keys tab. A nil source hides it.
func (s *Server) SetAPIKeys(src APIKeySource) { s.apiKeys = src }

// apiKeysSetup is the setup payload's apiKeys member: nil (omitted) without a
// source.
func (s *Server) apiKeysSetup() *APIKeySettings {
	if s.apiKeys == nil {
		return nil
	}
	st := s.apiKeys.APIKeySettings()
	if st.Scopes == nil {
		st.Scopes = []APIKeyScope{}
	}
	return &st
}
