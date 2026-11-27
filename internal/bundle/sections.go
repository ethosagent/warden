package bundle

import (
	"encoding/json"
	"fmt"
)

// Names of the payload sections a bundle can carry beside the policy. A worker
// ignores a section it does not know, so a new one never breaks an old worker.
const (
	// SectionPerUserSecrets carries the value-free per-user placeholder
	// mappings (W-P3-PUS-08).
	SectionPerUserSecrets = "perUserSecrets"
	// SectionUserGrantEpochs carries the per-user revocation epochs
	// (W-P3-PUS-08): {userKey: epoch}.
	SectionUserGrantEpochs = "userGrantEpochs"
)

// PerUserSecretsSection is the perUserSecrets section: the mappings a worker
// swaps and how long it may cache a minted token. It holds names, domains and
// agent ids only. It has no field for a token, a refresh token, a client
// secret, an email or a subject, and a test keeps it that way (the type is
// walked by reflection), because the section is signed and fetched by every
// worker.
type PerUserSecretsSection struct {
	// WorkerCacheTTLSeconds caps how long a worker reuses a minted access token
	// before it asks the control plane again.
	WorkerCacheTTLSeconds int                     `json:"workerCacheTTLSeconds"`
	Mappings              []PerUserMappingSection `json:"mappings"`
}

// PerUserMappingSection is one mapping of the perUserSecrets section.
type PerUserMappingSection struct {
	Placeholder string   `json:"placeholder"`
	Provider    string   `json:"provider"`
	Scopes      []string `json:"scopes"`
	Domains     []string `json:"domains"`
	In          []string `json:"in"`
	Agents      []string `json:"agents"`
}

// UserGrantEpochs is the userGrantEpochs section: the epoch of the newest
// revocation of each user, keyed by secrets.UserKey (a hash of iss and sub, so
// no subject is on the wire). An epoch is the publish-log seq of the bump, so
// a user's value only grows. A worker drops a cached token minted at an epoch
// below the user's value.
type UserGrantEpochs map[string]int64

// ParsePerUserSecrets decodes the perUserSecrets section a verified bundle
// carries. Unknown members are ignored (a later control plane may add some). A
// nil or empty raw is no section and returns nil.
func ParsePerUserSecrets(raw json.RawMessage) (*PerUserSecretsSection, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var s PerUserSecretsSection
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("bundle: perUserSecrets section: %w", err)
	}
	return &s, nil
}

// ParseUserGrantEpochs decodes the userGrantEpochs section. A nil or empty raw
// is no section and returns nil.
func ParseUserGrantEpochs(raw json.RawMessage) (UserGrantEpochs, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var e UserGrantEpochs
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, fmt.Errorf("bundle: userGrantEpochs section: %w", err)
	}
	return e, nil
}
