package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/agentid"
)

// Per-user secrets (P3 "Act as the user", W-P3-PUS-02): the CP-local
// `perUserSecrets:` block turns the feature on and holds the value-free
// mappings from a placeholder to a provider grant. The control plane is the
// single source of truth for them: it caps scopes at consent time and mints the
// access tokens, and it ships the mappings to workers only as the signed-bundle
// section perUserSecrets (W-P3-PUS-08), never over GET /policy or SettingsWire.
// Grants themselves live in consent.store (W-P3-CSIG-06), never here.

// Defaults and bounds of perUserSecrets.workerCacheTTL: how long a worker may
// reuse a minted access token before it asks the control plane again.
const (
	DefaultPerUserWorkerCacheTTL = 5 * time.Minute
	MinPerUserWorkerCacheTTL     = 30 * time.Second
	MaxPerUserWorkerCacheTTL     = 15 * time.Minute
)

// The request locations a per-user placeholder may be swapped in. The body is
// deliberately not one: a header- or query-only mapping never buffers a body.
const (
	PerUserInHeader = "header"
	PerUserInQuery  = "query"
)

// PerUserSecretsConfig is the `perUserSecrets:` block. The zero value (block
// absent) is disabled and changes nothing; a present block gets the defaults
// (workerCacheTTL 5m, in [header]). It holds no secret: placeholders, provider
// ids, scope names, domains and agent ids only.
type PerUserSecretsConfig struct {
	// Enabled turns per-user swapping on (default false).
	Enabled bool
	// WorkerCacheTTL caps how long a worker caches a minted access token
	// (default 5m, allowed 30s to 15m).
	WorkerCacheTTL time.Duration
	// Mappings tie a placeholder to the calling user's grant for a provider.
	Mappings []PerUserMapping
}

// PerUserMapping is one per-user placeholder: the worker swaps Placeholder for
// the calling user's Provider access token, but only in the request locations
// In, only toward Domains, and only for an identity bound to one of Agents.
type PerUserMapping struct {
	// Placeholder is the token the agent holds (8-128 of [A-Za-z0-9_{}-]).
	Placeholder string
	// Provider is a consent.providers id (the oauthbroker registry).
	Provider string
	// Scopes are the provider scopes the grant must include.
	Scopes []string
	// Domains are the destinations the token may be sent to, in the allowlist
	// domain grammar (exact, *.suffix, ~regex). Required.
	Domains []string
	// In lists where the placeholder is looked for: header and/or query
	// (default [header]).
	In []string
	// Agents are the bound agent ids allowed to use the mapping. Required.
	Agents []string
}

// rawPerUserSecrets mirrors the on-disk block. KnownFields(true) rejects an
// unknown key, so no value or token field can be smuggled in. The omitempty
// tags keep the write direction (EncodePerUserSecretsNode) minimal.
type rawPerUserSecrets struct {
	Enabled        bool                `yaml:"enabled"`
	WorkerCacheTTL string              `yaml:"workerCacheTTL,omitempty"`
	Mappings       []rawPerUserMapping `yaml:"mappings,omitempty"`
}

type rawPerUserMapping struct {
	Placeholder string   `yaml:"placeholder"`
	Provider    string   `yaml:"provider"`
	Scopes      []string `yaml:"scopes,omitempty"`
	Domains     []string `yaml:"domains"`
	In          []string `yaml:"in,omitempty"`
	Agents      []string `yaml:"agents"`
}

// parsePerUserSecrets converts the raw block and applies the defaults. An
// absent block is the zero value (disabled).
func parsePerUserSecrets(r *rawPerUserSecrets) (PerUserSecretsConfig, error) {
	if r == nil {
		return PerUserSecretsConfig{}, nil
	}
	c := PerUserSecretsConfig{Enabled: r.Enabled, WorkerCacheTTL: DefaultPerUserWorkerCacheTTL}
	if s := strings.TrimSpace(r.WorkerCacheTTL); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return PerUserSecretsConfig{}, fmt.Errorf("config: perUserSecrets.workerCacheTTL %q is not a valid duration: %w", s, err)
		}
		c.WorkerCacheTTL = d
	}
	for _, m := range r.Mappings {
		pm := PerUserMapping{
			Placeholder: strings.TrimSpace(m.Placeholder),
			Provider:    strings.TrimSpace(m.Provider),
			Scopes:      trimPerUser(m.Scopes, false),
			Domains:     trimPerUser(m.Domains, true),
			In:          trimPerUser(m.In, true),
			Agents:      trimPerUser(m.Agents, false),
		}
		// Match policy.NormalizeHost: a non-regex domain drops trailing dots.
		for i, d := range pm.Domains {
			if !strings.HasPrefix(d, "~") {
				pm.Domains[i] = strings.TrimRight(d, ".")
			}
		}
		if len(pm.In) == 0 {
			pm.In = []string{PerUserInHeader}
		}
		c.Mappings = append(c.Mappings, pm)
	}
	return c, nil
}

// trimPerUser returns a trimmed (and, with lower, lowercased) copy of vs; nil stays
// nil. Scope values are not trimmed of inner whitespace: validation rejects it.
func trimPerUser(vs []string, lower bool) []string {
	if vs == nil {
		return nil
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		v = strings.TrimSpace(v)
		if lower {
			v = strings.ToLower(v)
		}
		out[i] = v
	}
	return out
}

// perUserPlaceholderRE is the placeholder grammar: 8-128 characters of
// [A-Za-z0-9_{}-], so a placeholder is long enough not to occur by accident and
// holds no character that is special in a header, a query or a path.
var perUserPlaceholderRE = regexp.MustCompile(`^[A-Za-z0-9_{}-]{8,128}$`)

// validatePerUserSecrets checks the block when it is enabled. A disabled block
// is not validated (like consent:), so a half-written block in a served copy
// cannot stop a start that does not use it; the settings writer that enables
// it (W-P3-PUS-08) re-parses the whole document, so it is validated then.
// static is secrets[]: a per-user placeholder must not equal, contain or be
// contained in a static one or another mapping's, because the static swap
// replaces substrings. Every error names the key.
func validatePerUserSecrets(c PerUserSecretsConfig, static []SecretMapping) error {
	if !c.Enabled {
		return nil
	}
	if c.WorkerCacheTTL < MinPerUserWorkerCacheTTL || c.WorkerCacheTTL > MaxPerUserWorkerCacheTTL {
		return fmt.Errorf("config: perUserSecrets.workerCacheTTL %s must be between %s and %s", c.WorkerCacheTTL, MinPerUserWorkerCacheTTL, MaxPerUserWorkerCacheTTL)
	}
	for i, m := range c.Mappings {
		if err := validatePerUserMapping(fmt.Sprintf("perUserSecrets.mappings[%d]", i), m); err != nil {
			return err
		}
	}
	for i, m := range c.Mappings {
		key := fmt.Sprintf("perUserSecrets.mappings[%d].placeholder", i)
		for j, s := range static {
			if placeholdersOverlap(m.Placeholder, s.Placeholder) {
				return fmt.Errorf("config: %s %q overlaps secrets[%d].placeholder %q: placeholders must not equal, contain or be contained in one another", key, m.Placeholder, j, s.Placeholder)
			}
		}
		for j := i + 1; j < len(c.Mappings); j++ {
			if placeholdersOverlap(m.Placeholder, c.Mappings[j].Placeholder) {
				return fmt.Errorf("config: %s %q overlaps perUserSecrets.mappings[%d].placeholder %q: placeholders must not equal, contain or be contained in one another", key, m.Placeholder, j, c.Mappings[j].Placeholder)
			}
		}
	}
	return nil
}

// placeholdersOverlap reports whether a equals, contains or is contained in b.
// An empty static placeholder is rejected elsewhere; it never overlaps here.
func placeholdersOverlap(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return strings.Contains(a, b) || strings.Contains(b, a)
}

func validatePerUserMapping(key string, m PerUserMapping) error {
	if m.Placeholder == "" {
		return fmt.Errorf("config: %s.placeholder is required", key)
	}
	if !perUserPlaceholderRE.MatchString(m.Placeholder) {
		return fmt.Errorf("config: %s.placeholder must be 8-128 characters of [A-Za-z0-9_{}-]", key)
	}
	if m.Provider == "" {
		return fmt.Errorf("config: %s.provider is required", key)
	}
	if !ValidOAuthProviderID(m.Provider) {
		return fmt.Errorf("config: %s.provider %q is not a valid provider id (lowercase letter, then up to 31 of [a-z0-9-])", key, m.Provider)
	}
	seen := map[string]bool{}
	for j, s := range m.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n\v\f") {
			return fmt.Errorf("config: %s.scopes[%d] must be a non-empty scope without whitespace", key, j)
		}
		if seen[s] {
			return fmt.Errorf("config: %s.scopes has duplicate scope %q", key, s)
		}
		seen[s] = true
	}
	if len(m.Domains) == 0 {
		return fmt.Errorf("config: %s.domains is required", key)
	}
	for j, d := range m.Domains {
		if err := validateDomainPattern(fmt.Sprintf("%s.domains[%d]", key, j), d); err != nil {
			return err
		}
	}
	seen = map[string]bool{}
	for j, in := range m.In {
		if in != PerUserInHeader && in != PerUserInQuery {
			return fmt.Errorf("config: %s.in[%d] %q is invalid; must be header or query (body is not supported)", key, j, in)
		}
		if seen[in] {
			return fmt.Errorf("config: %s.in has duplicate location %q", key, in)
		}
		seen[in] = true
	}
	if len(m.Agents) == 0 {
		return fmt.Errorf("config: %s.agents is required (a mapping is used only by the agents it lists)", key)
	}
	seen = map[string]bool{}
	for j, a := range m.Agents {
		if err := agentid.ValidID(a); err != nil {
			return fmt.Errorf("config: %s.agents[%d]: %w", key, j, err)
		}
		if seen[a] {
			return fmt.Errorf("config: %s.agents has duplicate agent %q", key, a)
		}
		seen[a] = true
	}
	return nil
}

// EncodePerUserSecretsNode encodes c as the on-disk `perUserSecrets:` block,
// the write-direction counterpart of parsePerUserSecrets (it round-trips
// through rawPerUserSecrets, so the YAML tags stay in one place). A zero
// WorkerCacheTTL is left out (the parser's default fills it in). The raw type
// has no value field, so the encoding is value-free by construction.
func EncodePerUserSecretsNode(c PerUserSecretsConfig) (yaml.Node, error) {
	raw := rawPerUserSecrets{Enabled: c.Enabled}
	if c.WorkerCacheTTL != 0 {
		raw.WorkerCacheTTL = c.WorkerCacheTTL.String()
	}
	for _, m := range c.Mappings {
		raw.Mappings = append(raw.Mappings, rawPerUserMapping{
			Placeholder: m.Placeholder,
			Provider:    m.Provider,
			Scopes:      append([]string(nil), m.Scopes...),
			Domains:     append([]string(nil), m.Domains...),
			In:          append([]string(nil), m.In...),
			Agents:      append([]string(nil), m.Agents...),
		})
	}
	var node yaml.Node
	if err := node.Encode(raw); err != nil {
		return yaml.Node{}, fmt.Errorf("config: encode perUserSecrets: %w", err)
	}
	return node, nil
}

// deepCopy returns c with every slice independently allocated.
func (c PerUserSecretsConfig) deepCopy() PerUserSecretsConfig {
	if c.Mappings == nil {
		return c
	}
	out := c
	out.Mappings = make([]PerUserMapping, len(c.Mappings))
	for i, m := range c.Mappings {
		m.Scopes = cloneStrings(m.Scopes)
		m.Domains = cloneStrings(m.Domains)
		m.In = cloneStrings(m.In)
		m.Agents = cloneStrings(m.Agents)
		out.Mappings[i] = m
	}
	return out
}

func cloneStrings(vs []string) []string {
	if vs == nil {
		return nil
	}
	return append([]string(nil), vs...)
}
