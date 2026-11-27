package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// consent.store backend selectors. vault is parsed and shape-checked now, but
// the control plane refuses to start with it until the Vault KV v2 store
// (W-P3-PUS-01) is wired in (W-P3-PUS-02).
const (
	ConsentStoreBackendAWS   = "aws"
	ConsentStoreBackendVault = "vault"
	ConsentStoreBackendEcho  = "echo"
)

// DefaultConsentStoreNamePrefix is the default consent.store.namePrefix. It is
// disjoint from the distributed secretStore default (warden/) and from the keys
// default (warden-cp-keys/), so the CP role alone can be granted warden-cp/*.
const DefaultConsentStoreNamePrefix = "warden-cp/"

// DefaultConsentStoreVaultTokenEnv is the default consent.store.vault.tokenEnv.
const DefaultConsentStoreVaultTokenEnv = "VAULT_TOKEN"

// ConsentStore is the CP-only user credential store (`consent.store`,
// W-P3-CSIG-06): the one store for every per-user credential in P3 (IdP
// refresh tokens under idp/, provider grants under users/, parked revokes under
// revoking/ and OAuth client secrets under oauth-clients/). Like the rest of
// the consent block it is CP-local: it is read from the operator-owned
// --config only and never reaches SettingsWire or /policy.
//
// It carries no credential. The AWS client resolves credentials from the CP
// environment or instance role; the Vault token is read from the CP
// environment variable named by Vault.TokenEnv. The raw block has no key or
// token field, so the strict parse rejects one.
type ConsentStore struct {
	// Backend is aws, vault or echo (echo only with the CP's --dev flag).
	Backend string
	// NamePrefix is prepended to every logical key (default warden-cp/), so a
	// logical idp/<userKey> lives at warden-cp/idp/<userKey>.
	NamePrefix string
	AWS        *ConsentStoreAWS
	Vault      *ConsentStoreVault
}

// ConsentStoreAWS holds the AWS Secrets Manager settings of consent.store.
type ConsentStoreAWS struct {
	// Region is the Secrets Manager region (required).
	Region string
}

// ConsentStoreVault holds the Vault KV v2 settings of consent.store.
type ConsentStoreVault struct {
	Addr      string
	Mount     string
	Namespace string
	// TokenEnv names the CP environment variable holding the Vault token
	// (default VAULT_TOKEN); never the token itself.
	TokenEnv string
}

type rawConsentStore struct {
	Backend    string `yaml:"backend"`
	NamePrefix string `yaml:"namePrefix"`
	AWS        *struct {
		Region string `yaml:"region"`
	} `yaml:"aws"`
	Vault *struct {
		Addr      string `yaml:"addr"`
		Mount     string `yaml:"mount"`
		Namespace string `yaml:"namespace"`
		TokenEnv  string `yaml:"tokenEnv"`
	} `yaml:"vault"`
}

// parseConsentStore converts the raw block and applies the defaults. An absent
// block is nil: no CP-only store.
func parseConsentStore(r *rawConsentStore) *ConsentStore {
	if r == nil {
		return nil
	}
	s := &ConsentStore{
		Backend:    strings.ToLower(strings.TrimSpace(r.Backend)),
		NamePrefix: strings.TrimSpace(r.NamePrefix),
	}
	if s.NamePrefix == "" {
		s.NamePrefix = DefaultConsentStoreNamePrefix
	}
	if r.AWS != nil {
		s.AWS = &ConsentStoreAWS{Region: strings.TrimSpace(r.AWS.Region)}
	}
	if r.Vault != nil {
		v := &ConsentStoreVault{
			Addr:      strings.TrimSpace(r.Vault.Addr),
			Mount:     strings.Trim(strings.TrimSpace(r.Vault.Mount), "/"),
			Namespace: strings.Trim(strings.TrimSpace(r.Vault.Namespace), "/"),
			TokenEnv:  strings.TrimSpace(r.Vault.TokenEnv),
		}
		if v.TokenEnv == "" {
			v.TokenEnv = DefaultConsentStoreVaultTokenEnv
		}
		s.Vault = v
	}
	return s
}

// consentStorePrefixRE is the namePrefix grammar: characters valid in an AWS
// secret name and in a Vault path, no leading slash, ending in a slash.
var consentStorePrefixRE = regexp.MustCompile(`^[A-Za-z0-9_+=.@-][A-Za-z0-9_+=.@/-]*/$`)

// envNameRE is a POSIX-style environment variable name.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// validateConsentStore checks the shape of consent.store. Whether the backend
// may be used at all (echo needs --dev, vault needs W-P3-PUS-02) and whether it
// overlaps the distributed secretStore are control-plane startup checks
// (controlplane.NewUserStore), because they depend on flags and on the served
// secretStore.
func validateConsentStore(s *ConsentStore) error {
	if s == nil {
		return nil
	}
	switch s.Backend {
	case ConsentStoreBackendAWS, ConsentStoreBackendVault, ConsentStoreBackendEcho:
	case "":
		return fmt.Errorf("config: consent.store.backend is required (aws, vault or echo)")
	default:
		return fmt.Errorf("config: consent.store.backend %q is invalid; must be one of: aws, vault, echo", s.Backend)
	}
	if !consentStorePrefixRE.MatchString(s.NamePrefix) || strings.Contains(s.NamePrefix, "//") {
		return fmt.Errorf("config: consent.store.namePrefix %q must use only [A-Za-z0-9/_+=.@-], must not start with / and must end with /", s.NamePrefix)
	}
	if s.AWS != nil && s.Backend != ConsentStoreBackendAWS {
		return fmt.Errorf("config: consent.store.aws is set but consent.store.backend is %q", s.Backend)
	}
	if s.Vault != nil && s.Backend != ConsentStoreBackendVault {
		return fmt.Errorf("config: consent.store.vault is set but consent.store.backend is %q", s.Backend)
	}
	if s.Backend == ConsentStoreBackendAWS && (s.AWS == nil || s.AWS.Region == "") {
		return fmt.Errorf("config: consent.store.backend aws requires consent.store.aws.region")
	}
	if s.Backend != ConsentStoreBackendVault {
		return nil
	}
	v := s.Vault
	if v == nil {
		return fmt.Errorf("config: consent.store.backend vault requires consent.store.vault {addr, mount}")
	}
	u, err := url.Parse(v.Addr)
	if v.Addr == "" || err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("config: consent.store.vault.addr %q must be an absolute http(s) URL", v.Addr)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: consent.store.vault.addr %q must not carry userinfo, query or fragment", v.Addr)
	}
	if v.Mount == "" {
		return fmt.Errorf("config: consent.store.vault.mount is required")
	}
	if !envNameRE.MatchString(v.TokenEnv) {
		return fmt.Errorf("config: consent.store.vault.tokenEnv %q must be an environment variable name", v.TokenEnv)
	}
	return nil
}
