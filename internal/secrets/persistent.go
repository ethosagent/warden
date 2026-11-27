package secrets

import "context"

// Persistent is an OPTIONAL extension of SecretStore that reports whether the
// backend keeps values across restarts. Code that must not lose what it writes
// (the IdP link with consent.idpLink enabled, W-P3-CSIG-03; per-user grants,
// W-P3-PUS-02) refuses a store for which IsPersistent is false.
//
// EchoStore reports false (it keeps no value at all); the AWS and Vault KV v2
// stores report true.
type Persistent interface {
	Persists() bool
}

// IsPersistent reports whether s implements Persistent and Persists() is true.
// A store that does not implement Persistent counts as non-persistent, so a new
// backend has to opt in before it can hold per-user credentials.
func IsPersistent(s SecretStore) bool {
	p, ok := s.(Persistent)
	return ok && p.Persists()
}

// Persists reports false: the echo backend discards every value.
func (s *EchoStore) Persists() bool { return false }

// Persists reports true: AWS Secrets Manager keeps values.
func (s *awsSecretStore) Persists() bool { return true }

// Persists reports true: a Vault KV v2 mount keeps values.
func (s *vaultSecretStore) Persists() bool { return true }

// Prober is an OPTIONAL extension of SecretStore for a backend that can check,
// before first use, that it is reachable and configured as expected (the Vault
// store's KV v2 mount preflight). Startup code that must fail closed calls it.
type Prober interface {
	Probe(ctx context.Context) error
}

var (
	_ Persistent = (*EchoStore)(nil)
	_ Persistent = (*awsSecretStore)(nil)
	_ Persistent = (*vaultSecretStore)(nil)
	_ Prober     = (*vaultSecretStore)(nil)
)
