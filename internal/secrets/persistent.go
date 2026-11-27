package secrets

// Persistent is an OPTIONAL extension of SecretStore that reports whether the
// backend keeps values across restarts. Code that must not lose what it writes
// (the IdP link with consent.idpLink enabled, W-P3-CSIG-03; per-user grants,
// W-P3-PUS-02) refuses a store for which IsPersistent is false.
//
// EchoStore reports false (it keeps no value at all) and the AWS store true;
// the Vault KV v2 store (W-P3-PUS-01) reports true once wired.
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

var (
	_ Persistent = (*EchoStore)(nil)
	_ Persistent = (*awsSecretStore)(nil)
)
