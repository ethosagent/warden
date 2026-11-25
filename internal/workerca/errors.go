package workerca

import "errors"

// Typed errors of the worker CA. Callers match them with errors.Is; none of
// them carries key, CSR or certificate bytes.
var (
	// ErrUnsupportedKey is a CSR whose public key is not ECDSA P-256 or Ed25519.
	ErrUnsupportedKey = errors.New("workerca: unsupported key type (want ECDSA P-256 or Ed25519)")
	// ErrBadCSR is a missing, malformed or wrongly self-signed CSR.
	ErrBadCSR = errors.New("workerca: bad certificate request")
	// ErrInvalidWorkerID is a worker id outside ^[A-Za-z0-9._-]{1,128}$.
	ErrInvalidWorkerID = errors.New("workerca: invalid worker id")
	// ErrInvalidTTL is a non-positive certificate lifetime.
	ErrInvalidTTL = errors.New("workerca: certificate ttl must be positive")
	// ErrNotWorkerCert is a certificate that does not carry exactly one worker
	// SPIFFE URI SAN of the configured trust domain.
	ErrNotWorkerCert = errors.New("workerca: not a worker certificate")
	// ErrIntermediate is an intermediate that is not a valid worker CA: not a
	// CA, path length not 0, no certSign, key mismatch or a bad pair.
	ErrIntermediate = errors.New("workerca: invalid worker intermediate")
	// ErrIntermediateExpired is an intermediate outside its validity window.
	ErrIntermediateExpired = errors.New("workerca: worker intermediate is not valid now")
	// ErrSharedTrustRoot is an intermediate that equals, or chains to, the
	// proxy MITM / control-plane TLS CA.
	ErrSharedTrustRoot = errors.New("workerca: worker intermediate shares a trust root with the proxy CA")
	// ErrInvalidTrustDomain is an empty or malformed trust domain.
	ErrInvalidTrustDomain = errors.New("workerca: invalid trust domain")
)
