package bundle

import (
	"errors"
	"fmt"
)

// reasonError is a rejection with a fixed, metric-safe reason. Verify wraps
// one with the facts safe to print (seq, kid, a digest prefix) and never with
// payload content or credential values.
type reasonError struct {
	reason string
	text   string
}

func (e *reasonError) Error() string { return "bundle: " + e.text }

// Rejections Verify returns. Each maps to exactly one Reason, the label value
// of warden_bundle_rejected_total. Match them with errors.Is.
var (
	// ErrMalformed: the envelope or payload is not what this format says, or
	// the signed payload contradicts itself (contentSha256 does not match).
	ErrMalformed error = &reasonError{"malformed", "malformed envelope or payload"}
	// ErrTooLarge: the raw envelope is over MaxEnvelopeBytes.
	ErrTooLarge error = &reasonError{"too_large", "envelope exceeds the size limit"}
	// ErrUnsupportedFormat: the signed payload names a format version this
	// build does not understand.
	ErrUnsupportedFormat error = &reasonError{"unsupported_format", "unsupported bundle format"}
	// ErrUnsigned: the envelope carries no signatures.
	ErrUnsigned error = &reasonError{"unsigned", "envelope carries no signature"}
	// ErrUnknownKid: none of the envelope's signing kids is pinned.
	ErrUnknownKid error = &reasonError{"unknown_kid", "no signature is by a pinned key"}
	// ErrBadSignature: a signature by a pinned kid did not verify, and none did.
	ErrBadSignature error = &reasonError{"bad_signature", "signature does not verify"}
	// ErrIssuerMismatch: the payload cpID is not the issuer the worker expects.
	ErrIssuerMismatch error = &reasonError{"issuer_mismatch", "issuer does not match"}
	// ErrCredentialMismatch: the credentials sidecar does not match the hash
	// the signed payload commits to.
	ErrCredentialMismatch error = &reasonError{"credential_mismatch", "credentials sidecar does not match the signed hash"}
	// ErrRollback: the bundle's seq is below the applied seq.
	ErrRollback error = &reasonError{"rollback", "seq is older than the applied bundle"}
	// ErrEquivocation: the bundle has the applied seq but different content.
	ErrEquivocation error = &reasonError{"equivocation", "same seq as the applied bundle with different content"}
	// ErrExpired: now is past expiresAt plus the skew.
	ErrExpired error = &reasonError{"expired", "bundle has expired"}
	// ErrFuture: issuedAt is past now plus the skew.
	ErrFuture error = &reasonError{"future", "bundle is issued in the future"}

	// ErrUnchanged reports an identical re-delivery of the applied bundle:
	// same seq, same content, issuedAt not newer. It is not a rejection and
	// has no Reason; callers keep what they have.
	ErrUnchanged = errors.New("bundle: unchanged")
)

// Reason returns the fixed rejection reason for err, one of malformed,
// too_large, unsupported_format, unsigned, unknown_kid, bad_signature,
// issuer_mismatch, credential_mismatch, rollback, equivocation, expired and
// future. It returns "" for nil, ErrUnchanged and any error that is not a
// rejection from this package.
func Reason(err error) string {
	var re *reasonError
	if errors.As(err, &re) {
		return re.reason
	}
	return ""
}

// facts is the only context an error may carry: never payload content.
type facts struct {
	seq     int64
	kid     string
	payload []byte // reduced to a 16-hex digest prefix when printed
}

func (f facts) wrap(base error) error {
	s := ""
	if f.seq != 0 {
		s += fmt.Sprintf(" seq=%d", f.seq)
	}
	if f.kid != "" {
		s += " kid=" + f.kid
	}
	if len(f.payload) > 0 {
		s += " digest=" + digest16(f.payload)
	}
	if s == "" {
		return base
	}
	return fmt.Errorf("%w (%s)", base, s[1:])
}
