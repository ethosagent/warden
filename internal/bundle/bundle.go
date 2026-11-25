// Package bundle defines the signed policy bundle: the payload the control
// plane serves on GET /policy, the envelope that carries it, and the Sign and
// Verify pair around them.
//
// A signature covers the exact payload bytes behind a domain-separation
// prefix, so no JSON canonicalization exists anywhere and a worker checks the
// signature before it decodes a single byte of the payload. The algorithm
// comes from the pinned JWK, never from the envelope. Crypto goes through
// internal/keys; this package adds no dependency and does no I/O.
package bundle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"time"
)

const (
	// TypV1 is the payload type of this format version.
	TypV1 = "warden-bundle/v1"
	// MaxEnvelopeBytes bounds a serialized envelope: Sign refuses to produce
	// more and Verify refuses to look at more.
	MaxEnvelopeBytes = 4 << 20
	// SigningPrefix is the domain-separation string that precedes the
	// payload bytes in every signing input, so a bundle signature can never
	// be replayed as a token signature made by the same key family.
	SigningPrefix = "warden-bundle-v1"
)

// Bundle is the signed payload. Policy and Sections carry already-serialized
// JSON so the bytes the CP served are the bytes that were hashed and signed.
//
// Adding a top-level field (W-P2-WBND-06 added tokenIssuer) takes three steps:
// decode it in Bundle.setMember (payload.go), which the field-coverage test
// enforces; cover it in contentSHA256, or carry it inside a section, so a
// change to it changes the content hash; and compare it with the applied
// state where it matters.
type Bundle struct {
	Typ               string          `json:"typ"`
	Seq               int64           `json:"seq"`
	PolicyVersion     int64           `json:"policyVersion"` // informational only
	IssuedAt          time.Time       `json:"issuedAt"`
	ExpiresAt         time.Time       `json:"expiresAt"`
	CPID              string          `json:"cpID"`
	ContentSHA256     string          `json:"contentSha256"`
	Policy            json.RawMessage `json:"policy"`
	CredentialsSHA256 string          `json:"credentialsSha256,omitempty"`
	// TokenIssuer is the iss of the Warden tokens the control plane mints
	// (tokenService.issuer). It is signed and part of ContentSHA256, so a
	// worker verifies tokens against the issuer the signers vouched for, never
	// against cpID. Empty (omitted) when the control plane mints no tokens.
	TokenIssuer string                     `json:"tokenIssuer,omitempty"`
	Sections    map[string]json.RawMessage `json:"sections,omitempty"`
}

// Credentials is the unsigned sidecar the envelope carries beside the signed
// payload: the sanctioned AWS credential, whose SHA-256 the payload commits
// to. Every printing form is "[redacted]"; only JSON marshalling, which the
// envelope needs, shows the values.
type Credentials struct {
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

const redacted = "[redacted]"

// String implements fmt.Stringer.
func (Credentials) String() string { return redacted }

// GoString implements fmt.GoStringer, so %#v is redacted too.
func (Credentials) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Credentials) LogValue() slog.Value { return slog.StringValue(redacted) }

func (c Credentials) empty() bool { return c.AccessKeyID == "" && c.SecretAccessKey == "" }

// hash is the lowercase-hex SHA-256 the payload's credentialsSha256 carries,
// over length-prefixed members so no value can shift into its neighbour.
func (c Credentials) hash() string {
	h := sha256.New()
	writeField(h, []byte("warden-bundle-credentials-v1"))
	writeField(h, []byte(c.AccessKeyID))
	writeField(h, []byte(c.SecretAccessKey))
	return hex.EncodeToString(h.Sum(nil))
}

// State is what a worker has applied so far; the zero value means nothing.
type State struct {
	Seq           int64
	ContentSHA256 string
	IssuedAt      time.Time
}

// Options tune Verify. Now is required: a zero Now makes every bundle
// "future", so a forgotten clock fails closed. Issuer, when set, must equal
// the payload cpID. AllowMissingCredentials lets a bundle whose payload
// commits to a credentials hash verify without the sidecar (the cached
// envelope, which is stored without it): Verified.Credentials is then nil.
// A sidecar that is present must still match.
type Options struct {
	Now                     time.Time
	Skew                    time.Duration
	Issuer                  string
	AllowMissingCredentials bool
}

// Verified is an accepted bundle.
type Verified struct {
	Bundle Bundle
	// Seq and ContentSHA256 repeat the payload's values.
	Seq           int64
	ContentSHA256 string
	// KID is a pinned kid whose signature verified.
	KID string
	// Refresh is true when the content is the applied content re-signed with
	// a newer issuedAt: only the freshness window moves.
	Refresh bool
	// Credentials is the sidecar, present only when it matched the signed
	// hash. Nil when the bundle carries none.
	Credentials *Credentials

	// payload (the base64url text, aliasing the verified bytes) and
	// signatures are the envelope members Verify parsed, for
	// WithoutCredentials.
	payload    []byte
	signatures []Signature
}

// WithoutCredentials returns the verified envelope re-marshalled in canonical
// form with no credentials sidecar: only the payload and signatures that
// Verify itself parsed, under the names Sign writes. It is what may be
// persisted (the worker's last-known-good cache): no unknown member and no
// secret can come along, whatever the received envelope looked like. Verify
// accepts the result with Options.AllowMissingCredentials.
func (v Verified) WithoutCredentials() ([]byte, error) {
	if len(v.payload) == 0 || len(v.signatures) == 0 {
		return nil, errors.New("bundle: not a verified envelope")
	}
	return json.Marshal(Envelope{Payload: string(v.payload), Signatures: v.signatures})
}

// contentSHA256 hashes what makes two bundles the same content: cpID, policy,
// credentialsSha256, sections and tokenIssuer, not the timestamps, so a
// re-sign of unchanged content is recognisable. Fields are length-prefixed and
// sections are visited in key order. The token issuer is appended only when
// set, so the hash of a bundle without one is what it was before the field
// existed.
func contentSHA256(cpID string, policy json.RawMessage, credsSHA string, sections map[string]json.RawMessage, tokenIssuer string) string {
	h := sha256.New()
	writeField(h, []byte("warden-bundle-content-v1"))
	writeField(h, []byte(cpID))
	writeField(h, policy)
	writeField(h, []byte(credsSHA))
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(names)))
	_, _ = h.Write(n[:])
	for _, name := range names {
		writeField(h, []byte(name))
		writeField(h, sections[name])
	}
	if tokenIssuer != "" {
		writeField(h, []byte("tokenIssuer"))
		writeField(h, []byte(tokenIssuer))
	}
	return hex.EncodeToString(h.Sum(nil))
}

type writer interface{ Write(p []byte) (int, error) }

func writeField(w writer, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(b)
}

// digest16 is the 16-hex prefix of the SHA-256 of b: the only fingerprint of
// payload bytes an error may carry.
func digest16(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8])
}
