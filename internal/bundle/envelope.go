package bundle

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ethosagent/warden/internal/keys"
)

// Envelope is the wire form served on GET /policy. Payload is the unpadded
// base64url of the exact bytes every signature covers; Credentials is the
// unsigned sidecar.
type Envelope struct {
	Payload     string       `json:"payload"`
	Signatures  []Signature  `json:"signatures"`
	Credentials *Credentials `json:"credentials,omitempty"`
}

// Signature is one signer's signature, Sig being the unpadded base64url of
// the raw JWS signature bytes (keys.Signer.Sign output).
type Signature struct {
	KID string `json:"kid"`
	Sig string `json:"sig"`
}

// signingInput is SigningPrefix, one 0x00 byte, then the payload bytes.
func signingInput(payload []byte) []byte {
	in := make([]byte, 0, len(SigningPrefix)+1+len(payload))
	in = append(in, SigningPrefix...)
	in = append(in, 0)
	return append(in, payload...)
}

// Sign returns the serialized envelope for b. It sets Typ, ContentSHA256 and
// CredentialsSHA256 (from creds; nil or empty means none), marshals the
// payload once, and has every signer sign SigningPrefix + 0x00 + payload, so
// two signers during a key rotation both vouch for the same bytes. It
// rejects zero signers, an unusable bundle and an envelope over
// MaxEnvelopeBytes. Policy and the sections must be valid JSON; they are
// compacted so the hashed bytes are the marshalled bytes.
func Sign(ctx context.Context, b Bundle, creds *Credentials, signers ...keys.Signer) ([]byte, error) {
	if len(signers) == 0 {
		return nil, errors.New("bundle: sign needs at least one signer")
	}
	if b.Seq < 1 {
		return nil, fmt.Errorf("bundle: seq %d must be positive", b.Seq)
	}
	if b.CPID == "" {
		return nil, errors.New("bundle: cpID is required")
	}
	if b.IssuedAt.IsZero() || !b.ExpiresAt.After(b.IssuedAt) {
		return nil, errors.New("bundle: expiresAt must be after issuedAt")
	}
	policy, err := compactJSON(b.Policy)
	if err != nil {
		return nil, fmt.Errorf("bundle: policy: %w", err)
	}
	b.Policy = policy
	if len(b.Sections) > 0 {
		sections := make(map[string]json.RawMessage, len(b.Sections))
		for name, raw := range b.Sections {
			c, err := compactJSON(raw)
			if err != nil {
				return nil, fmt.Errorf("bundle: section %q: %w", name, err)
			}
			sections[name] = c
		}
		b.Sections = sections
	} else {
		b.Sections = nil
	}
	b.Typ = TypV1
	b.CredentialsSHA256 = ""
	var sidecar *Credentials
	if creds != nil && !creds.empty() {
		c := *creds
		sidecar = &c
		b.CredentialsSHA256 = c.hash()
	}
	b.ContentSHA256 = contentSHA256(b.CPID, b.Policy, b.CredentialsSHA256, b.Sections)

	payload, err := marshalNoEscape(b)
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal payload: %w", err)
	}
	in := signingInput(payload)
	env := Envelope{
		Payload:     base64.RawURLEncoding.EncodeToString(payload),
		Signatures:  make([]Signature, 0, len(signers)),
		Credentials: sidecar,
	}
	for _, s := range signers {
		sig, err := s.Sign(ctx, in)
		if err != nil {
			return nil, fmt.Errorf("bundle: sign with kid %s: %w", s.KID(), err)
		}
		env.Signatures = append(env.Signatures, Signature{KID: s.KID(), Sig: base64.RawURLEncoding.EncodeToString(sig)})
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("bundle: marshal envelope: %w", err)
	}
	if len(raw) > MaxEnvelopeBytes {
		return nil, fmt.Errorf("bundle: envelope is %d bytes, limit %d", len(raw), MaxEnvelopeBytes)
	}
	return raw, nil
}

func compactJSON(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return nil, errors.New("is empty")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, errors.New("is not valid JSON")
	}
	return buf.Bytes(), nil
}

// marshalNoEscape marshals v without HTML escaping, so a compacted
// RawMessage is emitted byte for byte and the content hash computed before
// marshalling still matches the bytes a verifier decodes.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
