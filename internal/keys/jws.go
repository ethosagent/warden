package keys

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Errors returned by ParseCompact and SignCompact. Like the rest of the
// package they name facts (a header member, a segment index), never bytes of
// the input: a rejected token is attacker-chosen and may be a stolen
// credential.
var (
	// ErrMalformedJWS reports a compact serialization that is not three
	// unpadded base64url segments, a header that is not a JSON object of the
	// expected shape, or a header with a duplicate or mis-cased member.
	ErrMalformedJWS = errors.New("keys: malformed jws")
	// ErrForbiddenHeader reports a header member that lets the token choose
	// or fetch its own verification key (jwk, jku, x5u, x5c) or that demands
	// extensions this package does not implement (crit).
	ErrForbiddenHeader = errors.New("keys: forbidden jws header member")
)

// Header is the protected header of a JWS this package signs or accepts: the
// only members it knows. Anything else is either ignored (harmless members
// such as "cty") or rejected (ErrForbiddenHeader).
type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// maxSegment bounds one segment ParseCompact will decode, so a caller that
// forgot its own size cap cannot make it allocate without limit.
const maxSegment = 1 << 20

// ParseCompact splits and decodes a JWS compact serialization (RFC 7515
// section 7.1) strictly: exactly three segments, each unpadded base64url with
// no stray characters, a non-empty payload and signature, and a header that is
// one JSON object. alg must be EdDSA or ES256 (ErrUnsupportedAlg otherwise:
// "none", HS* and RS* never get further); a header carrying crit, jku, jwk,
// x5u or x5c is ErrForbiddenHeader. Members are matched case-sensitively and
// a duplicate member (case-folded) is ErrMalformedJWS. kid is optional here;
// the verifier decides whether it is required.
//
// signingInput is the ASCII "header.payload" the signature covers, byte for
// byte as received. ParseCompact does not verify anything.
func ParseCompact(raw string) (h Header, payload, signingInput, sig []byte, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Header{}, nil, nil, nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformedJWS, len(parts))
	}
	var seg [3][]byte
	for i, p := range parts {
		// Strict decoding still skips CR and LF, so refuse them first.
		if p == "" || len(p) > maxSegment || strings.ContainsAny(p, "\r\n") {
			return Header{}, nil, nil, nil, fmt.Errorf("%w: segment %d is empty or too long", ErrMalformedJWS, i)
		}
		b, derr := base64.RawURLEncoding.Strict().DecodeString(p)
		if derr != nil {
			return Header{}, nil, nil, nil, fmt.Errorf("%w: segment %d is not unpadded base64url", ErrMalformedJWS, i)
		}
		seg[i] = b
	}
	h, err = parseHeader(seg[0])
	if err != nil {
		return Header{}, nil, nil, nil, err
	}
	return h, seg[1], []byte(parts[0] + "." + parts[1]), seg[2], nil
}

func parseHeader(data []byte) (Header, error) {
	bad := func(what string) error { return fmt.Errorf("%w: header %s", ErrMalformedJWS, what) }
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return Header{}, bad("is not a json object")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return Header{}, bad("is not a json object")
	}
	members := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return Header{}, bad("is malformed json")
		}
		name, ok := nameTok.(string)
		if !ok {
			return Header{}, bad("is malformed json")
		}
		folded := strings.ToLower(name)
		if seen[folded] {
			return Header{}, bad("has a duplicate member")
		}
		seen[folded] = true
		for _, known := range []string{"crit", "jku", "jwk", "x5u", "x5c"} {
			if strings.EqualFold(name, known) {
				return Header{}, fmt.Errorf("%w: %q", ErrForbiddenHeader, known)
			}
		}
		for _, known := range []string{"alg", "kid", "typ"} {
			if name != known && strings.EqualFold(name, known) {
				return Header{}, bad("has a mis-cased member")
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return Header{}, bad("is malformed json")
		}
		members[name] = v
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return Header{}, bad("is malformed json")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Header{}, bad("has trailing data")
	}
	var h Header
	for name, dst := range map[string]*string{"alg": &h.Alg, "kid": &h.Kid, "typ": &h.Typ} {
		v, ok := members[name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(v, dst); err != nil {
			return Header{}, bad("member " + name + " is not a string")
		}
	}
	switch h.Alg {
	case AlgEdDSA, AlgES256:
	case "":
		return Header{}, bad("has no alg")
	default:
		return Header{}, fmt.Errorf("%w: header alg %q", ErrUnsupportedAlg, safeAlg(h.Alg))
	}
	return h, nil
}

// safeAlg bounds an attacker-supplied alg before it is named in an error.
func safeAlg(s string) string {
	if len(s) > 16 {
		return s[:16] + "..."
	}
	return s
}

// SignCompact builds a JWS compact serialization of claims, signed by s. The
// header's Alg must be empty (the signer's algorithm is used) or equal to
// s.Alg(); an empty Kid becomes s.KID(). claims is marshalled with
// encoding/json. The result is exactly what ParseCompact reads back.
func SignCompact(ctx context.Context, s Signer, h Header, claims any) (string, error) {
	if s == nil {
		return "", fmt.Errorf("%w: nil signer", ErrInvalidKey)
	}
	if h.Alg == "" {
		h.Alg = s.Alg()
	}
	if h.Alg != s.Alg() {
		return "", fmt.Errorf("%w: header %q, signer %q", ErrAlgMismatch, h.Alg, s.Alg())
	}
	if h.Kid == "" {
		h.Kid = s.KID()
	}
	hb, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("keys: marshal jws header: %w", err)
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("keys: marshal jws claims: %w", err)
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(hb) + "." + enc.EncodeToString(cb)
	sig, err := s.Sign(ctx, []byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + enc.EncodeToString(sig), nil
}
