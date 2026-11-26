package bundle

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/ethosagent/warden/internal/keys"
)

// maxSignatures bounds the signature work one envelope can demand.
const maxSignatures = 16

// Verify checks raw as a signed bundle against the pinned keys and what the
// worker has applied. The order is: size, envelope decode, signatures (before
// any payload decode), payload decode, typ, issuer, credentials, future,
// expired, then the seq rules. It returns one of the Err* rejections (see
// Reason), or ErrUnchanged for an identical re-delivery. A newer issuedAt
// with the applied content is accepted with Refresh set.
//
// One valid signature by a pinned key is enough, which allows signing with
// two keys during rotation. The algorithm is the pinned JWK's, never the
// envelope's.
func Verify(raw []byte, pins []keys.JWK, applied State, opt Options) (Verified, error) {
	if len(raw) > MaxEnvelopeBytes {
		return Verified{}, ErrTooLarge
	}
	env, err := parseEnvelope(raw)
	if err != nil {
		return Verified{}, ErrMalformed
	}
	if len(env.Signatures) == 0 {
		return Verified{}, ErrUnsigned
	}
	if len(env.Signatures) > maxSignatures {
		return Verified{}, ErrMalformed
	}
	payload := make([]byte, base64.RawURLEncoding.DecodedLen(len(env.payload)))
	n, err := base64.RawURLEncoding.Strict().Decode(payload, env.payload)
	if err != nil || n == 0 {
		return Verified{}, ErrMalformed
	}
	payload = payload[:n]

	kid, err := checkSignatures(env.Signatures, payload, pins)
	if err != nil {
		return Verified{}, facts{kid: kid, payload: payload}.wrap(err)
	}

	b, err := decodePayload(payload)
	if err != nil {
		return Verified{}, facts{kid: kid, payload: payload}.wrap(ErrMalformed)
	}
	f := facts{seq: b.Seq, kid: kid, payload: payload}
	if b.Typ != TypV1 {
		return Verified{}, f.wrap(ErrUnsupportedFormat)
	}
	if b.Seq < 1 || b.CPID == "" || len(b.Policy) == 0 || !b.ExpiresAt.After(b.IssuedAt) ||
		contentSHA256(b.CPID, b.Policy, b.CredentialsSHA256, b.Sections, b.TokenIssuer) != b.ContentSHA256 {
		return Verified{}, f.wrap(ErrMalformed)
	}
	if opt.Issuer != "" && b.CPID != opt.Issuer {
		return Verified{}, f.wrap(ErrIssuerMismatch)
	}
	creds, err := checkCredentials(env.Credentials, b.CredentialsSHA256, opt.AllowMissingCredentials)
	if err != nil {
		return Verified{}, f.wrap(err)
	}
	if b.IssuedAt.After(opt.Now.Add(opt.Skew)) {
		return Verified{}, f.wrap(ErrFuture)
	}
	if opt.Now.After(b.ExpiresAt.Add(opt.Skew)) {
		return Verified{}, f.wrap(ErrExpired)
	}

	v := Verified{
		Bundle: b, Seq: b.Seq, ContentSHA256: b.ContentSHA256, KID: kid, Credentials: creds,
		payload: env.payload, signatures: slices.Clone(env.Signatures),
	}
	switch {
	case b.Seq < applied.Seq:
		return Verified{}, f.wrap(ErrRollback)
	case b.Seq == applied.Seq:
		if b.ContentSHA256 != applied.ContentSHA256 {
			return Verified{}, f.wrap(ErrEquivocation)
		}
		if !b.IssuedAt.After(applied.IssuedAt) {
			return Verified{}, ErrUnchanged
		}
		v.Refresh = true
	}
	return v, nil
}

// checkSignatures returns the kid of a pinned signature that verified. With
// no verified signature it returns ErrUnknownKid when no signing kid is
// pinned at all, ErrBadSignature when a pinned kid failed (and the kid of the
// first such failure, for the error text).
func checkSignatures(sigs []Signature, payload []byte, pins []keys.JWK) (string, error) {
	byKID := make(map[string]keys.JWK, len(pins))
	for _, p := range pins {
		kid, err := keys.Thumbprint(p)
		if err != nil {
			continue // an unusable pin can verify nothing
		}
		byKID[kid] = p
	}
	in := signingInput(payload)
	failedKID := ""
	pinnedSeen := false
	tried := make(map[string]bool, len(sigs))
	for _, s := range sigs {
		jwk, ok := byKID[s.KID]
		if !ok || tried[s.KID] {
			continue // unpinned, or this kid already had its one attempt
		}
		tried[s.KID] = true
		pinnedSeen = true
		sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Sig)
		if err == nil {
			err = keys.Verify(jwk, algOf(jwk), in, sig)
		}
		if err == nil {
			return s.KID, nil
		}
		if failedKID == "" {
			failedKID = s.KID
		}
	}
	if !pinnedSeen {
		return "", ErrUnknownKid
	}
	return failedKID, ErrBadSignature
}

// algOf is the JWS algorithm the pinned key implies. keys.Verify re-checks it
// against the key and any alg member.
func algOf(j keys.JWK) string {
	if j.Alg != "" {
		return j.Alg
	}
	switch j.Kty {
	case "OKP":
		return keys.AlgEdDSA
	case "EC":
		return keys.AlgES256
	}
	return ""
}

// checkCredentials accepts the sidecar only when it hashes to what the signed
// payload committed to; a sidecar the payload did not commit to, and a
// committed hash with no sidecar, are both mismatches.
func checkCredentials(sidecar *Credentials, want string, allowMissing bool) (*Credentials, error) {
	if sidecar == nil || sidecar.empty() {
		if want != "" && !allowMissing {
			return nil, ErrCredentialMismatch
		}
		return nil, nil
	}
	if want == "" || subtle.ConstantTimeCompare([]byte(sidecar.hash()), []byte(want)) != 1 {
		return nil, ErrCredentialMismatch
	}
	c := *sidecar
	return &c, nil
}

// isCaseVariant reports a member name that encoding/json would match to one of
// names case-insensitively without being spelled exactly like it. Both the
// fast path and the strict member scan refuse those.
func isCaseVariant(key string, names ...string) bool {
	for _, n := range names {
		if key != n && strings.EqualFold(key, n) {
			return true
		}
	}
	return false
}

// envelopeMembers are the envelope's member names, as Sign writes them.
var envelopeMembers = []string{"payload", "signatures", "credentials"}

var errEnvelope = errors.New("bundle: envelope is not a canonical bundle envelope")

// parseEnvelope decodes the envelope. Member names are matched exactly, the
// way Sign writes them: a name that only case-folds to payload, signatures or
// credentials, and a repeated one of those, is malformed. encoding/json would
// match such a name case-insensitively (and let the last duplicate win), and
// any other reader that parses the envelope its own way (a map lookup, say)
// would then disagree with Verify about which credentials sidecar the
// envelope carries. Unknown extra members are ignored.
//
// The payload member is megabytes of base64url, which encoding/json would
// scan three times; base64url never contains a backslash, so a plain string
// is cut out with a byte search and only the small members go through the
// decoder. Anything the fast path is not certain about (escapes, duplicate or
// odd members, any syntax doubt) falls back to a strict scan of the top-level
// member names followed by json.Unmarshal.
func parseEnvelope(raw []byte) (rawEnvelope, error) {
	if env, ok := fastEnvelope(raw); ok {
		return env, nil
	}
	if err := checkEnvelopeMembers(raw); err != nil {
		return rawEnvelope{}, err
	}
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return rawEnvelope{}, err
	}
	return rawEnvelope{payload: []byte(e.Payload), Signatures: e.Signatures, Credentials: e.Credentials}, nil
}

// checkEnvelopeMembers requires raw to be one JSON object whose top-level
// member names (after unescaping, as encoding/json sees them) contain no case
// variant and no duplicate of an envelope member.
func checkEnvelopeMembers(raw []byte) error {
	if !json.Valid(raw) {
		return errEnvelope
	}
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return errEnvelope
	}
	i++
	seen := make(map[string]bool, len(envelopeMembers))
	for {
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return errEnvelope
		}
		if raw[i] == '}' {
			return nil
		}
		if raw[i] == ',' {
			i = skipSpace(raw, i+1)
		}
		end, ok := skipValue(raw, i)
		if !ok {
			return errEnvelope
		}
		var key string
		if err := json.Unmarshal(raw[i:end], &key); err != nil {
			return errEnvelope
		}
		if isCaseVariant(key, envelopeMembers...) {
			return errEnvelope
		}
		if slices.Contains(envelopeMembers, key) {
			if seen[key] {
				return errEnvelope
			}
			seen[key] = true
		}
		i = skipSpace(raw, end)
		if i >= len(raw) || raw[i] != ':' {
			return errEnvelope
		}
		end, ok = skipValue(raw, skipSpace(raw, i+1))
		if !ok {
			return errEnvelope
		}
		i = end
	}
}

// rawEnvelope is an Envelope whose payload text is still a slice of the
// received bytes, so a megabyte payload is not copied into a string.
type rawEnvelope struct {
	payload     []byte
	Signatures  []Signature
	Credentials *Credentials
}

func fastEnvelope(raw []byte) (rawEnvelope, bool) {
	var env rawEnvelope
	i := skipSpace(raw, 0)
	if i >= len(raw) || raw[i] != '{' {
		return env, false
	}
	i++
	seen := map[string]bool{}
	for first := true; ; first = false {
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return env, false
		}
		if raw[i] == '}' && first {
			return env, skipSpace(raw, i+1) == len(raw)
		}
		kb, next, ok := plainBytes(raw, i)
		key := string(kb)
		if !ok || seen[key] || isCaseVariant(key, "payload", "signatures", "credentials") {
			return env, false
		}
		seen[key] = true
		i = skipSpace(raw, next)
		if i >= len(raw) || raw[i] != ':' {
			return env, false
		}
		i = skipSpace(raw, i+1)
		if key == "payload" {
			v, next, ok := plainBytes(raw, i)
			if !ok {
				return env, false
			}
			env.payload, i = v, next
		} else {
			dec := json.NewDecoder(bytes.NewReader(raw[i:]))
			var err error
			switch key {
			case "signatures":
				err = dec.Decode(&env.Signatures)
			case "credentials":
				err = dec.Decode(&env.Credentials)
			default:
				var skip json.RawMessage
				err = dec.Decode(&skip)
			}
			if err != nil {
				return env, false
			}
			i += int(dec.InputOffset())
		}
		i = skipSpace(raw, i)
		if i >= len(raw) {
			return env, false
		}
		switch raw[i] {
		case ',':
			i++
		case '}':
			return env, skipSpace(raw, i+1) == len(raw)
		default:
			return env, false
		}
	}
}

func skipSpace(b []byte, i int) int {
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return i
}

// plainBytes reads the JSON string at b[i] when it has no escape sequence,
// returning its body and the index after the closing quote.
func plainBytes(b []byte, i int) ([]byte, int, bool) {
	if i >= len(b) || b[i] != '"' {
		return nil, 0, false
	}
	n := bytes.IndexByte(b[i+1:], '"')
	if n < 0 {
		return nil, 0, false
	}
	body := b[i+1 : i+1+n]
	if bytes.IndexByte(body, '\\') >= 0 {
		return nil, 0, false
	}
	for _, c := range body {
		if c < 0x20 || c >= 0x80 { // control characters are invalid in a JSON string; non-ASCII is left to encoding/json
			return nil, 0, false
		}
	}
	return body, i + n + 2, true
}
