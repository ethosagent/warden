package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
)

var errPayload = errors.New("bundle: payload is not a valid bundle object")

// decodePayload decodes a signed payload into a Bundle. It is only called
// after the signature verified. The payload is validated with one scan
// (json.Valid); because it is then known to be well formed, the top-level
// members are cut out with a cheap structural skip instead of letting
// encoding/json scan the megabytes of policy a second time. Policy and the
// sections alias payload, which the caller owns. Member names are matched
// exactly (the signer writes them exactly); unknown members are ignored so
// later features can add fields.
func decodePayload(payload []byte) (Bundle, error) {
	var b Bundle
	if !json.Valid(payload) {
		return b, errPayload
	}
	i := skipSpace(payload, 0)
	if i >= len(payload) || payload[i] != '{' {
		return b, errPayload
	}
	i++
	for {
		i = skipSpace(payload, i)
		if i >= len(payload) {
			return b, errPayload
		}
		if payload[i] == '}' {
			return b, nil
		}
		if payload[i] == ',' {
			i = skipSpace(payload, i+1)
		}
		end, ok := skipValue(payload, i)
		if !ok {
			return b, errPayload
		}
		var key string
		if err := json.Unmarshal(payload[i:end], &key); err != nil {
			return b, errPayload
		}
		i = skipSpace(payload, end)
		if i >= len(payload) || payload[i] != ':' {
			return b, errPayload
		}
		i = skipSpace(payload, i+1)
		end, ok = skipValue(payload, i)
		if !ok {
			return b, errPayload
		}
		val := payload[i:end]
		if err := b.setMember(key, val); err != nil {
			return b, errPayload
		}
		i = end
	}
}

// memberNames are the top-level payload members decodePayload reads. A name
// that matches one only case-insensitively is rejected: encoding/json would
// accept it, but the signer never writes it, so it is not a bundle.
var memberNames = []string{"typ", "seq", "policyVersion", "issuedAt", "expiresAt", "cpID", "contentSha256", "policy", "credentialsSha256", "sections"}

func (b *Bundle) setMember(key string, val []byte) error {
	if isCaseVariant(key, memberNames...) {
		return errPayload
	}
	switch key {
	case "typ":
		return json.Unmarshal(val, &b.Typ)
	case "seq":
		return json.Unmarshal(val, &b.Seq)
	case "policyVersion":
		return json.Unmarshal(val, &b.PolicyVersion)
	case "issuedAt":
		return json.Unmarshal(val, &b.IssuedAt)
	case "expiresAt":
		return json.Unmarshal(val, &b.ExpiresAt)
	case "cpID":
		return json.Unmarshal(val, &b.CPID)
	case "contentSha256":
		return json.Unmarshal(val, &b.ContentSHA256)
	case "credentialsSha256":
		return json.Unmarshal(val, &b.CredentialsSHA256)
	case "policy":
		b.Policy = val
	case "sections":
		return json.Unmarshal(val, &b.Sections)
	}
	return nil
}

// skipValue returns the index just past the JSON value starting at b[i]. It
// assumes b is well-formed JSON (callers validated it) and only counts
// nesting, so it is a fraction of the cost of a validating scan. It reports
// false rather than reading out of range if that assumption is wrong.
func skipValue(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return 0, false
	}
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for i < len(b) {
			switch b[i] {
			case '"':
				end, ok := skipString(b, i)
				if !ok {
					return 0, false
				}
				i = end
				continue
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1, true
				}
			}
			i++
		}
		return 0, false
	}
	for i < len(b) {
		switch b[i] {
		case ',', '}', ']', ' ', '\t', '\n', '\r':
			return i, true
		}
		i++
	}
	return i, true
}

// skipString returns the index past the closing quote of the string at b[i].
func skipString(b []byte, i int) (int, bool) {
	j := i + 1
	for j < len(b) {
		n := bytes.IndexByte(b[j:], '"')
		if n < 0 {
			return 0, false
		}
		q := j + n
		slashes := 0
		for k := q - 1; k > i && b[k] == '\\'; k-- {
			slashes++
		}
		if slashes%2 == 0 {
			return q + 1, true
		}
		j = q + 1
	}
	return 0, false
}
