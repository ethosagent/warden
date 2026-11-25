package bundle_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
)

// TestVerifyPayloadShapes feeds Verify signed payloads whose JSON layout
// differs from what Sign writes: whitespace, member order, unknown members,
// escapes and nesting, which the structural decoder must read the same way
// encoding/json would.
func TestVerifyPayloadShapes(t *testing.T) {
	s, pin := newKey(t, keys.AlgEdDSA)
	good := mustSign(t, base(5), nil, s)
	pins := []keys.JWK{pin}

	edit := func(f func(b bundle.Bundle) string) []byte {
		return resign(t, good, s, func(p []byte) []byte {
			var b bundle.Bundle
			if err := json.Unmarshal(p, &b); err != nil {
				t.Fatal(err)
			}
			return []byte(f(b))
		})
	}

	// Escapes, nesting, unknown members and odd whitespace; the content hash
	// is that of the decoded bytes, so build the bundle through Sign first.
	b := base(5)
	b.Policy = json.RawMessage(`{"a":["x\"y\\", {"b": [1,2.5e3,true,null]}], "s": "}]\\\""}`)
	b.Sections = map[string]json.RawMessage{"x": json.RawMessage(`[{"k":"v\\"}]`)}
	raw := mustSign(t, b, nil, s)
	if _, err := bundle.Verify(raw, pins, bundle.State{}, opts()); err != nil {
		t.Fatalf("escapes and nesting: %v", err)
	}

	v0, err := bundle.Verify(good, pins, bundle.State{}, opts())
	if err != nil {
		t.Fatal(err)
	}
	layouts := map[string]func(b bundle.Bundle) string{
		"spaced and reordered with unknown members": func(b bundle.Bundle) string {
			return ` { "future": {"a":[1,"}"]}, "policy" : ` + string(b.Policy) + ` ,` +
				`"sections" : {"tokenJWKS":{"keys":[]}} , "cpID":"cp-1", "typ":"warden-bundle/v1", "seq": 5,` +
				`"policyVersion":3, "issuedAt":"` + b.IssuedAt.Format("2006-01-02T15:04:05Z") + `",` +
				`"expiresAt":"` + b.ExpiresAt.Format("2006-01-02T15:04:05Z") + `",` +
				`"contentSha256":"` + b.ContentSHA256 + `", "tail": 7 }`
		},
	}
	for name, f := range layouts {
		v, err := bundle.Verify(edit(f), pins, bundle.State{}, opts())
		if err != nil || v.ContentSHA256 != v0.ContentSHA256 || v.Seq != 5 {
			t.Fatalf("%s: %+v %v", name, v, err)
		}
	}

	malformed := map[string]string{
		"not an object":     `[1,2]`,
		"scalar":            `5`,
		"truncated":         `{"typ":"warden-bundle/v1"`,
		"seq not a number":  `{"typ":"warden-bundle/v1","seq":"x"}`,
		"time not a time":   `{"typ":"warden-bundle/v1","seq":1,"issuedAt":"nope"}`,
		"sections not obj":  `{"typ":"warden-bundle/v1","seq":1,"sections":[]}`,
		"missing colon":     `{"typ" "x"}`,
		"unterminated":      `{"typ":"warden-bundle/v1","policy":{"a":[}`,
		"trailing garbage":  `{"typ":"warden-bundle/v1"} x`,
		"bare scalar value": `{"typ":"warden-bundle/v1","seq":1,"cpID":}`,
	}
	if _, err := bundle.Verify(edit(func(bundle.Bundle) string { return `{}` }), pins, bundle.State{}, opts()); !errors.Is(err, bundle.ErrUnsupportedFormat) {
		t.Fatalf("empty object: got %v", err)
	}
	for name, p := range malformed {
		_, err := bundle.Verify(edit(func(bundle.Bundle) string { return p }), pins, bundle.State{}, opts())
		if !errors.Is(err, bundle.ErrMalformed) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}
