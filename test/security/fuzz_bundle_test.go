package security

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
)

// FuzzBundleVerify feeds mutated valid envelopes to bundle.Verify and fails on
// any input that verifies without carrying, byte for byte, the payload a
// pinned key signed in a seed, and yielding exactly that seed's verified
// content. The unmodified seeds verify; so do a few benign re-encodings of the
// outer JSON (extra whitespace, a duplicate member whose last value is the
// signed one, an unknown member, a member name in another case), because
// Verify parses the envelope with encoding/json semantics and the signature
// covers the payload bytes, not the envelope's spelling (see parseEnvelope).
// What must never verify is anything else: trailing data, a byte-order mark,
// a duplicate that leaves a different payload last, a flipped byte, an
// envelope signed by an unpinned key, a swapped credential sidecar. The seeds run
// in a plain go test; a longer fuzz run is manual:
//
//	go test ./test/security -run '^$' -fuzz FuzzBundleVerify -fuzztime 60s
//
// The keys are generated at run time; nothing secret is committed, and a
// failure prints the input's length and a prefix of its hash, never its bytes.
func FuzzBundleVerify(f *testing.F) {
	sg := UnpinnedSigner(f)
	pub, err := keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
	if err != nil {
		f.Fatalf("public JWK: %v", err)
	}
	pins := []keys.JWK{pub}
	issued := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	now := issued.Add(time.Minute)
	b := bundle.Bundle{
		Seq: 7, PolicyVersion: 7, IssuedAt: issued, ExpiresAt: issued.Add(24 * time.Hour), CPID: "cp_fuzz",
		Policy:   json.RawMessage(`{"allowlist":[{"domain":"api.example.com"}]}`),
		Sections: map[string]json.RawMessage{"token_jwks": json.RawMessage(`{"keys":[]}`)},
	}
	valid := Sign(f, b, nil, sg)
	other := Sign(f, b, nil, UnpinnedSigner(f))
	withCreds := Sign(f, b, &bundle.Credentials{AccessKeyID: "AKIAFUZZ0000000001", SecretAccessKey: "fuzz-secret-value-000001"}, sg)

	var env bundle.Envelope
	if err := json.Unmarshal(valid, &env); err != nil {
		f.Fatalf("decode the seed: %v", err)
	}
	// What a success must equal: the verified content of each signed seed and
	// the payload text its signature covers.
	type content struct {
		seq      int64
		sha, kid string
		creds    bundle.Credentials
		payload  string
	}
	var accepted []content
	for _, raw := range [][]byte{valid, withCreds} {
		v, err := bundle.Verify(raw, pins, bundle.State{}, bundle.Options{Now: now, Skew: 5 * time.Minute})
		if err != nil {
			f.Fatalf("the signed seed does not verify: %v", err)
		}
		var e bundle.Envelope
		if err := json.Unmarshal(raw, &e); err != nil {
			f.Fatalf("decode a seed: %v", err)
		}
		c := content{seq: v.Seq, sha: v.ContentSHA256, kid: v.KID, payload: e.Payload}
		if v.Credentials != nil {
			c.creds = *v.Credentials
		}
		accepted = append(accepted, c)
	}

	seeds := [][]byte{
		valid, withCreds, other,
		nil, []byte(""), []byte("{}"), []byte("null"), []byte("[]"), []byte("{not json"),
		// Trailing data after the envelope.
		append(append([]byte(nil), valid...), []byte(" {}")...),
		append(append([]byte(nil), valid...), '\n', '\x00'),
		// A byte-order mark and a leading space.
		append([]byte("\xef\xbb\xbf"), valid...),
		append([]byte(" "), valid...),
		// Duplicate members: the second payload or signatures list must not
		// win over, or hide behind, the signed one.
		bytes.Replace(valid, []byte(`{"payload":`), []byte(`{"payload":"AA","payload":`), 1),
		bytes.Replace(valid, []byte(`"signatures":`), []byte(`"signatures":[],"signatures":`), 1),
		bytes.Replace(valid, []byte(`"signatures":[`), []byte(`"signatures":[{"kid":"x","sig":"AA"},`), 1),
		// A member name in another case.
		bytes.Replace(valid, []byte(`"payload"`), []byte(`"Payload"`), 1),
		bytes.Replace(valid, []byte(`"signatures"`), []byte(`"SIGNATURES"`), 1),
		// Truncation, a flipped byte, an unknown member.
		valid[:len(valid)-1], valid[:len(valid)/2],
		flipByte(valid, len(valid)/2), flipByte(valid, 20),
		bytes.Replace(valid, []byte(`{"payload"`), []byte(`{"extra":1,"payload"`), 1),
		// The payload alone, the signature alone, the sidecar swapped.
		[]byte(`{"payload":"` + env.Payload + `"}`),
		[]byte(`{"signatures":[{"kid":"` + env.Signatures[0].KID + `","sig":"` + env.Signatures[0].Sig + `"}]}`),
		bytes.Replace(withCreds, []byte("fuzz-secret-value-000001"), []byte("fuzz-secret-value-000002"), 1),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := bundle.Verify(raw, pins, bundle.State{}, bundle.Options{Now: now, Skew: 5 * time.Minute})
		if err != nil {
			return
		}
		var creds bundle.Credentials
		if v.Credentials != nil {
			creds = *v.Credentials
		}
		for _, ok := range accepted {
			if v.Seq == ok.seq && v.ContentSHA256 == ok.sha && v.KID == ok.kid && creds == ok.creds &&
				bytes.Contains(raw, []byte(`"`+ok.payload+`"`)) {
				return
			}
		}
		t.Errorf("an input that is not a re-encoding of a signed seed verified (%d bytes, digest %s)", len(raw), digestOf(raw))
	})
}

func flipByte(b []byte, i int) []byte {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}
