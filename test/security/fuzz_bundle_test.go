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
// outer JSON (extra whitespace, an unknown member, an extra bad signature next
// to a good one). A case variant or a duplicate of a canonical member
// (payload, signatures, credentials) is NOT benign: the unsigned credentials
// sidecar is read from the envelope and reaches the bundle cache file, so a
// "Credentials" spelling or a second "credentials" member must be refused. The
// canonicalViolations seeds below must not verify; they fail until
// parseEnvelope refuses them (fix/bundle-envelope-canonical). Also never
// verifying: trailing data, a byte-order mark, a flipped byte, an envelope
// signed by an unpinned key, a swapped credential sidecar. The seeds run
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
		bytes.Replace(valid, []byte(`"signatures":[`), []byte(`"signatures":[{"kid":"x","sig":"AA"},`), 1),
		// Truncation, a flipped byte, an unknown member.
		valid[:len(valid)-1], valid[:len(valid)/2],
		flipByte(valid, len(valid)/2), flipByte(valid, 20),
		bytes.Replace(valid, []byte(`{"payload"`), []byte(`{"extra":1,"payload"`), 1),
		// The payload alone, the signature alone, the sidecar swapped.
		[]byte(`{"payload":"` + env.Payload + `"}`),
		[]byte(`{"signatures":[{"kid":"` + env.Signatures[0].KID + `","sig":"` + env.Signatures[0].Sig + `"}]}`),
		bytes.Replace(withCreds, []byte("fuzz-secret-value-000001"), []byte("fuzz-secret-value-000002"), 1),
	}
	// Case variants and duplicates of the canonical members: none may verify.
	canonicalViolations := [][]byte{
		bytes.Replace(valid, []byte(`{"payload":`), []byte(`{"payload":"AA","payload":`), 1),
		bytes.Replace(valid, []byte(`"signatures":`), []byte(`"signatures":[],"signatures":`), 1),
		bytes.Replace(valid, []byte(`"payload"`), []byte(`"Payload"`), 1),
		bytes.Replace(valid, []byte(`"signatures"`), []byte(`"SIGNATURES"`), 1),
		bytes.Replace(withCreds, []byte(`"credentials"`), []byte(`"Credentials"`), 1),
		bytes.Replace(withCreds, []byte(`"credentials":`), []byte(`"credentials":null,"credentials":`), 1),
	}
	forbidden := map[string]bool{}
	for _, raw := range canonicalViolations {
		if len(raw) == 0 {
			f.Fatal("a canonical-violation seed was not built")
		}
		forbidden[string(raw)] = true
		f.Add(raw)
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := bundle.Verify(raw, pins, bundle.State{}, bundle.Options{Now: now, Skew: 5 * time.Minute})
		if err != nil {
			return
		}
		if forbidden[string(raw)] {
			t.Errorf("a case variant or duplicate of a canonical envelope member verified (%d bytes, digest %s)", len(raw), digestOf(raw))
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
