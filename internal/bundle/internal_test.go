package bundle

import (
	"encoding/json"
	"reflect"
	"testing"
)

// FuzzDecodePayload pins the structural decoder to encoding/json: whenever it
// accepts a payload, json.Unmarshal must accept it too and produce the same
// bundle, field by field, with Policy and Sections equal as bytes.
func FuzzDecodePayload(f *testing.F) {
	f.Add([]byte(`{"typ":"warden-bundle/v1","seq":5,"policyVersion":3,"issuedAt":"2026-06-01T12:00:00Z","expiresAt":"2026-06-02T12:00:00Z","cpID":"cp","contentSha256":"ab","policy":{"a":["x\"}"]},"credentialsSha256":"c","sections":{"k":[1,{"z":null}]}}`))
	f.Add([]byte(` { "policy" : [ ] , "x" : { "y" : "\\" } , "seq" : 1 } `))
	f.Add([]byte(`{"Seq":1}`))
	f.Add([]byte(`{"seq":1,"seq":2,"sections":{"a":1},"sections":{"b":2}}`))
	f.Fuzz(func(t *testing.T, p []byte) {
		got, err := decodePayload(p)
		if err != nil {
			return
		}
		var want Bundle
		if err := json.Unmarshal(p, &want); err != nil {
			t.Fatalf("decodePayload accepted what encoding/json rejects: %v", err)
		}
		if got.Typ != want.Typ || got.Seq != want.Seq || got.PolicyVersion != want.PolicyVersion ||
			!got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
			got.CPID != want.CPID || got.ContentSHA256 != want.ContentSHA256 ||
			got.CredentialsSHA256 != want.CredentialsSHA256 {
			t.Fatalf("scalar mismatch:\n got %+v\nwant %+v", got, want)
		}
		if string(got.Policy) != string(want.Policy) {
			t.Fatalf("policy %q != %q", got.Policy, want.Policy)
		}
		if len(got.Sections) != len(want.Sections) {
			t.Fatalf("sections %v != %v", got.Sections, want.Sections)
		}
		for k, v := range want.Sections {
			if g, ok := got.Sections[k]; !ok || string(g) != string(v) {
				t.Fatalf("section %q: %q != %q", k, g, v)
			}
		}
	})
}

// FuzzFastEnvelope pins the fast envelope path to encoding/json: whenever it
// reports ok, json.Unmarshal must agree on every member.
func FuzzFastEnvelope(f *testing.F) {
	f.Add([]byte(`{"payload":"e30","signatures":[{"kid":"k","sig":"AA"}],"credentials":{"accessKeyId":"a","secretAccessKey":"b"}}`))
	f.Add([]byte(` {"extra":[1,{"a":"}"}], "payload" : "abc" , "signatures":null} `))
	f.Add([]byte(`{"Payload":"abc"}`))
	f.Add([]byte(`{"payload":"a","payload":"b"}`))
	f.Add([]byte(`{"payload":"ab"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, ok := fastEnvelope(raw)
		if !ok {
			return
		}
		var want Envelope
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("fast path accepted what encoding/json rejects: %v", err)
		}
		if string(got.payload) != want.Payload ||
			!reflect.DeepEqual(got.Signatures, want.Signatures) ||
			!reflect.DeepEqual(got.Credentials, want.Credentials) {
			t.Fatalf("mismatch:\n got %+v\nwant %+v", got, want)
		}
	})
}
