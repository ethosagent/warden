package keys

import (
	"encoding/base64"
	"strings"
	"testing"
)

// FuzzParseCompact feeds arbitrary strings to ParseCompact. It must never
// panic, and anything it accepts must be reproducible: the signing input is
// the first two segments of the input and the algorithm is one of the two
// allowed.
func FuzzParseCompact(f *testing.F) {
	enc := base64.RawURLEncoding.EncodeToString
	ok := enc([]byte(`{"alg":"EdDSA","kid":"k"}`)) + "." + enc([]byte(`{"a":1}`)) + "." + enc([]byte("sig"))
	for _, s := range []string{
		ok, "", "..", "a.b", "a.b.c.d",
		enc([]byte(`{"alg":"none"}`)) + ".e30.AA",
		enc([]byte(`{"alg":"EdDSA","jwk":{}}`)) + ".e30.AA",
		enc([]byte(`{"alg":"EdDSA","alg":"ES256"}`)) + ".e30.AA",
		enc([]byte(`{"ALG":"EdDSA"}`)) + ".e30.AA",
		ok + "=", "e30=.e30.AA",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		h, payload, input, sig, err := ParseCompact(raw)
		if err != nil {
			return
		}
		if h.Alg != AlgEdDSA && h.Alg != AlgES256 {
			t.Fatalf("accepted alg %q", h.Alg)
		}
		i := strings.LastIndexByte(raw, '.')
		if string(input) != raw[:i] {
			t.Fatalf("signing input is not the first two segments")
		}
		if len(payload) == 0 || len(sig) == 0 {
			t.Fatalf("accepted an empty payload or signature")
		}
	})
}
