package oidc

import "testing"

func FuzzParseToken(f *testing.F) {
	f.Add("")
	f.Add("a.b.c")
	f.Add(b64([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + b64([]byte(`{"sub":"u","aud":["a"],"exp":1,"groups":["g"]}`)) + ".sig")
	f.Add(b64([]byte(`{"alg":"none","crit":["x"]}`)) + "." + b64([]byte(`{"exp":"x","aud":5}`)) + ".")
	f.Fuzz(func(t *testing.T, raw string) {
		_, _, _ = parseToken(raw, "groups")
	})
}
