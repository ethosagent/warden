package agentreg

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/keys"
)

const (
	edX = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" // RFC 8037 appendix A.2
	ecX = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU" // RFC 7515 appendix A.3
	ecY = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
)

func edJWK(extra string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q%s}`, edX, extra))
}

func ecJWK(extra string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q%s}`, ecX, ecY, extra))
}

func agentWith(ks ...json.RawMessage) Agent {
	a := Agent{ID: "a1", AllowedGroups: []string{"eng"}}
	for _, k := range ks {
		a.Keys = append(a.Keys, Key{JWK: k})
	}
	return a
}

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	var ie *InvalidError
	if !errors.Is(err, ErrInvalid) || !errors.As(err, &ie) {
		t.Fatalf("err = %v, want an *InvalidError", err)
	}
	return ie.Field
}

// RFC 8037 A.3 and a P-256 vector (RFC 7515 A.3 key, thumbprint computed per
// RFC 7638 section 3) pin the jkt both planes must compute.
func TestValidate_ThumbprintVectors(t *testing.T) {
	got, err := Validate(agentWith(edJWK(""), ecJWK("")))
	if err != nil {
		t.Fatal(err)
	}
	if got.Keys[0].JKT != "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" {
		t.Errorf("ed25519 jkt = %s", got.Keys[0].JKT)
	}
	if got.Keys[1].JKT != "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U" {
		t.Errorf("p-256 jkt = %s", got.Keys[1].JKT)
	}
	if got.Keys[0].Alg != "EdDSA" || got.Keys[1].Alg != "ES256" {
		t.Errorf("algs = %s, %s", got.Keys[0].Alg, got.Keys[1].Alg)
	}
	if got.Keys[0].KID != got.Keys[0].JKT {
		t.Errorf("kid should default to the thumbprint, got %s", got.Keys[0].KID)
	}
	// The registry's jkt is exactly keys.Thumbprint.
	j, _ := got.Keys[1].PublicJWK()
	if tp, _ := keys.Thumbprint(j); tp != got.Keys[1].JKT {
		t.Errorf("registry jkt %s != keys.Thumbprint %s", got.Keys[1].JKT, tp)
	}
	if tps := Thumbprints(got); len(tps) != 2 || tps[0] > tps[1] {
		t.Errorf("Thumbprints not sorted: %v", tps)
	}
}

func TestValidate_KeyTable(t *testing.T) {
	long := json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":%q}`, edX, strings.Repeat("k", 2100)))
	offCurve := json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-256","x":%q,"y":%q}`, ecX, ecX))
	tests := []struct {
		name  string
		jwk   json.RawMessage
		field string
	}{
		{"private d", edJWK(`,"d":"AAAA"`), "keys[0].d"},
		{"private d null", edJWK(`,"d":null`), "keys[0].d"},
		{"private D mixed case", edJWK(`,"D":"AAAA"`), "keys[0].d"},
		{"oct with k", json.RawMessage(`{"kty":"oct","k":"AAAA"}`), "keys[0].k"},
		{"rsa members", json.RawMessage(`{"kty":"RSA","n":"AA","e":"AQ","p":"AA"}`), "keys[0].p"},
		{"rsa public", json.RawMessage(`{"kty":"RSA","n":"AA","e":"AQ"}`), "keys[0].kty"},
		{"oct", json.RawMessage(`{"kty":"oct"}`), "keys[0].kty"},
		{"dp", edJWK(`,"dp":"AA"`), "keys[0].dp"},
		{"dq", edJWK(`,"dq":"AA"`), "keys[0].dq"},
		{"qi", edJWK(`,"qi":"AA"`), "keys[0].qi"},
		{"q", edJWK(`,"q":"AA"`), "keys[0].q"},
		{"oth", edJWK(`,"oth":[]`), "keys[0].oth"},
		{"x5u", edJWK(`,"x5u":"https://x"`), "keys[0].x5u"},
		{"jku", edJWK(`,"jku":"https://x"`), "keys[0].jku"},
		{"x5c", edJWK(`,"x5c":["AA"]`), "keys[0].x5c"},
		{"wrong curve", json.RawMessage(fmt.Sprintf(`{"kty":"EC","crv":"P-384","x":%q,"y":%q}`, ecX, ecY)), "keys[0].crv"},
		{"okp with p-256", json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"P-256","x":%q}`, edX)), "keys[0].crv"},
		{"alg mismatch", edJWK(`,"alg":"ES256"`), "keys[0].alg"},
		{"alg RS256", ecJWK(`,"alg":"RS256"`), "keys[0].alg"},
		{"use enc", edJWK(`,"use":"enc"`), "keys[0].use"},
		{"key_ops sign", edJWK(`,"key_ops":["sign"]`), "keys[0].key_ops"},
		{"key_ops two", edJWK(`,"key_ops":["verify","sign"]`), "keys[0].key_ops"},
		{"kty not string", json.RawMessage(`{"kty":5}`), "keys[0].kty"},
		{"off curve", offCurve, "keys[0]"},
		{"short x", json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`), "keys[0]"},
		{"missing x", json.RawMessage(`{"kty":"OKP","crv":"Ed25519"}`), "keys[0]"},
		{"duplicate member", json.RawMessage(fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"x":%q}`, edX, edX)), "keys[0]"},
		{"over 2 KiB", long, "keys[0]"},
		{"not an object", json.RawMessage(`[1]`), "keys[0]"},
		{"null", json.RawMessage(`null`), "keys[0]"},
		{"empty", nil, "keys[0].jwk"},
		{"identity point", json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), "keys[0]"},
		{"all-zero x", json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`), "keys[0]"},
		{"non-canonical y=p", json.RawMessage(`{"kty":"OKP","crv":"Ed25519","x":"7f_______________________________________38"}`), "keys[0]"},
		{"upper-case D", edJWK(`,"D":"AAAA"`), "keys[0].d"},
		{"upper-case X5U", edJWK(`,"X5U":"https://x"`), "keys[0].x5u"},
		{"upper-case ALG mismatch", edJWK(`,"ALG":"ES256"`), "keys[0].alg"},
		{"upper-case USE", edJWK(`,"USE":"enc"`), "keys[0].use"},
		{"upper-case KEY_OPS", edJWK(`,"KEY_OPS":["sign"]`), "keys[0].key_ops"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(agentWith(tc.jwk))
			if got := fieldOf(t, err); got != tc.field {
				t.Fatalf("field = %q, want %q (%v)", got, tc.field, err)
			}
			if strings.Contains(err.Error(), edX) || strings.Contains(err.Error(), "AAAA") {
				t.Fatalf("error echoes a value: %v", err)
			}
		})
	}
}

func TestValidate_AcceptsUseAndKeyOps(t *testing.T) {
	got, err := Validate(agentWith(edJWK(`,"use":"sig","key_ops":["verify"],"alg":"EdDSA","kid":"mine"`)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Keys[0].KID != "mine" {
		t.Errorf("kid from the jwk member = %q", got.Keys[0].KID)
	}
	// The stored document is canonical: no foreign members survive.
	if strings.Contains(string(got.Keys[0].JWK), "key_ops") {
		t.Errorf("document not canonical: %s", got.Keys[0].JWK)
	}
	a := agentWith(edJWK(""))
	a.Keys[0].KID = "explicit"
	got, err = Validate(a)
	if err != nil || got.Keys[0].KID != "explicit" {
		t.Fatalf("explicit kid: %+v, %v", got.Keys, err)
	}
}

func TestValidate_KeyCountAndDuplicates(t *testing.T) {
	if _, err := Validate(agentWith()); fieldOf(t, err) != "keys" {
		t.Errorf("0 keys: %v", err)
	}
	three := agentWith(edJWK(""), ecJWK(""), edJWK(`,"kid":"z"`))
	if _, err := Validate(three); fieldOf(t, err) != "keys" {
		t.Errorf("3 keys: %v", err)
	}
	same := agentWith(edJWK(""), edJWK(`,"kid":"other"`))
	if _, err := Validate(same); fieldOf(t, err) != "keys[1]" {
		t.Errorf("same key twice: %v", err)
	}
	dupKID := agentWith(edJWK(`,"kid":"k"`), ecJWK(`,"kid":"k"`))
	if _, err := Validate(dupKID); fieldOf(t, err) != "keys[1].kid" {
		t.Errorf("duplicate kid: %v", err)
	}
	for _, kid := range []string{strings.Repeat("k", 129), "has space", "tab\t", "café"} {
		a := agentWith(edJWK(""))
		a.Keys[0].KID = kid
		if _, err := Validate(a); fieldOf(t, err) != "keys[0].kid" {
			t.Errorf("kid %q: %v", kid, err)
		}
	}
}

func TestValidate_Fields(t *testing.T) {
	ok := agentWith(edJWK(""))
	mod := func(f func(*Agent)) Agent { a := ok; a.Keys = append([]Key(nil), ok.Keys...); f(&a); return a }
	scopes33 := make([]string, 33)
	for i := range scopes33 {
		scopes33[i] = fmt.Sprintf("s%d", i)
	}
	tests := []struct {
		name  string
		agent Agent
		field string
	}{
		{"bad id", mod(func(a *Agent) { a.ID = "!identity-scoped" }), "id"},
		{"empty id", mod(func(a *Agent) { a.ID = "" }), "id"},
		{"bad status", mod(func(a *Agent) { a.Status = "paused" }), "status"},
		{"no groups when active", mod(func(a *Agent) { a.AllowedGroups = nil }), "allowed_groups"},
		{"blank group", mod(func(a *Agent) { a.AllowedGroups = []string{"eng", " "} }), "allowed_groups[1]"},
		{"long group", mod(func(a *Agent) { a.AllowedGroups = []string{strings.Repeat("g", 257)} }), "allowed_groups[0]"},
		{"too many groups", mod(func(a *Agent) { a.AllowedGroups = make([]string, 257) }), "allowed_groups"},
		{"zero-width in name", mod(func(a *Agent) { a.DisplayName = "a\u200bb" }), "display_name"},
		{"bidi override in name", mod(func(a *Agent) { a.DisplayName = "a\u202eb" }), "display_name"},
		{"format char in owner", mod(func(a *Agent) { a.OwnerSub = "s\ufeff" }), "owner_sub"},
		{"upper scope", mod(func(a *Agent) { a.AllowedScopes = []string{"ok", "Bad"} }), "allowed_scopes[1]"},
		{"space scope", mod(func(a *Agent) { a.AllowedScopes = []string{"a b"} }), "allowed_scopes[0]"},
		{"empty scope", mod(func(a *Agent) { a.AllowedScopes = []string{""} }), "allowed_scopes[0]"},
		{"long scope", mod(func(a *Agent) { a.AllowedScopes = []string{strings.Repeat("s", 65)} }), "allowed_scopes[0]"},
		{"33 scopes", mod(func(a *Agent) { a.AllowedScopes = scopes33 }), "allowed_scopes"},
		{"long name", mod(func(a *Agent) { a.DisplayName = strings.Repeat("é", 129) }), "display_name"},
		{"control in name", mod(func(a *Agent) { a.DisplayName = "a\x00b" }), "display_name"},
		{"newline in name", mod(func(a *Agent) { a.DisplayName = "a\nb" }), "display_name"},
		{"bad utf8 name", mod(func(a *Agent) { a.DisplayName = "a\xffb" }), "display_name"},
		{"long owner", mod(func(a *Agent) { a.OwnerEmail = strings.Repeat("e", 257) }), "owner_email"},
		{"control in owner", mod(func(a *Agent) { a.OwnerSub = "s\x07" }), "owner_sub"},
		{"control in iss", mod(func(a *Agent) { a.OwnerIss = "i\n" }), "owner_iss"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Validate(tc.agent)
			if got := fieldOf(t, err); got != tc.field {
				t.Fatalf("field = %q, want %q (%v)", got, tc.field, err)
			}
		})
	}
}

func TestValidate_NormalizesWithoutMutatingInput(t *testing.T) {
	in := agentWith(edJWK(""))
	in.AllowedGroups = []string{"ops", "eng", "ops"}
	in.AllowedScopes = []string{"b:x", "a.y", "b:x"}
	in.DisplayName = strings.Repeat("é", 128) // 128 runes, 256 bytes: allowed
	out, err := Validate(in)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out.AllowedGroups, []string{"eng", "ops"}) || !reflect.DeepEqual(out.AllowedScopes, []string{"a.y", "b:x"}) {
		t.Fatalf("out = %v / %v", out.AllowedGroups, out.AllowedScopes)
	}
	if out.Status != StatusActive {
		t.Errorf("status = %q", out.Status)
	}
	if !reflect.DeepEqual(in.AllowedGroups, []string{"ops", "eng", "ops"}) || in.Keys[0].JKT != "" {
		t.Errorf("input was modified: %+v", in)
	}
	dis := agentWith(edJWK(""))
	dis.Status = StatusDisabled
	if _, err := Validate(dis); err != nil {
		t.Errorf("a disabled agent may have no groups: %v", err)
	}
	if _, err := Validate(agentWith(edJWK(""))); err != nil {
		t.Fatal(err)
	}
	if got := Thumbprints(Agent{}); got != nil {
		t.Errorf("Thumbprints(empty) = %v", got)
	}
	if !StatusActive.Valid() || !StatusDisabled.Valid() || Status("x").Valid() {
		t.Error("Status.Valid")
	}
}

func TestKeyPublicJWK_BadDocument(t *testing.T) {
	if _, err := (Key{KID: "k", JWK: json.RawMessage(`{"kty":"oct"}`)}).PublicJWK(); err == nil {
		t.Fatal("want an error")
	}
}

func TestThumbprintPrefixOf(t *testing.T) {
	if got := ThumbprintPrefix("abcdefghijkl"); got != "abcdefgh" {
		t.Errorf("got %q", got)
	}
	if got := ThumbprintPrefix("abc"); got != "abc" {
		t.Errorf("got %q", got)
	}
}
