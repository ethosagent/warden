package fakes

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"go/parser"
	"go/token"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func httpGet(c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := httpGet(&http.Client{Timeout: 5 * time.Second}, url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d", url, resp.StatusCode)
	}
	var m map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	return m
}

// decoded splits a minted token into header, claims and signature parts.
func decoded(t *testing.T, raw string) (hdr, claims map[string]any, in string, sig []byte) {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("minted token has %d segments, want 3", len(parts))
	}
	dec := func(s string, v any) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("segment not base64url: %v", err)
		}
		if v != nil {
			if err := json.Unmarshal(b, v); err != nil {
				t.Fatalf("segment not JSON: %v", err)
			}
		}
	}
	dec(parts[0], &hdr)
	dec(parts[1], &claims)
	sig, _ = base64.RawURLEncoding.DecodeString(parts[2])
	return hdr, claims, parts[0] + "." + parts[1], sig
}

// verifySig checks sig over in against the JWK published under kid.
func verifySig(t *testing.T, iss *OIDCIssuer, kid, in string, sig []byte) bool {
	t.Helper()
	keys, _ := getJSON(t, iss.JWKSURL())["keys"].([]any)
	sum := sha256.Sum256([]byte(in))
	for _, k := range keys {
		jwk := k.(map[string]any)
		if jwk["kid"] != kid {
			continue
		}
		num := func(f string) *big.Int {
			b, _ := base64.RawURLEncoding.DecodeString(jwk[f].(string))
			return new(big.Int).SetBytes(b)
		}
		switch jwk["kty"] {
		case "RSA":
			pub := &rsa.PublicKey{N: num("n"), E: int(num("e").Int64())}
			return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
		case "EC":
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: num("x"), Y: num("y")}
			return len(sig) == 64 && ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		}
	}
	t.Fatalf("no JWK with kid %q", kid)
	return false
}

func TestOIDCIssuerDiscoveryAndJWKS(t *testing.T) {
	iss := NewOIDCIssuer(t)
	disc := getJSON(t, iss.Issuer()+"/.well-known/openid-configuration")
	if disc["issuer"] != iss.Issuer() {
		t.Errorf("discovery issuer = %v, want %v", disc["issuer"], iss.Issuer())
	}
	if disc["jwks_uri"] != iss.JWKSURL() {
		t.Errorf("jwks_uri = %v, want %v", disc["jwks_uri"], iss.JWKSURL())
	}
	if algs, _ := disc["id_token_signing_alg_values_supported"].([]any); len(algs) != 2 {
		t.Errorf("signing algs = %v, want RS256 and ES256", algs)
	}
	keys := getJSON(t, iss.JWKSURL())["keys"].([]any)
	got := map[string]string{}
	for _, k := range keys {
		jwk := k.(map[string]any)
		got[jwk["kty"].(string)] = jwk["alg"].(string)
		if _, private := jwk["d"]; private {
			t.Error("JWKS leaks private key material")
		}
	}
	if got["RSA"] != "RS256" || got["EC"] != "ES256" || len(keys) != 2 {
		t.Errorf("JWKS = %v, want one RS256 and one ES256 key", got)
	}
}

func TestOIDCIssuerJWKSRequestCounter(t *testing.T) {
	iss := NewOIDCIssuer(t)
	if iss.JWKSRequests() != 0 {
		t.Fatalf("fresh counter = %d, want 0", iss.JWKSRequests())
	}
	for i := 1; i <= 3; i++ {
		getJSON(t, iss.JWKSURL())
		if iss.JWKSRequests() != i {
			t.Fatalf("after %d fetches counter = %d", i, iss.JWKSRequests())
		}
	}
	getJSON(t, iss.Issuer()+"/.well-known/openid-configuration")
	if iss.JWKSRequests() != 3 || iss.DiscoveryRequests() != 1 {
		t.Errorf("jwks=%d discovery=%d, want 3 and 1", iss.JWKSRequests(), iss.DiscoveryRequests())
	}
}

func TestOIDCIssuerMintDefaultsAndSignatures(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	iss := NewOIDCIssuer(t, WithIssuerClock(func() time.Time { return now }))
	for name, opt := range map[string]MintOption{"rs256": func(*mintSpec) {}, "es256": WithES256()} {
		hdr, claims, in, sig := decoded(t, iss.Mint(opt))
		if !verifySig(t, iss, hdr["kid"].(string), in, sig) {
			t.Errorf("%s: signature does not verify against the published JWK", name)
		}
		if claims["iss"] != iss.Issuer() || claims["aud"] != OIDCAudience || claims["azp"] != OIDCAZP {
			t.Errorf("%s: default iss/aud/azp wrong: %v %v %v", name, claims["iss"], claims["aud"], claims["azp"])
		}
		if claims["iat"] != float64(now.Unix()) || claims["exp"] != float64(now.Add(OIDCTokenTTL).Unix()) {
			t.Errorf("%s: iat/exp do not follow the issuer clock", name)
		}
	}
	if h, _, _, _ := decoded(t, iss.Mint(WithES256())); h["alg"] != "ES256" {
		t.Errorf("WithES256 alg = %v", h["alg"])
	}
}

func TestOIDCIssuerMintHonorsEveryOverride(t *testing.T) {
	iss := NewOIDCIssuer(t)
	at := time.Unix(1_700_000_000, 0)
	tok := iss.Mint(
		WithIss("https://other"), WithSub("s"), WithAud("a1", "a2"), WithAZP("z"),
		WithEmail("e@x"), WithEmailVerified(false), WithGroups("g1", "g2"), WithSID("sid-1"),
		WithExp(at.Add(time.Hour)), WithNBF(at), WithIAT(at), WithNonce("n1"),
		WithClaim("custom", 7), WithAlg("RS256"), WithKID("kid-x"), WithHeader("typ", "at+jwt"),
	)
	hdr, c, _, _ := decoded(t, tok)
	want := map[string]any{
		"iss": "https://other", "sub": "s", "azp": "z", "email": "e@x", "email_verified": false,
		"sid": "sid-1", "nonce": "n1", "custom": float64(7),
		"exp": float64(at.Add(time.Hour).Unix()), "nbf": float64(at.Unix()), "iat": float64(at.Unix()),
	}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if aud, _ := c["aud"].([]any); len(aud) != 2 {
		t.Errorf("aud = %v, want two entries", c["aud"])
	}
	if g, _ := c["groups"].([]any); len(g) != 2 {
		t.Errorf("groups = %v, want two entries", c["groups"])
	}
	if hdr["kid"] != "kid-x" || hdr["typ"] != "at+jwt" || hdr["alg"] != "RS256" {
		t.Errorf("header overrides not applied: %v", hdr)
	}
	_, c, _, _ = decoded(t, iss.Mint(WithoutClaim("exp", "aud")))
	if _, ok := c["exp"]; ok {
		t.Error("WithoutClaim(exp) left exp in the token")
	}
	if _, ok := c["aud"]; ok {
		t.Error("WithoutClaim(aud) left aud in the token")
	}
	hdr, _, _, _ = decoded(t, iss.Mint(WithAlg("none")))
	if hdr["alg"] != "none" {
		t.Errorf("alg = %v, want none", hdr["alg"])
	}
	if parts := strings.Split(iss.Mint(WithAlg("none")), "."); parts[2] != "" {
		t.Error("alg none must be unsigned")
	}
}

func TestOIDCIssuerConvenienceConstructors(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	iss := NewOIDCIssuer(t, WithIssuerClock(func() time.Time { return now }))

	_, c, _, _ := decoded(t, iss.Mint(Valid("u1", "u1@example.com", "eng", "ops")))
	if c["sub"] != "u1" || c["email"] != "u1@example.com" || c["email_verified"] != true {
		t.Errorf("Valid claims wrong: %v", c)
	}
	if g, _ := c["groups"].([]any); len(g) != 2 {
		t.Errorf("Valid groups = %v", c["groups"])
	}
	_, c, _, _ = decoded(t, iss.Mint(Valid("u2", "u2@example.com")))
	if _, ok := c["groups"]; ok {
		t.Error("Valid without groups must omit the claim")
	}
	_, c, _, _ = decoded(t, iss.Mint(Expired()))
	if exp := int64(c["exp"].(float64)); exp >= now.Add(-time.Minute*5).Unix() {
		t.Errorf("Expired exp %d is not well in the past", exp)
	}
	_, c, _, _ = decoded(t, iss.Mint(WrongAudience()))
	if c["aud"] == OIDCAudience {
		t.Error("WrongAudience kept the default audience")
	}
	_, c, _, _ = decoded(t, iss.Mint(WrongAZP()))
	if c["azp"] == OIDCAZP {
		t.Error("WrongAZP kept the default azp")
	}
	_, c, _, _ = decoded(t, iss.Mint(TooLong()))
	if ttl := int64(c["exp"].(float64)) - int64(c["iat"].(float64)); ttl <= 3600 {
		t.Errorf("TooLong lifetime = %ds, want over 3600", ttl)
	}
}

func TestOIDCIssuerRotateKeyPublishesSecondKID(t *testing.T) {
	iss := NewOIDCIssuer(t)
	before := iss.KIDs()
	hdr, _, in, sig := decoded(t, iss.Mint(RotateKey()))
	kid := hdr["kid"].(string)
	for _, k := range before {
		if k == kid {
			t.Fatalf("RotateKey reused existing kid %q", kid)
		}
	}
	if got := len(iss.KIDs()); got != len(before)+1 {
		t.Fatalf("published keys = %d, want %d", got, len(before)+1)
	}
	if !verifySig(t, iss, kid, in, sig) {
		t.Error("rotated token does not verify against the new JWK")
	}
	// The old key keeps verifying older tokens.
	h2, _, in2, sig2 := decoded(t, iss.Mint())
	if !verifySig(t, iss, h2["kid"].(string), in2, sig2) {
		t.Error("default key stopped verifying after rotation")
	}
}

func TestOIDCIssuerUnpublishedAndNamedKeys(t *testing.T) {
	iss := NewOIDCIssuer(t)
	hdr, _, _, _ := decoded(t, iss.Mint(WithUnpublishedKey()))
	for _, k := range iss.KIDs() {
		if k == hdr["kid"] {
			t.Error("WithUnpublishedKey published its key")
		}
	}
	es := iss.KIDs()[1]
	hdr, _, in, sig := decoded(t, iss.Mint(WithSigningKey(es)))
	if hdr["kid"] != es || hdr["alg"] != "ES256" || !verifySig(t, iss, es, in, sig) {
		t.Errorf("WithSigningKey(%s) header %v", es, hdr)
	}
}

func TestOIDCIssuerStopAndStart(t *testing.T) {
	iss := NewOIDCIssuer(t)
	url := iss.Issuer()
	getJSON(t, iss.JWKSURL())
	iss.Stop()
	iss.Stop() // idempotent
	client := &http.Client{Timeout: time.Second}
	if resp, err := httpGet(client, iss.JWKSURL()); err == nil {
		_ = resp.Body.Close()
		t.Fatal("JWKS still reachable after Stop")
	}
	before := iss.JWKSRequests()
	iss.Start()
	if iss.Issuer() != url {
		t.Errorf("issuer changed across restart: %s -> %s", url, iss.Issuer())
	}
	getJSON(t, iss.JWKSURL())
	if iss.JWKSRequests() != before+1 {
		t.Error("counter lost across restart")
	}
	// Keys survive: a token minted before Stop still verifies after Start.
	hdr, _, in, sig := decoded(t, iss.Mint())
	if !verifySig(t, iss, hdr["kid"].(string), in, sig) {
		t.Error("keys changed across restart")
	}
}

// The fake must not share code with the code under test. The package as a
// whole does import internal/identity (fakes.Verifier, #21), so the rule is
// scoped to this file, checked on its import list.
func TestOIDCIssuerFileImportsNeitherIdentityNorControlPlane(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "oidcissuer.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if strings.Contains(p, "internal/identity") || strings.Contains(p, "internal/controlplane") {
			t.Errorf("oidcissuer.go imports %s", p)
		}
		if first, _, _ := strings.Cut(p, "/"); strings.Contains(first, ".") {
			t.Errorf("oidcissuer.go imports non-stdlib %s", p)
		}
	}
}
