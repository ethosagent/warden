package oidc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
)

func ctx2s(t testing.TB) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestOIDCVerifier(t *testing.T) {
	for _, mk := range []func(testing.TB, string) *signer{newRSASigner, newECSigner} {
		sg := mk(t, "k1")
		other := mk(t, "k2")
		t.Run(sg.alg, func(t *testing.T) {
			srv := newJWKSServer(t, "", sg)
			iss := srv.URL
			now := testNow
			tests := []struct {
				name       string
				token      func() string
				cfg        func(*Config)
				wantSt     identity.Status
				wantR      identity.Reason
				wantSub    bool
				wantNoJWKS bool
			}{
				{name: "valid", token: func() string { return sg.sign(baseClaims(iss, now)) }, wantSt: identity.StatusValid, wantSub: true},
				{name: "wrong iss", token: func() string { c := baseClaims(iss, now); c["iss"] = iss + "/x"; return sg.sign(c) }, wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongIss, wantSub: true},
				{name: "wrong aud", token: func() string { c := baseClaims(iss, now); c["aud"] = "other"; return sg.sign(c) }, wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAud, wantSub: true},
				{name: "aud array", token: func() string { c := baseClaims(iss, now); c["aud"] = []string{"x", "warden"}; return sg.sign(c) }, wantSt: identity.StatusValid, wantSub: true},
				{name: "audiences member", cfg: func(c *Config) { c.Audience = "a"; c.Audiences = []string{"warden"} }, token: func() string { return sg.sign(baseClaims(iss, now)) }, wantSt: identity.StatusValid, wantSub: true},
				{name: "wrong azp", cfg: func(c *Config) { c.AllowedAZP = []string{"cli"} }, token: func() string { c := baseClaims(iss, now); c["azp"] = "evil"; return sg.sign(c) }, wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAZP, wantSub: true},
				{name: "azp ok", cfg: func(c *Config) { c.AllowedAZP = []string{"cli"} }, token: func() string { return sg.sign(baseClaims(iss, now)) }, wantSt: identity.StatusValid, wantSub: true},
				{name: "azp absent two auds", cfg: func(c *Config) { c.AllowedAZP = []string{"cli"} }, token: func() string {
					c := baseClaims(iss, now)
					delete(c, "azp")
					c["aud"] = []string{"warden", "b"}
					return sg.sign(c)
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonWrongAZP, wantSub: true},
				{name: "azp absent one aud", cfg: func(c *Config) { c.AllowedAZP = []string{"cli"} }, token: func() string {
					c := baseClaims(iss, now)
					delete(c, "azp")
					return sg.sign(c)
				}, wantSt: identity.StatusValid, wantSub: true},
				{name: "expired 61s", token: func() string {
					c := baseClaims(iss, now)
					c["iat"] = now.Add(-time.Hour).Unix()
					c["exp"] = now.Add(-61 * time.Second).Unix()
					return sg.sign(c)
				}, wantSt: identity.StatusExpired, wantSub: true},
				{name: "expired 59s within skew", token: func() string {
					c := baseClaims(iss, now)
					c["iat"] = now.Add(-time.Hour).Unix()
					c["exp"] = now.Add(-59 * time.Second).Unix()
					return sg.sign(c)
				}, wantSt: identity.StatusValid, wantSub: true},
				{name: "nbf future", token: func() string {
					c := baseClaims(iss, now)
					c["nbf"] = now.Add(2 * time.Minute).Unix()
					return sg.sign(c)
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonMalformed},
				{name: "nbf within skew", token: func() string {
					c := baseClaims(iss, now)
					c["nbf"] = now.Add(30 * time.Second).Unix()
					return sg.sign(c)
				}, wantSt: identity.StatusValid, wantSub: true},
				{name: "alg none", token: func() string {
					return b64(mustJSON(map[string]any{"alg": "none"})) + "." + b64(mustJSON(baseClaims(iss, now))) + "."
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonAlgNotAllowed, wantSub: true, wantNoJWKS: true},
				{name: "hs256 with public key", token: func() string {
					return hs256(pubBytes(sg), map[string]any{"alg": "HS256", "kid": "k1"}, baseClaims(iss, now))
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonAlgNotAllowed, wantSub: true, wantNoJWKS: true},
				{name: "ttl too long", token: func() string {
					c := baseClaims(iss, now)
					c["exp"] = now.Add(time.Hour + time.Second).Unix()
					return sg.sign(c)
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonTTLTooLong, wantSub: true},
				{name: "too large", token: func() string { return strings.Repeat("a", 17<<10) }, wantSt: identity.StatusInvalid, wantR: identity.ReasonTooLarge, wantNoJWKS: true},
				{name: "crit header", token: func() string {
					return sg.signHeader(map[string]any{"alg": sg.alg, "kid": "k1", "crit": []string{"x"}, "x": 1}, baseClaims(iss, now))
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonMalformed, wantNoJWKS: true},
				{name: "garbage", token: func() string { return "not.a.jwt" }, wantSt: identity.StatusInvalid, wantR: identity.ReasonMalformed, wantNoJWKS: true},
				{name: "empty", token: func() string { return "" }, wantSt: identity.StatusInvalid, wantR: identity.ReasonMalformed, wantNoJWKS: true},
				{name: "unknown key", token: func() string { return other.sign(baseClaims(iss, now)) }, wantSt: identity.StatusInvalid, wantR: identity.ReasonUnknownKID, wantSub: true},
				{name: "bad signature", token: func() string {
					forged := mk(t, "k1")
					return forged.sign(baseClaims(iss, now))
				}, wantSt: identity.StatusInvalid, wantR: identity.ReasonBadSignature, wantSub: true},
			}
			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					srv.hits.Store(0)
					v := newTestVerifier(t, srv, &clock{t: now}, tc.cfg)
					tok := tc.token()
					c, st, r := v.Verify(ctx2s(t), tok)
					if st != tc.wantSt || r != tc.wantR {
						t.Fatalf("got %s/%q want %s/%q", st, r, tc.wantSt, tc.wantR)
					}
					if tc.wantSub != (c.Sub == "suite-user") {
						t.Errorf("sub = %q, wantSub=%v", c.Sub, tc.wantSub)
					}
					if tc.wantNoJWKS && srv.hits.Load() != 0 {
						t.Errorf("jwks hits = %d, want 0", srv.hits.Load())
					}
					if st != identity.StatusValid && identity.SubjectFrom(c, st) != nil {
						t.Error("subject for non-valid")
					}
				})
			}
		})
	}
}

func pubBytes(s *signer) []byte {
	if s.rsa != nil {
		return s.rsa.N.Bytes()
	}
	return s.ec.X.Bytes()
}

func TestEmail(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	tests := []struct {
		name      string
		mod       func(map[string]any)
		wantEmail string
		wantVer   bool
	}{
		{"verified lowercased", func(map[string]any) {}, "suite.user@example.com", true},
		{"false drops", func(c map[string]any) { c["email_verified"] = false }, "", false},
		{"string false drops", func(c map[string]any) { c["email_verified"] = "false" }, "", false},
		{"absent keeps", func(c map[string]any) { delete(c, "email_verified") }, "suite.user@example.com", false},
		{"string true not verified", func(c map[string]any) { c["email_verified"] = "true" }, "suite.user@example.com", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClaims(srv.URL, testNow)
			tc.mod(c)
			v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
			got, st, _ := v.Verify(ctx2s(t), sg.sign(c))
			if st != identity.StatusValid || got.Email != tc.wantEmail || got.EmailVerified != tc.wantVer {
				t.Errorf("st=%s email=%q verified=%v", st, got.Email, got.EmailVerified)
			}
		})
	}
}

func TestGroups(t *testing.T) {
	sg := newECSigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	many := make([]string, 100)
	for i := range many {
		many[i] = fmt.Sprintf("g%03d", i)
	}
	tests := []struct {
		name      string
		claim     string
		groups    any
		wantLen   int
		wantTrunc bool
	}{
		{"dn", "groups", []string{"cn=eng,ou=groups,dc=corp"}, 1, false},
		{"100", "groups", many, 64, true},
		{"long", "groups", []string{"a", "b", "c", strings.Repeat("x", 300)}, 3, true},
		{"normal", "groups", []string{"a", "b", "c"}, 3, false},
		{"absent", "groups", nil, 0, false},
		{"custom claim", "roles", []string{"r1"}, 1, false},
		{"single string", "groups", "solo", 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := baseClaims(srv.URL, testNow)
			if tc.groups != nil {
				c[tc.claim] = tc.groups
			}
			v := newTestVerifier(t, srv, &clock{t: testNow}, func(cf *Config) {
				if tc.claim != "groups" {
					cf.GroupsClaim = tc.claim
				}
			})
			got, st, _ := v.Verify(ctx2s(t), sg.sign(c))
			if st != identity.StatusValid || len(got.Groups) != tc.wantLen || got.GroupsTruncated != tc.wantTrunc {
				t.Fatalf("st=%s len=%d trunc=%v", st, len(got.Groups), got.GroupsTruncated)
			}
			if s := identity.SubjectFrom(got, st); s.GroupsTruncated != tc.wantTrunc {
				t.Error("subject truncated flag not copied")
			}
		})
	}
}

func TestUnverifiedClaims(t *testing.T) {
	sg := newRSASigner(t, "k1")
	other := newRSASigner(t, "zz")
	srv := newJWKSServer(t, "", sg)
	v := newTestVerifier(t, srv, &clock{t: testNow}, nil)

	c := baseClaims(srv.URL, testNow)
	c["iat"] = testNow.Add(-time.Hour).Unix()
	c["exp"] = testNow.Add(-10 * time.Minute).Unix()
	got, st, _ := v.Verify(ctx2s(t), sg.sign(c))
	if st != identity.StatusExpired || got.Sub != "suite-user" || identity.SubjectFrom(got, st) != nil {
		t.Errorf("expired: %s %+v", st, got)
	}
	got, st, r := v.Verify(ctx2s(t), other.sign(baseClaims(srv.URL, testNow)))
	if st != identity.StatusInvalid || r != identity.ReasonUnknownKID || got.Sub != "suite-user" || got.Email == "" || identity.SubjectFrom(got, st) != nil {
		t.Errorf("unknown key: %s/%s %+v", st, r, got)
	}
}

func TestOIDCVerifierHTTPIssuerRule(t *testing.T) {
	_, err := NewOIDCVerifier(Config{Issuer: "http://idp.local/x", Audience: "warden"})
	if err == nil || !strings.Contains(err.Error(), "internalIssuerURL") {
		t.Fatalf("err = %v", err)
	}
	if _, err := NewOIDCVerifier(Config{Issuer: "http://idp.local/x", Audience: "warden", InternalIssuerURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatalf("internal set should be accepted: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	base := Config{Issuer: "https://idp.example.com", Audience: "w"}
	bad := map[string]func(*Config){
		"no audience":   func(c *Config) { c.Audience = "" },
		"neg skew":      func(c *Config) { c.ClockSkew = -1 },
		"big skew":      func(c *Config) { c.ClockSkew = 6 * time.Minute },
		"neg ttl":       func(c *Config) { c.MaxTokenTTL = -1 },
		"relative jwks": func(c *Config) { c.JWKSURL = "/keys" },
	}
	for name, mod := range bad {
		c := base
		mod(&c)
		if _, err := NewOIDCVerifier(c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	v, err := NewOIDCVerifier(base)
	if err != nil {
		t.Fatal(err)
	}
	if s := v.(interface{ ClockSkew() time.Duration }).ClockSkew(); s != 60*time.Second {
		t.Errorf("default skew = %v", s)
	}
	c := base
	c.ClockSkew = 90 * time.Second
	v, _ = NewOIDCVerifier(c)
	if s := v.(interface{ ClockSkew() time.Duration }).ClockSkew(); s != 90*time.Second {
		t.Errorf("skew = %v", s)
	}
}

func TestOIDCVerifierInternalOrigin(t *testing.T) {
	sg := newECSigner(t, "k1")
	srv := newJWKSServer(t, "/dex", sg)
	pub := "http://localhost:5556/dex"
	srv.issuerF = func() string { return pub }
	v, err := NewOIDCVerifier(Config{Issuer: pub, Audience: "warden", InternalIssuerURL: srv.URL, Now: (&clock{t: testNow}).now})
	if err != nil {
		t.Fatal(err)
	}
	c, st, r := v.Verify(ctx2s(t), sg.sign(baseClaims(pub, testNow)))
	if st != identity.StatusValid {
		t.Fatalf("st=%s r=%s", st, r)
	}
	if c.Issuer != pub || srv.disc.Load() != 1 || srv.hits.Load() != 1 {
		t.Errorf("issuer=%q disc=%d jwks=%d", c.Issuer, srv.disc.Load(), srv.hits.Load())
	}
}

func TestWithNonce(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
	cl := baseClaims(srv.URL, testNow)
	cl["nonce"] = "n1"
	tok := sg.sign(cl)
	if _, st, _ := v.Verify(ctx2s(t), tok, identity.WithNonce("n1")); st != identity.StatusValid {
		t.Errorf("match: %s", st)
	}
	if _, st, r := v.Verify(ctx2s(t), tok, identity.WithNonce("n2")); st != identity.StatusInvalid || r != identity.ReasonWrongNonce {
		t.Errorf("mismatch: %s/%s", st, r)
	}
	// A nonce-checked success must not have populated the cache, or a later
	// call with the wrong nonce would be skipped... and one without would hit.
	if _, st, r := v.Verify(ctx2s(t), tok, identity.WithNonce("n2")); st != identity.StatusInvalid || r != identity.ReasonWrongNonce {
		t.Errorf("mismatch after success: %s/%s", st, r)
	}
}

func TestCacheHit(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	clk := &clock{t: testNow}
	v := newTestVerifier(t, srv, clk, nil)
	tok := sg.sign(baseClaims(srv.URL, testNow))
	if _, st, _ := v.Verify(ctx2s(t), tok); st != identity.StatusValid {
		t.Fatal(st)
	}
	n := srv.hits.Load()
	if _, st, _ := v.Verify(ctx2s(t), tok); st != identity.StatusValid || srv.hits.Load() != n {
		t.Errorf("second verify: %s hits %d -> %d", st, n, srv.hits.Load())
	}
	clk.advance(10*time.Minute + 61*time.Second)
	if _, st, _ := v.Verify(ctx2s(t), tok); st != identity.StatusExpired {
		t.Errorf("after exp+skew: %s", st)
	}
}

func TestNoTokenInErrors(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
	toks := []string{
		sg.sign(baseClaims(srv.URL, testNow)),
		newRSASigner(t, "k1").sign(baseClaims(srv.URL, testNow)),
		strings.Repeat("s3cr3t", 4000),
		"abc.def.ghi",
	}
	for _, tok := range toks {
		c, st, r := v.Verify(ctx2s(t), tok)
		if out := fmt.Sprintf("%+v|%s|%s", c, st, r); strings.Contains(out, tok) {
			t.Error("token in verifier output")
		}
	}
	for _, cfg := range []Config{
		{Issuer: "http://user:s3cr3tpw@idp.local/x", Audience: "a"},
		{Issuer: "https://idp.example.com", Audience: "a", JWKSURL: "ftp://user:s3cr3tpw@h/k"},
	} {
		if _, err := NewOIDCVerifier(cfg); err == nil || strings.Contains(err.Error(), "s3cr3tpw") {
			t.Errorf("err = %v", err)
		}
	}
}

// TestOneHTTPClient proves the verifier builds no second client: composite
// http.Client literals appear only in httpclient.go.
func TestOneHTTPClient(t *testing.T) {
	fset := token.NewFileSet()
	matches, _ := filepath.Glob("*.go")
	for _, f := range matches {
		if f == "httpclient.go" || strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if cl, ok := n.(*ast.CompositeLit); ok {
				if se, ok := cl.Type.(*ast.SelectorExpr); ok && se.Sel.Name == "Client" {
					if id, ok := se.X.(*ast.Ident); ok && id.Name == "http" {
						t.Errorf("%s builds an http.Client", f)
					}
				}
			}
			return true
		})
	}
}

func TestCacheState(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	clk := &clock{t: testNow}
	iv := newTestVerifier(t, srv, clk, nil)
	v := iv.(*verifier)
	tok := sg.sign(baseClaims(srv.URL, testNow))
	if _, st, _ := v.Verify(ctx2s(t), tok); st != identity.StatusValid {
		t.Fatal(st)
	}
	if n := len(v.cache.m); n != 1 {
		t.Fatalf("cache entries after valid verify = %d, want 1", n)
	}
	for _, el := range v.cache.m {
		want := testNow.Add(cacheTTL)
		if got := el.Value.(*cacheEntry).until; !got.Equal(want) {
			t.Errorf("until = %v, want now+5m %v", got, want)
		}
	}
	clk.advance(cacheTTL + time.Second)
	if _, st, _ := v.Verify(ctx2s(t), tok); st != identity.StatusValid {
		t.Fatalf("re-verify after cache ttl: %s", st)
	}
	// An exp earlier than now+5m bounds the entry.
	cl := baseClaims(srv.URL, clk.now())
	cl["exp"] = clk.now().Add(time.Minute).Unix()
	short := sg.sign(cl)
	if _, st, _ := v.Verify(ctx2s(t), short); st != identity.StatusValid {
		t.Fatal(st)
	}
	k := sha256.Sum256([]byte(short))
	if got := v.cache.m[k].Value.(*cacheEntry).until; !got.Equal(clk.now().Add(time.Minute)) {
		t.Errorf("until = %v, want exp", got)
	}
	// Nonce verifies are never cached.
	nc := baseClaims(srv.URL, clk.now())
	nc["nonce"] = "n1"
	ntok := sg.sign(nc)
	before := len(v.cache.m)
	if _, st, _ := v.Verify(ctx2s(t), ntok, identity.WithNonce("n1")); st != identity.StatusValid {
		t.Fatal(st)
	}
	if len(v.cache.m) != before {
		t.Error("nonce verify was cached")
	}
}

func TestEmptyNonceFailsClosed(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
	tok := sg.sign(baseClaims(srv.URL, testNow))
	if _, st, r := v.Verify(ctx2s(t), tok, identity.WithNonce("")); st != identity.StatusInvalid || r != identity.ReasonWrongNonce {
		t.Errorf("empty nonce: %s/%s, want invalid/wrong_nonce", st, r)
	}
}

func TestSingleFlightJoin(t *testing.T) {
	sg := newRSASigner(t, "k1")
	srv := newJWKSServer(t, "", sg)
	srv.gate = make(chan struct{})
	v := newTestVerifier(t, srv, &clock{t: testNow}, nil)
	tok := sg.sign(baseClaims(srv.URL, testNow))
	const n = 20
	var wg sync.WaitGroup
	sts := make([]identity.Status, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, sts[i], _ = v.Verify(ctx2s(t), tok)
		}()
	}
	deadline := time.Now().Add(2 * time.Second)
	for srv.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // let the other callers reach the join
	close(srv.gate)
	wg.Wait()
	for i, st := range sts {
		if st != identity.StatusValid {
			t.Errorf("caller %d: %s, want valid", i, st)
		}
	}
	if h := srv.hits.Load(); h != 1 {
		t.Errorf("jwks hits = %d, want 1", h)
	}
}
