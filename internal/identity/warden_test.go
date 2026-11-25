package identity_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

const (
	testIssuer = "https://cp.example.com"
	testJKT    = "tp-agent-a-key-1-0123456789012345678901234"
)

var wardenNow = time.Unix(1_800_000_000, 0)

func newSigner(t testing.TB, alg string) *signer.LocalSigner {
	t.Helper()
	s, err := signer.GenerateLocal(alg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jwkOf(t testing.TB, s keys.Signer) keys.JWK {
	t.Helper()
	j, err := keys.PublicJWK(s.Public(), s.Alg())
	if err != nil {
		t.Fatal(err)
	}
	j.Kid = s.KID()
	return j
}

// goodClaims is a token the control plane would mint, valid at wardenNow.
func goodClaims() map[string]any {
	now := wardenNow.Unix()
	return map[string]any{
		"ver": 1, "iss": testIssuer, "aud": identity.WardenAudience, "sub": "user-1",
		"idp_iss": "https://idp.example.com", "email": "u@example.com", "email_verified": true,
		"groups": []string{"eng"}, "act": map[string]string{"sub": "agent-a"},
		"sid": "wts_1", "jti": "j1", "iat": now, "nbf": now, "exp": now + 300,
		"cnf": map[string]string{"jkt": testJKT},
	}
}

func mint(t testing.TB, s keys.Signer, hdr keys.Header, claims map[string]any) string {
	t.Helper()
	if hdr.Alg == "" {
		hdr.Alg = s.Alg()
	}
	if hdr.Kid == "" {
		hdr.Kid = s.KID()
	}
	tok, err := keys.SignCompact(context.Background(), s, hdr, claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// mintNoKID signs a Warden token whose header has no kid.
func mintNoKID(t testing.TB, s keys.Signer, claims map[string]any) string {
	t.Helper()
	seg := func(x any) string {
		b, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	in := seg(map[string]string{"alg": s.Alg(), "typ": identity.WardenTokenTyp}) + "." + seg(claims)
	sig, err := s.Sign(context.Background(), []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func wardenHdr() keys.Header { return keys.Header{Typ: identity.WardenTokenTyp} }

func newWarden(t testing.TB, logger *slog.Logger) *identity.WardenVerifier {
	t.Helper()
	v, err := identity.NewWardenVerifier(identity.WardenConfig{Now: func() time.Time { return wardenNow }, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func install(t testing.TB, v *identity.WardenVerifier, gen int64, iss string, agents map[string]identity.WardenAgent, signers ...keys.Signer) {
	t.Helper()
	var jwks []keys.JWK
	for _, s := range signers {
		jwks = append(jwks, jwkOf(t, s))
	}
	snap, err := identity.NewWardenSnapshot(identity.WardenBundle{Generation: gen, TokenIssuer: iss, JWKS: jwks, Agents: agents})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.SetSnapshot(snap); err != nil {
		t.Fatal(err)
	}
}

func TestWardenVerifier(t *testing.T) {
	k1, k2 := newSigner(t, keys.AlgEdDSA), newSigner(t, keys.AlgEdDSA)
	es := newSigner(t, keys.AlgES256)
	v := newWarden(t, nil)
	install(t, v, 1, testIssuer, nil, k1, es)

	with := func(mod func(map[string]any)) map[string]any {
		c := goodClaims()
		mod(c)
		return c
	}
	now := wardenNow.Unix()
	tests := []struct {
		name   string
		tok    string
		status identity.Status
		reason identity.Reason
	}{
		{"valid EdDSA", mint(t, k1, wardenHdr(), goodClaims()), identity.StatusValid, ""},
		{"valid ES256", mint(t, es, wardenHdr(), goodClaims()), identity.StatusValid, ""},
		{"valid with aud list", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["aud"] = []string{"x", identity.WardenAudience} })), identity.StatusValid, ""},
		{"key not in the bundle", mint(t, k2, wardenHdr(), goodClaims()), identity.StatusInvalid, identity.ReasonUnknownKID},
		{"no kid", mintNoKID(t, k1, goodClaims()), identity.StatusInvalid, identity.ReasonUnknownKID},
		{"wrong typ", mint(t, k1, keys.Header{Typ: "JWT"}, goodClaims()), identity.StatusInvalid, identity.ReasonMalformed},
		{"wrong issuer", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["iss"] = testIssuer + "/" })), identity.StatusInvalid, identity.ReasonWrongIss},
		{"idp audience", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["aud"] = "warden" })), identity.StatusInvalid, identity.ReasonWrongAud},
		{"ttl 20m", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["exp"] = now + 20*60 })), identity.StatusInvalid, identity.ReasonTTLTooLong},
		{"ttl 15m ok", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["exp"] = now + 15*60 })), identity.StatusValid, ""},
		{"missing cnf", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "cnf") })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"empty cnf.jkt", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["cnf"] = map[string]string{"jkt": ""} })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"missing sub", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "sub") })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"missing act", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "act") })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"missing sid", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "sid") })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"missing jti", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "jti") })), identity.StatusInvalid, identity.ReasonMissingClaim},
		{"missing exp", mint(t, k1, wardenHdr(), with(func(c map[string]any) { delete(c, "exp") })), identity.StatusInvalid, identity.ReasonMalformed},
		{"wrong ver", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["ver"] = 2 })), identity.StatusInvalid, identity.ReasonMalformed},
		{"expired", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now-600, now-600, now-120 })), identity.StatusExpired, ""},
		{"expired within skew", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["iat"], c["nbf"], c["exp"] = now-600, now-600, now-30 })), identity.StatusValid, ""},
		{"not yet valid", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["nbf"] = now + 300 })), identity.StatusInvalid, identity.ReasonMalformed},
		{"not yet valid within skew", mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["nbf"] = now + 30 })), identity.StatusValid, ""},
		{"empty token", "", identity.StatusInvalid, identity.ReasonMalformed},
		{"not a jwt", "abc", identity.StatusInvalid, identity.ReasonMalformed},
		{"too large", strings.Repeat("a", identity.MaxTokenBytes+1), identity.StatusInvalid, identity.ReasonTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, st, r := v.Verify(context.Background(), tc.tok)
			if st != tc.status || r != tc.reason {
				t.Fatalf("got %s/%s, want %s/%s", st, r, tc.status, tc.reason)
			}
			if c.TokenType != identity.TokenWarden {
				t.Errorf("TokenType = %q, want warden", c.TokenType)
			}
		})
	}

	t.Run("claims of a valid token", func(t *testing.T) {
		c, st, _ := v.Verify(context.Background(), mint(t, k1, wardenHdr(), goodClaims()))
		if st != identity.StatusValid {
			t.Fatal(st)
		}
		if c.Sub != "user-1" || c.Act != "agent-a" || c.CnfJKT != testJKT || c.SID != "wts_1" || c.KID != k1.KID() ||
			c.Email != "u@example.com" || !c.EmailVerified || c.Issuer != testIssuer || c.TokenType != identity.TokenWarden {
			t.Fatalf("claims = %+v", c)
		}
		s := identity.SubjectFrom(c, st)
		if s == nil || s.AgentID != "agent-a" || s.Email != "u@example.com" || !s.EmailVerified || s.Sub != "user-1" {
			t.Fatalf("subject = %+v", s)
		}
	})
	t.Run("post-signature failures keep the authentic sub for the block list", func(t *testing.T) {
		c, st, r := v.Verify(context.Background(), mint(t, k1, wardenHdr(), with(func(c map[string]any) { c["aud"] = "warden" })))
		if st != identity.StatusInvalid || r != identity.ReasonWrongAud || c.Sub != "user-1" || c.Email != "u@example.com" {
			t.Fatalf("got %+v %s/%s", c, st, r)
		}
		if identity.SubjectFrom(c, st) != nil {
			t.Fatal("an invalid token yielded a subject")
		}
	})
	t.Run("a nonce never matches", func(t *testing.T) {
		_, st, r := v.Verify(context.Background(), mint(t, k1, wardenHdr(), goodClaims()), identity.WithNonce("n"))
		if st != identity.StatusInvalid || r != identity.ReasonWrongNonce {
			t.Fatalf("got %s/%s", st, r)
		}
	})
}

// TestWardenAlgConfusion: none, HMAC and RSA never reach a key, and a header
// alg that does not fit the key is refused.
func TestWardenAlgConfusion(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, nil)
	install(t, v, 1, testIssuer, nil, k1)
	seg := func(x any) string {
		b, _ := json.Marshal(x)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	claims := seg(goodClaims())
	pub := jwkOf(t, k1)
	for _, alg := range []string{"none", "HS256", "HS512", "RS256", "PS256", "ES384"} {
		tok := seg(map[string]string{"alg": alg, "typ": identity.WardenTokenTyp, "kid": k1.KID()}) + "." + claims + "." + base64.RawURLEncoding.EncodeToString([]byte(pub.X))
		if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusInvalid || r != identity.ReasonAlgNotAllowed {
			t.Errorf("alg %s: %s/%s, want invalid/alg_not_allowed", alg, st, r)
		}
	}
	// ES256 header over an Ed25519 key.
	tok := seg(map[string]string{"alg": "ES256", "typ": identity.WardenTokenTyp, "kid": k1.KID()}) + "." + claims + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusInvalid || r != identity.ReasonAlgNotAllowed {
		t.Errorf("ES256 over an OKP key: %s/%s", st, r)
	}
	// A tampered payload fails its signature.
	good := mint(t, k1, wardenHdr(), goodClaims())
	parts := strings.Split(good, ".")
	forged := goodClaims()
	forged["sub"] = "admin"
	tampered := parts[0] + "." + seg(forged) + "." + parts[2]
	if _, st, r := v.Verify(context.Background(), tampered); st != identity.StatusInvalid || r != identity.ReasonBadSignature {
		t.Errorf("tampered payload: %s/%s", st, r)
	}
}

func TestWardenUnavailable(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	tok := mint(t, k1, wardenHdr(), goodClaims())
	t.Run("before the first snapshot", func(t *testing.T) {
		v := newWarden(t, nil)
		if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
			t.Fatalf("got %s/%s", st, r)
		}
	})
	t.Run("an empty issuer means the CP mints no tokens", func(t *testing.T) {
		v := newWarden(t, nil)
		install(t, v, 1, "", nil, k1)
		if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
			t.Fatalf("got %s/%s", st, r)
		}
	})
	t.Run("no keys", func(t *testing.T) {
		v := newWarden(t, nil)
		install(t, v, 1, testIssuer, nil)
		if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
			t.Fatalf("got %s/%s", st, r)
		}
	})
}

func TestWardenSnapshotValidation(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	j := jwkOf(t, k1)
	for name, jwks := range map[string][]keys.JWK{
		"no kid":        {{Kty: j.Kty, Crv: j.Crv, X: j.X}},
		"duplicate kid": {j, j},
		"bad key":       {{Kty: "OKP", Crv: "Ed25519", X: "AAAA", Kid: "k"}},
	} {
		if _, err := identity.NewWardenSnapshot(identity.WardenBundle{Generation: 1, TokenIssuer: testIssuer, JWKS: jwks}); err == nil {
			t.Errorf("%s: snapshot accepted", name)
		}
	}
	v := newWarden(t, nil)
	if err := v.SetSnapshot(nil); err == nil {
		t.Error("nil snapshot accepted")
	}
	install(t, v, 5, testIssuer, nil, k1)
	older, _ := identity.NewWardenSnapshot(identity.WardenBundle{Generation: 4, TokenIssuer: testIssuer})
	if err := v.SetSnapshot(older); err != identity.ErrStaleSnapshot {
		t.Errorf("older snapshot: %v, want ErrStaleSnapshot", err)
	}
	if v.Snapshot().Generation() != 5 {
		t.Error("a refused snapshot replaced the installed one")
	}
}

func TestWardenSnapshotAgents(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, nil)
	install(t, v, 1, testIssuer, map[string]identity.WardenAgent{
		"agent-a": {Active: true, JKT: map[string]struct{}{testJKT: {}}},
	}, k1)
	a, ok := v.Snapshot().Agent("agent-a")
	if !ok || !a.Active {
		t.Fatalf("agent-a = %+v, %v", a, ok)
	}
	if _, has := a.JKT[testJKT]; !has {
		t.Error("thumbprint missing")
	}
	if _, ok := v.Snapshot().Agent("agent-b"); ok {
		t.Error("unregistered agent found")
	}
	var nilSnap *identity.WardenSnapshot
	if _, ok := nilSnap.Agent("x"); ok || nilSnap.Available() || nilSnap.Generation() != 0 || nilSnap.Issuer() != "" {
		t.Error("a nil snapshot must answer nothing")
	}
}

// TestWardenKeysetSwap: a token cached as valid under K1 is unknown_kid on the
// very next Verify after a bundle without K1 is applied, and K2 tokens from
// the new bundle verify with no restart, while 100 goroutines verify through
// the swap.
func TestWardenKeysetSwap(t *testing.T) {
	k1, k2 := newSigner(t, keys.AlgEdDSA), newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, nil)
	install(t, v, 1, testIssuer, nil, k1)
	tok1 := mint(t, k1, wardenHdr(), goodClaims())
	tok2 := mint(t, k2, wardenHdr(), goodClaims())
	ctx := context.Background()
	for i := 0; i < 2; i++ { // the second hit is served from the cache
		if _, st, _ := v.Verify(ctx, tok1); st != identity.StatusValid {
			t.Fatalf("K1 before the swap: %s", st)
		}
	}

	var swapped atomic.Bool
	var wg sync.WaitGroup
	var bad atomic.Int32
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				after := swapped.Load() // read before Verify: a swap that finished earlier must be seen
				_, st1, r1 := v.Verify(ctx, tok1)
				_, st2, _ := v.Verify(ctx, tok2)
				if after && (st1 != identity.StatusInvalid || r1 != identity.ReasonUnknownKID || st2 != identity.StatusValid) {
					bad.Add(1)
				}
			}
		}()
	}
	install(t, v, 2, testIssuer, nil, k2)
	swapped.Store(true)
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Fatalf("%d verifications after the swap saw the old keys", n)
	}
	if _, st, r := v.Verify(ctx, tok1); st != identity.StatusInvalid || r != identity.ReasonUnknownKID {
		t.Fatalf("K1 after the swap: %s/%s", st, r)
	}
	if _, st, _ := v.Verify(ctx, tok2); st != identity.StatusValid {
		t.Fatalf("K2 after the swap: %s", st)
	}
}

// TestWardenEqualGenerationDropsCache: replacing a snapshot at the same
// generation (for example after a config change) cannot serve old results.
func TestWardenEqualGenerationDropsCache(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, nil)
	install(t, v, 3, testIssuer, nil, k1)
	tok := mint(t, k1, wardenHdr(), goodClaims())
	if _, st, _ := v.Verify(context.Background(), tok); st != identity.StatusValid {
		t.Fatal(st)
	}
	install(t, v, 3, "", nil, k1)
	if _, st, r := v.Verify(context.Background(), tok); st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable {
		t.Fatalf("got %s/%s", st, r)
	}
}

// TestWardenCacheExpiry: a cached result stops at exp plus skew.
func TestWardenCacheExpiry(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	var mu sync.Mutex
	now := wardenNow
	v, err := identity.NewWardenVerifier(identity.WardenConfig{Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now }})
	if err != nil {
		t.Fatal(err)
	}
	install(t, v, 1, testIssuer, nil, k1)
	tok := mint(t, k1, wardenHdr(), goodClaims()) // exp = now+300
	if _, st, _ := v.Verify(context.Background(), tok); st != identity.StatusValid {
		t.Fatal(st)
	}
	mu.Lock()
	now = wardenNow.Add(300*time.Second + v.ClockSkew() + time.Second)
	mu.Unlock()
	if _, st, _ := v.Verify(context.Background(), tok); st != identity.StatusExpired {
		t.Fatalf("after exp+skew: %s", st)
	}
}

func TestWardenCacheBounded(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	v, err := identity.NewWardenVerifier(identity.WardenConfig{Now: func() time.Time { return wardenNow }, CacheSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	install(t, v, 1, testIssuer, nil, k1)
	for i := 0; i < 5; i++ {
		c := goodClaims()
		c["jti"] = string(rune('a' + i))
		if _, st, _ := v.Verify(context.Background(), mint(t, k1, wardenHdr(), c)); st != identity.StatusValid {
			t.Fatal(st)
		}
	}
}

func TestWardenConfigValidation(t *testing.T) {
	if _, err := identity.NewWardenVerifier(identity.WardenConfig{ClockSkew: -time.Second}); err == nil {
		t.Error("negative skew accepted")
	}
	if _, err := identity.NewWardenVerifier(identity.WardenConfig{ClockSkew: 6 * time.Minute}); err == nil {
		t.Error("skew over 5m accepted")
	}
	v, err := identity.NewWardenVerifier(identity.WardenConfig{})
	if err != nil || v.ClockSkew() != identity.DefaultClockSkew {
		t.Fatalf("default skew: %v %v", v, err)
	}
}

// TestWardenNeverLogsTokens: every refusal path logs at debug with a kid and a
// short fingerprint only.
func TestWardenNeverLogsTokens(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	k1, k2 := newSigner(t, keys.AlgEdDSA), newSigner(t, keys.AlgEdDSA)
	v := newWarden(t, logger)
	install(t, v, 1, testIssuer, nil, k1)
	var toks []string
	bad := goodClaims()
	bad["aud"] = "warden"
	exp := goodClaims()
	exp["iat"], exp["nbf"], exp["exp"] = wardenNow.Unix()-600, wardenNow.Unix()-600, wardenNow.Unix()-120
	for _, tok := range []string{
		mint(t, k1, wardenHdr(), goodClaims()),
		mint(t, k2, wardenHdr(), goodClaims()),
		mint(t, k1, wardenHdr(), bad),
		mint(t, k1, wardenHdr(), exp),
	} {
		toks = append(toks, tok)
		v.Verify(context.Background(), tok)
	}
	out := buf.String()
	if out == "" {
		t.Fatal("expected debug lines")
	}
	for _, tok := range toks {
		for _, seg := range strings.Split(tok, ".") {
			if len(seg) >= 8 && strings.Contains(out, seg[:8]) && strings.Contains(out, seg) {
				t.Fatalf("log contains a token segment: %s", out)
			}
		}
		if strings.Contains(out, tok) {
			t.Fatal("log contains a token")
		}
	}
	if strings.Contains(out, testJKT) || strings.Contains(out, "u@example.com") {
		t.Fatalf("log carries a claim value: %s", out)
	}
	// An attacker-chosen kid is truncated.
	buf.Reset()
	long := strings.Repeat("k", 500)
	v.Verify(context.Background(), mint(t, k1, keys.Header{Typ: identity.WardenTokenTyp, Alg: keys.AlgEdDSA, Kid: long}, goodClaims()))
	if strings.Contains(buf.String(), long) {
		t.Error("an oversized kid was logged whole")
	}
}

func BenchmarkWardenVerify(b *testing.B) {
	k1 := newSigner(b, keys.AlgEdDSA)
	v := newWarden(b, nil)
	install(b, v, 1, testIssuer, nil, k1)
	tok := mint(b, k1, wardenHdr(), goodClaims())
	ctx := context.Background()
	b.Run("cached", func(b *testing.B) {
		v.Verify(ctx, tok)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, st, _ := v.Verify(ctx, tok); st != identity.StatusValid {
				b.Fatal(st)
			}
		}
	})
	b.Run("uncached", func(b *testing.B) {
		// A one-entry cache and two tokens in turn: every Verify misses.
		v2, err := identity.NewWardenVerifier(identity.WardenConfig{Now: func() time.Time { return wardenNow }, CacheSize: 1})
		if err != nil {
			b.Fatal(err)
		}
		install(b, v2, 1, testIssuer, nil, k1)
		c := goodClaims()
		c["jti"] = "other"
		toks := [2]string{tok, mint(b, k1, wardenHdr(), c)}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, st, _ := v2.Verify(ctx, toks[i%2]); st != identity.StatusValid {
				b.Fatal(st)
			}
		}
	})
}
