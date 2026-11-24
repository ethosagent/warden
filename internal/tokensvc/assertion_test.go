package tokensvc_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/tokensvc"
)

const issuer = "https://cp.example.test"

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

// fakeAgents is an agentreg.Store that only serves Get.
type fakeAgents struct {
	agentreg.Store
	mu     sync.Mutex
	agents map[string]agentreg.Agent
	err    error
}

func (f *fakeAgents) Get(_ context.Context, id string) (agentreg.Agent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return agentreg.Agent{}, f.err
	}
	a, ok := f.agents[id]
	if !ok {
		return agentreg.Agent{}, agentreg.ErrNotFound
	}
	return a, nil
}

// memReplay is an in-memory ReplayStore.
type memReplay struct {
	mu   sync.Mutex
	rows map[string]time.Time
	err  error
}

func (m *memReplay) Consume(_ context.Context, agentID, jtiHash string, exp time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return false, m.err
	}
	k := agentID + "/" + jtiHash
	if _, ok := m.rows[k]; ok {
		return false, nil
	}
	if m.rows == nil {
		m.rows = map[string]time.Time{}
	}
	m.rows[k] = exp
	return true, nil
}

func (m *memReplay) Purge(_ context.Context, now time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for k, e := range m.rows {
		if e.Before(now) {
			delete(m.rows, k)
			n++
		}
	}
	return n, nil
}

func (m *memReplay) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rows)
}

type env struct {
	t      *testing.T
	agents *fakeAgents
	replay *memReplay
	v      *tokensvc.AssertionVerifier
	now    time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, agents: &fakeAgents{agents: map[string]agentreg.Agent{}}, replay: &memReplay{}, now: t0}
	e.v = &tokensvc.AssertionVerifier{
		Agents: e.agents, Replay: e.replay, Issuer: issuer,
		Now: func() time.Time { return e.now },
	}
	return e
}

// register creates an agent with a fresh key of alg and returns its signer.
func (e *env) register(id, alg string, status agentreg.Status) *signer.LocalSigner {
	e.t.Helper()
	s, err := signer.GenerateLocal(alg)
	if err != nil {
		e.t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(s.Public(), alg)
	if err != nil {
		e.t.Fatal(err)
	}
	doc, err := json.Marshal(jwk)
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := agentreg.Validate(agentreg.Agent{ID: id, AllowedGroups: []string{"eng"}, Keys: []agentreg.Key{{JWK: doc}}})
	if err != nil {
		e.t.Fatal(err)
	}
	a.Status = status
	e.agents.agents[id] = a
	return s
}

var jtiSeq atomic.Int64

// claimsFor returns valid claims for agent id at the env's clock.
func (e *env) claimsFor(id string) map[string]any {
	return map[string]any{
		"iss": id, "sub": id, "aud": issuer,
		"iat": e.now.Unix(), "exp": e.now.Add(time.Minute).Unix(),
		"jti": fmt.Sprintf("jti-secret-%d", jtiSeq.Add(1)),
	}
}

func (e *env) sign(s keys.Signer, claims map[string]any) string {
	e.t.Helper()
	raw, err := keys.SignCompact(context.Background(), s, keys.Header{}, claims)
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

// forge assembles a compact JWS from a literal header and claims with an
// arbitrary signature, for the shapes SignCompact refuses to produce.
func forge(header string, claims map[string]any, sig []byte) string {
	cb, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc(cb) + "." + enc(sig)
}

func wantReason(t *testing.T, err error, want tokensvc.Reason) {
	t.Helper()
	var te *tokensvc.Error
	if !errors.As(err, &te) {
		t.Fatalf("want *tokensvc.Error %s, got %v", want, err)
	}
	if te.Reason != want {
		t.Fatalf("reason = %s, want %s", te.Reason, want)
	}
	wantCode := tokensvc.CodeInvalidClient
	if want == tokensvc.ReasonStoreUnavailable {
		wantCode = tokensvc.CodeTemporarilyUnavailable
	}
	if te.Code != wantCode {
		t.Fatalf("code = %s, want %s", te.Code, wantCode)
	}
}

func TestVerifyClientAssertion(t *testing.T) {
	ctx := context.Background()
	t.Run("valid", func(t *testing.T) {
		for _, alg := range []string{keys.AlgEdDSA, keys.AlgES256} {
			e := newEnv(t)
			s := e.register("agent-1", alg, agentreg.StatusActive)
			c, err := e.v.VerifyClientAssertion(ctx, e.sign(s, e.claimsFor("agent-1")))
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			jwk, _ := keys.PublicJWK(s.Public(), alg)
			want, _ := keys.Thumbprint(jwk)
			if c.AgentID != "agent-1" || c.JKT != want || c.KID != s.KID() {
				t.Fatalf("%s: client = %+v, want jkt %s", alg, c, want)
			}
			if got := agentreg.Thumbprints(e.agents.agents["agent-1"]); len(got) != 1 || got[0] != c.JKT {
				t.Fatalf("jkt %s is not the thumbprint the registry serves: %v", c.JKT, got)
			}
		}
	})

	t.Run("kid may be the thumbprint", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
		key := e.agents.agents["agent-1"].Keys[0]
		key.KID = "friendly-name"
		e.agents.agents["agent-1"] = agentreg.Agent{ID: "agent-1", Keys: []agentreg.Key{key}, Status: agentreg.StatusActive}
		for _, kid := range []string{"friendly-name", key.JKT} {
			raw, err := keys.SignCompact(ctx, s, keys.Header{Kid: kid}, e.claimsFor("agent-1"))
			if err != nil {
				t.Fatal(err)
			}
			c, err := e.v.VerifyClientAssertion(ctx, raw)
			if err != nil || c.KID != "friendly-name" || c.JKT != key.JKT {
				t.Fatalf("kid %q: %+v %v", kid, c, err)
			}
		}
	})

	t.Run("rejections", func(t *testing.T) {
		e := newEnv(t)
		ed := e.register("agent-ed", keys.AlgEdDSA, agentreg.StatusActive)
		ec := e.register("agent-ec", keys.AlgES256, agentreg.StatusActive)
		e.register("agent-off", keys.AlgEdDSA, agentreg.StatusDisabled)
		offSigner := e.register("agent-off2", keys.AlgEdDSA, agentreg.StatusDisabled)
		stranger, _ := signer.GenerateLocal(keys.AlgEdDSA)
		edKID := ed.KID()
		hsKey := []byte(ed.Public().(ed25519.PublicKey))
		mac := func(input string) []byte {
			h := hmac.New(sha256.New, hsKey)
			h.Write([]byte(input))
			return h.Sum(nil)
		}
		forgedHS := func() string {
			cb, _ := json.Marshal(e.claimsFor("agent-ed"))
			enc := base64.RawURLEncoding.EncodeToString
			in := enc([]byte(`{"alg":"HS256","kid":"`+edKID+`"}`)) + "." + enc(cb)
			return in + "." + enc(mac(in))
		}()
		edHdr := func(extra string) string { return `{"alg":"EdDSA","kid":"` + edKID + `"` + extra + `}` }
		tampered := func() string {
			raw := e.sign(ed, e.claimsFor("agent-ed"))
			i := strings.LastIndexByte(raw, '.')
			sig := []byte(raw[i+1:])
			if sig[0] == 'A' {
				sig[0] = 'B'
			} else {
				sig[0] = 'A'
			}
			return raw[:i+1] + string(sig)
		}()
		wrongKey, _ := keys.SignCompact(ctx, stranger, keys.Header{Kid: edKID}, e.claimsFor("agent-ed"))

		cases := []struct {
			name string
			raw  string
			want tokensvc.Reason
		}{
			{"alg none", forge(`{"alg":"none","kid":"`+edKID+`"}`, e.claimsFor("agent-ed"), []byte("x")), tokensvc.ReasonAlgNotAllowed},
			{"HS256 signed with the public key", forgedHS, tokensvc.ReasonAlgNotAllowed},
			{"RS256", forge(`{"alg":"RS256","kid":"`+edKID+`"}`, e.claimsFor("agent-ed"), make([]byte, 256)), tokensvc.ReasonAlgNotAllowed},
			{"ES256 header on an Ed25519 key", forge(`{"alg":"ES256","kid":"`+edKID+`"}`, e.claimsFor("agent-ed"), make([]byte, 64)), tokensvc.ReasonAlgNotAllowed},
			{"EdDSA header on an EC key", forge(`{"alg":"EdDSA","kid":"`+ec.KID()+`"}`, e.claimsFor("agent-ec"), make([]byte, 64)), tokensvc.ReasonAlgNotAllowed},
			{"jwk header", forge(edHdr(`,"jwk":{"kty":"OKP"}`), e.claimsFor("agent-ed"), make([]byte, 64)), tokensvc.ReasonMalformed},
			{"jku header", forge(edHdr(`,"jku":"https://evil.test/jwks"`), e.claimsFor("agent-ed"), make([]byte, 64)), tokensvc.ReasonMalformed},
			{"missing kid", forge(`{"alg":"EdDSA"}`, e.claimsFor("agent-ed"), make([]byte, 64)), tokensvc.ReasonUnknownKID},
			{"unknown kid", forge(`{"alg":"EdDSA","kid":"nope"}`, e.claimsFor("agent-ed"), make([]byte, 64)), tokensvc.ReasonUnknownKID},
			{"unknown agent", e.sign(stranger, e.claimsFor("agent-nobody")), tokensvc.ReasonAgentUnknown},
			{"invalid agent id", e.sign(stranger, e.claimsFor("bad id!")), tokensvc.ReasonAgentUnknown},
			{"bad signature", tampered, tokensvc.ReasonBadSignature},
			{"signed by another key", wrongKey, tokensvc.ReasonBadSignature},
			{"disabled agent", e.sign(offSigner, e.claimsFor("agent-off2")), tokensvc.ReasonAgentDisabled},
			{"not a jws", "not.a.jws", tokensvc.ReasonMalformed},
			{"two segments", "a.b", tokensvc.ReasonMalformed},
			{"too large", strings.Repeat("a", tokensvc.MaxAssertionSize+1), tokensvc.ReasonTooLarge},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				before := e.replay.count()
				_, err := e.v.VerifyClientAssertion(ctx, c.raw)
				wantReason(t, err, c.want)
				if e.replay.count() != before {
					t.Fatal("a rejected assertion must not insert a replay row")
				}
				if strings.Contains(err.Error(), c.raw) || strings.Contains(fmt.Sprintf("%+v", err), "jti-secret") {
					t.Fatal("error leaks the assertion or a jti")
				}
			})
		}
	})

	t.Run("unknown agent, unknown kid, bad signature and disabled share one client-visible error shape", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("a1", keys.AlgEdDSA, agentreg.StatusActive)
		off := e.register("a2", keys.AlgEdDSA, agentreg.StatusDisabled)
		stranger, _ := signer.GenerateLocal(keys.AlgEdDSA)
		raws := []string{
			e.sign(stranger, e.claimsFor("ghost")),
			forge(`{"alg":"EdDSA","kid":"nope"}`, e.claimsFor("a1"), make([]byte, 64)),
			forge(`{"alg":"EdDSA","kid":"`+s.KID()+`"}`, e.claimsFor("a1"), make([]byte, 64)),
			e.sign(off, e.claimsFor("a2")),
		}
		for _, raw := range raws {
			_, err := e.v.VerifyClientAssertion(ctx, raw)
			var te *tokensvc.Error
			if !errors.As(err, &te) || te.Code != tokensvc.CodeInvalidClient {
				t.Fatalf("got %v, want invalid_client", err)
			}
		}
	})

	t.Run("form client_id must equal iss", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("a1", keys.AlgEdDSA, agentreg.StatusActive)
		_, err := e.v.VerifyClientAssertionFor(ctx, e.sign(s, e.claimsFor("a1")), "someone-else")
		wantReason(t, err, tokensvc.ReasonWrongIss)
		if _, err := e.v.VerifyClientAssertionFor(ctx, e.sign(s, e.claimsFor("a1")), "a1"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("registry and replay store failures are temporarily_unavailable", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("a1", keys.AlgEdDSA, agentreg.StatusActive)
		e.replay.err = errors.New("db down")
		_, err := e.v.VerifyClientAssertion(ctx, e.sign(s, e.claimsFor("a1")))
		wantReason(t, err, tokensvc.ReasonStoreUnavailable)
		e.replay.err = nil
		e.agents.err = errors.New("db down")
		_, err = e.v.VerifyClientAssertion(ctx, e.sign(s, e.claimsFor("a1")))
		wantReason(t, err, tokensvc.ReasonStoreUnavailable)
	})

	t.Run("a misconfigured verifier fails closed", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("a1", keys.AlgEdDSA, agentreg.StatusActive)
		raw := e.sign(s, e.claimsFor("a1"))
		for _, v := range []*tokensvc.AssertionVerifier{
			nil,
			{Replay: e.replay, Issuer: issuer, Now: e.v.Now},
			{Agents: e.agents, Issuer: issuer, Now: e.v.Now},
			{Agents: e.agents, Replay: e.replay, Now: e.v.Now},
			{Agents: e.agents, Replay: e.replay, Issuer: issuer},
		} {
			_, err := v.VerifyClientAssertion(ctx, raw)
			wantReason(t, err, tokensvc.ReasonStoreUnavailable)
		}
	})
}

func TestAssertionClaims(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
	mod := func(f func(c map[string]any)) string {
		c := e.claimsFor("agent-1")
		f(c)
		return e.sign(s, c)
	}
	now := e.now.Unix()
	cases := []struct {
		name string
		raw  string
		want tokensvc.Reason // "" = accepted
	}{
		{"aud is the issuer", mod(func(c map[string]any) {}), ""},
		{"aud is the token endpoint", mod(func(c map[string]any) { c["aud"] = issuer + "/oauth2/token" }), ""},
		{"aud array of one", mod(func(c map[string]any) { c["aud"] = []string{issuer + "/oauth2/token"} }), ""},
		{"aud array of two", mod(func(c map[string]any) { c["aud"] = []string{issuer, "https://other"} }), tokensvc.ReasonWrongAud},
		{"aud other", mod(func(c map[string]any) { c["aud"] = "https://other" }), tokensvc.ReasonWrongAud},
		{"aud empty array", mod(func(c map[string]any) { c["aud"] = []string{} }), tokensvc.ReasonWrongAud},
		{"aud missing", mod(func(c map[string]any) { delete(c, "aud") }), tokensvc.ReasonWrongAud},
		{"aud number", mod(func(c map[string]any) { c["aud"] = 5 }), tokensvc.ReasonWrongAud},
		{"iss != sub", mod(func(c map[string]any) { c["sub"] = "other" }), tokensvc.ReasonWrongIss},
		{"sub missing", mod(func(c map[string]any) { delete(c, "sub") }), tokensvc.ReasonWrongIss},
		{"client_id differs", mod(func(c map[string]any) { c["client_id"] = "other" }), tokensvc.ReasonWrongIss},
		{"client_id equals iss", mod(func(c map[string]any) { c["client_id"] = "agent-1" }), ""},
		{"lifetime 5m", mod(func(c map[string]any) { c["exp"] = now + 300 }), ""},
		{"lifetime 6m", mod(func(c map[string]any) { c["exp"] = now + 360 }), tokensvc.ReasonLifetimeTooLong},
		{"exp 2m in the past", mod(func(c map[string]any) { c["iat"] = now - 180; c["exp"] = now - 120 }), tokensvc.ReasonExpired},
		{"exp 30s in the past is within skew", mod(func(c map[string]any) { c["iat"] = now - 90; c["exp"] = now - 30 }), ""},
		{"exp exactly skew in the past", mod(func(c map[string]any) { c["iat"] = now - 90; c["exp"] = now - 60 }), tokensvc.ReasonExpired},
		{"exp before iat", mod(func(c map[string]any) { c["exp"] = now - 10 }), tokensvc.ReasonMalformed},
		{"exp missing", mod(func(c map[string]any) { delete(c, "exp") }), tokensvc.ReasonMalformed},
		{"iat missing", mod(func(c map[string]any) { delete(c, "iat") }), tokensvc.ReasonMalformed},
		{"exp is a string", mod(func(c map[string]any) { c["exp"] = "soon" }), tokensvc.ReasonMalformed},
		{"iat 90s in the future", mod(func(c map[string]any) { c["iat"] = now + 90; c["exp"] = now + 150 }), tokensvc.ReasonNotYetValid},
		{"iat 30s in the future", mod(func(c map[string]any) { c["iat"] = now + 30; c["exp"] = now + 90 }), ""},
		{"nbf 90s in the future", mod(func(c map[string]any) { c["nbf"] = now + 90 }), tokensvc.ReasonNotYetValid},
		{"nbf in the past", mod(func(c map[string]any) { c["nbf"] = now - 10 }), ""},
		{"jti missing", mod(func(c map[string]any) { delete(c, "jti") }), tokensvc.ReasonMalformed},
		{"jti empty", mod(func(c map[string]any) { c["jti"] = "" }), tokensvc.ReasonMalformed},
		{"jti 129 chars", mod(func(c map[string]any) { c["jti"] = strings.Repeat("a", 129) }), tokensvc.ReasonMalformed},
		{"jti 128 chars", mod(func(c map[string]any) { c["jti"] = strings.Repeat("b", 128) }), ""},
		{"jti with a space", mod(func(c map[string]any) { c["jti"] = "a b" }), tokensvc.ReasonMalformed},
		{"jti with a control byte", mod(func(c map[string]any) { c["jti"] = "a\x01b" }), tokensvc.ReasonMalformed},
		{"jti non-ASCII", mod(func(c map[string]any) { c["jti"] = "jti-é" }), tokensvc.ReasonMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := e.v.VerifyClientAssertion(ctx, c.raw)
			if c.want == "" {
				if err != nil {
					t.Fatalf("want accepted, got %v", err)
				}
				return
			}
			wantReason(t, err, c.want)
		})
	}

	t.Run("a trailing slash on the issuer still accepts the token endpoint", func(t *testing.T) {
		e2 := newEnv(t)
		e2.v.Issuer = issuer + "/"
		s2 := e2.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
		c := e2.claimsFor("agent-1")
		c["aud"] = issuer + "/oauth2/token"
		if _, err := e2.v.VerifyClientAssertion(ctx, e2.sign(s2, c)); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAssertionReplay(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
	raw := e.sign(s, e.claimsFor("agent-1"))

	const n = 50
	var ok, replays atomic.Int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := e.v.VerifyClientAssertion(ctx, raw)
			var te *tokensvc.Error
			switch {
			case err == nil:
				ok.Add(1)
			case errors.As(err, &te) && te.Reason == tokensvc.ReasonReplay:
				replays.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != 1 || replays.Load() != n-1 {
		t.Fatalf("successes = %d, replays = %d, want 1 and %d", ok.Load(), replays.Load(), n-1)
	}
	_, err := e.v.VerifyClientAssertion(ctx, raw)
	wantReason(t, err, tokensvc.ReasonReplay)

	t.Run("the same jti from another agent is not a replay", func(t *testing.T) {
		s2 := e.register("agent-2", keys.AlgEdDSA, agentreg.StatusActive)
		c := e.claimsFor("agent-2")
		c["jti"] = "shared-jti"
		c1 := e.claimsFor("agent-1")
		c1["jti"] = "shared-jti"
		for _, p := range []struct {
			s keys.Signer
			c map[string]any
		}{{s, c1}, {s2, c}} {
			if _, err := e.v.VerifyClientAssertion(ctx, e.sign(p.s, p.c)); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("a rejected assertion does not burn its jti", func(t *testing.T) {
		c := e.claimsFor("agent-1")
		c["aud"] = "https://other"
		_, err := e.v.VerifyClientAssertion(ctx, e.sign(s, c))
		wantReason(t, err, tokensvc.ReasonWrongAud)
		c["aud"] = issuer
		if _, err := e.v.VerifyClientAssertion(ctx, e.sign(s, c)); err != nil {
			t.Fatalf("the corrected assertion must still be accepted: %v", err)
		}
	})

	t.Run("the replay row outlives the assertion by the skew", func(t *testing.T) {
		e := newEnv(t)
		s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
		c := e.claimsFor("agent-1")
		exp := time.Unix(c["exp"].(int64), 0)
		if _, err := e.v.VerifyClientAssertion(ctx, e.sign(s, c)); err != nil {
			t.Fatal(err)
		}
		for _, got := range e.replay.rows {
			if !got.Equal(exp.Add(tokensvc.DefaultSkew)) {
				t.Fatalf("row expires at %v, want %v", got, exp.Add(tokensvc.DefaultSkew))
			}
		}
	})
}

func TestAssertionErrorsCarryOnlyAHashPrefix(t *testing.T) {
	e := newEnv(t)
	s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
	c := e.claimsFor("agent-1")
	raw := e.sign(s, c)
	if _, err := e.v.VerifyClientAssertion(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	_, err := e.v.VerifyClientAssertion(context.Background(), raw)
	var te *tokensvc.Error
	if !errors.As(err, &te) {
		t.Fatal(err)
	}
	if want := tokensvc.JTIHash(c["jti"].(string))[:8]; te.JTI != want || len(te.JTI) != 8 {
		t.Fatalf("JTI = %q, want %q", te.JTI, want)
	}
	if te.AgentID != "agent-1" {
		t.Fatalf("AgentID = %q", te.AgentID)
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v %+v %#v", err, te, te)} {
		if strings.Contains(s, c["jti"].(string)) || strings.Contains(s, raw) {
			t.Fatal("error leaks the jti or the assertion")
		}
	}
}

// TestAssertionJTIPurge covers the domain contract with the in-memory store;
// the SQLite file check lives in adapters/sqlite.
func TestAssertionJTIPurge(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	s := e.register("agent-1", keys.AlgEdDSA, agentreg.StatusActive)
	raw := e.sign(s, e.claimsFor("agent-1"))
	if _, err := e.v.VerifyClientAssertion(ctx, raw); err != nil {
		t.Fatal(err)
	}
	for k := range e.replay.rows {
		if strings.Contains(k, "jti-secret") {
			t.Fatal("the store holds the raw jti")
		}
	}
	e.now = e.now.Add(2 * time.Minute) // exp is +1m, the row lives to exp+60s
	if n, _ := e.replay.Purge(ctx, e.now); n != 0 {
		t.Fatalf("purged %d at exp+60s, want 0", n)
	}
	e.now = e.now.Add(time.Second)
	if n, _ := e.replay.Purge(ctx, e.now); n != 1 || e.replay.count() != 0 {
		t.Fatalf("purged %d, rows left %d", n, e.replay.count())
	}
}
