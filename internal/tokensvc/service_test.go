package tokensvc_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
	"github.com/ethosagent/warden/internal/tokensvc"
	tokensqlite "github.com/ethosagent/warden/internal/tokensvc/adapters/sqlite"
	"github.com/ethosagent/warden/test/fakes"
)

var update = flag.Bool("update", false, "rewrite testdata golden files")

const (
	subjectToken = "subject-token-secret"
	idpIssuer    = "https://idp.example.test"
)

// flakySessions wraps the real SQLite session store and fails Touch on demand.
type flakySessions struct {
	tokensvc.SessionStore
	mu  sync.Mutex
	err error
}

func (f *flakySessions) setErr(err error) { f.mu.Lock(); f.err = err; f.mu.Unlock() }

func (f *flakySessions) Touch(ctx context.Context, k tokensvc.SessionKey, issued, now time.Time, p tokensvc.SessionPolicy, sid string) (string, error) {
	f.mu.Lock()
	err := f.err
	f.mu.Unlock()
	if err != nil {
		return "", err
	}
	return f.SessionStore.Touch(ctx, k, issued, now, p, sid)
}

type fakeBlocks struct {
	mu           sync.Mutex
	subs, emails map[string]bool
	err          error
	gotEmail     string
}

func (f *fakeBlocks) IsBlocked(_ context.Context, sub, email string) (bool, error) {
	f.mu.Lock()
	f.gotEmail = email
	f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	return f.subs[sub] || (email != "" && f.emails[strings.ToLower(email)]), nil
}

type fakeSigners struct {
	mu  sync.Mutex
	s   keys.Signer
	err error
	got []string
}

func (f *fakeSigners) Active(purpose string) (keys.Signer, error) {
	f.mu.Lock()
	f.got = append(f.got, purpose)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.s, nil
}

// detRand is a deterministic io.Reader: sha256 of a counter, repeated.
type detRand struct {
	mu sync.Mutex
	n  uint64
}

func (d *detRand) Read(p []byte) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < len(p); {
		var c [8]byte
		binary.BigEndian.PutUint64(c[:], d.n)
		d.n++
		sum := sha256.Sum256(c[:])
		i += copy(p[i:], sum[:])
	}
	return len(p), nil
}

type svcEnv struct {
	*env
	svc      *tokensvc.Service
	verifier *fakes.Verifier
	blocks   *fakeBlocks
	signers  *fakeSigners
	sessions *flakySessions
	db       *cpstate.DB
	mint     *signer.LocalSigner
	agent    *signer.LocalSigner
}

func fixedSigner(t *testing.T, label string) *signer.LocalSigner {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	s, err := signer.NewLocalSigner(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newSvcEnv builds a service over fakes, with one active agent "agent-1"
// (allowed group eng, scopes read and write) that signs with a fixed key.
func newSvcEnv(t *testing.T) *svcEnv { return newSvcEnvWith(t, nil) }

// newSvcEnvWith is newSvcEnv with a last look at the service Config, for the
// limiter, recorder and metrics hooks.
func newSvcEnvWith(t *testing.T, mod func(*tokensvc.Config)) *svcEnv {
	t.Helper()
	e := &svcEnv{
		env:      newEnv(t),
		verifier: fakes.NewVerifier(),
		blocks:   &fakeBlocks{subs: map[string]bool{}, emails: map[string]bool{}},
		mint:     fixedSigner(t, "mint"),
		agent:    fixedSigner(t, "agent"),
	}
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), tokensqlite.SessionMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.sessions = &flakySessions{SessionStore: tokensqlite.NewSessions(db)}
	e.signers = &fakeSigners{s: e.mint}
	e.setAgent(func(a *agentreg.Agent) {})
	e.verifier.Set(subjectToken, e.claims(), identity.StatusValid, "")
	cfg := tokensvc.Config{
		Issuer:  issuer,
		Clients: e.v, Agents: e.agents, Blocks: e.blocks, Signers: e.signers, Sessions: e.sessions,
		Resolvers: map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(e.verifier)},
		Now:       func() time.Time { return e.now },
		Rand:      &detRand{},
	}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := tokensvc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	return e
}

// setAgent (re)registers agent-1 with the fixed key and applies mod.
func (e *svcEnv) setAgent(mod func(*agentreg.Agent)) {
	e.t.Helper()
	jwk, err := keys.PublicJWK(e.agent.Public(), keys.AlgEdDSA)
	if err != nil {
		e.t.Fatal(err)
	}
	doc, _ := json.Marshal(jwk)
	a, err := agentreg.Validate(agentreg.Agent{
		ID: "agent-1", AllowedGroups: []string{"eng"}, AllowedScopes: []string{"write", "read"},
		Keys: []agentreg.Key{{JWK: doc}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	a.Status = agentreg.StatusActive
	mod(&a)
	e.agents.mu.Lock()
	e.agents.agents["agent-1"] = a
	e.agents.mu.Unlock()
}

func (e *svcEnv) claims() identity.Claims {
	return identity.Claims{
		Sub: "user-1", Email: "Alice@Example.test", EmailVerified: true,
		Groups: []string{"eng", "ops"}, SID: "idp-sid-1", Issuer: idpIssuer, AZP: "agent-harness",
		IssuedAt: e.now.Add(-time.Minute), Expiry: e.now.Add(time.Hour),
	}
}

func (e *svcEnv) req() tokensvc.ExchangeRequest {
	return tokensvc.ExchangeRequest{
		ClientAssertion:  e.sign(e.agent, e.claimsFor("agent-1")),
		SubjectToken:     subjectToken,
		SubjectTokenType: tokensvc.TokenTypeIDToken,
	}
}

func wantErr(t *testing.T, err error, code tokensvc.OAuthCode, reason tokensvc.Reason) *tokensvc.Error {
	t.Helper()
	var te *tokensvc.Error
	if !errors.As(err, &te) {
		t.Fatalf("want *tokensvc.Error %s/%s, got %v", code, reason, err)
	}
	if te.Code != code || te.Reason != reason {
		t.Fatalf("error = %s/%s, want %s/%s", te.Code, te.Reason, code, reason)
	}
	return te
}

// parseIssued splits a minted token into header and claims maps and verifies
// the signature with keys.Verify.
func parseIssued(t *testing.T, raw string, pub keys.Signer) (keys.Header, map[string]any) {
	t.Helper()
	h, payload, input, sig, err := keys.ParseCompact(raw)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(pub.Public(), pub.Alg())
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.Verify(jwk, h.Alg, input, sig); err != nil {
		t.Fatalf("minted token signature: %v", err)
	}
	var c map[string]any
	if err := json.Unmarshal(payload, &c); err != nil {
		t.Fatal(err)
	}
	return h, c
}

func TestExchangeGoldenClaims(t *testing.T) {
	e := newSvcEnv(t)
	got, err := e.svc.Exchange(context.Background(), e.req())
	if err != nil {
		t.Fatal(err)
	}
	h, claims := parseIssued(t, got.AccessToken, e.mint)
	if len(e.signers.got) != 1 || e.signers.got[0] != keys.PurposeToken {
		t.Fatalf("signer purposes asked = %v, want only %q", e.signers.got, keys.PurposeToken)
	}
	if got.ExpiresIn != 900 || got.TokenType != "Bearer" || got.IssuedTokenType != tokensvc.TokenTypeJWT {
		t.Fatalf("response = %+v", got)
	}
	out, err := json.MarshalIndent(map[string]any{"header": h, "claims": claims}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	const path = "testdata/issued_golden.json"
	if *update {
		if err := os.WriteFile(path, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("issued token differs from %s (run with -update to rewrite):\n%s", path, out)
	}
	// cnf.jkt is the thumbprint of the key that signed the assertion.
	jkt := agentreg.Thumbprints(e.agents.agents["agent-1"])[0]
	if c, _ := claims["cnf"].(map[string]any); c["jkt"] != jkt {
		t.Fatalf("cnf = %v, want jkt %s", claims["cnf"], jkt)
	}
	if h.Kid != e.mint.KID() || h.Typ != "wt+jwt" || h.Alg != keys.AlgEdDSA {
		t.Fatalf("header = %+v", h)
	}
}

func TestExchangeBlockedUser(t *testing.T) {
	ctx := context.Background()
	t.Run("by sub", func(t *testing.T) {
		e := newSvcEnv(t)
		e.blocks.subs["user-1"] = true
		got, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked)
		if got != nil {
			t.Fatal("token released for a blocked user")
		}
	})
	t.Run("by verified email only", func(t *testing.T) {
		e := newSvcEnv(t)
		e.blocks.emails["alice@example.test"] = true
		_, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonUserBlocked)
	})
	t.Run("unverified email does not match", func(t *testing.T) {
		e := newSvcEnv(t)
		c := e.claims()
		c.EmailVerified = false
		e.verifier.Set(subjectToken, c, identity.StatusValid, "")
		e.blocks.emails["alice@example.test"] = true
		got, err := e.svc.Exchange(ctx, e.req())
		if err != nil {
			t.Fatal(err)
		}
		if e.blocks.gotEmail != "" {
			t.Fatalf("an unverified email reached the block check: %q", e.blocks.gotEmail)
		}
		_, claims := parseIssued(t, got.AccessToken, e.mint)
		if _, ok := claims["email"]; ok {
			t.Fatalf("unverified email in token: %v", claims)
		}
	})
	t.Run("check error fails closed", func(t *testing.T) {
		e := newSvcEnv(t)
		e.blocks.err = errors.New("db down")
		got, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonBlockStoreUnavailable)
		if got != nil {
			t.Fatal("token released on a block store error")
		}
	})
}

func TestExchangeAuthorization(t *testing.T) {
	ctx := context.Background()
	scopeOf := func(t *testing.T, e *svcEnv, scope string) (*tokensvc.Issued, error) {
		r := e.req()
		r.Scope = scope
		return e.svc.Exchange(ctx, r)
	}
	t.Run("no group intersection", func(t *testing.T) {
		e := newSvcEnv(t)
		e.setAgent(func(a *agentreg.Agent) { a.AllowedGroups = []string{"finance"} })
		_, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeUnauthorizedClient, tokensvc.ReasonGroupNotAllowed)
	})
	t.Run("truncated groups with no match fail closed", func(t *testing.T) {
		e := newSvcEnv(t)
		c := e.claims()
		c.GroupsTruncated = true
		c.Groups = []string{"ops"}
		e.verifier.Set(subjectToken, c, identity.StatusValid, "")
		_, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeUnauthorizedClient, tokensvc.ReasonGroupNotAllowed)
	})
	t.Run("scope outside allowed", func(t *testing.T) {
		e := newSvcEnv(t)
		_, err := scopeOf(t, e, "admin")
		wantErr(t, err, tokensvc.CodeInvalidScope, tokensvc.ReasonScopeNotAllowed)
	})
	t.Run("scope grammar and count", func(t *testing.T) {
		e := newSvcEnv(t)
		many := make([]string, 17)
		for i := range many {
			many[i] = fmt.Sprintf("s%d", i)
		}
		e.setAgent(func(a *agentreg.Agent) { a.AllowedScopes = many })
		for _, bad := range []string{"READ", "read  write", " read", "read ", strings.Repeat("a", 65), strings.Join(many, " ")} {
			_, err := scopeOf(t, e, bad)
			wantErr(t, err, tokensvc.CodeInvalidScope, tokensvc.ReasonScopeNotAllowed)
		}
	})
	t.Run("requested subset", func(t *testing.T) {
		e := newSvcEnv(t)
		got, err := scopeOf(t, e, "write read read")
		if err != nil || got.Scope != "read write" {
			t.Fatalf("scope = %q, %v", got.Scope, err)
		}
	})
	t.Run("omitted scope yields allowed_scopes", func(t *testing.T) {
		e := newSvcEnv(t)
		got, err := scopeOf(t, e, "")
		if err != nil || got.Scope != "read write" {
			t.Fatalf("scope = %q, %v", got.Scope, err)
		}
	})
	t.Run("empty allowed_scopes means no scope claim", func(t *testing.T) {
		e := newSvcEnv(t)
		e.setAgent(func(a *agentreg.Agent) { a.AllowedScopes = nil })
		got, err := scopeOf(t, e, "")
		if err != nil || got.Scope != "" {
			t.Fatalf("scope = %q, %v", got.Scope, err)
		}
		_, claims := parseIssued(t, got.AccessToken, e.mint)
		if _, ok := claims["scope"]; ok {
			t.Fatalf("scope claim present: %v", claims)
		}
		if _, err := scopeOf(t, e, "read"); err == nil {
			t.Fatal("scope granted to an agent with none allowed")
		}
	})
	t.Run("audience", func(t *testing.T) {
		e := newSvcEnv(t)
		r := e.req()
		r.Audience = "other"
		_, err := e.svc.Exchange(ctx, r)
		wantErr(t, err, tokensvc.CodeInvalidTarget, tokensvc.ReasonInvalidTarget)
		r = e.req()
		r.Audience = "warden-worker"
		if _, err := e.svc.Exchange(ctx, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("token types", func(t *testing.T) {
		e := newSvcEnv(t)
		r := e.req()
		r.SubjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
		_, err := e.svc.Exchange(ctx, r)
		wantErr(t, err, tokensvc.CodeInvalidRequest, tokensvc.ReasonUnsupportedTokenType)
		r = e.req()
		r.RequestedTokenType = "urn:ietf:params:oauth:token-type:refresh_token"
		_, err = e.svc.Exchange(ctx, r)
		wantErr(t, err, tokensvc.CodeInvalidRequest, tokensvc.ReasonUnsupportedTokenType)
		r = e.req()
		r.RequestedTokenType = tokensvc.TokenTypeAccessToken
		if _, err := e.svc.Exchange(ctx, r); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("agent disabled or re-keyed after authentication", func(t *testing.T) {
		e := newSvcEnv(t)
		r := e.req()
		e.setAgent(func(a *agentreg.Agent) { a.Status = agentreg.StatusDisabled })
		// The assertion check already refuses a disabled agent.
		_, err := e.svc.Exchange(ctx, r)
		wantReason(t, err, tokensvc.ReasonAgentDisabled)

		// A disable that lands during the IdP round trip is caught by the re-read.
		e = newSvcEnv(t)
		e.verifier.Set(subjectToken, e.claims(), identity.StatusValid, "")
		slow := &disableOnResolve{Verifier: e.verifier, disable: func() {
			e.setAgent(func(a *agentreg.Agent) { a.Status = agentreg.StatusDisabled })
		}}
		svc := e.rebuild(slow)
		_, err = svc.Exchange(ctx, e.req())
		wantReason(t, err, tokensvc.ReasonAgentDisabled)

		e = newSvcEnv(t)
		slow = &disableOnResolve{Verifier: e.verifier, disable: func() {
			other := fixedSigner(t, "rotated")
			jwk, _ := keys.PublicJWK(other.Public(), keys.AlgEdDSA)
			doc, _ := json.Marshal(jwk)
			e.setAgent(func(a *agentreg.Agent) {
				a.Keys = []agentreg.Key{{KID: other.KID(), JKT: other.KID(), Alg: keys.AlgEdDSA, JWK: doc}}
			})
		}}
		_, err = e.rebuild(slow).Exchange(ctx, e.req())
		wantReason(t, err, tokensvc.ReasonUnknownKID)
	})
	t.Run("agent store error", func(t *testing.T) {
		e := newSvcEnv(t)
		slow := &disableOnResolve{Verifier: e.verifier, disable: func() { e.agents.err = errors.New("db down") }}
		_, err := e.rebuild(slow).Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonAgentStoreUnavailable)
	})
}

// disableOnResolve runs a hook between agent authentication and the agent
// re-read, simulating a change that lands while the IdP answers.
type disableOnResolve struct {
	*fakes.Verifier
	disable func()
}

func (d *disableOnResolve) Verify(ctx context.Context, raw string, o ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	d.disable()
	return d.Verifier.Verify(ctx, raw, o...)
}

func (e *svcEnv) rebuild(v identity.Verifier) *tokensvc.Service {
	e.t.Helper()
	svc, err := tokensvc.New(tokensvc.Config{
		Issuer:  issuer,
		Clients: e.v, Agents: e.agents, Blocks: e.blocks, Signers: e.signers, Sessions: e.sessions,
		Resolvers: map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(v)},
		Now:       func() time.Time { return e.now },
		Rand:      &detRand{},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

func TestExchangeSubjectAndSignerFailures(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		status identity.Status
		reason identity.Reason
		code   tokensvc.OAuthCode
		want   tokensvc.Reason
	}{
		{"expired", identity.StatusExpired, "", tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectExpired},
		{"wrong azp", identity.StatusInvalid, identity.ReasonWrongAZP, tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid},
		{"malformed", identity.StatusInvalid, identity.ReasonMalformed, tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid},
		{"conflict", identity.StatusConflict, "", tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid},
		{"none", identity.StatusNone, "", tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid},
		{"off", identity.StatusOff, "", tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid},
		{"unverified", identity.StatusUnverified, identity.ReasonJWKSUnavailable, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonIdPUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newSvcEnv(t)
			e.verifier.Set(subjectToken, e.claims(), tc.status, tc.reason)
			got, err := e.svc.Exchange(ctx, e.req())
			te := wantErr(t, err, tc.code, tc.want)
			if te.AgentID != "agent-1" {
				t.Fatalf("AgentID = %q, want the authenticated agent", te.AgentID)
			}
			if got != nil {
				t.Fatal("token released")
			}
		})
	}
	t.Run("valid status without a usable subject", func(t *testing.T) {
		for name, mod := range map[string]func(*identity.Claims){
			"no sub":    func(c *identity.Claims) { c.Sub = "" },
			"no issuer": func(c *identity.Claims) { c.Issuer = "" },
			"no expiry": func(c *identity.Claims) { c.Expiry = time.Time{} },
		} {
			e := newSvcEnv(t)
			c := e.claims()
			mod(&c)
			e.verifier.Set(subjectToken, c, identity.StatusValid, "")
			_, err := e.svc.Exchange(ctx, e.req())
			wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectInvalid)
			_ = name
		}
	})
	t.Run("subject expiring inside the same second", func(t *testing.T) {
		e := newSvcEnv(t)
		c := e.claims()
		c.Expiry = e.now.Add(-time.Second)
		e.verifier.Set(subjectToken, c, identity.StatusValid, "")
		_, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonSubjectExpired)
	})
	t.Run("no active key", func(t *testing.T) {
		e := newSvcEnv(t)
		e.signers.err = fmt.Errorf("%w: token", keys.ErrNoActiveKey)
		got, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonSignerUnavailable)
		if got != nil {
			t.Fatal("token released")
		}
		var n int
		if err := e.db.SQL().QueryRow(`SELECT COUNT(*) FROM token_sessions`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("a session was created although no token could be minted")
		}
	})
	t.Run("assertion failure", func(t *testing.T) {
		e := newSvcEnv(t)
		r := e.req()
		r.ClientAssertion = "not.a.jws"
		_, err := e.svc.Exchange(ctx, r)
		wantReason(t, err, tokensvc.ReasonMalformed)
		if e.verifier.Calls() != 0 {
			t.Fatal("the subject token was verified for an unauthenticated agent")
		}
	})
	t.Run("session store error", func(t *testing.T) {
		e := newSvcEnv(t)
		e.sessions.setErr(errors.New("db down"))
		_, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonSessionStoreUnavailable)
	})
	t.Run("token too large", func(t *testing.T) {
		e := newSvcEnv(t)
		c := e.claims()
		c.Groups = nil
		for i := 0; i < identity.MaxGroups; i++ {
			c.Groups = append(c.Groups, fmt.Sprintf("%03d-%s", i, strings.Repeat("g", 240)))
		}
		c.Groups = append(c.Groups, "eng")
		e.verifier.Set(subjectToken, c, identity.StatusValid, "")
		got, err := e.svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeInvalidRequest, tokensvc.ReasonTokenTooLarge)
		if got != nil {
			t.Fatal("token released")
		}
		var n int
		if err := e.db.SQL().QueryRow(`SELECT COUNT(*) FROM token_sessions`).Scan(&n); err != nil || n != 0 {
			t.Fatalf("an oversized token created %d sessions (%v)", n, err)
		}
	})
	t.Run("random source failure", func(t *testing.T) {
		e := newSvcEnv(t)
		svc, err := tokensvc.New(tokensvc.Config{
			Issuer: issuer, Clients: e.v, Agents: e.agents, Blocks: e.blocks, Signers: e.signers, Sessions: e.sessions,
			Resolvers: map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(e.verifier)},
			Now:       func() time.Time { return e.now },
			Rand:      bytes.NewReader(nil),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.Exchange(ctx, e.req())
		wantErr(t, err, tokensvc.CodeTemporarilyUnavailable, tokensvc.ReasonSignerUnavailable)
	})
}

func TestExchangeSessionID(t *testing.T) {
	ctx := context.Background()
	e := newSvcEnv(t)
	exchange := func() *tokensvc.Issued {
		t.Helper()
		e.verifier.Set(subjectToken, e.claims(), identity.StatusValid, "")
		got, err := e.svc.Exchange(ctx, e.req())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("expiry is the subject expiry", func(t *testing.T) {
		c := e.claims()
		c.Expiry = e.now.Add(5 * time.Minute)
		e.verifier.Set(subjectToken, c, identity.StatusValid, "")
		got, err := e.svc.Exchange(ctx, e.req())
		if err != nil {
			t.Fatal(err)
		}
		if got.ExpiresIn != 300 || !got.Exp.Equal(e.now.Add(5*time.Minute)) {
			t.Fatalf("ExpiresIn = %d, Exp = %s", got.ExpiresIn, got.Exp)
		}
	})

	first := exchange()
	if !strings.HasPrefix(first.SID, "wts_") {
		t.Fatalf("sid = %q", first.SID)
	}
	e.now = e.now.Add(11 * time.Hour)
	if got := exchange(); got.SID != first.SID {
		t.Fatalf("sid changed within the idle window: %s -> %s", first.SID, got.SID)
	}
	e.now = e.now.Add(12*time.Hour + time.Second)
	second := exchange()
	if second.SID == first.SID {
		t.Fatal("sid reused after 12h+1s idle")
	}

	// Revoke: a subject issued before it is refused, one issued after starts
	// a new session.
	found, err := e.sessions.Revoke(ctx, second.SID, e.now)
	if err != nil || !found {
		t.Fatalf("Revoke = %v, %v", found, err)
	}
	c := e.claims()
	c.IssuedAt = e.now.Add(-time.Minute)
	e.verifier.Set(subjectToken, c, identity.StatusValid, "")
	_, err = e.svc.Exchange(ctx, e.req())
	wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonSessionRevoked)

	e.now = e.now.Add(time.Minute)
	c = e.claims()
	c.IssuedAt = e.now
	e.verifier.Set(subjectToken, c, identity.StatusValid, "")
	e.verifier.Set(subjectToken, c, identity.StatusValid, "")
	got3, err := e.svc.Exchange(ctx, e.req())
	if err != nil {
		t.Fatal(err)
	}
	third := got3
	if third.SID == second.SID || third.SID == first.SID {
		t.Fatalf("sid after a later sign-in = %s, want a new one", third.SID)
	}

	// The pre-revoke subject token stays dead even though a newer live
	// session now exists (a stolen ID token must not ride the new sign-in).
	e.now = e.now.Add(time.Minute)
	stale := e.claims()
	stale.IssuedAt = e.now.Add(-10 * time.Minute)
	stale.Expiry = e.now.Add(time.Hour)
	e.verifier.Set(subjectToken, stale, identity.StatusValid, "")
	stolen, err := e.svc.Exchange(ctx, e.req())
	wantErr(t, err, tokensvc.CodeInvalidGrant, tokensvc.ReasonSessionRevoked)
	if stolen != nil {
		t.Fatal("token released for a pre-revoke subject token")
	}
}

func TestNewValidation(t *testing.T) {
	e := newSvcEnv(t)
	base := func() tokensvc.Config {
		return tokensvc.Config{
			Issuer: issuer, Clients: e.v, Agents: e.agents, Blocks: e.blocks, Signers: e.signers, Sessions: e.sessions,
			Resolvers: map[string]tokensvc.SubjectResolver{tokensvc.TokenTypeIDToken: tokensvc.NewIDTokenResolver(e.verifier)},
			Now:       time.Now, Rand: &detRand{},
		}
	}
	if _, err := tokensvc.New(base()); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(*tokensvc.Config){
		"ttl too long":  func(c *tokensvc.Config) { c.TTL = 16 * time.Minute },
		"ttl too short": func(c *tokensvc.Config) { c.TTL = 30 * time.Second },
		"no clients":    func(c *tokensvc.Config) { c.Clients = nil },
		"no agents":     func(c *tokensvc.Config) { c.Agents = nil },
		"no blocks":     func(c *tokensvc.Config) { c.Blocks = nil },
		"no signers":    func(c *tokensvc.Config) { c.Signers = nil },
		"no sessions":   func(c *tokensvc.Config) { c.Sessions = nil },
		"no clock":      func(c *tokensvc.Config) { c.Now = nil },
		"no rand":       func(c *tokensvc.Config) { c.Rand = nil },
		"no resolvers":  func(c *tokensvc.Config) { c.Resolvers = nil },
		"nil resolver":  func(c *tokensvc.Config) { c.Resolvers = map[string]tokensvc.SubjectResolver{"x": nil} },
		"bad issuer":    func(c *tokensvc.Config) { c.Issuer = "http://cp.example.test" },
		"negative idle": func(c *tokensvc.Config) { c.SessionIdle = -1 },
	} {
		cfg := base()
		mod(&cfg)
		if _, err := tokensvc.New(cfg); err == nil {
			t.Errorf("%s: New accepted the config", name)
		}
	}
}

func TestValidateIssuer(t *testing.T) {
	for _, ok := range []string{
		"https://cp.example.test", "https://cp.example.test:8443", "https://cp.example.test/warden",
		"http://localhost:9090", "http://127.0.0.1:9090", "http://[::1]:9090",
	} {
		if err := tokensvc.ValidateIssuer(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"", "cp.example.test", "http://cp.example.test", "http://localhost.example.test", "ftp://cp.example.test",
		"https://cp.example.test/", "https://cp.example.test/warden/", "https://cp.example.test?x=1", "https://cp.example.test#f",
		"https://cp.example.test/#", "https://cp.example.test?", "https://user@cp.example.test", "https://", "https:///x",
		"https://cp.example.test ", " https://cp.example.test", "https://cp.example.test\n", "https:cp.example.test",
	} {
		if err := tokensvc.ValidateIssuer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIssuedNeverPrintsToken(t *testing.T) {
	e := newSvcEnv(t)
	got, err := e.svc.Exchange(context.Background(), e.req())
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("issued", "issued", got)
	for _, s := range []string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got), buf.String()} {
		if strings.Contains(s, got.AccessToken) || strings.Contains(s, "eyJ") || strings.Contains(s, "user-1") {
			t.Fatalf("Issued leaked: %s", s)
		}
	}
	if !strings.Contains(buf.String(), got.SID) {
		t.Fatalf("log line lacks the sid: %s", buf.String())
	}
	// By value, embedded and nil pointers never print the token either.
	byValue := *got
	type wrapper struct{ I tokensvc.Issued }
	var nilIssued *tokensvc.Issued
	var vb bytes.Buffer
	slog.New(slog.NewJSONHandler(&vb, nil)).Info("issued", "issued", byValue)
	for _, s := range []string{fmt.Sprintf("%v", byValue), fmt.Sprintf("%+v", byValue), fmt.Sprintf("%#v", byValue),
		fmt.Sprintf("%v", wrapper{byValue}), fmt.Sprintf("%v", nilIssued), vb.String()} {
		if strings.Contains(s, got.AccessToken) || strings.Contains(s, "eyJ") {
			t.Fatalf("by-value Issued leaked: %s", s)
		}
	}
}

func TestExchangeConcurrent(t *testing.T) {
	e := newSvcEnv(t)
	var wg sync.WaitGroup
	reqs := make([]tokensvc.ExchangeRequest, 20)
	for i := range reqs {
		reqs[i] = e.req()
	}
	sids := make(chan string, len(reqs))
	for _, r := range reqs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := e.svc.Exchange(context.Background(), r)
			if err != nil {
				t.Error(err)
				return
			}
			sids <- got.SID
		}()
	}
	wg.Wait()
	close(sids)
	seen := map[string]bool{}
	for s := range sids {
		seen[s] = true
	}
	if len(seen) != 1 {
		t.Fatalf("concurrent exchanges for one user and agent made %d sessions", len(seen))
	}
}
