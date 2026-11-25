package identity_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/keys"
)

const testIdPIssuer = "https://idp.example.com"

// stubIdP is an IdP verifier that accepts every token and counts the calls.
type stubIdP struct {
	mu    sync.Mutex
	calls int
}

func (s *stubIdP) Verify(context.Context, string, ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return identity.Claims{Sub: "idp-user", Issuer: testIdPIssuer}, identity.StatusValid, ""
}

func (s *stubIdP) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// unsigned builds a token with the given header typ and iss. Its signature is
// junk: only routing is under test.
func unsigned(typ, iss string) string {
	seg := func(x any) string {
		b, _ := json.Marshal(x)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return seg(map[string]string{"alg": "RS256", "typ": typ, "kid": "k"}) + "." + seg(map[string]string{"iss": iss}) + "." + "c2ln"
}

func TestMultiVerifierDispatch(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	warden := newWarden(t, nil)
	install(t, warden, 1, testIssuer, nil, k1)
	wardenTok := mint(t, k1, wardenHdr(), goodClaims())

	build := func(accept bool, idp identity.Verifier) *identity.MultiVerifier {
		return identity.NewMultiVerifier(identity.MultiConfig{
			Warden: warden, IdP: idp, IdPIssuer: testIdPIssuer, AcceptIdP: accept,
			Now: func() time.Time { return wardenNow },
		})
	}
	ctx := context.Background()

	t.Run("a Warden token goes to the Warden verifier", func(t *testing.T) {
		idp := &stubIdP{}
		c, st, r := build(true, idp).Verify(ctx, wardenTok)
		if st != identity.StatusValid || r != "" || c.TokenType != identity.TokenWarden || c.Act != "agent-a" {
			t.Fatalf("got %+v %s/%s", c, st, r)
		}
		if idp.count() != 0 {
			t.Fatal("the IdP verifier saw a Warden token")
		}
	})
	t.Run("an IdP token is accepted when allowed", func(t *testing.T) {
		idp := &stubIdP{}
		c, st, _ := build(true, idp).Verify(ctx, unsigned("JWT", testIdPIssuer))
		if st != identity.StatusValid || c.TokenType != identity.TokenIdP || c.Sub != "idp-user" {
			t.Fatalf("got %+v %s", c, st)
		}
		if identity.SubjectFrom(c, st).AgentID != "" {
			t.Fatal("an IdP token carries no agent")
		}
	})
	t.Run("an IdP token is unbound when not accepted", func(t *testing.T) {
		idp := &stubIdP{}
		c, st, r := build(false, idp).Verify(ctx, unsigned("JWT", testIdPIssuer))
		if st != identity.StatusInvalid || r != identity.ReasonUnboundToken || c.TokenType != identity.TokenIdP {
			t.Fatalf("got %+v %s/%s", c, st, r)
		}
		if idp.count() != 0 {
			t.Fatal("a refused IdP token reached the IdP verifier")
		}
	})
	t.Run("no IdP verifier is unbound too", func(t *testing.T) {
		_, st, r := build(true, nil).Verify(ctx, unsigned("JWT", testIdPIssuer))
		if st != identity.StatusInvalid || r != identity.ReasonUnboundToken {
			t.Fatalf("got %s/%s", st, r)
		}
	})
	t.Run("any other issuer is wrong_iss", func(t *testing.T) {
		idp := &stubIdP{}
		c, st, r := build(true, idp).Verify(ctx, unsigned("JWT", "https://other.example.net"))
		if st != identity.StatusInvalid || r != identity.ReasonWrongIss || c.TokenType != identity.TokenNone {
			t.Fatalf("got %+v %s/%s", c, st, r)
		}
		if idp.count() != 0 {
			t.Fatal("a foreign issuer reached the IdP verifier")
		}
	})
	t.Run("a Warden-typed token with the IdP issuer never reaches the IdP", func(t *testing.T) {
		idp := &stubIdP{}
		_, st, r := build(true, idp).Verify(ctx, unsigned(identity.WardenTokenTyp, testIdPIssuer))
		if st != identity.StatusInvalid || r != identity.ReasonAlgNotAllowed {
			t.Fatalf("got %s/%s", st, r)
		}
		if idp.count() != 0 {
			t.Fatal("reached the IdP verifier")
		}
	})
	t.Run("the Warden issuer with a plain typ is malformed", func(t *testing.T) {
		_, st, r := build(true, &stubIdP{}).Verify(ctx, mint(t, k1, keys.Header{Typ: "JWT"}, goodClaims()))
		if st != identity.StatusInvalid || r != identity.ReasonMalformed {
			t.Fatalf("got %s/%s", st, r)
		}
	})
	t.Run("a wrong-issuer Warden token", func(t *testing.T) {
		bad := goodClaims()
		bad["iss"] = "https://other-cp.example.net"
		c, st, r := build(true, &stubIdP{}).Verify(ctx, mint(t, k1, wardenHdr(), bad))
		if st != identity.StatusInvalid || r != identity.ReasonWrongIss || c.TokenType != identity.TokenWarden {
			t.Fatalf("got %+v %s/%s", c, st, r)
		}
	})
	t.Run("malformed and oversized tokens", func(t *testing.T) {
		m := build(true, &stubIdP{})
		for _, tok := range []string{"", "abc", "a.b", "!!!.!!!.!!!", unsigned("JWT", "")[:10]} {
			if _, st, r := m.Verify(ctx, tok); st != identity.StatusInvalid || r != identity.ReasonMalformed {
				t.Errorf("%q: %s/%s", tok, st, r)
			}
		}
		if _, st, r := m.Verify(ctx, strings.Repeat("a", identity.MaxTokenBytes+1)); st != identity.StatusInvalid || r != identity.ReasonTooLarge {
			t.Errorf("too large: %s/%s", st, r)
		}
	})
	t.Run("skew comes from the Warden verifier", func(t *testing.T) {
		if got := build(true, nil).ClockSkew(); got != identity.DefaultClockSkew {
			t.Fatalf("skew = %v", got)
		}
	})
	t.Run("no Warden verifier is no dispatcher", func(t *testing.T) {
		if identity.NewMultiVerifier(identity.MultiConfig{}) != nil {
			t.Fatal("built a dispatcher without a Warden verifier")
		}
	})
}

// TestMultiVerifierWardenUnavailable: before a bundle is applied (and for a
// control plane that mints no tokens) a Warden token is unverified, not wrong_iss.
func TestMultiVerifierWardenUnavailable(t *testing.T) {
	k1 := newSigner(t, keys.AlgEdDSA)
	tok := mint(t, k1, wardenHdr(), goodClaims())
	for name, setup := range map[string]func(*identity.WardenVerifier){
		"no bundle yet":        func(*identity.WardenVerifier) {},
		"the CP mints nothing": func(v *identity.WardenVerifier) { install(t, v, 1, "", nil, k1) },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWarden(t, nil)
			setup(w)
			m := identity.NewMultiVerifier(identity.MultiConfig{Warden: w, IdP: &stubIdP{}, IdPIssuer: testIdPIssuer, AcceptIdP: true})
			c, st, r := m.Verify(context.Background(), tok)
			if st != identity.StatusUnverified || r != identity.ReasonJWKSUnavailable || c.TokenType != identity.TokenWarden {
				t.Fatalf("got %+v %s/%s", c, st, r)
			}
		})
	}
}

// TestMultiVerifierIdPDeprecationWarn: a valid IdP token logs one WARN an
// hour, with no token data.
func TestMultiVerifierIdPDeprecationWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	var mu sync.Mutex
	now := wardenNow
	m := identity.NewMultiVerifier(identity.MultiConfig{
		Warden: newWarden(t, nil), IdP: &stubIdP{}, IdPIssuer: testIdPIssuer, AcceptIdP: true, Logger: logger,
		Now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
	})
	tok := unsigned("JWT", testIdPIssuer)
	warns := func() int { return strings.Count(buf.String(), "level=WARN") }
	for i := 0; i < 5; i++ {
		m.Verify(context.Background(), tok)
	}
	if warns() != 1 {
		t.Fatalf("%d warnings for 5 tokens in one hour, want 1: %s", warns(), buf.String())
	}
	mu.Lock()
	now = now.Add(59 * time.Minute)
	mu.Unlock()
	m.Verify(context.Background(), tok)
	if warns() != 1 {
		t.Fatalf("a second warning inside the hour: %d", warns())
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	m.Verify(context.Background(), tok)
	if warns() != 2 {
		t.Fatalf("no warning after the hour: %d", warns())
	}
	if strings.Contains(buf.String(), tok) || strings.Contains(buf.String(), "idp-user") {
		t.Fatalf("the warning carries token data: %s", buf.String())
	}
}
