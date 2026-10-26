package harness

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/clock/clocktest"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/test/fakes"
)

// newConformanceVerifier builds the REAL verifier against iss. The issuer is a
// plain-http loopback URL, which the shared OIDC client only accepts together
// with an internal issuer URL (the split-horizon opt-in); the same origin is
// passed so no rewrite happens.
func newConformanceVerifier(t *testing.T, iss *fakes.OIDCIssuer, now func() time.Time) identity.Verifier {
	t.Helper()
	v, err := oidc.NewOIDCVerifier(oidc.Config{
		Issuer:            iss.Issuer(),
		InternalIssuerURL: iss.Issuer(),
		Audience:          fakes.OIDCAudience,
		AllowedAZP:        []string{fakes.OIDCAZP},
		Now:               now,
	})
	if err != nil {
		t.Fatalf("build the real verifier: %v", err)
	}
	return v
}

func httpGet(c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func verify(t *testing.T, v identity.Verifier, tok string) (identity.Claims, identity.Status, identity.Reason) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return v.Verify(ctx, tok)
}

func wantOutcome(t *testing.T, st identity.Status, r identity.Reason, wantSt identity.Status, wantR identity.Reason) {
	t.Helper()
	if st != wantSt || r != wantR {
		t.Errorf("verdict = %q/%q, want %q/%q", st, r, wantSt, wantR)
	}
}

// TestOIDCIssuerConformance runs every Mint variant through the real verifier:
// the fake is only useful if the verifier reaches the verdict each variant is
// named for.
func TestOIDCIssuerConformance(t *testing.T) {
	setup := func(t *testing.T) (*fakes.OIDCIssuer, identity.Verifier, *clocktest.Fake) {
		clk := clocktest.NewFake(time.Now())
		iss := fakes.NewOIDCIssuer(t, fakes.WithIssuerClock(clk.Now))
		return iss, newConformanceVerifier(t, iss, clk.Now), clk
	}

	t.Run("valid", func(t *testing.T) {
		iss, v, _ := setup(t)
		for name, opt := range map[string]fakes.MintOption{"rs256": fakes.Valid("u1", "u1@example.com", "eng", "ops"), "es256": fakes.WithES256()} {
			c, st, r := verify(t, v, iss.Mint(opt, fakes.WithSID("sid-1")))
			wantOutcome(t, st, r, identity.StatusValid, "")
			if name == "rs256" && (c.Sub != "u1" || c.Email != "u1@example.com" || !c.EmailVerified || len(c.Groups) != 2 || c.SID != "sid-1") {
				t.Errorf("claims not carried: sub=%q email=%q verified=%v groups=%d sid=%q", c.Sub, c.Email, c.EmailVerified, len(c.Groups), c.SID)
			}
		}
	})
	t.Run("expired", func(t *testing.T) {
		iss, v, _ := setup(t)
		_, st, r := verify(t, v, iss.Mint(fakes.Expired()))
		wantOutcome(t, st, r, identity.StatusExpired, "")
	})
	t.Run("wrong_aud", func(t *testing.T) {
		iss, v, _ := setup(t)
		_, st, r := verify(t, v, iss.Mint(fakes.WrongAudience()))
		wantOutcome(t, st, r, identity.StatusInvalid, identity.ReasonWrongAud)
	})
	t.Run("wrong_azp", func(t *testing.T) {
		iss, v, _ := setup(t)
		_, st, r := verify(t, v, iss.Mint(fakes.WrongAZP()))
		wantOutcome(t, st, r, identity.StatusInvalid, identity.ReasonWrongAZP)
	})
	t.Run("ttl_too_long", func(t *testing.T) {
		iss, v, _ := setup(t)
		_, st, r := verify(t, v, iss.Mint(fakes.TooLong()))
		wantOutcome(t, st, r, identity.StatusInvalid, identity.ReasonTTLTooLong)
	})
	t.Run("overrides_reach_the_verdict", func(t *testing.T) {
		iss, v, _ := setup(t)
		cases := []struct {
			name string
			opt  fakes.MintOption
			st   identity.Status
			r    identity.Reason
		}{
			{"wrong_iss", fakes.WithIss("https://elsewhere.example.com"), identity.StatusInvalid, identity.ReasonWrongIss},
			{"alg_none", fakes.WithAlg("none"), identity.StatusInvalid, identity.ReasonAlgNotAllowed},
			{"unknown_kid", fakes.WithUnpublishedKey(), identity.StatusInvalid, identity.ReasonUnknownKID},
		}
		for _, c := range cases {
			_, st, r := verify(t, v, iss.Mint(c.opt))
			if st != c.st || r != c.r {
				t.Errorf("%s: verdict = %q/%q, want %q/%q", c.name, st, r, c.st, c.r)
			}
		}
		// A published kid on a token signed by another key is a bad signature.
		_, st, r := verify(t, v, iss.Mint(fakes.WithUnpublishedKey(), fakes.WithKID(iss.KIDs()[0])))
		wantOutcome(t, st, r, identity.StatusInvalid, identity.ReasonBadSignature)
	})
	t.Run("rotated_kid_one_refetch", func(t *testing.T) {
		iss, v, clk := setup(t)
		_, st, r := verify(t, v, iss.Mint())
		wantOutcome(t, st, r, identity.StatusValid, "")
		if got := iss.JWKSRequests(); got != 1 {
			t.Fatalf("JWKS requests after the first token = %d, want 1", got)
		}
		rotated := iss.Mint(fakes.RotateKey())
		// Inside the verifier's refetch floor the new kid is unknown and no
		// request is spent.
		_, st, r = verify(t, v, rotated)
		wantOutcome(t, st, r, identity.StatusInvalid, identity.ReasonUnknownKID)
		if got := iss.JWKSRequests(); got != 1 {
			t.Fatalf("JWKS requests inside the floor = %d, want still 1", got)
		}
		clk.Advance(31 * time.Second)
		rotated = iss.Mint(fakes.RotateKey()) // fresh iat/exp on the advanced clock
		_, st, r = verify(t, v, rotated)
		wantOutcome(t, st, r, identity.StatusValid, "")
		if got := iss.JWKSRequests(); got != 2 {
			t.Errorf("JWKS requests after rotation = %d, want exactly one refetch (2)", got)
		}
	})
	t.Run("issuer_stopped_cold_cache", func(t *testing.T) {
		iss, v, clk := setup(t)
		tok := iss.Mint(fakes.Valid("u1", "u1@example.com"))
		iss.Stop()
		c, st, r := verify(t, v, tok)
		wantOutcome(t, st, r, identity.StatusUnverified, identity.ReasonJWKSUnavailable)
		if c.Sub != "" {
			t.Error("an unverified verdict must not carry claims")
		}
		iss.Start()
		clk.Advance(31 * time.Second)
		_, st, r = verify(t, v, iss.Mint())
		wantOutcome(t, st, r, identity.StatusValid, "")
	})
}

// TestWithOIDCIssuer: the option starts the fake on the harness clock and
// h.Issuer() hands it out; without the option Issuer fails the test.
func TestWithOIDCIssuer(t *testing.T) {
	h := New(t, WithOIDCIssuer())
	iss := h.Issuer()
	v := newConformanceVerifier(t, iss, h.Clock().Now)
	_, st, r := verify(t, v, iss.Mint(fakes.Valid("u1", "u1@example.com")))
	wantOutcome(t, st, r, identity.StatusValid, "")
	h.Clock().Advance(2 * time.Hour) // the harness clock drives mint time too
	_, st, r = verify(t, v, iss.Mint())
	wantOutcome(t, st, r, identity.StatusValid, "")
}

// connectRecorder is a TCP listener that records each CONNECT's headers and
// refuses the tunnel, standing in for a proxy that reads Proxy-Authorization.
type connectRecorder struct {
	addr string
	mu   sync.Mutex
	got  []http.Header
}

func newConnectRecorder(t *testing.T) *connectRecorder {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &connectRecorder{addr: l.Addr().String()}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				r.mu.Lock()
				r.got = append(r.got, req.Header.Clone())
				r.mu.Unlock()
				_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); wg.Wait() })
	return r
}

func (r *connectRecorder) auths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, h := range r.got {
		out = append(out, h.Get("Proxy-Authorization"))
	}
	return out
}

// TestAgentWithProxyToken: both token agents send
// "Proxy-Authorization: Basic base64(session:<token>)" on CONNECT, and
// through the real worker they still carry traffic.
func TestAgentWithProxyToken(t *testing.T) {
	const token = "aaa.bbb-ccc_ddd.eee" // JWT-shaped, not a real credential
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("session:"+token))

	h := New(t)
	for name, h2 := range map[string]bool{"http1": false, "h2": true} {
		t.Run(name+"_sends_basic_on_connect", func(t *testing.T) {
			rec := newConnectRecorder(t)
			cl := h.proxyTokenClient(rec.addr, token, h2)
			resp, err := httpGet(cl, "https://api.example.com/x")
			if err == nil {
				_ = resp.Body.Close()
			}
			got := rec.auths()
			if len(got) != 1 {
				t.Fatalf("recorded %d Proxy-Authorization lines, want 1", len(got))
			}
			if got[0] != want { // never print the value: it carries the token
				t.Errorf("Proxy-Authorization is not Basic base64(session:<token>) (scheme %q, length %d, want length %d)",
					strings.SplitN(got[0], " ", 2)[0], len(got[0]), len(want))
			}
		})
	}

	t.Run("public_helpers_use_the_worker", func(t *testing.T) {
		api := h.Upstream("api.example.com")
		for name, cl := range map[string]*http.Client{"http1": h.AgentWithProxyToken(token), "h2": h.AgentH2WithProxyToken(token)} {
			before := len(api.Requests())
			resp, err := httpGet(cl, "https://api.example.com/ping")
			if err != nil {
				t.Fatalf("%s: GET through the worker: %v", name, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s: status = %d, want 200", name, resp.StatusCode)
			}
			if len(api.Requests()) != before+1 {
				t.Errorf("%s: upstream did not see the request", name)
			}
		}
		for _, rec := range h.AgentResponses() {
			if strings.Contains(rec.URL+"\n"+rec.Err, token) {
				t.Error("the agent transcript holds the token")
			}
		}
	})
}

// TestConnectStatusWithAuth: the raw CONNECT probe carries the header lines a
// client library never would.
func TestConnectStatusWithAuth(t *testing.T) {
	h := New(t)
	for name, auth := range map[string]string{
		"basic":     "Basic " + base64.StdEncoding.EncodeToString([]byte("session:x.y.z")),
		"bearer":    "Bearer x.y.z",
		"malformed": "Basic !!!not-base64",
		"duplicate": "Basic YTpi\r\nProxy-Authorization: Bearer x.y.z",
		"none":      "",
	} {
		if got := h.ConnectStatusWithAuth("evil.example.test:443", auth); got != http.StatusForbidden {
			t.Errorf("%s: CONNECT to a non-allowlisted host = %d, want 403", name, got)
		}
	}
	if got := h.ConnectStatusWithAuth("api.example.com:443", "Bearer x.y.z"); got != http.StatusOK {
		t.Errorf("CONNECT to an allowlisted host with a Bearer credential = %d, want 200", got)
	}
}
