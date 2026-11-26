package security

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

// Issued-token lifetime cases (W-P2-SECT-03): the exchange caps a Warden token
// at 15 minutes (and at the subject token's own expiry), and a token past exp
// plus the verifier's skew is refused on a new CONNECT.
//
// Mid-tunnel expiry (W-P2-WBND-09): a MITM-terminated tunnel opened with a token
// that then passes exp plus skew must refuse its next request. The workers share
// the stack's fake clock through worker.Overrides.Clock, which reaches the
// proxy's identity checks and its session expiry loop (leaf-cert minting stays
// on the wall clock).

const (
	keyExp1 = "issued.token"
	// verifierSkew is identity.DefaultClockSkew: the harness sets no
	// identity.clockSkewSeconds, so the workers apply the default.
	verifierSkew = 60 * time.Second
)

// expiredTokenCases: a token past exp plus skew, on a new CONNECT. The worker's
// verifier reads the shared fake clock, so the cached-valid token is spent the
// moment time passes exp plus skew.
var expiredTokenCases = []Case{{
	Name: "a token past exp plus skew on a new CONNECT is challenged",
	Path: PathWorker,
	Setup: func(t testing.TB, s *Stack) {
		exp := time.Unix(decodeClaims(t, scratchToken(s, keyExp1)).Exp, 0)
		// Inside the skew the token still serves.
		s.Clock.Advance(exp.Add(verifierSkew - time.Second).Sub(s.Clock.Now()))
		if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyExp1))); r.Status != http.StatusOK {
			t.Fatalf("a CONNECT inside the skew = %d, want 200", r.Status)
		}
		// Past it, the token is spent.
		s.Clock.Advance(2 * time.Second)
	},
	Attack: func(t testing.TB, s *Stack) Observed {
		return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyExp1))))
	},
	WantStatus: http.StatusProxyAuthRequired,
	WantBody:   "identity_required",
	WantResult: "expired",
	WantDeny:   "identity_required",
}}

func TestIssuedTokenLifetime(t *testing.T) {
	t.Run("mid_tunnel_expiry", func(t *testing.T) {
		s := StartStack(t, StackOptions{})
		a := agentSetup(t, s, "agent-a")
		s.Put(keyExp1, s.MintWardenToken(t, a, "user-1", "eng"))
		w := s.Worker("agent-a")
		tun := s.OpenTunnel(t, w, TransportConnect, scratchToken(s, keyExp1))
		if tun.Open.Status != http.StatusOK {
			t.Fatalf("the tunnel did not open: %d %s", tun.Open.Status, tun.Open.Body)
		}
		if r := tun.MustGet(t); r.Status != http.StatusOK {
			t.Fatalf("a request before exp = %d, want 200", r.Status)
		}
		hits := s.Upstream.Hits()
		exp := time.Unix(decodeClaims(t, scratchToken(s, keyExp1)).Exp, 0)
		s.Clock.Advance(exp.Add(verifierSkew + time.Second).Sub(s.Clock.Now()))
		// Refused whichever of the two gets there first: the session expiry
		// loop closes the connection, or the per-request recheck answers 403.
		if r, err := tun.Get(t); err == nil && r.Status == http.StatusOK {
			t.Errorf("a request on the tunnel past exp plus skew = %d, want it refused", r.Status)
		}
		if got := s.Upstream.Hits() - hits; got != 0 {
			t.Errorf("%d upstream hits past exp plus skew, want 0", got)
		}
		s.AssertNoLeak(t, LeakCheck{AllowSwapUpTo: s.Upstream.Hits()})
	})

	t.Run("cap", func(t *testing.T) {
		s := StartStack(t, StackOptions{})
		a := agentSetup(t, s, "agent-a")
		lifetime := func(subject string) (iat, exp int64, expiresIn string) {
			r, tok := s.Exchange(t, a, subject, nil)
			if tok == "" {
				t.Fatalf("exchange = %d %s", r.Status, r.Body)
			}
			c := decodeClaims(t, tok)
			return c.Iat, c.Exp, r.Body
		}
		// A subject token that outlives the cap (the verifier allows up to 1h): the issued token is capped at
		// 15 minutes.
		long := s.UserToken("user-1", []string{"eng"}, fakes.WithExp(s.Clock.Now().Add(50*time.Minute)))
		if iat, exp, body := lifetime(long); exp-iat != int64((15*time.Minute).Seconds()) || !strings.Contains(body, `"expires_in":900`) {
			t.Errorf("a token over a 50m subject token lives %ds (reply %s), want 900", exp-iat, body)
		}
		// A subject token that ends sooner: the issued token ends with it.
		subExp := s.Clock.Now().Add(5 * time.Minute).Truncate(time.Second)
		short := s.UserToken("user-2", []string{"eng"}, fakes.WithExp(subExp))
		if _, exp, _ := lifetime(short); exp != subExp.Unix() {
			t.Errorf("a token over a 5m subject token expires at %d, want the subject's %d", exp, subExp.Unix())
		}
		s.AssertNoLeak(t, LeakCheck{})
	})

	t.Run("expired_token", func(t *testing.T) {
		s := StartStack(t, StackOptions{})
		a := agentSetup(t, s, "agent-a")
		s.Put(keyExp1, s.MintWardenToken(t, a, "user-1", "eng"))
		s.PositiveControl(t, "worker", func(t *testing.T) {
			if r := s.Do(t, s.Worker("agent-a"), Via(TransportConnect, scratchToken(s, keyExp1))); r.Status != http.StatusOK {
				t.Fatalf("status %d, want 200", r.Status)
			}
		})
		Run(t, s, "worker", expiredTokenCases)
	})
}
