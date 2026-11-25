package security

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/test/fakes"
)

// The worker matrix of W-P2-SECT-02: forged, malformed, expired and confused
// tokens presented to agent-a's worker. The stack runs in challenge mode:
// config validation still refuses identity mode "require" (W-P2-WBND-03), so a
// credential the worker will not accept is answered 407 with the Basic
// challenge instead of the 403 identity_required of a require-mode terminated
// or MCP request. The transport column is therefore the same for every case;
// the three transports are exercised for the two attacks the ticket names
// (alg none and unknown kid), and the control proves all three accept a good
// token. When require lands, switch StackOptions.IdentityMode (stack.go) and
// pin the 403 shapes here.

// workerRefusal is one refused credential: 407 with the Basic challenge, one
// count under the pinned result and reason and token type, a deny event, and no
// request upstream. tok builds the credential.
func workerRefusal(name, result, reason, tokenType string, tr Transport, tok func(t testing.TB, s *Stack) string) Case {
	c := Case{
		Name: name,
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(tr, tok(t, s))))
		},
		WantStatus:       http.StatusProxyAuthRequired,
		WantHeader:       map[string]string{"Proxy-Authenticate": `Basic realm="warden"`},
		WantBody:         "identity_required",
		WantResult:       result,
		WantReason:       reason,
		WantTokenType:    tokenType,
		WantDeny:         "identity_required",
		WantUpstreamHits: 0,
	}
	if result == "invalid" {
		c.Covers = []string{CoverIdentity(reason)}
	}
	return c
}

// workerAccept is a credential the worker accepts: 200 from the upstream, one
// valid verification, exactly one request upstream.
func workerAccept(name, tokenType string, tr Transport, tok func(t testing.TB, s *Stack) string) Case {
	return Case{
		Name: name,
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(tr, tok(t, s))))
		},
		WantStatus:       http.StatusOK,
		WantResult:       "valid",
		WantTokenType:    tokenType,
		WantUpstreamHits: 1,
	}
}

// forged builds a Warden-shaped token for user-1 as agent-a, edited by opts.
func forged(opts ...TokenOption) func(t testing.TB, s *Stack) string {
	return func(t testing.TB, s *Stack) string {
		return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", opts...)
	}
}

// relative is a Unix time d from the shared clock's now.
func relative(s *Stack, d time.Duration) int64 {
	return s.Clock.Now().Truncate(time.Second).Add(d).Unix()
}

// skewBounds is identity.clockSkewSeconds of the stack that runs the time
// bound cases (the maximum, 300s): a margin of seconds around it needs a clock
// that does not drift, and the proxy re-checks a tunnel's expiry on the real
// clock (the worker's proxy takes no clock override), which runs ahead of the
// stack's frozen one by however long the test has been running.
const skewBounds = 300 * time.Second

// defaultSkew is the verifier's default tolerance, 60s (the fuzz seeds use it).
const defaultSkew = 60 * time.Second

// insideSkew is how far inside the tolerance an accepted expired token is: far
// more than the real clock's drift over a slow run can eat.
const insideSkew = 2 * time.Minute

// forgedAt edits a token's time claims relative to the stack's clock.
func forgedAt(edit func(s *Stack) []TokenOption) func(t testing.TB, s *Stack) string {
	return func(t testing.TB, s *Stack) string {
		return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", edit(s)...)
	}
}

// A token expired by skew+5s is refused; one expired by skew-5s is accepted:
// the leeway is exercised from both sides (the lifetime stays short of the
// 15 minute cap and iat stays before exp).
var wardenForgeries = func() []Case {
	var out []Case
	// alg none and an unknown kid on all three transports.
	for _, tr := range Transports {
		tr := tr
		out = append(out,
			workerRefusal("alg none with an empty signature over "+string(tr), "invalid", "malformed", "warden", tr, forged(Unsigned())),
			workerRefusal("alg none with a signature over "+string(tr), "invalid", "alg_not_allowed", "warden", tr, forged(Header("alg", "none"), JunkSignature())),
			workerRefusal("unknown kid over "+string(tr), "invalid", "unknown_kid", "warden", tr, forged(Header("kid", "no-such-key-id"))),
		)
	}
	out = append(out,
		workerRefusal("HS256 keyed with the public JWK bytes", "invalid", "alg_not_allowed", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string {
				return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", HMAC(s.TokenJWK(t)))
			}),
		workerRefusal("alg RS256", "invalid", "alg_not_allowed", "warden", TransportConnect, forged(Header("alg", "RS256"), JunkSignature())),
		workerRefusal("alg swapped to the other allowed algorithm", "invalid", "alg_not_allowed", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string {
				other := "ES256"
				if s.TokenKey(t).Alg() == "ES256" {
					other = "EdDSA"
				}
				return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", Header("alg", other))
			}),
		workerRefusal("flipped signature bytes", "invalid", "bad_signature", "warden", TransportConnect, forged(FlippedSignature())),
		workerRefusal("a foreign key under a real kid", "invalid", "bad_signature", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string {
				return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", SignedBy(s.ForeignSigner(t)))
			}),
		workerRefusal("a token signed by the bundle key", "invalid", "unknown_kid", "warden", TransportConnect,
			func(t testing.TB, s *Stack) string {
				bk := s.BundleKey(t)
				return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", SignedBy(bk), Header("kid", bk.KID()), Header("alg", bk.Alg()))
			}),
		workerRefusal("an embedded jwk header", "invalid", "malformed", "warden", TransportConnect, forged(Header("jwk", map[string]string{"kty": "OKP"}))),
		workerRefusal("a jku header", "invalid", "malformed", "warden", TransportConnect, forged(Header("jku", "https://attacker.example/keys"))),
		workerRefusal("an x5u header", "invalid", "malformed", "warden", TransportConnect, forged(Header("x5u", "https://attacker.example/cert"))),
		workerRefusal("an unknown crit header", "invalid", "malformed", "warden", TransportConnect, forged(Header("crit", []string{"exp-ext"}), Header("exp-ext", true))),
		workerRefusal("a five segment JWE shape", "invalid", "malformed", "none", TransportConnect,
			func(t testing.TB, s *Stack) string {
				seg := Segments(s.ForgeWarden(t, s.Agent("agent-a"), "user-1"))
				enc := base64.RawURLEncoding.EncodeToString
				return strings.Join([]string{seg[0], enc([]byte("key")), enc([]byte("iv")), seg[1], enc([]byte("tag"))}, ".")
			}),
		workerRefusal("a token over 16 KiB", "invalid", "too_large", "none", TransportConnect, forged(Claim("pad", strings.Repeat("a", 17<<10)))),
		workerRefusal("a Warden token without the wt+jwt type, routed by its issuer", "invalid", "malformed", "warden", TransportConnect, forged(WithoutHeader("typ"))),
		workerRefusal("wrong iss", "invalid", "wrong_iss", "warden", TransportConnect, forged(Claim("iss", "https://attacker.example"))),
		workerRefusal("wrong aud", "invalid", "wrong_aud", "warden", TransportConnect, forged(Claim("aud", "warden"))),
		workerRefusal("missing exp", "invalid", "malformed", "warden", TransportConnect, forged(WithoutClaim("exp"))),
		workerRefusal("exp minus iat over 15 minutes", "invalid", "ttl_too_long", "warden", TransportConnect,
			forgedAt(func(s *Stack) []TokenOption {
				return []TokenOption{Claim("exp", relative(s, 20*time.Minute))}
			})),
		workerRefusal("missing sub", "invalid", "missing_claim", "warden", TransportConnect, forged(WithoutClaim("sub"))),
		workerRefusal("missing act.sub", "invalid", "missing_claim", "warden", TransportConnect, forged(Claim("act", map[string]any{}))),
		workerRefusal("missing cnf.jkt", "invalid", "missing_claim", "warden", TransportConnect, forged(WithoutClaim("cnf"))),
	)
	return out
}()

// wardenTimeBounds are the tolerance cases: the leeway is exercised from both
// sides, each token otherwise valid and signed by the control plane's key.
var wardenTimeBounds = []Case{
	workerRefusal("expired by the skew plus 5s", "expired", "", "warden", TransportConnect,
		forgedAt(func(s *Stack) []TokenOption {
			return []TokenOption{Claim("iat", relative(s, -10*time.Minute)), Claim("exp", relative(s, -(skewBounds+ForgedSkew)))}
		})),
	workerRefusal("not yet valid by the skew plus 5s", "invalid", "malformed", "warden", TransportConnect,
		forgedAt(func(s *Stack) []TokenOption { return []TokenOption{Claim("nbf", relative(s, skewBounds+ForgedSkew))} })),
	workerRefusal("issued in the future by the skew plus 5s", "invalid", "malformed", "warden", TransportConnect,
		forgedAt(func(s *Stack) []TokenOption {
			return []TokenOption{Claim("iat", relative(s, skewBounds+ForgedSkew)), Claim("nbf", relative(s, 0))}
		})),
	// Boundary controls: inside the tolerance the same tokens are accepted.
	workerAccept("expired by the skew minus 2 minutes is still accepted", "warden", TransportConnect,
		forgedAt(func(s *Stack) []TokenOption {
			return []TokenOption{Claim("iat", relative(s, -10*time.Minute)), Claim("exp", relative(s, -(skewBounds-insideSkew)))}
		})),
	workerAccept("not yet valid by the skew minus 5s is still accepted", "warden", TransportConnect,
		forgedAt(func(s *Stack) []TokenOption { return []TokenOption{Claim("nbf", relative(s, skewBounds-ForgedSkew))} })),
}

func workerControl(s *Stack) func(t *testing.T) {
	return func(t *testing.T) {
		cred := s.ForgeWarden(t, s.Agent("agent-a"), "user-1")
		for _, tr := range Transports {
			if r := s.Do(t, s.Worker("agent-a"), Via(tr, cred)); r.Status != http.StatusOK {
				t.Fatalf("%s: a template token = %d, want 200", tr, r.Status)
			}
		}
	}
}

// userToken is a raw IdP ID token for user-1 the identity block accepts, edited
// by opts.
func userToken(opts ...fakes.MintOption) func(t testing.TB, s *Stack) string {
	return func(t testing.TB, s *Stack) string { return s.UserToken("user-1", []string{"eng"}, opts...) }
}

// idpCases are the cross-type cases on a worker that accepts IdP tokens.
var idpCases = []Case{
	workerAccept("raw IdP token is accepted where IdP tokens are accepted", "idp", TransportConnect, userToken()),
	workerRefusal("IdP token with the wrong azp", "invalid", "wrong_azp", "idp", TransportConnect, userToken(fakes.WrongAZP())),
	workerRefusal("a console audience token", "invalid", "wrong_aud", "idp", TransportConnect,
		userToken(fakes.WithAud(ConsoleClientID), fakes.WithAZP(ConsoleClientID))),
	workerRefusal("an expired IdP token", "expired", "", "idp", TransportConnect, userToken(fakes.Expired())),
	workerRefusal("an IdP token from another issuer", "invalid", "wrong_iss", "none", TransportConnect, userToken(fakes.WithIss("https://attacker.example"))),
	// An IdP token presented as a Warden token: the wt+jwt type or the Warden
	// issuer routes it to the Warden verifier, which refuses its RS256.
	workerRefusal("an IdP token typed as a Warden token", "invalid", "alg_not_allowed", "warden", TransportConnect,
		userToken(fakes.WithHeader("typ", identity.WardenTokenTyp))),
	workerRefusal("an IdP token claiming the Warden issuer", "invalid", "alg_not_allowed", "warden", TransportConnect,
		userToken(fakes.WithIss(TokenIssuer))),
	// A Warden token presented as an IdP token: routed by its iss to the IdP
	// verifier, which holds no key for it.
	workerRefusal("a Warden token claiming the IdP issuer", "invalid", "alg_not_allowed", "idp", TransportConnect,
		func(t testing.TB, s *Stack) string {
			return s.ForgeWarden(t, s.Agent("agent-a"), "user-1", Claim("iss", s.Issuer.Issuer()), WithoutHeader("typ"))
		}),
	{
		Name: "different valid subjects on Proxy-Authorization and X-Warden-Identity conflict",
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			a := s.Agent("agent-a")
			r := Request{Transport: TransportTerminated,
				ConnectToken: Str(s.ForgeWarden(t, a, "user-1")), HeaderToken: Str(s.ForgeWarden(t, a, "user-2"))}
			return Seen(s.Do(t, s.Worker("agent-a"), r))
		},
		WantStatus:       http.StatusForbidden,
		WantBody:         "identity_conflict",
		WantResult:       "conflict",
		WantDeny:         "identity_conflict",
		WantUpstreamHits: 0,
	},
}

func TestTokenWorker(t *testing.T) {
	t.Run("forgeries", func(t *testing.T) {
		s := StartStack(t, StackOptions{})
		agentSetup(t, s, "agent-a")
		s.PositiveControl(t, "worker", workerControl(s))
		Run(t, s, "worker", wardenForgeries)
		// A proxied token can never answer a console login: wrong_nonce is not
		// among the reasons the worker counted.
		if n := s.Metric(t, s.Worker("agent-a"), "warden_identity_verify_total", map[string]string{"reason": "wrong_nonce"}); n != 0 {
			t.Errorf("warden_identity_verify_total{reason=wrong_nonce} = %v, want 0", n)
		}
	})
	t.Run("clock skew bounds", func(t *testing.T) {
		s := StartStack(t, StackOptions{ClockSkewSeconds: int(skewBounds / time.Second)})
		agentSetup(t, s, "agent-a")
		s.PositiveControl(t, "worker", workerControl(s))
		Run(t, s, "worker", wardenTimeBounds)
	})
	t.Run("type confusion with IdP tokens accepted", func(t *testing.T) {
		s := StartStack(t, StackOptions{})
		agentSetup(t, s, "agent-a")
		s.PositiveControl(t, "worker", workerControl(s))
		Run(t, s, "worker", idpCases)
	})
	// A valid raw IdP ID token never satisfies agent binding when the worker
	// does not accept them: unbound_token, whatever the user is.
	t.Run("raw dex token with acceptDexTokens false", func(t *testing.T) {
		off := false
		s := StartStack(t, StackOptions{AcceptDexTokens: &off})
		agentSetup(t, s, "agent-a")
		s.PositiveControl(t, "worker", workerControl(s))
		Run(t, s, "worker", rawDexRefused)
	})
}

// TestTokenWorkerAttribute: an agent in attribute mode is never challenged. A
// raw IdP token gives attribution only: the request is allowed by policy and
// the event carries the user; a forged token is not attributed to anyone.
func TestTokenWorkerAttribute(t *testing.T) {
	s := StartStack(t, StackOptions{AgentModes: map[string]string{"agent-a": "attribute"}})
	agentSetup(t, s, "agent-a")
	w := s.Worker("agent-a")
	s.PositiveControl(t, "worker", func(t *testing.T) {
		if r := s.Do(t, w, Via(TransportConnect, s.UserToken("user-1", []string{"eng"}))); r.Status != http.StatusOK {
			t.Fatalf("a raw IdP token in attribute mode = %d, want 200", r.Status)
		}
	})
	attributed := func(sub string) bool {
		for _, e := range s.AllEvents(t, w) {
			if e.UserSub == sub && e.IdentityStatus == "valid" && e.IdentityTokenType == "idp" {
				return true
			}
		}
		return false
	}
	s.WaitIdle(t)
	if !attributed("user-1") {
		t.Fatal("the control request carries no attributed identity (user-1, valid, idp)")
	}
	Run(t, s, "worker", []Case{{
		Name: "raw Dex token in attribute mode is allowed and attributed",
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, s.UserToken("user-2", []string{"eng"}))))
		},
		WantStatus: http.StatusOK, WantResult: "valid", WantTokenType: "idp", WantUpstreamHits: 1,
	}, {
		Name: "a forged token in attribute mode is allowed but never attributed",
		Path: PathWorker,
		Attack: func(t testing.TB, s *Stack) Observed {
			return Seen(s.Do(t, s.Worker("agent-a"), Via(TransportConnect, s.ForgeWarden(t, s.Agent("agent-a"), "user-3", FlippedSignature()))))
		},
		WantStatus: http.StatusOK, WantResult: "invalid", WantReason: "bad_signature", WantTokenType: "warden", WantUpstreamHits: 1,
	}})
	s.WaitIdle(t)
	if !attributed("user-2") {
		t.Error("the raw IdP token was allowed but the event carries no attributed identity")
	}
	for _, e := range s.AllEvents(t, w) {
		if e.UserSub == "user-3" {
			t.Error("a forged token's subject was attributed in the event log")
		}
	}
}

var rawDexRefused = func() []Case {
	var out []Case
	for _, tr := range Transports {
		out = append(out, workerRefusal("raw Dex token over "+string(tr), "invalid", "unbound_token", "idp", tr, userToken()))
	}
	return append(out,
		workerRefusal("raw Dex token with the wrong azp", "invalid", "unbound_token", "idp", TransportConnect, userToken(fakes.WrongAZP())))
}()
