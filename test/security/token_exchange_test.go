package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/fakes"
)

// The /oauth2/token matrix of W-P2-SECT-02. A refusal of a verified agent (the
// client assertion authenticated, the subject or policy failed) is one denied
// token_events row; a refusal before that leaves no row, because only a
// verified agent is recorded, and is pinned through the token_exchange_denied
// debug line the control plane writes for every refusal (the stack logs the CP
// at debug level for that: the WARN of an unauthenticated caller is rate
// limited per reason and client address, so it cannot tell two cases of one
// reason apart).

// denied is the log line fragment of a refusal.
func denied(code, reason string) string {
	return `"msg":"token_exchange_denied","code":"` + code + `","reason":"` + reason + `"`
}

// exchangeCase is a refused exchange for agent-a: sub builds the subject token
// (nil: a valid one), extra overrides form fields, opts adjusts the assertion.
type exchangeCase struct {
	name   string
	sub    func(s *Stack) string
	extra  url.Values
	opts   func(s *Stack) []fakes.AssertionOption
	agent  func(s *Stack) *Agent
	status int
	body   string
	// Unverified refusals leave no row; verified ones are one denied row.
	reason     string
	code       string
	unverified bool
	covers     bool
}

func (e exchangeCase) build() Case {
	c := Case{
		Name: e.name,
		Path: PathToken,
		Attack: func(t testing.TB, s *Stack) Observed {
			a := s.Agent("agent-a")
			if e.agent != nil {
				a = e.agent(s)
			}
			sub := s.UserToken("user-1", []string{"eng"})
			if e.sub != nil {
				sub = e.sub(s)
			}
			var opts []fakes.AssertionOption
			if e.opts != nil {
				opts = e.opts(s)
			}
			return SeenReply(s.PostToken(t, s.ExchangeForm(a, sub, e.extra, opts...)))
		},
		WantStatus: e.status,
		WantBody:   e.body,
		WantReason: e.reason,
	}
	if e.unverified {
		c.Unverified = true
		c.WantLog = denied(e.code, e.reason)
	} else {
		c.WantResult = "denied"
	}
	if e.covers {
		c.Covers = []string{CoverToken(e.reason)}
	}
	return c
}

// client assertion refusals: 401 invalid_client, whatever the reason.
func badAssertion(name, reason string, opts func(s *Stack) []fakes.AssertionOption) exchangeCase {
	return exchangeCase{
		name: name, opts: opts, status: http.StatusUnauthorized, body: `"error":"invalid_client"`,
		reason: reason, code: "invalid_client", unverified: true, covers: true,
	}
}

func asOpts(o ...fakes.AssertionOption) func(*Stack) []fakes.AssertionOption {
	return func(*Stack) []fakes.AssertionOption { return o }
}

// badSubject is a verified agent presenting a subject token that does not
// verify: 400 invalid_grant subject_invalid, one denied row.
func badSubject(name string, sub func(s *Stack) string) exchangeCase {
	return exchangeCase{
		name: name, sub: sub, status: http.StatusBadRequest, body: `"error":"invalid_grant"`,
		reason: "subject_invalid", covers: true,
	}
}

var exchangeCases = func() []Case {
	rawJWK := func(s *Stack) []byte { return s.Issuer.PublicKeyPEM(s.Issuer.KIDs()[0]) }
	now := func(s *Stack) time.Time { return s.Clock.Now() }
	// agent-b is registered in TestTokenExchange: its own key, claiming agent-a.
	wrongKeyAgent := func(s *Stack) *Agent {
		return &Agent{ID: "agent-a", Key: s.Agent("agent-b").Key}
	}
	table := []exchangeCase{
		// Client assertion forgeries.
		badAssertion("assertion alg none with an empty signature", "malformed", asOpts(fakes.AssertionHeader("alg", "none"))),
		badAssertion("assertion alg None with a signature", "alg_not_allowed", asOpts(fakes.AssertionHeader("alg", "None"))),
		badAssertion("assertion HS256 keyed with the agent public JWK", "alg_not_allowed", func(s *Stack) []fakes.AssertionOption {
			return []fakes.AssertionOption{fakes.AssertionHS256(s.Agent("agent-a").Key.JWK())}
		}),
		badAssertion("assertion signed with a foreign key under the agent kid", "bad_signature", func(s *Stack) []fakes.AssertionOption {
			return []fakes.AssertionOption{fakes.AssertionSignedBy(fakes.NewAgentKey(s.tb, "foreign"))}
		}),
		badAssertion("assertion with an unknown kid", "unknown_kid", asOpts(fakes.AssertionHeader("kid", "no-such-key"))),
		badAssertion("assertion with iss different from sub", "wrong_iss", asOpts(fakes.AssertionClaim("sub", "agent-b"))),
		badAssertion("assertion for another audience", "wrong_aud", asOpts(fakes.AssertionClaim("aud", "https://attacker.example/oauth2/token"))),
		badAssertion("assertion with exp minus iat over 5 minutes", "lifetime_too_long", func(s *Stack) []fakes.AssertionOption {
			return []fakes.AssertionOption{fakes.AssertionClaim("exp", now(s).Add(10*time.Minute).Unix())}
		}),
		badAssertion("expired assertion", "expired", func(s *Stack) []fakes.AssertionOption {
			return []fakes.AssertionOption{fakes.AssertionClaim("iat", now(s).Add(-5*time.Minute).Unix()), fakes.AssertionClaim("exp", now(s).Add(-2*time.Minute).Unix())}
		}),
		badAssertion("assertion issued in the future", "not_yet_valid", func(s *Stack) []fakes.AssertionOption {
			return []fakes.AssertionOption{fakes.AssertionClaim("iat", now(s).Add(5*time.Minute).Unix()), fakes.AssertionClaim("exp", now(s).Add(8*time.Minute).Unix())}
		}),
		badAssertion("assertion without a jti", "malformed", asOpts(fakes.AssertionClaim("jti", nil))),
		badAssertion("assertion over 8 KiB", "too_large", asOpts(fakes.AssertionClaim("pad", strings.Repeat("a", 9<<10)))),
		{
			name: "assertion that is not a JWT", extra: url.Values{"client_assertion": {"not-a-jwt"}},
			status: http.StatusUnauthorized, body: `"error":"invalid_client"`, reason: "malformed", code: "invalid_client", unverified: true,
		},
		{
			name: "agent-b key claiming agent-a", agent: wrongKeyAgent,
			status: http.StatusUnauthorized, body: `"error":"invalid_client"`, reason: "unknown_kid", code: "invalid_client", unverified: true,
		},
		{
			name: "an agent nobody registered",
			agent: func(s *Stack) *Agent {
				return &Agent{ID: "agent-nobody", Key: fakes.NewAgentKey(s.tb, "nobody-key-1")}
			},
			status: http.StatusUnauthorized, body: `"error":"invalid_client"`, reason: "agent_unknown", code: "invalid_client", unverified: true, covers: true,
		},
		// Request-level refusals before the assertion is read.
		{
			name: "a subject token type the service does not resolve", extra: url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}},
			status: http.StatusBadRequest, body: `"error":"invalid_request"`, reason: "unsupported_token_type", code: "invalid_request", unverified: true, covers: true,
		},
		{
			name: "an audience other than the workers", extra: url.Values{"audience": {"https://attacker.example"}},
			status: http.StatusBadRequest, body: `"error":"invalid_target"`, reason: "invalid_target", code: "invalid_target", unverified: true, covers: true,
		},
		// Subject token forgeries and confusions, with a valid assertion.
		badSubject("subject token alg none", func(s *Stack) string { return s.UserToken("user-1", []string{"eng"}, fakes.WithAlg("none")) }),
		badSubject("subject token HS256 keyed with the issuer public key", func(s *Stack) string {
			return s.UserToken("user-1", []string{"eng"}, fakes.WithHS256(rawJWK(s)))
		}),
		badSubject("subject token signed by a foreign key under a real kid", func(s *Stack) string {
			return s.UserToken("user-1", []string{"eng"}, fakes.WithForeignKey(s.Issuer.KIDs()[0]))
		}),
		badSubject("subject token with the wrong issuer", func(s *Stack) string {
			return s.UserToken("user-1", []string{"eng"}, fakes.WithIss("https://attacker.example"))
		}),
		badSubject("subject token with the wrong audience", func(s *Stack) string {
			return s.UserToken("user-1", []string{"eng"}, fakes.WithAud("someone-else"))
		}),
		badSubject("a console audience token as the subject token", func(s *Stack) string {
			return s.UserToken("user-1", []string{"eng"}, fakes.WithAud(ConsoleClientID), fakes.WithAZP(ConsoleClientID))
		}),
		badSubject("a Warden token as the subject token", func(s *Stack) string {
			return s.ForgeWarden(s.tb, s.Agent("agent-a"), "user-1")
		}),
		{
			name: "an expired subject token", sub: func(s *Stack) string { return s.UserToken("user-1", []string{"eng"}, fakes.Expired()) },
			status: http.StatusBadRequest, body: `"error":"invalid_grant"`, reason: "subject_expired", covers: true,
		},
		{
			// 40 groups of 250 bytes verify as a subject token and then make a
			// Warden token over the 12 KiB cap.
			name: "a subject whose Warden token would be over 12 KiB",
			sub: func(s *Stack) string {
				groups := make([]string, 40)
				groups[0] = "eng"
				for i := 1; i < len(groups); i++ {
					groups[i] = fmt.Sprintf("%03d", i) + strings.Repeat("g", 247)
				}
				return s.UserToken("user-1", groups, fakes.WithGroups(groups...))
			},
			agent:  func(s *Stack) *Agent { return s.Agent("agent-a") },
			status: http.StatusBadRequest, body: `"error":"invalid_request"`, reason: "token_too_large", covers: true,
		},
	}
	var out []Case
	for _, e := range table {
		out = append(out, e.build())
	}
	return out
}()

// requestRefusals are the endpoint's own refusals of a malformed request. They
// are unauthenticated: no row, a counter and the debug line.
var requestRefusals = func() []Case {
	post := func(hdr http.Header, query string, body url.Values) func(t testing.TB, s *Stack) Observed {
		return func(t testing.TB, s *Stack) Observed {
			if hdr.Get("Content-Type") == "" {
				hdr.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			return SeenReply(s.Send(t, s.CP.HTTP, http.MethodPost, tokenPath+query, hdr, []byte(body.Encode())))
		}
	}
	valid := func(s *Stack, extra url.Values) url.Values {
		return s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-1", []string{"eng"}), extra)
	}
	refusal := func(name, reason string, status int, code string, attack func(t testing.TB, s *Stack) Observed) Case {
		return Case{
			Name: name, Path: PathToken, Attack: attack, Unverified: true,
			WantStatus: status, WantBody: `"error":"` + code + `"`, WantReason: reason, WantLog: denied(code, reason),
		}
	}
	return []Case{
		refusal("an Authorization header", "authorization_header_not_allowed", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				return post(http.Header{"Authorization": {"Bearer anything"}}, "", valid(s, nil))(t, s)
			}),
		refusal("a query string", "query_parameters_not_allowed", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				return post(http.Header{}, "?client_id=agent-a", valid(s, nil))(t, s)
			}),
		refusal("a JSON body", "unsupported_content_type", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				return SeenReply(s.Send(t, s.CP.HTTP, http.MethodPost, tokenPath, http.Header{"Content-Type": {"application/json"}}, []byte(`{}`)))
			}),
		refusal("a different grant type", "unsupported_grant_type", http.StatusBadRequest, "unsupported_grant_type",
			func(t testing.TB, s *Stack) Observed {
				return post(http.Header{}, "", valid(s, url.Values{"grant_type": {"client_credentials"}}))(t, s)
			}),
		refusal("an actor token", "unsupported_parameter", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				return post(http.Header{}, "", valid(s, url.Values{"actor_token": {"x"}}))(t, s)
			}),
		refusal("no client assertion", "client_authentication_failed", http.StatusUnauthorized, "invalid_client",
			func(t testing.TB, s *Stack) Observed {
				f := valid(s, nil)
				f.Del("client_assertion")
				return post(http.Header{}, "", f)(t, s)
			}),
		refusal("no subject token", "missing_parameter", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				f := valid(s, nil)
				f.Del("subject_token")
				return post(http.Header{}, "", f)(t, s)
			}),
		refusal("a duplicated parameter", "duplicate_parameter", http.StatusBadRequest, "invalid_request",
			func(t testing.TB, s *Stack) Observed {
				f := valid(s, nil)
				f.Add("subject_token", "second")
				return post(http.Header{}, "", f)(t, s)
			}),
		{
			// The method check runs before any logging or counting.
			Name: "a GET", Path: PathToken,
			Attack: func(t testing.TB, s *Stack) Observed {
				return SeenReply(s.Send(t, s.CP.HTTP, http.MethodGet, tokenPath, nil, nil))
			},
			WantStatus: http.StatusMethodNotAllowed, WantBody: `"error":"invalid_request"`, WantHeader: map[string]string{"Allow": "POST"},
		},
	}
}()

// replayedJTI: an accepted assertion is spent; the same jti resent within its
// lifetime is invalid_client and issues nothing.
func replayedJTI() Case {
	var form url.Values
	return Case{
		Name: "replayed jti",
		Path: PathToken,
		Setup: func(t testing.TB, s *Stack) {
			form = s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-1", []string{"eng"}), nil)
			r := s.PostToken(t, form)
			if r.Status != http.StatusOK {
				t.Fatalf("the first use of the assertion = %d, want 200", r.Status)
			}
			var tok struct {
				AccessToken string `json:"access_token"`
			}
			if json.Unmarshal([]byte(r.Body), &tok) == nil && tok.AccessToken != "" {
				s.Track("warden token", tok.AccessToken)
			}
		},
		Attack: func(t testing.TB, s *Stack) Observed {
			return SeenReply(s.PostToken(t, form))
		},
		Covers:     []string{CoverToken("replay"), CoverRoute("/oauth2/token")},
		Unverified: true,
		WantStatus: http.StatusUnauthorized, WantBody: `"error":"invalid_client"`,
		WantReason: "replay", WantLog: denied("invalid_client", "replay"),
	}
}

func TestTokenExchange(t *testing.T) {
	s := StartStack(t, StackOptions{DebugCP: true})
	a := agentSetup(t, s, "agent-a")
	b := agentSetup(t, s, "agent-b")
	s.PositiveControl(t, "token", func(t *testing.T) {
		r, tok := s.Exchange(t, a, s.UserToken("user-1", []string{"eng"}), nil)
		if tok == "" {
			t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
		}
		// agent-b's own key authenticates as agent-b, so the case that
		// presents it as agent-a fails on agent-a's key list alone.
		if r, tok := s.Exchange(t, b, s.UserToken("user-2", []string{"eng"}), nil); tok == "" {
			t.Fatalf("agent-b's own exchange = %d %s, want a token", r.Status, r.Body)
		}
	})
	Run(t, s, "token", exchangeCases)
	Run(t, s, "token", requestRefusals)
	Run(t, s, "token", []Case{replayedJTI()})
}
