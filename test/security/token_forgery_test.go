package security

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/ethosagent/warden/test/fakes"
)

// TestTokenForgeryLogin covers identity.wrong_nonce. A Warden token carries no
// nonce, so the Warden verifier answers wrong_nonce to any caller that asks
// for one, and a proxied token never asks (the worker matrix asserts the
// counter stays at zero). The one path that does ask is the console login: an
// ID token whose nonce is not the one the login started with is refused with
// nonce_mismatch, which the login maps from identity.ReasonWrongNonce.
func TestTokenForgeryLogin(t *testing.T) {
	s := StartStack(t, StackOptions{})
	s.PositiveControl(t, "cp-route", func(t *testing.T) {
		if r := s.LoginAttempt(t, consoleAdmin); r.Status != http.StatusFound || r.Header.Get("Location") == "" {
			t.Fatalf("a login with the issued nonce = %d, want a 302 to the dashboard", r.Status)
		}
	})
	Run(t, s, "cp-route", forgedNonceCases)
}

var forgedNonceCases = []Case{{
	Name:   "a console login with a forged nonce",
	Path:   PathCPRoute,
	Covers: []string{CoverIdentity("wrong_nonce")},
	Attack: func(t testing.TB, s *Stack) Observed {
		return SeenReply(s.LoginAttempt(t, consoleAdmin, fakes.WithNonce("a-nonce-the-login-never-issued")))
	},
	WantStatus: http.StatusFound, WantBody: "login_error=nonce_mismatch",
	WantReason: "wrong_nonce", WantLog: `"result":"failed","reason":"nonce_mismatch"`,
	WantAudit: "auth.login_failed",
}}

var consoleAdmin = fakes.Valid("admin-1", "admin-1@example.com", ConsoleAdminGroup)

// TestTokenExchangeSignerUnavailable: before the first token key has been
// published for the window workers need to hold it, the endpoint refuses to
// mint (503 temporarily_unavailable, Retry-After) and records the denial; once
// the window has passed on the shared clock the same agent gets a token.
func TestTokenExchangeSignerUnavailable(t *testing.T) {
	s := StartStack(t, StackOptions{})
	a := agentSetup(t, s, "agent-a")
	s.PositiveControl(t, "token", func(t *testing.T) {
		// A valid assertion authenticates and a bad subject is the refusal of
		// a verified agent: the endpoint, the agent registry and the audit of
		// refusals all work. Only the signer is not ready.
		r := s.PostToken(t, s.ExchangeForm(a, s.UserToken("user-1", []string{"eng"}, fakes.WithAlg("none")), nil))
		if r.Status != http.StatusBadRequest {
			t.Fatalf("a verified agent with a forged subject = %d %s, want 400", r.Status, r.Body)
		}
	})
	Run(t, s, "token", signerCases)
	if r, tok := s.Exchange(t, a, s.UserToken("user-1", []string{"eng"}), nil); tok == "" {
		t.Fatalf("after the publish window the exchange = %d %s, want a token", r.Status, r.Body)
	}
}

var signerCases = []Case{{
	Name:   "no published token key yet",
	Path:   PathToken,
	Covers: []string{CoverToken("signer_unavailable")},
	Attack: func(t testing.TB, s *Stack) Observed {
		return SeenReply(s.PostToken(t, s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-1", []string{"eng"}), nil)))
	},
	WantStatus: http.StatusServiceUnavailable, WantBody: `"error":"temporarily_unavailable"`,
	WantHeader: map[string]string{"Retry-After": "*"},
	WantResult: "denied", WantReason: "signer_unavailable",
}}

// TestTokenExchangeRateLimit: with the default tokenService.rateLimit the 31st
// exchange of one user within a minute is 429 with Retry-After, recorded as
// rate_limited. Each exchange before it is issued.
func TestTokenExchangeRateLimit(t *testing.T) {
	s := StartStack(t, StackOptions{DefaultTokenRate: true})
	a := agentSetup(t, s, "agent-a")
	s.PositiveControl(t, "token", func(t *testing.T) {
		if r, tok := s.Exchange(t, a, s.UserToken("user-1", []string{"eng"}), nil); tok == "" {
			t.Fatalf("exchange = %d %s, want a token", r.Status, r.Body)
		}
	})
	Run(t, s, "token", rateCases)
}

var rateCases = []Case{{
	Name:   "the 31st exchange of one user in a minute",
	Path:   PathToken,
	Covers: []string{CoverToken("rate_limited")},
	Setup: func(t testing.TB, s *Stack) {
		for i := 1; i <= 30; i++ {
			r := s.PostToken(t, s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-rate", []string{"eng"}), nil))
			if r.Status != http.StatusOK {
				t.Fatalf("exchange %d of the user = %d %s, want 200", i, r.Status, r.Body)
			}
			var out struct {
				AccessToken string `json:"access_token"`
			}
			if json.Unmarshal([]byte(r.Body), &out) == nil {
				s.Track("warden token", out.AccessToken)
			}
		}
	},
	Attack: func(t testing.TB, s *Stack) Observed {
		return SeenReply(s.PostToken(t, s.ExchangeForm(s.Agent("agent-a"), s.UserToken("user-rate", []string{"eng"}), url.Values{})))
	},
	WantStatus: http.StatusTooManyRequests, WantBody: `"error":"rate_limited"`,
	WantHeader: map[string]string{"Retry-After": "*"},
	WantResult: "denied", WantReason: "rate_limited",
}}
