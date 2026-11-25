package worker

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
)

// TestIdentityRebuildFailureKeepsSkew: a failed rebuild (the IdP verifier
// cannot be built) leaves the Warden verifier's skew as it was.
func TestIdentityRebuildFailureKeepsSkew(t *testing.T) {
	a, fake, _, buildErr, _ := identityApplier(t)
	idp := "http://idp.test"
	wire := func(skew int) *config.SettingsWire {
		w := identityWire(idp)
		w.Identity.ClockSkewSeconds = skew
		return w
	}
	fake.settings = wire(0)
	a.Apply()
	if got := a.identity.warden.ClockSkew(); got != identity.DefaultClockSkew {
		t.Fatalf("initial skew %v", got)
	}
	live := a.identity.live.v

	*buildErr = errors.New("boom")
	fake.settings = wire(200)
	a.Apply()
	if got := a.identity.warden.ClockSkew(); got != identity.DefaultClockSkew {
		t.Fatalf("a failed rebuild changed the skew to %v", got)
	}
	if a.identity.live.v != live {
		t.Fatal("a failed rebuild replaced the live verifier")
	}

	*buildErr = nil
	a.Apply()
	if got := a.identity.warden.ClockSkew(); got != 200*time.Second {
		t.Fatalf("after a good rebuild skew = %v, want 200s", got)
	}
}

// TestIdentityChallengeWithoutIdPTokensWarns: challenge mode with
// acceptDexTokens false logs one warning.
func TestIdentityChallengeWithoutIdPTokensWarns(t *testing.T) {
	no := false
	a, fake, _, _, logs := identityApplier(t)
	a.identity.canChallenge = func() bool { return true }
	idp := "http://idp.test"
	fake.settings = &config.SettingsWire{
		Identity: &config.IdentitySettings{DefaultMode: "challenge", Issuer: idp, Audience: "warden", InternalIssuerURL: idp, AcceptDexTokens: &no},
	}
	a.Apply()
	a.Apply()
	if n := strings.Count(logs.String(), "challenge mode with acceptDexTokens false"); n != 1 {
		t.Fatalf("%d warnings, want 1:\n%s", n, logs.String())
	}
}

func TestIdentityWarnings(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		name string
		s    config.IdentitySettings
		want int
	}{
		{"challenge, false", config.IdentitySettings{DefaultMode: "challenge", AcceptDexTokens: &no}, 1},
		{"challenge, true", config.IdentitySettings{DefaultMode: "challenge", AcceptDexTokens: &yes}, 0},
		{"challenge, unset", config.IdentitySettings{DefaultMode: "challenge"}, 0},
		{"attribute, false", config.IdentitySettings{DefaultMode: "attribute", AcceptDexTokens: &no}, 0},
	}
	for _, c := range cases {
		if got := len(config.IdentityWarnings(c.s, nil)); got != c.want {
			t.Errorf("%s: %d warnings, want %d", c.name, got, c.want)
		}
	}
	agents := []config.AgentPolicy{{ID: "a", Identity: "challenge"}}
	if len(config.IdentityWarnings(config.IdentitySettings{AcceptDexTokens: &no}, agents)) != 1 {
		t.Error("an agent in challenge mode did not warn")
	}
}
