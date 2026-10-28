package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func identityBlock(extra string) string {
	return baseAllow + "\nidentity:\n" + extra
}

func TestValidateIdentity(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // "" = valid
	}{
		{"absent block is off", baseAllow, ""},
		{"explicit off needs nothing", identityBlock("  defaultMode: off\n"), ""},
		{"attribute https", identityBlock("  defaultMode: attribute\n  issuer: https://idp.example.com\n  audience: warden\n"), ""},
		{"attribute https with internal url", identityBlock("  defaultMode: attribute\n  issuer: https://idp.example.com\n  audience: warden\n  internalIssuerURL: http://dex:5556\n"), ""},
		{"http issuer with internal url", identityBlock("  defaultMode: attribute\n  issuer: http://localhost:5556/dex\n  audience: warden\n  internalIssuerURL: http://dex:5556\n"), ""},
		{"internal url trailing slash", identityBlock("  issuer: https://i.example.com\n  internalIssuerURL: http://dex:5556/\n"), ""},
		{"http issuer rejected even when off", identityBlock("  issuer: http://dex:5556\n"), "plain http"},
		{"require is Phase 2", identityBlock("  defaultMode: require\n  issuer: https://i.example.com\n  audience: warden\n"), "Phase 2"},
		{"unknown mode", identityBlock("  defaultMode: enforce\n  issuer: https://i.example.com\n  audience: warden\n"), "invalid"},
		{"http issuer without internal url", identityBlock("  defaultMode: attribute\n  issuer: http://dex:5556\n  audience: warden\n"), "plain http"},
		{"missing issuer", identityBlock("  defaultMode: attribute\n  audience: warden\n"), "identity.issuer is required"},
		{"missing audience", identityBlock("  defaultMode: attribute\n  issuer: https://i.example.com\n"), "identity.audience is required"},
		{"internal url with path", identityBlock("  issuer: https://i.example.com\n  internalIssuerURL: http://dex:5556/dex\n"), "origin only"},
		{"internal url with query", identityBlock("  issuer: https://i.example.com\n  internalIssuerURL: http://dex:5556?x=1\n"), "origin only"},
		{"internal url with userinfo", identityBlock("  issuer: https://i.example.com\n  internalIssuerURL: http://u:p@dex:5556\n"), "origin only"},
		{"internal url non-http scheme", identityBlock("  issuer: https://i.example.com\n  internalIssuerURL: ftp://dex:5556\n"), "absolute http or https"},
		{"internal url without issuer", identityBlock("  internalIssuerURL: http://dex:5556\n"), "requires identity.issuer"},
		{"clock skew too large", identityBlock("  clockSkewSeconds: 301\n"), "clockSkewSeconds"},
		{"clock skew negative", identityBlock("  clockSkewSeconds: -1\n"), "clockSkewSeconds"},
		{"clock skew max", identityBlock("  clockSkewSeconds: 300\n"), ""},
		{"negative ttl", identityBlock("  maxTokenTTLSeconds: -5\n"), "maxTokenTTLSeconds"},
		{"agent attribute needs issuer", baseAllow + "\nagents:\n  - id: a\n    identity: attribute\n", "identity.issuer is required"},
		{"agent attribute with block", baseAllow + "\nagents:\n  - id: a\n    identity: attribute\nidentity:\n  issuer: https://i.example.com\n  audience: warden\n", ""},
		{"agent require is Phase 2", baseAllow + "\nagents:\n  - id: a\n    identity: require\n", "Phase 2"},
		{"agent unknown mode", baseAllow + "\nagents:\n  - id: a\n    identity: bogus\n", "agents[0].identity"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse([]byte(tc.yaml))
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestIdentityYAMLParseAndDefaults(t *testing.T) {
	lp, err := parse([]byte(baseAllow))
	if err != nil {
		t.Fatal(err)
	}
	p := lp.policy
	if !p.Identity.isZero() {
		t.Fatalf("absent block must be the zero value, got %+v", p.Identity)
	}
	if SettingsWireFromPolicy(p.DeepCopy()) != nil {
		t.Fatal("absent identity block must not produce settings")
	}

	lp, err = parse([]byte(baseAllow + `
identity:
  defaultMode: attribute
  issuer: https://idp.example.com
  audience: warden
  allowedAZP: [agent-harness, warden-cli]
  jwksURL: https://idp.example.com/keys
  groupsClaim: groups
  clockSkewSeconds: 30
  maxTokenTTLSeconds: 600
agents:
  - id: a
    identity: off
`))
	if err != nil {
		t.Fatal(err)
	}
	p = lp.policy
	want := IdentitySettings{
		DefaultMode: "attribute", Issuer: "https://idp.example.com", Audience: "warden",
		AllowedAZP: []string{"agent-harness", "warden-cli"}, JWKSURL: "https://idp.example.com/keys",
		GroupsClaim: "groups", ClockSkewSeconds: 30, MaxTokenTTLSeconds: 600,
	}
	if !reflect.DeepEqual(p.Identity, want) {
		t.Fatalf("identity = %+v, want %+v", p.Identity, want)
	}
	if p.Agents[0].Identity != "off" {
		t.Fatalf("agent identity = %q", p.Agents[0].Identity)
	}
	if !reflect.DeepEqual(p.DeepCopy().Identity, want) {
		t.Fatal("Policy.DeepCopy lost the identity block")
	}
}

func TestIdentityWireRoundTrip(t *testing.T) {
	w := &SettingsWire{
		Identity: &IdentitySettings{
			DefaultMode: "attribute", Issuer: "http://localhost:5556/dex", Audience: "warden",
			AllowedAZP: []string{"agent-harness", "warden-cli"}, JWKSURL: "http://dex:5556/keys",
			GroupsClaim: "groups", ClockSkewSeconds: 60, MaxTokenTTLSeconds: 3600,
			InternalIssuerURL: "http://dex:5556",
		},
		Agents: []AgentSettings{{ID: "a", Policy: "p", Identity: "attribute"}},
	}
	first, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var back SettingsWire
	if err := json.Unmarshal(first, &back); err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(&back)
	third, _ := json.Marshal(back.DeepCopy())
	if string(first) != string(second) || string(first) != string(third) {
		t.Fatalf("not byte-identical:\n%s\n%s\n%s", first, second, third)
	}

	// DeepCopy must not alias the slice.
	cp := w.DeepCopy()
	cp.Identity.AllowedAZP[0] = "mutated"
	if w.Identity.AllowedAZP[0] != "agent-harness" {
		t.Fatal("DeepCopy aliased AllowedAZP")
	}

	// Reverse projection and the agents conversion keep the mode.
	id := IdentityFromSettings(w.Identity)
	if !reflect.DeepEqual(id, *w.Identity) {
		t.Fatalf("IdentityFromSettings = %+v", id)
	}
	if AgentsFromSettings(w.Agents)[0].Identity != "attribute" {
		t.Fatal("AgentsFromSettings dropped identity")
	}
	if got := SettingsWireFromPolicy(Policy{Identity: id, Agents: AgentsFromSettings(w.Agents)}); !reflect.DeepEqual(got, w) {
		t.Fatalf("SettingsWireFromPolicy = %+v", got)
	}
}

func TestIdentityWireAbsentHasNoKey(t *testing.T) {
	b, err := json.Marshal(&SettingsWire{Advisory: &ToggleSetting{Enabled: true}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "identity") {
		t.Fatalf("wire without identity must have no identity key: %s", b)
	}
	if IdentityFromSettings(nil).DefaultMode != "" {
		t.Fatal("nil must project to the zero value")
	}
}

func TestRemotePolicyUnknownIdentityMode(t *testing.T) {
	body := `{"allowlist":[{"domain":"api.openai.com"}],"settings":{"identity":{"defaultMode":"require"},"agents":[{"id":"a","identity":"require"}]}}`
	p, s, err := parseRemotePolicy([]byte(body))
	if err != nil {
		t.Fatalf("a served unsupported mode must not fail the pull: %v", err)
	}
	if p == nil || s == nil || s.Identity == nil || s.Identity.DefaultMode != "require" {
		t.Fatalf("settings not returned intact: %+v %+v", p, s)
	}
}

func TestIdentityNoInsecureKey(t *testing.T) {
	// The removed insecure-issuer key must be rejected by the strict parser.
	key := "allowInsecure" + "Issuer"
	_, err := parse([]byte(identityBlock("  defaultMode: attribute\n  issuer: http://dex:5556\n  audience: warden\n  " + key + ": true\n")))
	if err == nil || !strings.Contains(err.Error(), key) {
		t.Fatalf("want unknown-field error naming %s, got %v", key, err)
	}
}

func TestIdentityChallengeMode(t *testing.T) {
	const block = "  defaultMode: challenge\n  issuer: http://localhost:5556/dex\n  internalIssuerURL: http://dex:5556\n  audience: warden\n  allowedAZP: [agent-harness, warden-cli]\n"

	t.Run("accepted in YAML with a signIn block", func(t *testing.T) {
		lp, err := parse([]byte(identityBlock(block + "  signIn:\n    clientID: warden-cli\n    scopes: [openid, email]\n    maxPending: 8\n    startsPerMinute: 4\n")))
		if err != nil {
			t.Fatalf("challenge must be accepted: %v", err)
		}
		si := lp.policy.Identity.SignIn
		if lp.policy.Identity.DefaultMode != IdentityModeChallenge || si == nil || si.MaxPending != 8 || si.StartsPerMinute != 4 || si.ClientID != "warden-cli" {
			t.Fatalf("identity = %+v signIn = %+v", lp.policy.Identity, si)
		}
		if !reflect.DeepEqual(lp.policy.DeepCopy().Identity, lp.policy.Identity) {
			t.Fatal("Policy.DeepCopy lost the signIn block")
		}
	})
	t.Run("accepted per agent", func(t *testing.T) {
		_, err := parse([]byte(baseAllow + "\nagents:\n  - id: a\n    identity: challenge\nidentity:\n  issuer: https://i.example.com\n  audience: warden\n"))
		if err != nil {
			t.Fatalf("agents[].identity challenge must be accepted: %v", err)
		}
	})
	t.Run("signIn defaults", func(t *testing.T) {
		var none *SignInSettings
		e := none.Effective()
		if e.ClientID != "warden-cli" || e.MaxPending != 32 || e.StartsPerMinute != 30 || !reflect.DeepEqual(e.Scopes, DefaultSignInScopes) {
			t.Fatalf("defaults = %+v", e)
		}
		e.Scopes[0] = "mutated"
		if DefaultSignInScopes[0] != "openid" {
			t.Fatal("Effective aliased the default scopes")
		}
	})
	t.Run("rejections", func(t *testing.T) {
		cases := []struct{ name, yaml, want string }{
			{"missing issuer", identityBlock("  defaultMode: challenge\n  audience: warden\n"), "identity.issuer is required"},
			{"missing audience", identityBlock("  defaultMode: challenge\n  issuer: https://i.example.com\n"), "identity.audience is required"},
			{"clientID not in allowedAZP", identityBlock(block + "  signIn:\n    clientID: other-cli\n"), "wrong_azp"},
			{"default clientID not in allowedAZP", identityBlock("  defaultMode: challenge\n  issuer: https://i.example.com\n  audience: warden\n  allowedAZP: [agent-harness]\n"), "identity.signIn.clientID"},
			{"negative maxPending", identityBlock(block + "  signIn:\n    maxPending: -1\n"), "maxPending"},
			{"huge startsPerMinute", identityBlock(block + "  signIn:\n    startsPerMinute: 100000\n"), "startsPerMinute"},
			{"scope with a space", identityBlock(block + "  signIn:\n    scopes: [\"a b\"]\n"), "scopes"},
			{"require still rejected", identityBlock("  defaultMode: require\n  issuer: https://i.example.com\n  audience: warden\n"), "Phase 2"},
			{"unknown signIn key", identityBlock(block + "  signIn:\n    clientSecret: x\n"), "clientSecret"},
		}
		for _, tc := range cases {
			_, err := parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
			}
		}
	})
	t.Run("azp unchecked when allowedAZP is empty", func(t *testing.T) {
		_, err := parse([]byte(identityBlock("  defaultMode: challenge\n  issuer: https://i.example.com\n  audience: warden\n  signIn:\n    clientID: anything\n")))
		if err != nil {
			t.Fatalf("empty allowedAZP means no azp check: %v", err)
		}
	})
	t.Run("wire round trip and deep copy", func(t *testing.T) {
		w := &SettingsWire{Identity: &IdentitySettings{
			DefaultMode: "challenge", Issuer: "http://localhost:5556/dex", Audience: "warden",
			InternalIssuerURL: "http://dex:5556",
			SignIn:            &SignInSettings{ClientID: "warden-cli", Scopes: []string{"openid"}, MaxPending: 3, StartsPerMinute: 5},
		}, Agents: []AgentSettings{{ID: "a", Identity: "challenge"}}}
		first, err := json.Marshal(w)
		if err != nil {
			t.Fatal(err)
		}
		var back SettingsWire
		if err := json.Unmarshal(first, &back); err != nil {
			t.Fatal(err)
		}
		second, _ := json.Marshal(back.DeepCopy())
		if string(first) != string(second) {
			t.Fatalf("not byte-identical:\n%s\n%s", first, second)
		}
		cp := w.DeepCopy()
		cp.Identity.SignIn.Scopes[0] = "mutated"
		cp.Identity.SignIn.MaxPending = 99
		if w.Identity.SignIn.Scopes[0] != "openid" || w.Identity.SignIn.MaxPending != 3 {
			t.Fatal("DeepCopy aliased the signIn block")
		}
		if !reflect.DeepEqual(IdentityFromSettings(w.Identity), *w.Identity) {
			t.Fatal("IdentityFromSettings changed the block")
		}
		if got := SettingsWireFromPolicy(Policy{Identity: IdentityFromSettings(w.Identity), Agents: AgentsFromSettings(w.Agents)}); !reflect.DeepEqual(got, w) {
			t.Fatalf("SettingsWireFromPolicy = %+v", got)
		}
	})
}
