package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func tokenServiceYAML(block string) []byte {
	return []byte("policy:\n  allowlist:\n    - domain: api.example.com\n" + block)
}

func loadTokenServiceYAML(t *testing.T, block string) (TokenServiceConfig, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "warden.yaml")
	if err := os.WriteFile(path, tokenServiceYAML(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadTokenService(path)
}

const validTokenService = "tokenService:\n  enabled: true\n  issuer: https://warden.example.com\n"

// TestTokenServiceConfig covers the default, a fully set block, and every
// invalid value with the key it names.
func TestTokenServiceConfig(t *testing.T) {
	t.Run("absent block is disabled with the defaults", func(t *testing.T) {
		c, err := loadTokenServiceYAML(t, "")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(c, DefaultTokenService()) || c.Enabled || c.Issuer != "" {
			t.Fatalf("absent block = %+v", c)
		}
		if c.TTL != 15*time.Minute || c.AssertionMaxAge != 5*time.Minute || c.ClockSkew != time.Minute ||
			c.Session.Idle != 12*time.Hour || c.Session.Absolute != 168*time.Hour || c.EventRetention != 720*time.Hour ||
			!reflect.DeepEqual(c.AllowedAZP, []string{"agent-harness"}) ||
			c.RateLimit != (TokenServiceRateLimit{PerIP: "120/minute", PerAgent: "300/minute", PerUser: "30/minute", MaxInFlight: 64}) {
			t.Fatalf("defaults = %+v", c)
		}
		prov, err := parse(tokenServiceYAML(""))
		if err != nil {
			t.Fatal(err)
		}
		p, _ := prov.GetPolicy()
		if !reflect.DeepEqual(p.TokenService, c) {
			t.Fatalf("full load = %+v, want %+v", p.TokenService, c)
		}
	})

	t.Run("a full block", func(t *testing.T) {
		c, err := loadTokenServiceYAML(t, `tokenService:
  enabled: true
  issuer: https://warden.example.com/sso
  ttl: 10m
  assertionMaxAge: 2m
  clockSkew: 30s
  allowedAZP: [agent-harness, other-client]
  session:
    idle: 1h
    absolute: 24h
  rateLimit:
    perIP: 5/second
    perAgent: 10/hour
    perUser: 7/minute
    maxInFlight: 8
  eventRetention: 48h
`)
		if err != nil {
			t.Fatal(err)
		}
		want := TokenServiceConfig{
			Enabled: true, Issuer: "https://warden.example.com/sso", TTL: 10 * time.Minute,
			AssertionMaxAge: 2 * time.Minute, ClockSkew: 30 * time.Second,
			AllowedAZP:     []string{"agent-harness", "other-client"},
			Session:        TokenServiceSession{Idle: time.Hour, Absolute: 24 * time.Hour},
			RateLimit:      TokenServiceRateLimit{PerIP: "5/second", PerAgent: "10/hour", PerUser: "7/minute", MaxInFlight: 8},
			EventRetention: 48 * time.Hour,
		}
		if !reflect.DeepEqual(c, want) {
			t.Fatalf("got %+v\nwant %+v", c, want)
		}
	})

	t.Run("loopback http is accepted", func(t *testing.T) {
		for _, iss := range []string{"http://localhost:8443", "http://127.0.0.1:8443", "http://[::1]:8443"} {
			if _, err := loadTokenServiceYAML(t, "tokenService:\n  enabled: true\n  issuer: "+iss+"\n"); err != nil {
				t.Errorf("issuer %s rejected: %v", iss, err)
			}
		}
	})

	bad := []struct{ name, block, want string }{
		{"ttl above the maximum", validTokenService + "  ttl: 16m\n", "tokenService.ttl"},
		{"ttl below the minimum", validTokenService + "  ttl: 30s\n", "tokenService.ttl"},
		{"ttl not a duration", validTokenService + "  ttl: soon\n", "tokenService.ttl"},
		{"negative duration", validTokenService + "  clockSkew: -1s\n", "tokenService.clockSkew"},
		{"zero clock skew", validTokenService + "  clockSkew: 0s\n", "tokenService.clockSkew"},
		{"assertion age too long", validTokenService + "  assertionMaxAge: 1h\n", "tokenService.assertionMaxAge"},
		{"enabled without issuer", "tokenService:\n  enabled: true\n", "tokenService.issuer"},
		{"non-loopback http issuer", "tokenService:\n  enabled: true\n  issuer: http://warden.example.com\n", "loopback"},
		{"trailing slash", "tokenService:\n  enabled: true\n  issuer: https://warden.example.com/\n", "trailing slash"},
		{"query in issuer", "tokenService:\n  enabled: true\n  issuer: https://warden.example.com?x=1\n", "query"},
		{"fragment in issuer", "tokenService:\n  enabled: true\n  issuer: https://warden.example.com#x\n", "fragment"},
		{"relative issuer", "tokenService:\n  enabled: true\n  issuer: /\n", "tokenService.issuer"},
		{"userinfo in issuer", "tokenService:\n  enabled: true\n  issuer: https://user@warden.example.com\n", "absolute"},
		{"ftp issuer", "tokenService:\n  enabled: true\n  issuer: ftp://warden.example.com\n", "scheme"},
		{"bad issuer while disabled", "tokenService:\n  issuer: http://warden.example.com\n", "loopback"},
		{"empty allowedAZP", validTokenService + "  allowedAZP: []\n", "tokenService.allowedAZP"},
		{"duplicate allowedAZP", validTokenService + "  allowedAZP: [a, a]\n", "tokenService.allowedAZP"},
		{"blank allowedAZP entry", validTokenService + "  allowedAZP: [' ']\n", "tokenService.allowedAZP"},
		{"idle above absolute", validTokenService + "  session:\n    idle: 48h\n    absolute: 24h\n", "tokenService.session"},
		{"absolute too long", validTokenService + "  session:\n    absolute: 9999h\n", "tokenService.session"},
		{"rate without a period", validTokenService + "  rateLimit:\n    perIP: '120'\n", "tokenService.rateLimit.perIP"},
		{"rate with a bad period", validTokenService + "  rateLimit:\n    perAgent: 5/day\n", "tokenService.rateLimit.perAgent"},
		{"rate with a zero count", validTokenService + "  rateLimit:\n    perUser: 0/minute\n", "tokenService.rateLimit.perUser"},
		{"maxInFlight zero", validTokenService + "  rateLimit:\n    maxInFlight: 0\n", "tokenService.rateLimit.maxInFlight"},
		{"maxInFlight too big", validTokenService + "  rateLimit:\n    maxInFlight: 100000\n", "tokenService.rateLimit.maxInFlight"},
		{"retention too short", validTokenService + "  eventRetention: 1h\n", "tokenService.eventRetention"},
		{"unknown key", validTokenService + "  insecure: true\n", "insecure"},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadTokenServiceYAML(t, tc.block)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to name %q", err, tc.want)
			}
			// A full policy load refuses the same file.
			if _, perr := parse(tokenServiceYAML(tc.block)); perr == nil {
				t.Fatal("full load accepted the block LoadTokenService refused")
			}
		})
	}
}

// TestTokenServiceNotOnWire: the block is CP-local; it never reaches the
// policy JSON.
func TestTokenServiceNotOnWire(t *testing.T) {
	prov, err := parse(tokenServiceYAML("tokenService:\n  enabled: true\n  issuer: https://secret-issuer.example.com\n  allowedAZP: [secret-client]\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	low := strings.ToLower(string(b))
	if strings.Contains(low, "secret-issuer") || strings.Contains(low, "secret-client") || strings.Contains(low, "tokenservice") {
		t.Errorf("tokenService block leaked onto the policy wire: %s", b)
	}
}

// TestTokenServiceDeepCopy: a copy shares no slice with the original.
func TestTokenServiceDeepCopy(t *testing.T) {
	prov, err := parse(tokenServiceYAML(validTokenService))
	if err != nil {
		t.Fatal(err)
	}
	p, _ := prov.GetPolicy()
	cp := p.DeepCopy()
	cp.TokenService.AllowedAZP[0] = "mutated"
	if p.TokenService.AllowedAZP[0] != "agent-harness" {
		t.Fatalf("DeepCopy shares AllowedAZP: %v", p.TokenService.AllowedAZP)
	}
}
