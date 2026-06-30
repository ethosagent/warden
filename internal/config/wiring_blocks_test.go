package config

import (
	"testing"
	"time"
)

const baseAllow = `
policy:
  allowlist:
    - domain: api.openai.com
`

func TestParseWiringBlocks(t *testing.T) {
	yaml := baseAllow + `
auth:
  - match: api.stripe.com
    type: hmac
    algorithm: sha256
    secret: ${STRIPE_SECRET}
    header: Stripe-Signature
  - match: api.sendgrid.com
    type: api_key
    location: header
    name: Authorization
    value: "Bearer ${SENDGRID}"
controlPlane:
  endpoint: https://cp.example.com/policy
  tokenEnv: CP_TOKEN
  pollInterval: 15s
central:
  mode: worker
  endpoint: https://agg.example.com/central/ingest
  proxyID: edge-1
audit:
  signedReceipts:
    enabled: true
    log: /var/log/warden/receipts.jsonl
  compliance:
    enabled: true
`
	p, err := parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	pol := p.policy
	if len(pol.Auth) != 2 {
		t.Fatalf("auth entries = %d, want 2", len(pol.Auth))
	}
	if pol.Auth[0].Type != AuthHMAC || pol.Auth[0].Secret != "${STRIPE_SECRET}" {
		t.Errorf("auth[0] not parsed: %+v", pol.Auth[0])
	}
	if pol.ControlPlane.Endpoint != "https://cp.example.com/policy" || pol.ControlPlane.PollInterval != 15*time.Second {
		t.Errorf("controlPlane not parsed: %+v", pol.ControlPlane)
	}
	if pol.Central.Mode != "worker" || pol.Central.BatchSize != defaultCentralBatchSize {
		t.Errorf("central not parsed/defaulted: %+v", pol.Central)
	}
	if !pol.Audit.SignedReceipts.Enabled || pol.Audit.SignedReceipts.Log == "" || !pol.Audit.Compliance.Enabled {
		t.Errorf("audit not parsed: %+v", pol.Audit)
	}
}

func TestWiringValidationErrors(t *testing.T) {
	cases := map[string]string{
		"hmac bad algorithm": baseAllow + `
auth:
  - match: x.com
    type: hmac
    algorithm: md5
    secret: s
    header: H
`,
		"api_key bad location": baseAllow + `
auth:
  - match: x.com
    type: api_key
    location: query
    name: k
    value: v
`,
		"unknown auth type": baseAllow + `
auth:
  - match: x.com
    type: bogus
`,
		"controlPlane non-https": baseAllow + `
controlPlane:
  endpoint: http://cp.example.com/policy
`,
		"central worker without endpoint": baseAllow + `
central:
  mode: worker
`,
		"central bad mode": baseAllow + `
central:
  mode: sideways
`,
		"signed receipts without log": baseAllow + `
audit:
  signedReceipts:
    enabled: true
`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(yaml)); err == nil {
				t.Fatalf("expected validation error for %q, got nil", name)
			}
		})
	}
}
