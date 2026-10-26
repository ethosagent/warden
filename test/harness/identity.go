package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/audit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/test/fakes"
)

// The identity block WithIdentity distributes. The values are the reference
// config's: audience warden, azp from the two first-party clients.
const (
	// IdentityAudience is the audience the harness's identity block expects.
	IdentityAudience = "warden"
	// IdentityAZP is the first allowed azp; MintUserToken stamps it.
	IdentityAZP = "agent-harness"
)

var identityAllowedAZP = []string{IdentityAZP, "warden-cli"}

// WithIdentity turns on user-token verification (W-P1-VRFY-05): the policy
// gains an `identity` block whose issuer is the in-process OIDC fake (so it
// implies WithOIDCIssuer), audience "warden", allowedAZP [agent-harness,
// warden-cli] and defaultMode = mode ("attribute" or "off"). The fake is plain
// http on loopback, so internalIssuerURL is set to its own origin, which is
// what the http-issuer rule requires of a development issuer.
//
// The block rides BOTH policy sources the way a deployment's does: the control
// plane's served YAML (workers pull it as SettingsWire.Identity and hot-apply
// later changes) and the worker's local policy (boot). Signed audit receipts
// are switched on too, so a scenario can read the JSON an event signs
// (h.Receipts).
func WithIdentity(mode string) Option {
	return func(h *H) {
		h.wantIssuer = true
		h.identityMode = mode
	}
}

// MintUserToken mints a token the WithIdentity block accepts: the issuer
// fake's defaults with aud = IdentityAudience and azp = IdentityAZP, then opts
// (fakes.Valid, Expired, WrongAudience, WrongAZP, ...). The fake's own defaults
// (warden-test, warden-test-client) do not match the block, so mint through
// here, not h.Issuer().Mint, for tokens the worker should accept.
func (h *H) MintUserToken(opts ...fakes.MintOption) string {
	h.tb.Helper()
	all := append([]fakes.MintOption{fakes.WithAud(IdentityAudience), fakes.WithAZP(IdentityAZP)}, opts...)
	return h.Issuer().Mint(all...)
}

// identitySettings is the block WithIdentity distributes, or the zero value
// when the option is absent.
func (h *H) identitySettings() config.IdentitySettings {
	if h.identityMode == "" {
		return config.IdentitySettings{}
	}
	return config.IdentitySettings{
		DefaultMode:       h.identityMode,
		Issuer:            h.issuer.Issuer(),
		Audience:          IdentityAudience,
		AllowedAZP:        append([]string(nil), identityAllowedAZP...),
		InternalIssuerURL: h.issuer.Issuer(),
	}
}

// identityYAML renders the identity block for the control plane's config file
// (empty when the option is absent).
func (h *H) identityYAML() string {
	if h.identityMode == "" {
		return ""
	}
	b, err := yaml.Marshal(map[string]config.IdentitySettings{"identity": h.identitySettings()})
	if err != nil {
		h.tb.Fatalf("harness: render the identity block: %v", err)
	}
	return "\n" + string(b)
}

// receiptLogPath is worker i's signed-receipt log (JSONL, one receipt a line).
func (h *H) receiptLogPath(i int) string {
	return filepath.Join(h.root, fmt.Sprintf("worker-%d-receipts.jsonl", i))
}

// Receipts returns the events worker-1 signed, decoded from the JSON each
// receipt carries (the bytes the Ed25519 signature covers) after checking the
// signature. It first drains the oracles like Events does. Needs WithIdentity
// (the option that enables receipts).
func (h *H) Receipts() []analytics.Event {
	h.tb.Helper()
	if h.identityMode == "" {
		h.tb.Fatal("harness: Receipts needs the WithIdentity option (it enables signed receipts)")
	}
	h.awaitQuiescence()
	f, err := os.Open(h.receiptLogPath(1))
	if err != nil {
		h.tb.Fatalf("harness: open the receipt log: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []analytics.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		r, err := audit.UnmarshalReceipt(sc.Bytes())
		if err != nil {
			h.tb.Fatalf("harness: decode a receipt: %v", err)
		}
		if !audit.Verify(r, r.PublicKey) {
			h.tb.Fatalf("harness: a receipt's signature does not verify")
		}
		var ev analytics.Event
		if err := json.Unmarshal(r.EventJSON, &ev); err != nil {
			h.tb.Fatalf("harness: decode a receipt's event: %v", err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		h.tb.Fatalf("harness: read the receipt log: %v", err)
	}
	return out
}
