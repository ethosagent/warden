package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// idpDeprecationInterval is the shortest gap between two deprecation warnings
// for accepted IdP tokens.
const idpDeprecationInterval = time.Hour

// MultiConfig configures NewMultiVerifier.
type MultiConfig struct {
	// Warden verifies the tokens the control plane mints. Required.
	Warden *WardenVerifier
	// IdP verifies user tokens from the configured identity provider. nil
	// means there is none (no identity.issuer).
	IdP Verifier
	// IdPIssuer is identity.issuer: the iss that selects the IdP path, also
	// when AcceptIdP is false (the token is then refused as unbound).
	IdPIssuer string
	// AcceptIdP is identity.acceptDexTokens resolved: whether IdP tokens are
	// accepted at all. false refuses them as invalid/unbound_token.
	AcceptIdP bool
	// Logger receives at most one deprecation warning per hour for accepted IdP
	// tokens. It carries no token data. nil logs nothing.
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// MultiVerifier is the worker's identity verifier once a control plane can mint
// Warden tokens: it reads the unverified iss (after the size cap) and sends the
// token to the verifier that owns that issuer. It never lets one issuer's keys
// vouch for another's tokens.
//
//   - A Warden token (the bundle's tokenIssuer, or the wt+jwt header type) goes
//     to the WardenVerifier, which answers unverified/jwks_unavailable while it
//     holds no usable bundle snapshot.
//   - iss equal to identity.issuer goes to the IdP verifier when IdP tokens are
//     accepted, and is invalid/unbound_token when they are not.
//   - Any other iss is invalid/wrong_iss.
//
// Every result carries Claims.TokenType, so the metric label and later binding
// know which kind of token they hold.
type MultiVerifier struct {
	warden    *WardenVerifier
	idp       Verifier
	idpIssuer string
	accept    bool
	log       *slog.Logger
	now       func() time.Time

	warnMu   sync.Mutex
	lastWarn time.Time
}

// NewMultiVerifier builds the dispatcher. A missing Warden verifier is the
// only invalid input; it returns nil, which callers treat as "no verifier".
func NewMultiVerifier(cfg MultiConfig) *MultiVerifier {
	if cfg.Warden == nil {
		return nil
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &MultiVerifier{
		warden: cfg.Warden, idp: cfg.IdP, idpIssuer: cfg.IdPIssuer,
		accept: cfg.AcceptIdP && cfg.IdP != nil, log: cfg.Logger, now: cfg.Now,
	}
}

// ClockSkew returns the exp tolerance, which the proxy applies when it
// re-checks a CONNECT identity's expiry on each later request.
func (m *MultiVerifier) ClockSkew() time.Duration { return m.warden.ClockSkew() }

// Verify implements Verifier.
func (m *MultiVerifier) Verify(ctx context.Context, raw string, opts ...VerifyOption) (Claims, Status, Reason) {
	none := Claims{TokenType: TokenNone}
	if len(raw) > MaxTokenBytes {
		return none, StatusInvalid, ReasonTooLarge
	}
	if raw == "" {
		return none, StatusInvalid, ReasonMalformed
	}
	typ, iss, ok := peekRouting(raw)
	if !ok {
		return none, StatusInvalid, ReasonMalformed
	}
	snap := m.warden.Snapshot()
	switch {
	case typ == WardenTokenTyp, snap != nil && snap.issuer != "" && iss == snap.issuer:
		return m.warden.Verify(ctx, raw, opts...)
	case m.idpIssuer != "" && iss == m.idpIssuer:
		if !m.accept {
			return Claims{TokenType: TokenIdP}, StatusInvalid, ReasonUnboundToken
		}
		c, st, r := m.idp.Verify(ctx, raw, opts...)
		c.TokenType = TokenIdP
		if st == StatusValid {
			m.warnIdP()
		}
		return c, st, r
	}
	return none, StatusInvalid, ReasonWrongIss
}

// warnIdP logs the IdP-token deprecation at most once an hour.
func (m *MultiVerifier) warnIdP() {
	if m.log == nil {
		return
	}
	now := m.now()
	m.warnMu.Lock()
	due := m.lastWarn.IsZero() || now.Sub(m.lastWarn) >= idpDeprecationInterval
	if due {
		m.lastWarn = now
	}
	m.warnMu.Unlock()
	if due {
		m.log.Warn("identity: accepting IdP tokens directly is deprecated; agents should exchange them for Warden tokens (set identity.acceptDexTokens=false once they do)")
	}
}

// peekRouting reads the JOSE typ header and the iss claim of a compact token
// without verifying anything. It is used only to choose a verifier; the chosen
// verifier checks everything again. ok is false for a token that is not three
// base64url segments with a JSON header and payload.
func peekRouting(raw string) (typ, iss string, ok bool) {
	h, rest, found := strings.Cut(raw, ".")
	if !found {
		return "", "", false
	}
	p, _, found := strings.Cut(rest, ".")
	if !found {
		return "", "", false
	}
	hb, err := base64.RawURLEncoding.DecodeString(h)
	if err != nil {
		return "", "", false
	}
	pb, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		return "", "", false
	}
	var hdr struct {
		Typ string `json:"typ"`
	}
	var body struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(hb, &hdr) != nil || json.Unmarshal(pb, &body) != nil {
		return "", "", false
	}
	return hdr.Typ, body.Iss, true
}
