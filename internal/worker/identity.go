package worker

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/identity/adapters/oidc"
	"github.com/ethosagent/warden/internal/proxy"
)

// identityWiring owns the worker's user-token verifier: it builds it from the
// identity block, resolves this agent's mode, hands both to the proxy, and on a
// settings change rebuilds the verifier only when a verifier input moved.
//
// It is touched from boot and from the single apply goroutine, never
// concurrently, so it needs no lock; the proxy swap itself is atomic.
type identityWiring struct {
	p       *proxy.Proxy
	agentID string
	logger  *slog.Logger
	// build is oidc.NewOIDCVerifier in production; a test substitutes it to
	// count rebuilds. It does no network I/O, so boot and a hot reload never
	// contact the issuer.
	build func(oidc.Config) (identity.Verifier, error)
	// buildSignIn builds the challenge-mode sign-in starter; a test
	// substitutes it. It does no network I/O.
	buildSignIn func(config.IdentitySettings) (proxy.SignInStarter, error)
	// canChallenge reports whether the proxy has a CONNECT listener (nil means
	// ask the proxy); a test substitutes it for a transparent-only worker.
	canChallenge func() bool

	// live is the identity config the proxy is serving: the verifier (nil when
	// off), the inputs it was built from, and the mode.
	live liveIdentity

	// scoped returns how many live allow entries are identity-scoped (nil =
	// unknown, no warning). warned is the count already warned about while the
	// mode is off, so the WARN repeats only when that count changes.
	scoped func() int
	warned int
}

type liveIdentity struct {
	v    identity.Verifier
	key  verifierKey
	mode proxy.IdentityMode
	// starter and signInKey are the challenge-mode sign-in starter and the
	// settings it was built from (nil/"" until challenge was applied).
	starter   proxy.SignInStarter
	signInKey string
}

// verifierKey is every setting that changes what the verifier accepts. The
// mode is deliberately absent: a mode change swaps the mode and reuses the
// verifier. AllowedAZP is joined into a string so the key stays comparable.
type verifierKey struct {
	issuer, internalIssuerURL, audience, jwksURL, groupsClaim string
	allowedAZP                                                string
	skewSeconds, ttlSeconds                                   int
}

func keyOf(s config.IdentitySettings) verifierKey {
	return verifierKey{
		issuer: s.Issuer, internalIssuerURL: s.InternalIssuerURL, audience: s.Audience,
		jwksURL: s.JWKSURL, groupsClaim: s.GroupsClaim,
		allowedAZP:  fmt.Sprintf("%q", s.AllowedAZP),
		skewSeconds: s.ClockSkewSeconds, ttlSeconds: s.MaxTokenTTLSeconds,
	}
}

func newIdentityWiring(p *proxy.Proxy, agentID string, logger *slog.Logger) *identityWiring {
	return &identityWiring{p: p, agentID: agentID, logger: logger, build: oidc.NewOIDCVerifier, buildSignIn: newSignInStarter}
}

// newSignInStarter builds the device-authorization starter for challenge mode.
// Its HTTP client rewrites the issuer's origin to internalIssuerURL, like the
// verifier's, so a split-horizon issuer is reached from the worker's network.
func newSignInStarter(s config.IdentitySettings) (proxy.SignInStarter, error) {
	hc, err := oidc.NewHTTPClient(oidc.HTTPClientConfig{Issuer: s.Issuer, InternalIssuerURL: s.InternalIssuerURL})
	if err != nil {
		return nil, err
	}
	si := s.SignIn.Effective()
	return proxy.NewDeviceStarter(proxy.DeviceStarterConfig{
		Issuer: s.Issuer, ClientID: si.ClientID, Scopes: si.Scopes,
		MaxPending: si.MaxPending, StartsPerMinute: si.StartsPerMinute, HTTP: hc,
	})
}

// signInKey is every sign-in setting that changes the starter it builds.
func signInKey(s config.IdentitySettings) string {
	si := s.SignIn.Effective()
	return fmt.Sprintf("%s|%s|%q|%q|%d|%d", s.Issuer, s.InternalIssuerURL, si.ClientID, si.Scopes, si.MaxPending, si.StartsPerMinute)
}

// resolveIdentityMode picks this agent's mode: its own Agents entry, then the
// block's DefaultMode, then off. An empty string at either level falls through.
func resolveIdentityMode(s config.IdentitySettings, agents []config.AgentPolicy, agentID string) string {
	for _, a := range agents {
		if a.ID == agentID && a.Identity != "" {
			return a.Identity
		}
	}
	if s.DefaultMode != "" {
		return s.DefaultMode
	}
	return config.IdentityModeOff
}

// apply moves the proxy to the identity config described by s and agents. A
// rebuild failure or a mode this build does not know (a newer control plane)
// keeps the previous config and logs one warning with no token data.
func (w *identityWiring) apply(s config.IdentitySettings, agents []config.AgentPolicy) {
	switch mode := resolveIdentityMode(s, agents, w.agentID); mode {
	case config.IdentityModeOff:
		if w.live.mode != "" && w.live.mode != proxy.IdentityModeOff {
			w.logger.Info("identity verification disabled by settings")
		}
		w.p.SetIdentity(nil, proxy.IdentityModeOff)
		// The verifier and its key stay, so turning attribute back on with the
		// same inputs reuses it.
		w.live.mode = proxy.IdentityModeOff
		w.warnScopedWithoutIdentity()
	case config.IdentityModeAttribute:
		w.warned = 0
		w.applyVerified(s, proxy.IdentityModeAttribute)
	case config.IdentityModeChallenge:
		w.warned = 0
		if !w.supportsChallenge() {
			// A transparent-only worker has no CONNECT to answer a 407 on: keep
			// the previous config rather than silently allow everyone.
			w.logger.Warn("identity settings ignored; keeping previous identity config",
				"reason", "challenge mode needs a CONNECT listener (proxy.mode forward or both)", "mode", mode)
			return
		}
		w.applyVerified(s, proxy.IdentityModeChallenge)
	default:
		w.logger.Warn("identity settings ignored; keeping previous identity config",
			"reason", "unknown identity mode", "mode", mode)
	}
}

func (w *identityWiring) supportsChallenge() bool {
	if w.canChallenge != nil {
		return w.canChallenge()
	}
	return w.p.SupportsChallenge()
}

// warnScopedWithoutIdentity logs one WARN per agent and scoped-entry count when
// identity-scoped allow entries exist but this agent's identity mode is off:
// without verification no request has a subject, so every scoped destination is
// denied (identity_required). It logs the count only, never group names.
func (w *identityWiring) warnScopedWithoutIdentity() {
	n := 0
	if w.scoped != nil {
		n = w.scoped()
	}
	if n == 0 {
		w.warned = 0
		return
	}
	if n == w.warned {
		return
	}
	w.warned = n
	w.logger.Warn("identity-scoped allow entries exist but identity verification is off for this agent; scoped destinations are denied (identity_required)",
		"agent", w.agentID, "scopedEntries", n)
}

// countScoped counts allow entries limited to groups or users.
func countScoped(p config.Policy) int {
	n := 0
	for _, e := range p.Allowlist {
		if len(e.Groups) > 0 || len(e.Users) > 0 {
			n++
		}
	}
	return n
}

// applyVerified moves the proxy to attribute or challenge mode with a verifier
// built from s, reusing the live verifier (and sign-in starter) while their
// inputs did not change. A failed rebuild keeps the previous config.
func (w *identityWiring) applyVerified(s config.IdentitySettings, mode proxy.IdentityMode) {
	key := keyOf(s)
	v := w.live.v
	if v == nil || key != w.live.key {
		nv, err := w.build(verifierConfig(s))
		if err != nil {
			// Only the cause class is logged: the error text names config, never a token.
			w.logger.Warn("identity verifier rebuild failed; keeping previous identity config", "error", err)
			return
		}
		v = nv
	}
	starter, signKey := w.live.starter, w.live.signInKey
	if mode == proxy.IdentityModeChallenge {
		if k := signInKey(s); starter == nil || k != signKey {
			ns, err := w.buildSignIn(s)
			if err != nil {
				w.logger.Warn("identity sign-in starter rebuild failed; keeping previous identity config", "error", err)
				return
			}
			starter, signKey = ns, k
		}
	} else {
		starter, signKey = nil, ""
	}
	if w.live.v == v && w.live.mode == mode && w.live.starter == starter {
		return // nothing relevant changed
	}
	w.p.SetIdentityWithSignIn(v, mode, starter)
	if w.live.mode != mode {
		w.logger.Info("identity verification enabled", "mode", string(mode))
	}
	w.live = liveIdentity{v: v, key: key, mode: mode, starter: starter, signInKey: signKey}
}

// verifierConfig maps the settings onto the OIDC verifier's config.
func verifierConfig(s config.IdentitySettings) oidc.Config {
	return oidc.Config{
		Issuer:            s.Issuer,
		InternalIssuerURL: s.InternalIssuerURL,
		Audience:          s.Audience,
		AllowedAZP:        s.AllowedAZP,
		JWKSURL:           s.JWKSURL,
		GroupsClaim:       s.GroupsClaim,
		ClockSkew:         time.Duration(s.ClockSkewSeconds) * time.Second,
		MaxTokenTTL:       time.Duration(s.MaxTokenTTLSeconds) * time.Second,
	}
}
