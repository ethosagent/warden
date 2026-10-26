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

	// live is the identity config the proxy is serving: the verifier (nil when
	// off), the inputs it was built from, and the mode.
	live liveIdentity
}

type liveIdentity struct {
	v    identity.Verifier
	key  verifierKey
	mode proxy.IdentityMode
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
	return &identityWiring{p: p, agentID: agentID, logger: logger, build: oidc.NewOIDCVerifier}
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
	case config.IdentityModeAttribute:
		w.applyAttribute(s)
	default:
		w.logger.Warn("identity settings ignored; keeping previous identity config",
			"reason", "unknown identity mode", "mode", mode)
	}
}

func (w *identityWiring) applyAttribute(s config.IdentitySettings) {
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
	} else if w.live.mode == proxy.IdentityModeAttribute {
		return // nothing relevant changed
	}
	w.p.SetIdentity(v, proxy.IdentityModeAttribute)
	if w.live.mode != proxy.IdentityModeAttribute {
		w.logger.Info("identity verification enabled", "mode", config.IdentityModeAttribute)
	}
	w.live = liveIdentity{v: v, key: key, mode: proxy.IdentityModeAttribute}
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
