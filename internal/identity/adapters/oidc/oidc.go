package oidc

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/url"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ethosagent/warden/internal/identity"
)

const (
	cacheSize = 10_000
	cacheTTL  = 5 * time.Minute
)

// Config configures NewOIDCVerifier. Issuer is the public issuer string, which
// every token's iss must equal. Audience (plus the optional Audiences) is the
// set of values of which one must appear in aud. JWKSURL is optional; empty
// means lazy discovery from the issuer. InternalIssuerURL and CAFile go to the
// shared HTTP client. Now is for tests; nil means time.Now.
type Config struct {
	Issuer            string
	Audience          string
	Audiences         []string
	AllowedAZP        []string
	JWKSURL           string
	ClockSkew         time.Duration
	MaxTokenTTL       time.Duration
	GroupsClaim       string
	InternalIssuerURL string
	CAFile            string
	Now               func() time.Time
}

type verifier struct {
	cfg   Config
	auds  map[string]bool
	azps  map[string]bool
	keys  *keySet
	cache *resultCache
	now   func() time.Time
}

// NewOIDCVerifier builds the verifier. It does no network I/O: discovery and
// key fetches happen on the first Verify that needs keys, through the one
// shared HTTP client.
func NewOIDCVerifier(cfg Config) (identity.Verifier, error) {
	client, err := NewHTTPClient(HTTPClientConfig{Issuer: cfg.Issuer, InternalIssuerURL: cfg.InternalIssuerURL, CAFile: cfg.CAFile})
	if err != nil {
		return nil, err
	}
	auds := map[string]bool{}
	for _, a := range append([]string{cfg.Audience}, cfg.Audiences...) {
		if a != "" {
			auds[a] = true
		}
	}
	if len(auds) == 0 {
		return nil, errors.New("oidc verifier: audience is required")
	}
	switch {
	case cfg.ClockSkew < 0 || cfg.ClockSkew > identity.MaxClockSkew:
		return nil, errors.New("oidc verifier: clock skew must be between 0 and 5m")
	case cfg.ClockSkew == 0:
		cfg.ClockSkew = identity.DefaultClockSkew
	}
	switch {
	case cfg.MaxTokenTTL < 0:
		return nil, errors.New("oidc verifier: max token ttl must not be negative")
	case cfg.MaxTokenTTL == 0:
		cfg.MaxTokenTTL = identity.DefaultMaxTokenTTL
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = identity.DefaultGroupsClaim
	}
	if cfg.JWKSURL != "" {
		u, err := url.Parse(cfg.JWKSURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, errors.New("oidc verifier: jwksURL must be an absolute http or https URL")
		}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	azps := map[string]bool{}
	for _, a := range cfg.AllowedAZP {
		azps[a] = true
	}
	return &verifier{
		cfg:   cfg,
		auds:  auds,
		azps:  azps,
		keys:  newKeySet(client, cfg.Issuer, cfg.JWKSURL, cfg.Now),
		cache: newResultCache(cacheSize),
		now:   cfg.Now,
	}, nil
}

// ClockSkew returns the effective exp/nbf tolerance.
func (v *verifier) ClockSkew() time.Duration { return v.cfg.ClockSkew }

// Verify checks raw. Warden runs every time, size, algorithm, audience and
// azp check itself; go-oidc is used only for the signature (StaticKeySet), so
// none of its built-in expiry checks run.
func (v *verifier) Verify(ctx context.Context, raw string, opts ...identity.VerifyOption) (identity.Claims, identity.Status, identity.Reason) {
	o := identity.ApplyOptions(opts...)
	if len(raw) > identity.MaxTokenBytes {
		return identity.Claims{}, identity.StatusInvalid, identity.ReasonTooLarge
	}
	if raw == "" {
		return identity.Claims{}, identity.StatusInvalid, identity.ReasonMalformed
	}
	now := v.now()
	skew := v.cfg.ClockSkew

	var ck [32]byte
	if !o.NonceSet {
		ck = sha256.Sum256([]byte(raw))
		if c, ok := v.cache.get(ck, now); ok {
			return c, identity.StatusValid, ""
		}
	}

	hdr, p, err := parseToken(raw, v.cfg.GroupsClaim)
	if err != nil {
		return identity.Claims{}, identity.StatusInvalid, identity.ReasonMalformed
	}
	c := p.claims
	uv := identity.Claims{Sub: c.Sub, Email: c.Email, EmailVerified: c.EmailVerified, Issuer: c.Issuer, Expiry: c.Expiry}
	invalid := func(r identity.Reason) (identity.Claims, identity.Status, identity.Reason) {
		return uv, identity.StatusInvalid, r
	}

	if hdr.Alg != "RS256" && hdr.Alg != "ES256" {
		return invalid(identity.ReasonAlgNotAllowed)
	}
	key, res := v.keys.lookup(ctx, hdr.Kid, hdr.Alg)
	switch res {
	case keysUnavailable:
		return identity.Claims{}, identity.StatusUnverified, identity.ReasonJWKSUnavailable
	case keyUnknown:
		return invalid(identity.ReasonUnknownKID)
	}
	if !keyFitsAlg(key, hdr.Alg) {
		return invalid(identity.ReasonBadSignature)
	}
	ks := &gooidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Key}}
	if _, err := ks.VerifySignature(ctx, raw); err != nil {
		return invalid(identity.ReasonBadSignature)
	}

	if c.Issuer != v.cfg.Issuer {
		return invalid(identity.ReasonWrongIss)
	}
	if !v.audOK(p.aud) {
		return invalid(identity.ReasonWrongAud)
	}
	if len(v.azps) > 0 {
		if c.AZP != "" {
			if !v.azps[c.AZP] {
				return invalid(identity.ReasonWrongAZP)
			}
		} else if len(p.aud) != 1 {
			return invalid(identity.ReasonWrongAZP)
		}
	}
	if c.Expiry.Sub(c.IssuedAt) > v.cfg.MaxTokenTTL {
		return invalid(identity.ReasonTTLTooLong)
	}
	if now.After(c.Expiry.Add(skew)) {
		return uv, identity.StatusExpired, ""
	}
	// The bounded Reason set has no not-yet-valid value; malformed is deliberate.
	if p.nbf != nil && now.Add(skew).Before(*p.nbf) {
		return identity.Claims{}, identity.StatusInvalid, identity.ReasonMalformed
	}
	if o.NonceSet {
		if o.Nonce == "" || subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(o.Nonce)) != 1 {
			return invalid(identity.ReasonWrongNonce)
		}
		return c, identity.StatusValid, ""
	}
	until := now.Add(cacheTTL)
	if c.Expiry.Before(until) {
		until = c.Expiry
	}
	v.cache.put(ck, c, until)
	return c, identity.StatusValid, ""
}

func (v *verifier) audOK(auds []string) bool {
	for _, a := range auds {
		if v.auds[a] {
			return true
		}
	}
	return false
}
