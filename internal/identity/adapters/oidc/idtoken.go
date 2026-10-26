package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/ethosagent/warden/internal/identity"
)

// IDTokenConfig configures NewIDTokenVerifier, the verifier the console login
// uses for the ID token it gets back from the code exchange. ClientID is the
// console's own client: it must be the audience and, when the token names an
// authorized party, the azp. InternalIssuerURL and CAFile go to the shared HTTP
// client; Now is for tests.
type IDTokenConfig struct {
	Issuer            string
	ClientID          string
	InternalIssuerURL string
	CAFile            string
	Now               func() time.Time
}

// NewIDTokenVerifier is NewOIDCVerifier pinned to the console client:
// Audience=ClientID and AllowedAZP=[ClientID]. The shared verifier then also
// enforces the OIDC Core rule that a token with several audiences must carry
// an azp equal to ClientID, and it shares the keyset, the RS256/ES256
// allowlist and the clock skew handling with the worker's verifier. Callers
// pass identity.WithNonce on every Verify; the nonce is compared in constant
// time and an empty expected nonce never matches.
func NewIDTokenVerifier(cfg IDTokenConfig) (identity.Verifier, error) {
	if cfg.ClientID == "" {
		return nil, errors.New("oidc id token verifier: client id is required")
	}
	return NewOIDCVerifier(Config{
		Issuer:            cfg.Issuer,
		Audience:          cfg.ClientID,
		AllowedAZP:        []string{cfg.ClientID},
		InternalIssuerURL: cfg.InternalIssuerURL,
		CAFile:            cfg.CAFile,
		Now:               cfg.Now,
	})
}

// Endpoints are the two OAuth endpoints the console login needs, as the
// provider's discovery document publishes them (public URLs: the shared client
// routes requests for the issuer's origin to the internal origin, so these stay
// the addresses a browser can reach).
type Endpoints struct {
	AuthURL, TokenURL string
}

// Discover fetches the discovery document of issuer through client (the shared
// client from NewHTTPClient) and returns its authorization and token
// endpoints. go-oidc checks that the document's issuer equals issuer.
func Discover(ctx context.Context, client *http.Client, issuer string) (Endpoints, error) {
	p, err := gooidc.NewProvider(WithHTTPClient(ctx, client), issuer)
	if err != nil {
		return Endpoints{}, fmt.Errorf("oidc discovery: %w", err)
	}
	e := p.Endpoint()
	if e.AuthURL == "" || e.TokenURL == "" {
		return Endpoints{}, errors.New("oidc discovery: document has no authorization or token endpoint")
	}
	return Endpoints{AuthURL: e.AuthURL, TokenURL: e.TokenURL}, nil
}
