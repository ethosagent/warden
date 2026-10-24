// Package oidc holds the one shared HTTP client for every server-side OIDC call
// (discovery, JWKS, token exchange) and the helper that hands it to go-oidc and
// golang.org/x/oauth2. It is IdP-neutral: the optional internal issuer URL is
// plain configuration. go-oidc is imported as gooidc because this package is
// also named oidc.
package oidc
