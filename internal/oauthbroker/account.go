package oauthbroker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// googleIssuers are the iss values of a Google id_token.
var googleIssuers = map[string]bool{"https://accounts.google.com": true, "accounts.google.com": true}

// githubUserURL is the default userinfo endpoint of github and githubApp.
const githubUserURL = "https://api.github.com/user"

// IdentifyTimeout bounds the userinfo call.
const IdentifyTimeout = 10 * time.Second

// ErrIdentity is returned when the provider account cannot be identified (no
// id_token, a token for another client, a userinfo failure, no userinfo
// endpoint). Its text never holds provider data.
var ErrIdentity = errors.New("oauthbroker: cannot identify the provider account")

// Identity is the provider account a token belongs to, as the provider told
// it. EmailVerified is true only when the provider vouched for Email: Google's
// email_verified claim, a generic userinfo email_verified, and for GitHub the
// profile email (GitHub lets a user publish only a verified address).
// HostedDomain is Google's hd claim.
type Identity struct {
	ID            string
	Login         string
	Email         string
	EmailVerified bool
	HostedDomain  string
}

// Account is what a grant stores: the stable id and the label shown to the
// owner (the GitHub login, else the email).
func (i Identity) Account() Account { return Account{ID: i.ID, Login: i.Login} }

// identityEndpoint returns the endpoint Identify reads for p ("" when none).
func (p *Provider) identityEndpoint() string {
	switch p.Type {
	case config.OAuthProviderGitHub, config.OAuthProviderGitHubApp:
		if p.UserinfoURL != "" {
			return p.UserinfoURL
		}
		return githubUserURL
	case config.OAuthProviderGeneric:
		return p.UserinfoURL
	}
	return ""
}

// Identify reads the provider account the token response belongs to. google:
// the id_token the token endpoint returned directly over TLS (OIDC Core
// 3.1.3.7 lets the client skip signature validation for it), with iss, aud
// and exp checked. github and githubApp: GET userinfoURL (default
// api.github.com/user) with the new access token. generic: userinfoURL when
// set, else ErrIdentity. Errors carry no provider text.
func (p *Provider) Identify(ctx context.Context, tok TokenResponse) (Identity, error) {
	switch p.Type {
	case config.OAuthProviderGoogle:
		return p.identifyGoogle(tok.IDToken)
	case config.OAuthProviderGitHub, config.OAuthProviderGitHubApp:
		return p.identifyUserinfo(ctx, tok, true)
	default:
		if p.UserinfoURL == "" {
			return Identity{}, ErrIdentity
		}
		return p.identifyUserinfo(ctx, tok, false)
	}
}

func (p *Provider) identifyGoogle(idToken string) (Identity, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return Identity{}, ErrIdentity
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, ErrIdentity
	}
	var c struct {
		Iss           string          `json:"iss"`
		Aud           json.RawMessage `json:"aud"`
		Exp           json.Number     `json:"exp"`
		Sub           string          `json:"sub"`
		Email         string          `json:"email"`
		EmailVerified json.RawMessage `json:"email_verified"`
		HD            string          `json:"hd"`
	}
	if json.Unmarshal(raw, &c) != nil || !googleIssuers[c.Iss] || c.Sub == "" || !audienceIs(c.Aud, p.ClientID) {
		return Identity{}, ErrIdentity
	}
	if exp, err := c.Exp.Int64(); err != nil || exp <= p.clock().Unix() {
		return Identity{}, ErrIdentity
	}
	return Identity{
		ID: c.Sub, Login: c.Email, Email: c.Email,
		EmailVerified: c.Email != "" && jsonTrue(c.EmailVerified), HostedDomain: c.HD,
	}, nil
}

func (p *Provider) identifyUserinfo(ctx context.Context, tok TokenResponse, github bool) (Identity, error) {
	endpoint := p.identityEndpoint()
	rq, _ := p.httpc.(Requester)
	if endpoint == "" || rq == nil || tok.AccessToken == "" || !refreshURLAllowed(endpoint) {
		return Identity{}, ErrIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, IdentifyTimeout)
	defer cancel()
	accept := "application/json"
	if github {
		accept = "application/vnd.github+json"
	}
	status, body, err := rq.Do(ctx, Request{
		Method: "GET", URL: endpoint, Bearer: tok.AccessToken, Accept: accept, MaxBytes: MaxRevokeResponseBytes,
	})
	if err != nil || status != 200 || len(body) > MaxRevokeResponseBytes {
		return Identity{}, ErrIdentity
	}
	var u struct {
		ID                json.RawMessage `json:"id"`
		Sub               json.RawMessage `json:"sub"`
		Login             string          `json:"login"`
		PreferredUsername string          `json:"preferred_username"`
		Email             string          `json:"email"`
		EmailVerified     json.RawMessage `json:"email_verified"`
		HD                string          `json:"hd"`
	}
	if json.Unmarshal(body, &u) != nil {
		return Identity{}, ErrIdentity
	}
	id := Identity{Email: u.Email, HostedDomain: u.HD}
	if github {
		id.ID = scalarString(u.ID)
		id.Login = u.Login
		// GitHub only lets a user publish an email address it verified.
		id.EmailVerified = u.Email != ""
	} else {
		id.ID = firstNonEmpty(scalarString(u.Sub), scalarString(u.ID))
		id.Login = firstNonEmpty(u.Login, u.PreferredUsername, u.Email)
		id.EmailVerified = u.Email != "" && jsonTrue(u.EmailVerified)
	}
	if id.ID == "" {
		return Identity{}, ErrIdentity
	}
	return id, nil
}

// scalarString reads a JSON string or integer as text ("" otherwise).
func scalarString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		if i, err := n.Int64(); err == nil {
			return strconv.FormatInt(i, 10)
		}
	}
	return ""
}

// jsonTrue reads email_verified, which is a bool but "true" from some IdPs.
func jsonTrue(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	var s string
	return json.Unmarshal(raw, &s) == nil && s == "true"
}

// audienceIs reports whether an aud claim (a string or an array) names want.
func audienceIs(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, a := range many {
		if a == want {
			return true
		}
	}
	return false
}

// AccountRules reports whether id satisfies the provider's allowedAccountDomains
// and requireEmailMatch. sessionEmail must be vouched for by the IdP
// (sessionVerified), else requireEmailMatch fails. A Google account is judged
// by its hd claim, never by its email domain (a consumer Google account can
// carry any address); other providers by a verified email's domain.
func (p *Provider) AccountRules(id Identity, sessionEmail string, sessionVerified bool) bool {
	if len(p.AllowedAccountDomains) > 0 {
		domain := id.HostedDomain
		if p.Type != config.OAuthProviderGoogle {
			domain = ""
			if id.EmailVerified {
				if _, d, ok := splitEmail(id.Email); ok {
					domain = d
				}
			}
		}
		domain = asciiLower(domain)
		ok := false
		for _, d := range p.AllowedAccountDomains {
			if domain != "" && domain == asciiLower(d) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if p.RequireEmailMatch {
		_, _, okA := splitEmail(id.Email)
		_, _, okB := splitEmail(sessionEmail)
		ea, eb := asciiLower(id.Email), asciiLower(sessionEmail)
		if !sessionVerified || !id.EmailVerified || !okA || !okB || ea == "" || ea != eb {
			return false
		}
	}
	return true
}

// HasAccountRules reports whether an account rule is configured.
func (p *Provider) HasAccountRules() bool {
	return len(p.AllowedAccountDomains) > 0 || p.RequireEmailMatch
}

func (i Identity) String() string { return fmt.Sprintf("Identity{id=%s}", i.ID) }

// splitEmail splits local@domain: exactly one "@", both parts non-empty and the
// whole address ASCII. Anything else is not an email for account rules.
func splitEmail(e string) (local, domain string, ok bool) {
	if !isASCII(e) || strings.Count(e, "@") != 1 {
		return "", "", false
	}
	local, domain, _ = strings.Cut(e, "@")
	return local, domain, local != "" && domain != ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// asciiLower lower-cases ASCII only and returns "" for a non-ASCII string, so a
// look-alike (U+212A KELVIN SIGN folds to "k" under Unicode case folding) never
// matches.
func asciiLower(s string) string {
	if !isASCII(s) {
		return ""
	}
	return strings.ToLower(s)
}
