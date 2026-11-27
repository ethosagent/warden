package fakes

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// This file adds a Dex-shaped refresh_token grant to the OIDC issuer fake
// (W-P3-OFFB-02). Each live refresh token names a chain (sub, email, client).
// A refresh consumes the presented token and returns a new one with a fresh
// ID token (no nonce), as Dex does. A code exchange that returns a refresh
// token starts a new chain for that subject and invalidates the earlier ones
// (Dex keeps only the newest chain of a user and client live). The error
// answers use the Dex v2.41.1 shapes, so the refresh job's classification is
// exercised against the wire it will meet.

// Dex v2.41.1 refresh error descriptions.
const (
	DexRefreshInvalidDescription = "Refresh token is invalid or has already been claimed by another client."
	DexRefreshExpiredDescription = "Refresh token expired."
)

type refreshChain struct {
	sub, email, client string
}

// RefreshFailure is a canned token-endpoint answer for one subject's
// refreshes. Status 0 clears it.
type RefreshFailure struct {
	Status      int
	Error       string
	Description string
}

// Canned Dex answers.
var (
	// RefreshUpstreamRefused is Dex's answer when the connector refuses the
	// refresh (LDAP: userSearch no longer finds the user).
	RefreshUpstreamRefused = RefreshFailure{Status: http.StatusInternalServerError, Error: "invalid_request"}
	// RefreshExpired is the chain's absolute lifetime.
	RefreshExpired = RefreshFailure{Status: http.StatusBadRequest, Error: "invalid_request", Description: DexRefreshExpiredDescription}
	// RefreshClaimed is an unknown or already-used token.
	RefreshClaimed = RefreshFailure{Status: http.StatusBadRequest, Error: "invalid_request", Description: DexRefreshInvalidDescription}
	// RefreshUnavailable is a plain 503 with no OAuth body.
	RefreshUnavailable = RefreshFailure{Status: http.StatusServiceUnavailable}
)

// AddRefreshChain makes token a live refresh token of sub for client, as a
// login would, and invalidates sub's earlier chains for that client.
func (i *OIDCIssuer) AddRefreshChain(token, sub, email, client string) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.addChainLocked(token, refreshChain{sub: sub, email: email, client: client})
}

func (i *OIDCIssuer) addChainLocked(token string, c refreshChain) {
	if i.flow.chains == nil {
		i.flow.chains = map[string]refreshChain{}
	}
	for t, old := range i.flow.chains {
		if old.sub == c.sub && old.client == c.client {
			delete(i.flow.chains, t)
		}
	}
	i.flow.chains[token] = c
}

// SetRefreshFailure makes every refresh of sub answer f (Status 0 clears it).
func (i *OIDCIssuer) SetRefreshFailure(sub string, f RefreshFailure) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	if i.flow.refreshFail == nil {
		i.flow.refreshFail = map[string]RefreshFailure{}
	}
	if f.Status == 0 {
		delete(i.flow.refreshFail, sub)
		return
	}
	i.flow.refreshFail[sub] = f
}

// SetRefreshMint adds options to the ID token every later refresh of sub
// mints (WithSub("someone-else") for a subject mismatch). None clears them.
func (i *OIDCIssuer) SetRefreshMint(sub string, opts ...MintOption) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	if i.flow.refreshMint == nil {
		i.flow.refreshMint = map[string][]MintOption{}
	}
	i.flow.refreshMint[sub] = opts
}

// SetRefreshRotation chooses whether a refresh returns a new refresh token
// (true, the default, as Dex does) or none (an IdP that keeps the token).
func (i *OIDCIssuer) SetRefreshRotation(rotate bool) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.flow.noRotate = !rotate
}

// OnRefresh runs fn (outside the fake's lock) at the start of every refresh
// request, before the token is looked up; nil clears it. Tests use it to
// race a login against an in-flight refresh.
func (i *OIDCIssuer) OnRefresh(fn func(sub string)) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.flow.onRefresh = fn
}

// RefreshRequests counts refresh_token grant requests.
func (i *OIDCIssuer) RefreshRequests() int {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	return i.flow.refreshCalls
}

// LastIssuedRefreshToken is the refresh token the latest refresh returned.
func (i *OIDCIssuer) LastIssuedRefreshToken() string {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	return i.flow.lastIssued
}

// LiveRefreshToken reports whether token is a live refresh token.
func (i *OIDCIssuer) LiveRefreshToken(token string) bool {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	_, ok := i.flow.chains[token]
	return ok
}

// clientAuth returns the authenticated client id of a token request, or "".
func (i *OIDCIssuer) clientAuth(r *http.Request) string {
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	i.flow.mu.Lock()
	want, known := i.flow.clients[id]
	i.flow.mu.Unlock()
	if !known || subtle.ConstantTimeCompare([]byte(secret), []byte(want)) != 1 {
		return ""
	}
	return id
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	_ = json.NewEncoder(w).Encode(body)
}

// handleRefresh serves grant_type=refresh_token (r.PostForm is parsed).
func (i *OIDCIssuer) handleRefresh(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	i.flow.mu.Lock()
	i.flow.refreshCalls++
	hook := i.flow.onRefresh
	hookSub := i.flow.chains[presented].sub
	i.flow.mu.Unlock()
	if hook != nil {
		hook(hookSub)
	}
	client := i.clientAuth(r)
	if client == "" {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials.")
		return
	}
	i.flow.mu.Lock()
	c, live := i.flow.chains[presented]
	if !live || c.client != client {
		i.flow.mu.Unlock()
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", DexRefreshInvalidDescription)
		return
	}
	if f, ok := i.flow.refreshFail[c.sub]; ok {
		i.flow.mu.Unlock()
		if f.Error == "" {
			http.Error(w, "fake refresh failure", f.Status)
			return
		}
		writeOAuthError(w, f.Status, f.Error, f.Description)
		return
	}
	extra := append([]MintOption(nil), i.flow.refreshMint[c.sub]...)
	resp := map[string]any{"access_token": "fake-access-token", "token_type": "Bearer", "expires_in": int(OIDCTokenTTL.Seconds())}
	if !i.flow.noRotate {
		delete(i.flow.chains, presented)
		next := "rt-fake-" + randomToken()
		i.flow.chains[next] = c
		i.flow.lastIssued = next
		resp["refresh_token"] = next
	}
	i.flow.mu.Unlock()
	opts := append([]MintOption{Valid(c.sub, c.email), WithAud(c.client), WithAZP(c.client)}, extra...)
	resp["id_token"] = i.Mint(opts...)
	writeJSON(w, resp)
}

// tokenSubject reads sub and email from a minted token's payload (the fake
// trusts its own tokens).
func tokenSubject(tok string) (sub, email string) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var c struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
	}
	_ = json.Unmarshal(b, &c)
	return c.Sub, c.Email
}
