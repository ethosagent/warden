package fakes

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// This file adds the authorization-code half to the OIDC issuer fake
// (W-P1-SSO-03): an authorization endpoint that redirects straight back with a
// code, and a token endpoint that checks the client secret and the S256 PKCE
// verifier before it mints an ID token. A real browser flow therefore runs
// against it with no human step. It shares nothing with the console's code.

// DefaultLoginSub is the subject an ID token carries when SetLogin was not
// called.
const DefaultLoginSub = "login-user"

// AuthRequest is one request the authorization endpoint accepted.
type AuthRequest struct {
	ClientID, RedirectURI, State, Nonce string
	Challenge, ChallengeMethod, Scope   string
}

type authCode struct {
	req AuthRequest
}

type flowState struct {
	mu          sync.Mutex
	clients     map[string]string
	codes       map[string]authCode
	login       []MintOption
	authErr     string
	tokenStatus int
	requests    []AuthRequest
	tokenCalls  int
}

// RegisterClient makes the token endpoint accept id with secret (client_secret
// basic or post). The authorization endpoint accepts only registered ids.
func (i *OIDCIssuer) RegisterClient(id, secret string) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	if i.flow.clients == nil {
		i.flow.clients = map[string]string{}
	}
	i.flow.clients[id] = secret
}

// SetLogin sets the options every later code exchange mints its ID token with.
// aud, azp and nonce default to the client and the request's nonce, so an
// option can override them (a wrong audience, a wrong nonce). Without a call
// the token is Valid(DefaultLoginSub, ...).
func (i *OIDCIssuer) SetLogin(opts ...MintOption) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.flow.login = opts
}

// FailAuthorize makes the authorization endpoint answer with error=code
// instead of a code, until called with "".
func (i *OIDCIssuer) FailAuthorize(code string) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.flow.authErr = code
}

// SetTokenStatus makes the token endpoint answer with this HTTP status and no
// token, until called with 0.
func (i *OIDCIssuer) SetTokenStatus(status int) {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	i.flow.tokenStatus = status
}

// AuthRequests returns the authorization requests accepted so far.
func (i *OIDCIssuer) AuthRequests() []AuthRequest {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	return append([]AuthRequest(nil), i.flow.requests...)
}

// TokenRequests counts requests to the token endpoint.
func (i *OIDCIssuer) TokenRequests() int {
	i.flow.mu.Lock()
	defer i.flow.mu.Unlock()
	return i.flow.tokenCalls
}

func (i *OIDCIssuer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	req := AuthRequest{
		ClientID: q.Get("client_id"), RedirectURI: q.Get("redirect_uri"), State: q.Get("state"),
		Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"),
		ChallengeMethod: q.Get("code_challenge_method"), Scope: q.Get("scope"),
	}
	i.flow.mu.Lock()
	_, known := i.flow.clients[req.ClientID]
	authErr := i.flow.authErr
	i.flow.mu.Unlock()
	ru, err := url.Parse(req.RedirectURI)
	if !known || err != nil || ru.Host == "" || q.Get("response_type") != "code" {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	out := ru.Query()
	if req.State != "" {
		out.Set("state", req.State)
	}
	if authErr != "" {
		out.Set("error", authErr)
		out.Set("error_description", "fake issuer refused the login")
	} else {
		if req.Challenge == "" || req.ChallengeMethod != "S256" {
			http.Error(w, "PKCE S256 is required", http.StatusBadRequest)
			return
		}
		code := randomToken()
		i.flow.mu.Lock()
		if i.flow.codes == nil {
			i.flow.codes = map[string]authCode{}
		}
		i.flow.codes[code] = authCode{req: req}
		i.flow.requests = append(i.flow.requests, req)
		i.flow.mu.Unlock()
		out.Set("code", code)
	}
	ru.RawQuery = out.Encode()
	http.Redirect(w, r, ru.String(), http.StatusFound)
}

func (i *OIDCIssuer) handleToken(w http.ResponseWriter, r *http.Request) {
	i.flow.mu.Lock()
	i.flow.tokenCalls++
	status := i.flow.tokenStatus
	i.flow.mu.Unlock()
	if status != 0 {
		http.Error(w, "fake token endpoint failure", status)
		return
	}
	if r.Method != http.MethodPost || r.ParseForm() != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") == deviceGrant {
		i.handleDeviceToken(w, r)
		return
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	i.flow.mu.Lock()
	want, known := i.flow.clients[id]
	var ac authCode
	haveCode := false
	if known && subtle.ConstantTimeCompare([]byte(secret), []byte(want)) == 1 {
		ac, haveCode = i.flow.codes[r.PostForm.Get("code")]
		delete(i.flow.codes, r.PostForm.Get("code")) // single use, win or lose
	}
	login := append([]MintOption(nil), i.flow.login...)
	i.flow.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if r.PostForm.Get("grant_type") != "authorization_code" || !haveCode ||
		ac.req.ClientID != id || ac.req.RedirectURI != r.PostForm.Get("redirect_uri") ||
		subtle.ConstantTimeCompare([]byte(challenge), []byte(ac.req.Challenge)) != 1 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	opts := []MintOption{Valid(DefaultLoginSub, DefaultLoginSub+"@example.com"), WithAud(id), WithAZP(id), WithNonce(ac.req.Nonce)}
	if len(login) > 0 {
		opts = append(opts, login...)
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   int(OIDCTokenTTL.Seconds()),
		"id_token":     i.Mint(opts...),
	})
}

func randomToken() string {
	var b [24]byte
	_, _ = rand.Read(b[:])
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b[:]), "=")
}
