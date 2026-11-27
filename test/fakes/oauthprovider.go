package fakes

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// OAuthProvider is an httptest OAuth 2.0 provider for the OAuth broker
// (W-P3-BRKR-04): an authorization endpoint that checks the request and mints
// a one-time code, and a token endpoint that checks the client secret, the
// redirect URI and the S256 PKCE verifier before it returns a token. Two wire
// styles: Google (space separated scope, refresh_token on first consent) and
// GitHub (comma separated scope, HTTP 200 with an error field on failure).
// Authorize plays the browser's part, so a flow runs with no human step.
// It listens on loopback; an exchanger that dials it needs the loopback range
// allowed.
type OAuthProvider struct {
	srv *httptest.Server

	mu       sync.Mutex
	clientID string
	secret   string
	style    OAuthStyle
	codes    map[string]oauthCode
	next     int
	issued   int

	grantScopes *string // when set, replaces the requested scope in a token response
	omitRefresh bool
	errorCode   string // when set, the token endpoint answers with this error
	errorStatus int
	tokenCalls  int
	lastForm    url.Values
	forms       []url.Values
}

// OAuthStyle is the wire dialect of an OAuthProvider's token endpoint.
type OAuthStyle int

const (
	// OAuthGoogle returns space separated scopes and a refresh token, and
	// fails with a 400 and an error field.
	OAuthGoogle OAuthStyle = iota
	// OAuthGitHub returns comma separated scopes, no refresh token, and fails
	// with HTTP 200 and an error field.
	OAuthGitHub
)

type oauthCode struct {
	challenge string
	scope     string
	redirect  string
	used      bool
}

// Fixed values a test asserts on.
const (
	OAuthDefaultClientID = "fake-oauth-client"
	OAuthDefaultSecret   = "fake-oauth-client-secret"
)

// NewOAuthProvider starts the provider and stops it when t ends. It accepts
// OAuthDefaultClientID with OAuthDefaultSecret in the Google style.
func NewOAuthProvider(t testing.TB) *OAuthProvider {
	t.Helper()
	p := &OAuthProvider{clientID: OAuthDefaultClientID, secret: OAuthDefaultSecret, codes: map[string]oauthCode{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/authorize":
			p.authorize(w, r)
		case "/token":
			p.token(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

// AuthURL and TokenURL are the endpoints a provider config points at.
func (p *OAuthProvider) AuthURL() string  { return p.srv.URL + "/authorize" }
func (p *OAuthProvider) TokenURL() string { return p.srv.URL + "/token" }

// SetStyle chooses the wire dialect.
func (p *OAuthProvider) SetStyle(s OAuthStyle) { p.locked(func() { p.style = s }) }

// SetClient changes the accepted client id and secret.
func (p *OAuthProvider) SetClient(id, secret string) {
	p.locked(func() { p.clientID, p.secret = id, secret })
}

// GrantScopes makes every later token response carry scope instead of the
// scope the authorization requested (a provider that widens or narrows the
// grant). Pass the wire form for the style.
func (p *OAuthProvider) GrantScopes(scope string) { p.locked(func() { p.grantScopes = &scope }) }

// ClearGrantScopes undoes GrantScopes: token responses carry the requested
// scope again.
func (p *OAuthProvider) ClearGrantScopes() { p.locked(func() { p.grantScopes = nil }) }

// OmitRefreshToken drops refresh_token from token responses (a reconnect).
func (p *OAuthProvider) OmitRefreshToken(omit bool) { p.locked(func() { p.omitRefresh = omit }) }

// FailToken makes the token endpoint answer with the OAuth error code (clear
// with an empty code). The Google style uses status; the GitHub style answers
// 200 whatever the status.
func (p *OAuthProvider) FailToken(code string, status int) {
	p.locked(func() { p.errorCode, p.errorStatus = code, status })
}

// TokenRequests is how many requests the token endpoint received.
func (p *OAuthProvider) TokenRequests() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenCalls
}

// LastTokenForm is a copy of the last token request's form.
func (p *OAuthProvider) LastTokenForm() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := url.Values{}
	for k, v := range p.lastForm {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// TokenForms is every token request's form, oldest first, so a test can search
// logs for each code and verifier the provider saw.
func (p *OAuthProvider) TokenForms() []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]url.Values(nil), p.forms...)
}

// AccessToken and RefreshToken are the values the n-th issued token carries
// (1-based), so a test can search logs and rows for them.
func (p *OAuthProvider) AccessToken(n int) string  { return fmt.Sprintf("fake-access-token-%d", n) }
func (p *OAuthProvider) RefreshToken(n int) string { return fmt.Sprintf("fake-refresh-token-%d", n) }

// Issued is how many tokens the token endpoint has issued.
func (p *OAuthProvider) Issued() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.issued
}

func (p *OAuthProvider) locked(f func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f()
}

// Authorize plays the browser: it sends the authorization URL (a start's
// Location) to the authorization endpoint and returns the redirect target, the
// broker's callback URL with a fresh code and the request's state. With deny it
// returns the callback with error=access_denied instead.
func (p *OAuthProvider) Authorize(authURL string, deny bool) (callbackURL string, err error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if deny {
		q.Set("deny", "1")
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, p.AuthURL()+"?"+u.RawQuery, nil)
	if err != nil {
		return "", err
	}
	// A bare transport returns the 302 as is, so nothing follows the redirect
	// into the broker.
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("fake oauth provider: authorize answered %d", resp.StatusCode)
	}
	return resp.Header.Get("Location"), nil
}

func (p *OAuthProvider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	redirect := q.Get("redirect_uri")
	switch {
	case q.Get("client_id") != p.clientID, q.Get("response_type") != "code",
		q.Get("code_challenge_method") != "S256", q.Get("code_challenge") == "", redirect == "", q.Get("state") == "":
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	cb, err := url.Parse(redirect)
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	cq := cb.Query()
	cq.Set("state", q.Get("state"))
	if q.Get("deny") != "" {
		cq.Set("error", "access_denied")
		cq.Set("error_description", "the user said no (fake provider text)")
	} else {
		p.next++
		code := fmt.Sprintf("fake-code-%d", p.next)
		p.codes[code] = oauthCode{challenge: q.Get("code_challenge"), scope: q.Get("scope"), redirect: redirect}
		cq.Set("code", code)
	}
	cb.RawQuery = cq.Encode()
	http.Redirect(w, r, cb.String(), http.StatusFound)
}

func (p *OAuthProvider) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenCalls++
	p.lastForm = r.PostForm
	p.forms = append(p.forms, r.PostForm)
	if r.Method != http.MethodPost || !strings.Contains(r.Header.Get("Accept"), "application/json") {
		p.fail(w, "invalid_request", http.StatusBadRequest)
		return
	}
	if p.errorCode != "" {
		p.fail(w, p.errorCode, p.errorStatus)
		return
	}
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	if u, pw, ok := r.BasicAuth(); ok {
		id, secret = u, pw
	}
	if id != p.clientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.secret)) != 1 {
		p.fail(w, "invalid_client", http.StatusUnauthorized)
		return
	}
	code := r.PostForm.Get("code")
	c, ok := p.codes[code]
	if r.PostForm.Get("grant_type") != "authorization_code" || !ok || c.used || r.PostForm.Get("redirect_uri") != c.redirect {
		p.fail(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge {
		p.fail(w, "invalid_grant", http.StatusBadRequest)
		return
	}
	c.used = true
	p.codes[code] = c
	p.issued++

	scope := c.scope
	if p.grantScopes != nil {
		scope = *p.grantScopes
	}
	body := map[string]any{"access_token": p.AccessToken(p.issued)}
	switch p.style {
	case OAuthGitHub:
		body["token_type"] = "bearer"
		body["scope"] = strings.ReplaceAll(scope, " ", ",")
	default:
		body["token_type"] = "Bearer"
		body["expires_in"] = 3599
		body["scope"] = scope
		if !p.omitRefresh {
			body["refresh_token"] = p.RefreshToken(p.issued)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (p *OAuthProvider) fail(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	if p.style == OAuthGitHub {
		status = http.StatusOK
	} else if status == 0 {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "fake provider text that must never reach a user"})
}
