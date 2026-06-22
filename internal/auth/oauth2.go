package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// OAuth2ClientCredentials implements the OAuth2 client_credentials flow.
// It caches the access token and refreshes it when expired.
type OAuth2ClientCredentials struct {
	tokenURL     string
	clientID     string
	clientSecret string
	scopes       []string
	client       *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewOAuth2ClientCredentials creates an OAuth2ClientCredentials transformer.
// The caller must supply an *http.Client that uses SafeDialer so that
// token-endpoint requests go through the same SSRF-protection and egress
// policy as proxied traffic.
func NewOAuth2ClientCredentials(client *http.Client, tokenURL, clientID, clientSecret string, scopes []string) *OAuth2ClientCredentials {
	return &OAuth2ClientCredentials{
		tokenURL:     tokenURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		scopes:       scopes,
		client:       client,
	}
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

// Transform sets the Authorization header with a valid bearer token, fetching
// a new one from the token endpoint if the cached token has expired.
func (o *OAuth2ClientCredentials) Transform(req *http.Request) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.token != "" && time.Now().Before(o.expiry) {
		req.Header.Set("Authorization", "Bearer "+o.token)
		return nil
	}

	// Fetch new token
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", o.clientID)
	form.Set("client_secret", o.clientSecret)
	if len(o.scopes) > 0 {
		form.Set("scope", strings.Join(o.scopes, " "))
	}

	tokenReq, err := http.NewRequest("POST", o.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("auth: build token request: %w", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := o.client.Do(tokenReq)
	if err != nil {
		return fmt.Errorf("auth: token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("auth: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return fmt.Errorf("auth: decode token response: %w", err)
	}

	o.token = tr.AccessToken
	expiry := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second).Add(-30 * time.Second)
	if expiry.Before(time.Now()) {
		expiry = time.Now() // don't go into the past; will refresh next call
	}
	o.expiry = expiry

	req.Header.Set("Authorization", "Bearer "+o.token)
	return nil
}
