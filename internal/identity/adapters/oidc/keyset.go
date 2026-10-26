package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
)

const (
	refetchFloor = 30 * time.Second
	fetchTimeout = 10 * time.Second
	minRSABits   = 2048
)

type lookupResult int

const (
	keyFound lookupResult = iota
	keyUnknown
	keysUnavailable
)

// keySet serves signing keys lazily. Fetches are single-flight, at most one
// attempt per floor interval, and run on their own context so one caller's
// cancel cannot fail the others. The last good key list is kept on failure.
type keySet struct {
	client  *http.Client
	issuer  string
	jwksURL string
	now     func() time.Time
	floor   time.Duration

	mu          sync.Mutex
	keys        []jose.JSONWebKey
	loaded      bool
	lastAttempt time.Time
	inflight    *fetchCall
}

type fetchCall struct{ done chan struct{} }

func newKeySet(client *http.Client, issuer, jwksURL string, now func() time.Time) *keySet {
	return &keySet{client: client, issuer: issuer, jwksURL: jwksURL, now: now, floor: refetchFloor}
}

func (k *keySet) lookup(ctx context.Context, kid, alg string) (jose.JSONWebKey, lookupResult) {
	k.mu.Lock()
	if key, ok := k.find(kid, alg); ok {
		k.mu.Unlock()
		return key, keyFound
	}
	call := k.inflight
	if call == nil {
		now := k.now()
		if !k.lastAttempt.IsZero() && now.Sub(k.lastAttempt) < k.floor {
			loaded := k.loaded
			k.mu.Unlock()
			if loaded {
				return jose.JSONWebKey{}, keyUnknown
			}
			return jose.JSONWebKey{}, keysUnavailable
		}
		k.lastAttempt = now
		call = &fetchCall{done: make(chan struct{})}
		k.inflight = call
		go k.fetch(call)
	}
	k.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return jose.JSONWebKey{}, keysUnavailable
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.find(kid, alg); ok {
		return key, keyFound
	}
	if k.loaded {
		return jose.JSONWebKey{}, keyUnknown
	}
	return jose.JSONWebKey{}, keysUnavailable
}

// find searches the current keys. An empty kid matches only when exactly one
// key fits alg. The caller holds mu.
func (k *keySet) find(kid, alg string) (jose.JSONWebKey, bool) {
	var fit []jose.JSONWebKey
	for _, key := range k.keys {
		if kid != "" {
			if key.KeyID == kid {
				return key, true
			}
			continue
		}
		if keyFitsAlg(key, alg) {
			fit = append(fit, key)
		}
	}
	if kid == "" && len(fit) == 1 {
		return fit[0], true
	}
	return jose.JSONWebKey{}, false
}

func keyFitsAlg(key jose.JSONWebKey, alg string) bool {
	if key.Algorithm != "" && key.Algorithm != alg {
		return false
	}
	switch key.Key.(type) {
	case *rsa.PublicKey:
		return alg == "RS256"
	case *ecdsa.PublicKey:
		return alg == "ES256"
	}
	return false
}

func (k *keySet) fetch(call *fetchCall) {
	ctx, cancel := context.WithTimeout(WithHTTPClient(context.Background(), k.client), fetchTimeout)
	defer cancel()
	keys, err := k.load(ctx)

	k.mu.Lock()
	if err == nil {
		k.keys, k.loaded = keys, true
	}
	k.inflight = nil
	k.mu.Unlock()
	close(call.done)
}

var errNoKeys = errors.New("oidc: no usable signing keys")

// load fetches and filters the key list. Errors are fixed strings: a response
// body or URL is never carried in them.
func (k *keySet) load(ctx context.Context) ([]jose.JSONWebKey, error) {
	url := k.currentJWKSURL()
	if url == "" {
		p, err := gooidc.NewProvider(ctx, k.issuer)
		if err != nil {
			return nil, errors.New("oidc: discovery failed")
		}
		var doc struct {
			JWKSURL string `json:"jwks_uri"`
		}
		if err := p.Claims(&doc); err != nil || doc.JWKSURL == "" {
			return nil, errors.New("oidc: discovery has no jwks_uri")
		}
		url = doc.JWKSURL
		k.mu.Lock()
		k.jwksURL = url
		k.mu.Unlock()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New("oidc: bad jwks url")
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return nil, errors.New("oidc: jwks fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("oidc: jwks fetch status")
	}
	var set jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, errors.New("oidc: jwks decode failed")
	}
	var out []jose.JSONWebKey
	for _, key := range set.Keys {
		if usableKey(key) {
			out = append(out, key)
		}
	}
	if len(out) == 0 {
		return nil, errNoKeys
	}
	return out, nil
}

func (k *keySet) currentJWKSURL() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.jwksURL
}

func usableKey(key jose.JSONWebKey) bool {
	if !key.Valid() || !key.IsPublic() || (key.Use != "" && key.Use != "sig") {
		return false
	}
	switch pub := key.Key.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen() >= minRSABits
	case *ecdsa.PublicKey:
		return pub.Curve == elliptic.P256()
	}
	return false
}
