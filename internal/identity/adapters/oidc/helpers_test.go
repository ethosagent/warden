package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ethosagent/warden/internal/identity"
)

var testNow = time.Unix(1_800_000_000, 0)

type signer struct {
	kid string
	alg string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

func newRSASigner(t testing.TB, kid string) *signer {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{kid: kid, alg: "RS256", rsa: k}
}

func newECSigner(t testing.TB, kid string) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{kid: kid, alg: "ES256", ec: k}
}

func (s *signer) jwk() jose.JSONWebKey {
	if s.rsa != nil {
		return jose.JSONWebKey{Key: &s.rsa.PublicKey, KeyID: s.kid, Algorithm: s.alg, Use: "sig"}
	}
	return jose.JSONWebKey{Key: &s.ec.PublicKey, KeyID: s.kid, Algorithm: s.alg, Use: "sig"}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// sign builds a signed token with the signer's own header.
func (s *signer) sign(claims map[string]any) string {
	return s.signHeader(map[string]any{"alg": s.alg, "kid": s.kid, "typ": "JWT"}, claims)
}

func (s *signer) signHeader(hdr, claims map[string]any) string {
	in := b64(mustJSON(hdr)) + "." + b64(mustJSON(claims))
	sum := sha256.Sum256([]byte(in))
	var sig []byte
	if s.rsa != nil {
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsa, crypto.SHA256, sum[:])
		if err != nil {
			panic(err)
		}
	} else {
		r, ss, err := ecdsa.Sign(rand.Reader, s.ec, sum[:])
		if err != nil {
			panic(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		ss.FillBytes(sig[32:])
	}
	return in + "." + b64(sig)
}

func hs256(secret []byte, hdr, claims map[string]any) string {
	in := b64(mustJSON(hdr)) + "." + b64(mustJSON(claims))
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(in))
	return in + "." + b64(m.Sum(nil))
}

// jwksServer serves discovery and a swappable key list, counting JWKS hits.
type jwksServer struct {
	*httptest.Server
	mu      sync.Mutex
	keys    []*signer
	hits    atomic.Int64
	disc    atomic.Int64
	status  atomic.Int64
	prefix  string
	issuerF func() string
	// gate, when set, blocks every JWKS response until it is closed.
	gate chan struct{}
}

func newJWKSServer(t testing.TB, prefix string, keys ...*signer) *jwksServer {
	t.Helper()
	s := &jwksServer{keys: keys, prefix: prefix}
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		s.disc.Add(1)
		iss := s.URL + prefix
		if s.issuerF != nil {
			iss = s.issuerF()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": s.URL + prefix + "/keys"})
	})
	mux.HandleFunc(prefix+"/keys", func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.gate != nil {
			<-s.gate
		}
		if st := int(s.status.Load()); st != 0 {
			w.WriteHeader(st)
			return
		}
		s.mu.Lock()
		set := jose.JSONWebKeySet{}
		for _, k := range s.keys {
			set.Keys = append(set.Keys, k.jwk())
		}
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(set)
	})
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func (s *jwksServer) setKeys(keys ...*signer) {
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
}

// clock is a settable fake time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func baseClaims(iss string, now time.Time) map[string]any {
	return map[string]any{
		"iss": iss, "sub": "suite-user", "aud": "warden", "azp": "cli",
		"email": "Suite.User@Example.com", "email_verified": true,
		"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	}
}

func newTestVerifier(t testing.TB, srv *jwksServer, c *clock, mod func(*Config)) identity.Verifier {
	t.Helper()
	cfg := Config{Issuer: srv.URL + srv.prefix, Audience: "warden", InternalIssuerURL: srv.URL, Now: c.now}
	if mod != nil {
		mod(&cfg)
	}
	v, err := NewOIDCVerifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func ctxTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
