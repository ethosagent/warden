package fakes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file is the in-process OIDC issuer fake (W-P1-VRFY-11). It deliberately
// imports neither internal/identity nor internal/controlplane: the fake must
// not share code with the verifier it tests, and the issuer must stay usable
// from packages those import. It signs with crypto/rsa and crypto/ecdsa
// directly, so there is no JWT library and no committed key: every instance
// generates its own.

// Defaults a freshly minted token carries; verifier configs in tests use them.
const (
	// OIDCAudience is the default aud claim.
	OIDCAudience = "warden-test"
	// OIDCAZP is the default azp claim.
	OIDCAZP = "warden-test-client"
	// OIDCTokenTTL is the default exp-iat of a minted token.
	OIDCTokenTTL = 5 * time.Minute
)

// OIDCIssuer is an httptest OIDC provider: a discovery document and a JWKS
// endpoint, plus Mint to sign tokens it vouches for. Safe for concurrent use.
type OIDCIssuer struct {
	tb   testing.TB
	now  func() time.Time
	addr string

	jwksReqs atomic.Int64
	discReqs atomic.Int64

	mu      sync.Mutex
	srv     *httptest.Server // nil while stopped
	keys    []*issuerKey     // published, in order; keys[0] signs by default
	nextKID int
}

// IssuerOption customizes NewOIDCIssuer.
type IssuerOption func(*OIDCIssuer)

// WithIssuerClock makes Mint take "now" from fn (the harness passes its fake
// clock so tokens agree with the worker's time).
func WithIssuerClock(fn func() time.Time) IssuerOption {
	return func(i *OIDCIssuer) { i.now = fn }
}

type issuerKey struct {
	kid string
	alg string
	rsa *rsa.PrivateKey
	ec  *ecdsa.PrivateKey
}

// NewOIDCIssuer starts the issuer on a loopback port with one RS256 and one
// ES256 key, and stops it at test cleanup.
func NewOIDCIssuer(tb testing.TB, opts ...IssuerOption) *OIDCIssuer {
	tb.Helper()
	i := &OIDCIssuer{tb: tb, now: time.Now}
	for _, o := range opts {
		o(i)
	}
	i.keys = []*issuerKey{i.genRSA(), i.genEC()}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("oidc issuer: listen: %v", err)
	}
	i.addr = l.Addr().String()
	i.serve(l)
	tb.Cleanup(i.Stop)
	return i
}

// Issuer is the iss string: the base URL, stable across Stop and Start.
func (i *OIDCIssuer) Issuer() string { return "http://" + i.addr }

// JWKSURL is where the key set is served.
func (i *OIDCIssuer) JWKSURL() string { return i.Issuer() + "/jwks" }

// JWKSRequests counts JWKS requests served since creation.
func (i *OIDCIssuer) JWKSRequests() int { return int(i.jwksReqs.Load()) }

// DiscoveryRequests counts discovery document requests served.
func (i *OIDCIssuer) DiscoveryRequests() int { return int(i.discReqs.Load()) }

// KIDs lists the published key ids in publication order.
func (i *OIDCIssuer) KIDs() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]string, len(i.keys))
	for n, k := range i.keys {
		out[n] = k.kid
	}
	return out
}

// Stop closes the server (issuer-down and cold-cache cases). Idempotent.
func (i *OIDCIssuer) Stop() {
	i.mu.Lock()
	srv := i.srv
	i.srv = nil
	i.mu.Unlock()
	if srv != nil {
		srv.CloseClientConnections()
		srv.Close()
	}
}

// Start brings a stopped issuer back on the same address, with the same keys.
func (i *OIDCIssuer) Start() {
	i.tb.Helper()
	i.mu.Lock()
	running := i.srv != nil
	i.mu.Unlock()
	if running {
		return
	}
	var l net.Listener
	var err error
	for n := 0; n < 50; n++ { // the port can linger briefly after Close
		if l, err = net.Listen("tcp", i.addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		i.tb.Fatalf("oidc issuer: restart on %s: %v", i.addr, err)
	}
	i.serve(l)
}

func (i *OIDCIssuer) serve(l net.Listener) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(i.route))
	srv.Listener = l
	srv.Start()
	i.mu.Lock()
	i.srv = srv
	i.mu.Unlock()
}

// route dispatches the two endpoints by path (a switch, not a mux, so the fake
// registers no routes: X9 keeps those in a server's routes.go).
func (i *OIDCIssuer) route(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		i.handleDiscovery(w, r)
	case "/jwks":
		i.handleJWKS(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (i *OIDCIssuer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	i.discReqs.Add(1)
	writeJSON(w, map[string]any{
		"issuer":                                i.Issuer(),
		"jwks_uri":                              i.JWKSURL(),
		"authorization_endpoint":                i.Issuer() + "/auth",
		"token_endpoint":                        i.Issuer() + "/token",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
	})
}

func (i *OIDCIssuer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	i.jwksReqs.Add(1)
	i.mu.Lock()
	keys := make([]map[string]string, 0, len(i.keys))
	for _, k := range i.keys {
		keys = append(keys, k.jwk())
	}
	i.mu.Unlock()
	writeJSON(w, map[string]any{"keys": keys})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *issuerKey) jwk() map[string]string {
	if k.rsa != nil {
		return map[string]string{
			"kty": "RSA", "use": "sig", "alg": k.alg, "kid": k.kid,
			"n": b64url(k.rsa.N.Bytes()),
			"e": b64url(big.NewInt(int64(k.rsa.E)).Bytes()),
		}
	}
	pad := func(n *big.Int) string { return b64url(n.FillBytes(make([]byte, 32))) }
	return map[string]string{
		"kty": "EC", "use": "sig", "alg": k.alg, "kid": k.kid, "crv": "P-256",
		"x": pad(k.ec.X), "y": pad(k.ec.Y),
	}
}

func (i *OIDCIssuer) newKID(prefix string) string {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.nextKID++
	return fmt.Sprintf("%s-%d", prefix, i.nextKID)
}

func (i *OIDCIssuer) genRSA() *issuerKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		i.tb.Fatalf("oidc issuer: generate RSA key: %v", err)
	}
	return &issuerKey{kid: i.newKID("rs"), alg: "RS256", rsa: k}
}

func (i *OIDCIssuer) genEC() *issuerKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		i.tb.Fatalf("oidc issuer: generate EC key: %v", err)
	}
	return &issuerKey{kid: i.newKID("es"), alg: "ES256", ec: k}
}

// sign signs in with the key's own algorithm, or produces an empty signature
// for the header alg "none".
func (k *issuerKey) sign(in string, headerAlg string) ([]byte, error) {
	if headerAlg == "none" {
		return nil, nil
	}
	sum := sha256.Sum256([]byte(in))
	var signer crypto.Signer = k.ec
	if k.rsa != nil {
		signer = k.rsa
	}
	sig, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil || k.rsa != nil {
		return sig, err
	}
	// crypto.Signer returns ES256 as ASN.1 DER; JWS wants fixed-width r||s.
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	rs.R.FillBytes(out[:32])
	rs.S.FillBytes(out[32:])
	return out, nil
}

// mintSpec is what Mint builds a token from; MintOptions edit it.
type mintSpec struct {
	iss    *OIDCIssuer
	claims map[string]any
	header map[string]any
	omit   map[string]bool
	key    *issuerKey
}

// MintOption overrides one part of a token. Options apply in order; a later
// one wins.
type MintOption func(*mintSpec)

// Mint signs a token. With no options it is a valid token for the default
// audience and azp, signed by the first RS256 key. Failures print claim and
// option names only, never token text.
func (i *OIDCIssuer) Mint(opts ...MintOption) string {
	i.tb.Helper()
	now := i.now()
	i.mu.Lock()
	def := i.keys[0]
	i.mu.Unlock()
	s := &mintSpec{
		iss: i,
		claims: map[string]any{
			"iss": i.Issuer(), "sub": "user-1", "aud": OIDCAudience, "azp": OIDCAZP,
			"iat": now.Unix(), "exp": now.Add(OIDCTokenTTL).Unix(),
		},
		header: map[string]any{"typ": "JWT"},
		omit:   map[string]bool{},
		key:    def,
	}
	for _, o := range opts {
		o(s)
	}
	if _, ok := s.header["alg"]; !ok {
		s.header["alg"] = s.key.alg
	}
	if _, ok := s.header["kid"]; !ok {
		s.header["kid"] = s.key.kid
	}
	for name := range s.omit {
		delete(s.claims, name)
	}
	hb, err := json.Marshal(s.header)
	if err != nil {
		i.tb.Fatalf("oidc issuer: encode token header: %v", err)
	}
	cb, err := json.Marshal(s.claims)
	if err != nil {
		i.tb.Fatalf("oidc issuer: encode token claims: %v", err)
	}
	in := b64url(hb) + "." + b64url(cb)
	alg, _ := s.header["alg"].(string)
	sig, err := s.key.sign(in, alg)
	if err != nil {
		i.tb.Fatalf("oidc issuer: sign token: %v", err)
	}
	return in + "." + b64url(sig)
}

// WithClaim sets any claim by name, including ones with no dedicated option.
func WithClaim(name string, v any) MintOption {
	return func(s *mintSpec) { s.claims[name] = v; delete(s.omit, name) }
}

// WithoutClaim removes claims from the token (a missing exp, aud, ...).
func WithoutClaim(names ...string) MintOption {
	return func(s *mintSpec) {
		for _, n := range names {
			s.omit[n] = true
		}
	}
}

// WithIss overrides iss.
func WithIss(v string) MintOption { return WithClaim("iss", v) }

// WithSub overrides sub.
func WithSub(v string) MintOption { return WithClaim("sub", v) }

// WithAud overrides aud with a single string.
func WithAud(v ...string) MintOption {
	return func(s *mintSpec) {
		delete(s.omit, "aud")
		if len(v) == 1 {
			s.claims["aud"] = v[0]
			return
		}
		s.claims["aud"] = v
	}
}

// WithAZP overrides azp.
func WithAZP(v string) MintOption { return WithClaim("azp", v) }

// WithEmail overrides email.
func WithEmail(v string) MintOption { return WithClaim("email", v) }

// WithEmailVerified overrides email_verified.
func WithEmailVerified(v bool) MintOption { return WithClaim("email_verified", v) }

// WithGroups sets the groups claim.
func WithGroups(v ...string) MintOption { return WithClaim("groups", v) }

// WithSID overrides sid.
func WithSID(v string) MintOption { return WithClaim("sid", v) }

// WithNonce overrides nonce.
func WithNonce(v string) MintOption { return WithClaim("nonce", v) }

// WithExp overrides exp.
func WithExp(t time.Time) MintOption { return WithClaim("exp", t.Unix()) }

// WithNBF sets nbf.
func WithNBF(t time.Time) MintOption { return WithClaim("nbf", t.Unix()) }

// WithIAT overrides iat.
func WithIAT(t time.Time) MintOption { return WithClaim("iat", t.Unix()) }

// WithAlg overrides the alg header only; the signature still comes from the
// signing key's own algorithm (except "none", which is unsigned), so a lying
// header is what the verifier sees.
func WithAlg(alg string) MintOption {
	return func(s *mintSpec) { s.header["alg"] = alg }
}

// WithKID overrides the kid header only (the signing key is unchanged).
func WithKID(kid string) MintOption {
	return func(s *mintSpec) { s.header["kid"] = kid }
}

// WithHeader sets any extra header field (typ, jku, x5u, crit, ...).
func WithHeader(name string, v any) MintOption {
	return func(s *mintSpec) { s.header[name] = v }
}

// WithSigningKey signs with the published key whose kid is given; the header
// alg and kid follow that key. An unknown kid fails the test.
func WithSigningKey(kid string) MintOption {
	return func(s *mintSpec) {
		s.iss.mu.Lock()
		defer s.iss.mu.Unlock()
		for _, k := range s.iss.keys {
			if k.kid == kid {
				s.key = k
				delete(s.header, "alg")
				delete(s.header, "kid")
				return
			}
		}
		s.iss.tb.Fatalf("oidc issuer: WithSigningKey: no published key with kid %q", kid)
	}
}

// WithES256 signs with the published ES256 key.
func WithES256() MintOption { return withPublishedAlg("ES256") }

func withPublishedAlg(alg string) MintOption {
	return func(s *mintSpec) {
		s.iss.mu.Lock()
		defer s.iss.mu.Unlock()
		for _, k := range s.iss.keys {
			if k.alg == alg {
				s.key = k
				delete(s.header, "alg")
				delete(s.header, "kid")
				return
			}
		}
		s.iss.tb.Fatalf("oidc issuer: no published %s key", alg)
	}
}

// WithUnpublishedKey signs with a fresh key that is never published: the
// token's kid is not in the JWKS, or (with WithKID of a published kid) its
// signature does not match.
func WithUnpublishedKey() MintOption {
	return func(s *mintSpec) {
		k := s.iss.genRSA()
		k.kid = "unpublished-" + k.kid
		s.key = k
		delete(s.header, "alg")
		delete(s.header, "kid")
	}
}

// Valid is a token for sub with the given email (verified) and groups.
func Valid(sub, email string, groups ...string) MintOption {
	return func(s *mintSpec) {
		WithSub(sub)(s)
		WithEmail(email)(s)
		WithEmailVerified(true)(s)
		if len(groups) > 0 {
			WithGroups(groups...)(s)
		}
	}
}

// Expired is a token whose exp is well past any clock skew.
func Expired() MintOption {
	return func(s *mintSpec) {
		now := s.iss.now()
		WithIAT(now.Add(-30 * time.Minute))(s)
		WithExp(now.Add(-10 * time.Minute))(s)
	}
}

// WrongAudience is a token for an audience nobody asked for.
func WrongAudience() MintOption { return WithAud("someone-else") }

// WrongAZP is a token issued to a client outside the allowed azp set.
func WrongAZP() MintOption { return WithAZP("unexpected-client") }

// TooLong is a token whose lifetime (exp-iat) is 2h, over the 1h ceiling.
func TooLong() MintOption {
	return func(s *mintSpec) {
		now := s.iss.now()
		WithIAT(now)(s)
		WithExp(now.Add(2 * time.Hour))(s)
	}
}

// RotateKey publishes a new RS256 key under a fresh kid and signs with it.
// The kid is unknown to a verifier that cached the JWKS before this call.
func RotateKey() MintOption {
	return func(s *mintSpec) {
		k := s.iss.genRSA()
		s.iss.mu.Lock()
		s.iss.keys = append(s.iss.keys, k)
		s.iss.mu.Unlock()
		s.key = k
		delete(s.header, "alg")
		delete(s.header, "kid")
	}
}
