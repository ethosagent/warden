package controlplane

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ethosagent/warden/internal/keys"
)

// The public token JWKS and the readiness probe (W-P2-KEYS-04). Both are
// mounted on the control plane's mux directly: outside withSession, the authz
// table, the admin audit middleware and worker auth, because a verifier
// fetches the JWKS with no credential and a load balancer probes /readyz the
// same way. Neither does any I/O per request — the JWKS answers from bytes
// built from the KeySet's in-memory snapshot.

const (
	// jwksPath is the public token JWKS (RFC 8615 well-known location).
	jwksPath = "/.well-known/jwks.json"
	// readyzPath is readiness: 200 unless keys are enabled and a purpose has
	// no loaded active key. /healthz stays plain liveness.
	readyzPath = "/readyz"

	// jwksContentType is the media type of a JWK Set (RFC 7517 section 8.5.1).
	jwksContentType = "application/jwk-set+json"
	// jwksMaxAge is how long a verifier may cache the set. It is far inside
	// every prepublish window, so a key is always published before it signs.
	jwksMaxAge = 5 * time.Minute
	// jwksRecheck is how often a request re-derives the set when the KeySet
	// version has not moved: a retired key leaves the set when its overlap
	// ends, which changes no version.
	jwksRecheck = time.Second
)

// jwksDoc is one rendering of the token JWKS.
type jwksDoc struct {
	ver  uint64
	at   time.Time
	body []byte
	etag string
}

// jwksServer serves the token JWKS from a cached rendering. The rendering is
// rebuilt from the KeySet snapshot (memory only) when the KeySet version moves
// or jwksRecheck has passed, never per request: a burst of fetches costs one
// atomic load each.
type jwksServer struct {
	set *keys.KeySet
	now func() time.Time
	cur atomic.Pointer[jwksDoc]
}

func newJWKSServer(set *keys.KeySet, now func() time.Time) *jwksServer {
	j := &jwksServer{set: set, now: now}
	j.cur.Store(j.render())
	return j
}

// render builds the document from the snapshot. An empty set renders to a nil
// body (the handler answers 503).
func (j *jwksServer) render() *jwksDoc {
	ver := j.set.Version()
	at := j.now()
	set := j.set.JWKS(keys.PurposeToken)
	if len(set.Keys) == 0 {
		return &jwksDoc{ver: ver, at: at}
	}
	// keys.JWK has exactly kty, crv, x, y, kid, alg and use, none of them
	// private, so marshalling it is the whole filter.
	body, err := json.Marshal(set)
	if err != nil {
		return &jwksDoc{ver: ver, at: at}
	}
	sum := sha256.Sum256(body)
	return &jwksDoc{ver: ver, at: at, body: body, etag: `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`}
}

// doc returns the current rendering, refreshing it first when stale.
func (j *jwksServer) doc() *jwksDoc {
	d := j.cur.Load()
	if d.ver == j.set.Version() && j.now().Sub(d.at) < jwksRecheck {
		return d
	}
	nd := j.render()
	j.cur.Store(nd)
	return nd
}

// ServeHTTP answers GET and HEAD; every other method is 405.
func (j *jwksServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeAuthzJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	d := j.doc()
	h := w.Header()
	if d.body == nil {
		// Enabled but nothing published: a verifier must not cache this.
		h.Set("Cache-Control", "no-store")
		writeAuthzJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "signing_unavailable"})
		return
	}
	h.Set("Content-Type", jwksContentType)
	h.Set("Cache-Control", "public, max-age="+strconv.Itoa(int(jwksMaxAge/time.Second)))
	h.Set("ETag", d.etag)
	if etagMatches(r.Header.Get("If-None-Match"), d.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(d.body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(d.body)
	}
}

// etagMatches reports whether an If-None-Match header names etag (weak
// comparison, RFC 9110 section 13.1.2): "*", or any listed tag equal to etag
// once a W/ prefix is dropped.
func etagMatches(header, etag string) bool {
	for _, tag := range strings.Split(header, ",") {
		tag = strings.TrimSpace(tag)
		if tag == "*" || strings.TrimPrefix(tag, "W/") == etag {
			return true
		}
	}
	return false
}

// readyz serves GET /readyz: 200, or 503 {"keys":"no_active_key"} when keys
// are enabled and a purpose has no loaded active key. It reads the KeySet
// snapshot only.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeAuthzJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.cfg.Keys != nil && !s.cfg.Keys.Ready() {
		writeAuthzJSON(w, http.StatusServiceUnavailable, map[string]string{"keys": "no_active_key"})
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write([]byte("ok\n"))
	}
}
