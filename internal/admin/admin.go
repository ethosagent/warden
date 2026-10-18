// Package admin exposes the proxy's small administrative HTTP surface:
// GET /healthz (liveness) and POST /admin/refresh-secrets (drop the secret
// cache and refetch; hard-fail on failure per the cache semantics). Every
// state-changing request under /admin/ is gated on the host's bearer token
// (SetWriteGuard) and fails closed when none is installed; GET and HEAD stay
// open.
package admin

import (
	"net/http"
	"path"
	"strings"
	"sync"

	"github.com/ethosagent/warden/internal/secrets"
)

// adminPrefix is the path prefix of every admin route. The write guard covers
// every method but GET/HEAD on every path under it, registered or not, so a new
// writer is guarded by default.
const adminPrefix = "/admin/"

// WriteGuard decides whether a state-changing /admin/ request may proceed. It
// returns status 0 to allow it, or the HTTP status and message to refuse with.
// It mirrors dashboard.WriteGuard so a host can pass the dashboard package's
// shared bearer guard straight through: this package cannot import the
// dashboard (the data plane never imports the control plane), so the type is
// re-declared here and the constant-time compare stays defined once.
type WriteGuard func(r *http.Request) (status int, msg string)

// Server holds the admin handlers' dependencies. It depends only on the
// SecretProvider interface, never on a concrete provider.
type Server struct {
	secrets secrets.SecretProvider

	// writeGuard, when set, gates every state-changing request under /admin/.
	writeGuardMu sync.RWMutex
	writeGuard   WriteGuard
}

// NewServer constructs the admin server over a SecretProvider.
func NewServer(sp secrets.SecretProvider) *Server {
	return &Server{secrets: sp}
}

// SetWriteGuard installs the guard run before every non-GET/HEAD request under
// /admin/. With none set, every write is refused (403): the default is deny,
// so a host that forgets to wire a guard cannot ship an open writer.
func (s *Server) SetWriteGuard(g WriteGuard) {
	s.writeGuardMu.Lock()
	defer s.writeGuardMu.Unlock()
	s.writeGuard = g
}

// Handler returns the admin HTTP mux with /healthz and /admin/refresh-secrets,
// behind the write guard.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/admin/refresh-secrets", s.refreshSecrets)
	return s.guardWrites(mux)
}

// guardWrites runs the write guard ahead of the mux. It keys on the cleaned
// path and fails closed on the method: anything but GET/HEAD under /admin/ is
// a write, registered or not; /healthz sits outside the prefix and stays open.
func (s *Server) guardWrites(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && strings.HasPrefix(path.Clean("/"+r.URL.Path)+"/", adminPrefix) {
			s.writeGuardMu.RLock()
			g := s.writeGuard
			s.writeGuardMu.RUnlock()
			if g == nil {
				http.Error(w, "admin writes are disabled: no write guard configured", http.StatusForbidden)
				return
			}
			if status, msg := g(r); status != 0 {
				http.Error(w, msg, status)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// healthz is a liveness probe; it always returns 200 OK while the process is
// serving.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// refreshSecrets triggers a manual cache refresh. On failure it returns 503 so
// callers see the hard-fail; on success it returns 200.
func (s *Server) refreshSecrets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.secrets.RefreshSecrets(); err != nil {
		http.Error(w, "refresh failed", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("refreshed"))
}
