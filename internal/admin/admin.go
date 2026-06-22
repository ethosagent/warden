// Package admin exposes the proxy's small administrative HTTP surface:
// GET /healthz (liveness) and POST /admin/refresh-secrets (drop the secret
// cache and refetch; hard-fail on failure per the cache semantics).
package admin

import (
	"net/http"

	"github.com/ethosagent/warden/internal/secrets"
)

// Server holds the admin handlers' dependencies. It depends only on the
// SecretProvider interface, never on a concrete provider.
type Server struct {
	secrets secrets.SecretProvider
}

// NewServer constructs the admin server over a SecretProvider.
func NewServer(sp secrets.SecretProvider) *Server {
	return &Server{secrets: sp}
}

// Handler returns the admin HTTP mux with /healthz and /admin/refresh-secrets.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.healthz)
	mux.HandleFunc("/admin/refresh-secrets", s.refreshSecrets)
	return mux
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
