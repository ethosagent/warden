// Package controlplane implements the Warden control plane: a server that
// distributes allow/deny policy to data-plane workers and aggregates their
// analytics for a fleet dashboard.
//
// Boundary invariant: the control plane is policy + visibility ONLY. It never
// holds or serves secrets. The policy sent to workers is an explicit allow/deny
// wire type (policyWire), so a future field added to config.Policy can never
// accidentally leak across the boundary — the guarantee is structural, not a
// matter of struct tags.
package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/secrets"
)

// Config configures the control-plane server.
type Config struct {
	// PolicyPath is the YAML file whose allow/deny policy is served to workers.
	// It is re-read on each /policy request so edits propagate on the next poll.
	PolicyPath string
	// Token is the bearer token workers must present on /policy and
	// /central/ingest. Empty disables auth (development only).
	Token string
	// MaxEvents caps the in-memory central analytics store (0 = default).
	MaxEvents int
	// Logger receives lifecycle and policy-load logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// policyWire is the ONLY shape sent to workers: allow/deny policy and nothing
// else. Secrets, judge config, and observability never appear here.
type policyWire struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
}

// Server is the control plane. It is safe for concurrent use.
type Server struct {
	cfg      Config
	central  *analytics.CentralStore
	mu       sync.RWMutex
	lastGood *policyWire
}

// New constructs a control-plane Server backed by an in-memory central store.
func New(cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Server{
		cfg:     cfg,
		central: analytics.NewCentralStore(cfg.MaxEvents),
	}
}

// Handler returns the control plane's HTTP routes:
//
//	GET  /policy          — allow/deny policy for workers (bearer-auth)
//	POST /central/ingest  — fleet analytics ingest (bearer-auth)
//	     /dashboard/      — fleet dashboard over the aggregated store
//	GET  /healthz         — liveness
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/policy", s.handlePolicy)
	mux.Handle("/central/ingest", analytics.NewIngestHandler(s.central, s.cfg.Token))

	// The fleet dashboard reads the aggregated central store. The control plane
	// holds no secrets, so it is given an empty secret provider and a
	// secret-free policy view; the dashboard's secrets panel is naturally empty.
	emptySecrets, _ := secrets.NewCache(secrets.NewEnvFetcher(map[string]string{}), 0, nil)
	wire, err := s.loadPolicy()
	if err != nil {
		s.cfg.Logger.Warn("control plane: dashboard starting with empty policy view", "error", err)
	}
	dashPolicy := config.Policy{Allowlist: wire.Allowlist, Denylist: wire.Denylist}
	dash := dashboard.NewServer(s.central, dashPolicy, emptySecrets)
	// Policy panel re-reads the served file so it reflects live edits, not the
	// snapshot captured when the control plane started.
	dash.SetLivePolicy(func() config.Policy {
		w, lErr := s.loadPolicy()
		if lErr != nil {
			return dashPolicy // fall back to the startup snapshot on a read error
		}
		return config.Policy{Allowlist: w.Allowlist, Denylist: w.Denylist}
	})
	mux.Handle("/dashboard/", dash.Handler())

	return mux
}

// handlePolicy serves the current allow/deny policy as JSON. On a load failure
// it serves the last-known-good policy (so a mid-edit malformed file never
// breaks workers); with no prior good policy it returns 500 and the worker
// keeps its own last-known-good.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.Token != "" {
		want := "Bearer " + s.cfg.Token
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	wire, err := s.loadPolicy()
	if err != nil {
		s.mu.RLock()
		lg := s.lastGood
		s.mu.RUnlock()
		if lg == nil {
			s.cfg.Logger.Error("control plane: policy load failed and no last-known-good", "error", err)
			http.Error(w, "policy unavailable", http.StatusInternalServerError)
			return
		}
		s.cfg.Logger.Warn("control plane: serving last-known-good policy", "error", err)
		wire = *lg
	} else {
		good := wire
		s.mu.Lock()
		s.lastGood = &good
		s.mu.Unlock()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wire)
}

// loadPolicy re-reads and validates the policy file, returning the allow/deny
// wire view. Re-reading per call keeps served policy fresh without a watcher.
func (s *Server) loadPolicy() (policyWire, error) {
	prov, err := config.NewLocalYAMLProvider(s.cfg.PolicyPath)
	if err != nil {
		return policyWire{}, err
	}
	p, err := prov.GetPolicy()
	if err != nil {
		return policyWire{}, err
	}
	return policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist}, nil
}
