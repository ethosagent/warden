package controlplane

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// maxSecretBodyBytes caps the POST /central/secrets request body. Secrets are a
// single small key/value pair, so a tight cap is ample; this mirrors the ingest
// handler's MaxBytesReader pattern (a bounded body read that fails closed on
// oversize) rather than reusing its 16 MiB cap, which is sized for event batches.
const maxSecretBodyBytes = 1 << 20 // 1 MiB

// NewSecretStore builds the control plane's WRITE-scoped SecretStore from the
// operator's OWN secretStore.backend selection, or returns nil when no writable
// store is configured — in which case the /central/secrets endpoints are simply
// not mounted (a CP with backend env/none behaves exactly as before):
//
//   - echo → a NON-PRODUCTION EchoStore (persists nothing; the "value" is the
//     key itself), so the write→read→swap loop is provable with zero cloud deps.
//   - aws  → not yet available (Phase 5): logs and returns nil, so the write
//     endpoints stay unmounted until the aws store lands.
//   - env / empty → env is a LOCAL read-only placeholder→envVar map with no write
//     surface, so there is nothing to expose (back-compat).
//
// It mirrors how the fleet Store and Integrations are injected into Config: the
// thin cmd layer constructs the backend and hands the interface to the server.
func NewSecretStore(cfg config.SecretStoreConfig, logger *slog.Logger) secrets.SecretStore {
	if logger == nil {
		logger = slog.Default()
	}
	switch cfg.ResolvedBackend() {
	case config.SecretBackendEcho:
		logger.Warn("control plane ECHO secret store active — NON-PRODUCTION: it persists nothing and the resolved value is the key itself; never use it to protect a real secret")
		return secrets.NewEchoStore()
	case config.SecretBackendAWS:
		logger.Info("control plane secretStore.backend=aws not yet available (Phase 5); secret write endpoints disabled")
		return nil
	default:
		// env / empty: no writable store — endpoints not mounted.
		return nil
	}
}

// bearerOK reports whether the request presents the configured bearer token,
// compared in constant time. An empty configured token disables auth (development
// only), matching the other CP routes. Shared by the secret endpoints and the
// heartbeat handler so the gate is defined once.
func (s *Server) bearerOK(r *http.Request) bool {
	if s.cfg.Token == "" {
		return true
	}
	want := "Bearer " + s.cfg.Token
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) == 1
}

// handleSecrets serves the collection route POST /central/secrets (upsert) and
// GET /central/secrets (list metadata). It is mounted only when a writable store
// is configured; the same constant-time bearer gate as the other /central/*
// routes fronts every method.
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.bearerOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		s.putSecret(w, r)
	case http.MethodGet:
		s.listSecrets(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// putSecret upserts a key→value. The value flows through the CP process IN
// TRANSIT only: it is handed straight to the backend store's Put and held for the
// request's duration — never persisted in the CP, never written to its own
// store/DB, and logged ONLY by-reference (Ref: sha256 + last-4 + length), never
// raw. Empty key or value → 400. Returns 204 on success.
func (s *Server) putSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecretBodyBytes)).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	key := strings.TrimSpace(body.Key)
	if key == "" || body.Value == "" {
		http.Error(w, "key and value are required", http.StatusBadRequest)
		return
	}
	if err := s.secretStore.Put(r.Context(), key, body.Value); err != nil {
		// By-reference only: the error path must not leak the value either.
		s.cfg.Logger.Error("control plane secret put failed",
			"key", key, "value", secrets.Ref(body.Value).String(), "error", err)
		http.Error(w, "secret store error", http.StatusInternalServerError)
		return
	}
	// BY-REFERENCE LOGGING ONLY — Ref hashes the value (sha256 + last-4 + length);
	// the raw value is never logged, and the CP retains nothing after this handler.
	s.cfg.Logger.Info("control plane secret upserted",
		"key", key, "value", secrets.Ref(body.Value).String())
	w.WriteHeader(http.StatusNoContent)
}

// listSecrets returns METADATA ONLY ([]secrets.SecretMeta: key, version,
// updatedAt) as JSON. SecretMeta is value-free by construction, so no value can
// cross this response. Always emits a JSON array (never null) for a stable client
// contract.
func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	metas, err := s.secretStore.List(r.Context())
	if err != nil {
		s.cfg.Logger.Error("control plane secret list failed", "error", err)
		http.Error(w, "secret store error", http.StatusInternalServerError)
		return
	}
	if metas == nil {
		metas = []secrets.SecretMeta{}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metas); err != nil {
		s.cfg.Logger.Error("control plane secret list encode failed", "error", err)
	}
}

// handleSecretByKey serves DELETE /central/secrets/{key}. Delete is idempotent
// (removing an absent key returns 204). Only DELETE is allowed on this subtree;
// there is no value in hand, so it logs the key only.
func (s *Server) handleSecretByKey(w http.ResponseWriter, r *http.Request) {
	if !s.bearerOK(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// r.URL.Path is already percent-decoded by net/http, so a key with escaped
	// characters arrives verbatim.
	key := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/central/secrets/"))
	if key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}
	if err := s.secretStore.Delete(r.Context(), key); err != nil {
		s.cfg.Logger.Error("control plane secret delete failed", "key", key, "error", err)
		http.Error(w, "secret store error", http.StatusInternalServerError)
		return
	}
	s.cfg.Logger.Info("control plane secret deleted", "key", key)
	w.WriteHeader(http.StatusNoContent)
}
