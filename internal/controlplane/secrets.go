package controlplane

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/secrets"
)

// maxSecretBodyBytes caps the POST /central/secrets request body. Secrets are a
// single small key/value pair, so a tight cap is ample; this mirrors the ingest
// handler's MaxBytesReader pattern (a bounded body read that fails closed on
// oversize) rather than reusing its 16 MiB cap, which is sized for event batches.
const maxSecretBodyBytes = 1 << 20 // 1 MiB

// awsSecretsClientFactory builds the AWS Secrets Manager client for a region,
// resolving credentials by precedence (explicit config keys → env → IMDS role).
// It is a package var so tests inject a fake without touching AWS or the network.
var awsSecretsClientFactory = secrets.NewAWSSecretsClient

// NewSecretStore builds the control plane's WRITE-scoped SecretStore from the
// operator's OWN secretStore.backend selection, or returns a nil store when no
// writable store is configured — in which case the /central/secrets endpoints
// are simply not mounted (a CP with backend env/none behaves exactly as before):
//
//   - echo → a NON-PRODUCTION EchoStore (persists nothing; the "value" is the
//     key itself), so the write→read→swap loop is provable with zero cloud deps.
//   - aws  → a write-scoped awsSecretStore over the real net/http + SigV4 client
//     (built from region/namePrefix + ENV credentials). Missing creds return an
//     error so the CP fails fast at startup rather than silently disabling writes.
//   - env / empty → env is a LOCAL read-only placeholder→envVar map with no write
//     surface, so there is nothing to expose (back-compat): nil store, no error.
//
// It mirrors how the fleet Store and Integrations are injected into Config: the
// thin cmd layer constructs the backend and hands the interface to the server.
func NewSecretStore(cfg config.SecretStoreConfig, logger *slog.Logger) (secrets.SecretStore, error) {
	if logger == nil {
		logger = slog.Default()
	}
	switch cfg.ResolvedBackend() {
	case config.SecretBackendEcho:
		logger.Warn("control plane ECHO secret store active — NON-PRODUCTION: it persists nothing and the resolved value is the key itself; never use it to protect a real secret")
		return secrets.NewEchoStore(), nil
	case config.SecretBackendAWS:
		if cfg.AWS == nil {
			return nil, fmt.Errorf("control plane secretStore.backend=aws requires an aws config block")
		}
		client, err := awsSecretsClientFactory(cfg.AWS.Region, cfg.AWS.AccessKeyID, cfg.AWS.SecretAccessKey)
		if err != nil {
			return nil, fmt.Errorf("control plane secretStore.backend=aws: %w", err)
		}
		// By-reference only: log the region/prefix and WHETHER explicit creds were
		// supplied — never the accessKeyId or secret value.
		logger.Info("control plane AWS secret store active",
			"region", cfg.AWS.Region, "namePrefix", cfg.AWS.NamePrefix,
			"explicitCredentials", cfg.AWS.AccessKeyID != "" && cfg.AWS.SecretAccessKey != "")
		return secrets.NewAWSSecretStore(client, cfg.AWS.Region, cfg.AWS.NamePrefix), nil
	default:
		// env / empty: no writable store — endpoints not mounted.
		return nil, nil
	}
}

// secretsAction is the action name a /central/secrets request is authorized
// and logged under in oidc mode.
func secretsAction(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead:
		return "secrets.read"
	case http.MethodDelete:
		return "secrets.delete"
	}
	return "secrets.write"
}

// secretsAuthOK gates every /central/secrets request and writes the refusal
// itself. In console.auth none it is adminBearerOK: the CP admin bearer, or the
// shared worker token while no admin token is configured. In oidc mode
// the routes are human routes: only an admin session counts, and the
// Authorization header is never read, so neither the shared token nor any
// other bearer opens them. withSession (wrapped around both mounts) has
// already refused a session write without a matching CSRF header or with a
// foreign Origin, and puts no Principal in the context without a live session;
// with sessions unavailable (no state db) every request is therefore 401.
func (s *Server) secretsAuthOK(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Console.Auth != config.ConsoleAuthOIDC {
		if !s.adminBearerOK(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return false
		}
		return true
	}
	row := authzRow{MinRole: config.RoleAdmin, Action: secretsAction(r.Method)}
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		logDenied(s.cfg.Logger, row, 0, Principal{}, r)
		writeAuthzJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return false
	}
	role, _ := s.cfg.Console.RoleFor(p.Groups)
	if role < row.MinRole {
		logDenied(s.cfg.Logger, row, role, p, r)
		writeAuthzJSON(w, http.StatusForbidden, map[string]string{"error": "role_required", "need": row.MinRole.String()})
		return false
	}
	return true
}

// handleSecrets serves the collection route POST /central/secrets (upsert) and
// GET /central/secrets (list metadata). It is mounted only when a writable store
// is configured; secretsAuthOK fronts every method (the admin bearer in none
// mode, an admin session plus CSRF in oidc mode).
func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	if !s.secretsAuthOK(w, r) {
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
	// The audit row names the key, never the value.
	adminaudit.Annotate(r.Context(), secretRef(key), map[string]string{adminaudit.DetailOp: "put"})
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

// secretRef is the admin audit target_ref of a secret key.
func secretRef(key string) string { return "secret:" + key }

// handleSecretByKey serves DELETE /central/secrets/{key}. Delete is idempotent
// (removing an absent key returns 204). Only DELETE is allowed on this subtree;
// there is no value in hand, so it logs the key only. secretsAuthOK gates it
// like the collection route.
func (s *Server) handleSecretByKey(w http.ResponseWriter, r *http.Request) {
	if !s.secretsAuthOK(w, r) {
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
	adminaudit.Annotate(r.Context(), secretRef(key), map[string]string{adminaudit.DetailOp: "delete"})
	if err := s.secretStore.Delete(r.Context(), key); err != nil {
		s.cfg.Logger.Error("control plane secret delete failed", "key", key, "error", err)
		http.Error(w, "secret store error", http.StatusInternalServerError)
		return
	}
	s.cfg.Logger.Info("control plane secret deleted", "key", key)
	w.WriteHeader(http.StatusNoContent)
}
