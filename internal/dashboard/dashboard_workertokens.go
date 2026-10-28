package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// The worker token admin API (W-P1-WTOK-03): list, mint and revoke the
// per-worker tokens a data-plane worker authenticates with. The handlers reach
// the control plane's token store through WorkerTokenAdmin (internal/controlplane
// imports this package, not the other way round). The routes answer only when
// SetWorkerTokens was called, which the control plane does when it has a state
// dir; a worker or a control plane without one answers 404.
//
// The plaintext token exists in exactly one place: the 201 body of a create.
// Nothing here logs, caches or stores it, and no later response carries it.

// workerTokensPath is the collection; one token lives below it
// (workerTokensPath + "/{id}").
const workerTokensPath = "/dashboard/api/worker-tokens"

const (
	// maxWorkerTokenBody caps a create body ({name, proxyID, expiresIn}).
	maxWorkerTokenBody = 8 << 10
	// maxWorkerTokenExpiresIn bounds expiresIn, so an overflowing duration
	// cannot wrap into the past.
	maxWorkerTokenExpiresIn = 10 * 365 * 24 * time.Hour
)

// Errors a WorkerTokenAdmin returns. The handlers answer them with a fixed
// status; a wrapped message after the sentinel describes the caller's own input
// only and may be shown for the invalid case.
var (
	// ErrWorkerTokenInvalid: a name, proxy id or expiry is not acceptable (400).
	ErrWorkerTokenInvalid = errors.New("invalid worker token request")
	// ErrWorkerTokenConflict: the name is taken, or the proxy id already has the
	// maximum number of active tokens (409).
	ErrWorkerTokenConflict = errors.New("worker token conflict")
	// ErrWorkerTokenNotFound: no token has the id (404).
	ErrWorkerTokenNotFound = errors.New("worker token not found")
	// ErrWorkerTokenNoActor: the request carries no console identity to attribute
	// the change to (401).
	ErrWorkerTokenNoActor = errors.New("no console identity")
)

// WorkerTokenView is one token's metadata. It has no field for the plaintext or
// the hash. Times are RFC 3339 in UTC; an unset time is omitted.
type WorkerTokenView struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	ProxyID    string `json:"proxyID"`
	CreatedBy  string `json:"createdBy"`
	CreatedAt  string `json:"createdAt"`
	ExpiresAt  string `json:"expiresAt,omitempty"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
	RevokedAt  string `json:"revokedAt,omitempty"`
}

// WorkerTokenCreated is the 201 body of a create: the metadata and, once, the
// token.
type WorkerTokenCreated struct {
	WorkerTokenView
	Token string `json:"token"`
}

// WorkerTokenRequest is a create. ExpiresIn zero means the token never expires.
type WorkerTokenRequest struct {
	Name, ProxyID string
	ExpiresIn     time.Duration
}

// WorkerTokenAdmin is the control plane's token store as the dashboard sees it.
// ctx carries the caller's console identity, which the implementation records
// as the actor.
type WorkerTokenAdmin interface {
	List(ctx context.Context) ([]WorkerTokenView, error)
	// Create returns the plaintext once; no other call can.
	Create(ctx context.Context, req WorkerTokenRequest) (WorkerTokenView, string, error)
	Revoke(ctx context.Context, id string) error
}

// SetWorkerTokens enables the worker token routes. Only the control plane
// calls it; elsewhere the routes answer 404.
func (s *Server) SetWorkerTokens(a WorkerTokenAdmin) { s.workerTokens = a }

// workerTokenCreateReq is the create body. Unknown fields are rejected, so a
// field the API does not have (proxyIDPrefix) is an error rather than ignored.
type workerTokenCreateReq struct {
	Name      string `json:"name"`
	ProxyID   string `json:"proxyID"`
	ExpiresIn string `json:"expiresIn"`
}

// handleWorkerTokens serves /dashboard/api/worker-tokens: GET lists (revoked
// tokens included), POST mints.
func (s *Server) handleWorkerTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.workerTokens == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// A body or a refusal on this route may sit next to a credential; keep every
	// response out of shared caches.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		s.listWorkerTokens(w, r)
		return
	}
	if s.workerTokenWritesAllowed(w) {
		s.createWorkerToken(w, r)
	}
}

// handleWorkerTokenByID serves DELETE /dashboard/api/worker-tokens/{id}.
func (s *Server) handleWorkerTokenByID(w http.ResponseWriter, r *http.Request) {
	id, ok := workerTokenID(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.workerTokens == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.workerTokenWritesAllowed(w) {
		return
	}
	if err := s.workerTokens.Revoke(r.Context(), id); err != nil {
		writeWorkerTokenError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// workerTokenWritesAllowed refuses a mint or revoke unless the console has
// real identities (oidc). Without one there is nobody to attribute a mint to,
// and the console would be an open credential minter behind one shared bearer.
// It fails closed: an unset or unknown mode refuses.
func (s *Server) workerTokenWritesAllowed(w http.ResponseWriter) bool {
	if s.authMode == "oidc" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{
		"error":   "use_cli",
		"message": "worker tokens are not created or revoked from the console without sign-in (console.auth: none); use `warden control-plane token create|revoke` on the control plane host",
	})
	return false
}

func (s *Server) listWorkerTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.workerTokens.List(r.Context())
	if err != nil {
		writeWorkerTokenError(w, err)
		return
	}
	if toks == nil {
		toks = []WorkerTokenView{}
	}
	writeJSON(w, toks)
}

func (s *Server) createWorkerToken(w http.ResponseWriter, r *http.Request) {
	var req workerTokenCreateReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWorkerTokenBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// One JSON value only: trailing data is a malformed request.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	in := WorkerTokenRequest{Name: req.Name, ProxyID: req.ProxyID}
	if req.ExpiresIn != "" {
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 || d > maxWorkerTokenExpiresIn {
			writeError(w, http.StatusBadRequest, "expiresIn must be a positive duration such as 720h, at most 87600h")
			return
		}
		in.ExpiresIn = d
	}
	view, token, err := s.workerTokens.Create(r.Context(), in)
	if err != nil {
		writeWorkerTokenError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(WorkerTokenCreated{WorkerTokenView: view, Token: token})
}

// writeWorkerTokenError answers a WorkerTokenAdmin error with a fixed message.
// Only the invalid case echoes detail, which describes the caller's input; any
// other error stays server-side (the control plane logs it).
func writeWorkerTokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrWorkerTokenInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrWorkerTokenConflict):
		writeError(w, http.StatusConflict, "a worker token with this name exists, or the proxy id has too many active tokens")
	case errors.Is(err, ErrWorkerTokenNotFound):
		writeError(w, http.StatusNotFound, "worker token not found")
	case errors.Is(err, ErrWorkerTokenNoActor):
		writeError(w, http.StatusUnauthorized, "console session required")
	default:
		writeError(w, http.StatusInternalServerError, "worker token store error")
	}
}

// workerTokenID extracts {id} from /dashboard/api/worker-tokens/{id}. ok is
// false for an empty id, a nested path or a trailing slash.
func workerTokenID(p string) (string, bool) {
	id, found := strings.CutPrefix(p, workerTokensPath+"/")
	if !found || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}
