package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// The worker certificate revoke route (W-P2-WCA-05): POST
// /dashboard/api/workers/{id}/revoke revokes every unexpired certificate of a
// worker, or the one named by an optional {serial}. The handler reaches the
// control plane's certificate store through WorkerCertAdmin. The route answers
// only when SetWorkerCertAdmin was called (workerCA enabled with a state dir).

// workersPath is the fleet collection; one worker's revoke lives below it.
const workersPath = "/dashboard/api/workers"

// maxWorkerRevokeBody caps the optional {serial} body.
const maxWorkerRevokeBody = 1 << 10

// Errors a WorkerCertAdmin returns.
var (
	// ErrWorkerCertNotFound: no such worker, or the serial is not its own (404).
	ErrWorkerCertNotFound = errors.New("worker certificate not found")
	// ErrWorkerCertInvalid: the serial is not acceptable (400).
	ErrWorkerCertInvalid = errors.New("invalid worker certificate request")
	// ErrWorkerCertNoActor: no console identity to attribute the revoke to (401).
	ErrWorkerCertNoActor = errors.New("no console identity")
)

// WorkerCertAdmin is the control plane's certificate store as the dashboard
// sees it. ctx carries the caller's console identity, which the implementation
// records as the actor.
type WorkerCertAdmin interface {
	// Revoke revokes the worker's unexpired certificates (only serial when it
	// is not empty) and returns how many it revoked; 0 when they were all
	// revoked already.
	Revoke(ctx context.Context, workerID, serial string) (int, error)
}

// SetWorkerCertAdmin enables the revoke route. Only the control plane calls
// it; elsewhere the route answers 404.
func (s *Server) SetWorkerCertAdmin(a WorkerCertAdmin) { s.workerCerts = a }

// workerRevokeID extracts {id} from /dashboard/api/workers/{id}/revoke.
func workerRevokeID(p string) (string, bool) {
	rest, found := strings.CutPrefix(p, workersPath+"/")
	if !found {
		return "", false
	}
	id, tail, _ := strings.Cut(rest, "/")
	if id == "" || tail != "revoke" {
		return "", false
	}
	return id, true
}

// handleWorkerRevoke serves POST /dashboard/api/workers/{id}/revoke.
func (s *Server) handleWorkerRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := workerRevokeID(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.workerCerts == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// Without real identities there is nobody to attribute the revoke to.
	if s.authMode != "oidc" {
		writeJSONStatus(w, http.StatusForbidden, map[string]string{
			"error":   "use_cli",
			"message": "worker certificates are not revoked from the console without sign-in (console.auth: none); use `warden control-plane worker revoke` on the control plane host",
		})
		return
	}
	var req struct {
		Serial string `json:"serial"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWorkerRevokeBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	} else if err == nil {
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}
	n, err := s.workerCerts.Revoke(r.Context(), id, req.Serial)
	switch {
	case err == nil:
		writeJSON(w, map[string]int{"revoked": n})
	case errors.Is(err, ErrWorkerCertNotFound):
		writeError(w, http.StatusNotFound, "worker not found")
	case errors.Is(err, ErrWorkerCertInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrWorkerCertNoActor):
		writeError(w, http.StatusUnauthorized, "console session required")
	default:
		writeError(w, http.StatusInternalServerError, "worker certificate store error")
	}
}
