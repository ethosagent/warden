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

// The worker enrollment token admin API (W-P2-WCA-08): list, mint and revoke
// the wet_ tokens a worker trades for a certificate at POST /control/enroll.
// The handlers reach the control plane's enrollment store through
// EnrollmentAdmin (internal/controlplane imports this package, not the other
// way round). The routes answer only when SetWorkerEnrollments was called,
// which the control plane does when workerCA is enabled with a state dir;
// elsewhere they answer 404.
//
// The plaintext token exists in exactly one place: the 201 body of a create.
// Nothing here logs, caches or stores it, and no later response carries it.

// workerEnrollmentsPath is the collection; one token lives below it
// (workerEnrollmentsPath + "/{id}").
const workerEnrollmentsPath = "/dashboard/api/worker-enrollments"

// maxEnrollmentBody caps a create body.
const maxEnrollmentBody = 8 << 10

// Errors an EnrollmentAdmin returns. The handlers answer them with a fixed
// status; a wrapped message after the invalid sentinel describes the caller's
// own input only and may be shown.
var (
	// ErrEnrollmentInvalid: a name, binding, use count or lifetime is not
	// acceptable (400).
	ErrEnrollmentInvalid = errors.New("invalid enrollment token request")
	// ErrEnrollmentConflict: the name is already used (409).
	ErrEnrollmentConflict = errors.New("enrollment token conflict")
	// ErrEnrollmentNotFound: no token has the id (404).
	ErrEnrollmentNotFound = errors.New("enrollment token not found")
	// ErrEnrollmentNoActor: the request carries no console identity to
	// attribute the change to (401).
	ErrEnrollmentNoActor = errors.New("no console identity")
)

// EnrollmentView is one token's metadata. It has no field for the plaintext or
// the hash. Times are RFC 3339 in UTC; an unset time is omitted. Exactly one of
// WorkerID and WorkerIDPrefix is set.
type EnrollmentView struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	WorkerID       string `json:"workerId,omitempty"`
	WorkerIDPrefix string `json:"workerIdPrefix,omitempty"`
	MaxUses        int    `json:"maxUses"`
	Uses           int    `json:"uses"`
	CreatedBy      string `json:"createdBy"`
	CreatedAt      string `json:"createdAt"`
	ExpiresAt      string `json:"expiresAt,omitempty"`
	RevokedAt      string `json:"revokedAt,omitempty"`
}

// EnrollmentCreated is the 201 body of a create: the metadata and, once, the
// token.
type EnrollmentCreated struct {
	EnrollmentView
	Token string `json:"token"`
}

// EnrollmentRequest is a create. MaxUses zero means one use; ExpiresIn zero
// means the control plane's workerCA.enrollTokenTTL.
type EnrollmentRequest struct {
	Name           string
	WorkerID       string
	WorkerIDPrefix string
	MaxUses        int
	ExpiresIn      time.Duration
}

// EnrollmentAdmin is the control plane's enrollment token store as the
// dashboard sees it. ctx carries the caller's console identity, which the
// implementation records as the actor.
type EnrollmentAdmin interface {
	List(ctx context.Context) ([]EnrollmentView, error)
	// Create returns the plaintext once; no other call can.
	Create(ctx context.Context, req EnrollmentRequest) (EnrollmentView, string, error)
	// Revoke is idempotent; an unknown id is ErrEnrollmentNotFound.
	Revoke(ctx context.Context, id string) error
}

// SetWorkerEnrollments enables the enrollment token routes. Only the control
// plane calls it; elsewhere the routes answer 404.
func (s *Server) SetWorkerEnrollments(a EnrollmentAdmin) { s.enrollments = a }

// enrollmentCreateReq is the create body. Unknown fields are rejected, so a
// misspelled field is an error rather than silently ignored.
type enrollmentCreateReq struct {
	Name           string `json:"name"`
	WorkerID       string `json:"workerId"`
	WorkerIDPrefix string `json:"workerIdPrefix"`
	MaxUses        int    `json:"maxUses"`
	ExpiresIn      string `json:"expiresIn"`
}

// handleWorkerEnrollments serves /dashboard/api/worker-enrollments: GET lists
// (revoked tokens included), POST mints.
func (s *Server) handleWorkerEnrollments(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.enrollments == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	// A body or a refusal on this route may sit next to a credential; keep every
	// response out of shared caches.
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		s.listEnrollments(w, r)
		return
	}
	if s.enrollmentWritesAllowed(w) {
		s.createEnrollment(w, r)
	}
}

// handleWorkerEnrollment serves DELETE /dashboard/api/worker-enrollments/{id}.
func (s *Server) handleWorkerEnrollment(w http.ResponseWriter, r *http.Request) {
	id, ok := workerEnrollmentID(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.enrollments == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.enrollmentWritesAllowed(w) {
		return
	}
	if err := s.enrollments.Revoke(r.Context(), id); err != nil {
		writeEnrollmentError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// enrollmentWritesAllowed refuses a mint or revoke unless the console has real
// identities (oidc): without one there is nobody to attribute a mint to, and
// the console would be an open credential minter behind one shared bearer. It
// fails closed: an unset or unknown mode refuses.
func (s *Server) enrollmentWritesAllowed(w http.ResponseWriter) bool {
	if s.authMode == "oidc" {
		return true
	}
	writeJSONStatus(w, http.StatusForbidden, map[string]string{
		"error":   "use_cli",
		"message": "enrollment tokens are not created or revoked from the console without sign-in (console.auth: none); use `warden control-plane enroll-token create|revoke` on the control plane host",
	})
	return false
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	toks, err := s.enrollments.List(r.Context())
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	if toks == nil {
		toks = []EnrollmentView{}
	}
	writeJSON(w, toks)
}

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req enrollmentCreateReq
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEnrollmentBody))
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
	in := EnrollmentRequest{Name: req.Name, WorkerID: req.WorkerID, WorkerIDPrefix: req.WorkerIDPrefix, MaxUses: req.MaxUses}
	if req.ExpiresIn != "" {
		// The upper bound only guards against an overflowing duration; the
		// store applies workerCA.enrollTokenMaxTTL.
		d, err := time.ParseDuration(req.ExpiresIn)
		if err != nil || d <= 0 || d > maxWorkerTokenExpiresIn {
			writeError(w, http.StatusBadRequest, "expiresIn must be a positive duration such as 1h")
			return
		}
		in.ExpiresIn = d
	}
	view, token, err := s.enrollments.Create(r.Context(), in)
	if err != nil {
		writeEnrollmentError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(EnrollmentCreated{EnrollmentView: view, Token: token})
}

// writeEnrollmentError answers an EnrollmentAdmin error with a fixed message.
// Only the invalid case echoes detail, which describes the caller's input; any
// other error stays server-side (the control plane logs it).
func writeEnrollmentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEnrollmentInvalid):
		writeError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrEnrollmentConflict):
		writeError(w, http.StatusConflict, "an enrollment token with this name exists")
	case errors.Is(err, ErrEnrollmentNotFound):
		writeError(w, http.StatusNotFound, "enrollment token not found")
	case errors.Is(err, ErrEnrollmentNoActor):
		writeError(w, http.StatusUnauthorized, "console session required")
	default:
		writeError(w, http.StatusInternalServerError, "enrollment token store error")
	}
}

// workerEnrollmentID extracts {id} from /dashboard/api/worker-enrollments/{id}.
// ok is false for an empty id, a nested path or a trailing slash.
func workerEnrollmentID(p string) (string, bool) {
	id, found := strings.CutPrefix(p, workerEnrollmentsPath+"/")
	if !found || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}
