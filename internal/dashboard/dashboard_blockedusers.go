package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

// The user block list admin API (W-P1-BLOCK-11): list, add and remove entries.
// It is control-plane-only: the control plane sets a BlockListStore (or, with
// no --state-dir, a stub that answers state_dir_required) and on a worker, with
// none set, all routes are 404. Roles and the audit row are the control plane's
// authz table and middleware, not this file; the store adapter owns the
// caller's identity (created_by, self-unblock protection).

// Errors a BlockListStore returns. The handlers map them to 400, 409, 422, 404,
// 403 and 503. Wrap them with %w and, for ErrBlockInvalid, text that names the
// caller's own input problem (never an entry value or a reason).
var (
	ErrBlockInvalid       = errors.New("invalid entry")
	ErrBlockDuplicate     = errors.New("already blocked")
	ErrBlockTooMany       = errors.New("block list is full")
	ErrBlockNotFound      = errors.New("entry not found")
	ErrBlockSelfUnblock   = errors.New("self unblock forbidden")
	ErrBlockStateRequired = errors.New("state dir required")
)

// BlockListEntry is one entry as the API returns it.
type BlockListEntry struct {
	ID        string `json:"id"`
	Sub       string `json:"sub,omitempty"`
	Email     string `json:"email,omitempty"`
	Reason    string `json:"reason"`
	CreatedBy string `json:"createdBy"`
	CreatedAt string `json:"createdAt"` // RFC3339 (UTC)
}

// BlockListAdd is a validated-by-the-store add request.
type BlockListAdd struct {
	Sub    string
	Email  string
	Reason string
}

// BlockListStore is the dashboard's view of the block list. The control plane
// adapts its BlockStore to it; the dashboard imports neither cpstate nor
// controlplane. Implementations read the caller from ctx.
type BlockListStore interface {
	List(ctx context.Context) ([]BlockListEntry, error)
	// Add stores the entry and returns it as stored (normalized, with id).
	Add(ctx context.Context, in BlockListAdd) (BlockListEntry, error)
	// Remove deletes the entry; ErrBlockSelfUnblock when the caller is it.
	Remove(ctx context.Context, id string) error
}

const (
	blockedUsersPath = "/dashboard/api/blocked-users"
	// blockedUsersMaxBody bounds a POST body (sub, email and a 512-byte reason).
	blockedUsersMaxBody = 8 << 10
	// blockedUsersEmailHint is returned when only an email is given.
	blockedUsersEmailHint = "an email can change at the identity provider; also block the sub to keep the block when it does"
)

// SetBlockListStore wires the block list admin API. Set it before serving;
// without one (a worker) the routes are 404.
func (s *Server) SetBlockListStore(st BlockListStore) {
	s.blockList = st
}

type blockedUsersListResponse struct {
	Entries []BlockListEntry `json:"entries"`
}

type blockedUsersAddRequest struct {
	Sub    string `json:"sub"`
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

type blockedUsersAddResponse struct {
	BlockListEntry
	Hint string `json:"hint,omitempty"`
}

// handleBlockedUsers serves GET (list) and POST (add) on /dashboard/api/blocked-users.
func (s *Server) handleBlockedUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.blockList == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodGet {
		entries, err := s.blockList.List(r.Context())
		if err != nil {
			writeBlockError(w, err)
			return
		}
		if entries == nil {
			entries = []BlockListEntry{}
		}
		writeJSON(w, blockedUsersListResponse{Entries: entries})
		return
	}
	var req blockedUsersAddRequest
	if status, msg := decodeBlockBody(w, r, &req); status != 0 {
		writeError(w, status, msg)
		return
	}
	entry, err := s.blockList.Add(r.Context(), BlockListAdd(req))
	if err != nil {
		writeBlockError(w, err)
		return
	}
	resp := blockedUsersAddResponse{BlockListEntry: entry}
	if entry.Sub == "" && entry.Email != "" {
		resp.Hint = blockedUsersEmailHint
	}
	writeJSONStatus(w, http.StatusCreated, resp)
}

// handleBlockedUser serves DELETE /dashboard/api/blocked-users/{id}.
func (s *Server) handleBlockedUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.blockList == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	id, ok := blockedUserID(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found")
		return
	}
	if err := s.blockList.Remove(r.Context(), id); err != nil {
		writeBlockError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// blockedUserID extracts the single id segment after the collection path.
func blockedUserID(p string) (string, bool) {
	id, ok := strings.CutPrefix(p, blockedUsersPath+"/")
	if !ok || id == "" || strings.Contains(id, "/") {
		return "", false
	}
	return id, true
}

// decodeBlockBody reads a capped JSON body into v, rejecting unknown fields and
// trailing data. It returns a non-zero status and a fixed message on failure.
func decodeBlockBody(w http.ResponseWriter, r *http.Request, v any) (int, string) {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, blockedUsersMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return http.StatusRequestEntityTooLarge, "request body too large"
		}
		return http.StatusBadRequest, "body must be JSON {sub, email, reason}"
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return http.StatusRequestEntityTooLarge, "request body too large"
		}
		return http.StatusBadRequest, "body must be a single JSON object"
	}
	return 0, ""
}

// writeBlockError maps a store error to a fixed response. An unknown error is a
// 500 with a fixed message: the detail is the adapter's to log.
func writeBlockError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrBlockStateRequired):
		writeError(w, http.StatusServiceUnavailable, "state_dir_required")
	case errors.Is(err, ErrBlockInvalid):
		msg := strings.TrimPrefix(err.Error(), ErrBlockInvalid.Error()+": ")
		if msg == err.Error() {
			msg = "invalid entry"
		}
		writeError(w, http.StatusBadRequest, msg)
	case errors.Is(err, ErrBlockDuplicate):
		writeError(w, http.StatusConflict, "already_blocked")
	case errors.Is(err, ErrBlockTooMany):
		writeError(w, http.StatusUnprocessableEntity, "block_list_full")
	case errors.Is(err, ErrBlockNotFound):
		writeError(w, http.StatusNotFound, "not_found")
	case errors.Is(err, ErrBlockSelfUnblock):
		writeError(w, http.StatusForbidden, "self_unblock_forbidden")
	default:
		writeError(w, http.StatusInternalServerError, "block list unavailable")
	}
}
