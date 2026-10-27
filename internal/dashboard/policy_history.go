package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The policy history API (W-P1-PVER-03): list the versions of the versioned
// policy document, fetch one, diff two and roll back to one. The handlers reach
// the control plane's store through PolicyHistory (internal/controlplane
// imports this package, not the other way round). The routes answer only when
// SetPolicyHistory was called, which the control plane does in
// --policy-store=versioned; a worker or a file-mode control plane answers 404.

// policyVersionsPath is the history list; one version, its diff and its
// rollback live below it (policyVersionsPath + "/{v}[/diff|/rollback]").
const policyVersionsPath = "/dashboard/api/policy/versions"

// Policy history bounds.
const (
	defaultHistoryLimit = 50
	maxHistoryLimit     = 200
	// maxRollbackNote caps the optional rollback note, in characters.
	maxRollbackNote = maxPolicyMessage
	// maxRollbackBody caps the rollback request body ({"note": ...}).
	maxRollbackBody = 4 << 10
)

// ErrPolicyVersionNotFound is returned by a PolicyHistory method for a version
// the store does not hold. The handlers answer it with 404.
var ErrPolicyVersionNotFound = errors.New("policy version not found")

// InvalidPolicyError is returned by a versioned writer when the document it
// would publish fails validation with today's config loader. Err is the
// loader's error, which describes the document only. A rollback answers it
// with 422; the other writers keep answering validation errors with 400.
type InvalidPolicyError struct{ Err error }

func (e *InvalidPolicyError) Error() string { return e.Err.Error() }

func (e *InvalidPolicyError) Unwrap() error { return e.Err }

// PolicyVersionMeta is one version's metadata, without its document.
type PolicyVersionMeta struct {
	Version     int64     `json:"version"`
	Parent      int64     `json:"parent"`
	CreatedAt   time.Time `json:"created_at"`
	AuthorSub   string    `json:"author_sub"`
	AuthorEmail string    `json:"author_email"`
	AuthorKind  string    `json:"author_kind"`
	Message     string    `json:"message"`
	Source      string    `json:"source"`
	DocSHA256   string    `json:"doc_sha256"`
}

// PolicyVersionDoc is one version with its document. Doc carries credentials
// only as fingerprints (sha256:<16 hex>), never a raw value.
type PolicyVersionDoc struct {
	PolicyVersionMeta
	Doc any `json:"doc"`
}

// PolicyVersionDiff is the structural diff from version From to version To:
// what moving the policy from From to To changes. Diff is the control plane's
// DiffDocs result (W-P1-PVER-09).
type PolicyVersionDiff struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
	Diff any   `json:"diff"`
}

// RollbackResult is a rollback's outcome. Changed is false when the target's
// document equals head's: no version was created and Head is unchanged.
type RollbackResult struct {
	Head    int64 `json:"head"`
	Changed bool  `json:"changed"`
}

// PolicyHistory is the versioned policy store as the history routes see it.
// The control plane implements it over its PolicyVersionStore.
type PolicyHistory interface {
	// List returns up to limit versions older than cursor (0 = from the
	// newest), newest first, and the cursor of the next page (0 = no more).
	List(ctx context.Context, cursor int64, limit int) ([]PolicyVersionMeta, int64, error)
	// Get returns one version with its credential-redacted document.
	Get(ctx context.Context, version int64) (PolicyVersionDoc, error)
	// Diff returns the diff from version against (0 = head) to version.
	Diff(ctx context.Context, version, against int64) (PolicyVersionDiff, error)
	// Rollback publishes version's document as a new head version, based on
	// meta.ExpectedHead, with note appended to its message. A moved head is a
	// *ConflictError and a target that no longer validates an
	// *InvalidPolicyError.
	Rollback(ctx context.Context, version int64, note string, meta WriteMeta) (RollbackResult, error)
}

// SetPolicyHistory enables the policy history routes. Set only on a control
// plane in --policy-store=versioned; without it the routes answer 404.
func (s *Server) SetPolicyHistory(h PolicyHistory) {
	s.policyHistory = h
}

// policyVersionsResponse is GET /dashboard/api/policy/versions.
type policyVersionsResponse struct {
	Head       int64               `json:"head"`
	Versions   []PolicyVersionMeta `json:"versions"`
	NextCursor int64               `json:"next_cursor"`
}

// rollbackRequest is the optional POST .../rollback body.
type rollbackRequest struct {
	Note string `json:"note"`
}

// handlePolicyVersions serves GET /dashboard/api/policy/versions?cursor=&limit=.
func (s *Server) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.policyHistory == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	q := r.URL.Query()
	cursor, ok := positiveParam(q.Get("cursor"), 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid cursor: want a version number")
		return
	}
	limit, ok := positiveParam(q.Get("limit"), defaultHistoryLimit)
	if !ok || limit < 1 {
		writeError(w, http.StatusBadRequest, "invalid limit: want a positive integer")
		return
	}
	head, ok := s.versionForGet(w, r)
	if !ok {
		return
	}
	versions, next, err := s.policyHistory.List(r.Context(), cursor, int(min(limit, maxHistoryLimit)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the policy history")
		return
	}
	if versions == nil {
		versions = []PolicyVersionMeta{}
	}
	writeJSON(w, policyVersionsResponse{Head: head, Versions: versions, NextCursor: next})
}

// handlePolicyVersion serves the routes below a version:
//
//	GET  /dashboard/api/policy/versions/{v}
//	GET  /dashboard/api/policy/versions/{v}/diff?against={u}
//	POST /dashboard/api/policy/versions/{v}/rollback
func (s *Server) handlePolicyVersion(w http.ResponseWriter, r *http.Request) {
	seg, action, ok := splitVersionPath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	want := http.MethodGet
	if action == "rollback" {
		want = http.MethodPost
	}
	if r.Method != want {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.policyHistory == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	v, ok := positiveParam(seg, 0)
	if !ok || v == 0 {
		writeError(w, http.StatusBadRequest, "invalid version: want a positive integer")
		return
	}
	switch action {
	case "":
		s.getPolicyVersion(w, r, v)
	case "diff":
		s.diffPolicyVersion(w, r, v)
	default:
		s.rollbackPolicyVersion(w, r, v)
	}
}

func (s *Server) getPolicyVersion(w http.ResponseWriter, r *http.Request, v int64) {
	doc, err := s.policyHistory.Get(r.Context(), v)
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, doc)
}

func (s *Server) diffPolicyVersion(w http.ResponseWriter, r *http.Request, v int64) {
	against, ok := positiveParam(r.URL.Query().Get("against"), 0)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid against: want a version number")
		return
	}
	d, err := s.policyHistory.Diff(r.Context(), v, against)
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	writeJSON(w, d)
}

// rollbackPolicyVersion requires If-Match (428 without it, 400 malformed): a
// rollback is always based on the head the editor saw.
func (s *Server) rollbackPolicyVersion(w http.ResponseWriter, r *http.Request, v int64) {
	expected, ok := requireIfMatch(w, r, "a rollback")
	if !ok {
		return
	}
	var req rollbackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRollbackBody)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	note := stripControl(req.Note)
	if len([]rune(note)) > maxRollbackNote {
		writeError(w, http.StatusBadRequest, "note is longer than 512 characters")
		return
	}
	res, err := s.policyHistory.Rollback(r.Context(), v, note, WriteMeta{ExpectedHead: expected})
	if err != nil {
		writeHistoryError(w, err)
		return
	}
	w.Header().Set(PolicyVersionHeader, strconv.FormatInt(res.Head, 10))
	writeJSON(w, res)
}

// writeHistoryError answers a PolicyHistory error with a fixed message: 404
// for an unknown version, 422 with the loader error for a target that no
// longer validates, 403/409 as writeWriterError, else 500 (the store's error
// stays server-side; the control plane logs it).
func writeHistoryError(w http.ResponseWriter, err error) {
	var ie *InvalidPolicyError
	var ce *ConflictError
	var re *RoleRequiredError
	switch {
	case errors.Is(err, ErrPolicyVersionNotFound):
		writeError(w, http.StatusNotFound, "policy version not found")
	case errors.As(err, &ie):
		writeJSONStatus(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid_policy", "detail": ie.Error()})
	case errors.As(err, &ce), errors.As(err, &re):
		writeWriterError(w, err)
	default:
		writeError(w, http.StatusInternalServerError, "policy history error")
	}
}

// splitVersionPath splits a path below policyVersionsPath into its version
// segment and action ("", "diff" or "rollback"). ok is false for any other
// shape, including an empty segment or a trailing slash.
func splitVersionPath(p string) (seg, action string, ok bool) {
	rest, found := strings.CutPrefix(p, policyVersionsPath+"/")
	if !found {
		return "", "", false
	}
	seg, action, _ = strings.Cut(rest, "/")
	if seg == "" {
		return "", "", false
	}
	switch action {
	case "":
		return seg, "", !strings.HasSuffix(rest, "/")
	case "diff", "rollback":
		return seg, action, true
	default:
		return "", "", false
	}
}

// RoutePath maps a request path to the Routes() path it is served under: a
// concrete version path (/dashboard/api/policy/versions/3/diff) becomes its
// template (/dashboard/api/policy/versions/{v}/diff), whatever the segment
// holds; every other path is returned unchanged. The control plane keys its
// authz table and audit classification on the result.
func RoutePath(p string) string {
	if _, action, ok := splitVersionPath(p); ok {
		t := policyVersionsPath + "/{v}"
		if action != "" {
			t += "/" + action
		}
		return t
	}
	return p
}

// positiveParam parses an optional decimal value: "" is def, anything else
// must be a non-negative integer that fits an int64.
func positiveParam(s string, def int64) (int64, bool) {
	if s == "" {
		return def, true
	}
	if strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// stripControl removes control characters from s.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
