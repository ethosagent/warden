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
	"unicode/utf8"
)

// The change draft API (W-P2-APPR-04). A draft is a proposed policy change
// that a second person approves before it is published. The handlers reach the
// control plane's approvals service through ChangeDrafts (internal/controlplane
// imports this package, not the other way round); they only parse, bound and
// map. The routes answer only when SetChangeDrafts was called, which the
// control plane does when console.approvals.enabled; a worker answers 404.
//
//	GET  /dashboard/api/changes?target=&state=&cursor=&limit=   viewer
//	POST /dashboard/api/changes                                  editor, If-Match "v<base>"
//	GET  /dashboard/api/changes/{id}                             viewer
//	GET  /dashboard/api/changes/{id}/diff                        viewer
//	PUT  /dashboard/api/changes/{id}                             editor (author), If-Match "r<rev>"
//	POST /dashboard/api/changes/{id}/submit|withdraw|rebase      editor (author)
//	POST /dashboard/api/changes/{id}/approve|reject              editor, and the draft's required role
//	POST /dashboard/api/changes/{id}/replay                      editor
//	POST /dashboard/api/changes/{id}/emergency-apply             admin, break-glass session only (W-P2-APPR-07)
//	POST /dashboard/api/changes/{id}/review                      admin, never a break-glass session (W-P2-APPR-07)

// changesPath is the draft list; one draft and its actions live below it.
const changesPath = "/dashboard/api/changes"

// Change draft bounds.
const (
	// maxChangeBody caps every draft request body.
	maxChangeBody = 1 << 20
	// maxChangeComment caps an approval or rejection comment, in characters.
	maxChangeComment = 1024
	// maxChangeMessage caps a draft's change message, in characters: a policy
	// version message has the same cap.
	maxChangeMessage = maxPolicyMessage
	// maxChangeCursor caps the opaque list cursor, in bytes.
	maxChangeCursor = 256
	// maxChangeIDLen caps a draft id in a path.
	maxChangeIDLen = 64
)

// ChangeError is a refusal a ChangeDrafts method returns: the HTTP status, a
// stable code and extra body fields (never a doc, a credential or a store
// error text). The handlers answer it as {"error": Code, ...Fields}.
type ChangeError struct {
	Status int
	Code   string
	Fields map[string]any
	// Err is the cause, for logs and errors.Is; never sent to the client.
	Err error
}

func (e *ChangeError) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Err.Error()
	}
	return e.Code
}

func (e *ChangeError) Unwrap() error { return e.Err }

// ChangeActor names a person on a draft.
type ChangeActor struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
}

// ChangeReason is one reason a change counts as widening. Path and Detail are
// a destination or a settings path, never a value.
type ChangeReason struct {
	Code   string `json:"code"`
	Path   string `json:"path"`
	Detail string `json:"detail"`
}

// ChangeDraftView is one draft without its document.
type ChangeDraftView struct {
	ID     string `json:"id"`
	Target string `json:"target"`
	// TargetRef names the entity of a target other than the policy: a block
	// entry id, an agent id. Empty for the policy.
	TargetRef         string         `json:"target_ref,omitempty"`
	Revision          int            `json:"revision"`
	BaseVersion       int64          `json:"base_version"`
	State             string         `json:"state"`
	Author            ChangeActor    `json:"author"`
	Source            string         `json:"source"`
	Message           string         `json:"message"`
	DocSHA256         string         `json:"doc_sha256"`
	Widening          bool           `json:"widening"`
	Reasons           []ChangeReason `json:"reasons"`
	RequiredRole      string         `json:"required_role"`
	LastError         string         `json:"last_error,omitempty"`
	Approvals         int            `json:"approvals"`
	ApprovalsRequired int            `json:"approvals_required"`
	AppliedVersion    int64          `json:"applied_version,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	ExpiresAt         time.Time      `json:"expires_at"`
}

// ChangeApprovalView is one decision on a draft.
type ChangeApprovalView struct {
	Revision            int         `json:"revision"`
	DocSHA256           string      `json:"doc_sha256"`
	Decision            string      `json:"decision"`
	Approver            ChangeActor `json:"approver"`
	ApproverRole        string      `json:"approver_role"`
	AuthMethod          string      `json:"auth_method"`
	ReplayID            string      `json:"replay_id,omitempty"`
	AcknowledgeNoReplay bool        `json:"acknowledge_no_replay,omitempty"`
	Comment             string      `json:"comment,omitempty"`
	At                  time.Time   `json:"at"`
}

// ChangeReplayView is one replay of a draft revision. Result is the replay
// runner's value-free comparison.
type ChangeReplayView struct {
	ID            string          `json:"id"`
	Revision      int             `json:"revision"`
	BaseVersion   int64           `json:"base_version"`
	Status        string          `json:"status"`
	EventsScanned int             `json:"events_scanned"`
	Truncated     bool            `json:"truncated"`
	ErrorCode     string          `json:"error_code,omitempty"`
	WindowFrom    time.Time       `json:"window_from"`
	WindowTo      time.Time       `json:"window_to"`
	FinishedAt    *time.Time      `json:"finished_at,omitempty"`
	Result        json.RawMessage `json:"result,omitempty"`
}

// ChangeDraftDetail is one draft with its credential-redacted document, its
// decisions and its latest replay.
type ChangeDraftDetail struct {
	ChangeDraftView
	Doc          any                  `json:"doc"`
	ApprovalRows []ChangeApprovalView `json:"approval_rows"`
	LatestReplay *ChangeReplayView    `json:"latest_replay,omitempty"`
}

// ChangeDiff is the structural diff of a draft's current revision against its
// base version, with credential paths only as fingerprints.
//
// For a target other than the policy (W-P2-APPR-08) Diff is {current, proposed}:
// the entity as it is now (null when it does not exist yet) and as the draft
// would leave it, in the shape the detail's doc has.
type ChangeDiff struct {
	ID          string `json:"id"`
	Revision    int    `json:"revision"`
	BaseVersion int64  `json:"base_version"`
	Diff        any    `json:"diff"`
}

// ChangeResult is the outcome of a transition: the draft, and the policy
// version it published when it applied.
type ChangeResult struct {
	ChangeDraftView
	Version int64 `json:"version,omitempty"`
}

// ChangeFilter narrows the list. Empty fields match everything.
type ChangeFilter struct{ Target, State string }

// ChangeCreateInput is POST /dashboard/api/changes. BaseVersion comes from
// If-Match "v<N>"; Doc is the whole canonical doc ({allowlist, denylist,
// settings}).
type ChangeCreateInput struct {
	Target      string          `json:"target"`
	Message     string          `json:"message"`
	Doc         json.RawMessage `json:"doc"`
	BaseVersion int64           `json:"-"`
}

// ChangeUpdateInput is PUT /dashboard/api/changes/{id}.
type ChangeUpdateInput struct {
	Message string          `json:"message"`
	Doc     json.RawMessage `json:"doc"`
}

// ChangeApproveInput is POST .../approve: the revision, doc digest and replay
// the reviewer saw.
type ChangeApproveInput struct {
	Revision            int    `json:"revision"`
	DocSHA256           string `json:"doc_sha256"`
	ReplayID            string `json:"replay_id"`
	AcknowledgeNoReplay bool   `json:"acknowledgeNoReplay"`
	Comment             string `json:"comment"`
}

// ChangeEmergencyInput is POST .../emergency-apply: why the second person is
// being bypassed (10 to 512 characters), and optionally the revision and doc
// digest the operator saw (the draft's current ones when absent).
type ChangeEmergencyInput struct {
	Reason    string `json:"reason"`
	Revision  int    `json:"revision"`
	DocSHA256 string `json:"doc_sha256"`
}

// ChangeReviewInput is POST .../review: the post-hoc review of an emergency
// apply, optionally pinned to the revision and doc digest the reviewer saw.
type ChangeReviewInput struct {
	Comment   string `json:"comment"`
	Revision  int    `json:"revision"`
	DocSHA256 string `json:"doc_sha256"`
}

// maxEmergencyReason caps the reason in characters (approvals.MaxEmergencyReason;
// the dashboard does not import approvals). The 10 character floor is the
// service's, so a caller that may not emergency-apply is refused before it.
const maxEmergencyReason = 512

// ChangeRejectInput is POST .../reject.
type ChangeRejectInput struct {
	Revision  int    `json:"revision"`
	DocSHA256 string `json:"doc_sha256"`
	Comment   string `json:"comment"`
}

// ChangeDrafts is the change draft service as the routes see it. Every method
// takes the request context, which carries the caller's identity; the
// implementation enforces the author, role and two-person rules and returns a
// *ChangeError for any refusal. revision 0 means "the draft's current
// revision" for the transitions that take one.
type ChangeDrafts interface {
	List(ctx context.Context, f ChangeFilter, cursor string, limit int) ([]ChangeDraftView, string, error)
	Get(ctx context.Context, id string) (ChangeDraftDetail, error)
	Diff(ctx context.Context, id string) (ChangeDiff, error)
	Create(ctx context.Context, in ChangeCreateInput) (ChangeDraftDetail, error)
	Update(ctx context.Context, id string, revision int, in ChangeUpdateInput) (ChangeDraftDetail, error)
	Submit(ctx context.Context, id string, revision int) (ChangeResult, error)
	Withdraw(ctx context.Context, id string, revision int) (ChangeResult, error)
	Rebase(ctx context.Context, id string, revision int) (ChangeResult, error)
	Approve(ctx context.Context, id string, in ChangeApproveInput) (ChangeResult, error)
	Reject(ctx context.Context, id string, in ChangeRejectInput) (ChangeResult, error)
	Replay(ctx context.Context, id string) (ChangeReplayView, error)
	// EmergencyApply publishes a pending draft past the two-person rule for a
	// break-glass session (W-P2-APPR-07); Review closes it afterwards.
	EmergencyApply(ctx context.Context, id string, in ChangeEmergencyInput) (ChangeResult, error)
	Review(ctx context.Context, id string, in ChangeReviewInput) (ChangeResult, error)
}

// SetChangeDrafts enables the change draft routes. Set only on a control plane
// with console.approvals.enabled; without it the routes answer 404.
func (s *Server) SetChangeDrafts(c ChangeDrafts) { s.changeDrafts = c }

// SetApprovalsReplayTimeout tells the console how long the server lets a replay
// run (console.approvals.replayTimeout), so the Changes tab polls a pending
// replay no longer than that. Zero (the default) leaves it to the page.
func (s *Server) SetApprovalsReplayTimeout(d time.Duration) { s.approvalsReplayTimeout = d }

type changeListResponse struct {
	Drafts     []ChangeDraftView `json:"drafts"`
	NextCursor string            `json:"next_cursor"`
}

// changeActions are the verbs below a draft and the method each takes.
var changeActions = map[string]string{
	"diff": http.MethodGet, "submit": http.MethodPost, "withdraw": http.MethodPost, "rebase": http.MethodPost,
	"approve": http.MethodPost, "reject": http.MethodPost, "replay": http.MethodPost,
	"emergency-apply": http.MethodPost, "review": http.MethodPost,
}

// splitChangePath splits a path below changesPath into the draft id and the
// action ("" for the draft itself). ok is false for any other shape.
func splitChangePath(p string) (id, action string, ok bool) {
	rest, found := strings.CutPrefix(p, changesPath+"/")
	if !found {
		return "", "", false
	}
	id, action, _ = strings.Cut(rest, "/")
	if id == "" {
		return "", "", false
	}
	if action == "" {
		return id, "", !strings.HasSuffix(rest, "/")
	}
	if _, known := changeActions[action]; !known {
		return "", "", false
	}
	return id, action, true
}

func validChangeID(id string) bool {
	if id == "" || len(id) > maxChangeIDLen {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// ChangeDraftID is the draft id in a /dashboard/api/changes/{id}[/action] path.
func ChangeDraftID(p string) (string, bool) {
	id, _, ok := splitChangePath(p)
	return id, ok && validChangeID(id)
}

// handleChanges serves GET and POST /dashboard/api/changes.
func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.changeDrafts == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method == http.MethodPost {
		s.createChange(w, r)
		return
	}
	q := r.URL.Query()
	cursor := q.Get("cursor")
	if len(cursor) > maxChangeCursor {
		writeError(w, http.StatusBadRequest, "invalid cursor")
		return
	}
	limit, ok := positiveParam(q.Get("limit"), defaultHistoryLimit)
	if !ok || limit < 1 {
		writeError(w, http.StatusBadRequest, "invalid limit: want a positive integer")
		return
	}
	drafts, next, err := s.changeDrafts.List(r.Context(), ChangeFilter{Target: q.Get("target"), State: q.Get("state")}, cursor, int(min(limit, maxHistoryLimit)))
	if err != nil {
		writeChangeError(w, err)
		return
	}
	if drafts == nil {
		drafts = []ChangeDraftView{}
	}
	writeJSON(w, changeListResponse{Drafts: drafts, NextCursor: next})
}

func (s *Server) createChange(w http.ResponseWriter, r *http.Request) {
	base, ok := requireIfMatch(w, r, "creating a draft")
	if !ok {
		return
	}
	var in ChangeCreateInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok2 bool
	if in.Message, ok2 = cleanChangeText(w, in.Message, maxChangeMessage, "message"); !ok2 {
		return
	}
	in.BaseVersion = base
	d, err := s.changeDrafts.Create(r.Context(), in)
	if err != nil {
		writeChangeError(w, err)
		return
	}
	w.Header().Set("ETag", changeETag(d.Revision))
	writeJSONStatus(w, http.StatusCreated, d)
}

// handleChange serves everything below /dashboard/api/changes/{id}.
func (s *Server) handleChange(w http.ResponseWriter, r *http.Request) {
	id, action, ok := splitChangePath(r.URL.Path)
	if !ok {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch {
	case action == "" && (r.Method == http.MethodGet || r.Method == http.MethodPut):
	case action != "" && r.Method == changeActions[action]:
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.changeDrafts == nil || !validChangeID(id) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ctx := r.Context()
	switch {
	case action == "" && r.Method == http.MethodGet:
		d, err := s.changeDrafts.Get(ctx, id)
		if err != nil {
			writeChangeError(w, err)
			return
		}
		w.Header().Set("ETag", changeETag(d.Revision))
		writeJSON(w, d)
	case action == "diff":
		d, err := s.changeDrafts.Diff(ctx, id)
		if err != nil {
			writeChangeError(w, err)
			return
		}
		writeJSON(w, d)
	case action == "":
		s.updateChange(w, r, id)
	case action == "approve":
		s.approveChange(w, r, id)
	case action == "reject":
		s.rejectChange(w, r, id)
	case action == "emergency-apply":
		s.emergencyApplyChange(w, r, id)
	case action == "review":
		s.reviewChange(w, r, id)
	case action == "replay":
		rp, err := s.changeDrafts.Replay(ctx, id)
		if err != nil {
			writeChangeError(w, err)
			return
		}
		writeJSONStatus(w, http.StatusAccepted, rp)
	default:
		s.transitionChange(w, r, id, action)
	}
}

func (s *Server) updateChange(w http.ResponseWriter, r *http.Request, id string) {
	rev, ok := requireRevisionIfMatch(w, r, "an edit")
	if !ok {
		return
	}
	var in ChangeUpdateInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok2 bool
	if in.Message, ok2 = cleanChangeText(w, in.Message, maxChangeMessage, "message"); !ok2 {
		return
	}
	d, err := s.changeDrafts.Update(r.Context(), id, rev, in)
	if err != nil {
		writeChangeError(w, err)
		return
	}
	w.Header().Set("ETag", changeETag(d.Revision))
	writeJSON(w, d)
}

// transitionChange serves submit, withdraw and rebase. A body is not read; the
// revision comes from an optional If-Match "r<N>" (the current revision when
// absent).
func (s *Server) transitionChange(w http.ResponseWriter, r *http.Request, id, action string) {
	rev := 0
	if _, present := r.Header["If-Match"]; present {
		var ok bool
		if rev, ok = requireRevisionIfMatch(w, r, "a "+action); !ok {
			return
		}
	}
	var (
		res ChangeResult
		err error
	)
	switch action {
	case "submit":
		res, err = s.changeDrafts.Submit(withForce(r.Context(), r), id, rev)
	case "withdraw":
		res, err = s.changeDrafts.Withdraw(r.Context(), id, rev)
	default:
		res, err = s.changeDrafts.Rebase(r.Context(), id, rev)
	}
	s.writeChangeResult(w, res, err)
}

func (s *Server) approveChange(w http.ResponseWriter, r *http.Request, id string) {
	var in ChangeApproveInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok bool
	if in.Comment, ok = cleanChangeText(w, in.Comment, maxChangeComment, "comment"); !ok {
		return
	}
	if in.Revision < 1 || in.DocSHA256 == "" {
		writeError(w, http.StatusBadRequest, "revision and doc_sha256 are required")
		return
	}
	res, err := s.changeDrafts.Approve(withForce(r.Context(), r), id, in)
	s.writeChangeResult(w, res, err)
}

func (s *Server) rejectChange(w http.ResponseWriter, r *http.Request, id string) {
	var in ChangeRejectInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok bool
	if in.Comment, ok = cleanChangeText(w, in.Comment, maxChangeComment, "comment"); !ok {
		return
	}
	if in.Revision < 1 || in.DocSHA256 == "" {
		writeError(w, http.StatusBadRequest, "revision and doc_sha256 are required")
		return
	}
	res, err := s.changeDrafts.Reject(r.Context(), id, in)
	s.writeChangeResult(w, res, err)
}

// emergencyApplyChange serves POST .../emergency-apply. The reason is
// required here; whether the caller may use it at all is the service's call.
func (s *Server) emergencyApplyChange(w http.ResponseWriter, r *http.Request, id string) {
	var in ChangeEmergencyInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok bool
	if in.Reason, ok = cleanChangeText(w, in.Reason, maxEmergencyReason, "reason"); !ok {
		return
	}
	res, err := s.changeDrafts.EmergencyApply(withForce(r.Context(), r), id, in)
	s.writeChangeResult(w, res, err)
}

// reviewChange serves POST .../review.
func (s *Server) reviewChange(w http.ResponseWriter, r *http.Request, id string) {
	var in ChangeReviewInput
	if !decodeChangeBody(w, r, &in) {
		return
	}
	var ok bool
	if in.Comment, ok = cleanChangeText(w, in.Comment, maxChangeComment, "comment"); !ok {
		return
	}
	res, err := s.changeDrafts.Review(r.Context(), id, in)
	s.writeChangeResult(w, res, err)
}

// writeChangeResult answers a transition: the draft, with the published
// version in the version header when it applied.
func (s *Server) writeChangeResult(w http.ResponseWriter, res ChangeResult, err error) {
	if err != nil {
		writeChangeError(w, err)
		return
	}
	if res.Version > 0 {
		w.Header().Set(PolicyVersionHeader, strconv.FormatInt(res.Version, 10))
	}
	w.Header().Set("ETag", changeETag(res.Revision))
	writeJSON(w, res)
}

// decodeChangeBody reads one JSON object of at most maxChangeBody bytes into
// v, refusing unknown fields and trailing data. On a refusal it has answered
// and returns false.
func decodeChangeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxChangeBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, terr := dec.Token(); !errors.Is(terr, io.EOF) {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeJSONStatus(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
			return false
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// cleanChangeText strips control characters and enforces the length cap in
// characters. On a refusal it has answered and returns false.
func cleanChangeText(w http.ResponseWriter, s string, limit int, field string) (string, bool) {
	s = stripControl(s)
	if utf8.RuneCountInString(s) > limit {
		writeError(w, http.StatusBadRequest, field+" is longer than "+strconv.Itoa(limit)+" characters")
		return "", false
	}
	return s, true
}

// changeETag is the revision tag a draft GET and write return, "r<N>".
func changeETag(revision int) string { return `"r` + strconv.Itoa(revision) + `"` }

// requireRevisionIfMatch reads the If-Match "r<N>" a draft edit must carry:
// 428 when absent, 400 when malformed.
func requireRevisionIfMatch(w http.ResponseWriter, r *http.Request, what string) (int, bool) {
	raw, present := r.Header["If-Match"]
	if !present {
		writeJSONStatus(w, http.StatusPreconditionRequired, map[string]string{
			"error":  "precondition_required",
			"detail": what + ` needs If-Match: "r<N>", the revision from the last GET`,
		})
		return 0, false
	}
	n, ok := parseRevisionIfMatch(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, `invalid If-Match: want "r<N>", the revision from the last GET`)
		return 0, false
	}
	return n, true
}

// parseRevisionIfMatch parses exactly one If-Match value of the form "r<N>"
// (quoted, N >= 1).
func parseRevisionIfMatch(values []string) (int, bool) {
	if len(values) != 1 {
		return 0, false
	}
	v := values[0]
	if len(v) < 4 || v[0] != '"' || v[1] != 'r' || v[len(v)-1] != '"' {
		return 0, false
	}
	digits := v[2 : len(v)-1]
	if strings.TrimLeft(digits, "0123456789") != "" || len(digits) > 9 {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// writeChangeError answers a ChangeDrafts error. A *ChangeError carries its own
// status and body; anything else is a fixed 500 (the control plane logs it).
func writeChangeError(w http.ResponseWriter, err error) {
	var ce *ChangeError
	if !errors.As(err, &ce) {
		writeError(w, http.StatusInternalServerError, "change draft error")
		return
	}
	body := map[string]any{"error": ce.Code}
	for k, v := range ce.Fields {
		if k != "error" {
			body[k] = v
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ce.Status)
	_ = json.NewEncoder(w).Encode(body)
}
