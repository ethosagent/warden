package dashboard

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"
)

// The admin audit log read API (W-P1-AAUD-03): list the signed admin audit
// chain, verify it, and publish the public key of every signing key it
// declares. It is control-plane-only: the control plane sets an
// AdminAuditSource when console.adminAudit is enabled, and without one (a
// worker, or a control plane with admin audit off) all three routes are 404.
// The routes are distinct from the receipts Audit tab's /dashboard/api/audit*.
// Roles are enforced by the control plane's authz table, not here.

// AdminAuditSource is the dashboard's read-only view of the admin audit chain.
// The control plane adapts its adminaudit store to it; the dashboard never
// imports the store and never writes to the chain.
type AdminAuditSource interface {
	// List returns entries newest first, at most q.Limit, with seq below
	// q.Cursor when it is positive.
	List(ctx context.Context, q AdminAuditQuery) ([]AdminAuditEntry, error)
	// Verify checks the chain from req.FromSeq, at most req.MaxRows rows.
	Verify(ctx context.Context, req AdminAuditVerifyRequest) (AdminAuditVerifyResult, error)
	// PubKeys lists every signing key the chain declares, oldest first.
	PubKeys(ctx context.Context) ([]AdminAuditKey, error)
}

// AdminAuditQuery is a validated list request. Empty fields match everything.
type AdminAuditQuery struct {
	Actor   string // an actor_id or a sub
	Action  string
	Outcome string
	Since   time.Time
	Cursor  int64
	Limit   int
}

// AdminAuditEntry is one listed entry: the signed fields (hashes hex-encoded)
// plus the actor's plaintext sub and email from the side table. It never
// carries the signature or any request body.
type AdminAuditEntry struct {
	Seq        int64             `json:"seq"`
	TSUnixNano int64             `json:"tsUnixNano"`
	Time       string            `json:"time"` // RFC3339 (UTC) of TSUnixNano, for display
	ActorID    string            `json:"actorId"`
	ActorSub   string            `json:"actorSub"`
	ActorEmail string            `json:"actorEmail"`
	ActorRole  string            `json:"actorRole"`
	AuthMethod string            `json:"authMethod"`
	Action     string            `json:"action"`
	Target     string            `json:"target"`
	TargetRef  string            `json:"targetRef"`
	Details    map[string]string `json:"details"`
	Outcome    string            `json:"outcome"`
	HTTPStatus int               `json:"httpStatus"`
	BeforeHash string            `json:"beforeHash"`
	AfterHash  string            `json:"afterHash"`
	ClientIP   string            `json:"clientIp"`
	RequestID  string            `json:"requestId"`
	KeyID      string            `json:"keyId"`
	PrevHash   string            `json:"prevHash"`
	EntryHash  string            `json:"entryHash"`
}

// AdminAuditAnchor is a previously observed head (seq and entry hash), for
// example from an emitted warden.admin.v1 log line. Verify fails when the
// chain no longer reaches it or its hash changed.
type AdminAuditAnchor struct {
	Seq  int64
	Hash []byte
}

// AdminAuditVerifyRequest bounds one verification run.
type AdminAuditVerifyRequest struct {
	FromSeq int64
	Anchor  *AdminAuditAnchor
	MaxRows int
}

// AdminAuditVerifyResult is the outcome of a verification run. When Partial is
// set the row cap stopped it; the caller resumes with FromSeq =
// LastVerifiedSeq + 1. Reason is a fixed code naming the failed check.
type AdminAuditVerifyResult struct {
	OK              bool   `json:"ok"`
	Checked         int    `json:"checked"`
	FirstBadSeq     int64  `json:"firstBadSeq"`
	Reason          string `json:"reason,omitempty"`
	HeadSeq         int64  `json:"headSeq"`
	HeadHash        string `json:"headHash"` // hex
	LastVerifiedSeq int64  `json:"lastVerifiedSeq"`
	Partial         bool   `json:"partial"`
}

// AdminAuditKey is one signing key the chain declares.
type AdminAuditKey struct {
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"` // std base64 of the 32-byte Ed25519 key
	FirstSeq  int64  `json:"firstSeq"`
}

// adminAuditListResponse is the GET /dashboard/api/admin-audit body.
// NextCursor is the cursor of the next page, 0 when there is none.
type adminAuditListResponse struct {
	Entries    []AdminAuditEntry `json:"entries"`
	NextCursor int64             `json:"nextCursor"`
}

// adminAuditPubKeyResponse is the GET /dashboard/api/admin-audit/pubkey body.
type adminAuditPubKeyResponse struct {
	Alg  string          `json:"alg"`
	Keys []AdminAuditKey `json:"keys"`
}

const (
	adminAuditDefaultLimit = 50
	adminAuditMaxLimit     = 200
	// adminAuditVerifyMaxRows caps the rows one verify call checks, so a
	// request returns in bounded time; the client resumes a partial run.
	adminAuditVerifyMaxRows = 10000
	// adminAuditVerifyMaxBody bounds the optional {fromSeq, anchor} body.
	adminAuditVerifyMaxBody = 4096
	// Filter bounds: an actor is a sub, an email or a 64-hex actor_id.
	adminAuditMaxActor  = 320
	adminAuditMaxAction = 128
)

// adminAuditOutcomes are the outcomes an entry can carry (adminaudit.Outcome*).
var adminAuditOutcomes = map[string]bool{"ok": true, "denied": true, "rejected": true, "error": true}

// SetAdminAudit wires the admin audit read API. Only the control plane calls
// it, and only when admin audit is enabled; without it the routes are 404.
// Set it before serving.
func (s *Server) SetAdminAudit(src AdminAuditSource) {
	s.adminAudit = src
}

// handleAdminAudit serves GET /dashboard/api/admin-audit: one page of entries,
// newest first, filtered by actor, action, outcome and since.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.adminAudit == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	q, msg := parseAdminAuditQuery(r)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	entries, err := s.adminAudit.List(r.Context(), q)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "admin audit log unavailable")
		return
	}
	if len(entries) > q.Limit {
		entries = entries[:q.Limit]
	}
	resp := adminAuditListResponse{Entries: entries}
	if resp.Entries == nil {
		resp.Entries = []AdminAuditEntry{}
	}
	if len(entries) == q.Limit {
		resp.NextCursor = entries[len(entries)-1].Seq
	}
	writeJSON(w, resp)
}

// parseAdminAuditQuery validates the list parameters. It returns a message
// describing the caller's own bad input, or "".
func parseAdminAuditQuery(r *http.Request) (AdminAuditQuery, string) {
	v := r.URL.Query()
	q := AdminAuditQuery{
		Actor:   v.Get("actor"),
		Action:  v.Get("action"),
		Outcome: v.Get("outcome"),
		Limit:   adminAuditDefaultLimit,
	}
	if utf8.RuneCountInString(q.Actor) > adminAuditMaxActor || !utf8.ValidString(q.Actor) {
		return q, "actor is too long or not UTF-8"
	}
	if len(q.Action) > adminAuditMaxAction || !utf8.ValidString(q.Action) {
		return q, "action is too long or not UTF-8"
	}
	if q.Outcome != "" && !adminAuditOutcomes[q.Outcome] {
		return q, "outcome must be one of ok, denied, rejected, error"
	}
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > adminAuditMaxLimit {
			return q, "limit must be an integer from 1 to 200"
		}
		q.Limit = n
	}
	if raw := v.Get("cursor"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 1 {
			return q, "cursor must be a positive integer"
		}
		q.Cursor = n
	}
	if raw := v.Get("since"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return q, "since must be an RFC3339 time"
		}
		q.Since = t
	}
	return q, ""
}

// adminAuditVerifyBody is the optional POST /dashboard/api/admin-audit/verify
// body. Anchor.Hash is the hex entry hash at Anchor.Seq.
type adminAuditVerifyBody struct {
	FromSeq int64 `json:"fromSeq"`
	Anchor  *struct {
		Seq  int64  `json:"seq"`
		Hash string `json:"hash"`
	} `json:"anchor"`
}

// handleAdminAuditVerify serves POST /dashboard/api/admin-audit/verify: verify
// the chain (from fromSeq, at most adminAuditVerifyMaxRows rows), optionally
// against an anchor. It only reads; one run at a time, a concurrent call is
// refused with 429.
func (s *Server) handleAdminAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.adminAudit == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	req, msg := parseAdminAuditVerify(w, r)
	if msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}
	if !s.adminAuditVerifying.CompareAndSwap(false, true) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "a verification is already running")
		return
	}
	defer s.adminAuditVerifying.Store(false)
	res, err := s.adminAudit.Verify(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "admin audit verification failed to run")
		return
	}
	writeJSON(w, res)
}

// parseAdminAuditVerify reads and validates the optional verify body.
func parseAdminAuditVerify(w http.ResponseWriter, r *http.Request) (AdminAuditVerifyRequest, string) {
	req := AdminAuditVerifyRequest{MaxRows: adminAuditVerifyMaxRows}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, adminAuditVerifyMaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return req, "request body too large"
		}
		return req, "unreadable request body"
	}
	if len(raw) == 0 {
		return req, ""
	}
	var body adminAuditVerifyBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return req, "body must be JSON {fromSeq, anchor:{seq, hash}}"
	}
	if body.FromSeq < 0 {
		return req, "fromSeq must not be negative"
	}
	req.FromSeq = body.FromSeq
	if body.Anchor != nil {
		h, err := hex.DecodeString(body.Anchor.Hash)
		if body.Anchor.Seq < 1 || err != nil || len(h) != 32 {
			return req, "anchor needs a positive seq and a 64-character hex hash"
		}
		req.Anchor = &AdminAuditAnchor{Seq: body.Anchor.Seq, Hash: h}
	}
	return req, ""
}

// handleAdminAuditPubKey serves GET /dashboard/api/admin-audit/pubkey: the
// public key of every key_id in the chain, so an entry signed under an earlier
// key stays verifiable.
func (s *Server) handleAdminAuditPubKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.adminAudit == nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	keys, err := s.adminAudit.PubKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "admin audit keys unavailable")
		return
	}
	if keys == nil {
		keys = []AdminAuditKey{}
	}
	writeJSON(w, adminAuditPubKeyResponse{Alg: "ed25519", Keys: keys})
}
