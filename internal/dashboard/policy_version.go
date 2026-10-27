package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The policy version contract (W-P1-PVER-08). In --policy-store=versioned the
// policy, settings and llmProviders panels edit one versioned document with
// one head. Their GETs report the head (a version field and the
// X-Warden-Policy-Version header); their writes name the head they were based
// on with If-Match: "v<N>", which reaches the writer as WriteMeta.ExpectedHead.
// A writer that finds the head moved returns a *ConflictError, answered 409
// policy_conflict. In file mode (no version) none of this applies and the
// handlers behave as before.

// PolicyVersionHeader carries the head policy version on the policy, settings
// and llmProviders GETs in versioned mode.
const PolicyVersionHeader = "X-Warden-Policy-Version"

// PolicyMessageHeader carries a versioned save's optional message,
// percent-encoded UTF-8 (a header value cannot hold arbitrary text), at most
// maxPolicyMessage characters once decoded. File mode ignores it.
const PolicyMessageHeader = "X-Warden-Policy-Message"

// maxPolicyMessage caps a save message, in characters: the store's cap.
const maxPolicyMessage = 512

// ConflictAuthor is the author of the head version a stale write conflicted
// with.
type ConflictAuthor struct {
	Sub   string `json:"sub"`
	Email string `json:"email,omitempty"`
}

// ConflictError is returned by a versioned writer when the head is no longer
// the WriteMeta.ExpectedHead the edit was based on. Head and Author describe
// the current head; Err is the underlying store error (never sent to the
// client). The dashboard answers it with 409
// {"error":"policy_conflict","head":N,"author":{...}}.
type ConflictError struct {
	Head   int64
	Author ConflictAuthor
	Err    error
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("policy conflict: head is v%d", e.Head)
}

func (e *ConflictError) Unwrap() error { return e.Err }

// conflictResponse is the 409 body for a ConflictError. It names the head and
// its author only, never doc content.
type conflictResponse struct {
	Error  string         `json:"error"`
	Head   int64          `json:"head"`
	Author ConflictAuthor `json:"author"`
}

// SetPolicyVersion supplies the head policy version shared by the policy,
// settings and llmProviders documents. fn returns 0 in file mode (no
// versions), which turns the version contract off; nil is the same. Set only
// on the control plane.
func (s *Server) SetPolicyVersion(fn func(context.Context) (int64, error)) {
	s.policyVersion = fn
}

// headVersion is the head policy version, 0 in file mode.
func (s *Server) headVersion(ctx context.Context) (int64, error) {
	if s.policyVersion == nil {
		return 0, nil
	}
	return s.policyVersion(ctx)
}

// versionForGet returns the head version for a GET response and sets the
// version header when there is one. On error it has answered 500 and returns
// false.
func (s *Server) versionForGet(w http.ResponseWriter, r *http.Request) (int64, bool) {
	v, err := s.headVersion(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the policy version")
		return 0, false
	}
	if v > 0 {
		w.Header().Set(PolicyVersionHeader, strconv.FormatInt(v, 10))
	}
	return v, true
}

// writeMeta builds a write's WriteMeta. In versioned mode it requires
// If-Match (428 when absent, 400 when malformed: every save names the head it
// was based on) and reads the optional PolicyMessageHeader (400 when it is not
// valid percent-encoded UTF-8 or is longer than maxPolicyMessage characters).
// In file mode both headers are ignored. On a refusal it has written the
// response and returns false.
func (s *Server) writeMeta(w http.ResponseWriter, r *http.Request) (WriteMeta, bool) {
	v, err := s.headVersion(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cannot read the policy version")
		return WriteMeta{}, false
	}
	if v == 0 {
		return WriteMeta{}, true
	}
	n, ok := requireIfMatch(w, r, "a save")
	if !ok {
		return WriteMeta{}, false
	}
	msg, ok := policyMessage(r.Header.Get(PolicyMessageHeader))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid "+PolicyMessageHeader+": want percent-encoded UTF-8, at most 512 characters")
		return WriteMeta{}, false
	}
	return WriteMeta{ExpectedHead: n, Message: msg}, true
}

// requireIfMatch reads the If-Match a versioned write must carry: 428
// precondition_required when it is absent, 400 when it is malformed. what
// names the write in the 428 detail. On a refusal it has written the response
// and returns false.
func requireIfMatch(w http.ResponseWriter, r *http.Request, what string) (int64, bool) {
	raw, present := r.Header["If-Match"]
	if !present {
		writeJSONStatus(w, http.StatusPreconditionRequired, map[string]string{
			"error":  "precondition_required",
			"detail": what + ` needs If-Match: "v<N>", the head version from the last GET`,
		})
		return 0, false
	}
	n, ok := parseIfMatch(raw)
	if !ok {
		writeError(w, http.StatusBadRequest, `invalid If-Match: want "v<N>", the version from the last GET`)
		return 0, false
	}
	return n, true
}

// policyMessage decodes a PolicyMessageHeader value: percent-encoded UTF-8
// (encodeURIComponent), control characters stripped, at most maxPolicyMessage
// characters. "" is no message.
func policyMessage(raw string) (string, bool) {
	msg, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(msg) {
		return "", false
	}
	msg = stripControl(msg)
	if utf8.RuneCountInString(msg) > maxPolicyMessage {
		return "", false
	}
	return msg, true
}

// parseIfMatch parses exactly one If-Match value of the form "v<N>" (quoted,
// N >= 1). Weak tags, "*" and lists are refused.
func parseIfMatch(values []string) (int64, bool) {
	if len(values) != 1 {
		return 0, false
	}
	v := values[0]
	if len(v) < 4 || v[0] != '"' || v[1] != 'v' || v[len(v)-1] != '"' {
		return 0, false
	}
	digits := v[2 : len(v)-1]
	if strings.TrimLeft(digits, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// writeWriterError answers a versioned writer's error: 403 for a
// *RoleRequiredError, 409 for a *ConflictError, else 400 with the error text
// (the writers' validation errors).
func writeWriterError(w http.ResponseWriter, err error) {
	var re *RoleRequiredError
	if errors.As(err, &re) {
		writeJSONStatus(w, http.StatusForbidden, roleRequiredResponse{Error: "role_required", Need: re.Need, Fields: re.Fields})
		return
	}
	var ce *ConflictError
	if errors.As(err, &ce) {
		writeJSONStatus(w, http.StatusConflict, conflictResponse{Error: "policy_conflict", Head: ce.Head, Author: ce.Author})
		return
	}
	writeError(w, http.StatusBadRequest, err.Error())
}
