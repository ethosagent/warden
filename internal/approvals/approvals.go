// Package approvals is the change-approval domain (W-P2-APPR-01): the draft
// of a policy change, the state machine that governs it, the Store port and the
// Service that creates drafts and applies approved ones.
//
// A draft holds the same credential-redacted canonical doc as a policy
// version (Doc) and is applied only through a per-target Applier, which the
// control plane implements over its versioned publish path with
// expectedHead=base_version. Approvals therefore never skip validation,
// credential redaction or the policy audit row.
//
// The package does no I/O: the SQLite Store lives in adapters/sqlstore and the
// Appliers in internal/controlplane, so this package imports neither.
package approvals

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// Target is what a draft changes.
type Target string

const (
	// TargetPolicy is the canonical policy doc {allowlist, denylist, settings}.
	TargetPolicy Target = "policy"
	// TargetBlockedUsers is a block-list removal (W-P2-APPR-08).
	TargetBlockedUsers Target = "blocked_users"
	// TargetAgents is an agent-registry change.
	TargetAgents Target = "agents"
)

// Valid reports whether t is a known target.
func (t Target) Valid() bool {
	switch t {
	case TargetPolicy, TargetBlockedUsers, TargetAgents:
		return true
	}
	return false
}

// Source is what produced a draft. It exists now so the git and admin-MCP
// features need no migration.
type Source string

const (
	SourceConsole  Source = "console"
	SourceRollback Source = "rollback"
	SourceCLI      Source = "cli"
	SourceAPI      Source = "api"
	SourceGit      Source = "git"
	SourceAdminMCP Source = "admin-mcp"
)

// Valid reports whether s is a known source.
func (s Source) Valid() bool {
	switch s {
	case SourceConsole, SourceRollback, SourceCLI, SourceAPI, SourceGit, SourceAdminMCP:
		return true
	}
	return false
}

// Decision is what one change_approvals row records.
type Decision string

const (
	// DecisionApprove is a second person's approval of one revision.
	DecisionApprove Decision = "approve"
	// DecisionReject ends a pending draft.
	DecisionReject Decision = "reject"
	// DecisionSelf records a narrowing change applied at submit (APPR-04).
	DecisionSelf Decision = "self"
	// DecisionEmergency records an audited break-glass apply (APPR-07).
	DecisionEmergency Decision = "emergency"
	// DecisionPostReview records the after-the-fact review of an emergency
	// apply (APPR-07).
	DecisionPostReview Decision = "post_review"
)

// Valid reports whether d is a known decision.
func (d Decision) Valid() bool {
	switch d {
	case DecisionApprove, DecisionReject, DecisionSelf, DecisionEmergency, DecisionPostReview:
		return true
	}
	return false
}

// Doc is the canonical policy doc a policy-target draft carries. Its JSON
// shape (field names and order, omitempty) is exactly that of the control
// plane's policy_versions doc without the block list, so the doc_sha256 of a
// draft equals the one policy_versions computes for the same doc. YAML is never
// stored. A stored Doc is always credential-redacted.
type Doc struct {
	Allowlist []config.AllowlistEntry `json:"allowlist"`
	Denylist  []config.DenylistEntry  `json:"denylist"`
	Settings  *config.SettingsWire    `json:"settings,omitempty"`
}

// Author is who created a draft. Kind is the admin-audit auth_method (oidc,
// breakglass, cli, bearer, none, system); the Applier passes it through to the
// policy version it creates.
type Author struct {
	Iss   string
	Sub   string
	Email string
	Kind  string
}

// Provenance records where a draft came from. Source and Message are stored in
// their own columns; the rest is provenance_json.
type Provenance struct {
	// Source is what produced the draft (default console).
	Source Source `json:"-"`
	// Message is the author's change message (a policy version message).
	Message string `json:"-"`
	// Ref names an outside origin: a git commit, an admin-MCP session, a CLI
	// file name. Never a credential.
	Ref string `json:"ref,omitempty"`
	// RollbackTo is the version a rollback draft restores.
	RollbackTo int64 `json:"rollbackTo,omitempty"`
}

// Draft is one change draft at its current revision.
type Draft struct {
	ID          string
	Target      Target
	TargetRef   string
	Revision    int
	BaseVersion int64
	State       State
	Author      Author
	Source      Source
	Provenance  Provenance
	Message     string
	// DocJSON is the stored redacted canonical doc; DocSHA256 its digest.
	DocJSON   json.RawMessage
	DocSHA256 string
	// Classification is the widening classification of this revision
	// (W-P2-APPR-02), opaque to this package. Empty until classified.
	Classification json.RawMessage
	// RequiredRole is the lowest console role that may approve ("" = editor).
	RequiredRole   string
	LastError      string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ExpiresAt      time.Time
	AppliedVersion int64
}

// PolicyDoc decodes DocJSON into a Doc.
func (d Draft) PolicyDoc() (Doc, error) {
	var doc Doc
	if err := json.Unmarshal(d.DocJSON, &doc); err != nil {
		return Doc{}, err
	}
	return doc, nil
}

// Approval is one append-only change_approvals row.
type Approval struct {
	ID                  int64
	DraftID             string
	Revision            int
	DocSHA256           string
	ApproverIss         string
	ApproverSub         string
	ApproverEmail       string
	ApproverRole        string
	AuthMethod          string
	Decision            Decision
	ReplayID            string
	AcknowledgeNoReplay bool
	Comment             string
	At                  time.Time
}

// Errors returned by the Store and Service. Callers match with errors.Is.
var (
	// ErrNotFound: no draft has the id.
	ErrNotFound = errors.New("approvals: draft not found")
	// ErrStateChanged: the draft was no longer in the state and revision the
	// caller read (a compare-and-swap lost). Nothing was written.
	ErrStateChanged = errors.New("approvals: draft changed since it was read")
	// ErrIllegalTransition: the state machine has no such transition from the
	// draft's state. Nothing was written.
	ErrIllegalTransition = errors.New("approvals: illegal state transition")
	// ErrTooManyDrafts: creating would exceed console.approvals.maxOpenDrafts.
	ErrTooManyDrafts = errors.New("approvals: too many open drafts")
	// ErrRebaseRequired: the target moved since base_version, so the draft
	// cannot apply as written. An Applier returns it; Service.Apply moves the
	// draft to needs_rebase.
	ErrRebaseRequired = errors.New("approvals: base version is stale; rebase the draft")
	// ErrDuplicateDecision: the same approver already decided this revision.
	ErrDuplicateDecision = errors.New("approvals: approver already decided this revision")
	// ErrUnsupportedTarget: no Applier or doc codec for the target yet.
	ErrUnsupportedTarget = errors.New("approvals: unsupported target")
)
