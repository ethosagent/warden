package approvals

// review.go is the review half of the Service (W-P2-APPR-04): classification
// of every revision, the two-person rule on approve, and the self-apply of a
// narrowing draft at submit. The HTTP layer maps the errors below to status
// codes; nothing here knows about HTTP.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// Review errors. Callers match with errors.Is / errors.As.
var (
	// ErrSelfApproval: the approver is the draft's author.
	ErrSelfApproval = errors.New("approvals: an author cannot approve their own change")
	// ErrBreakglassApprover: a break-glass session can apply an emergency
	// change (APPR-07) but never approves one.
	ErrBreakglassApprover = errors.New("approvals: a break-glass session cannot approve")
	// ErrRevisionChanged: the approver saw another revision or doc than the
	// draft now holds.
	ErrRevisionChanged = errors.New("approvals: the draft changed since the reviewer saw it")
	// ErrReplayRequired: no usable replay evidence was cited.
	ErrReplayRequired = errors.New("approvals: replay evidence is required")
	// ErrNotPending: the draft is not waiting for a decision.
	ErrNotPending = errors.New("approvals: the draft is not pending")
)

// RoleRequiredError says the approver's role is below what the draft needs.
// Fields names the changed settings fields that need it, when that is why.
type RoleRequiredError struct {
	Need   config.Role
	Fields []string
}

func (e *RoleRequiredError) Error() string {
	if len(e.Fields) == 0 {
		return "role " + e.Need.String() + " required"
	}
	return "role " + e.Need.String() + " required to change " + strings.Join(e.Fields, ", ")
}

// classifyAgainstBase classifies raw (an encoded doc) against the doc of
// baseVersion. It returns nils when no BaseDoc is wired, so the revision stays
// unclassified (fail closed).
func (s *Service) classifyAgainstBase(ctx context.Context, baseVersion int64, raw json.RawMessage) (json.RawMessage, string, error) {
	if s.cfg.BaseDoc == nil {
		return nil, "", nil
	}
	var doc Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("approvals: decode doc: %w", err)
	}
	var base Doc
	if baseVersion > 0 {
		b, err := s.cfg.BaseDoc(ctx, baseVersion)
		if err != nil {
			return nil, "", fmt.Errorf("approvals: read base version %d: %w", baseVersion, err)
		}
		base = b
	}
	return encodeClassification(Classify(base, doc))
}

func encodeClassification(c Classification) (json.RawMessage, string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, "", fmt.Errorf("approvals: encode classification: %w", err)
	}
	return b, c.RequiredRole.String(), nil
}

// DecodeClassification parses a draft's stored classification.
func DecodeClassification(d Draft) (Classification, error) {
	var c Classification
	if err := json.Unmarshal(d.Classification, &c); err != nil {
		return Classification{}, fmt.Errorf("%w: draft %s revision %d", ErrUnclassified, d.ID, d.Revision)
	}
	return c, nil
}

// selfApplies reports whether d applies at submit with no second person: a
// narrowing change while allowSelfApproveNarrowing is on.
func (s *Service) selfApplies(d Draft) bool {
	if !s.cfg.AllowSelfApproveNarrowing || RequireClassified(d) != nil {
		return false
	}
	c, err := DecodeClassification(d)
	return err == nil && !c.Widening
}

// MinApprovals is how many distinct approvers a held change needs.
func (s *Service) MinApprovals() int {
	if s.cfg.MinApprovals < 1 {
		return 1
	}
	return s.cfg.MinApprovals
}

func (s *Service) replayMaxAge() time.Duration {
	if s.cfg.ReplayMaxAge > 0 {
		return s.cfg.ReplayMaxAge
	}
	return config.DefaultApprovalsReplayMaxAge
}

// applyClassified is Apply behind the fail-closed classification guard.
func (s *Service) applyClassified(ctx context.Context, d Draft, actorSub string) (Draft, error) {
	if err := RequireClassified(d); err != nil {
		return Draft{}, err
	}
	return s.Apply(ctx, d.ID, d.Revision, actorSub)
}

// SubmitResult is the outcome of SubmitOrApply.
type SubmitResult struct {
	Draft Draft
	// Applied is true when the draft was narrowing and applied at once.
	Applied bool
}

// SubmitOrApply submits a draft. A narrowing draft with allowSelfApproveNarrowing
// on is recorded as a self decision and applied in the same call
// (Submit -> RecordDecision(self) -> Apply); anything else stays pending with a
// replay queued. When the self-apply cannot publish, the error is Apply's and
// the draft is left pending (validation) or needs_rebase (moved head).
func (s *Service) SubmitOrApply(ctx context.Context, id string, revision int, author Author) (SubmitResult, error) {
	d, err := s.cfg.Store.Submit(ctx, id, revision, author.Sub)
	if err != nil {
		return SubmitResult{}, err
	}
	if !s.selfApplies(d) {
		s.queueReplay(ctx, d)
		return SubmitResult{Draft: d}, nil
	}
	d, _, err = s.cfg.Store.RecordDecision(ctx, d.ID, DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: DecisionSelf,
		Approver: author, ApproverRole: d.RequiredRole,
	})
	if err != nil {
		return SubmitResult{Draft: d}, err
	}
	nd, err := s.applyClassified(ctx, d, author.Sub)
	if err != nil {
		return SubmitResult{Draft: nd}, err
	}
	return SubmitResult{Draft: nd, Applied: true}, nil
}

// ApproveInput is one reviewer's approval. Revision and DocSHA256 are what
// the reviewer saw; Role is the console role they hold now.
type ApproveInput struct {
	ID        string
	Revision  int
	DocSHA256 string
	Approver  Author
	Role      config.Role
	ReplayID  string
	// AcknowledgeNoReplay approves with no replay evidence; it is accepted only
	// when the revision's latest replay failed, was unavailable or never ran.
	AcknowledgeNoReplay bool
	Comment             string
}

// ApproveResult is what an approval did.
type ApproveResult struct {
	Draft Draft
	// Approvals is the distinct approvers the revision now has, Required how
	// many it needs.
	Approvals, Required int
	// Applied is true when this approval was the last and the draft published.
	Applied bool
}

// Approve records a second person's approval of one revision and, when it is
// the last one the draft needs, applies the draft in the same call, so there is
// no gap between approval and publish.
//
// Checks, in order: the draft is pending; the approver is not the author and
// not a break-glass session; the approver holds the role the draft needs now
// (re-classified against the live head); the revision and doc are the ones the
// reviewer saw; the revision is classified; replay evidence. An approval that
// fails any of them records nothing.
//
// A head that moved since base_version is ErrRebaseRequired: the draft becomes
// needs_rebase and its approvals are void once it is rebased.
func (s *Service) Approve(ctx context.Context, in ApproveInput) (ApproveResult, error) {
	d, err := s.cfg.Store.Get(ctx, in.ID)
	if err != nil {
		return ApproveResult{}, err
	}
	if d.State != StatePending {
		return ApproveResult{}, fmt.Errorf("%w: a %s draft cannot be approved", ErrIllegalTransition, d.State)
	}
	switch {
	case in.Approver.Kind == "breakglass":
		return ApproveResult{}, ErrBreakglassApprover
	case in.Approver.Sub == "" || (in.Approver.Sub == d.Author.Sub && in.Approver.Iss == d.Author.Iss):
		return ApproveResult{}, ErrSelfApproval
	}
	if d.Revision != in.Revision || d.DocSHA256 != in.DocSHA256 {
		return ApproveResult{}, fmt.Errorf("%w: the draft is at revision %d", ErrRevisionChanged, d.Revision)
	}
	if err := RequireClassified(d); err != nil {
		return ApproveResult{}, err
	}
	if err := s.checkRole(ctx, d, in.Role); err != nil {
		return ApproveResult{}, err
	}
	if err := s.checkEvidence(ctx, d, in); err != nil {
		return ApproveResult{}, err
	}

	need := s.MinApprovals()
	_, count, err := s.cfg.Store.RecordDecision(ctx, d.ID, DecisionInput{
		Revision: d.Revision, DocSHA256: d.DocSHA256, Decision: DecisionApprove,
		Approver: in.Approver, ApproverRole: in.Role.String(),
		ReplayID: in.ReplayID, AcknowledgeNoReplay: in.AcknowledgeNoReplay, Comment: in.Comment,
	})
	switch {
	case errors.Is(err, ErrDuplicateDecision):
		// A retry after an apply that did not publish: the approval is already
		// on file, so go on if the revision has all it needs.
		n, cerr := s.countApprovals(ctx, d)
		if cerr != nil || n < need {
			return ApproveResult{}, err
		}
		count = n
	case errors.Is(err, ErrStateChanged):
		return ApproveResult{}, fmt.Errorf("%w: %w", ErrRevisionChanged, err)
	case err != nil:
		return ApproveResult{}, err
	}
	res := ApproveResult{Draft: d, Approvals: count, Required: need}
	if count < need {
		return res, nil
	}
	if err := s.reclassifyForApply(ctx, d); err != nil {
		return res, err
	}
	nd, err := s.applyClassified(ctx, d, in.Approver.Sub)
	if err != nil {
		res.Draft = nd
		return res, err
	}
	res.Draft, res.Applied = nd, true
	return res, nil
}

// ApprovalCount is the distinct approvers d's current revision has.
func (s *Service) ApprovalCount(ctx context.Context, d Draft) (int, error) {
	return s.countApprovals(ctx, d)
}

// countApprovals is the distinct approvers of d's current revision and doc.
func (s *Service) countApprovals(ctx context.Context, d Draft) (int, error) {
	rows, err := s.cfg.Store.Approvals(ctx, d.ID)
	if err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	for _, a := range rows {
		if a.Revision == d.Revision && a.DocSHA256 == d.DocSHA256 && a.Decision == DecisionApprove {
			seen[a.ApproverIss+"\x00"+a.ApproverSub] = true
		}
	}
	return len(seen), nil
}

// checkRole requires role to meet the draft's stored required role and, when
// the head still is the base, the role Classify gives against the live head.
func (s *Service) checkRole(ctx context.Context, d Draft, role config.Role) error {
	need, err := requiredRole(d)
	if err != nil {
		return err
	}
	if fresh, ok := s.freshClassification(ctx, d); ok && fresh.RequiredRole > need {
		need = fresh.RequiredRole
	}
	if role < need {
		c, _ := DecodeClassification(d)
		return &RoleRequiredError{Need: need, Fields: adminFields(c)}
	}
	return nil
}

func requiredRole(d Draft) (config.Role, error) {
	var r config.Role
	if err := r.UnmarshalText([]byte(d.RequiredRole)); err != nil {
		return 0, fmt.Errorf("%w: draft %s has required role %q", ErrUnclassified, d.ID, d.RequiredRole)
	}
	return r, nil
}

// adminFields lists the changed top-level settings fields that need an admin,
// so a refusal can name them. Empty when the role comes from something finer
// than a field (an agents[].identity edit).
func adminFields(c Classification) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range c.Reasons {
		if r.Code != CodeSettingsChanged {
			continue
		}
		top, _, _ := strings.Cut(r.Path, ".")
		if top == "settings" || top == "" || seen[top] || config.SettingsFieldMinRole(top) != config.RoleAdmin {
			continue
		}
		seen[top] = true
		out = append(out, top)
	}
	return out
}

// freshClassification re-runs Classify of d's doc against the live head. It
// reports ok=false when the head is unavailable or is not d's base (then the
// apply will report the moved head).
func (s *Service) freshClassification(ctx context.Context, d Draft) (Classification, bool) {
	if s.cfg.Head == nil {
		return Classification{}, false
	}
	head, hd, err := s.cfg.Head(ctx)
	if err != nil || head != d.BaseVersion {
		return Classification{}, false
	}
	doc, err := d.PolicyDoc()
	if err != nil {
		return Classification{}, false
	}
	return Classify(hd, doc), true
}

// reclassifyForApply is the re-run of Classify against the live head when the
// last approval arrives: a draft whose fresh verdict needs a role above what
// every approver held when they approved is refused instead of published.
func (s *Service) reclassifyForApply(ctx context.Context, d Draft) error {
	fresh, ok := s.freshClassification(ctx, d)
	if !ok {
		return nil
	}
	rows, err := s.cfg.Store.Approvals(ctx, d.ID)
	if err != nil {
		return err
	}
	for _, a := range rows {
		if a.Revision != d.Revision || a.Decision != DecisionApprove {
			continue
		}
		var r config.Role
		if r.UnmarshalText([]byte(a.ApproverRole)) == nil && r >= fresh.RequiredRole {
			return nil
		}
	}
	c, _ := DecodeClassification(d)
	return &RoleRequiredError{Need: fresh.RequiredRole, Fields: adminFields(c)}
}

// checkEvidence enforces the replay rule: a done replay of this revision, no
// older than replayMaxAge, or an explicit acknowledgement when the latest
// replay failed, was unavailable or never ran.
func (s *Service) checkEvidence(ctx context.Context, d Draft, in ApproveInput) error {
	if in.ReplayID != "" {
		rp, err := s.GetReplay(ctx, in.ReplayID)
		switch {
		case errors.Is(err, ErrReplayNotFound):
			return fmt.Errorf("%w: unknown replay", ErrReplayRequired)
		case err != nil:
			return err
		case rp.DraftID != d.ID || rp.Revision != d.Revision:
			return fmt.Errorf("%w: the replay is of another revision", ErrReplayRequired)
		case !rp.Fresh(s.cfg.Now(), s.replayMaxAge()):
			return fmt.Errorf("%w: the replay is not done or is older than %s", ErrReplayRequired, s.replayMaxAge())
		}
		return nil
	}
	if !in.AcknowledgeNoReplay {
		return fmt.Errorf("%w: cite a done replay or acknowledge there is none", ErrReplayRequired)
	}
	latest, ok, err := s.LatestReplay(ctx, d.ID, d.Revision)
	if err != nil {
		return err
	}
	if ok && latest.Status != ReplayFailed && latest.Status != ReplayUnavailable {
		return fmt.Errorf("%w: the latest replay is %s; cite it or wait for it", ErrReplayRequired, latest.Status)
	}
	return nil
}

// RejectInput is one reviewer's rejection.
type RejectInput struct {
	ID        string
	Revision  int
	DocSHA256 string
	Approver  Author
	Role      config.Role
	Comment   string
}

// Reject records a rejection of one revision and moves the draft to rejected.
// The caller has checked the reviewer's role (editor).
func (s *Service) Reject(ctx context.Context, in RejectInput) (Draft, error) {
	d, _, err := s.cfg.Store.RecordDecision(ctx, in.ID, DecisionInput{
		Revision: in.Revision, DocSHA256: in.DocSHA256, Decision: DecisionReject,
		Approver: in.Approver, ApproverRole: in.Role.String(), Comment: in.Comment,
	})
	if errors.Is(err, ErrStateChanged) {
		return Draft{}, fmt.Errorf("%w: %w", ErrRevisionChanged, err)
	}
	return d, err
}
