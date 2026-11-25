package controlplane

// approvals_agents.go holds agent registry edits that widen access for approval
// (W-P2-APPR-08). With console.approvals.enabled, registering an agent, adding
// an allowed group or scope, adding or replacing a key and re-enabling an agent
// create a pending `agents` draft (202); disabling, removals and display name
// edits apply directly, as do all of them with approvals off. The draft's
// target_ref is the agent id and its base_version the agent revision the client
// sent as If-Match (0 for a registration), so a draft whose agent moved since is
// refused at apply (ErrRebaseRequired).
//
// A draft holds the canonical public key documents the registry validated (kty,
// crv, x, y, kid, alg, use: nothing private can pass agentreg.Validate), because
// applying needs them. Everything a person or a log sees (the draft detail, the
// diff, the audit rows, the reasons) carries only the kid, alg and thumbprint.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/dashboard"
)

// agentDraftKey is one key of an agent draft. JWK is the canonical public
// document, needed to apply and never shown (View drops it).
type agentDraftKey struct {
	KID string          `json:"kid"`
	JKT string          `json:"jkt"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk,omitempty"`
}

// agentDraftDoc is the doc of an `agents` draft: the agent as it would be after
// the change, minus the owner and audit fields (the store keeps those).
type agentDraftDoc struct {
	ID            string          `json:"id"`
	DisplayName   string          `json:"display_name,omitempty"`
	Keys          []agentDraftKey `json:"keys"`
	AllowedGroups []string        `json:"allowed_groups"`
	AllowedScopes []string        `json:"allowed_scopes"`
	Status        string          `json:"status"`
}

func agentDraftOf(a agentreg.Agent) agentDraftDoc {
	d := agentDraftDoc{
		ID: a.ID, DisplayName: a.DisplayName, Status: string(a.Status),
		Keys:          make([]agentDraftKey, 0, len(a.Keys)),
		AllowedGroups: nonNilStrings(a.AllowedGroups), AllowedScopes: nonNilStrings(a.AllowedScopes),
	}
	for _, k := range a.Keys {
		d.Keys = append(d.Keys, agentDraftKey{KID: k.KID, JKT: k.JKT, Alg: k.Alg, JWK: k.JWK})
	}
	return d
}

func (d agentDraftDoc) json() json.RawMessage {
	b, _ := json.Marshal(d) // strings and raw JSON that was already valid
	return b
}

func decodeAgentDraft(raw json.RawMessage) (agentDraftDoc, error) {
	var d agentDraftDoc
	if err := json.Unmarshal(raw, &d); err != nil || d.ID == "" {
		return agentDraftDoc{}, errors.New("controlplane: agent draft doc is not an agent")
	}
	return d, nil
}

// agent is the registry value of the draft, status and keys as drafted. The
// owner is the caller's to set.
func (d agentDraftDoc) agent() agentreg.Agent {
	a := agentreg.Agent{
		ID: d.ID, DisplayName: d.DisplayName, AllowedGroups: d.AllowedGroups, AllowedScopes: d.AllowedScopes,
		Status: agentreg.Status(d.Status),
	}
	for _, k := range d.Keys {
		a.Keys = append(a.Keys, agentreg.Key{KID: k.KID, JKT: k.JKT, Alg: k.Alg, JWK: k.JWK})
	}
	return a
}

// agentTarget is the Classifier and Applier of the agents target.
type agentTarget struct{ s *Server }

var (
	_ approvals.Classifier       = agentTarget{}
	_ approvals.Applier          = agentTarget{}
	_ approvals.EmergencyApplier = agentTarget{}
	_ targetAdapter              = agentTarget{}
)

// current is the stored agent id, ok false when there is none.
func (t agentTarget) current(ctx context.Context, id string) (agentreg.Agent, bool, error) {
	a, err := t.s.agents.Get(ctx, id)
	switch {
	case err == nil:
		return a, true, nil
	case errors.Is(err, agentreg.ErrNotFound):
		return agentreg.Agent{}, false, nil
	}
	return agentreg.Agent{}, false, err
}

// Classify compares the drafted agent with the stored one. It widens when the
// agent is new, is switched back on, gains a key (added or replaced), a group
// or a scope; display name edits, removals and a disable do not. Reasons name
// the agent and the field, never a group, scope or key value (a key shows its
// thumbprint prefix).
func (t agentTarget) Classify(ctx context.Context, ref string, raw json.RawMessage) (approvals.Classification, error) {
	doc, err := decodeAgentDraft(raw)
	if err != nil {
		return approvals.Classification{}, err
	}
	if doc.ID != ref {
		return approvals.Classification{}, errors.New("controlplane: agent draft doc names another agent")
	}
	cur, ok, err := t.current(ctx, ref)
	if err != nil {
		return approvals.Classification{}, err
	}
	path := func(field string) string { return "agents:" + ref + "." + field }
	if !ok {
		return approvals.TargetClassification([]approvals.Reason{{Code: approvals.CodeAgentCreated, Path: "agents:" + ref, Detail: "agent registered"}}), nil
	}
	var reasons []approvals.Reason
	if cur.Status != agentreg.StatusActive && agentreg.Status(doc.Status) == agentreg.StatusActive {
		reasons = append(reasons, approvals.Reason{Code: approvals.CodeAgentEnabled, Path: path("status"), Detail: "agent re-enabled"})
	}
	have := agentreg.Thumbprints(cur)
	for _, k := range doc.Keys {
		if !slices.Contains(have, k.JKT) {
			reasons = append(reasons, approvals.Reason{Code: approvals.CodeAgentKeyAdded, Path: path("keys"), Detail: "key added, jkt " + agentreg.ThumbprintPrefix(k.JKT)})
		}
	}
	if added, _ := setDiff(cur.AllowedGroups, doc.AllowedGroups); len(added) > 0 {
		reasons = append(reasons, approvals.Reason{Code: approvals.CodeAgentGroupAdded, Path: path("allowed_groups"), Detail: fmt.Sprintf("%d group(s) added", len(added))})
	}
	if added, _ := setDiff(cur.AllowedScopes, doc.AllowedScopes); len(added) > 0 {
		reasons = append(reasons, approvals.Reason{Code: approvals.CodeAgentScopeAdded, Path: path("allowed_scopes"), Detail: fmt.Sprintf("%d scope(s) added", len(added))})
	}
	return approvals.TargetClassification(reasons), nil
}

func (t agentTarget) Apply(ctx context.Context, d approvals.Draft) (int64, error) {
	return t.apply(ctx, d, blockActor(ctx), false)
}

func (t agentTarget) ApplyEmergency(ctx context.Context, d approvals.Draft, _ approvals.Clearance, actor approvals.Author) (int64, error) {
	return t.apply(ctx, d, actor.Sub, true)
}

// apply writes the drafted agent through the registry Store with the draft's
// base revision as the compare-and-swap token, as actor. It returns the agent's
// new revision. A moved agent is ErrRebaseRequired and writes nothing.
func (t agentTarget) apply(ctx context.Context, d approvals.Draft, actor string, committed bool) (int64, error) {
	if d.Target != approvals.TargetAgents {
		return 0, fmt.Errorf("%w: %s", approvals.ErrUnsupportedTarget, d.Target)
	}
	if _, err := t.s.gate.ClearApplied(ctx, d); err != nil {
		return 0, err
	}
	doc, err := decodeAgentDraft(d.DocJSON)
	if err != nil {
		return 0, err
	}
	cur, exists, err := t.current(ctx, d.TargetRef)
	if err != nil {
		return 0, err
	}
	want := doc.agent()
	before := t.s.targetHashNow(ctx, AgentAuditTarget)

	var out agentreg.Agent
	var op string
	switch {
	case d.BaseVersion == 0 && exists:
		return 0, fmt.Errorf("%w: agent %s is registered now", approvals.ErrRebaseRequired, d.TargetRef)
	case d.BaseVersion == 0:
		want.OwnerIss, want.OwnerSub, want.OwnerEmail = d.Author.Iss, d.Author.Sub, d.Author.Email
		op = agentActionCreate
		out, err = t.s.agents.Create(ctx, want, actor)
	case !exists || cur.Revision != d.BaseVersion:
		return 0, fmt.Errorf("%w: agent %s moved from revision %d", approvals.ErrRebaseRequired, d.TargetRef, d.BaseVersion)
	default:
		out, op, err = t.update(ctx, cur, want, actor)
	}
	if err != nil {
		t.s.agentMetrics.inc(op, agentOutcome(err))
		return 0, t.mapApplyErr(op, d.TargetRef, err)
	}
	t.s.agentMetrics.inc(op, agentOutcomeOK)
	var details map[string]string
	switch op {
	case agentActionCreate:
		details = AgentAuditDetails(nil, out)
	case agentActionEnable, agentActionDisable:
		details = AgentStatusAuditDetails(cur, op)
	default:
		details = AgentAuditDetails(&cur, out)
	}
	if len(details) < agentAuditMaxKeys {
		details[adminaudit.DetailSource] = SourceApproval
	}
	addAuditFollowUp(ctx, auditFollowUp{
		Action: agentAuditAction(op), Target: AgentAuditTarget, TargetRef: AgentAuditRef(d.TargetRef),
		Details: details, BeforeHash: before, AfterHash: t.s.targetHashNow(ctx, AgentAuditTarget), Committed: committed,
	})
	t.s.refresh()
	return out.Revision, nil
}

// update writes the editable fields when they differ from cur, then the status
// when it does. Both steps carry the revision just read, so a concurrent write
// between them is a conflict rather than a lost update.
func (t agentTarget) update(ctx context.Context, cur, want agentreg.Agent, actor string) (agentreg.Agent, string, error) {
	out, op := cur, agentActionUpdate
	if agentFieldsDiffer(cur, want) {
		want.OwnerIss, want.OwnerSub, want.OwnerEmail = cur.OwnerIss, cur.OwnerSub, cur.OwnerEmail
		want.Revision = cur.Revision
		var err error
		if out, err = t.s.agents.Update(ctx, want, actor); err != nil {
			return agentreg.Agent{}, op, err
		}
	}
	if want.Status != cur.Status {
		op = agentActionEnable
		if want.Status == agentreg.StatusDisabled {
			op = agentActionDisable
		}
		var err error
		if out, err = t.s.agents.SetStatus(ctx, cur.ID, want.Status, out.Revision, actor); err != nil {
			return agentreg.Agent{}, op, err
		}
	}
	return out, op, nil
}

func agentFieldsDiffer(a, b agentreg.Agent) bool {
	if a.DisplayName != b.DisplayName {
		return true
	}
	if !slices.Equal(nonNilStrings(a.AllowedGroups), nonNilStrings(b.AllowedGroups)) || !slices.Equal(nonNilStrings(a.AllowedScopes), nonNilStrings(b.AllowedScopes)) {
		return true
	}
	return !slices.Equal(agentreg.Thumbprints(a), agentreg.Thumbprints(b)) || !slices.Equal(agentKIDs(a), agentKIDs(b))
}

func agentAuditAction(op string) string {
	switch op {
	case agentActionCreate:
		return AgentActionCreate
	case agentActionEnable:
		return AgentActionEnable
	case agentActionDisable:
		return AgentActionDisable
	}
	return AgentActionUpdate
}

// mapApplyErr maps a registry refusal at apply time to the response of the
// approve request. A stale revision is a rebase; the rest are the validation
// and uniqueness refusals the direct route answers.
func (t agentTarget) mapApplyErr(op, id string, err error) error {
	var ie *agentreg.InvalidError
	fail := func(status int, code string) error {
		return &dashboard.ChangeError{Status: status, Code: code, Err: err}
	}
	switch {
	case errors.Is(err, agentreg.ErrConflict), errors.Is(err, agentreg.ErrNotFound), errors.Is(err, agentreg.ErrAlreadyExists):
		return fmt.Errorf("%w: agent %s: %v", approvals.ErrRebaseRequired, id, err)
	case errors.As(err, &ie):
		return &dashboard.ChangeError{Status: http.StatusUnprocessableEntity, Code: "invalid_agent", Fields: map[string]any{"field": ie.Field, "message": ie.Reason}, Err: err}
	case errors.Is(err, agentreg.ErrKeyInUse):
		return fail(http.StatusConflict, "key_in_use")
	case errors.Is(err, agentreg.ErrRegistryFull):
		return fail(http.StatusUnprocessableEntity, "registry_full")
	}
	t.s.cfg.Logger.Error("agent registry request failed", "op", op, "agent", id, "error", err)
	return err
}

// agentViewOf is an agent draft as the console sees it: keys by id, algorithm
// and thumbprint only.
func agentViewOf(d agentDraftDoc) any {
	d.Keys = slices.Clone(d.Keys)
	for i := range d.Keys {
		d.Keys[i].JWK = nil
	}
	return d
}

func (agentTarget) View(d approvals.Draft, _ bool) (any, error) {
	doc, err := decodeAgentDraft(d.DocJSON)
	if err != nil {
		return nil, err
	}
	return agentViewOf(doc), nil
}

func (t agentTarget) Current(ctx context.Context, d approvals.Draft, _ bool) (any, error) {
	a, ok, err := t.current(ctx, d.TargetRef)
	if err != nil || !ok {
		return nil, err
	}
	return agentViewOf(agentDraftOf(a)), nil
}

// holdAgent gates one registry write. proposed is the agent as it would be
// after the write (status included), base the revision the client saw (0 for a
// registration). It returns nil when the write may go ahead at once (approvals
// off, or the change does not widen), a *dashboard.HeldForApproval when it was
// held as a draft, and an error when the write cannot be validated or the gate
// is unavailable.
func (a agentRegistryAPI) holdAgent(ctx context.Context, action string, proposed agentreg.Agent, base int64) error {
	s := a.srv
	if s == nil || !s.gate.Enabled() {
		return nil
	}
	v, err := agentreg.Validate(proposed)
	if err != nil {
		return a.failed(action, proposed.ID, err)
	}
	author, err := s.writeAuthor(ctx)
	if err != nil {
		return err
	}
	ch := approvals.Change{
		Target: approvals.TargetAgents, TargetRef: v.ID, Base: base, TargetDoc: agentDraftOf(v).json(),
		Author: s.draftAuthor(ctx, author), Source: approvals.SourceConsole, Message: action + " agent " + v.ID,
	}
	_, err = s.gate.Clear(ctx, ch)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, approvals.ErrApprovalRequired):
		a.metrics.inc(action, agentOutcomeHeld)
		return s.hold(ctx, ch)
	}
	return s.gateError(err)
}
