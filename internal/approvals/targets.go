package approvals

// targets.go is what a target other than the policy doc needs from the
// approvals domain (W-P2-APPR-08): a Classifier that says whether a proposed
// change to one entity widens access, and the draft that carries it. The block
// list and the agent registry are the first two; the MCP registry
// (W-P4-MREG-03) is the next. The policy target keeps its own Doc codec and
// Classify.
//
// A non-policy draft stores the target's own canonical JSON as its doc (the
// target adapter marshals it, so the same state always hashes the same) and
// names the entity in target_ref. Its base_version is the entity's revision
// when it has one (an agent's), else 0. Nothing in a stored doc may be a
// credential or free text an operator wrote (a block reason, a private key).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/ethosagent/warden/internal/config"
)

// Reason codes of the CP-local targets. They follow the policy reasons'
// shape: Path names the entity and the field, Detail never holds a user,
// group, scope or key value.
const (
	CodeBlockRemoved    = "blocklist.removed" // a block-list entry removed: that user is unblocked
	CodeAgentCreated    = "agent.created"     // a new agent registered
	CodeAgentEnabled    = "agent.enabled"     // a disabled agent switched back on
	CodeAgentKeyAdded   = "agent.key_added"   // a key the agent did not have (added or replaced)
	CodeAgentGroupAdded = "agent.group_added" // a group may now delegate to the agent
	CodeAgentScopeAdded = "agent.scope_added" // a delegation may now carry another scope
)

// Classifier says whether changing the entity ref of a non-policy target to doc
// (the canonical JSON a draft of the target carries) widens access, judged
// against the target's state now. The Service calls it again at approve time,
// so an implementation reads live state and never a cached copy.
type Classifier interface {
	Classify(ctx context.Context, ref string, doc json.RawMessage) (Classification, error)
}

// TargetDraft is a new draft of a non-policy target.
type TargetDraft struct {
	Target Target
	// Ref names the entity (a block id, an agent id).
	Ref string
	// Base is the revision of the entity the change was computed from; 0 when it
	// has none or the entity does not exist yet.
	Base   int64
	Doc    json.RawMessage
	Author Author
	Prov   Provenance
}

// DocSHA256Of is the digest of a non-policy doc's canonical JSON, the doc_sha256
// a draft stores for it.
func DocSHA256Of(doc json.RawMessage) string {
	sum := sha256.Sum256(doc)
	return hex.EncodeToString(sum[:])
}

// classifyTarget runs the registered Classifier of target.
func (s *Service) classifyTarget(ctx context.Context, target Target, ref string, doc json.RawMessage) (Classification, error) {
	c, ok := s.cfg.Classifiers[target]
	if !ok || c == nil {
		return Classification{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	return c.Classify(ctx, ref, doc)
}

// CreateTargetDraft stores td as a new draft in state draft, classified against
// the target's state now. Only a target with both a Classifier and an Applier is
// supported. A draft of the policy target goes through CreateDraft.
func (s *Service) CreateTargetDraft(ctx context.Context, td TargetDraft) (Draft, error) {
	switch {
	case !td.Target.Valid() || td.Target == TargetPolicy:
		return Draft{}, fmt.Errorf("%w: %q", ErrUnsupportedTarget, td.Target)
	case s.cfg.Appliers[td.Target] == nil:
		return Draft{}, fmt.Errorf("%w: %s has no applier", ErrUnsupportedTarget, td.Target)
	case strings.TrimSpace(td.Author.Sub) == "":
		return Draft{}, errors.New("approvals: draft author has no subject")
	case strings.TrimSpace(td.Ref) == "":
		return Draft{}, errors.New("approvals: a target draft needs a target ref")
	case td.Base < 0:
		return Draft{}, errors.New("approvals: negative base version")
	case !json.Valid(td.Doc):
		return Draft{}, errors.New("approvals: the draft doc is not JSON")
	}
	if td.Prov.Source == "" {
		td.Prov.Source = SourceConsole
	}
	if !td.Prov.Source.Valid() {
		return Draft{}, fmt.Errorf("approvals: unknown source %q", td.Prov.Source)
	}
	class, err := s.classifyTarget(ctx, td.Target, td.Ref, td.Doc)
	if err != nil {
		return Draft{}, err
	}
	raw, role, err := encodeClassification(class)
	if err != nil {
		return Draft{}, err
	}
	return s.cfg.Store.Create(ctx, NewDraft{
		Target: td.Target, TargetRef: td.Ref, BaseVersion: td.Base, Author: td.Author,
		Source: td.Prov.Source, Provenance: td.Prov, Message: capMessage(td.Prov.Message),
		DocJSON: td.Doc, DocSHA256: DocSHA256Of(td.Doc), Classification: raw, RequiredRole: role,
		ExpiresAt: s.cfg.Now().Add(s.cfg.DraftTTL),
	}, s.cfg.MaxOpenDrafts)
}

// TargetClassification builds the Classification of a widening change to a
// non-policy target: every such change needs an admin, the role that may write
// the target directly.
func TargetClassification(reasons []Reason) Classification {
	if reasons == nil {
		reasons = []Reason{}
	}
	return Classification{Widening: len(reasons) > 0, Reasons: reasons, RequiredRole: config.RoleAdmin}
}
