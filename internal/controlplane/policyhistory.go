package controlplane

// policyhistory.go is the control plane's dashboard.PolicyHistory (W-P1-PVER-03):
// the history, diff and rollback routes over the versioned PolicyVersionStore.
// It is wired only in --policy-store=versioned. Rollback never rewrites
// history: it publishes the target's doc as a new head version through
// Server.publishVersion, so authorship, validation, the conflict check and the
// policy server refresh are the ones every versioned write uses.

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

// policyHistory implements dashboard.PolicyHistory over s.versions.
type policyHistory struct{ s *Server }

var _ dashboard.PolicyHistory = policyHistory{}

// policyHistoryAPI returns the dashboard's policy history, or nil in file
// mode (the routes then answer 404).
func (s *Server) policyHistoryAPI() dashboard.PolicyHistory {
	if s.versions == nil {
		return nil
	}
	return policyHistory{s: s}
}

// List implements dashboard.PolicyHistory.
func (h policyHistory) List(ctx context.Context, cursor int64, limit int) ([]dashboard.PolicyVersionMeta, int64, error) {
	vs, next, err := h.s.versions.List(ctx, cursor, limit)
	if err != nil {
		return nil, 0, h.storeError("list", 0, err)
	}
	out := make([]dashboard.PolicyVersionMeta, len(vs))
	for i, v := range vs {
		out[i] = versionMeta(v)
	}
	return out, next, nil
}

// Get implements dashboard.PolicyHistory. The doc is redacted again on the way
// out: versions are stored redacted, and a response never carries a raw
// credential even if one were stored.
func (h policyHistory) Get(ctx context.Context, version int64) (dashboard.PolicyVersionDoc, error) {
	v, err := h.s.versions.Get(ctx, version)
	if err != nil {
		return dashboard.PolicyVersionDoc{}, h.storeError("get", version, err)
	}
	return dashboard.PolicyVersionDoc{PolicyVersionMeta: versionMeta(v), Doc: RedactCredentials(v.Doc)}, nil
}

// Diff implements dashboard.PolicyHistory: DiffDocs from against (0 = head)
// to version, so with the default it is what a rollback to version would
// change.
func (h policyHistory) Diff(ctx context.Context, version, against int64) (dashboard.PolicyVersionDiff, error) {
	if against == 0 {
		head, err := h.s.versions.Head(ctx)
		if err != nil {
			return dashboard.PolicyVersionDiff{}, h.storeError("diff", version, err)
		}
		against = head
	}
	from, err := h.s.versions.Get(ctx, against)
	if err != nil {
		return dashboard.PolicyVersionDiff{}, h.storeError("diff", against, err)
	}
	to, err := h.s.versions.Get(ctx, version)
	if err != nil {
		return dashboard.PolicyVersionDiff{}, h.storeError("diff", version, err)
	}
	d, err := DiffDocs(RedactCredentials(from.Doc), RedactCredentials(to.Doc))
	if err != nil {
		return dashboard.PolicyVersionDiff{}, h.storeError("diff", version, err)
	}
	return dashboard.PolicyVersionDiff{From: against, To: version, Diff: d}, nil
}

// Rollback implements dashboard.PolicyHistory. Under publish's write lock it
// checks meta.ExpectedHead against head first (a stale rollback is a 409 even
// when the target no longer validates), then replaces head's doc with the
// target's, keeping head's credential fingerprint: the live credential is
// never part of a version and stays the one the served YAML holds, as does
// every serve-time overlay (the block list). publish revalidates the result
// with today's loader and creates latest+1 with source rollback; a doc equal
// to head's creates nothing. The log line names versions and the actor only,
// never doc content.
func (h policyHistory) Rollback(ctx context.Context, version int64, note string, meta dashboard.WriteMeta) (dashboard.RollbackResult, error) {
	meta.Message = rollbackMessage(version, note)
	var fromHead int64
	mutate := func(w *policyWire) error {
		head, err := h.s.versions.Head(ctx)
		if err != nil {
			return h.storeError("rollback", version, err)
		}
		fromHead = head
		if meta.ExpectedHead != 0 && head != meta.ExpectedHead {
			return h.s.conflictError(ctx, fmt.Errorf("%w: head is v%d, expected v%d", ErrConflict, head, meta.ExpectedHead))
		}
		target, err := h.s.versions.Get(ctx, version)
		if err != nil {
			return h.storeError("rollback", version, err)
		}
		doc := target.Doc
		keepCredential(&doc, credentialOf(*w))
		*w = doc
		return nil
	}
	newHead, changed, err := h.s.publishVersion(ctx, mutate, meta, SourceRollback)
	if err != nil {
		return dashboard.RollbackResult{}, err
	}
	actor, _ := h.s.writeAuthor(ctx) // publishVersion already resolved it
	h.s.cfg.Logger.Info("policy rollback",
		"from_head", fromHead, "to_version", version, "new_head", newHead,
		"changed", changed, "actor_sub", actor.Sub)
	adminaudit.Annotate(ctx, "policy@"+h.s.policy.currentETag(), nil)
	return dashboard.RollbackResult{Head: newHead, Changed: changed}, nil
}

// rollbackMessage is "rollback to v<N>", plus ": <note>" when there is a
// note. The note is cut, never the prefix, so the message fits the store's
// maxPolicyMessage and always names the target version.
func rollbackMessage(version int64, note string) string {
	msg := fmt.Sprintf("rollback to v%d", version)
	if note == "" {
		return msg
	}
	msg += ": "
	if r := []rune(note); len(r) > maxPolicyMessage-len(msg) {
		note = string(r[:maxPolicyMessage-len(msg)])
	}
	return msg + note
}

// keepCredential sets doc's secretAccessKey to key (head's fingerprint, or ""
// when head has none). A doc without a secrets block is left alone.
func keepCredential(doc *policyWire, key string) {
	if doc.Settings == nil || doc.Settings.Secrets == nil {
		return
	}
	settings := *doc.Settings
	secrets := *settings.Secrets
	secrets.SecretAccessKey = key
	settings.Secrets = &secrets
	doc.Settings = &settings
}

// storeError maps an unknown version to dashboard.ErrPolicyVersionNotFound
// and logs anything else (the dashboard answers it with a fixed 500 message).
func (h policyHistory) storeError(op string, version int64, err error) error {
	if errors.Is(err, ErrVersionNotFound) {
		return dashboard.ErrPolicyVersionNotFound
	}
	h.s.cfg.Logger.Error("control plane: policy history "+op+" failed", "version", version, "error", err)
	return err
}

func versionMeta(v PolicyVersion) dashboard.PolicyVersionMeta {
	return dashboard.PolicyVersionMeta{
		Version: v.Version, Parent: v.Parent, CreatedAt: v.CreatedAt.UTC(),
		AuthorSub: v.Author.Sub, AuthorEmail: v.Author.Email, AuthorKind: v.Author.Kind,
		Message: v.Message, Source: v.Source, DocSHA256: v.DocSHA256,
	}
}
