package controlplane

// policycli_approvals.go is the offline `warden policy import` with approvals
// enabled (W-P2-APPR-06): the CLI cannot publish past the gate, so it stores the
// file as a pending change draft authored cli:<os user> and leaves head alone.
// It never approves or applies; the control plane queues the draft's replay on
// its next sweep and a second person approves it in the console.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
)

// approvalsMeta reads what the control plane last started with. found is false
// when approvals were never enabled on this state database.
func (o *OfflinePolicyStore) approvalsMeta(ctx context.Context) (sqlstore.Meta, bool, error) {
	m, found, err := sqlstore.ReadMeta(ctx, o.db.SQL())
	if err != nil {
		return sqlstore.Meta{}, false, fmt.Errorf("policy import: cannot tell whether approvals are enabled: %w", err)
	}
	return m, found && m.Enabled, nil
}

// holdImport stores doc as a pending draft based on the head instead of a
// version. It returns the draft id in PolicyImportResult, with Held set.
func (o *OfflinePolicyStore) holdImport(ctx context.Context, m sqlstore.Meta, doc PolicyDoc, msg string, expectedHead int64, rec adminaudit.Recorder) (PolicyImportResult, error) {
	head, err := o.st.Head(ctx)
	if err != nil {
		return PolicyImportResult{}, err
	}
	if head != expectedHead {
		return PolicyImportResult{}, fmt.Errorf("%w: the head is now v%d (expected v%d); nothing was imported", ErrConflict, head, expectedHead)
	}
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:         sqlstore.New(o.db.SQL(), time.Now, slog.New(slog.DiscardHandler)),
		Redact:        redactDraftDoc,
		Now:           time.Now,
		DraftTTL:      m.DraftTTL,
		MaxOpenDrafts: m.MaxOpenDrafts,
		BaseDoc: func(ctx context.Context, version int64) (approvals.Doc, error) {
			v, err := o.st.Get(ctx, version)
			if err != nil {
				return approvals.Doc{}, err
			}
			return draftDoc(RedactCredentials(v.Doc)), nil
		},
	})
	if err != nil {
		return PolicyImportResult{}, err
	}
	d := draftDoc(RedactCredentials(doc.wire))
	if head > 0 {
		hv, err := o.st.Get(ctx, head)
		if err != nil {
			return PolicyImportResult{}, err
		}
		if _, sha, err := approvals.EncodeDoc(d, redactDraftDoc); err == nil && sha == hv.DocSHA256 {
			return PolicyImportResult{Version: head, Parent: head}, nil
		}
	}
	author := approvals.Author{Sub: adminaudit.CLIActor(), Kind: AuthorKindCLI}
	draft, err := svc.CreateDraft(ctx, approvals.TargetPolicy, d, author, approvals.Provenance{
		Source: approvals.SourceCLI, Message: msg, Ref: filepath.Base(doc.path),
	}, head)
	if err != nil {
		if errors.Is(err, approvals.ErrTooManyDrafts) {
			return PolicyImportResult{}, fmt.Errorf("policy import: too many open change drafts (console.approvals.maxOpenDrafts is %d); resolve some first: %w", m.MaxOpenDrafts, err)
		}
		return PolicyImportResult{}, err
	}
	if draft, err = svc.Submit(ctx, draft.ID, draft.Revision, author.Sub); err != nil {
		return PolicyImportResult{}, fmt.Errorf("policy import: draft %s was created but could not be submitted: %w", draft.ID, err)
	}
	res := PolicyImportResult{Parent: head, Held: true, DraftID: draft.ID}
	if rec == nil {
		return res, nil
	}
	hash := ""
	if head > 0 {
		hv, err := o.st.Get(ctx, head)
		if err != nil {
			return res, err
		}
		hash = fmt.Sprintf("v%d:%s", hv.Version, hv.DocSHA256)
	}
	if _, err := rec.Record(ctx, adminaudit.Input{
		Action:     actionPolicyImport,
		Target:     auditTargetChangeDraft,
		TargetRef:  "draft:" + draft.ID + "@r" + fmt.Sprint(draft.Revision),
		Outcome:    adminaudit.OutcomeOK,
		Details:    map[string]string{adminaudit.DetailOp: "held", adminaudit.DetailBaseVersion: fmt.Sprint(head)},
		BeforeHash: hash,
		AfterHash:  hash,
	}); err != nil {
		return res, fmt.Errorf("draft %s was created but its admin audit row was not appended: %w", draft.ID, err)
	}
	return res, nil
}
