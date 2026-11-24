package controlplane

// approvals_apply.go wires the change-approval domain (W-P2-APPR-01) into the
// control plane: the policy Applier over s.publish, the approvals Service and
// the expiry sweeper. Everything here is built only when
// console.approvals.enabled, so a control plane without it has no table, no
// goroutine and no new code path.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/internal/dashboard"
)

// approvalsSweepInterval is how often the sweeper moves expired drafts. Expiry
// is measured in hours, so a minute is precise enough and cheap.
const approvalsSweepInterval = time.Minute

// stateMigrationsWithApprovals applies approvals/0001 and 0002 when the gate is on, so a
// control plane without approvals creates no table (the migration is Optional
// and always registered for the downgrade guard).
func stateMigrationsWithApprovals(migs []cpstate.Migration, ac config.ConsoleApprovals) []cpstate.Migration {
	if ac.Enabled {
		return cpstate.Enable(migs, sqlstore.EnabledMigrationIDs()...)
	}
	return migs
}

// checkApprovalsStartup validates what console.approvals.enabled needs, naming
// the first missing item. A disabled block always passes.
func checkApprovalsStartup(cc config.ConsoleConfig, policyStore, stateDir string) error {
	if !cc.Approvals.Enabled {
		return nil
	}
	switch {
	case cc.Auth != config.ConsoleAuthOIDC:
		return errors.New("control-plane: console.approvals.enabled needs console.auth: oidc (approvals need a signed-in identity for the author and the approver)")
	case policyStore != PolicyStoreVersioned:
		return errors.New("control-plane: console.approvals.enabled needs --policy-store=versioned (drafts apply through the versioned publish path)")
	case stateDir == "":
		return errors.New("control-plane: console.approvals.enabled needs --state-dir (drafts live in the control-plane state database)")
	case !cc.AdminAudit.Enabled:
		return errors.New("control-plane: console.approvals.enabled needs console.adminAudit.enabled: true (every transition is an audited change)")
	}
	return nil
}

// policyApplier publishes an approved policy draft through Server.publish's
// path (publish) with expectedHead=base_version, source `approval`
// and the draft author as the version author. Validation, credential
// redaction and the policy audit row are the publish path's, so approving a
// draft can never skip them.
type policyApplier struct{ s *Server }

var _ approvals.Applier = policyApplier{}

// draftVersionPrefix starts the message of every version a draft publishes. It
// names the draft and revision, which is how Reconcile finds the version of an
// interrupted apply.
func draftVersionPrefix(id string, revision int) string {
	return fmt.Sprintf("draft %s@r%d: ", id, revision)
}

// errDraftCredential is the validation-class refusal of a credential change.
func errDraftCredential(draftFP, headFP string) error {
	return &dashboard.InvalidPolicyError{Err: fmt.Errorf(
		"credential changes cannot go through a draft; change the served credential first (draft secretAccessKey %s, current %s)",
		fingerprintOrNone(draftFP), fingerprintOrNone(headFP))}
}

// Apply implements approvals.Applier. A moved head is approvals.ErrRebaseRequired
// and creates no version; a validation failure is the loader's
// *dashboard.InvalidPolicyError, also with no version.
func (a policyApplier) Apply(ctx context.Context, d approvals.Draft) (int64, error) {
	if d.Target != approvals.TargetPolicy {
		return 0, fmt.Errorf("%w: %s", approvals.ErrUnsupportedTarget, d.Target)
	}
	doc, err := d.PolicyDoc()
	if err != nil {
		return 0, fmt.Errorf("controlplane: decode draft %s doc: %w", d.ID, err)
	}
	// The Gate mints the clearance of a draft the Service is applying (state
	// applying, classified); nothing else reaches publish through this path.
	clr, err := a.s.gate.ClearApplied(d)
	if err != nil {
		return 0, err
	}
	author := PolicyAuthor{Sub: d.Author.Sub, Email: d.Author.Email, Kind: d.Author.Kind}
	mutate := func(w *policyWire) error {
		// publish treats ExpectedHead 0 as "the head I read", which would let a
		// draft based on an empty store overwrite a head that has since moved.
		// This runs under writeMu, so the check and the publish see one head.
		head, err := a.s.versions.Head(ctx)
		if err != nil {
			return fmt.Errorf("controlplane: read policy head: %w", err)
		}
		if head != d.BaseVersion {
			return fmt.Errorf("%w: head is v%d, the draft is based on v%d", approvals.ErrRebaseRequired, head, d.BaseVersion)
		}
		// A version keeps only the credential fingerprint and the CP serves the
		// served config's value for it, so a draft that changes the credential
		// would publish a fingerprint nothing serves. Only fingerprints are named.
		if got, cur := credentialOf(policyWire{Settings: doc.Settings}), credentialOf(*w); got != cur {
			return errDraftCredential(got, cur)
		}
		// The draft doc is the whole canonical doc; the block list is a serve-time
		// overlay and stays as the head has it.
		w.Allowlist, w.Denylist, w.Settings = doc.Allowlist, doc.Denylist, doc.Settings
		return nil
	}
	msg := draftVersionPrefix(d.ID, d.Revision) + d.Message
	version, _, err := a.s.publish(ctx, clr, author, mutate, dashboard.WriteMeta{ExpectedHead: d.BaseVersion, Message: msg}, SourceApproval)
	switch {
	case err == nil:
		return version, nil
	case errors.Is(err, approvals.ErrRebaseRequired):
		return 0, err
	case errors.Is(err, ErrConflict):
		return 0, fmt.Errorf("%w: %s", approvals.ErrRebaseRequired, err)
	}
	return 0, err
}

// findDraftVersion is the approvals.VersionFinder: the `approval` version whose
// message starts with the draft's prefix.
func (s *Server) findDraftVersion(ctx context.Context, id string, revision int) (int64, bool, error) {
	prefix := draftVersionPrefix(id, revision)
	var v int64
	err := s.cfg.State.SQL().QueryRowContext(ctx,
		"SELECT version FROM policy_versions WHERE source = ? AND substr(message, 1, ?) = ? ORDER BY version DESC LIMIT 1",
		SourceApproval, len([]rune(prefix)), prefix).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("controlplane: find the version of draft %s: %w", id, err)
	}
	return v, true, nil
}

// draftDoc and policyWireDoc convert between the approvals doc and the policy
// wire: the same three fields, in the same JSON shape.
func draftDoc(w policyWire) approvals.Doc {
	return approvals.Doc{Allowlist: w.Allowlist, Denylist: w.Denylist, Settings: w.Settings}
}

// redactDraftDoc is RedactCredentials over an approvals doc: the one redaction
// helper policy versions use, injected into the approvals Service.
func redactDraftDoc(d approvals.Doc) approvals.Doc {
	return draftDoc(RedactCredentials(policyWire{Allowlist: d.Allowlist, Denylist: d.Denylist, Settings: d.Settings}))
}

// initApprovals builds the approvals Service when console.approvals is enabled
// on a versioned control plane with a state database. Run's startup checks
// guarantee those; a Server built without them (a test) simply has no gate.
func (s *Server) initApprovals() {
	ac := s.cfg.Console.Approvals
	if !ac.Enabled {
		// A state database that once ran with approvals records that it no
		// longer does, so the offline CLI imports directly again.
		if s.cfg.State != nil {
			if err := sqlstore.WriteMeta(context.Background(), s.cfg.State.SQL(), sqlstore.Meta{}, s.cfg.Clock.Now()); err != nil {
				s.cfg.Logger.Warn("control plane: cannot record that approvals are disabled", "error", err)
			}
		}
		return
	}
	if s.versions == nil || s.cfg.State == nil {
		s.approvalsErr = errors.New("control-plane: console.approvals.enabled needs the versioned policy store and the state database")
		return
	}
	store := sqlstore.New(s.cfg.State.SQL(), s.cfg.Clock.Now, s.cfg.Logger)
	svc, err := approvals.NewService(approvals.ServiceConfig{
		Store:         store,
		Appliers:      map[approvals.Target]approvals.Applier{approvals.TargetPolicy: policyApplier{s: s}},
		Redact:        redactDraftDoc,
		Now:           s.cfg.Clock.Now,
		DraftTTL:      ac.DraftTTL,
		MaxOpenDrafts: ac.MaxOpenDrafts,
		Logger:        s.cfg.Logger,

		MinApprovals:              ac.MinApprovals,
		AllowSelfApproveNarrowing: ac.AllowSelfApproveNarrowing,
		ReplayMaxAge:              ac.ReplayMaxAge,
		BaseDoc: func(ctx context.Context, version int64) (approvals.Doc, error) {
			v, err := s.versions.Get(ctx, version)
			if err != nil {
				return approvals.Doc{}, err
			}
			return draftDoc(RedactCredentials(v.Doc)), nil
		},
		Head: func(ctx context.Context) (int64, approvals.Doc, error) {
			head, doc, err := s.headDoc(ctx)
			return head, draftDoc(RedactCredentials(doc)), err
		},
	})
	if err != nil {
		s.approvalsErr = fmt.Errorf("control-plane: approvals service: %w", err)
		return
	}
	// A crash mid-apply leaves a draft in applying: settle it from the versions.
	if n, err := svc.Reconcile(context.WithoutCancel(context.Background()), s.findDraftVersion); err != nil {
		s.approvalsErr = fmt.Errorf("control-plane: approvals reconcile: %w", err)
		return
	} else if n > 0 {
		s.cfg.Logger.Warn("control plane: settled change drafts interrupted mid-apply", "count", n)
	}
	if err := s.initReplays(svc); err != nil {
		s.approvalsErr = err
		return
	}
	// The offline CLI reads this row to hold its imports as drafts. A control
	// plane that cannot write it must not start: the CLI would publish past the
	// gate.
	meta := sqlstore.Meta{Enabled: true, DraftTTL: ac.DraftTTL, MaxOpenDrafts: ac.MaxOpenDrafts}
	if err := sqlstore.WriteMeta(context.Background(), s.cfg.State.SQL(), meta, s.cfg.Clock.Now()); err != nil {
		s.approvalsErr = fmt.Errorf("control-plane: %w", err)
		return
	}
	s.approvals = svc
}

// Approvals returns the approvals Service, or nil when console.approvals is not
// enabled.
func (s *Server) Approvals() *approvals.Service { return s.approvals }

// sweepApprovals moves expired drafts to expired until ctx ends. It runs on the
// CP clock only, so expiry never depends on a worker's or a client's time.
func (s *Server) sweepApprovals(ctx context.Context) {
	for {
		// Drafts the offline CLI created have no replay yet: queue them.
		if n, err := s.approvals.QueueMissingReplays(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.cfg.Logger.Warn("control plane: cannot queue replays of pending drafts", "error", err)
		} else if n > 0 {
			s.cfg.Logger.Info("control plane: queued replays of pending change drafts", "count", n)
		}
		if n, err := s.approvals.Sweep(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.cfg.Logger.Warn("control plane: approvals expiry sweep failed", "error", err)
		} else if n > 0 {
			s.cfg.Logger.Info("control plane: expired change drafts", "count", n)
		}
		if !waitOn(ctx, s.cfg.Clock, approvalsSweepInterval) {
			return
		}
	}
}
