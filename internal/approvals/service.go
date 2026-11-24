package approvals

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// maxLastError caps the error text stored on a draft, in bytes; maxMessage caps
// a change message, in runes (a policy version message has the same cap).
//
// A draft's doc is bounded by the caller: APPR-04's request body cap (1 MiB)
// is what limits doc_json, this package does not re-measure it.
const (
	maxLastError = 512
	maxMessage   = 512
)

func capMessage(m string) string {
	if r := []rune(m); len(r) > maxMessage {
		return string(r[:maxMessage])
	}
	return m
}

// ServiceConfig wires a Service.
type ServiceConfig struct {
	Store Store
	// Appliers holds one Applier per supported target.
	Appliers map[Target]Applier
	// Redact replaces credential values with their fingerprint (the control
	// plane's RedactCredentials). Required: a draft must never hold a raw
	// credential.
	Redact func(Doc) Doc
	// Now is the clock (the CP clock port); required, since this package never
	// reads the wall clock.
	Now func() time.Time
	// DraftTTL and MaxOpenDrafts are console.approvals.draftTTL and
	// maxOpenDrafts.
	DraftTTL      time.Duration
	MaxOpenDrafts int
	Logger        *slog.Logger
}

// Service creates drafts and applies approved ones. Later tickets add the
// two-person rule (APPR-04) and the clearance gate (APPR-06) on top of it.
type Service struct {
	cfg ServiceConfig
	// applyMu serialises Apply so two callers cannot publish the same draft.
	applyMu sync.Mutex
}

// NewService validates cfg and returns a Service.
func NewService(cfg ServiceConfig) (*Service, error) {
	switch {
	case cfg.Store == nil:
		return nil, errors.New("approvals: service needs a store")
	case cfg.Redact == nil:
		return nil, errors.New("approvals: service needs a redaction func")
	case cfg.Now == nil:
		return nil, errors.New("approvals: service needs a clock")
	case cfg.DraftTTL <= 0:
		return nil, errors.New("approvals: draftTTL must be positive")
	case cfg.MaxOpenDrafts <= 0:
		return nil, errors.New("approvals: maxOpenDrafts must be positive")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Service{cfg: cfg}, nil
}

// Store returns the underlying store, for the read and transition paths the
// API layer drives directly.
func (s *Service) Store() Store { return s.cfg.Store }

// EncodeDoc redacts doc with redact and returns its canonical JSON and the
// sha256 of that JSON. For the policy target this is byte-for-byte what
// policy_versions stores and hashes for the same doc.
func EncodeDoc(doc Doc, redact func(Doc) Doc) (json.RawMessage, string, error) {
	b, err := json.Marshal(redact(doc))
	if err != nil {
		return nil, "", fmt.Errorf("approvals: encode doc: %w", err)
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

// CreateDraft stores doc (credential-redacted) as a new draft based on
// baseVersion, in state draft. Only the policy target has a doc codec so far.
func (s *Service) CreateDraft(ctx context.Context, target Target, doc Doc, author Author, prov Provenance, baseVersion int64) (Draft, error) {
	if !target.Valid() {
		return Draft{}, fmt.Errorf("approvals: unknown target %q", target)
	}
	if target != TargetPolicy {
		return Draft{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, target)
	}
	if strings.TrimSpace(author.Sub) == "" {
		return Draft{}, errors.New("approvals: draft author has no subject")
	}
	if prov.Source == "" {
		prov.Source = SourceConsole
	}
	if !prov.Source.Valid() {
		return Draft{}, fmt.Errorf("approvals: unknown source %q", prov.Source)
	}
	if baseVersion < 0 {
		return Draft{}, errors.New("approvals: negative base version")
	}
	raw, sha, err := EncodeDoc(doc, s.cfg.Redact)
	if err != nil {
		return Draft{}, err
	}
	return s.cfg.Store.Create(ctx, NewDraft{
		Target: target, BaseVersion: baseVersion, Author: author,
		Source: prov.Source, Provenance: prov, Message: capMessage(prov.Message),
		DocJSON: raw, DocSHA256: sha,
		ExpiresAt: s.cfg.Now().Add(s.cfg.DraftTTL),
	}, s.cfg.MaxOpenDrafts)
}

// UpdateDraft is Store.Update with the doc redacted and hashed here, so no edit
// path can store a raw credential or a digest that does not match its doc.
func (s *Service) UpdateDraft(ctx context.Context, id string, expectedRevision int, doc Doc, message, actorSub string) (Draft, error) {
	raw, sha, err := EncodeDoc(doc, s.cfg.Redact)
	if err != nil {
		return Draft{}, err
	}
	return s.cfg.Store.Update(ctx, id, UpdateInput{ExpectedRevision: expectedRevision, Message: capMessage(message), DocJSON: raw, DocSHA256: sha}, actorSub)
}

// RebaseDraft is Store.Rebase with the doc redacted and hashed here: doc is the
// draft's change re-applied onto the new head (W-P1-PVER-09 structural diff,
// done by the caller).
func (s *Service) RebaseDraft(ctx context.Context, id string, expectedRevision int, newBase int64, doc Doc, message, actorSub string) (Draft, error) {
	if newBase < 0 {
		return Draft{}, errors.New("approvals: negative base version")
	}
	raw, sha, err := EncodeDoc(doc, s.cfg.Redact)
	if err != nil {
		return Draft{}, err
	}
	return s.cfg.Store.Rebase(ctx, id, UpdateInput{ExpectedRevision: expectedRevision, BaseVersion: newBase, Message: capMessage(message), DocJSON: raw, DocSHA256: sha}, actorSub)
}

// Apply publishes a pending draft at revision through its target's Applier and
// marks it applied. Whoever calls it has already counted the approvals (the
// two-person rule is APPR-04's).
//
// The draft is first claimed with pending -> applying (one compare-and-swap),
// so a concurrent withdraw, edit, reject or expiry is refused instead of racing
// the publish. Then:
//
//   - A moved base returns ErrRebaseRequired and the draft becomes needs_rebase.
//   - Any other Applier error (a validation failure) is returned as is and the
//     draft returns to pending with last_error set.
//   - A draft that is not pending returns ErrIllegalTransition and no version
//     is created, so a second Apply of an applied draft is harmless.
//
// A crash between the claim and the outcome is repaired by Reconcile.
func (s *Service) Apply(ctx context.Context, id string, revision int, actorSub string) (Draft, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	d, err := s.cfg.Store.Get(ctx, id)
	if err != nil {
		return Draft{}, err
	}
	if d.Revision != revision {
		return Draft{}, fmt.Errorf("%w: draft is at revision %d, not %d", ErrStateChanged, d.Revision, revision)
	}
	if _, err := Transition(d.State, EventBeginApply); err != nil {
		return Draft{}, err
	}
	ap, ok := s.cfg.Appliers[d.Target]
	if !ok {
		return Draft{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, d.Target)
	}
	d, err = s.cfg.Store.BeginApply(ctx, id, revision, actorSub)
	if err != nil {
		return Draft{}, err
	}
	version, aerr := ap.Apply(ctx, d)
	// The outcome must be recorded even if the caller's context ended: the
	// publish may already have happened.
	octx := context.WithoutCancel(ctx)
	switch {
	case errors.Is(aerr, ErrRebaseRequired):
		nd, merr := s.cfg.Store.MarkNeedsRebase(octx, id, revision, truncate(aerr.Error()), actorSub)
		if merr != nil {
			return Draft{}, merr
		}
		return nd, ErrRebaseRequired
	case aerr != nil:
		if _, ferr := s.cfg.Store.FailApply(octx, id, revision, truncate(aerr.Error()), actorSub); ferr != nil {
			s.cfg.Logger.Error("approvals: cannot return the draft to pending after a refused apply", "draft_id", id, "error", ferr)
		}
		return Draft{}, aerr
	}
	nd, err := s.cfg.Store.MarkApplied(octx, id, revision, version, actorSub)
	if err != nil {
		// Once more: the version is already live. A persistent failure leaves
		// the draft applying until the startup Reconcile settles it.
		nd, err = s.cfg.Store.MarkApplied(octx, id, revision, version, actorSub)
	}
	if err != nil {
		s.cfg.Logger.Error("approvals: draft was published but could not be marked applied; reconcile will repair it",
			"draft_id", id, "revision", revision, "applied_version", version, "error", err)
		return Draft{}, err
	}
	return nd, nil
}

// VersionFinder reports the version a draft revision published, if any. The
// control plane implements it by finding the `approval`-source policy version
// whose message names the draft id and revision.
type VersionFinder func(ctx context.Context, draftID string, revision int) (version int64, found bool, err error)

// Reconcile repairs drafts a crash left in applying: one with a published
// version becomes applied at it, one without returns to pending with a
// last_error. It returns how many it moved.
func (s *Service) Reconcile(ctx context.Context, find VersionFinder) (int, error) {
	ds, err := s.cfg.Store.Applying(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, d := range ds {
		version, found, err := find(ctx, d.ID, d.Revision)
		if err != nil {
			return n, err
		}
		if found {
			_, err = s.cfg.Store.MarkApplied(ctx, d.ID, d.Revision, version, "system")
		} else {
			_, err = s.cfg.Store.FailApply(ctx, d.ID, d.Revision, "apply was interrupted before a version was published; approve again", "system")
		}
		if err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Sweep moves open drafts past their expiry to expired and returns how many.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	ds, err := s.cfg.Store.ExpireDue(ctx, s.cfg.Now())
	return len(ds), err
}

func truncate(msg string) string {
	if len(msg) <= maxLastError {
		return msg
	}
	return strings.ToValidUTF8(msg[:maxLastError], "")
}
