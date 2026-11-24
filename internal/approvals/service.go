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

// maxLastError caps the error text stored on a draft, in bytes.
const maxLastError = 512

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
		Source: prov.Source, Provenance: prov, Message: prov.Message,
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
	return s.cfg.Store.Update(ctx, id, UpdateInput{ExpectedRevision: expectedRevision, Message: message, DocJSON: raw, DocSHA256: sha}, actorSub)
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
	return s.cfg.Store.Rebase(ctx, id, UpdateInput{ExpectedRevision: expectedRevision, BaseVersion: newBase, Message: message, DocJSON: raw, DocSHA256: sha}, actorSub)
}

// Apply publishes a pending draft at revision through its target's Applier and
// marks it applied. Whoever calls it has already counted the approvals (the
// two-person rule is APPR-04's).
//
//   - A moved base returns ErrRebaseRequired and the draft becomes needs_rebase.
//   - Any other Applier error (a validation failure) is returned as is and the
//     draft stays pending with last_error set.
//   - A draft that is not pending returns ErrIllegalTransition and no version
//     is created, so a second Apply of an applied draft is harmless.
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
	if _, err := Transition(d.State, EventApply); err != nil {
		return Draft{}, err
	}
	ap, ok := s.cfg.Appliers[d.Target]
	if !ok {
		return Draft{}, fmt.Errorf("%w: %s", ErrUnsupportedTarget, d.Target)
	}
	version, err := ap.Apply(ctx, d)
	switch {
	case errors.Is(err, ErrRebaseRequired):
		nd, merr := s.cfg.Store.MarkNeedsRebase(ctx, id, revision, truncate(err.Error()), actorSub)
		if merr != nil {
			return Draft{}, merr
		}
		return nd, ErrRebaseRequired
	case err != nil:
		if rerr := s.cfg.Store.RecordError(ctx, id, revision, truncate(err.Error())); rerr != nil {
			s.cfg.Logger.Warn("approvals: cannot record the apply error on the draft", "draft_id", id, "error", rerr)
		}
		return Draft{}, err
	}
	nd, err := s.cfg.Store.MarkApplied(ctx, id, revision, version, actorSub)
	if err != nil {
		// The version is already published; the draft row is what lost (for
		// example a concurrent withdraw). Say so loudly rather than hide it.
		s.cfg.Logger.Error("approvals: draft was published but could not be marked applied",
			"draft_id", id, "revision", revision, "applied_version", version, "error", err)
		return Draft{}, err
	}
	return nd, nil
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
