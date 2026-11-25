package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

// enrollmentRef is the admin audit target_ref of an enrollment token, the same
// one the enroll-token CLI records.
func enrollmentRef(id string) string { return "enroll_token:" + id }

// enrollmentAdmin adapts the EnrollmentTokenStore to dashboard.EnrollmentAdmin
// (W-P2-WCA-08). The store has no HTTP or identity concerns; this adapter takes
// the actor from the console Principal in ctx, maps store errors to the
// dashboard's sentinels and annotates the admin audit row with the token id.
// The plaintext token is returned by Create and goes nowhere else: not into
// the annotation, the log or the audit state hash.
type enrollmentAdmin struct {
	store  EnrollmentTokenStore
	logger *slog.Logger
}

func (a enrollmentAdmin) actor(ctx context.Context) (string, error) {
	p, ok := PrincipalFrom(ctx)
	// ActorSub: a write made with an API key is attributed to the key's owner.
	actor := p.ActorSub()
	if !ok || actor == "" {
		return "", dashboard.ErrEnrollmentNoActor
	}
	return actor, nil
}

func (a enrollmentAdmin) List(ctx context.Context) ([]dashboard.EnrollmentView, error) {
	toks, err := a.store.List(ctx)
	if err != nil {
		a.logger.Error("enrollment tokens: list failed", "error", err)
		return nil, err
	}
	out := make([]dashboard.EnrollmentView, 0, len(toks))
	for _, t := range toks {
		out = append(out, enrollmentView(t))
	}
	return out, nil
}

func (a enrollmentAdmin) Create(ctx context.Context, req dashboard.EnrollmentRequest) (dashboard.EnrollmentView, string, error) {
	actor, err := a.actor(ctx)
	if err != nil {
		return dashboard.EnrollmentView{}, "", err
	}
	plaintext, tok, _, err := a.store.Create(ctx, EnrollCreateOpts{
		Name: req.Name, WorkerID: req.WorkerID, WorkerIDPrefix: req.WorkerIDPrefix,
		MaxUses: req.MaxUses, TTL: req.ExpiresIn, Actor: actor,
	})
	if err != nil {
		return dashboard.EnrollmentView{}, "", a.mapError("create", err)
	}
	details := map[string]string{adminaudit.DetailOp: "create"}
	if tok.WorkerID != "" {
		details[adminaudit.DetailWorkerID] = tok.WorkerID
	}
	adminaudit.Annotate(ctx, enrollmentRef(tok.ID), details)
	return enrollmentView(tok), plaintext, nil
}

func (a enrollmentAdmin) Revoke(ctx context.Context, id string) error {
	actor, err := a.actor(ctx)
	if err != nil {
		return err
	}
	adminaudit.Annotate(ctx, enrollmentRef(id), map[string]string{adminaudit.DetailOp: "revoke"})
	if err := a.store.Revoke(ctx, id, actor); err != nil {
		return a.mapError("revoke", err)
	}
	return nil
}

// mapError turns a store error into a dashboard sentinel. An invalid-input
// error keeps its text (it describes the caller's own input); everything else
// is logged here and returned bare so the handler answers 500.
func (a enrollmentAdmin) mapError(op string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return fmt.Errorf("%w: %v", dashboard.ErrEnrollmentInvalid, err)
	case errors.Is(err, ErrEnrollNameTaken), errors.Is(err, ErrEnrollInUse):
		return dashboard.ErrEnrollmentConflict
	case errors.Is(err, ErrEnrollNotFound):
		return dashboard.ErrEnrollmentNotFound
	}
	a.logger.Error("enrollment tokens: "+op+" failed", "error", err)
	return err
}

func enrollmentView(t EnrollToken) dashboard.EnrollmentView {
	return dashboard.EnrollmentView{
		ID: t.ID, Name: t.Name, WorkerID: t.WorkerID, WorkerIDPrefix: t.WorkerIDPrefix,
		MaxUses: t.MaxUses, Uses: t.Uses, CreatedBy: t.CreatedBy,
		CreatedAt: rfc3339(t.CreatedAt),
		ExpiresAt: rfc3339(t.ExpiresAt),
		RevokedAt: rfc3339(t.RevokedAt),
	}
}

// enrollmentsStateHash is the keyed hash of every token's metadata: id, name,
// binding, use limit, expiry and whether it is revoked. Never a plaintext or a
// token hash, and not the use count, which changes without an admin acting.
func (s *Server) enrollmentsStateHash(ctx context.Context) (string, error) {
	toks, err := s.cfg.Enrollment.List(ctx)
	if err != nil {
		return "", err
	}
	sort.Slice(toks, func(i, j int) bool { return toks[i].ID < toks[j].ID })
	type meta struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Worker  string `json:"worker_id"`
		Prefix  string `json:"worker_id_prefix"`
		MaxUses int    `json:"max_uses"`
		Expires int64  `json:"expires_at"`
		Revoked bool   `json:"revoked"`
	}
	rows := make([]meta, 0, len(toks))
	for _, t := range toks {
		m := meta{ID: t.ID, Name: t.Name, Worker: t.WorkerID, Prefix: t.WorkerIDPrefix, MaxUses: t.MaxUses, Revoked: !t.RevokedAt.IsZero()}
		if !t.ExpiresAt.IsZero() {
			m.Expires = t.ExpiresAt.Unix()
		}
		rows = append(rows, m)
	}
	return s.stateHashJSON(auditTargetWorkerEnrollments, rows)
}

// wireWorkerEnrollments mounts the enrollment token admin routes and their
// audit state hasher when the control plane has an enrollment store (workerCA
// enabled with a state dir). Without one the routes answer 404.
func (s *Server) wireWorkerEnrollments(dash *dashboard.Server) {
	if s.cfg.Enrollment == nil {
		return
	}
	dash.SetWorkerEnrollments(enrollmentAdmin{store: s.cfg.Enrollment, logger: s.cfg.Logger})
	s.RegisterStateHasher(auditTargetWorkerEnrollments, s.enrollmentsStateHash)
}
