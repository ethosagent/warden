package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

// auditTargetWorkerTokens is the admin audit target of token create and
// revoke; its state hasher covers token metadata only.
const auditTargetWorkerTokens = "worker_tokens"

// workerTokenRef is the admin audit target_ref of a token.
func workerTokenRef(id string) string { return "token:" + id }

// workerTokenAdmin adapts the WorkerTokenStore to dashboard.WorkerTokenAdmin.
// The store has no HTTP or identity concerns; this adapter takes the actor
// from the console Principal in ctx, maps store errors to the dashboard's
// sentinels and annotates the admin audit row with the token id.
type workerTokenAdmin struct {
	store  *WorkerTokenStore
	now    func() time.Time
	logger *slog.Logger
}

func (a workerTokenAdmin) actor(ctx context.Context) (string, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok || p.Sub == "" {
		return "", dashboard.ErrWorkerTokenNoActor
	}
	return p.Sub, nil
}

func (a workerTokenAdmin) List(ctx context.Context) ([]dashboard.WorkerTokenView, error) {
	toks, err := a.store.List(ctx)
	if err != nil {
		a.logger.Error("worker tokens: list failed", "error", err)
		return nil, err
	}
	out := make([]dashboard.WorkerTokenView, 0, len(toks))
	for _, t := range toks {
		out = append(out, tokenView(t))
	}
	return out, nil
}

func (a workerTokenAdmin) Create(ctx context.Context, req dashboard.WorkerTokenRequest) (dashboard.WorkerTokenView, string, error) {
	actor, err := a.actor(ctx)
	if err != nil {
		return dashboard.WorkerTokenView{}, "", err
	}
	opts := CreateOpts{Name: req.Name, ProxyID: req.ProxyID, Actor: actor}
	if req.ExpiresIn > 0 {
		opts.ExpiresAt = a.now().Add(req.ExpiresIn)
	}
	plaintext, tok, err := a.store.Create(ctx, opts)
	if err != nil {
		return dashboard.WorkerTokenView{}, "", a.mapError("create", err)
	}
	adminaudit.Annotate(ctx, workerTokenRef(tok.ID), map[string]string{adminaudit.DetailOp: "create"})
	return tokenView(tok), plaintext, nil
}

func (a workerTokenAdmin) Revoke(ctx context.Context, id string) error {
	actor, err := a.actor(ctx)
	if err != nil {
		return err
	}
	adminaudit.Annotate(ctx, workerTokenRef(id), map[string]string{adminaudit.DetailOp: "revoke"})
	if err := a.store.Revoke(ctx, id, actor); err != nil {
		return a.mapError("revoke", err)
	}
	return nil
}

// mapError turns a store error into a dashboard sentinel. An invalid-input
// error keeps its text (it describes the caller's own input); everything else
// is logged here and returned bare so the handler answers 500.
func (a workerTokenAdmin) mapError(op string, err error) error {
	switch {
	case errors.Is(err, ErrInvalidInput):
		return fmt.Errorf("%w: %v", dashboard.ErrWorkerTokenInvalid, err)
	case errors.Is(err, ErrNameTaken), errors.Is(err, ErrTooManyActive), errors.Is(err, ErrTokenInUse):
		return dashboard.ErrWorkerTokenConflict
	case errors.Is(err, ErrWorkerTokenNotFound):
		return dashboard.ErrWorkerTokenNotFound
	}
	a.logger.Error("worker tokens: "+op+" failed", "error", err)
	return err
}

func tokenView(t Token) dashboard.WorkerTokenView {
	return dashboard.WorkerTokenView{
		ID: t.ID, Name: t.Name, ProxyID: t.ProxyID, CreatedBy: t.CreatedBy,
		CreatedAt:  rfc3339(t.CreatedAt),
		ExpiresAt:  rfc3339(t.ExpiresAt),
		LastUsedAt: rfc3339(t.LastUsedAt),
		RevokedAt:  rfc3339(t.RevokedAt),
	}
}

// rfc3339 formats t in UTC; the zero time is "" (omitted from the JSON).
func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// workerTokensStateHash is the keyed hash of every token's metadata: id, name,
// proxy id, expiry and whether it is revoked. Never a plaintext, a token hash
// or a last-used time (which changes without an admin acting).
func (s *Server) workerTokensStateHash(ctx context.Context) (string, error) {
	toks, err := s.cfg.WorkerTokens.List(ctx)
	if err != nil {
		return "", err
	}
	type meta struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		ProxyID string `json:"proxy_id"`
		Expires int64  `json:"expires_at"`
		Revoked bool   `json:"revoked"`
	}
	rows := make([]meta, 0, len(toks))
	for _, t := range toks {
		m := meta{ID: t.ID, Name: t.Name, ProxyID: t.ProxyID, Revoked: !t.RevokedAt.IsZero()}
		if !t.ExpiresAt.IsZero() {
			m.Expires = t.ExpiresAt.Unix()
		}
		rows = append(rows, m)
	}
	return s.stateHashJSON(auditTargetWorkerTokens, rows)
}

// wireWorkerTokens mounts the worker token admin routes and their audit state
// hasher when the control plane has a token store, and fills the fleet view's
// token fields. Without a store the routes answer 404 and the fleet view shows
// no token fields.
func (s *Server) wireWorkerTokens(dash *dashboard.Server) {
	if s.cfg.WorkerTokens == nil {
		return
	}
	dash.SetWorkerTokens(workerTokenAdmin{store: s.cfg.WorkerTokens, now: s.cfg.Clock.Now, logger: s.cfg.Logger})
	s.RegisterStateHasher(auditTargetWorkerTokens, s.workerTokensStateHash)
}

// fillWorkerAuth sets the fleet view's authentication fields from the registry
// rows (authKind, tokenName: Views) plus the token store's last-use time and
// the authenticator's shared-token request count.
func (s *Server) fillWorkerAuth(views []dashboard.WorkerView) {
	var lastUsed map[string]time.Time
	for i := range views {
		v := &views[i]
		v.LegacyRequests = s.workerAuth.LegacyRequests(v.ProxyID)
		if v.AuthKind != string(KindToken) || s.cfg.WorkerTokens == nil || v.TokenName == "" {
			continue
		}
		if lastUsed == nil {
			lastUsed = map[string]time.Time{}
			toks, err := s.cfg.WorkerTokens.List(context.Background())
			if err != nil {
				s.cfg.Logger.Warn("worker tokens: fleet last-used lookup failed", "error", err)
				continue
			}
			for _, t := range toks {
				lastUsed[t.Name] = t.LastUsedAt
			}
		}
		v.TokenLastUsed = rfc3339(lastUsed[v.TokenName])
	}
}
