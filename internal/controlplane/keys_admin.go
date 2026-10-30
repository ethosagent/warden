package controlplane

import (
	"context"
	"errors"
	"log/slog"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/keys"
)

// auditTargetKeys is the admin audit target of a console key rotation; its
// state hasher covers public key metadata only. The row's target_ref names the
// purpose ("keys:token").
const auditTargetKeys = "keys"

// keysAdmin adapts the key manager to dashboard.KeysSource. The manager has no
// HTTP or console concerns; this adapter takes the actor from the console
// Principal in ctx and maps manager errors to the dashboard's sentinels.
type keysAdmin struct {
	mgr    *keys.Manager
	logger *slog.Logger
}

// keyPurposes are the purposes the console lists, in display order.
var keyPurposes = []string{keys.PurposeToken, keys.PurposeBundle}

func (a keysAdmin) Keys(context.Context) dashboard.KeysResponse {
	set := a.mgr.KeySet()
	var resp dashboard.KeysResponse
	for _, p := range keyPurposes {
		for _, r := range set.Records(p) {
			resp.Keys = append(resp.Keys, keyView(r))
		}
		resp.Purposes = append(resp.Purposes, dashboard.KeyPurposeView{
			Purpose: p, Loaded: set.Loaded(p), LastError: a.mgr.LastError(p),
		})
	}
	return resp
}

func (a keysAdmin) Rotate(ctx context.Context, req dashboard.KeyRotateRequest) error {
	p, ok := PrincipalFrom(ctx)
	if !ok || p.Sub == "" {
		return dashboard.ErrKeysNoActor
	}
	method := adminaudit.AuthMethodOIDC
	if p.Kind == PrincipalBreakglass {
		method = adminaudit.AuthMethodBreakglass
	}
	op := "rotate"
	if req.Emergency {
		op = "emergency_rotate"
	}
	adminaudit.Annotate(ctx, "keys:"+req.Purpose, map[string]string{adminaudit.DetailOp: op})
	err := a.mgr.Rotate(ctx, req.Purpose, keys.RotateOpts{
		Emergency: req.Emergency, ConfirmPinned: req.ConfirmPinned,
		Actor: keys.Actor{Subject: p.Sub, AuthMethod: method},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keys.ErrInvalidPurpose), errors.Is(err, keys.ErrBundleNotPinned):
		return dashboard.ErrKeysInvalid
	case errors.Is(err, keys.ErrNoNextKey), errors.Is(err, keys.ErrNotPrepublished), errors.Is(err, keys.ErrConflict):
		return dashboard.ErrKeysConflict
	}
	a.logger.Error("keys: console rotation failed", "purpose", req.Purpose, "error", err)
	return err
}

func keyView(r keys.Record) dashboard.KeyView {
	return dashboard.KeyView{
		KID: r.KID, Purpose: r.Purpose, Alg: r.Alg, State: string(r.State), Backend: r.StoreBackend,
		CreatedAt: rfc3339(r.CreatedAt), PublishAt: rfc3339(r.PublishAt), ActivateAt: rfc3339(r.ActivateAt),
		RetireAt: rfc3339(r.RetireAt), DestroyedAt: rfc3339(r.DestroyedAt),
		PublicJWK: dashboard.KeyJWK{
			Kty: r.PublicJWK.Kty, Crv: r.PublicJWK.Crv, X: r.PublicJWK.X, Y: r.PublicJWK.Y,
			Kid: r.PublicJWK.Kid, Alg: r.PublicJWK.Alg, Use: r.PublicJWK.Use,
		},
	}
}

// keysStateHash is the keyed hash of every key's public metadata: kid, purpose,
// state and lifecycle times. No key material is in the document.
func (s *Server) keysStateHash(context.Context) (string, error) {
	var rows []dashboard.KeyView
	for _, p := range keyPurposes {
		for _, r := range s.cfg.Keys.KeySet().Records(p) {
			rows = append(rows, keyView(r))
		}
	}
	return s.stateHashJSON(auditTargetKeys, rows)
}

// wireKeys mounts the key admin routes and their audit state hasher. Without a
// key manager the dashboard answers 404.
func (s *Server) wireKeys(dash *dashboard.Server) {
	if s.cfg.Keys == nil {
		return
	}
	dash.SetKeysSource(keysAdmin{mgr: s.cfg.Keys, logger: s.cfg.Logger})
	s.RegisterStateHasher(auditTargetKeys, s.keysStateHash)
}
