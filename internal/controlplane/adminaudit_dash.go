package controlplane

import (
	"context"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/dashboard"
)

// adminAuditDashSource adapts the admin audit store to the dashboard's
// read-only AdminAuditSource (W-P1-AAUD-03). It maps store rows to the
// dashboard's view (hashes hex-encoded, no signature) and logs store errors
// here, since the dashboard answers with a fixed message.
type adminAuditDashSource struct {
	store  *adminaudit.Store
	logger *slog.Logger
}

var _ dashboard.AdminAuditSource = adminAuditDashSource{}

func (a adminAuditDashSource) List(ctx context.Context, q dashboard.AdminAuditQuery) ([]dashboard.AdminAuditEntry, error) {
	items, err := a.store.List(ctx, adminaudit.Filter{Actor: q.Actor, Action: q.Action, Outcome: q.Outcome, Since: q.Since}, q.Limit, q.Cursor)
	if err != nil {
		a.logger.Error("admin audit list failed", "err", err)
		return nil, err
	}
	out := make([]dashboard.AdminAuditEntry, 0, len(items))
	for _, it := range items {
		out = append(out, dashboard.AdminAuditEntry{
			Seq:        it.Seq,
			TSUnixNano: it.TSUnixNano,
			Time:       time.Unix(0, it.TSUnixNano).UTC().Format(time.RFC3339),
			ActorID:    it.ActorID,
			ActorSub:   it.Actor.Sub,
			ActorEmail: it.Actor.Email,
			ActorRole:  it.ActorRole,
			AuthMethod: it.AuthMethod,
			Action:     it.Action,
			Target:     it.Target,
			TargetRef:  it.TargetRef,
			Details:    it.Details,
			Outcome:    it.Outcome,
			HTTPStatus: it.HTTPStatus,
			BeforeHash: it.BeforeHash,
			AfterHash:  it.AfterHash,
			ClientIP:   it.ClientIP,
			RequestID:  it.RequestID,
			KeyID:      it.KeyID,
			PrevHash:   hex.EncodeToString(it.PrevHash),
			EntryHash:  hex.EncodeToString(it.EntryHash),
		})
	}
	return out, nil
}

func (a adminAuditDashSource) Verify(ctx context.Context, req dashboard.AdminAuditVerifyRequest) (dashboard.AdminAuditVerifyResult, error) {
	opts := adminaudit.VerifyOptions{FromSeq: req.FromSeq, MaxRows: req.MaxRows}
	if req.Anchor != nil {
		opts.Anchor = &adminaudit.Anchor{Seq: req.Anchor.Seq, Hash: req.Anchor.Hash}
	}
	res, err := a.store.VerifyWithStoreKey(ctx, opts)
	if err != nil {
		a.logger.Error("admin audit verify failed", "err", err)
		return dashboard.AdminAuditVerifyResult{}, err
	}
	if !res.OK {
		a.logger.Warn("admin audit chain verification failed", "first_bad_seq", res.FirstBadSeq, "reason", res.Reason)
	}
	return dashboard.AdminAuditVerifyResult{
		OK:              res.OK,
		Checked:         res.Checked,
		FirstBadSeq:     res.FirstBadSeq,
		Reason:          res.Reason,
		HeadSeq:         res.HeadSeq,
		HeadHash:        hex.EncodeToString(res.HeadHash),
		LastVerifiedSeq: res.LastVerifiedSeq,
		Partial:         res.Partial,
	}, nil
}

func (a adminAuditDashSource) PubKeys(ctx context.Context) ([]dashboard.AdminAuditKey, error) {
	keys, err := a.store.PubKeys(ctx)
	if err != nil {
		a.logger.Error("admin audit key list failed", "err", err)
		return nil, err
	}
	out := make([]dashboard.AdminAuditKey, 0, len(keys))
	for _, k := range keys {
		out = append(out, dashboard.AdminAuditKey{KeyID: k.KeyID, PublicKey: k.PublicKey, FirstSeq: k.FirstSeq})
	}
	return out, nil
}
