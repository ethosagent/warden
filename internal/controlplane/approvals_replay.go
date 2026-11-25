package controlplane

// approvals_replay.go wires W-P2-APPR-03: the runner that replays recent fleet
// events against a draft's base version and the draft, and the Replayer that
// queues it on submit and on every new revision.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/approvals"
	"github.com/ethosagent/warden/internal/approvals/adapters/sqlstore"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/policyeval"
)

// replayCheckEvery is how many events the scan callback handles between
// context checks (a scan already checks between pages).
const replayCheckEvery = 1024

// policyReplayRunner implements approvals.ReplayRunner for the policy target:
// the base version's doc and the draft's doc are decoded to config.Policy and
// compared by policyeval.Comparer over the fleet store's events.
type policyReplayRunner struct {
	versions PolicyVersionStore
	scan     func(ctx context.Context, since time.Time, limit int, fn func(analytics.Event) error) error
}

var _ approvals.ReplayRunner = policyReplayRunner{}

// docPolicy is the replayed form of a policy doc: the allow and deny lists. The
// block list is a serve-time overlay and the settings do not decide
// destinations, so neither is replayed.
func docPolicy(allow []config.AllowlistEntry, deny []config.DenylistEntry) config.Policy {
	return config.Policy{Allowlist: allow, Denylist: deny}
}

// Run implements approvals.ReplayRunner. Its errors carry a value-free code; the
// stored result never holds a URL, path, query, header or group list.
func (r policyReplayRunner) Run(ctx context.Context, req approvals.ReplayRequest) (approvals.ReplayOutcome, error) {
	d := req.Draft
	if d.Target != approvals.TargetPolicy {
		return approvals.ReplayOutcome{}, &approvals.ReplayError{Code: "unsupported_target", Err: fmt.Errorf("target %s", d.Target)}
	}
	var base config.Policy
	if d.BaseVersion > 0 {
		v, err := r.versions.Get(ctx, d.BaseVersion)
		if err != nil {
			return approvals.ReplayOutcome{}, &approvals.ReplayError{Code: "base_unavailable", Err: err}
		}
		base = docPolicy(v.Doc.Allowlist, v.Doc.Denylist)
	}
	doc, err := d.PolicyDoc()
	if err != nil {
		return approvals.ReplayOutcome{}, &approvals.ReplayError{Code: "draft_undecodable", Err: err}
	}
	cmp := policyeval.NewComparer(base, docPolicy(doc.Allowlist, doc.Denylist))
	scanned := 0
	err = r.scan(ctx, req.Since, req.Limit, func(e analytics.Event) error {
		if scanned%replayCheckEvery == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		scanned++
		cmp.Add(e)
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return approvals.ReplayOutcome{}, ctx.Err()
		}
		return approvals.ReplayOutcome{}, &approvals.ReplayError{Code: "scan_failed", Err: err}
	}
	res := cmp.Result()
	raw, err := json.Marshal(res)
	if err != nil {
		return approvals.ReplayOutcome{}, fmt.Errorf("controlplane: encode replay result: %w", err)
	}
	return approvals.ReplayOutcome{
		Result: raw, Events: res.Events, Scanned: scanned, Truncated: scanned >= req.Limit,
		ToAllowGroups: len(res.ChangedToAllow), ToDenyGroups: len(res.ChangedToDeny),
	}, nil
}

// initReplays builds the Replayer over the draft_replays table and the fleet
// store and hands it to svc. Replays left pending or running by an earlier
// process are failed as interrupted first.
func (s *Server) initReplays(svc *approvals.Service) error {
	if s.central == nil {
		return errors.New("control-plane: approvals replay needs the fleet analytics store")
	}
	// Validated config always sets these; a Server built without Run (a test)
	// falls back to the defaults.
	ac := s.cfg.Console.Approvals
	if ac.ReplayWindow <= 0 {
		ac.ReplayWindow = config.DefaultApprovalsReplayWindow
	}
	if ac.ReplayMaxEvents <= 0 {
		ac.ReplayMaxEvents = config.DefaultApprovalsReplayEvents
	}
	if ac.ReplayTimeout <= 0 {
		ac.ReplayTimeout = config.DefaultApprovalsReplayTimeout
	}
	runner := policyReplayRunner{
		versions: s.versions,
		scan: func(ctx context.Context, since time.Time, limit int, fn func(analytics.Event) error) error {
			return analytics.ScanReplay(ctx, s.central, since, limit, fn)
		},
	}
	rp, err := approvals.NewReplayer(approvals.ReplayerConfig{
		Store: sqlstore.NewReplayStore(s.cfg.State.SQL()), Runner: runner, Now: s.cfg.Clock.Now,
		CurrentRevision: func(ctx context.Context, id string) (int, error) {
			d, err := svc.Store().Get(ctx, id)
			return d.Revision, err
		},
		MaxWaiting: ac.MaxOpenDrafts,
		Window:     ac.ReplayWindow, MaxEvents: ac.ReplayMaxEvents, Timeout: ac.ReplayTimeout, Logger: s.cfg.Logger,
	})
	if err != nil {
		return fmt.Errorf("control-plane: approvals replayer: %w", err)
	}
	n, err := rp.Recover(context.WithoutCancel(context.Background()))
	if err != nil {
		return fmt.Errorf("control-plane: approvals replay recovery: %w", err)
	}
	if n > 0 {
		s.cfg.Logger.Warn("control plane: failed change-draft replays interrupted by a restart", "count", n)
	}
	svc.SetReplayer(rp)
	return nil
}
