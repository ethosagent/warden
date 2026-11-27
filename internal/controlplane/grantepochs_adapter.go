package controlplane

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
	"github.com/ethosagent/warden/internal/oauthbroker"
)

// ErrGrantEpochsUnavailable is returned by the epoch adapter when this control
// plane serves no signed bundles: nothing could carry the epoch to a worker, so
// a revoke must not report it as delivered.
var ErrGrantEpochsUnavailable = errors.New("controlplane: user grant epochs need signed bundles")

// ErrPerUserSecretsOff is returned by the epoch adapter when per-user secrets
// are off: EpochStore.Bump published nothing (epoch 0), so no worker was told.
// It wraps oauthbroker.ErrEpochSkipped, which the revoke reports as skipped.
// Accepted limitation: such a revoke records no epoch, so a worker partitioned
// before the "off" bundle that rejoins after per-user secrets are on again can
// keep a cached per-user token for up to workerCacheTTL (at most 15m).
var ErrPerUserSecretsOff = fmt.Errorf("controlplane: per-user secrets are off, no epoch was published: %w", oauthbroker.ErrEpochSkipped)

// grantEpochBumper implements oauthbroker.EpochBumper over EpochStore.Bump
// (W-P3-PORT-05). oauthbroker never imports controlplane; the control plane
// hands this adapter to the broker when the consent block is set.
type grantEpochBumper struct {
	srv *Server
}

var _ oauthbroker.EpochBumper = grantEpochBumper{}

// GrantEpochBumper returns the adapter RevokeUserGrant bumps a user's epoch
// through. It never returns nil; with no signed bundles every Bump fails with
// ErrGrantEpochsUnavailable instead of silently doing nothing.
func (s *Server) GrantEpochBumper() oauthbroker.EpochBumper {
	return grantEpochBumper{srv: s}
}

// Bump bumps userKey's epoch and logs grant_epoch_bumped with the first 8
// characters of the key, never the sub. An error is returned as is: wrapping
// ErrEpochNotPublished means the epoch is recorded but workers are not told yet.
func (b grantEpochBumper) Bump(ctx context.Context, userKey string) error {
	store := b.srv.GrantEpochs()
	if store == nil {
		return ErrGrantEpochsUnavailable
	}
	epoch, err := store.Bump(ctx, userKey)
	if err != nil {
		return err
	}
	if epoch == 0 {
		return ErrPerUserSecretsOff
	}
	b.srv.cfg.Logger.Info("grant_epoch_bumped", "key_prefix", keyPrefix(userKey), "epoch", epoch)
	return nil
}

// keyPrefix is the first 8 characters of a user key, the only part of it that
// is logged.
func keyPrefix(userKey string) string {
	if len(userKey) > 8 {
		return userKey[:8]
	}
	return userKey
}

// grantWorkerCaps implements oauthbroker.WorkerCapsReader over the heartbeat
// caps the worker registry stores (W-P1-BLOCK-10).
type grantWorkerCaps struct {
	registry *WorkerRegistry
	agents   func() map[string]bool
}

var _ oauthbroker.WorkerCapsReader = grantWorkerCaps{}

// GrantWorkerCaps returns the reader RevokeUserGrant lists workers_without_cap
// from: the online workers lacking the capability, sorted, at most 50.
func (s *Server) GrantWorkerCaps() oauthbroker.WorkerCapsReader {
	return grantWorkerCaps{registry: s.registry, agents: s.policy.servedPerUserAgents}
}

// WorkersWithoutCap lists the online workers that do not advertise cap and
// serve an agent with a per-user mapping in the served bundle: the same filter
// as FlagNoUserSecrets, applied before the registry's bound. Nothing is listed
// while per-user secrets are off (no worker caches a token then).
func (w grantWorkerCaps) WorkersWithoutCap(cap string) []string {
	if w.registry == nil {
		return nil
	}
	agents := w.agents()
	if len(agents) == 0 {
		return nil
	}
	ids, _ := w.registry.WorkersLackingCap(cap, func(agentID string) bool { return agents[agentID] })
	return ids
}

// servedPerUserAgents returns the agents the served bundle carries a per-user
// mapping for, nil while the feature is off. It reads a snapshot the publisher
// updates under refreshMu, so it never waits behind a refresh or a Bump.
func (ps *policyServer) servedPerUserAgents() map[string]bool {
	if ps.bundles == nil {
		return nil
	}
	if m := ps.bundles.puAgents.Load(); m != nil {
		return *m
	}
	return nil
}

// FlagNoUserSecrets sets NoUserSecrets on every online view whose caps lack
// usersecrets/v1 while the served bundle maps per-user secrets to its agent.
// Such a worker neither fills the placeholder nor drops a cached token on a
// revoke. A worker that reports no agent id is never flagged, as in the rollout
// guard (a mapping reaches a worker only through its agent id). The flag holds
// no sub or user key.
func FlagNoUserSecrets(views []dashboard.WorkerView, agents map[string]bool) {
	for i := range views {
		v := &views[i]
		v.NoUserSecrets = v.Online && agents[v.AgentID] && !slices.Contains(v.Caps, config.CapUserSecretsV1)
	}
}
