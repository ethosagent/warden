package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/ethosagent/warden/internal/agentreg"
	"github.com/ethosagent/warden/internal/config"
)

// agentRegistryOverlayName is the overlay name, the key of its fingerprint and
// the reason of the publish-log row an ETag change caused by a registry write
// appends in versioned mode (W-P1-PVER-10).
const agentRegistryOverlayName = "agent_registry"

// agentLoadFailedMsg is the one log line a failed registry load writes per
// failure episode. It carries no entry values.
const agentLoadFailedMsg = "agentreg_load_failed"

// agentSyncer is the optional part of a Store that re-checks the database for a
// write by another process (the SQLite store's data_version pragma).
type agentSyncer interface {
	Sync(ctx context.Context) error
}

// agentLoadReporter logs a failed registry load once per failure episode.
type agentLoadReporter struct {
	logger  *slog.Logger
	failing atomic.Bool
}

func (r *agentLoadReporter) failed() {
	if r.failing.CompareAndSwap(false, true) {
		r.logger.Error(agentLoadFailedMsg + ": serving the last-known-good agent list")
	}
}

func (r *agentLoadReporter) ok() { r.failing.Store(false) }

// agentRegistryOverlay merges the registry into the served wire: id, status
// and key thumbprints per agent, sorted by id. Because it is an overlay the
// list is never part of a policy version, so a rollback can neither re-enable
// an agent nor restore a removed key. A read or validation error fails the
// load, so Refresh keeps the previous wire and ETag.
//
// Every apply (each Refresh: writes and the 3s reload tick) first asks the
// store to re-check its data_version, so an offline-CLI write is served within
// one policyReloadInterval and not one reload plus the store's own 2s poll.
//
// TODO(#96 signed bundles): when the registry becomes a bundle section it needs
// a marker row in the publisher (like token_jwks), because this overlay's
// changes move the policy ETag only through the served wire.
func agentRegistryOverlay(store agentreg.Store, rep *agentLoadReporter) wireOverlay {
	return wireOverlay{name: agentRegistryOverlayName, apply: func(ctx context.Context, w *policyWire) (string, error) {
		fp, err := withRegisteredAgents(ctx, store, w)
		if err != nil {
			rep.failed()
			return "", err
		}
		rep.ok()
		return fp, nil
	}}
}

// withRegisteredAgents sets w.RegisteredAgents from the store and returns the
// list's fingerprint: the first 16 hex of the sha256 of the list, empty when
// the registry is empty.
func withRegisteredAgents(ctx context.Context, store agentreg.Store, w *policyWire) (string, error) {
	if sy, ok := store.(agentSyncer); ok {
		// A failed sync already dropped the store's cache, so the List below
		// reads the database; its own error is the one that matters.
		_ = sy.Sync(ctx)
	}
	agents, err := store.List(ctx)
	if err != nil {
		return "", fmt.Errorf("agent registry: list: %w", err)
	}
	if len(agents) == 0 {
		w.RegisteredAgents = nil
		return "", nil
	}
	list := make([]config.RegisteredAgent, 0, len(agents))
	for _, a := range agents {
		list = append(list, config.RegisteredAgent{ID: a.ID, Status: string(a.Status), JKT: agentreg.Thumbprints(a)})
	}
	config.SortRegisteredAgents(list)
	if err := config.ValidateRegisteredAgents(list); err != nil {
		return "", err
	}
	b, err := json.Marshal(list)
	if err != nil {
		return "", fmt.Errorf("agent registry: encode: %w", err)
	}
	w.RegisteredAgents = list
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:8]), nil
}
