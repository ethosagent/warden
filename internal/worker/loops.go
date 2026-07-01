package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/proxy"
)

// ControlPlaneClient is the worker↔control-plane contract the background loops
// consume: it splits the transport (long-poll, policy fetch, settings, heartbeat)
// from the assembly. *config.RemoteProvider satisfies it. Defining it here, in the
// consumer package, keeps the long-poll + heartbeat loops testable with a fake and
// free of the concrete provider's construction concerns.
type ControlPlaneClient interface {
	PollLong(ctx context.Context, wait time.Duration) (changed bool, err error)
	GetPolicy() (config.Policy, error)
	Settings() *config.SettingsWire
	Heartbeat(ctx context.Context) error
}

// Compile-time proof that the concrete control-plane provider satisfies the seam
// the loops + applier consume, so the assembler can pass it as ControlPlaneClient.
var _ ControlPlaneClient = (*config.RemoteProvider)(nil)

// longPollControlPlane holds a long-poll against the control plane: the CP
// returns immediately when policy changes (hot-swapping the evaluator) or after
// `wait` with no change, and the worker re-polls at once. A failed poll is logged
// and the last-known-good policy is kept (capped backoff), so a worker rides out
// a control-plane outage. It returns when ctx is cancelled.
//
// onApply, when non-nil, runs after each applied policy change (same long-poll
// round-trip) so the worker can apply the distributed behavioral settings —
// notably rebuilding + atomically swapping the MCP gateway — in lock-step with
// the allow/deny reload. It is passed as a closure so the loop stays free of the
// proxy/scanner/store internals the rebuild needs.
func longPollControlPlane(ctx context.Context, cp ControlPlaneClient, ev proxy.PolicyEvaluator, wait time.Duration, logger *slog.Logger, onApply func()) {
	const maxBackoff = 15 * time.Second
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		changed, err := cp.PollLong(ctx, wait)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("control plane long-poll failed; keeping last-known policy", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second
		if changed {
			if remote, gErr := cp.GetPolicy(); gErr == nil {
				ev.Replace(remote)
				logger.Info("control plane policy reloaded")
				// Apply behavioral settings (e.g. MCP gateway rebuild) in the same
				// round-trip, so a single long-poll lands both policy and settings.
				if onApply != nil {
					onApply()
				}
			}
		}
		// 304 (no change): re-poll immediately.
	}
}

// heartbeatControlPlane pings the control plane every interval so it lists this
// worker as online even when idle (no traffic, long-poll held open).
func heartbeatControlPlane(ctx context.Context, cp ControlPlaneClient, interval time.Duration, logger *slog.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := cp.Heartbeat(ctx); err != nil && ctx.Err() == nil {
				logger.Debug("control plane heartbeat failed", "error", err)
			}
		}
	}
}

// pushMCPSnapshots forwards this worker's MCP inventory + observed schema to the
// control plane over the analytics ingest channel. It pushes whenever the
// snapshot changes (hash-gated) and unconditionally every few ticks as a safety
// net (so a restarted control plane re-learns the snapshot). It returns when ctx
// is cancelled. The snapshot is value-free — only paths, types, and sensitivity.
func pushMCPSnapshots(ctx context.Context, gw *gateway.Gateway, remote *analytics.HTTPRemoteStore, interval time.Duration, logger *slog.Logger) {
	const forceEveryN = 5
	var lastHash string
	ticks := 0
	push := func(force bool) {
		snap := analytics.MCPSnapshot{Inventory: gw.Inventory(), Schema: gw.SchemaSnapshot()}
		h := hashMCPSnapshot(snap)
		if h == lastHash && !force {
			return
		}
		if err := remote.SendMCP(snap); err != nil {
			if ctx.Err() == nil {
				logger.Debug("mcp snapshot push failed; will retry", "error", err)
			}
			return
		}
		lastHash = h
	}
	push(true) // initial full push
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ticks++
			push(ticks%forceEveryN == 0)
		}
	}
}
