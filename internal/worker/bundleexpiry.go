package worker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

// bundleExpiryInterval is how often the applied bundle's expiry is checked.
const bundleExpiryInterval = 10 * time.Second

// serialEvaluator serializes every policy apply on the worker. The embedded
// evaluator is the gated one (agent gate, then swap); raw is the evaluator
// itself, for deny-all, which must not run the gate with a policy that lacks
// the registry list (that would re-enable a disabled agent). The long-poll loop
// applies through Replace; the expiry loop through denyIfExpired and
// restoreIfValid, which re-check the bundle state and read the newest policy
// snapshot under the same lock, so an older snapshot is never applied over a
// newer one.
type serialEvaluator struct {
	proxy.PolicyEvaluator
	raw proxy.PolicyEvaluator
	mu  sync.Mutex
}

func (s *serialEvaluator) Replace(p config.Policy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PolicyEvaluator.Replace(p)
}

// locked runs fn under the apply lock. Anything that must not interleave with a
// policy apply (installing the Warden token snapshot that goes with it) runs
// here.
func (s *serialEvaluator) locked(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// denyIfExpired swaps in deny-all when the applied bundle is expired now.
func (s *serialEvaluator) denyIfExpired(cp ControlPlaneClient) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !cp.BundleStatus().Expired {
		return false
	}
	s.raw.Replace(config.Policy{})
	return true
}

// restoreIfValid re-applies the newest policy when the bundle is valid again.
func (s *serialEvaluator) restoreIfValid(cp ControlPlaneClient) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cp.BundleStatus().Expired {
		return false
	}
	pol, err := cp.GetPolicy()
	if err != nil {
		return false
	}
	s.PolicyEvaluator.Replace(pol)
	return true
}

// enforceBundleExpiry applies controlPlane.bundleExpiry to the applied signed
// bundle. A bundle is only checked for expiry when it arrives, so a worker whose
// control plane went away keeps the bundle it has. While the bundle is within
// expiresAt plus the skew nothing happens. Past it, mode keep logs one WARN and
// keeps enforcing; mode deny swaps in an empty policy (deny all) until a bundle
// that is valid again arrives, and then puts that policy back.
func enforceBundleExpiry(ctx context.Context, clk clock.Clock, cp ControlPlaneClient, ev *serialEvaluator, logger *slog.Logger) {
	t := clk.NewTimer(bundleExpiryInterval)
	defer t.Stop()
	var denied, warned bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C():
			t.Reset(bundleExpiryInterval)
		}
		st := cp.BundleStatus()
		if st.Applied && st.Expired {
			if !warned {
				warned = true
				logger.Warn("applied bundle has expired and no valid replacement arrived",
					"seq", st.Seq, "expiresAt", st.ExpiresAt, "mode", string(st.Expiry))
			}
			if st.Expiry == config.BundleExpiryDeny && !denied && ev.denyIfExpired(cp) {
				denied = true
				logger.Warn("bundle expired: denying all traffic until a valid bundle arrives", "seq", st.Seq)
			}
			continue
		}
		warned = false
		if denied && ev.restoreIfValid(cp) {
			denied = false
			logger.Info("bundle valid again; enforcement restored", "seq", cp.BundleStatus().Seq)
		}
	}
}
