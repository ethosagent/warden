package worker

import (
	"context"
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/clock"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/proxy"
)

// bundleExpiryInterval is how often the applied bundle's expiry is checked.
const bundleExpiryInterval = 10 * time.Second

// enforceBundleExpiry applies controlPlane.bundleExpiry to the applied signed
// bundle. A bundle is only checked for expiry when it arrives, so a worker whose
// control plane went away keeps the bundle it has. While the bundle is within
// expiresAt plus the skew nothing happens. Past it, mode keep logs one WARN and
// keeps enforcing; mode deny swaps in an empty policy (deny all) until a bundle
// that is valid again arrives, and then puts that policy back.
//
// raw is the evaluator itself: deny-all must bypass the agent gate, whose
// apply of a policy without the registry list would re-enable a disabled agent.
// restore goes through the gate like any applied policy.
func enforceBundleExpiry(ctx context.Context, clk clock.Clock, cp ControlPlaneClient, raw, restore proxy.PolicyEvaluator, logger *slog.Logger) {
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
			if st.Expiry != config.BundleExpiryDeny || denied {
				continue
			}
			raw.Replace(config.Policy{})
			denied = true
			logger.Warn("bundle expired: denying all traffic until a valid bundle arrives", "seq", st.Seq)
			// A valid bundle may have been applied while this ran; its own
			// swap could then have come first. Look again.
			if cp.BundleStatus().Expired {
				continue
			}
		}
		warned = st.Applied && st.Expired
		if denied && !cp.BundleStatus().Expired {
			if pol, err := cp.GetPolicy(); err == nil {
				restore.Replace(pol)
				denied = false
				logger.Info("bundle valid again; enforcement restored", "seq", cp.BundleStatus().Seq)
			}
		}
	}
}
