package worker

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/config"
)

// logBundleVerification states once at startup how signed policy bundles are
// treated: a CP-managed worker without pins takes policy unverified (WARN), and
// a local-only worker ignores any bundle settings (INFO). Pins have no runtime
// effect until the RemoteProvider reads them (W-P2-SBND-04).
func logBundleVerification(logger *slog.Logger, cp config.ControlPlaneConfig, managed, localOnly bool) {
	switch {
	case managed && !cp.BundleVerification():
		logger.Warn("bundle verification disabled (no controlPlane.bundleKeys)")
	case localOnly && (cp.BundleVerification() || cp.RequireSignedBundles):
		logger.Info("controlPlane bundle keys ignored: local-only mode enforces local policy")
	}
}
