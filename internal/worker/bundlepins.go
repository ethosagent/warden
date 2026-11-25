package worker

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/config"
)

// logBundleVerification states once at startup how signed policy bundles are
// treated: a CP-managed worker without pins takes policy unverified (WARN), and
// a local-only worker ignores any bundle settings (INFO). With pins the
// RemoteProvider verifies every bundle and never applies the unsigned wire.
func logBundleVerification(logger *slog.Logger, cp config.ControlPlaneConfig, managed, localOnly bool) {
	switch {
	case managed && !cp.BundleVerification():
		logger.Warn("bundle verification disabled (no controlPlane.bundleKeys)")
	case localOnly && (cp.BundleVerification() || cp.RequireSignedBundles):
		logger.Info("controlPlane bundle keys ignored: local-only mode enforces local policy")
	}
}
