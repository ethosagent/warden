package worker

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/config"
)

// logBundleVerification states once at startup how signed policy bundles are
// treated: a CP-managed worker without pins (only possible after the explicit
// controlPlane.requireSignedBundles: false opt-out, since pins are required by
// default) takes policy unverified (WARN), and a local-only worker ignores any
// bundle keys (INFO). With pins the
// RemoteProvider verifies every bundle and never applies the unsigned wire.
func logBundleVerification(logger *slog.Logger, cp config.ControlPlaneConfig, managed, localOnly bool) {
	switch {
	case managed && !cp.BundleVerification():
		logger.Warn("bundle verification disabled (no controlPlane.bundleKeys, controlPlane.requireSignedBundles: false): policy from the control plane is applied unsigned; this is a temporary opt-out, pin the control plane's bundle keys and remove requireSignedBundles: false",
			"requireSignedBundles", cp.RequireSignedBundles)
	case localOnly && cp.BundleVerification():
		logger.Info("controlPlane bundle keys ignored: local-only mode enforces local policy")
	}
}
