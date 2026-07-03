package controlplane

// detection_write.go adds the CONTROL-PLANE-ONLY detection editor: persist an
// edited `detection:` block to the served config file (preserving every other block
// byte-for-byte) and hot-reload the live temporal-detection engine over the SAME
// alert store — so tuning thresholds or toggling a detector takes effect without a
// restart. It mirrors WriteIntegrations / reloadIntegrations. Detection config
// carries no secrets and no bodies (only enums/numbers/durations), so nothing here
// surfaces or redacts sensitive values.

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/alertpipeline"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/detect"
)

// currentDetectionConfig returns the CP's live typed detection config under the
// read lock (updated by WriteDetection). It is the config half of the dashboard's
// detection source; the live status half (active detectors + evictions) comes from
// the pipeline.
func (s *Server) currentDetectionConfig() config.DetectionConfig {
	s.detectionMu.RLock()
	defer s.detectionMu.RUnlock()
	return s.detectionConfig
}

// setDetectionConfig replaces the live typed detection config under the write lock.
func (s *Server) setDetectionConfig(dc config.DetectionConfig) {
	s.detectionMu.Lock()
	s.detectionConfig = dc
	s.detectionMu.Unlock()
}

// WriteDetection validates and atomically persists an edited `detection:` block to
// the served config file, then hot-reloads the live detection engine — the
// detection analogue of WriteIntegrations. Like WritePolicy/WriteSettings it
// round-trips the file through a top-level YAML map so every block it does not own
// (policy, logging, mcp, judge, integrations, secrets, audit, …) survives
// byte-for-byte; it replaces ONLY the `detection` key.
//
// Persistence goes through atomicWriteConfig, which validates the candidate with
// the full loader (config.NewLocalYAMLProvider → validateDetection) before it can
// replace the good file — so an out-of-range threshold / bad window is rejected
// there and we do not reimplement that validation. After a successful write it
// rebuilds the engine from the new config via the shared DetectConfigFrom converter
// (the single home for that mapping) and updates the config the dashboard reads.
func (s *Server) WriteDetection(dc config.DetectionConfig) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	root := map[string]yaml.Node{}
	if cur, err := os.ReadFile(s.cfg.PolicyPath); err == nil {
		// Best-effort: a malformed current file just means we rebuild the block we
		// own; the loader validation in atomicWriteConfig still guards the result.
		_ = yaml.Unmarshal(cur, &root)
	}
	node, err := config.EncodeDetectionNode(dc)
	if err != nil {
		return fmt.Errorf("controlplane: encode detection block: %w", err)
	}
	root["detection"] = node

	if err := s.atomicWriteConfig(root); err != nil {
		return err
	}
	detectCfg, enabled, _ := alertpipeline.DetectConfigFrom(dc)
	if err := s.reloadDetection(detectCfg, enabled); err != nil {
		return err
	}
	s.setDetectionConfig(dc)
	s.cfg.Logger.Info("control plane detection updated via dashboard", "enabled", dc.Enabled)
	return nil
}

// reloadDetection hot-swaps the live detection engine via the embedded pipeline
// (which rebuilds detect.NewEngine and swaps it under the SAME lock guarding the
// manager pointer, so a concurrent tick/Observe never sees a half-swapped engine).
// A nil pipeline means detection is not hosted on this control plane.
func (s *Server) reloadDetection(cfg detect.Config, enabled bool) error {
	if s.pipeline == nil {
		return errors.New("controlplane: detection runtime is not available on this control plane")
	}
	return s.pipeline.ReloadDetection(cfg, enabled)
}
