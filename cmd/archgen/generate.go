package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/ethosagent/warden/internal/archtest"
)

// generate loads the inputs and writes the merged golangci-lint config. The
// architecture loads first: baseline entries key on rule IDs, so a baseline
// naming an undeclared rule is an input error, not a silent no-suppression.
func generate(archPath, configPath, baselinePath, outPath string) error {
	archData, err := os.ReadFile(archPath)
	if err != nil {
		return err
	}
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	arch, err := archtest.LoadArchitecture(archData)
	if err != nil {
		return err
	}
	var baseline *archtest.Baseline
	baselineData, err := os.ReadFile(baselinePath)
	switch {
	case err == nil:
		if baseline, err = archtest.LoadBaseline(baselineData, arch); err != nil {
			return err
		}
	case errors.Is(err, fs.ErrNotExist):
		// No baseline yet: nothing is suppressed.
	default:
		return err
	}
	out, err := archtest.GenerateGolangCI(arch, configData, baseline)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	return nil
}
