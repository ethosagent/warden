package config

import "testing"

// The sample worker configs the compose recipes mount name the in-container
// WARDEN_WORKER_TOKEN for both token keys, so each worker holds its own
// per-worker token under one shared file, and carry a proxy id (W-P1-WTOK-11).
func TestSampleWorkerConfigsPerWorkerToken(t *testing.T) {
	for _, name := range []string{
		"config.example-worker.yaml",
		"config.recipe-worker.yaml",
		"config.openrouter-worker.yaml",
	} {
		t.Run(name, func(t *testing.T) {
			p, err := NewLocalYAMLProvider("../../configs/" + name)
			if err != nil {
				t.Fatal(err)
			}
			pol, err := p.GetPolicy()
			if err != nil {
				t.Fatal(err)
			}
			if got := pol.ControlPlane.TokenEnv; got != "WARDEN_WORKER_TOKEN" {
				t.Errorf("controlPlane.tokenEnv = %q, want WARDEN_WORKER_TOKEN", got)
			}
			if got := pol.Central.TokenEnv; got != "WARDEN_WORKER_TOKEN" {
				t.Errorf("central.tokenEnv = %q, want WARDEN_WORKER_TOKEN", got)
			}
			if pol.Central.ProxyID == "" {
				t.Error("central.proxyID is empty: the worker has no stable identity")
			}
		})
	}
}
