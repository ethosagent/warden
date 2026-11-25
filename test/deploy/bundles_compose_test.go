package deploy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

// The signed-bundles compose overlay (W-P2-SBND-07), checked statically: its
// structure, and that the config files it mounts load as the control plane and
// the workers load them.

type bundlesOverlay struct {
	Services map[string]struct {
		User       string   `yaml:"user"`
		Entrypoint []string `yaml:"entrypoint"`
		Command    []string `yaml:"command"`
		Volumes    []string `yaml:"volumes"`
		DependsOn  any      `yaml:"depends_on"`
	} `yaml:"services"`
	Volumes map[string]any `yaml:"volumes"`
}

func TestBundlesOverlayStructure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "compose", "docker-compose.bundles.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var o bundlesOverlay
	if err := yaml.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	cp := strings.Join(o.Services["control-plane"].Command, " ")
	for _, want := range []string{"--policy-store=versioned", "--bundles=offer", "--state-dir=/data"} {
		if !strings.Contains(cp, want) {
			t.Errorf("control-plane command lacks %s", want)
		}
	}
	pins := o.Services["cp-pins"]
	if pins.User != "" {
		t.Errorf("cp-pins runs as %q; it must run as the image's warden user", pins.User)
	}
	if strings.Contains(strings.Join(pins.Entrypoint, " "), "chmod 0777") {
		t.Error("cp-pins opens its volume to everyone")
	}
	if _, ok := o.Volumes["cp-pins"]; !ok {
		t.Error("the cp-pins volume is not declared")
	}
	for _, w := range []string{"worker-1", "worker-2"} {
		s := o.Services[w]
		joined := strings.Join(s.Volumes, " ")
		if !strings.Contains(joined, "config.worker.bundles.yaml:/etc/warden/config.yaml:ro") ||
			!strings.Contains(joined, "cp-pins:/etc/warden/pins:ro") {
			t.Errorf("%s volumes = %v, want the bundles worker config and the read-only pin volume", w, s.Volumes)
		}
		if len(s.Entrypoint) != 0 {
			t.Errorf("%s overrides its entrypoint (%v); the config is mounted instead of rewritten", w, s.Entrypoint)
		}
	}
}

// TestBundlesOverlayConfigsLoad: the control-plane file enables keys with a
// manual bundle key, and the worker file loads with the pin file the cp-pins
// service writes (a real exported JWKS stands in for it).
func TestBundlesOverlayConfigsLoad(t *testing.T) {
	root := repoRoot(t)
	kc, err := config.LoadKeys(filepath.Join(root, "configs", "config.control-plane.bundles.yaml"))
	if err != nil {
		t.Fatalf("control-plane bundles config: %v", err)
	}
	if !kc.Enabled || kc.Bundle.RotationInterval != 0 {
		t.Errorf("keys = %+v, want enabled with a manual bundle key", kc)
	}

	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.PublicJWK(sg.Public(), sg.Alg())
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(keys.JWKS{Keys: []keys.JWK{jwk}})
	pinFile := filepath.Join(t.TempDir(), "bundle-keys.json")
	if err := os.WriteFile(pinFile, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	wcfg, err := os.ReadFile(filepath.Join(root, "configs", "config.worker.bundles.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	const mounted = "/etc/warden/pins/bundle-keys.json"
	if !strings.Contains(string(wcfg), mounted) {
		t.Fatalf("the worker config does not pin %s", mounted)
	}
	local := filepath.Join(t.TempDir(), "worker.yaml")
	if err := os.WriteFile(local, []byte(strings.ReplaceAll(string(wcfg), mounted, pinFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	prov, err := config.NewLocalYAMLProvider(local)
	if err != nil {
		t.Fatalf("worker bundles config: %v", err)
	}
	pol, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.ControlPlane.BundleKeys; len(got) != 1 || got[0].Kid != jwk.Kid {
		t.Errorf("pinned keys = %v, want the exported key %s", got, jwk.Kid)
	}
}
