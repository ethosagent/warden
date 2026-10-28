package compose

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ethosagent/warden/internal/config"
)

// The Ethos sign-in overlay (#621): Ethos runs under `warden identity exec
// --challenge-in-tunnel`, the control plane serves challenge mode against Dex,
// and a two-hop relay gives Ethos's client the issuer's port 5556 and nothing
// else. These tests parse the files, so they run without Docker; `docker compose
// config -q` over the three files is the other half of the check (see the
// overlay's header).

const (
	ethosSSOFile   = "docker-compose.ethos-sso.yml"
	ethosSSOConfig = "../../../configs/config.ethos-sso.yaml"
	dexDevConfig   = "../../../deploy/compose/dex/config.dev.yaml"
)

// ssoService is the part of a compose service these tests read.
type ssoService struct {
	Image       string    `yaml:"image"`
	Entrypoint  yaml.Node `yaml:"entrypoint"`
	Command     yaml.Node `yaml:"command"`
	Environment yaml.Node `yaml:"environment"`
	DependsOn   yaml.Node `yaml:"depends_on"`
	Networks    yaml.Node `yaml:"networks"`
	NetworkMode string    `yaml:"network_mode"`
	Ports       []string  `yaml:"ports"`
	Volumes     []string  `yaml:"volumes"`
}

func loadSSO(t *testing.T) map[string]ssoService {
	t.Helper()
	raw, err := os.ReadFile(composeDir + ethosSSOFile)
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]ssoService `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Services
}

func TestEthosSSOOverlayRunsEthosUnderExec(t *testing.T) {
	svc := loadSSO(t)
	e, ok := svc["ethos"]
	if !ok {
		t.Fatal("the overlay has no ethos service")
	}
	cmd := words(e.Entrypoint) + " " + words(e.Command)
	for _, want := range []string{
		"/opt/warden/warden identity", "--issuer=http://localhost:5556/dex", "--client-id=warden-cli",
		"exec", "--worker=worker:8080", "--ca=/etc/warden/certs/proxy-ca.crt", "--challenge-in-tunnel",
		"--env=NODE_USE_ENV_PROXY", "-- docker-entrypoint.sh",
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("ethos does not run %q; got: %s", want, cmd)
		}
	}
	// Nothing secret is passed to Ethos by name.
	for _, w := range strings.Fields(cmd) {
		if strings.HasPrefix(w, "--env=") && (strings.Contains(w, "TOKEN") || strings.Contains(w, "SECRET") || strings.Contains(w, "KEY")) {
			t.Errorf("the overlay passes %s to Ethos", w)
		}
	}
	// The binary comes from the one-shot copy, read-only; the copy has no network.
	if !hasVolume(e.Volumes, "warden-bin:/opt/warden:ro") {
		t.Errorf("ethos does not mount the warden binary read-only: %v", e.Volumes)
	}
	if got := conditions(t, e.DependsOn)["warden-bin"]; got != "service_completed_successfully" {
		t.Errorf("ethos depends_on warden-bin with %q, want service_completed_successfully", got)
	}
	if wb := svc["warden-bin"]; wb.NetworkMode != "none" || !strings.Contains(words(wb.Entrypoint), "cp /usr/local/bin/warden /opt/warden/warden") {
		t.Errorf("warden-bin is not a no-network one-shot copy: %+v", wb)
	}
	// The overlay must not give Ethos a network or a published port: it stays on the
	// recipe's internal-only network.
	if e.Networks.Kind != 0 || len(e.Ports) != 0 || e.NetworkMode != "" {
		t.Errorf("the overlay changes Ethos's networking (networks %v, ports %v, mode %q)", e.Networks.Kind, e.Ports, e.NetworkMode)
	}
}

func hasVolume(vols []string, want string) bool {
	for _, v := range vols {
		if v == want {
			return true
		}
	}
	return false
}

func TestEthosSSORelayReachesOnlyTheIssuerPort(t *testing.T) {
	svc := loadSSO(t)
	in, out := svc["idp-relay-in"], svc["idp-relay-out"]

	// Inside hop: Ethos's own namespace, loopback 5556 only, into a socket.
	if in.NetworkMode != "service:ethos" || len(in.Ports) != 0 || in.Networks.Kind != 0 {
		t.Errorf("idp-relay-in must share ethos's namespace and nothing else: %+v", in)
	}
	inCmd := words(in.Command)
	if !strings.Contains(inCmd, "TCP-LISTEN:5556,bind=127.0.0.1") || !strings.Contains(inCmd, "UNIX-CONNECT:/relay/idp.sock") ||
		strings.Count(inCmd, "TCP-LISTEN") != 1 {
		t.Errorf("idp-relay-in does not listen on loopback 5556 into the socket: %s", inCmd)
	}

	// Outside hop: one target, dex:5556, on the control-plane network only.
	outCmd := words(out.Command)
	if !strings.Contains(outCmd, "UNIX-LISTEN:/relay/idp.sock") || !strings.Contains(outCmd, "TCP:dex:5556") || strings.Count(outCmd, "TCP:") != 1 {
		t.Errorf("idp-relay-out does not forward to exactly dex:5556: %s", outCmd)
	}
	var nets []string
	if err := out.Networks.Decode(&nets); err != nil || len(nets) != 1 || nets[0] != "cp-net" {
		t.Errorf("idp-relay-out networks = %v (%v), want [cp-net]", nets, err)
	}
	if len(out.Ports) != 0 {
		t.Errorf("idp-relay-out publishes ports: %v", out.Ports)
	}
	for name, s := range map[string]ssoService{"idp-relay-in": in, "idp-relay-out": out} {
		if !hasVolume(s.Volumes, "idp-relay:/relay") {
			t.Errorf("%s does not mount the shared socket volume: %v", name, s.Volumes)
		}
	}
}

func TestEthosSSOOverlayServesChallengeMode(t *testing.T) {
	svc := loadSSO(t)
	cp := svc["control-plane"]
	if !hasVolume(cp.Volumes, "../../configs/config.ethos-sso.yaml:/etc/warden/config.yaml:ro") {
		t.Errorf("the control plane does not serve configs/config.ethos-sso.yaml: %v", cp.Volumes)
	}
	// The feature is in this build only: every Warden service uses one overridable
	// image, never the published 0.3.0 default that predates challenge mode.
	for _, name := range []string{"control-plane", "worker", "cp-bootstrap", "warden-bin"} {
		if img := svc[name].Image; !strings.Contains(img, "WARDEN_SSO_IMAGE") {
			t.Errorf("%s image = %q, want ${WARDEN_SSO_IMAGE:-...}", name, img)
		}
	}

	// The served config loads, is in challenge mode, and names the same issuer and
	// client Dex's dev config defines.
	p, err := config.NewLocalYAMLProvider(ethosSSOConfig)
	if err != nil {
		t.Fatalf("configs/config.ethos-sso.yaml does not load: %v", err)
	}
	pol, err := p.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	id := pol.Identity
	if id.DefaultMode != config.IdentityModeChallenge || id.SignIn == nil || id.SignIn.ClientID != "warden-cli" {
		t.Errorf("identity = mode %q signIn %+v, want challenge with clientID warden-cli", id.DefaultMode, id.SignIn)
	}
	dex, err := os.ReadFile(dexDevConfig)
	if err != nil {
		t.Fatal(err)
	}
	var dexCfg struct {
		Issuer string `yaml:"issuer"`
	}
	if err := yaml.Unmarshal(dex, &dexCfg); err != nil {
		t.Fatal(err)
	}
	if id.Issuer != dexCfg.Issuer {
		t.Errorf("identity.issuer %q differs from Dex's issuer %q", id.Issuer, dexCfg.Issuer)
	}
	if !strings.Contains(string(dex), "id: warden-cli") {
		t.Error("Dex's dev config has no warden-cli client")
	}
	if len(pol.Allowlist) == 0 {
		t.Error("the SSO config lost the Ethos allowlist")
	}
}
