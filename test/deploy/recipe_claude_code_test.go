package deploy

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// recipeCompose is the slice of `docker compose config --format json` the recipe
// tests read.
type recipeCompose struct {
	Services map[string]recipeService `json:"services"`
	Networks map[string]struct {
		Internal bool `json:"internal"`
	} `json:"networks"`
}

type recipeService struct {
	Image       string                     `json:"image"`
	Build       map[string]any             `json:"build"`
	Init        bool                       `json:"init"`
	Command     []string                   `json:"command"`
	Environment map[string]*string         `json:"environment"`
	Networks    map[string]json.RawMessage `json:"networks"`
	NetworkMode string                     `json:"network_mode"`
	DependsOn   map[string]struct {
		Condition string `json:"condition"`
	} `json:"depends_on"`
	Ports   []map[string]any `json:"ports"`
	Volumes []struct {
		Type   string `json:"type"`
		Source string `json:"source"`
		Target string `json:"target"`
	} `json:"volumes"`
}

func (s recipeService) env(k string) string {
	if v := s.Environment[k]; v != nil {
		return *v
	}
	return ""
}

func (s recipeService) onNetwork(n string) bool {
	_, ok := s.Networks[n]
	return ok
}

// loadEnvFile parses KEY=VALUE lines of a dotenv file (comments and blanks skipped).
func loadEnvFile(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return out
}

// renderRecipe runs `docker compose config` over the three files of the Claude
// Code recipe, with the dev placeholders of deploy/compose/dex/.env.example and
// the extra env, and returns the raw output and its parsed form. config needs no
// daemon, only the compose plugin.
func renderRecipe(t *testing.T, extraEnv ...string) ([]byte, recipeCompose) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("BLOCKED: the recipe test renders the compose files with `docker compose config`; docker not on PATH")
	}
	root := repoRoot(t)
	dir := filepath.Join(root, "deploy", "compose")
	cmd := exec.Command("docker", "compose",
		"-f", "docker-compose.control-plane.yml",
		"-f", "docker-compose.identity.yml",
		"-f", "docker-compose.claude-code.yml",
		"config", "--format", "json")
	cmd.Dir = dir
	// An explicit environment, not the process's: only what the docker CLI needs
	// to run, so the render never depends on the caller's exported variables.
	for _, k := range []string{"PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG", "XDG_RUNTIME_DIR"} {
		if v := os.Getenv(k); v != "" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	cmd.Env = append(cmd.Env, loadEnvFile(t, filepath.Join(dir, "dex", ".env.example"))...)
	cmd.Env = append(cmd.Env, extraEnv...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, stderr.String())
	}
	var c recipeCompose
	if err := json.Unmarshal(stdout.Bytes(), &c); err != nil {
		t.Fatalf("parse compose config: %v", err)
	}
	return stdout.Bytes(), c
}

var digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// TestClaudeCodeRecipe pins the isolation shape of docker-compose.claude-code.yml:
// the agent has one internal-only network and mounts nothing that holds identity
// material, and the pieces that make the worker require a Warden token are wired.
func TestClaudeCodeRecipe(t *testing.T) {
	raw, c := renderRecipe(t, "ANTHROPIC_API_KEY=x")
	agent, ok := c.Services["claude-code"]
	if !ok {
		t.Fatal("service claude-code missing")
	}

	t.Run("agent is on one internal network", func(t *testing.T) {
		if len(agent.Networks) != 1 || !agent.onNetwork("claude-code-internal") {
			t.Fatalf("claude-code networks = %v, want only claude-code-internal", keysOf(agent.Networks))
		}
		if agent.NetworkMode != "" {
			t.Fatalf("claude-code network_mode = %q, want none set", agent.NetworkMode)
		}
		if !c.Networks["claude-code-internal"].Internal {
			t.Fatal("claude-code-internal is not internal: true")
		}
		if len(agent.Ports) != 0 {
			t.Fatalf("claude-code publishes ports: %v", agent.Ports)
		}
		if !agent.Init {
			t.Fatal("claude-code needs init: true")
		}
	})

	t.Run("only the sidecar shares the agent network", func(t *testing.T) {
		for name, s := range c.Services {
			if name != "claude-code" && name != "warden-identity" && s.onNetwork("claude-code-internal") {
				t.Errorf("service %s is on claude-code-internal; only the agent and the sidecar may be", name)
			}
		}
		for _, name := range []string{"dex", "ldap", "control-plane", "warden"} {
			if c.Services[name].onNetwork("claude-code-internal") {
				t.Errorf("%s is reachable from the agent network", name)
			}
		}
		sc := c.Services["warden-identity"]
		if !sc.onNetwork("claude-code-internal") || !sc.onNetwork("cp-net") {
			t.Errorf("warden-identity networks = %v, want claude-code-internal and cp-net", keysOf(sc.Networks))
		}
	})

	t.Run("agent mounts no identity volume, key or CA key", func(t *testing.T) {
		identityVols := map[string]bool{}
		for _, v := range c.Services["warden-identity"].Volumes {
			if v.Type == "volume" {
				identityVols[v.Source] = true
			}
		}
		if len(identityVols) == 0 {
			t.Fatal("warden-identity mounts no volume; the test would prove nothing")
		}
		for _, v := range agent.Volumes {
			if v.Type == "volume" && (identityVols[v.Source] || strings.Contains(v.Source, "identity")) {
				t.Errorf("claude-code mounts identity volume %q", v.Source)
			}
			switch v.Type {
			case "bind":
				if strings.Contains(v.Source, "proxy-ca.key") || strings.HasSuffix(v.Source, "/certs") || strings.Contains(v.Source, ".key") {
					t.Errorf("claude-code bind-mounts %q: it may mount the CA certificate only", v.Source)
				}
				if !strings.HasSuffix(v.Source, "/certs/proxy-ca.crt") {
					t.Errorf("claude-code bind-mounts unexpected host path %q", v.Source)
				}
			case "volume":
			default:
				t.Errorf("claude-code mounts %s %q", v.Type, v.Source)
			}
		}
		// The sidecar gets the CA certificate, never the CA key.
		for _, v := range c.Services["warden-identity"].Volumes {
			if v.Type == "bind" && !strings.HasSuffix(v.Source, "/certs/proxy-ca.crt") {
				t.Errorf("warden-identity bind-mounts %q", v.Source)
			}
		}
	})

	t.Run("agent environment holds placeholders only", func(t *testing.T) {
		if got := agent.env("ANTHROPIC_API_KEY"); got != "anthropic_secret_001" {
			t.Errorf("agent ANTHROPIC_API_KEY = %q, want the placeholder", got)
		}
		if !strings.HasSuffix(agent.env("HTTPS_PROXY"), "@warden-identity:3128") {
			t.Errorf("agent HTTPS_PROXY does not point at the sidecar forwarder")
		}
		want := map[string]string{
			"NO_PROXY":            "localhost,127.0.0.1,::1",
			"NODE_EXTRA_CA_CERTS": "/etc/warden/certs/proxy-ca.crt",
			"NODE_USE_ENV_PROXY":  "1",
			"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
			"DISABLE_AUTOUPDATER":                      "1",
		}
		for k, v := range want {
			if got := agent.env(k); got != v {
				t.Errorf("agent %s = %q, want %q", k, got, v)
			}
		}
		env := ""
		for k, v := range agent.Environment {
			if v != nil {
				env += k + "=" + *v + "\n"
			}
		}
		if strings.Contains(env, "sk-ant-") {
			t.Error("agent environment holds an sk-ant- value")
		}
		if regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}`).MatchString(env) {
			t.Error("agent environment holds a JWT-shaped string")
		}
		for _, k := range []string{"WARDEN_IDENTITY_AGENT_KEY_FILE", "WARDEN_IDENTITY_TOKEN_ENDPOINT", "WARDEN_CLAUDE_CODE_WORKER_TOKEN", "WARDEN_WORKER_TOKEN"} {
			if _, ok := agent.Environment[k]; ok {
				t.Errorf("agent environment has %s", k)
			}
		}
		// The real key reaches the worker only, through the caller's environment.
		if got := c.Services["warden"].env("ANTHROPIC_API_KEY"); got != "x" {
			t.Errorf("worker ANTHROPIC_API_KEY = %q, want the caller's value", got)
		}
		for name, s := range c.Services {
			if name != "warden" && strings.Contains(s.env("ANTHROPIC_API_KEY"), "x") && s.env("ANTHROPIC_API_KEY") == "x" {
				t.Errorf("service %s receives the real ANTHROPIC_API_KEY", name)
			}
		}
	})

	t.Run("no shared worker token", func(t *testing.T) {
		if bytes.Contains(raw, []byte("WARDEN_CP_TOKEN")) {
			t.Error("rendered config mentions WARDEN_CP_TOKEN")
		}
	})

	t.Run("control plane serves signed bundles and the token endpoint", func(t *testing.T) {
		cp := c.Services["control-plane"]
		for _, f := range []string{"--state-dir=/data", "--policy-store=versioned", "--bundles=require", "--require-worker-tokens"} {
			if !contains(cp.Command, f) {
				t.Errorf("control-plane command lacks %s: %v", f, cp.Command)
			}
		}
	})

	t.Run("worker is bound to the agent", func(t *testing.T) {
		w := c.Services["warden"]
		if !contains(w.Command, "--agent-id=claude-code") {
			t.Errorf("worker command lacks --agent-id=claude-code: %v", w.Command)
		}
		for _, n := range []string{"cp-net", "egress"} {
			if !w.onNetwork(n) {
				t.Errorf("worker is not on %s", n)
			}
		}
		var bundleRO bool
		for _, v := range w.Volumes {
			if v.Target == "/etc/warden/bundle" {
				bundleRO = v.Source != ""
			}
		}
		if !bundleRO {
			t.Error("worker does not mount the exported bundle keys")
		}
	})

	t.Run("sidecar listener is not anonymous", func(t *testing.T) {
		sc := c.Services["warden-identity"]
		listensWide := false
		for _, a := range sc.Command {
			if strings.HasPrefix(a, "--listen=0.0.0.0") {
				listensWide = true
			}
		}
		// A non-loopback listener on a network shared with other services must
		// demand a credential (carry-forward from the #118 review).
		if listensWide && !contains(sc.Command, "--client-credential-env=WARDEN_FORWARDER_CREDENTIAL") {
			t.Error("warden-identity listens on 0.0.0.0 without --client-credential-env")
		}
		if sc.env("WARDEN_FORWARDER_CREDENTIAL") == "" {
			t.Error("warden-identity has no forwarder credential value")
		}
		if !contains(sc.Command, "--agent-id=claude-code") || !contains(sc.Command, "--worker=warden:8080") {
			t.Errorf("warden-identity command = %v", sc.Command)
		}
	})

	t.Run("bootstrap is a one-shot with no network", func(t *testing.T) {
		b := c.Services["identity-bootstrap"]
		if b.NetworkMode != "none" {
			t.Errorf("identity-bootstrap network_mode = %q, want none", b.NetworkMode)
		}
		for _, n := range []string{"warden-identity", "warden"} {
			if got := c.Services[n].DependsOn["identity-bootstrap"].Condition; got != "service_completed_successfully" {
				t.Errorf("%s waits on identity-bootstrap with condition %q, want service_completed_successfully", n, got)
			}
		}
	})

	t.Run("third-party images are pinned by digest", func(t *testing.T) {
		recipe := []string{"control-plane", "cp-bootstrap", "identity-bootstrap", "warden", "warden-identity", "claude-code", "dex", "ldap"}
		for _, name := range recipe {
			s := c.Services[name]
			if s.Build != nil {
				continue // built from this repo; its base is checked below
			}
			if !digestPinned.MatchString(s.Image) {
				t.Errorf("service %s image %q is not pinned by digest", name, s.Image)
			}
		}
		for _, df := range []string{
			filepath.Join("deploy", "compose", "claude-code", "Dockerfile"),
			"Dockerfile",
		} {
			raw, err := os.ReadFile(filepath.Join(repoRoot(t), df))
			if err != nil {
				t.Fatal(err)
			}
			from := 0
			for _, l := range strings.Split(string(raw), "\n") {
				f := strings.Fields(l)
				if len(f) < 2 || !strings.EqualFold(f[0], "FROM") {
					continue
				}
				ref := f[1]
				if strings.HasPrefix(ref, "--platform=") {
					ref = f[2]
				}
				from++
				if !strings.Contains(ref, "@sha256:") {
					t.Errorf("%s: FROM %s is not pinned by digest", df, ref)
				}
			}
			if from == 0 {
				t.Errorf("%s has no FROM line", df)
			}
		}
	})
}

// TestClaudeCodeRecipePolicy pins the served policy and the worker mapping: one
// allowed host, one agent in require mode, the placeholder swapped on the worker.
func TestClaudeCodeRecipePolicy(t *testing.T) {
	root := repoRoot(t)
	read := func(name string) map[string]any {
		raw, err := os.ReadFile(filepath.Join(root, "configs", name))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := yaml.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		return m
	}

	cp := read("config.cp-served.claude-code.yaml")
	allow, _ := at(cp, "policy", "allowlist").([]any)
	if len(allow) != 1 {
		t.Fatalf("allowlist has %d entries, want exactly api.anthropic.com:443", len(allow))
	}
	e, _ := allow[0].(map[string]any)
	if e["domain"] != "api.anthropic.com" || e["port"] != 443 {
		t.Errorf("allowlist entry = %v, want api.anthropic.com port 443", e)
	}
	if at(cp, "policy", "denylist") != nil {
		t.Error("recipe policy has a denylist; default-deny is the whole policy")
	}
	agents, _ := cp["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents has %d entries, want exactly one", len(agents))
	}
	a, _ := agents[0].(map[string]any)
	if a["id"] != "claude-code" || a["identity"] != "require" {
		t.Errorf("agent = %v, want id claude-code identity require", a)
	}
	if at(cp, "keys", "enabled") != true || at(cp, "tokenService", "enabled") != true {
		t.Error("keys and tokenService must both be enabled")
	}
	if at(cp, "identity", "acceptDexTokens") != false {
		t.Error("identity.acceptDexTokens must be false so a raw IdP token is refused")
	}
	if iss, _ := at(cp, "tokenService", "issuer").(string); !strings.HasPrefix(iss, "https://") {
		t.Errorf("tokenService.issuer = %q, want an https URL", iss)
	}

	w := read("config.recipe-claude-code-worker.yaml")
	sec, _ := w["secrets"].([]any)
	if len(sec) != 1 {
		t.Fatalf("worker secrets has %d entries, want one", len(sec))
	}
	s, _ := sec[0].(map[string]any)
	if s["placeholder"] != "anthropic_secret_001" || s["envVar"] != "ANTHROPIC_API_KEY" {
		t.Errorf("worker secret = %v", s)
	}
	if at(w, "controlPlane", "bundleKeysFile") != "/etc/warden/bundle/bundle-jwks.json" || at(w, "controlPlane", "requireSignedBundles") != true {
		t.Error("worker must pin the exported bundle keys and require signed bundles")
	}
	if at(w, "controlPlane", "localOnly") == true {
		t.Error("worker must not be local-only")
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
