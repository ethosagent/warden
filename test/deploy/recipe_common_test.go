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
	Privileged  bool                       `json:"privileged"`
	CapAdd      []string                   `json:"cap_add"`
	CapDrop     []string                   `json:"cap_drop"`
	SecurityOpt []string                   `json:"security_opt"`
	ExtraHosts  json.RawMessage            `json:"extra_hosts"`
	Pid         string                     `json:"pid"`
	Ipc         string                     `json:"ipc"`
	Devices     []json.RawMessage          `json:"devices"`
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

// recipeSpec names what differs between the identity recipes (Claude Code, Codex);
// the isolation assertions are the same for both.
type recipeSpec struct {
	name        string            // agent id, service name and compose file suffix
	keyEnv      string            // the vendor key variable (worker gets the real one)
	placeholder string            // what the agent holds instead
	keyPrefix   string            // a real key of this vendor starts with it; must not appear on the agent
	host        string            // the one allowed destination
	workerToken string            // variable holding the worker's wwt_ token
	wantEnv     map[string]string // exact agent environment values the recipe pins
}

func (r recipeSpec) composeFile() string { return "docker-compose." + r.name + ".yml" }
func (r recipeSpec) internalNet() string { return r.name + "-internal" }
func (r recipeSpec) realKey() string     { return r.keyEnv + "=" + realKeySentinel }

// renderRecipe runs `docker compose config` over the three files of a recipe,
// with the dev placeholders of deploy/compose/dex/.env.example and the extra
// env, and returns the raw output and its parsed form. config needs no daemon,
// only the compose plugin.
func renderRecipe(t *testing.T, r recipeSpec, extraFiles []string, extraEnv ...string) ([]byte, recipeCompose) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("BLOCKED: the recipe test renders the compose files with `docker compose config`; docker not on PATH")
	}
	root := repoRoot(t)
	dir := filepath.Join(root, "deploy", "compose")
	args := []string{"compose",
		"-f", "docker-compose.control-plane.yml",
		"-f", "docker-compose.identity.yml",
		"-f", r.composeFile()}
	for _, f := range extraFiles {
		args = append(args, "-f", f)
	}
	args = append(args, "config", "--format", "json")
	cmd := exec.Command("docker", args...)
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

// realKeySentinel stands in for the operator's real Anthropic key: it must reach
// the worker and no other service.
const realKeySentinel = "sentinel-real-key-7f3a9c41d2"

var digestPinned = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)

// checkRecipe pins the isolation shape of a recipe's compose file: the agent has
// one internal-only network and mounts nothing that holds identity material, and
// the pieces that make the worker require a Warden token are wired.
func checkRecipe(t *testing.T, r recipeSpec) {
	raw, c := renderRecipe(t, r, nil, r.realKey())
	agent, ok := c.Services[r.name]
	if !ok {
		t.Fatalf("service %s missing", r.name)
	}
	internal := r.internalNet()

	t.Run("agent is on one internal network", func(t *testing.T) {
		if len(agent.Networks) != 1 || !agent.onNetwork(internal) {
			t.Fatalf("agent networks = %v, want only %s", keysOf(agent.Networks), internal)
		}
		if agent.NetworkMode != "" {
			t.Fatalf("agent network_mode = %q, want none set", agent.NetworkMode)
		}
		if !c.Networks[internal].Internal {
			t.Fatalf("%s is not internal: true", internal)
		}
		if len(agent.Ports) != 0 {
			t.Fatalf("agent publishes ports: %v", agent.Ports)
		}
		if !agent.Init {
			t.Fatal("agent needs init: true")
		}
	})

	t.Run("only the sidecar shares the agent network", func(t *testing.T) {
		for name, s := range c.Services {
			if name != r.name && name != "warden-identity" && s.onNetwork(internal) {
				t.Errorf("service %s is on %s; only the agent and the sidecar may be", name, internal)
			}
		}
		for _, name := range []string{"dex", "ldap", "control-plane", "warden"} {
			if c.Services[name].onNetwork(internal) {
				t.Errorf("%s is reachable from the agent network", name)
			}
		}
		sc := c.Services["warden-identity"]
		if !sc.onNetwork(internal) || !sc.onNetwork("cp-net") {
			t.Errorf("warden-identity networks = %v, want %s and cp-net", keysOf(sc.Networks), internal)
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
		wantVols := map[string]bool{r.name + "-home": true, r.name + "-workspace": true}
		gotVols := map[string]bool{}
		var caBinds int
		for _, v := range agent.Volumes {
			switch v.Type {
			case "bind":
				if !strings.HasSuffix(v.Source, "/certs/proxy-ca.crt") || v.Target != "/etc/warden/certs/proxy-ca.crt" {
					t.Errorf("agent bind-mounts %q at %q: only the CA certificate is allowed", v.Source, v.Target)
				}
				caBinds++
			case "volume":
				gotVols[v.Source] = true
				if identityVols[v.Source] {
					t.Errorf("agent mounts the sidecar's volume %q", v.Source)
				}
				if !wantVols[v.Source] {
					t.Errorf("agent mounts volume %q, not in the allowlist", v.Source)
				}
			default:
				t.Errorf("agent mounts %s %q", v.Type, v.Source)
			}
		}
		if caBinds != 1 || len(gotVols) != len(wantVols) {
			t.Errorf("agent mounts %d CA binds and volumes %v, want 1 and exactly %v", caBinds, gotVols, wantVols)
		}
		// The sidecar gets the CA certificate, never the CA key.
		for _, v := range c.Services["warden-identity"].Volumes {
			if v.Type == "bind" && !strings.HasSuffix(v.Source, "/certs/proxy-ca.crt") {
				t.Errorf("warden-identity bind-mounts %q", v.Source)
			}
		}
	})

	t.Run("agent has no privilege or side doors", func(t *testing.T) {
		empty := func(name string, raw json.RawMessage) {
			if r := strings.TrimSpace(string(raw)); r != "" && r != "null" && r != "{}" && r != "[]" {
				t.Errorf("agent sets %s = %s", name, r)
			}
		}
		if agent.Privileged {
			t.Error("agent is privileged")
		}
		if len(agent.CapDrop) != 1 || agent.CapDrop[0] != "ALL" {
			t.Errorf("agent cap_drop = %v, want [ALL]", agent.CapDrop)
		}
		if !contains(agent.SecurityOpt, "no-new-privileges:true") {
			t.Errorf("agent security_opt = %v, want no-new-privileges:true", agent.SecurityOpt)
		}
		if len(agent.CapAdd) != 0 {
			t.Errorf("agent cap_add = %v", agent.CapAdd)
		}
		empty("extra_hosts", agent.ExtraHosts)
		if agent.Pid != "" || agent.Ipc != "" {
			t.Errorf("agent pid = %q ipc = %q, want both unset", agent.Pid, agent.Ipc)
		}
		if len(agent.Devices) != 0 {
			t.Errorf("agent devices = %v", agent.Devices)
		}
	})

	t.Run("agent environment holds placeholders only", func(t *testing.T) {
		if got := agent.env(r.keyEnv); got != r.placeholder {
			t.Errorf("agent %s = %q, want the placeholder", r.keyEnv, got)
		}
		if !strings.HasSuffix(agent.env("HTTPS_PROXY"), "@warden-identity:3128") {
			t.Errorf("agent HTTPS_PROXY does not point at the sidecar forwarder")
		}
		want := r.wantEnv
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
		if strings.Contains(env, r.keyPrefix) {
			t.Errorf("agent environment holds a %s value", r.keyPrefix)
		}
		if regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}`).MatchString(env) {
			t.Error("agent environment holds a JWT-shaped string")
		}
		for _, k := range []string{"WARDEN_IDENTITY_AGENT_KEY_FILE", "WARDEN_IDENTITY_TOKEN_ENDPOINT", r.workerToken, "WARDEN_WORKER_TOKEN"} {
			if _, ok := agent.Environment[k]; ok {
				t.Errorf("agent environment has %s", k)
			}
		}
		// The real key reaches the worker only, through the caller's environment.
		if got := c.Services["warden"].env(r.keyEnv); got != realKeySentinel {
			t.Errorf("worker %s = %q, want the caller's value", r.keyEnv, got)
		}
		for name, s := range c.Services {
			if name == "warden" {
				continue
			}
			sj, _ := json.Marshal(s)
			if bytes.Contains(sj, []byte(realKeySentinel)) {
				t.Errorf("service %s carries the real %s", name, r.keyEnv)
			}
		}
		if n := bytes.Count(raw, []byte(realKeySentinel)); n != 1 {
			t.Errorf("the real key appears %d times in the rendered config, want once (the worker)", n)
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
		if !contains(w.Command, "--agent-id="+r.name) {
			t.Errorf("worker command lacks --agent-id=%s: %v", r.name, w.Command)
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

	t.Run("sidecar listener is private and not anonymous", func(t *testing.T) {
		checkSidecarListener(t, r, c.Services["warden-identity"])
	})

	t.Run("subject-token override keeps the listener rules", func(t *testing.T) {
		_, o := renderRecipe(t, r, []string{"docker-compose." + r.name + ".subject-token.yml"}, r.realKey())
		sc := o.Services["warden-identity"]
		if !contains(sc.Command, "--subject-token-file=/data/subject-token") {
			t.Errorf("override sidecar command lacks --subject-token-file: %v", sc.Command)
		}
		checkSidecarListener(t, r, sc)
		if len(o.Services[r.name].Networks) != 1 {
			t.Error("override changed the agent's networks")
		}
	})

	t.Run("bootstrap is a one-shot with no network", func(t *testing.T) {
		b := c.Services["identity-bootstrap"]
		if got := b.env("AGENT_ID"); got != r.name {
			t.Errorf("identity-bootstrap AGENT_ID = %q, want %q", got, r.name)
		}
		if got := b.env("WORKER_TOKEN_ENV"); got != r.workerToken {
			t.Errorf("identity-bootstrap WORKER_TOKEN_ENV = %q, want %q", got, r.workerToken)
		}
		if tok := b.env(r.workerToken); tok == "" || tok != c.Services["warden"].env("WARDEN_WORKER_TOKEN") {
			t.Errorf("identity-bootstrap %s must be non-empty and equal the worker's WARDEN_WORKER_TOKEN", r.workerToken)
		}
		var bootMount bool
		for _, v := range b.Volumes {
			if v.Type == "bind" && v.Target == "/bootstrap.sh" && strings.HasSuffix(v.Source, "/deploy/compose/recipe-bootstrap.sh") {
				bootMount = true
			}
		}
		if !bootMount {
			t.Error("identity-bootstrap does not bind-mount recipe-bootstrap.sh at /bootstrap.sh")
		}
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
		recipe := []string{"control-plane", "cp-bootstrap", "identity-bootstrap", "warden", "warden-identity", r.name, "dex", "ldap"}
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
			filepath.Join("deploy", "compose", r.name, "Dockerfile"),
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

// checkRecipePolicy pins the served policy and the worker mapping: one allowed
// host, one agent in require mode, the placeholder swapped on the worker.
func checkRecipePolicy(t *testing.T, r recipeSpec) {
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

	cp := read("config.cp-served." + r.name + ".yaml")
	allow, _ := at(cp, "policy", "allowlist").([]any)
	if len(allow) != 1 {
		t.Fatalf("allowlist has %d entries, want exactly %s:443", len(allow), r.host)
	}
	e, _ := allow[0].(map[string]any)
	if e["domain"] != r.host || e["port"] != 443 {
		t.Errorf("allowlist entry = %v, want %s port 443", e, r.host)
	}
	if at(cp, "policy", "denylist") != nil {
		t.Error("recipe policy has a denylist; default-deny is the whole policy")
	}
	agents, _ := cp["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents has %d entries, want exactly one", len(agents))
	}
	a, _ := agents[0].(map[string]any)
	if a["id"] != r.name || a["identity"] != "require" {
		t.Errorf("agent = %v, want id %s identity require", a, r.name)
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

	w := read("config.recipe-" + r.name + "-worker.yaml")
	sec, _ := w["secrets"].([]any)
	if len(sec) != 1 {
		t.Fatalf("worker secrets has %d entries, want one", len(sec))
	}
	s, _ := sec[0].(map[string]any)
	if s["placeholder"] != r.placeholder || s["envVar"] != r.keyEnv {
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

// checkSidecarListener asserts the forwarder listens on its static address on
// the agent network (never 0.0.0.0, so cp-net cannot reach it) and still demands
// the client credential (carry-forward from the #118 review).
func checkSidecarListener(t *testing.T, r recipeSpec, sc recipeService) {
	t.Helper()
	var att struct {
		IPv4 string `json:"ipv4_address"`
	}
	if err := json.Unmarshal(sc.Networks[r.internalNet()], &att); err != nil || att.IPv4 == "" {
		t.Fatalf("warden-identity has no static address on %s: %v", r.internalNet(), err)
	}
	want := "--listen=" + att.IPv4 + ":3128"
	if !contains(sc.Command, want) {
		t.Errorf("warden-identity command lacks %s: %v", want, sc.Command)
	}
	for _, a := range sc.Command {
		if strings.HasPrefix(a, "--listen=0.0.0.0") || strings.HasPrefix(a, "--listen=:") || strings.HasPrefix(a, "--listen=[::]") {
			t.Errorf("warden-identity listens on every interface: %s", a)
		}
	}
	if !contains(sc.Command, "--client-credential-env=WARDEN_FORWARDER_CREDENTIAL") {
		t.Error("warden-identity lacks --client-credential-env")
	}
	if sc.env("WARDEN_FORWARDER_CREDENTIAL") == "" {
		t.Error("warden-identity has no forwarder credential value")
	}
	if !contains(sc.Command, "--agent-id="+r.name) || !contains(sc.Command, "--worker=warden:8080") {
		t.Errorf("warden-identity command = %v", sc.Command)
	}
}
