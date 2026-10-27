package compose

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The control-plane compose recipe and the e2e stack that overlays it run on
// per-worker tokens (W-P1-WTOK-06): a one-shot cp-bootstrap service registers
// each worker's token on the shared state volume, the control plane runs strict
// with its own admin token, and no container holds the retired shared
// WARDEN_CP_TOKEN. These tests parse the files, so they run without Docker.

const composeDir = "../../../deploy/compose/"

type composeFile struct {
	Services map[string]composeService `yaml:"services"`
}

type composeService struct {
	Command     yaml.Node `yaml:"command"`
	Entrypoint  yaml.Node `yaml:"entrypoint"`
	Environment yaml.Node `yaml:"environment"`
	DependsOn   yaml.Node `yaml:"depends_on"`
}

func loadCompose(t *testing.T, name string) (composeFile, string) {
	t.Helper()
	raw, err := os.ReadFile(composeDir + name)
	if err != nil {
		t.Fatal(err)
	}
	var f composeFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	// The text with comments dropped: what a `docker compose config` would show.
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	stripComments(&doc)
	out, err := yaml.Marshal(&doc)
	if err != nil {
		t.Fatal(err)
	}
	return f, string(out)
}

func stripComments(n *yaml.Node) {
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, c := range n.Content {
		stripComments(c)
	}
}

// words is a command or entrypoint as one string: a list joined by spaces, or
// the scalar itself.
func words(n yaml.Node) string {
	var list []string
	if n.Decode(&list) == nil {
		return strings.Join(list, " ")
	}
	var s string
	_ = n.Decode(&s)
	return s
}

// env is the environment block as KEY -> value, from either list or map form.
func env(t *testing.T, n yaml.Node) map[string]string {
	t.Helper()
	out := map[string]string{}
	var list []string
	if n.Decode(&list) == nil {
		for _, kv := range list {
			k, v, _ := strings.Cut(kv, "=")
			out[k] = v
		}
		return out
	}
	if err := n.Decode(&out); err != nil && n.Kind != 0 {
		t.Fatalf("environment: %v", err)
	}
	return out
}

// conditions is depends_on as service -> condition (a bare list is
// service_started).
func conditions(t *testing.T, n yaml.Node) map[string]string {
	t.Helper()
	out := map[string]string{}
	var list []string
	if n.Decode(&list) == nil {
		for _, s := range list {
			out[s] = "service_started"
		}
		return out
	}
	var m map[string]struct {
		Condition string `yaml:"condition"`
	}
	if err := n.Decode(&m); err != nil && n.Kind != 0 {
		t.Fatalf("depends_on: %v", err)
	}
	for s, d := range m {
		out[s] = d.Condition
	}
	return out
}

var tokenVar = regexp.MustCompile(`^\$\{(WARDEN_WORKER_\d_TOKEN):-(wwt_[a-z2-7]{52})\}$`)

func TestControlPlaneRecipeUsesPerWorkerTokens(t *testing.T) {
	for _, tc := range []struct {
		file    string
		workers []string
	}{
		{"docker-compose.control-plane.yml", []string{"worker-1", "worker-2"}},
		{"docker-compose.e2e.yml", []string{"worker-1", "worker-2", "worker-3"}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			f, text := loadCompose(t, tc.file)
			if strings.Contains(text, "WARDEN_CP_TOKEN") {
				t.Errorf("%s still mentions WARDEN_CP_TOKEN", tc.file)
			}
			if strings.Contains(text, "--token-env") {
				t.Errorf("%s still passes --token-env", tc.file)
			}

			seen := map[string]string{}
			for _, w := range tc.workers {
				svc, ok := f.Services[w]
				if !ok {
					t.Fatalf("%s has no %s", tc.file, w)
				}
				if got := conditions(t, svc.DependsOn)["cp-bootstrap"]; got != "service_completed_successfully" {
					t.Errorf("%s: %s depends_on cp-bootstrap with %q, want service_completed_successfully", tc.file, w, got)
				}
				m := tokenVar.FindStringSubmatch(env(t, svc.Environment)["WARDEN_WORKER_TOKEN"])
				if m == nil {
					t.Errorf("%s: %s WARDEN_WORKER_TOKEN is not ${WARDEN_WORKER_N_TOKEN:-<wwt_ dev value>}", tc.file, w)
					continue
				}
				if prev, dup := seen[m[1]]; dup {
					t.Errorf("%s: %s and %s share %s", tc.file, prev, w, m[1])
				}
				seen[m[1]] = w
				if _, ok := env(t, svc.Environment)["WARDEN_PROXY_ID"]; !ok {
					t.Errorf("%s: %s has no WARDEN_PROXY_ID", tc.file, w)
				}
			}

			boot, ok := f.Services["cp-bootstrap"]
			if !ok {
				t.Fatalf("%s has no cp-bootstrap service", tc.file)
			}
			cmd := words(boot.Entrypoint) + " " + words(boot.Command)
			for _, w := range tc.workers {
				if !strings.Contains(cmd, "--proxy-id "+w) && !strings.Contains(cmd, "--proxy-id="+w) {
					t.Errorf("%s: cp-bootstrap does not register %s", tc.file, w)
				}
			}
			for v, w := range seen {
				if got := env(t, boot.Environment)[v]; got == "" {
					t.Errorf("%s: cp-bootstrap has no %s for %s", tc.file, v, w)
				}
				if !strings.Contains(cmd, "--from-env "+v) && !strings.Contains(cmd, "--from-env="+v) {
					t.Errorf("%s: cp-bootstrap does not import %s with --from-env", tc.file, v)
				}
			}
			if !strings.Contains(cmd, "token create") {
				t.Errorf("%s: cp-bootstrap does not run token create", tc.file)
			}
		})
	}

	f, _ := loadCompose(t, "docker-compose.control-plane.yml")
	cp := f.Services["control-plane"]
	cmd := words(cp.Command)
	for _, want := range []string{"--require-worker-tokens", "--admin-token-env=WARDEN_CP_ADMIN_TOKEN", "--ca-cert=", "--state-dir=/data"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("control-plane command lacks %s: %s", want, cmd)
		}
	}
	if got := conditions(t, cp.DependsOn)["cp-bootstrap"]; got != "service_completed_successfully" {
		t.Errorf("control-plane depends_on cp-bootstrap with %q, want service_completed_successfully", got)
	}
	if !strings.HasPrefix(env(t, cp.Environment)["WARDEN_CP_ADMIN_TOKEN"], "${WARDEN_CP_ADMIN_TOKEN:-") {
		t.Errorf("control-plane WARDEN_CP_ADMIN_TOKEN = %q, want a ${WARDEN_CP_ADMIN_TOKEN:-dev} default", env(t, cp.Environment)["WARDEN_CP_ADMIN_TOKEN"])
	}
}

// The shared worker configs name the in-container variable, so two workers can
// share one file and still hold different tokens.
func TestWorkerConfigsUseWorkerTokenEnv(t *testing.T) {
	for _, name := range []string{"config.worker.yaml", "config.e2e-worker.yaml", "config.e2e-worker-transparent.yaml"} {
		raw, err := os.ReadFile("../../../configs/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "WARDEN_CP_TOKEN") {
			t.Errorf("%s still names WARDEN_CP_TOKEN", name)
		}
		if n := strings.Count(string(raw), "tokenEnv: WARDEN_WORKER_TOKEN"); n != 2 {
			t.Errorf("%s: %d tokenEnv: WARDEN_WORKER_TOKEN lines, want 2 (controlPlane and central)", name, n)
		}
	}
}

// .env.example documents the four variables with the same fake dev values the
// compose defaults use, and nothing else.
func TestComposeEnvExampleMatchesDefaults(t *testing.T) {
	raw, err := os.ReadFile(composeDir + ".env.example")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			k, v, _ := strings.Cut(l, "=")
			got[k] = v
		}
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := "WARDEN_CP_ADMIN_TOKEN WARDEN_WORKER_1_TOKEN WARDEN_WORKER_2_TOKEN WARDEN_WORKER_3_TOKEN"
	if strings.Join(keys, " ") != want {
		t.Fatalf(".env.example keys = %v, want %s", keys, want)
	}
	e2e, _ := loadCompose(t, "docker-compose.e2e.yml")
	for i, w := range []string{"worker-1", "worker-2", "worker-3"} {
		m := tokenVar.FindStringSubmatch(env(t, e2e.Services[w].Environment)["WARDEN_WORKER_TOKEN"])
		if m == nil {
			t.Fatalf("%s token default is malformed", w)
		}
		if got[m[1]] != m[2] {
			t.Errorf(".env.example %s = %q, compose default %q (worker %d)", m[1], got[m[1]], m[2], i+1)
		}
	}
	if !regexp.MustCompile(`^dev-`).MatchString(got["WARDEN_CP_ADMIN_TOKEN"]) {
		t.Errorf("WARDEN_CP_ADMIN_TOKEN is not an obvious dev placeholder")
	}
}
