package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release must not publish a GitHub Release unless the L2 suite passed on
// the image it just pushed (#369). These tests hold release.yml to that wiring,
// so dropping the `needs` edge or the digest hand-off cannot go unnoticed.

type releaseJob struct {
	Needs   []string          `yaml:"needs"`
	Uses    string            `yaml:"uses"`
	With    map[string]string `yaml:"with"`
	Secrets any               `yaml:"secrets"`
	Outputs map[string]string `yaml:"outputs"`
}

func TestRealReleaseIsGatedOnE2EOfThePushedImage(t *testing.T) {
	var wf struct {
		Jobs map[string]releaseJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustRead(t, "../../.github/workflows/release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	e2e, ok := wf.Jobs["e2e"]
	if !ok {
		t.Fatal("release.yml has no e2e job")
	}
	if e2e.Uses != "./.github/workflows/e2e.yml" {
		t.Errorf("e2e job uses %q, want the reusable ./.github/workflows/e2e.yml", e2e.Uses)
	}
	if !has(e2e.Needs, "image") {
		t.Errorf("e2e job needs %v: it must wait for the image job that pushes the image", e2e.Needs)
	}
	if want := "docker.io/ethosagent/warden@${{ needs.image.outputs.digest }}"; e2e.With["image"] != want {
		t.Errorf("e2e image input = %q, want %q (test the pushed digest, never a tag)", e2e.With["image"], want)
	}
	sec, _ := e2e.Secrets.(map[string]any)
	for _, k := range []string{"DOCKERHUB_USERNAME", "DOCKERHUB_TOKEN"} {
		if want := "${{ secrets." + k + " }}"; sec[k] != want {
			t.Errorf("e2e job secrets[%s] = %v, want %q passed by name (not `secrets: inherit`)", k, sec[k], want)
		}
	}
	if len(sec) != 2 {
		t.Errorf("e2e job passes secrets %v, want exactly the two Docker Hub ones", e2e.Secrets)
	}
	if !strings.Contains(wf.Jobs["image"].Outputs["digest"], "steps.build.outputs.digest") {
		t.Errorf("image job must export the build step's digest as an output, got %q", wf.Jobs["image"].Outputs["digest"])
	}
	if !has(wf.Jobs["release"].Needs, "e2e") {
		t.Errorf("release job needs %v: the GitHub Release must wait for the e2e job", wf.Jobs["release"].Needs)
	}
}

func has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// The release-path e2e logs in before it pulls, and only when it was given an
// image, so a PR run never touches the secrets.
func TestE2ELoginIsGatedOnTheImageInput(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string            `yaml:"name"`
				If   string            `yaml:"if"`
				Uses string            `yaml:"uses"`
				Run  string            `yaml:"run"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustRead(t, "../../.github/workflows/e2e.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	login, pull := -1, -1
	for i, s := range wf.Jobs["e2e"].Steps {
		if strings.HasPrefix(s.Uses, "docker/login-action@") {
			login = i
			if s.If != "${{ inputs.image != '' }}" {
				t.Errorf("login step if = %q, want it gated on the image input", s.If)
			}
			if s.With["username"] != "${{ secrets.DOCKERHUB_USERNAME }}" || s.With["password"] != "${{ secrets.DOCKERHUB_TOKEN }}" {
				t.Errorf("login step uses %v, want the Docker Hub secrets", s.With)
			}
		}
		if strings.Contains(s.Run, "docker pull") {
			pull = i
		}
	}
	if login < 0 || pull < 0 || login > pull {
		t.Errorf("login step at %d, pull step at %d: the login must come first", login, pull)
	}
}
