package main

import (
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release must not make the image publicly usable — no v{version} or
// `latest` tag, no signature — unless the L2 suite passed on that exact digest,
// and must not publish a GitHub Release before that (#421, #369). These tests
// hold release.yml to that order: push the image by digest only, run e2e on
// that digest, then a job that waits for e2e tags and signs the very same
// digest, and only then is the GitHub Release published. Dropping a `needs`
// edge, tagging at push time, or tagging/signing anything but the tested
// digest cannot go unnoticed.

type releaseStep struct {
	ID   string            `yaml:"id"`
	Name string            `yaml:"name"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
	Run  string            `yaml:"run"`
}

type releaseJob struct {
	Name    string            `yaml:"name"`
	Needs   []string          `yaml:"needs"`
	Uses    string            `yaml:"uses"`
	With    map[string]string `yaml:"with"`
	Secrets any               `yaml:"secrets"`
	Outputs map[string]string `yaml:"outputs"`
	Steps   []releaseStep     `yaml:"steps"`
}

const (
	releaseWorkflow = "../../.github/workflows/release.yml"
	imageRepo       = "docker.io/ethosagent/warden"
	// testedDigest is the only image the release may tag, sign and release:
	// the digest the image job pushed and e2e ran on.
	testedDigest = "${{ needs.image.outputs.digest }}"
)

func releaseJobs(t *testing.T) map[string]releaseJob {
	t.Helper()
	var wf struct {
		Jobs map[string]releaseJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustRead(t, releaseWorkflow)), &wf); err != nil {
		t.Fatal(err)
	}
	return wf.Jobs
}

// needsClosure returns the job's transitive `needs` set: everything that must
// succeed before it starts.
func needsClosure(jobs map[string]releaseJob, id string) map[string]bool {
	seen := map[string]bool{}
	var visit func(string)
	visit = func(cur string) {
		for _, n := range jobs[cur].Needs {
			if !seen[n] {
				seen[n] = true
				visit(n)
			}
		}
	}
	visit(id)
	return seen
}

func TestRealReleaseIsGatedOnE2EOfThePushedImage(t *testing.T) {
	jobs := releaseJobs(t)
	e2e, ok := jobs["e2e"]
	if !ok {
		t.Fatal("release.yml has no e2e job")
	}
	if e2e.Uses != "./.github/workflows/e2e.yml" {
		t.Errorf("e2e job uses %q, want the reusable ./.github/workflows/e2e.yml", e2e.Uses)
	}
	if !has(e2e.Needs, "image") {
		t.Errorf("e2e job needs %v: it must wait for the image job that pushes the image", e2e.Needs)
	}
	if want := imageRepo + "@" + testedDigest; e2e.With["image"] != want {
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
	if !strings.Contains(jobs["image"].Outputs["digest"], "steps.build.outputs.digest") {
		t.Errorf("image job must export the build step's digest as an output, got %q", jobs["image"].Outputs["digest"])
	}
	// The order (#421): image -> e2e -> publish (tag + sign) -> release. The
	// `needs` context only carries direct dependencies, so publish must name
	// both jobs: image for the digest, e2e for the gate.
	pub, ok := jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job: tagging and signing must wait for e2e (#421)")
	}
	if !has(pub.Needs, "e2e") {
		t.Errorf("publish job needs %v: it may only run once e2e passed", pub.Needs)
	}
	if !has(pub.Needs, "image") {
		t.Errorf("publish job needs %v: only direct needs are in its needs context, so it cannot read the tested digest otherwise", pub.Needs)
	}
	if !has(jobs["release"].Needs, "publish") {
		t.Errorf("release job needs %v: the GitHub Release must wait for the tag+sign job", jobs["release"].Needs)
	}
}

var (
	// imagetools create adds a tag to an already-pushed digest.
	imagetoolsCreate = regexp.MustCompile(`imagetools\s+create`)
	// dockerPush publishes a ref; with a tag on it, that is a release.
	dockerPush = regexp.MustCompile(`\bdocker\s+push\b`)
	// cosignImageSign matches `cosign sign` but not `cosign sign-blob` (which
	// signs release files, not the image).
	cosignImageSign = regexp.MustCompile(`cosign\s+sign\b`)
	// dockerBuild builds a new image; `docker buildx` is not one (it is the
	// plugin CLI that imagetools create runs through).
	dockerBuild = regexp.MustCompile(`\bdocker\s+build([^x]|$)`)
)

func signsImage(run string) bool {
	return cosignImageSign.MatchString(strings.ReplaceAll(run, "sign-blob", "sign_blob"))
}

// The image is pushed by digest only, and nothing tags or signs it before e2e
// has passed on that digest (#421): a failed e2e must leave no new v*/latest
// tag and no signature on Docker Hub.
func TestRealReleaseTagsAndSignsOnlyAfterE2E(t *testing.T) {
	jobs := releaseJobs(t)
	for id, job := range jobs {
		if needsClosure(jobs, id)["e2e"] || job.Uses != "" {
			continue // runs after e2e, or a reusable-call job with no steps of its own
		}
		for _, s := range job.Steps {
			for _, ban := range []struct {
				why string
				hit bool
			}{
				{"sets image tags (with.tags)", s.With["tags"] != ""},
				{"pushes with the docker CLI (docker push)", dockerPush.MatchString(s.Run)},
				{"adds tags to a pushed digest (imagetools create)", imagetoolsCreate.MatchString(s.Run)},
				{"signs the image (cosign sign)", signsImage(s.Run)},
			} {
				if ban.hit {
					t.Errorf("job %q step %q %s before e2e runs; an untested image must not be tagged or signed (#421)", id, s.Name, ban.why)
				}
			}
		}
	}

	// The build step pushes by digest only, so the digest is the whole image
	// until publish tags it.
	image := jobs["image"]
	var build *releaseStep
	for i := range image.Steps {
		if image.Steps[i].ID == "build" {
			build = &image.Steps[i]
		}
	}
	if build == nil {
		t.Fatal("the image job has no step with id `build`")
	}
	if !strings.Contains(build.With["outputs"], "push-by-digest=true") {
		t.Errorf("image build step outputs = %q, want push-by-digest=true (push by digest only; the publish job tags it after e2e)", build.With["outputs"])
	}

	// And the tagging + signing must really happen — on the exact digest e2e
	// tested, never a rebuild.
	pub, ok := jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job to tag and sign the tested digest once e2e passed")
	}
	tagged, signed := false, false
	for _, s := range pub.Steps {
		if dockerBuild.MatchString(s.Run) || strings.Contains(s.Uses, "build-push-action") {
			t.Errorf("publish step %q builds the image; it must tag the digest e2e already tested, never rebuild (#421)", s.Name)
		}
		digest := s.Env["DIGEST"]
		referencesDigest := strings.Contains(s.Run, imageRepo+"@${DIGEST}")
		if imagetoolsCreate.MatchString(s.Run) {
			tagged = true
			if !referencesDigest {
				t.Errorf("publish tag step tags %s: it must tag the tested digest (%s@%s)", oneLine(s.Run), imageRepo, testedDigest)
			}
			if digest != testedDigest {
				t.Errorf("publish tag step DIGEST = %q, want %q (the digest e2e tested)", digest, testedDigest)
			}
			if !strings.Contains(s.Run, ":${version}") || !strings.Contains(s.Run, ":latest") {
				t.Errorf("publish tag step must add both the version tag (:${version}) and :latest, got %q", oneLine(s.Run))
			}
		}
		if signsImage(s.Run) {
			signed = true
			if !referencesDigest {
				t.Errorf("publish sign step signs %s: it must sign the tested digest (%s@%s)", oneLine(s.Run), imageRepo, testedDigest)
			}
			if digest != testedDigest {
				t.Errorf("publish sign step DIGEST = %q, want %q (the digest e2e tested)", digest, testedDigest)
			}
		}
	}
	if !tagged {
		t.Error("no publish step adds the v{version}/latest tags to the tested digest (docker buildx imagetools create)")
	}
	if !signed {
		t.Error("no publish step signs the tested digest (cosign sign)")
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

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// The release-path e2e logs in before it pulls, and only when it was given an
// image, so a PR run never touches the secrets.
func TestE2ELoginIsGatedOnTheImageInput(t *testing.T) {
	var wf struct {
		Jobs map[string]struct {
			Steps []releaseStep `yaml:"steps"`
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
