package main

import (
	"maps"
	"regexp"
	"slices"
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
	// ContinueOnError is a bool or an `${{ … }}` expression; typed as any
	// because yaml.v3 refuses to unmarshal a bool scalar into a string.
	ContinueOnError any `yaml:"continue-on-error"`
}

type releaseJob struct {
	Name            string            `yaml:"name"`
	Needs           []string          `yaml:"needs"`
	If              string            `yaml:"if"`
	Uses            string            `yaml:"uses"`
	With            map[string]string `yaml:"with"`
	Secrets         any               `yaml:"secrets"`
	Outputs         map[string]string `yaml:"outputs"`
	Permissions     map[string]string `yaml:"permissions"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Steps           []releaseStep     `yaml:"steps"`
}

const (
	releaseWorkflow = "../../.github/workflows/release.yml"
	imageRepo       = "docker.io/ethosagent/warden"
	// testedDigest is the only image the release may tag, sign and release:
	// the digest the image job pushed and e2e ran on.
	testedDigest = "${{ needs.image.outputs.digest }}"
)

// parseReleaseWorkflow returns the jobs and the workflow-level `permissions`
// block: a job without a `permissions:` of its own gets the workflow-level
// one (or GitHub's defaults when neither exists).
func parseReleaseWorkflow(t *testing.T) (map[string]releaseJob, map[string]string) {
	t.Helper()
	var wf struct {
		Permissions map[string]string     `yaml:"permissions"`
		Jobs        map[string]releaseJob `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(mustRead(t, releaseWorkflow)), &wf); err != nil {
		t.Fatal(err)
	}
	return wf.Jobs, wf.Permissions
}

func releaseJobs(t *testing.T) map[string]releaseJob {
	t.Helper()
	jobs, _ := parseReleaseWorkflow(t)
	return jobs
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

// The sign must come before the tag in publish (#421, review round 1):
// `cosign sign` accepts repo@digest, so the untagged digest is signable, and a
// failed sign — a Sigstore or OIDC outage — then leaves no v{version}/latest
// tag pointing at an unsigned image.
func TestRealReleaseSignsTheDigestBeforeItTags(t *testing.T) {
	pub, ok := releaseJobs(t)["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	installed, signed, tagged := -1, -1, -1
	for i, s := range pub.Steps {
		switch {
		case strings.Contains(s.Uses, "cosign-installer") && installed < 0:
			installed = i
		case signsImage(s.Run) && signed < 0:
			signed = i
		case imagetoolsCreate.MatchString(s.Run) && tagged < 0:
			tagged = i
		}
	}
	if signed < 0 || tagged < 0 {
		t.Fatalf("publish signs at step %d and tags at step %d: it must both sign the tested digest and tag it", signed, tagged)
	}
	if signed > tagged {
		t.Errorf("publish tags at step %d and signs at step %d: the sign must come first, so a failed sign leaves no tag on an unsigned image (#421)", tagged, signed)
	}
	if installed < 0 || installed > signed {
		t.Errorf("cosign is installed at step %d and used at step %d: install cosign before signing", installed, signed)
	}
}

// gateBypass matches the `if:` expressions that can fire while an earlier job
// failed or was cancelled: any of them lets a job run behind a red e2e.
// `!cancelled()` is covered by the cancelled() term, `!success()` is the
// spelled-out failure().
var gateBypass = regexp.MustCompile(`always\(\)|failure\(\)|cancelled\(\)|!success\(\)`)

// continueOnErrorWanted reports whether a `continue-on-error` value turns the
// flag on: a bare true, or an expression (which we cannot prove false, so it
// counts as on).
func continueOnErrorWanted(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != "false"
	default:
		return false
	}
}

// Everything in e2e's forward closure runs only because e2e passed — unless it
// is given its own escape hatch: a job-level `if:` that fires on failure or
// cancellation, or `continue-on-error`, would let publish tag and sign (and
// release publish) behind a red e2e, which is exactly what #421 prevents. The
// e2e job itself and every publish step must be equally unskippable.
func TestRealReleaseForwardClosureCannotSkipTheGate(t *testing.T) {
	jobs := releaseJobs(t)
	e2e, ok := jobs["e2e"]
	if !ok {
		t.Fatal("release.yml has no e2e job")
	}
	if continueOnErrorWanted(e2e.ContinueOnError) {
		t.Error("the e2e job has continue-on-error: the release gate may not be allowed to fail silently (#421)")
	}

	pub, ok := jobs["publish"]
	if !ok {
		t.Fatal("release.yml has no publish job")
	}
	for _, s := range pub.Steps {
		if continueOnErrorWanted(s.ContinueOnError) {
			t.Errorf("publish step %q has continue-on-error: tagging and signing must fail the run when they fail (#421)", s.Name)
		}
	}

	// A job behind the gate: everything that transitively needs e2e —
	// publish, release, and anything added later that needs them.
	for id, job := range jobs {
		if !needsClosure(jobs, id)["e2e"] {
			continue
		}
		if gateBypass.MatchString(job.If) {
			t.Errorf("job %q has if: %q: an if that fires on failure or cancellation lets it run behind a red e2e (#421)", id, job.If)
		}
		if continueOnErrorWanted(job.ContinueOnError) {
			t.Errorf("job %q has continue-on-error: a job behind the e2e gate must fail the run when it fails (#421)", id)
		}
	}
}

// The registry-write surface of a `run:` step. A signature is itself a
// sha256-….sig tag on the registry, so cosign counts as a write too.
var registryWrites = []struct {
	re  *regexp.Regexp
	why string
}{
	{regexp.MustCompile(`\bdocker\s+push\b`), "pushes with the docker CLI (docker push)"},
	{regexp.MustCompile(`\bdocker\s+tag\b`), "re-tags a local image (docker tag, one step short of docker push)"},
	{regexp.MustCompile(`--push\b`), "pushes straight from a build (--push)"},
	{regexp.MustCompile(`\bcrane\b`), "mutates the registry with crane (e.g. crane tag)"},
	{regexp.MustCompile(`\bskopeo\b`), "copies or tags images with skopeo"},
	{regexp.MustCompile(`\boras\b`), "pushes or tags artifacts with oras"},
	{regexp.MustCompile(`\bregctl\b`), "copies or tags images with regctl"},
	{regexp.MustCompile(`\bcosign\b`), "signs with cosign (the signature lands as a sha256-….sig tag)"},
	{regexp.MustCompile(`\bimagetools\b`), "adds tags with imagetools create"},
	{regexp.MustCompile(`ethosagent/warden`), "names the image repo (ethosagent/warden)"},
}

// The actions the image job may run, by repo — any pinned SHA of them. The
// pre-e2e job that builds the image must stay exactly this narrow: nothing on
// the list can tag, sign or otherwise publish the image on its own.
var imageJobActions = map[string]bool{
	"actions/checkout":           true,
	"docker/setup-qemu-action":   true,
	"docker/setup-buildx-action": true,
	"docker/login-action":        true,
	"docker/build-push-action":   true,
}

// The pre-e2e half of the workflow is an allowlist (#421, review round 1): no
// job may delegate to a workflow other than the e2e job's e2e.yml, and no
// `run:` before e2e has passed may reach the registry — push and tag tools,
// signing tools, or the image repo — so nothing pre-e2e can publish or mutate
// an image, whatever it is compromised into running.
func TestRealReleasePreE2ECannotReachTheRegistry(t *testing.T) {
	jobs := releaseJobs(t)
	for id, job := range jobs {
		if needsClosure(jobs, id)["e2e"] {
			continue // behind the gate: publish signs and tags there on purpose
		}
		if job.Uses != "" {
			if id != "e2e" || job.Uses != "./.github/workflows/e2e.yml" {
				t.Errorf("job %q calls reusable workflow %q: before the gate, the only reusable call is the e2e job's ./.github/workflows/e2e.yml (#421)", id, job.Uses)
			}
			continue
		}
		for _, s := range job.Steps {
			for _, ban := range registryWrites {
				if ban.re.MatchString(s.Run) {
					t.Errorf("job %q step %q %s before e2e runs; nothing pre-e2e may write to the registry (#421)", id, s.Name, ban.why)
				}
			}
		}
	}

	for _, s := range jobs["image"].Steps {
		if s.Uses == "" {
			continue
		}
		action := s.Uses
		if i := strings.Index(action, "@"); i >= 0 {
			action = action[:i]
		}
		if !imageJobActions[action] {
			t.Errorf("image job step %q uses %q: only %v may run in the pre-e2e image job (#421)", s.Name, s.Uses, slices.Sorted(maps.Keys(imageJobActions)))
		}
	}
}

// id-token: write mints a Sigstore identity and packages: write publishes a
// GHCR package: only the two jobs that sign (publish, release) may hold the
// first, and the image job — which pushes with Docker Hub credentials — needs
// neither (#421, review round 1).
func TestRealReleasePermissionsAreLeastPrivilege(t *testing.T) {
	jobs, top := parseReleaseWorkflow(t)
	maySign := map[string]bool{"publish": true, "release": true}
	for id, job := range jobs {
		perms := job.Permissions
		if perms == nil {
			perms = top // jobs without their own block get the workflow-level one
		}
		if perms["id-token"] == "write" && !maySign[id] {
			t.Errorf("job %q has id-token: write: only publish and release sign the release artifacts, so only they may hold it (#421)", id)
		}
		if id == "image" && perms["packages"] == "write" {
			t.Error("image job has packages: write: it pushes with Docker Hub credentials, and must not be able to publish a package before e2e (#421)")
		}
	}
}

// imageBuildStep returns the image job's `build` step: the only step that
// pushes.
func imageBuildStep(t *testing.T) releaseStep {
	t.Helper()
	for _, s := range releaseJobs(t)["image"].Steps {
		if s.ID == "build" {
			return s
		}
	}
	t.Fatal("the image job has no step with id `build`")
	return releaseStep{}
}

// withLabels parses a build-push-action `labels:` block: one KEY=VALUE per
// line.
func withLabels(block string) map[string]string {
	labels := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			labels[k] = v
		}
	}
	return labels
}

// Dropping docker/metadata-action for the digest-only push must not drop its
// default OCI labels: title, description, created, licenses, url and
// documentation on top of the source/revision/version already there (review
// round 1). The values are the ones the action produced — repo fields read
// from the push event — except `created`, which comes from the commit
// timestamp instead of the action's start time, so the same tag always
// carries the same label.
func TestRealReleaseImageKeepsTheOCILabels(t *testing.T) {
	labels := withLabels(imageBuildStep(t).With["labels"])
	want := map[string]string{
		"org.opencontainers.image.title":         "${{ github.event.repository.name }}",
		"org.opencontainers.image.description":   "${{ github.event.repository.description }}",
		"org.opencontainers.image.created":       "${{ steps.oci.outputs.created }}",
		"org.opencontainers.image.licenses":      "${{ github.event.repository.license.spdx_id }}",
		"org.opencontainers.image.url":           "${{ github.event.repository.html_url }}",
		"org.opencontainers.image.documentation": "${{ github.event.repository.html_url }}#readme",
		"org.opencontainers.image.source":        "https://github.com/${{ github.repository }}",
		"org.opencontainers.image.revision":      "${{ github.sha }}",
		"org.opencontainers.image.version":       "${{ github.ref_name }}",
	}
	for k, v := range want {
		if labels[k] != v {
			t.Errorf("build step label %s = %q, want %q (the docker/metadata-action default set must survive the digest-only push)", k, labels[k], v)
		}
	}
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
