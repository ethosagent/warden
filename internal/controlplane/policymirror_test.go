package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/dashboard"
)

// The write-through mirror and drift check (W-P1-PVER-05): in versioned mode
// the served YAML is rewritten to equal head after every head move, and a hand
// edit of its policy/settings blocks is warned about, shown as drift and
// audited, but never served.

// yamlWire loads the served YAML with the full loader, as file mode serves it
// (credential included).
func yamlWire(t *testing.T, path string) policyWire {
	t.Helper()
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("load the served YAML: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatalf("load the served YAML: %v", err)
	}
	return policyWire{Allowlist: p.Allowlist, Denylist: p.Denylist, Settings: config.SettingsWireFromPolicy(p)}
}

func wireJSON(t *testing.T, w policyWire) string {
	t.Helper()
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// servedWire is the wire /policy serves now.
func servedWire(s *Server) policyWire {
	w, _, _, _ := s.policy.snapshot()
	return w
}

// logLines returns the decoded JSON log lines whose msg is msg.
func logLines(t *testing.T, logs string, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(logs) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// dashboardDrift reads the drift field of GET /dashboard/api/policy.
func dashboardDrift(t *testing.T, s *Server) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/policy", nil)
	req.Header.Set("Authorization", "Bearer "+dashTestToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy = %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Drift *bool `json:"drift"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Drift == nil {
		t.Fatalf("GET /dashboard/api/policy has no drift field: %s", rec.Body.String())
	}
	return *resp.Drift
}

// addAllowToYAML is a hand edit of the served YAML's policy block: one more
// allowlist domain, the rest of the file unchanged.
func addAllowToYAML(t *testing.T, path, domain string) string {
	t.Helper()
	cur := readFile(t, path)
	next := strings.Replace(cur, "  allowlist:\n", "  allowlist:\n    - domain: "+domain+"\n", 1)
	if next == cur {
		t.Fatalf("the served YAML has no allowlist to edit:\n%s", cur)
	}
	return editExternally(t, path, next)
}

// TestPolicyMirror: after each of three saves (policy, settings,
// llmProviders) the served YAML loads to the wire head serves, credential
// included, and a control plane restarted in file mode serves the same
// /policy bytes.
func TestPolicyMirror(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()

	saves := []func() error{
		func() error {
			return srv.WritePolicy(ctx, plusAllow(t, srv, "mirror.example.com"), dashboard.WriteMeta{})
		},
		func() error {
			in := awsSettings("")
			in.Agents = []config.AgentSettings{{ID: "a1", Policy: "read only"}}
			return srv.WriteSettings(ctx, in, dashboard.WriteMeta{})
		},
		func() error {
			return srv.WriteLLMProviders(ctx, []config.LLMProvider{{
				Name: "p1", BaseURL: "https://api.openai.com/v1", Model: "gpt-4o-mini", APIKeyEnv: "OPENAI_API_KEY",
			}}, dashboard.WriteMeta{})
		},
	}
	for i, save := range saves {
		if err := save(); err != nil {
			t.Fatalf("save %d: %v", i+1, err)
		}
		if h := mustHead(t, srv.versions); h != int64(i+2) {
			t.Fatalf("head after save %d = %d, want %d", i+1, h, i+2)
		}
		if got, want := wireJSON(t, yamlWire(t, path)), wireJSON(t, servedWire(srv)); got != want {
			t.Fatalf("save %d: the served YAML does not mirror head\n yaml: %s\n head: %s", i+1, got, want)
		}
	}
	if !strings.Contains(readFile(t, path), "secretAccessKey: "+policyStoreSecret) {
		t.Fatal("the mirror dropped the live credential from the served YAML")
	}
	if strings.Contains(readFile(t, path), credentialRedactPrefix) {
		t.Fatal("the mirror wrote a credential fingerprint into the served YAML")
	}
	if strings.Contains(logs.String(), policyStoreSecret) {
		t.Fatal("the credential reached a log line")
	}

	versioned := httptest.NewServer(srv.Handler())
	t.Cleanup(versioned.Close)
	file := New(Config{PolicyPath: path, Token: dashTestToken})
	fileTS := httptest.NewServer(file.Handler())
	t.Cleanup(fileTS.Close)
	auth := map[string]string{"Authorization": "Bearer " + dashTestToken}
	_, vb, vtag := getPolicy(t, versioned.URL+"/policy", auth)
	_, fb, ftag := getPolicy(t, fileTS.URL+"/policy", auth)
	if !bytes.Equal(vb, fb) || vtag != ftag {
		t.Fatalf("file mode over the mirrored YAML serves different /policy bytes\n versioned %s %s\n file      %s %s", vtag, vb, ftag, fb)
	}
	if srv.mirror.drift.Load() {
		t.Fatal("drift reported after the CP's own mirror writes")
	}
}

// TestPolicyMirrorCLIVersion: a version created outside the publish path (the
// CLI, another control plane) is mirrored when the ticker sees the head move.
func TestPolicyMirrorCLIVersion(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)

	doc := docWithAllow(headVersion(t, srv).Doc, "cli.example.com")
	if _, _, err := srv.versions.Create(ctx, doc, PolicyAuthor{Sub: "cli:op", Kind: AuthorKindCLI}, "cli", SourceImport, 1); err != nil {
		t.Fatal(err)
	}
	srv.reloadPolicy(ctx)
	if got := allowDomainsOf(yamlWire(t, path)); !slices.Contains(got, "cli.example.com") {
		t.Fatalf("served YAML allowlist = %v, want head v2 mirrored", got)
	}
	srv.reloadPolicy(ctx)
	if srv.mirror.drift.Load() {
		t.Fatal("drift reported after mirroring a CLI version")
	}
}

// makeUnwritable makes the served YAML unwritable for the mirror: read-only
// (0444), or, for root, which ignores file modes, replaced by a directory.
// The returned func reports how the served path changed ("" = untouched).
func makeUnwritable(t *testing.T, path string) func() string {
	t.Helper()
	if os.Geteuid() != 0 {
		want := readFile(t, path)
		if err := os.Chmod(path, 0o444); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
		return func() string {
			if got := readFile(t, path); got != want {
				return "the read-only served YAML was replaced:\n" + got
			}
			return ""
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	return func() string {
		if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
			return "the unwritable served path was replaced"
		}
		return ""
	}
}

// TestPolicyMirrorFailureNonFatal: with the served YAML read-only the save
// still creates a version, workers get it, and exactly one error line names
// the version.
func TestPolicyMirrorFailureNonFatal(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	before := makeUnwritable(t, path)
	logs.Reset()

	if err := srv.WritePolicy(context.Background(), plusAllow(t, srv, "ro.example.com"), dashboard.WriteMeta{}); err != nil {
		t.Fatalf("a mirror failure failed the save: %v", err)
	}
	if h := mustHead(t, srv.versions); h != 2 {
		t.Fatalf("head = %d, want 2 (the version stands)", h)
	}
	if got := allowDomainsOf(servedWire(srv)); !slices.Contains(got, "ro.example.com") {
		t.Fatalf("served allowlist = %v, want head v2", got)
	}
	if got := before(); got != "" {
		t.Fatal(got)
	}
	var errs []map[string]any
	for line := range strings.Lines(logs.String()) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatal(err)
		}
		if rec["level"] == "ERROR" {
			errs = append(errs, rec)
		}
	}
	if len(errs) != 1 || errs[0]["version"] != float64(2) {
		t.Fatalf("error lines = %v, want exactly one naming version 2", errs)
	}
	// The ticker does not retry the failed mirror or call it drift.
	srv.reloadPolicy(context.Background())
	if n := strings.Count(logs.String(), `"level":"ERROR"`); n != 1 {
		t.Fatalf("%d error lines after a tick, want still 1", n)
	}
	if srv.mirror.drift.Load() {
		t.Fatal("a failed mirror was reported as an external edit")
	}
}

// TestPolicyDrift: a hand edit of the YAML policy block is not served across
// two ticker cycles, is warned about exactly once with file_sha256 and head,
// and GET /dashboard/api/policy reports drift.
func TestPolicyDrift(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)
	if dashboardDrift(t, srv) {
		t.Fatal("drift before any edit")
	}
	etag := srv.policy.currentETag()

	addAllowToYAML(t, path, "hand.example.com")
	srv.reloadPolicy(ctx)
	srv.reloadPolicy(ctx)

	if got := srv.policy.currentETag(); got != etag {
		t.Fatalf("/policy ETag moved from %s to %s on a hand edit", etag, got)
	}
	if got := allowDomainsOf(servedWire(srv)); slices.Contains(got, "hand.example.com") {
		t.Fatalf("served allowlist = %v: the hand edit is served", got)
	}
	warns := logLines(t, logs.String(), mirrorDriftMsg)
	if len(warns) != 1 {
		t.Fatalf("%d drift warnings, want 1:\n%s", len(warns), logs)
	}
	if w := warns[0]; w["level"] != "WARN" || w["head"] != float64(1) || len(fmt.Sprint(w["file_sha256"])) != 64 {
		t.Fatalf("drift warning = %v, want WARN with head 1 and a file_sha256", w)
	}
	if !dashboardDrift(t, srv) {
		t.Fatal("GET /dashboard/api/policy drift = false after a hand edit")
	}
	if strings.Contains(logs.String(), "hand.example.com") {
		t.Fatal("the hand edit's content reached a log line")
	}

	// A second, different edit is a new external edit: one more warning.
	addAllowToYAML(t, path, "hand2.example.com")
	srv.reloadPolicy(ctx)
	if n := len(logLines(t, logs.String(), mirrorDriftMsg)); n != 2 {
		t.Fatalf("%d drift warnings after a second edit, want 2", n)
	}
}

// TestPolicyDriftAudited: with admin audit enabled each distinct hand edit
// appends one config.external_change row: before v<head>:<doc_sha256>, after
// file:<file_sha256>. The file-mode check of W-P1-AAUD-08 adds nothing.
func TestPolicyDriftAudited(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	rec := &fakeRecorder{}
	srv.auditRec = rec
	srv.primeExternalEdit()
	ctx := context.Background()
	srv.reloadPolicy(ctx)

	addAllowToYAML(t, path, "hand.example.com")
	srv.reloadPolicy(ctx)
	srv.reloadPolicy(ctx)

	got := rec.inputs()
	if len(got) != 1 {
		t.Fatalf("%d audit rows, want 1: %+v", len(got), got)
	}
	head := headVersion(t, srv)
	warn := logLines(t, logs.String(), mirrorDriftMsg)[0]
	want := adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: "system"},
		ActorRole:  "system",
		AuthMethod: adminaudit.AuthMethodSystem,
		Action:     "config.external_change",
		Target:     "policy",
		Outcome:    adminaudit.OutcomeOK,
		BeforeHash: fmt.Sprintf("v%d:%s", head.Version, head.DocSHA256),
		AfterHash:  fmt.Sprint("file:", warn["file_sha256"]),
	}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("audit row = %+v\nwant        %+v", got[0], want)
	}
}

// TestPolicyDriftClears: putting the YAML back to head clears drift; a later
// save mirrors over a hand edit and clears it too.
func TestPolicyDriftClears(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)
	orig := readFile(t, path)

	addAllowToYAML(t, path, "hand.example.com")
	srv.reloadPolicy(ctx)
	if !dashboardDrift(t, srv) {
		t.Fatal("no drift after a hand edit")
	}
	editExternally(t, path, orig)
	srv.reloadPolicy(ctx)
	if dashboardDrift(t, srv) {
		t.Fatal("drift still reported with the YAML back at head")
	}

	addAllowToYAML(t, path, "hand.example.com")
	srv.reloadPolicy(ctx)
	if !dashboardDrift(t, srv) {
		t.Fatal("no drift after a second hand edit")
	}
	if err := srv.WritePolicy(ctx, plusAllow(t, srv, "saved.example.com"), dashboard.WriteMeta{}); err != nil {
		t.Fatal(err)
	}
	if dashboardDrift(t, srv) {
		t.Fatal("drift still reported after a save mirrored head")
	}
	srv.reloadPolicy(ctx)
	if dashboardDrift(t, srv) {
		t.Fatal("drift reported on the tick after a save mirrored head")
	}
	if got := allowDomainsOf(yamlWire(t, path)); slices.Contains(got, "hand.example.com") || !slices.Contains(got, "saved.example.com") {
		t.Fatalf("served YAML allowlist = %v, want head v2", got)
	}
	if n := len(logLines(t, logs.String(), mirrorDriftMsg)); n != 1 {
		t.Fatalf("%d drift warnings, want 1 (the same edit twice is one distinct file hash)", n)
	}
}

// TestPolicyDriftIgnoresOtherBlocks: edits the drift check must not report: a
// CP-local block, and the credential (it lives only in the YAML and the
// credential overlay serves it).
func TestPolicyDriftIgnoresOtherBlocks(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)

	cur := readFile(t, path)
	editExternally(t, path, strings.Replace(cur, policyStoreSecret, "sk-rotated-by-hand", 1)+
		"controlPlane:\n  pollInterval: 7s\n")
	srv.reloadPolicy(ctx)
	if srv.mirror.drift.Load() || len(logLines(t, logs.String(), mirrorDriftMsg)) != 0 {
		t.Fatalf("an edit outside the policy/settings blocks was reported as drift:\n%s", logs)
	}
}

// TestPolicyDriftAtStartup: a control plane that starts on a YAML equal to
// head reports no drift; one that starts on a YAML edited while it was down
// reports it on the first tick and never serves it.
func TestPolicyDriftAtStartup(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	srv, _ := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)
	if srv.mirror.drift.Load() {
		t.Fatal("drift on the first tick after the initial import")
	}

	addAllowToYAML(t, path, "offline.example.com")
	var logs bytes.Buffer
	restarted := New(Config{
		PolicyPath: path, Token: dashTestToken, State: srv.cfg.State,
		PolicyStore: PolicyStoreVersioned, Logger: testJSONLogger(&logs),
	})
	restarted.reloadPolicy(ctx)
	if !restarted.mirror.drift.Load() {
		t.Fatal("a YAML edited while the control plane was down is not drift")
	}
	if got := allowDomainsOf(servedWire(restarted)); slices.Contains(got, "offline.example.com") {
		t.Fatalf("served allowlist = %v: the offline edit is served", got)
	}
	if n := len(logLines(t, logs.String(), mirrorDriftMsg)); n != 1 {
		t.Fatalf("%d drift warnings, want 1", n)
	}
	if !strings.Contains(readFile(t, path), "offline.example.com") {
		t.Fatal("startup overwrote the hand edit; only a head move mirrors")
	}
}

// TestPolicyDriftFileModeUnchanged: file mode has no mirror and no drift; a
// hand edit is served as before.
func TestPolicyDriftFileModeUnchanged(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path, Token: dashTestToken})
	addAllowToYAML(t, path, "hand.example.com")
	srv.reloadPolicy(context.Background())
	if got := allowDomainsOf(servedWire(srv)); !slices.Contains(got, "hand.example.com") {
		t.Fatalf("file mode: served allowlist = %v, want the hand edit", got)
	}
	if dashboardDrift(t, srv) {
		t.Fatal("file mode reported drift")
	}
}

// TestPolicyMirrorConcurrentTick: ticks racing saves never mirror an older
// version over a newer one; afterwards the served YAML equals head and no
// drift is reported.
func TestPolicyMirrorConcurrentTick(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv, logs := newPublishServer(t, path, config.ConsoleConfig{})
	ctx := context.Background()
	srv.reloadPolicy(ctx)

	stop := make(chan struct{})
	ticked := make(chan struct{})
	go func() {
		defer close(ticked)
		for {
			select {
			case <-stop:
				return
			default:
				srv.reloadPolicy(ctx)
			}
		}
	}()
	for i := range 10 {
		if err := srv.WritePolicy(ctx, plusAllow(t, srv, fmt.Sprintf("c%d.example.com", i)), dashboard.WriteMeta{}); err != nil {
			close(stop)
			<-ticked
			t.Fatalf("save %d: %v", i, err)
		}
	}
	close(stop)
	<-ticked
	srv.reloadPolicy(ctx)

	if got, want := wireJSON(t, yamlWire(t, path)), wireJSON(t, servedWire(srv)); got != want {
		t.Fatalf("the served YAML does not mirror head after racing ticks\n yaml: %s\n head: %s", got, want)
	}
	if srv.mirror.drift.Load() || len(logLines(t, logs.String(), mirrorDriftMsg)) != 0 {
		t.Fatalf("racing ticks reported the CP's own mirror writes as drift:\n%s", logs)
	}
}
