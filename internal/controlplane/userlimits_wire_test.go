package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/config"
	"gopkg.in/yaml.v3"
)

// With none of the per-user limit keys set, /policy and its ETag are the bytes
// of a build without them (W-P3-PUL-01).
func TestPolicyWire_UserLimitsAbsentUnchanged(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path, Logger: slog.New(slog.NewJSONHandler(io.Discard, nil))})
	body, etag := servePolicyOnce(t, srv.policy)
	const golden = `{"allowlist":[{"domain":"api.openai.com","port":0}],"denylist":[{"domain":"evil.example.com","port":0}]}`
	if string(body) != golden+"\n" {
		t.Fatalf("body = %q, want the pre-change golden %q", body, golden)
	}
	sum := sha256.Sum256([]byte(golden))
	if want := `"` + hex.EncodeToString(sum[:8]) + `"`; etag != want {
		t.Fatalf("etag = %q, want %q", etag, want)
	}
	for _, key := range []string{"userLimits", "defaultUserLimit", "anonymousLimit", "costBlockedUsers"} {
		if strings.Contains(string(body), key) {
			t.Fatalf("absent key %s is on the wire: %s", key, body)
		}
	}
}

// The new fields ride the wire and change the ETag; the cost blocks are not
// kept in a stored policy version.
func TestPolicyWire_UserLimitsRideTheWire(t *testing.T) {
	w := policyWire{
		Allowlist:        []config.AllowlistEntry{{Domain: "a.com"}},
		UserLimits:       []config.UserLimit{{Name: "eng", RateLimit: "60/minute", Match: config.UserLimitMatch{Groups: []string{"eng"}}}},
		DefaultUserLimit: &config.UserLimit{Name: "default", RateLimit: "1/second"},
		AnonymousLimit:   &config.UserLimit{Name: "anonymous", DailyCostUSD: 1},
		CostBlockedUsers: []config.CostBlockedUser{{Sub: "s", Rule: "eng", Day: "2026-11-27"}},
	}
	b, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"userLimits":[{"name":"eng"`, `"defaultUserLimit":{"name":"default"`, `"anonymousLimit":{"name":"anonymous","dailyCostUSD":1}`, `"costBlockedUsers":[{"sub":"s","rule":"eng","day":"2026-11-27"}]`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("wire lacks %s:\n%s", want, b)
		}
	}
	if etagFor(w) == etagFor(policyWire{Allowlist: w.Allowlist}) {
		t.Error("limits do not change the ETag")
	}
}

// A dashboard or file edit keeps the three YAML keys (and never writes the
// wire-only cost blocks), so WritePolicy cannot drop a configured rule.
func TestRenderPolicyBlock_KeepsUserLimits(t *testing.T) {
	p := config.Policy{
		Allowlist:        []config.AllowlistEntry{{Domain: "a.com"}},
		UserLimits:       []config.UserLimit{{Name: "eng", RateLimit: "60/minute", Match: config.UserLimitMatch{Groups: []string{"eng"}}}},
		DefaultUserLimit: &config.UserLimit{Name: "default", RateLimit: "1/second"},
		AnonymousLimit:   &config.UserLimit{Name: "anonymous", DailyCostUSD: 1},
		CostBlockedUsers: []config.CostBlockedUser{{Sub: "s", Rule: "eng", Day: "2026-11-27"}},
	}
	root := map[string]yaml.Node{}
	if err := renderPolicyBlock(root, policyYAMLOfPolicy(p)); err != nil {
		t.Fatal(err)
	}
	node := root["policy"]
	out, err := yaml.Marshal(&node)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"userLimits:", "name: eng", "groups:", "defaultUserLimit:", "anonymousLimit:", "dailyCostUSD: 1"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("policy block lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "costBlockedUsers") || strings.Contains(string(out), "sub:") {
		t.Errorf("wire-only cost blocks written to YAML:\n%s", out)
	}
	if got := policyOfWire(policyWireOfPolicy(p)); len(got.UserLimits) != 1 || got.AnonymousLimit == nil || got.CostBlockedUsers != nil {
		t.Errorf("wire projection = %+v", got)
	}
}

func limitsOnlyRoot(t *testing.T) map[string]yaml.Node {
	t.Helper()
	head := policyWire{
		Allowlist:        []config.AllowlistEntry{{Domain: "old.com"}},
		UserLimits:       []config.UserLimit{{Name: "eng", RateLimit: "60/minute", Match: config.UserLimitMatch{Groups: []string{"eng"}}}},
		DefaultUserLimit: &config.UserLimit{Name: "default", RateLimit: "1/second"},
		AnonymousLimit:   &config.UserLimit{Name: "anonymous", DailyCostUSD: 1},
	}
	root := map[string]yaml.Node{}
	if err := renderPolicyBlock(root, policyYAMLOfWire(head)); err != nil {
		t.Fatal(err)
	}
	return root
}

// An edit from the dashboard carries allow/deny only. The limit keys already
// in the file (file mode) or head doc (versioned mode; candidateWire renders the
// head into root first) must survive it.
func TestRenderPolicyEdit_KeepsExistingUserLimits(t *testing.T) {
	root := limitsOnlyRoot(t)
	edit := config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "new.com"}}}
	if err := renderPolicyEdit(root, edit); err != nil {
		t.Fatal(err)
	}
	got := policyYAMLFromRoot(root)
	if len(got.Allowlist) != 1 || got.Allowlist[0].Domain != "new.com" {
		t.Fatalf("allowlist edit lost: %+v", got.Allowlist)
	}
	if len(got.UserLimits) != 1 || got.UserLimits[0].Name != "eng" || got.DefaultUserLimit == nil || got.AnonymousLimit == nil {
		t.Fatalf("limits dropped by an allowlist edit: %+v", got)
	}
}

// An edit that does carry limits replaces them; one that carries none on a
// file without limits leaves the block without the keys.
func TestRenderPolicyEdit_ReplacesWhenPresentAndStaysAbsent(t *testing.T) {
	root := limitsOnlyRoot(t)
	edit := config.Policy{
		Allowlist:  []config.AllowlistEntry{{Domain: "new.com"}},
		UserLimits: []config.UserLimit{{Name: "ops", RateLimit: "1/second", Match: config.UserLimitMatch{Groups: []string{"ops"}}}},
	}
	if err := renderPolicyEdit(root, edit); err != nil {
		t.Fatal(err)
	}
	if got := policyYAMLFromRoot(root); len(got.UserLimits) != 1 || got.UserLimits[0].Name != "ops" || got.DefaultUserLimit != nil {
		t.Fatalf("explicit limits not applied: %+v", got)
	}
	empty := map[string]yaml.Node{}
	if err := renderPolicyEdit(empty, config.Policy{Allowlist: []config.AllowlistEntry{{Domain: "a.com"}}}); err != nil {
		t.Fatal(err)
	}
	node := empty["policy"]
	out, _ := yaml.Marshal(&node)
	if strings.Contains(string(out), "imit") {
		t.Fatalf("absent limits written: %s", out)
	}
}
