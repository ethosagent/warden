package controlplane

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
)

// writePolicyFile writes a policy YAML (with a secrets block) and returns its path.
func writePolicyFile(t *testing.T, allowDomain string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: " + allowDomain + "\n" +
		"  denylist:\n    - domain: evil.example.com\n" +
		"secrets:\n  - placeholder: openai_secret_001\n    envVar: OPENAI_API_KEY\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPolicyServedExcludesSecrets is the core boundary guarantee: the policy the
// control plane serves carries allow/deny only — never the secrets block.
func TestPolicyServedExcludesSecrets(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com")})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["allowlist"]; !ok {
		t.Error("served policy missing allowlist")
	}
	if _, ok := raw["denylist"]; !ok {
		t.Error("served policy missing denylist")
	}
	if _, ok := raw["secrets"]; ok {
		t.Fatal("served policy LEAKED secrets across the boundary")
	}
}

func TestPolicyTokenAuth(t *testing.T) {
	srv := New(Config{PolicyPath: writePolicyFile(t, "api.openai.com"), Token: "s3cret"})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// No token -> 401.
	resp, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}

	// Correct token -> 200.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/policy", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("with-token status = %d, want 200", resp2.StatusCode)
	}
}

// TestPolicyLastKnownGood verifies a mid-edit malformed policy file does not
// break workers: the last successfully-served policy is returned instead.
func TestPolicyLastKnownGood(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// First request caches last-known-good.
	r1, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("first status = %d, want 200", r1.StatusCode)
	}

	// Corrupt the file, then request again: still 200 from last-known-good.
	if err := os.WriteFile(path, []byte("{{{ not yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	r2, err := http.Get(ts.URL + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("after-corruption status = %d, want 200 (last-known-good)", r2.StatusCode)
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r2.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["allowlist"]; !ok {
		t.Error("last-known-good policy missing allowlist")
	}
}

// getPolicyLP issues a (long-)poll GET and returns status, ETag, and allow domains.
func getPolicyLP(t *testing.T, base, ifNoneMatch, wait string) (int, string, []string) {
	t.Helper()
	u := base + "/policy"
	if wait != "" {
		u += "?wait=" + wait
	}
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", `"`+ifNoneMatch+`"`)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	var body struct {
		Allowlist []struct {
			Domain string `json:"domain"`
		} `json:"allowlist"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	var doms []string
	for _, a := range body.Allowlist {
		doms = append(doms, a.Domain)
	}
	return resp.StatusCode, etag, doms
}

// TestLongPollETag covers the three long-poll outcomes: immediate 200 when the
// worker's ETag differs, 304 at timeout when it matches, and an instant 200 when
// an edit broadcasts to a waiter.
func TestLongPollETag(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. No ETag -> immediate 200 + ETag.
	code, etag, doms := getPolicyLP(t, ts.URL, "", "")
	if code != http.StatusOK || etag == "" || !contains(doms, "api.openai.com") {
		t.Fatalf("initial pull: code=%d etag=%q doms=%v", code, etag, doms)
	}

	// 2. Same ETag, short wait, no change -> 304 at timeout.
	code, _, _ = getPolicyLP(t, ts.URL, etag, "1s")
	if code != http.StatusNotModified {
		t.Fatalf("unchanged long-poll: code=%d, want 304", code)
	}

	// 3. Same ETag, longer wait, but an edit lands -> woken with 200 + new policy.
	done := make(chan struct{})
	var gotCode int
	var gotDoms []string
	go func() {
		gotCode, _, gotDoms = getPolicyLP(t, ts.URL, etag, "10s")
		close(done)
	}()
	time.Sleep(150 * time.Millisecond) // let the long-poll block
	if err := srv.writePolicy(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.anthropic.com"}},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll was not woken by the edit within 3s")
	}
	if gotCode != http.StatusOK || !contains(gotDoms, "api.anthropic.com") {
		t.Fatalf("woken long-poll: code=%d doms=%v, want 200 + api.anthropic.com", gotCode, gotDoms)
	}
}

// TestWritePolicyPersistsAndValidates verifies an edit is persisted (served on
// the next pull) and that an invalid edit is rejected without clobbering the
// good policy on disk.
func TestWritePolicyPersistsAndValidates(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Valid edit persists and is served.
	if err := srv.writePolicy(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "new.example.com", Port: 443}},
		Denylist:  []config.DenylistEntry{{Domain: "bad.example.com"}},
	}); err != nil {
		t.Fatalf("valid writePolicy: %v", err)
	}
	if got := fetchPolicyDomains(t, ts.URL); !contains(got, "new.example.com") {
		t.Fatalf("served policy after edit = %v, want new.example.com", got)
	}

	// Invalid edit (empty allowlist breaks default-deny) is rejected; the good
	// policy on disk is untouched.
	if err := srv.writePolicy(config.Policy{}); err == nil {
		t.Fatal("expected empty-allowlist edit to be rejected")
	}
	if got := fetchPolicyDomains(t, ts.URL); !contains(got, "new.example.com") {
		t.Fatalf("policy changed after a rejected edit: %v", got)
	}
}

func fetchPolicyDomains(t *testing.T, base string) []string {
	t.Helper()
	resp, err := http.Get(base + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body struct {
		Allowlist []struct {
			Domain string `json:"domain"`
		} `json:"allowlist"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, a := range body.Allowlist {
		out = append(out, a.Domain)
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// writePolicyFileWithSettings writes a CP config that includes behavioral blocks
// (mcp + judge + agents) in addition to allow/deny, returning its path.
func writePolicyFileWithSettings(t *testing.T, allowDomain string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: " + allowDomain + "\n" +
		"logging:\n  level: info\n  format: json\n" +
		"mcp:\n  enabled: true\n  mode: enforce\n" +
		"judge:\n  enabled: true\n  model: gpt-4o\n  baseURL: https://api.openai.com/v1\n  apiKeyEnv: OPENAI_API_KEY\n" +
		"agents:\n  - id: agent-1\n    policy: be careful\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// fetchPolicyRaw returns the decoded /policy body as a raw key map + its ETag.
func fetchPolicyRaw(t *testing.T, base string) (map[string]json.RawMessage, string) {
	t.Helper()
	resp, err := http.Get(base + "/policy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	etag := strings.Trim(resp.Header.Get("ETag"), `"`)
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	return raw, etag
}

// TestPolicyIncludesSettingsAndETagCovers verifies a CP serving behavioral
// blocks emits a "settings" object, that its ETag differs from the same config
// without those blocks, and that changing a settings field changes the ETag.
func TestPolicyIncludesSettingsAndETagCovers(t *testing.T) {
	withSettings := writePolicyFileWithSettings(t, "api.openai.com")
	srvA := New(Config{PolicyPath: withSettings})
	tsA := httptest.NewServer(srvA.Handler())
	defer tsA.Close()

	rawA, etagA := fetchPolicyRaw(t, tsA.URL)
	if _, ok := rawA["settings"]; !ok {
		t.Fatal("CP with behavioral blocks did not emit a settings object")
	}
	// The judge env-NAME reference must be present; no secret value can be.
	if !strings.Contains(string(rawA["settings"]), "OPENAI_API_KEY") {
		t.Errorf("settings missing judge env-name reference: %s", rawA["settings"])
	}

	// Same allow/deny but WITHOUT behavioral blocks → different ETag, no settings.
	plain := writePolicyFile(t, "api.openai.com")
	srvB := New(Config{PolicyPath: plain})
	tsB := httptest.NewServer(srvB.Handler())
	defer tsB.Close()
	rawB, etagB := fetchPolicyRaw(t, tsB.URL)
	if _, ok := rawB["settings"]; ok {
		t.Fatal("plain allow/deny CP must NOT emit a settings key (back-compat)")
	}
	if etagA == etagB {
		t.Fatalf("ETag did not change when settings were added: %q == %q", etagA, etagB)
	}

	// Change a settings field (mcp mode) on the with-settings CP → new ETag and
	// a long-poll waiter wakes.
	done := make(chan struct{})
	var wokeCode int
	go func() {
		wokeCode, _, _ = getPolicyLP(t, tsA.URL, etagA, "10s")
		close(done)
	}()
	time.Sleep(150 * time.Millisecond) // let the long-poll block
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
		"logging:\n  level: info\n  format: json\n" +
		"mcp:\n  enabled: true\n  mode: monitor\n" +
		"judge:\n  enabled: true\n  model: gpt-4o\n  baseURL: https://api.openai.com/v1\n  apiKeyEnv: OPENAI_API_KEY\n" +
		"agents:\n  - id: agent-1\n    policy: be careful\n"
	if err := os.WriteFile(withSettings, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srvA.refresh() // pick up the external edit immediately
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("settings change did not wake the long-poll within 3s")
	}
	if wokeCode != http.StatusOK {
		t.Fatalf("woken long-poll code = %d, want 200", wokeCode)
	}
	_, etagA2 := fetchPolicyRaw(t, tsA.URL)
	if etagA2 == etagA {
		t.Fatal("ETag did not change after a settings-field edit")
	}
}

// TestWritePolicyPreservesBehavioralBlocks verifies a policy edit from the
// dashboard does NOT clobber operator behavioral blocks (mcp/judge/agents) in
// the CP config file — only the allow/deny policy is rewritten.
func TestWritePolicyPreservesBehavioralBlocks(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	if err := srv.writePolicy(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "api.anthropic.com"}},
	}); err != nil {
		t.Fatalf("writePolicy: %v", err)
	}

	// Re-read the file: behavioral blocks survive, allow/deny is updated.
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after edit: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp block clobbered by policy edit: %+v", p.MCP)
	}
	if !p.Judge.Enabled || p.Judge.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("judge block clobbered by policy edit: %+v", p.Judge)
	}
	if len(p.Agents) != 1 || p.Agents[0].ID != "agent-1" {
		t.Errorf("agents block clobbered by policy edit: %+v", p.Agents)
	}
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.anthropic.com" {
		t.Errorf("allowlist not updated: %+v", p.Allowlist)
	}
}

// TestHeartbeatEndpoint verifies a heartbeat registers the worker with its
// policy ETag, and that the workers view flags it "behind" when that ETag does
// not match the policy the CP currently serves.
func TestHeartbeatEndpoint(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/control/heartbeat",
		strings.NewReader(`{"policyETag":"stale-version"}`))
	req.Header.Set("X-Warden-Proxy-ID", "worker-9")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat status = %d, want 204", resp.StatusCode)
	}

	// The workers endpoint should list worker-9, behind (its etag != served etag).
	wresp, err := http.Get(ts.URL + "/dashboard/api/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = wresp.Body.Close() }()
	var workers []struct {
		ProxyID    string `json:"proxyID"`
		PolicyETag string `json:"policyETag"`
		Behind     bool   `json:"behind"`
	}
	if err := json.NewDecoder(wresp.Body).Decode(&workers); err != nil {
		t.Fatal(err)
	}
	if len(workers) != 1 || workers[0].ProxyID != "worker-9" {
		t.Fatalf("workers = %+v", workers)
	}
	if workers[0].PolicyETag != "stale-version" || !workers[0].Behind {
		t.Errorf("worker not flagged behind: %+v", workers[0])
	}
}

// TestWorkerRegistry verifies policy-pull and ingest both register a worker and
// that Views reflects counts + online status.
func TestWorkerRegistry(t *testing.T) {
	r := NewWorkerRegistry()
	r.SeenPolicyPull("w1")
	r.SeenIngest("w1", 3)
	r.SeenIngest("w2", 1)
	r.SeenPolicyPull("") // blank id ignored

	views := r.Views()
	if len(views) != 2 {
		t.Fatalf("registry has %d workers, want 2", len(views))
	}
	for _, v := range views {
		switch v.ProxyID {
		case "w1":
			if v.EventsForwarded != 3 {
				t.Errorf("w1 eventsForwarded = %d, want 3", v.EventsForwarded)
			}
			if v.LastPolicyPull == "" {
				t.Error("w1 should have a last policy pull")
			}
			if !v.Online {
				t.Error("w1 should be online (just seen)")
			}
		case "w2":
			if v.EventsForwarded != 1 {
				t.Errorf("w2 eventsForwarded = %d, want 1", v.EventsForwarded)
			}
		default:
			t.Errorf("unexpected worker %q", v.ProxyID)
		}
	}
}

// TestMintServerTLS signs a server cert from a generated CA and verifies it
// chains to that CA for the requested hostname.
func TestMintServerTLS(t *testing.T) {
	caCertPath, caKeyPath, caCert := genTestCA(t)
	tlsCfg, err := MintServerTLS(caCertPath, caKeyPath, []string{"control-plane", "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("got %d certs, want 1", len(tlsCfg.Certificates))
	}
	leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "control-plane", Roots: roots}); err != nil {
		t.Fatalf("minted cert does not verify for control-plane: %v", err)
	}
}

// genTestCA generates an RSA CA, writes cert+key (PKCS#8) to temp files, and
// returns the paths and the parsed cert.
func genTestCA(t *testing.T) (certPath, keyPath string, caCert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, caCert
}

// TestWriteSettingsPersistsMCP verifies an MCP settings edit is persisted so the
// served file's MCPConfig reflects it (enabled, mode, tool allow/deny round-trip),
// that the /policy payload then carries the new settings.mcp, and that the ETag
// changed.
func TestWriteSettingsPersistsMCP(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com") // plain allow/deny, no mcp block
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, etag0 := fetchPolicyRaw(t, ts.URL) // baseline (no settings yet)

	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{
			Enabled: true,
			Mode:    "enforce",
			Tools:   &config.MCPToolsSettings{Allow: []string{"read_file"}, Deny: []string{"delete_file"}},
		},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	// The on-disk file round-trips through the full loader with the new MCP block.
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after settings edit: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Fatalf("mcp not persisted: %+v", p.MCP)
	}
	if len(p.MCP.Tools.Allow) != 1 || p.MCP.Tools.Allow[0] != "read_file" {
		t.Errorf("mcp tools.allow not round-tripped: %+v", p.MCP.Tools.Allow)
	}
	if len(p.MCP.Tools.Deny) != 1 || p.MCP.Tools.Deny[0] != "delete_file" {
		t.Errorf("mcp tools.deny not round-tripped: %+v", p.MCP.Tools.Deny)
	}

	// The /policy payload now carries settings.mcp and the ETag changed.
	raw, etag1 := fetchPolicyRaw(t, ts.URL)
	if etag1 == etag0 {
		t.Fatalf("ETag did not change after settings edit: %q", etag1)
	}
	settings, ok := raw["settings"]
	if !ok {
		t.Fatal("served policy missing settings after edit")
	}
	if !strings.Contains(string(settings), `"mcp"`) || !strings.Contains(string(settings), "enforce") {
		t.Errorf("settings.mcp not reflected in payload: %s", settings)
	}
}

// TestWriteSettingsPreservesPolicyBlock verifies a settings edit does NOT clobber
// the existing allow/deny policy block in the CP config file.
func TestWriteSettingsPreservesPolicyBlock(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com") // allowlist api.openai.com, denylist evil.example.com
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{Enabled: true, Mode: "monitor"},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("allowlist clobbered by settings edit: %+v", p.Allowlist)
	}
	if len(p.Denylist) != 1 || p.Denylist[0].Domain != "evil.example.com" {
		t.Errorf("denylist clobbered by settings edit: %+v", p.Denylist)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "monitor" {
		t.Errorf("mcp not applied: %+v", p.MCP)
	}
}

// TestWriteSettingsDisablesMCP verifies a nil MCP settings block removes the mcp
// block so the served settings disable MCP.
func TestWriteSettingsDisablesMCP(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // starts with mcp enabled+enforce
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Sanity: the served settings start with mcp present.
	raw0, _ := fetchPolicyRaw(t, ts.URL)
	if s, ok := raw0["settings"]; !ok || !strings.Contains(string(s), `"mcp"`) {
		t.Fatalf("expected initial settings.mcp, got %s", raw0["settings"])
	}

	// A settings doc with no MCP (nil) removes the block on disk.
	if err := srv.writeSettings(config.SettingsWire{}); err != nil {
		t.Fatalf("writeSettings(nil mcp): %v", err)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.MCP.Enabled {
		t.Errorf("mcp still enabled after nil-MCP settings edit: %+v", p.MCP)
	}
	// The served settings no longer advertise mcp (judge/agents from the fixture
	// keep a settings object present, but mcp must be gone).
	raw1, _ := fetchPolicyRaw(t, ts.URL)
	if s, ok := raw1["settings"]; ok && strings.Contains(string(s), `"mcp"`) {
		t.Errorf("settings.mcp not removed after disable: %s", s)
	}
}

// TestWriteSettingsWakesLongPoll verifies a settings edit wakes a blocked
// long-poll waiter (the ETag covers settings).
func TestWriteSettingsWakesLongPoll(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, etag := fetchPolicyRaw(t, ts.URL)

	done := make(chan struct{})
	var wokeCode int
	go func() {
		wokeCode, _, _ = getPolicyLP(t, ts.URL, etag, "10s")
		close(done)
	}()
	time.Sleep(150 * time.Millisecond) // let the long-poll block
	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("settings edit did not wake the long-poll within 3s")
	}
	if wokeCode != http.StatusOK {
		t.Fatalf("woken long-poll code = %d, want 200", wokeCode)
	}
}

// TestWriteSettingsPersistsJudge verifies a judge settings edit (enabled, model,
// apiKeyEnv, timeout, circuit breaker) persists so the served file's JudgeConfig
// reflects it with durations parsed correctly, that the /policy payload then
// carries settings.judge with the env NAME (never a secret value), and that the
// written block passes loader validation. ETag changed.
func TestWriteSettingsPersistsJudge(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com") // plain allow/deny, no judge block
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, etag0 := fetchPolicyRaw(t, ts.URL) // baseline (no settings yet)

	if err := srv.writeSettings(config.SettingsWire{
		Judge: &config.JudgeSettings{
			Enabled:        true,
			Model:          "gpt-4o",
			BaseURL:        "https://api.openai.com/v1",
			APIKeyEnv:      "OPENAI_API_KEY",
			TimeoutSeconds: 12,
			CircuitBreaker: &config.JudgeCircuitBreakerSettings{
				MaxFailures:     7,
				CooldownSeconds: 45,
			},
		},
		// validateJudge requires at least one agent when the judge is enabled.
		Agents: []config.AgentSettings{{ID: "agent-1", Policy: "be careful"}},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	// The on-disk file round-trips through the full loader (this also proves the
	// written judge block passes validation: a bad block would error here).
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after settings edit: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Judge.Enabled || p.Judge.Model != "gpt-4o" || p.Judge.APIKeyEnv != "OPENAI_API_KEY" {
		t.Fatalf("judge not persisted: %+v", p.Judge)
	}
	if p.Judge.Timeout != 12*time.Second {
		t.Errorf("judge.timeout did not round-trip: got %v, want 12s", p.Judge.Timeout)
	}
	if p.Judge.CircuitBreaker.MaxFailures != 7 {
		t.Errorf("judge.circuitBreaker.maxFailures = %d, want 7", p.Judge.CircuitBreaker.MaxFailures)
	}
	if p.Judge.CircuitBreaker.Cooldown != 45*time.Second {
		t.Errorf("judge.circuitBreaker.cooldown did not round-trip: got %v, want 45s", p.Judge.CircuitBreaker.Cooldown)
	}

	// The /policy payload now carries settings.judge with the env NAME and no value.
	raw, etag1 := fetchPolicyRaw(t, ts.URL)
	if etag1 == etag0 {
		t.Fatalf("ETag did not change after judge settings edit: %q", etag1)
	}
	settings, ok := raw["settings"]
	if !ok {
		t.Fatal("served policy missing settings after edit")
	}
	if !strings.Contains(string(settings), `"judge"`) || !strings.Contains(string(settings), "OPENAI_API_KEY") {
		t.Errorf("settings.judge env-name not reflected in payload: %s", settings)
	}
}

// TestWriteSettingsJudgeDefaultsValidate verifies a judge block written with only
// the required fields (no timeout/cache/circuit tuning) does NOT emit zero-value
// durations that would trip the loader: the loader applies its own defaults.
func TestWriteSettingsJudgeDefaultsValidate(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		Judge: &config.JudgeSettings{
			Enabled:   true,
			Model:     "gpt-4o",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
		},
		Agents: []config.AgentSettings{{ID: "agent-1", Policy: "be careful"}},
	}); err != nil {
		t.Fatalf("writeSettings (judge minimal): %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	// Loader defaults must apply (not zero values written by the encoder).
	if p.Judge.Timeout != 5*time.Second {
		t.Errorf("judge.timeout default not applied: got %v, want 5s", p.Judge.Timeout)
	}
	if p.Judge.CacheTTL != 5*time.Minute {
		t.Errorf("judge.cacheTTL default not applied: got %v, want 5m", p.Judge.CacheTTL)
	}
	if p.Judge.CircuitBreaker.MaxFailures != 5 {
		t.Errorf("judge.circuitBreaker.maxFailures default not applied: got %d, want 5", p.Judge.CircuitBreaker.MaxFailures)
	}
	if p.Judge.CircuitBreaker.Cooldown != 30*time.Second {
		t.Errorf("judge.circuitBreaker.cooldown default not applied: got %v, want 30s", p.Judge.CircuitBreaker.Cooldown)
	}
}

// TestWriteSettingsPersistsAgents verifies an agents settings edit persists so the
// served file's Agents list round-trips (id + policy text), in order.
func TestWriteSettingsPersistsAgents(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		Agents: []config.AgentSettings{
			{ID: "agent-a", Policy: "no exfiltration"},
			{ID: "agent-b", Policy: "read only"},
		},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Agents) != 2 {
		t.Fatalf("agents not persisted: %+v", p.Agents)
	}
	if p.Agents[0].ID != "agent-a" || p.Agents[0].Policy != "no exfiltration" {
		t.Errorf("agents[0] not round-tripped: %+v", p.Agents[0])
	}
	if p.Agents[1].ID != "agent-b" || p.Agents[1].Policy != "read only" {
		t.Errorf("agents[1] not round-tripped: %+v", p.Agents[1])
	}
}

// TestWriteSettingsDisablesJudge verifies a nil/disabled Judge settings block
// removes the judge block on disk so the worker disables the judge. The agents
// block is removed too when no agents are sent, but the policy/mcp blocks survive.
func TestWriteSettingsDisablesJudge(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // judge enabled+agent in fixture
	srv := New(Config{PolicyPath: path})

	// Sanity: the fixture starts with the judge enabled.
	prov0, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatal(err)
	}
	p0, _ := prov0.GetPolicy()
	if !p0.Judge.Enabled {
		t.Fatalf("expected fixture judge enabled, got %+v", p0.Judge)
	}

	// A settings doc with no judge (nil) and no agents removes both blocks while
	// keeping the mcp block (still enabled in the doc) intact.
	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
	}); err != nil {
		t.Fatalf("writeSettings(nil judge): %v", err)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.Judge.Enabled {
		t.Errorf("judge still enabled after nil-judge settings edit: %+v", p.Judge)
	}
	if len(p.Agents) != 0 {
		t.Errorf("agents not removed after empty-agents settings edit: %+v", p.Agents)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp clobbered by judge-disable edit: %+v", p.MCP)
	}
}

// TestWriteSettingsJudgePreservesMCPAndPolicy verifies setting the judge leaves an
// existing mcp block AND the allow/deny policy intact (full preservation).
func TestWriteSettingsJudgePreservesMCPAndPolicy(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // policy + mcp(enforce) + judge + agents
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		// Keep mcp enabled so the rewrite must preserve it alongside the new judge.
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
		Judge: &config.JudgeSettings{
			Enabled:   true,
			Model:     "gpt-4o-mini",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
		},
		Agents: []config.AgentSettings{{ID: "agent-1", Policy: "be careful"}},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	// Policy allow intact (the with-settings fixture has allow-only, no denylist).
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("allowlist clobbered by judge edit: %+v", p.Allowlist)
	}
	// mcp block intact.
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp clobbered by judge edit: %+v", p.MCP)
	}
	// judge updated.
	if !p.Judge.Enabled || p.Judge.Model != "gpt-4o-mini" {
		t.Errorf("judge not applied: %+v", p.Judge)
	}
}

// TestWriteSettingsPersistsLogging verifies a logging settings edit persists so the
// reloaded policy reflects the new level/format, the /policy payload carries
// settings.logging, and the ETag changed.
func TestWriteSettingsPersistsLogging(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com") // no logging block on disk yet
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, etag0 := fetchPolicyRaw(t, ts.URL)

	if err := srv.writeSettings(config.SettingsWire{
		Logging: &config.LoggingSettings{Level: "debug", Format: "text"},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.LogLevel != "debug" || p.LogFormat != "text" {
		t.Fatalf("logging not persisted: level=%q format=%q", p.LogLevel, p.LogFormat)
	}

	raw, etag1 := fetchPolicyRaw(t, ts.URL)
	if etag1 == etag0 {
		t.Fatalf("ETag did not change after logging edit: %q", etag1)
	}
	settings, ok := raw["settings"]
	if !ok {
		t.Fatal("served policy missing settings after logging edit")
	}
	if !strings.Contains(string(settings), `"logging"`) || !strings.Contains(string(settings), "debug") {
		t.Errorf("settings.logging not reflected in payload: %s", settings)
	}
}

// TestWriteSettingsNilLoggingPreservesExisting verifies that a settings edit with a
// nil Logging block does NOT delete an existing on-disk logging block (logging is
// co-owned by writePolicy's default; writeSettings must not fight it).
func TestWriteSettingsNilLoggingPreservesExisting(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // has logging: info/json
	srv := New(Config{PolicyPath: path})

	// Edit some unrelated block (mcp) with no Logging in the wire.
	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{Enabled: true, Mode: "monitor"},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cur), "logging:") {
		t.Errorf("nil-Logging edit deleted the existing logging block:\n%s", cur)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.LogLevel != "info" || p.LogFormat != "json" {
		t.Errorf("existing logging not preserved: level=%q format=%q", p.LogLevel, p.LogFormat)
	}
}

// TestWriteSettingsPersistsCacheTTL verifies a cacheTTLSeconds edit persists so the
// reloaded policy's CacheTTLSeconds reflects it.
func TestWriteSettingsPersistsCacheTTL(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	ttl := 1800
	if err := srv.writeSettings(config.SettingsWire{
		CacheTTLSeconds: &ttl,
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.CacheTTLSeconds != 1800 {
		t.Fatalf("cacheTTLSeconds not persisted: got %d, want 1800", p.CacheTTLSeconds)
	}
}

// TestWriteSettingsComplianceMergePreservesAudit is the core nested-merge test: a
// compliance toggle must set audit.compliance.enabled WITHOUT clobbering an
// existing audit.signedReceipts sub-block (a local-only key the control plane must
// never touch).
func TestWriteSettingsComplianceMergePreservesAudit(t *testing.T) {
	// Config carrying a local-only audit.signedReceipts block alongside allow/deny.
	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := "policy:\n  allowlist:\n    - domain: api.openai.com\n" +
		"audit:\n  signedReceipts:\n    enabled: true\n    keyFile: /var/warden/key.pem\n    log: /var/warden/receipts.jsonl\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		Compliance: &config.ToggleSetting{Enabled: true},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	// The signedReceipts sub-block must survive byte-for-byte (key/log paths).
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cur), "signedReceipts") ||
		!strings.Contains(string(cur), "/var/warden/key.pem") ||
		!strings.Contains(string(cur), "/var/warden/receipts.jsonl") {
		t.Fatalf("nested compliance merge clobbered signedReceipts:\n%s", cur)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Audit.Compliance.Enabled {
		t.Errorf("compliance not enabled after merge: %+v", p.Audit.Compliance)
	}
	// signedReceipts preserved through the loader too.
	if !p.Audit.SignedReceipts.Enabled ||
		p.Audit.SignedReceipts.KeyFile != "/var/warden/key.pem" ||
		p.Audit.SignedReceipts.Log != "/var/warden/receipts.jsonl" {
		t.Errorf("signedReceipts not preserved through merge: %+v", p.Audit.SignedReceipts)
	}
}

// TestWriteSettingsConfigBlocksPreserveCore verifies that writing logging,
// cacheTTLSeconds, and compliance together leaves the policy, mcp, and judge blocks
// from the fixture intact (full preservation across the new blocks).
func TestWriteSettingsConfigBlocksPreserveCore(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // policy + logging + mcp + judge + agents
	srv := New(Config{PolicyPath: path})

	ttl := 600
	if err := srv.writeSettings(config.SettingsWire{
		// Re-supply mcp/judge/agents so the rewrite preserves them alongside the
		// new logging/cache/compliance blocks.
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
		Judge: &config.JudgeSettings{
			Enabled:   true,
			Model:     "gpt-4o",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
		},
		Agents:          []config.AgentSettings{{ID: "agent-1", Policy: "be careful"}},
		Logging:         &config.LoggingSettings{Level: "warn", Format: "text"},
		CacheTTLSeconds: &ttl,
		Compliance:      &config.ToggleSetting{Enabled: true},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("allowlist clobbered: %+v", p.Allowlist)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp clobbered: %+v", p.MCP)
	}
	if !p.Judge.Enabled || p.Judge.Model != "gpt-4o" {
		t.Errorf("judge clobbered: %+v", p.Judge)
	}
	if p.LogLevel != "warn" || p.LogFormat != "text" {
		t.Errorf("logging not applied: level=%q format=%q", p.LogLevel, p.LogFormat)
	}
	if p.CacheTTLSeconds != 600 {
		t.Errorf("cacheTTLSeconds not applied: %d", p.CacheTTLSeconds)
	}
	if !p.Audit.Compliance.Enabled {
		t.Errorf("compliance not applied: %+v", p.Audit.Compliance)
	}
}

// TestWriteSettingsPersistsObservability verifies an observability edit is
// persisted so the served file's ObservabilityConfig reflects every field
// (enabled, serviceName, metricsEnabled, otlpEndpoint, resourceAttributes), that
// the /policy payload then carries settings.observability, and the ETag changed.
func TestWriteSettingsPersistsObservability(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com") // plain allow/deny, no observability block
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	_, etag0 := fetchPolicyRaw(t, ts.URL) // baseline (no settings yet)

	if err := srv.writeSettings(config.SettingsWire{
		Observability: &config.ObservabilitySettings{
			Enabled:            true,
			ServiceName:        "warden-prod",
			MetricsEnabled:     true,
			OTLPEndpoint:       "otel-collector:4317",
			ResourceAttributes: map[string]string{"env": "prod", "region": "us-east"},
		},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	// The on-disk file round-trips through the full loader with the new block.
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload after settings edit: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	o := p.Observability
	if !o.Enabled {
		t.Fatalf("observability not enabled: %+v", o)
	}
	if o.ServiceName != "warden-prod" {
		t.Errorf("serviceName not round-tripped: %q", o.ServiceName)
	}
	if !o.MetricsEnabled {
		t.Errorf("metricsEnabled not round-tripped: %v", o.MetricsEnabled)
	}
	if o.OTLPEndpoint != "otel-collector:4317" {
		t.Errorf("otlpEndpoint not round-tripped: %q", o.OTLPEndpoint)
	}
	if o.ResourceAttributes["env"] != "prod" || o.ResourceAttributes["region"] != "us-east" {
		t.Errorf("resourceAttributes not round-tripped: %+v", o.ResourceAttributes)
	}

	// The /policy payload now carries settings.observability and the ETag changed.
	raw, etag1 := fetchPolicyRaw(t, ts.URL)
	if etag1 == etag0 {
		t.Fatalf("ETag did not change after settings edit: %q", etag1)
	}
	settings, ok := raw["settings"]
	if !ok {
		t.Fatal("served policy missing settings after edit")
	}
	if !strings.Contains(string(settings), `"observability"`) ||
		!strings.Contains(string(settings), "warden-prod") {
		t.Errorf("settings.observability not reflected in payload: %s", settings)
	}
}

// TestWriteSettingsObservabilityMetricsFalseSurvives verifies an explicit
// metricsEnabled=false survives the round-trip — the loader defaults metrics ON
// when the block is present, so a naive encoder would silently re-default it to
// true. The pointer-valued metrics.enabled in the mirror prevents that.
func TestWriteSettingsObservabilityMetricsFalseSurvives(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		Observability: &config.ObservabilitySettings{
			Enabled:        true,
			ServiceName:    "warden-quiet",
			MetricsEnabled: false, // explicit false must survive
		},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Observability.Enabled {
		t.Fatalf("observability not enabled: %+v", p.Observability)
	}
	if p.Observability.MetricsEnabled {
		t.Errorf("explicit metricsEnabled=false was re-defaulted to true: %+v", p.Observability)
	}
}

// TestWriteSettingsDisablesObservability verifies that writing a nil/disabled
// observability block removes it on disk, so the worker disables OTel on restart.
func TestWriteSettingsDisablesObservability(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// First enable observability so there is a block to remove.
	if err := srv.writeSettings(config.SettingsWire{
		Observability: &config.ObservabilitySettings{Enabled: true, ServiceName: "warden-prod"},
	}); err != nil {
		t.Fatalf("writeSettings(enable): %v", err)
	}
	raw0, _ := fetchPolicyRaw(t, ts.URL)
	if s, ok := raw0["settings"]; !ok || !strings.Contains(string(s), `"observability"`) {
		t.Fatalf("expected initial settings.observability, got %s", raw0["settings"])
	}

	// A settings doc with no observability (nil) removes the block on disk.
	if err := srv.writeSettings(config.SettingsWire{}); err != nil {
		t.Fatalf("writeSettings(nil observability): %v", err)
	}
	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if p.Observability.Enabled {
		t.Errorf("observability still enabled after nil edit: %+v", p.Observability)
	}
	raw1, _ := fetchPolicyRaw(t, ts.URL)
	if s, ok := raw1["settings"]; ok && strings.Contains(string(s), `"observability"`) {
		t.Errorf("settings.observability not removed after disable: %s", s)
	}
}

// TestWriteSettingsObservabilityPreservesCore verifies that adding an
// observability block leaves the existing policy, mcp, and judge blocks intact.
func TestWriteSettingsObservabilityPreservesCore(t *testing.T) {
	path := writePolicyFileWithSettings(t, "api.openai.com") // policy + logging + mcp + judge + agents
	srv := New(Config{PolicyPath: path})

	if err := srv.writeSettings(config.SettingsWire{
		// Re-supply mcp/judge/agents so the rewrite preserves them alongside
		// observability (the judge requires at least one agent policy).
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
		Judge: &config.JudgeSettings{
			Enabled:   true,
			Model:     "gpt-4o",
			BaseURL:   "https://api.openai.com/v1",
			APIKeyEnv: "OPENAI_API_KEY",
		},
		Agents:        []config.AgentSettings{{ID: "agent-1", Policy: "be careful"}},
		Observability: &config.ObservabilitySettings{Enabled: true, MetricsEnabled: true},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}

	prov, err := config.NewLocalYAMLProvider(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	p, err := prov.GetPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "api.openai.com" {
		t.Errorf("allowlist clobbered: %+v", p.Allowlist)
	}
	if !p.MCP.Enabled || p.MCP.Mode != "enforce" {
		t.Errorf("mcp clobbered: %+v", p.MCP)
	}
	if !p.Judge.Enabled || p.Judge.Model != "gpt-4o" {
		t.Errorf("judge clobbered: %+v", p.Judge)
	}
	if !p.Observability.Enabled {
		t.Errorf("observability not applied: %+v", p.Observability)
	}
}
