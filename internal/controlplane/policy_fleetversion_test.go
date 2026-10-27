package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ethosagent/warden/internal/config"
)

// blockedOverlay is a test stand-in for W-P1-BLOCK-03's blocked_users overlay:
// while a user is blocked it appends a marker host to the served allowlist and
// reports the user as its fingerprint; unblocked it contributes nothing.
type blockedOverlay struct{ user atomic.Pointer[string] }

func (b *blockedOverlay) block(user string) { b.user.Store(&user) }

func (b *blockedOverlay) overlay() wireOverlay {
	return wireOverlay{name: "blocked_users", apply: func(_ context.Context, w *policyWire) (string, error) {
		u := b.user.Load()
		if u == nil || *u == "" {
			return "", nil
		}
		w.Allowlist = append(w.Allowlist, config.AllowlistEntry{Domain: *u + ".blocked.example"})
		return *u, nil
	}}
}

// newFleetServer is a versioned-mode Server over the YAML at path whose policy
// server also runs the test blocked_users overlay (after credential, as
// production registers them).
func newFleetServer(t *testing.T, path string, ov *blockedOverlay) *Server {
	t.Helper()
	s := newVersionedServer(t, path, nil)
	st, ok := s.versions.(*sqlitePolicyStore)
	if !ok {
		t.Fatalf("versions = %T, want *sqlitePolicyStore", s.versions)
	}
	ps := newPolicyServer(path, s.cfg.Token, s.cfg.Logger, s.registry)
	ps.versions = st
	st.etagOf = ps.servedETag
	st.onCreated = ps.Refresh
	for _, o := range []wireOverlay{credentialOverlay(path), ov.overlay()} {
		if err := ps.addOverlay(o); err != nil {
			t.Fatal(err)
		}
	}
	ps.Refresh()
	s.policy = ps
	return s
}

// createVersions appends n versions on top of the current head and returns the
// served ETag after each, indexed by version.
func createVersions(t *testing.T, s *Server, n int) map[int64]string {
	t.Helper()
	etags := map[int64]string{}
	for range n {
		head := mustHead(t, s.versions)
		doc := docWithAllow(baseDoc(t, s), "v"+string(rune('a'+head))+".example.com")
		v, changed, err := s.versions.Create(context.Background(), doc, testAuthor, "", SourcePolicy, head)
		if err != nil || !changed {
			t.Fatalf("Create on v%d = %v, %v", head, changed, err)
		}
		etags[v] = s.policy.currentETag()
	}
	return etags
}

func heartbeat(t *testing.T, base, proxyID, etag string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/control/heartbeat", strings.NewReader(`{"policyETag":"`+etag+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Warden-Proxy-ID", proxyID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("heartbeat = %d, want 204", resp.StatusCode)
	}
}

// fleetWorker is one /dashboard/api/workers entry. Raw keeps the JSON keys so a
// test can tell an omitted policyVersion from a zero one.
type fleetWorker struct {
	PolicyETag    string `json:"policyETag"`
	PolicyVersion int64  `json:"policyVersion"`
	Behind        bool   `json:"behind"`
	Raw           map[string]json.RawMessage
}

func fleet(t *testing.T, base string) map[string]fleetWorker {
	t.Helper()
	resp, err := http.Get(base + "/dashboard/api/workers")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var raw []map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	out := map[string]fleetWorker{}
	for _, r := range raw {
		b, _ := json.Marshal(r)
		var w fleetWorker
		if err := json.Unmarshal(b, &w); err != nil {
			t.Fatal(err)
		}
		w.Raw = r
		var id string
		_ = json.Unmarshal(r["proxyID"], &id)
		out[id] = w
	}
	return out
}

func publishLog(t *testing.T, s *Server) []PublishEntry {
	t.Helper()
	rows, err := s.versions.PublishLog(context.Background(), 0, maxPolicyListLimit)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestFleetPolicyVersion: a worker heartbeating the ETag of v2 while head is v4
// shows policyVersion 2 and behind; one on head shows 4 and up to date.
func TestFleetPolicyVersion(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	etags := createVersions(t, s, 4)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	heartbeat(t, ts.URL, "w-old", etags[2])
	heartbeat(t, ts.URL, "w-new", etags[4])
	got := fleet(t, ts.URL)
	if w := got["w-old"]; w.PolicyVersion != 2 || !w.Behind {
		t.Errorf("w-old = version %d behind %v, want 2 and behind", w.PolicyVersion, w.Behind)
	}
	if w := got["w-new"]; w.PolicyVersion != 4 || w.Behind {
		t.Errorf("w-new = version %d behind %v, want 4 and up to date", w.PolicyVersion, w.Behind)
	}
}

// TestFleetPolicyVersionOverlay: an overlay change after v4 appends exactly one
// publish_log row (reason blocked_users, version 4, actor system), a worker on
// the new ETag shows version 4, and a repeated Refresh appends nothing.
func TestFleetPolicyVersionOverlay(t *testing.T) {
	ov := &blockedOverlay{}
	s := newFleetServer(t, writePolicyFile(t, "api.openai.com"), ov)
	createVersions(t, s, 4)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	before := publishLog(t, s)

	ov.block("alice")
	s.policy.Refresh()
	after := publishLog(t, s)
	if len(after) != len(before)+1 {
		t.Fatalf("publish_log rows %d -> %d, want exactly one appended", len(before), len(after))
	}
	row := after[len(after)-1]
	newETag := s.policy.currentETag()
	if row.Reason != "blocked_users" || row.Version != 4 || row.ActorSub != "system" || row.ETag != newETag {
		t.Errorf("appended row = %+v, want reason blocked_users, version 4, actor system, etag %s", row, newETag)
	}

	heartbeat(t, ts.URL, "w1", newETag)
	if w := fleet(t, ts.URL)["w1"]; w.PolicyVersion != 4 || w.Behind {
		t.Errorf("w1 on the overlay ETag = version %d behind %v, want 4 and up to date", w.PolicyVersion, w.Behind)
	}

	s.policy.Refresh()
	if again := publishLog(t, s); len(again) != len(after) {
		t.Errorf("a repeated Refresh appended %d rows", len(again)-len(after))
	}
}

// TestPublishLogEtagReturns: unblocking back to the v4 ETag appends a new row
// (seq moves forward) and the ETag still maps to version 4.
func TestPublishLogEtagReturns(t *testing.T) {
	ov := &blockedOverlay{}
	s := newFleetServer(t, writePolicyFile(t, "api.openai.com"), ov)
	etags := createVersions(t, s, 4)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	ov.block("alice")
	s.policy.Refresh()
	blocked := publishLog(t, s)
	ov.block("")
	s.policy.Refresh()
	rows := publishLog(t, s)
	if len(rows) != len(blocked)+1 {
		t.Fatalf("unblock appended %d rows, want 1", len(rows)-len(blocked))
	}
	last, prev := rows[len(rows)-1], blocked[len(blocked)-1]
	if last.ETag != etags[4] || last.Version != 4 || last.Seq <= prev.Seq || last.Reason != "blocked_users" {
		t.Errorf("unblock row = %+v, want etag %s, version 4, reason blocked_users, seq > %d", last, etags[4], prev.Seq)
	}
	if v, ok := s.versions.VersionForETag(context.Background(), etags[4]); !ok || v != 4 {
		t.Errorf("VersionForETag(v4 etag) = %d, %v; want 4", v, ok)
	}
	heartbeat(t, ts.URL, "w1", etags[4])
	if w := fleet(t, ts.URL)["w1"]; w.PolicyVersion != 4 || w.Behind {
		t.Errorf("w1 = version %d behind %v, want 4 and up to date", w.PolicyVersion, w.Behind)
	}
}

// TestPublishLogMostRecentWins: an ETag served under two versions maps to the
// version of its most recent publish_log row.
func TestPublishLogMostRecentWins(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	createVersions(t, s, 1)
	v1 := baseDoc(t, s)
	etags := createVersions(t, s, 1)
	// v3 restores v1's doc, so it serves v1's ETag again.
	if _, _, err := s.versions.Create(context.Background(), v1, testAuthor, "", SourceRollback, 2); err != nil {
		t.Fatal(err)
	}
	cur := s.policy.currentETag()
	if cur == etags[2] {
		t.Fatal("v3 serves v2's ETag")
	}
	if v, ok := s.versions.VersionForETag(context.Background(), cur); !ok || v != 3 {
		t.Errorf("VersionForETag(v1 = v3 etag) = %d, %v; want 3", v, ok)
	}
	if v, ok := s.versions.VersionForETag(context.Background(), ""); ok {
		t.Errorf("VersionForETag(\"\") = %d, true; want unknown", v)
	}
}

// TestFleetPolicyVersionUnknown: an ETag with no publish_log row shows no
// policyVersion and stays behind.
func TestFleetPolicyVersionUnknown(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	createVersions(t, s, 2)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	heartbeat(t, ts.URL, "w-unknown", "0123456789abcdef")
	w := fleet(t, ts.URL)["w-unknown"]
	if _, has := w.Raw["policyVersion"]; has {
		t.Errorf("unknown ETag shows policyVersion %s", w.Raw["policyVersion"])
	}
	if !w.Behind {
		t.Error("unknown ETag not flagged behind")
	}
}

// TestFleetPolicyVersionFileMode: file mode (with a state dir) writes no
// publish_log row and the fleet view has no policyVersion.
func TestFleetPolicyVersionFileMode(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	s := New(Config{PolicyPath: path, PolicyStore: PolicyStoreFile, State: openPolicyState(t)})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	if err := os.WriteFile(path, []byte(strings.Replace(readFile(t, path), "api.openai.com", "api.anthropic.com", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()

	heartbeat(t, ts.URL, "w1", s.policy.currentETag())
	w := fleet(t, ts.URL)["w1"]
	if _, has := w.Raw["policyVersion"]; has {
		t.Errorf("file mode shows policyVersion %s", w.Raw["policyVersion"])
	}
	if w.Behind {
		t.Error("worker on the served ETag flagged behind")
	}
	if n := countRows(t, s, "policy_publish_log"); n != 0 {
		t.Errorf("file mode wrote %d publish_log rows", n)
	}
}

// TestPublishLogReasons: a credential rotation logs reason credential; a head
// written out of process with a publish row that does not carry the served
// ETag logs reason external for that head.
func TestPublishLogReasons(t *testing.T) {
	path := writeCredentialPolicyFile(t)
	s := newVersionedServer(t, path, nil)
	createVersions(t, s, 1)

	rotated := strings.Replace(readFile(t, path), policyStoreSecret, policyStoreSecret+"-rotated", 1)
	if err := os.WriteFile(path, []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	rows := publishLog(t, s)
	if last := rows[len(rows)-1]; last.Reason != "credential" || last.Version != 1 || last.ETag != s.policy.currentETag() {
		t.Errorf("rotation row = %+v, want reason credential, version 1, the served etag", last)
	}
	for _, r := range rows {
		if strings.Contains(r.ETag+r.Reason+r.ActorSub, policyStoreSecret) {
			t.Errorf("publish_log row holds the credential: %+v", r)
		}
	}

	// An out-of-process writer (the scenario's CLI stand-in) records no ETag.
	doc := docWithAllow(baseDoc(t, s), "cli.example.com")
	b, _ := json.Marshal(RedactCredentials(doc))
	sqlDB := s.cfg.State.SQL()
	for _, stmt := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
		  VALUES (2, 1, 0, 'cli:t', '', 'cli', '', 'import', ?, ?)`, []any{string(b), sha256Hex(string(b))}},
		{"UPDATE policy_head SET version = 2 WHERE version = 1", nil},
		{"INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (2, '', 'import', 'cli:t', 0)", nil},
	} {
		if _, err := sqlDB.Exec(stmt.q, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.q, err)
		}
	}
	s.policy.Refresh()
	rows = publishLog(t, s)
	if last := rows[len(rows)-1]; last.Reason != "external" || last.Version != 2 || last.ETag != s.policy.currentETag() {
		t.Errorf("out-of-process head row = %+v, want reason external, version 2, the served etag", last)
	}
}

// TestPublishLogStaleHead: AppendPublish for a version that is no longer head
// appends nothing (the head's own Create row covers it), as does an ETag the
// latest row already carries.
func TestPublishLogStaleHead(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	etags := createVersions(t, s, 2)
	ctx := context.Background()
	before := len(publishLog(t, s))
	if ok, err := s.versions.AppendPublish(ctx, 1, "fedcba9876543210", "external", "system"); err != nil || ok {
		t.Errorf("AppendPublish(stale v1) = %v, %v; want nothing appended", ok, err)
	}
	if ok, err := s.versions.AppendPublish(ctx, 2, etags[2], "external", "system"); err != nil || ok {
		t.Errorf("AppendPublish(latest etag) = %v, %v; want nothing appended", ok, err)
	}
	if ok, err := s.versions.AppendPublish(ctx, 2, "", "external", "system"); err == nil || ok {
		t.Errorf("AppendPublish(empty etag) = %v, %v; want an error", ok, err)
	}
	if n := len(publishLog(t, s)); n != before {
		t.Errorf("publish_log rows %d -> %d, want unchanged", before, n)
	}
}

// countingStore counts VersionForETag calls.
type countingStore struct {
	PolicyVersionStore
	lookups atomic.Int64
}

func (c *countingStore) VersionForETag(ctx context.Context, etag string) (int64, bool) {
	c.lookups.Add(1)
	return c.PolicyVersionStore.VersionForETag(ctx, etag)
}

// TestFleetPolicyVersionLookupCost: the ETag lookup runs once per distinct ETag
// per worker-list call, and never on the heartbeat or /policy paths.
func TestFleetPolicyVersionLookupCost(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	etags := createVersions(t, s, 2)
	cs := &countingStore{PolicyVersionStore: s.versions}
	s.versions = cs
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	heartbeat(t, ts.URL, "w1", etags[2])
	heartbeat(t, ts.URL, "w2", etags[2])
	heartbeat(t, ts.URL, "w3", etags[1])
	if code, _, _ := getPolicy(t, ts.URL+"/policy", nil); code != http.StatusOK {
		t.Fatalf("GET /policy = %d", code)
	}
	if n := cs.lookups.Load(); n != 0 {
		t.Errorf("heartbeat and /policy ran %d lookups, want 0", n)
	}
	fleet(t, ts.URL)
	if n := cs.lookups.Load(); n != 2 {
		t.Errorf("one list call ran %d lookups for 2 distinct ETags, want 2", n)
	}
}
