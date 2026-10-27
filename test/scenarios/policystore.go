package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// The versioned policy store scenario (W-P1-PVER-01): a control plane started
// with --policy-store=versioned on an empty store imports the served YAML as
// version 1 (W-P1-PVER-07) and enforces it exactly as file mode does; once
// another process (standing in for the CLI) appends version 2 and moves the
// head, workers enforce the head version within the control plane's reload
// tick plus one long-poll cycle, and the YAML is no longer what is served.

func policyStoreOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// pverHost is allowed only by the head version, never by the YAML.
const pverHost = "pver.example.com"

func policyStoreVersioned(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)

	// Version 1 is the imported YAML: its allowlist, default-deny for
	// everything else.
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Fatalf("imported v1: CONNECT api.example.com = %d, want 200 (YAML allowlist)", got)
	}
	if got := connectStatus(t, h, pverHost+":443"); got != http.StatusForbidden {
		t.Fatalf("imported v1: CONNECT %s = %d, want 403 (not in the YAML)", pverHost, got)
	}

	// Version 2, written out of process: pver allowed, llm.example.com dropped.
	appendPolicyVersion(t, h.ControlPlaneStateDB(),
		`{"allowlist":[{"domain":"api.example.com"},{"domain":"`+pverHost+`"}],"denylist":null}`)

	h.Eventually("workers enforce head version 2", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})
	if got := connectStatus(t, h, "llm.example.com:443"); got != http.StatusForbidden {
		t.Errorf("head v2: CONNECT llm.example.com = %d, want 403 (the YAML allowlist is no longer served)", got)
	}
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Errorf("head v2: CONNECT api.example.com = %d, want 200", got)
	}
}

// appendPolicyVersion appends docJSON as the next version the way an
// out-of-process writer does: one BEGIN IMMEDIATE transaction that reads the
// head, inserts the version, moves the head by compare-and-swap and appends
// the publish log row.
func appendPolicyVersion(t *testing.T, path, docJSON string) {
	t.Helper()
	ctx := context.Background()
	db, err := cpstate.Open(ctx, path, controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	conn, err := db.SQL().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	sum := sha256.Sum256([]byte(docJSON))
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	var head int64
	if err := conn.QueryRowContext(ctx, "SELECT version FROM policy_head").Scan(&head); err != nil {
		t.Fatalf("read the head: %v", err)
	}
	next := head + 1
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
		  VALUES (?, ?, 0, 'cli:harness', '', 'cli', 'scenario', 'import', ?, ?)`, []any{next, head, docJSON, hex.EncodeToString(sum[:])}},
		{"UPDATE policy_head SET version = ? WHERE version = ?", []any{next, head}},
		{"INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (?, '', 'import', 'cli:harness', 0)", []any{next}},
		{"COMMIT", nil},
	} {
		if _, err := conn.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
}

// The initial import scenario (W-P1-PVER-07): the first versioned start on an
// empty store stores the served YAML as version 1, authored system:import,
// appends one policy.initial_import admin audit row, and workers keep
// enforcing the same policy. A control-plane restart imports nothing more.

func policyImportOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore(), harness.WithAdminAudit()}
}

func policyStoreInitialImport(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)
	assertYAMLEnforced := func(when string) {
		t.Helper()
		if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
			t.Fatalf("%s: CONNECT api.example.com = %d, want 200 (YAML allowlist)", when, got)
		}
		if got := connectStatus(t, h, pverHost+":443"); got != http.StatusForbidden {
			t.Fatalf("%s: CONNECT %s = %d, want 403 (not in the YAML)", when, pverHost, got)
		}
	}
	assertImportedOnce := func(when string) {
		t.Helper()
		authors := policyVersionAuthors(t, h.ControlPlaneStateDB())
		if len(authors) != 1 || authors[0] != "system:import/import" {
			t.Fatalf("%s: policy versions = %v, want exactly version 1 by system:import/import", when, authors)
		}
		var imports int
		for _, r := range h.AdminAuditRows() {
			if r.Action == "policy.initial_import" {
				imports++
				if r.AuthMethod != "system" {
					t.Errorf("%s: policy.initial_import auth_method = %q, want system", when, r.AuthMethod)
				}
			}
		}
		if imports != 1 {
			t.Fatalf("%s: %d policy.initial_import audit rows, want 1", when, imports)
		}
	}

	assertYAMLEnforced("first start")
	assertImportedOnce("first start")

	h.CP().Stop()
	h.CP().Start()
	assertYAMLEnforced("after a restart")
	assertImportedOnce("after a restart")
}

// policyVersionAuthors reads every stored version, oldest first, as
// "<author_sub>/<source>", read-only.
func policyVersionAuthors(t *testing.T, path string) []string {
	t.Helper()
	db, err := cpstate.OpenReadOnly(context.Background(), path, controlplane.StateMigrations())
	if err != nil {
		t.Fatalf("open the state db: %v", err)
	}
	defer func() { _ = db.Close() }()
	rows, err := db.SQL().Query("SELECT author_sub, source FROM policy_versions ORDER BY version")
	if err != nil {
		t.Fatalf("read policy_versions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var sub, source string
		if err := rows.Scan(&sub, &source); err != nil {
			t.Fatalf("scan policy_versions: %v", err)
		}
		out = append(out, sub+"/"+source)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read policy_versions: %v", err)
	}
	return out
}

// The versioned publish scenario (W-P1-PVER-02): with --policy-store=versioned
// a dashboard policy save creates version 2 instead of rewriting the YAML and
// workers enforce it; an llmProviders save creates version 3 that carries the
// policy edit. In console.auth none both are authored "anonymous".

func policyStorePublishOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

func policyStoreDashboardPublish(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)
	if got := connectStatus(t, h, pverHost+":443"); got != http.StatusForbidden {
		t.Fatalf("imported v1: CONNECT %s = %d, want 403", pverHost, got)
	}

	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := h.CP().GetJSON("/dashboard/api/policy", &cur); err != nil {
		t.Fatal(err)
	}
	edit := map[string]any{
		"allowlist": append(cur.Allowlist, map[string]any{"domain": pverHost}),
		"denylist":  cur.Denylist,
	}
	if err := h.CP().PostJSON("/dashboard/api/policy", edit, nil); err != nil {
		t.Fatalf("dashboard policy save: %v", err)
	}
	h.Eventually("workers enforce the published version 2", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Errorf("v2: CONNECT api.example.com = %d, want 200 (kept from v1)", got)
	}

	providers := []map[string]any{{
		"name": "pver", "baseURL": "https://llm.example.com/v1", "model": "m1", "apiKeyEnv": "PVER_LLM_KEY",
	}}
	if err := h.CP().PostJSON("/dashboard/api/llmproviders", providers, nil); err != nil {
		t.Fatalf("dashboard llmProviders save: %v", err)
	}
	var view struct {
		Providers []struct {
			Name string `json:"name"`
		} `json:"providers"`
	}
	if err := h.CP().GetJSON("/dashboard/api/llmproviders", &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Providers) != 1 || view.Providers[0].Name != "pver" {
		t.Fatalf("llmProviders view = %+v, want the published registry", view.Providers)
	}

	want := []string{"system:import/import", "anonymous/policy", "anonymous/llmproviders"}
	if got := policyVersionAuthors(t, h.ControlPlaneStateDB()); !slices.Equal(got, want) {
		t.Fatalf("policy versions = %v, want %v", got, want)
	}
	// Version 3 carried the policy edit: the host stays allowed.
	if got := connectStatus(t, h, pverHost+":443"); got != http.StatusOK {
		t.Errorf("v3: CONNECT %s = %d, want 200 (carried from v2)", pverHost, got)
	}
}

// The mirror and drift scenario (W-P1-PVER-05): with --policy-store=versioned
// a dashboard save is mirrored into the served YAML. A hand edit of the YAML's
// policy block is not served: the dashboard reports drift and admin audit
// records one config.external_change row (before v<head>:..., after file:...).
// Putting the file back clears the drift.

func policyMirrorOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore(), harness.WithAdminAudit()}
}

// handHost is added to the served YAML by hand; it must never be enforced.
const handHost = "hand.example.com"

func policyStoreMirrorDrift(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)
	h.Upstream(handHost)

	var cur struct {
		Allowlist []map[string]any `json:"allowlist"`
		Denylist  []map[string]any `json:"denylist"`
	}
	if err := h.CP().GetJSON("/dashboard/api/policy", &cur); err != nil {
		t.Fatal(err)
	}
	edit := map[string]any{"allowlist": append(cur.Allowlist, map[string]any{"domain": pverHost}), "denylist": cur.Denylist}
	if err := h.CP().PostJSON("/dashboard/api/policy", edit, nil); err != nil {
		t.Fatalf("dashboard policy save: %v", err)
	}
	h.Eventually("workers enforce the published version 2", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})
	mirrored := h.ReadControlPlaneConfig()
	if !strings.Contains(mirrored, "domain: "+pverHost) {
		t.Fatalf("the served YAML does not mirror head version 2:\n%s", mirrored)
	}

	drift := func() bool {
		var p struct {
			Drift bool `json:"drift"`
		}
		if err := h.CP().GetJSON("/dashboard/api/policy", &p); err != nil {
			t.Fatal(err)
		}
		return p.Drift
	}
	external := func() []harness.AdminAuditRow {
		var out []harness.AdminAuditRow
		for _, r := range h.AdminAuditRows() {
			if r.Action == externalChangeAction {
				out = append(out, r)
			}
		}
		return out
	}
	if drift() || len(external()) != 0 {
		t.Fatal("the control plane's own mirror write was reported as an external edit")
	}

	h.EditControlPlaneConfig(func(body string) string {
		return strings.Replace(body, "  allowlist:\n", "  allowlist:\n    - domain: "+handHost+"\n", 1)
	})
	h.EventuallyWithin(15*time.Second, "the hand edit is recorded as config.external_change", func() bool {
		return len(external()) == 1
	})
	row := external()[0]
	if row.AuthMethod != "system" || row.Target != "policy" ||
		!strings.HasPrefix(row.BeforeHash, "v2:") || !strings.HasPrefix(row.AfterHash, "file:") {
		t.Fatalf("external change row = %+v, want system/policy, before v2:<doc_sha256>, after file:<sha256>", row)
	}
	if !drift() {
		t.Fatal("GET /dashboard/api/policy drift = false after a hand edit")
	}
	if got := connectStatus(t, h, handHost+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT %s = %d, want 403 (a hand edit is never served)", handHost, got)
	}

	h.EditControlPlaneConfig(func(string) string { return mirrored })
	h.EventuallyWithin(15*time.Second, "drift clears with the YAML back at head", func() bool {
		return !drift()
	})
	if n := len(external()); n != 1 {
		t.Fatalf("%d config.external_change rows, want 1", n)
	}
}
