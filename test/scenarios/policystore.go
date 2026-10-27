package scenarios

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/controlplane"
	"github.com/ethosagent/warden/internal/cpstate"
	"github.com/ethosagent/warden/test/harness"
)

// The versioned policy store scenario (W-P1-PVER-01): a control plane started
// with --policy-store=versioned and an empty store enforces the served YAML
// exactly as file mode does; once another process (standing in for the CLI)
// appends version 1 and moves the head, workers enforce the head version
// within the control plane's reload tick plus one long-poll cycle, and the YAML
// is no longer what is served.

func policyStoreOpts() []harness.Option {
	return []harness.Option{harness.WithVersionedPolicyStore()}
}

// pverHost is allowed only by the head version, never by the YAML.
const pverHost = "pver.example.com"

func policyStoreVersioned(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)

	// Empty store: the YAML allowlist, default-deny for everything else.
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Fatalf("empty store: CONNECT api.example.com = %d, want 200 (YAML allowlist)", got)
	}
	if got := connectStatus(t, h, pverHost+":443"); got != http.StatusForbidden {
		t.Fatalf("empty store: CONNECT %s = %d, want 403 (not in the YAML)", pverHost, got)
	}

	// Version 1, written out of process: pver allowed, llm.example.com dropped.
	appendPolicyVersion(t, h.ControlPlaneStateDB(),
		`{"allowlist":[{"domain":"api.example.com"},{"domain":"`+pverHost+`"}],"denylist":null}`)

	h.Eventually("workers enforce head version 1", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})
	if got := connectStatus(t, h, "llm.example.com:443"); got != http.StatusForbidden {
		t.Errorf("head v1: CONNECT llm.example.com = %d, want 403 (the YAML allowlist is no longer served)", got)
	}
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusOK {
		t.Errorf("head v1: CONNECT api.example.com = %d, want 200", got)
	}
}

// policyStoreFleetVersion (W-P1-PVER-10): the out-of-process writer records
// version 1 with no served ETag, so the control plane's Refresh appends the
// publish-log row for the ETag it actually serves (reason external), and the
// fleet view maps every up-to-date worker's heartbeat ETag to version 1
// instead of showing it as unknown.
func policyStoreFleetVersion(t *testing.T, h *harness.H) {
	h.Upstream(pverHost)
	appendPolicyVersion(t, h.ControlPlaneStateDB(),
		`{"allowlist":[{"domain":"api.example.com"},{"domain":"`+pverHost+`"}],"denylist":null}`)
	h.Eventually("workers enforce head version 1", func() bool {
		return connectStatus(t, h, pverHost+":443") == http.StatusOK
	})

	type worker struct {
		ProxyID       string `json:"proxyID"`
		PolicyETag    string `json:"policyETag"`
		PolicyVersion int64  `json:"policyVersion"`
		Behind        bool   `json:"behind"`
	}
	var last []worker
	h.Eventually("every worker shows policy version 1, up to date", func() bool {
		// Workers heartbeat on the harness's fake clock: one beat per advance.
		h.Clock().Advance(time.Second)
		last = nil
		if err := h.CP().GetJSON("/dashboard/api/workers", &last); err != nil || len(last) == 0 {
			return false
		}
		for _, w := range last {
			if w.PolicyETag == "" || w.PolicyVersion != 1 || w.Behind {
				return false
			}
		}
		return true
	})
	if len(last) == 0 {
		t.Fatalf("fleet view lists no workers")
	}
}

// appendPolicyVersion appends docJSON as version 1 on an empty store the way an
// out-of-process writer does: one BEGIN IMMEDIATE transaction that inserts the
// version, moves the head by compare-and-swap from 0 and appends the publish
// log row.
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
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"BEGIN IMMEDIATE", nil},
		{`INSERT INTO policy_versions (version, parent_version, created_at, author_sub, author_email, author_kind, message, source, doc_json, doc_sha256)
		  VALUES (1, 0, 0, 'cli:harness', '', 'cli', 'scenario', 'import', ?, ?)`, []any{docJSON, hex.EncodeToString(sum[:])}},
		{"UPDATE policy_head SET version = 1 WHERE version = 0", nil},
		{"INSERT INTO policy_publish_log (version, etag, reason, actor_sub, at) VALUES (1, '', 'import', 'cli:harness', 0)", nil},
		{"COMMIT", nil},
	} {
		if _, err := conn.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
}
