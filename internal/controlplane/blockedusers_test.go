package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// blockServer builds a Server with a state DB (file-mode policy) and a log sink.
func blockServer(t *testing.T, logs io.Writer, mod func(*Config)) *Server {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	cfg := Config{
		PolicyPath: writePolicyFile(t, "api.openai.com"),
		State:      openPolicyState(t),
		Logger:     slog.New(slog.NewJSONHandler(logs, nil)),
	}
	if mod != nil {
		mod(&cfg)
	}
	return New(cfg)
}

func wireBlocked(t *testing.T, body []byte) []config.BlockedUser {
	t.Helper()
	var w policyWire
	if err := json.Unmarshal(body, &w); err != nil {
		t.Fatal(err)
	}
	return w.BlockedUsers
}

func TestBlockedUsers_AddWakesLongPoll(t *testing.T) {
	s := blockServer(t, nil, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	_, _, etag := getPolicy(t, ts.URL+"/policy", nil)

	type result struct {
		code int
		body []byte
		at   time.Time
	}
	done := make(chan result, 1)
	go func() {
		code, body, _ := getPolicy(t, ts.URL+"/policy?wait=5s", map[string]string{"If-None-Match": etag})
		done <- result{code, body, time.Now()}
	}()
	start := time.Now()
	if _, err := s.blocks.Add(context.Background(), BlockEntry{Email: "alice@corp.com", Reason: "left the company"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.code != http.StatusOK {
			t.Fatalf("long-poll = %d, want 200", r.code)
		}
		if d := r.at.Sub(start); d > time.Second {
			t.Errorf("long-poll woke after %s, want within 1s", d)
		}
		got := wireBlocked(t, r.body)
		if len(got) != 1 || got[0] != (config.BlockedUser{Email: "alice@corp.com"}) {
			t.Errorf("blockedUsers = %+v, want [{email alice@corp.com}]", got)
		}
		if strings.Contains(string(r.body), "reason") || strings.Contains(string(r.body), "left the company") {
			t.Errorf("wire carries the reason: %s", r.body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("long-poll waiter not woken by Add")
	}
}

func TestBlockedUsers_RemoveRestoresETag(t *testing.T) {
	s := blockServer(t, nil, nil)
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	ctx := context.Background()
	_, body0, etag0 := getPolicy(t, ts.URL+"/policy", nil)

	id, err := s.blocks.Add(ctx, BlockEntry{Sub: "u-1"}, "cli:tester")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "bu_") || len(id) != 3+16 {
		t.Errorf("id = %q, want bu_ + 16 hex", id)
	}
	if _, _, etag1 := getPolicy(t, ts.URL+"/policy", nil); etag1 == etag0 {
		t.Fatal("Add did not change the ETag")
	}
	var changes int
	s.blocks.OnChange(func() { changes++ })
	if err := s.blocks.Remove(ctx, id, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Errorf("OnChange ran %d times after Remove, want 1", changes)
	}
	_, body2, etag2 := getPolicy(t, ts.URL+"/policy", nil)
	if etag2 != etag0 || !bytes.Equal(body2, body0) {
		t.Errorf("after Add+Remove ETag %s body %s; want original %s %s", etag2, body2, etag0, body0)
	}
	if err := s.blocks.Remove(ctx, "bu_0000000000000000", "cli:tester"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove(unknown) = %v, want ErrNotFound", err)
	}
	if changes != 1 {
		t.Errorf("a failed Remove ran OnChange (%d)", changes)
	}
}

func TestBlockedUsers_LoadErrorKeepsLastGood(t *testing.T) {
	var logs syncBuffer
	s := blockServer(t, &logs, func(c *Config) {
		c.AlertDBPath = filepath.Join(t.TempDir(), "warden-alerts.db")
	})
	ctx := context.Background()
	if _, err := s.blocks.Add(ctx, BlockEntry{Email: "alice@corp.com"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	wire0, etag0, _, _ := s.policy.snapshot()
	if len(wire0.BlockedUsers) != 1 {
		t.Fatalf("setup: blockedUsers = %+v", wire0.BlockedUsers)
	}

	sqlDB := s.cfg.State.SQL()
	if _, err := sqlDB.Exec(`ALTER TABLE blocked_users RENAME TO blocked_users_gone`); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		s.policy.Refresh()
	}
	wire1, etag1, _, _ := s.policy.snapshot()
	if etag1 != etag0 || len(wire1.BlockedUsers) != 1 {
		t.Errorf("a read error changed the served policy: etag %s -> %s, blockedUsers %+v", etag0, etag1, wire1.BlockedUsers)
	}
	if n := strings.Count(logs.String(), blockLoadFailedMsg); n != 1 {
		t.Errorf("%s logged %d times across 3 refreshes, want 1\n%s", blockLoadFailedMsg, n, logs.String())
	}
	if strings.Contains(logs.String(), "alice@corp.com") {
		t.Error("log line carries an entry value")
	}
	alerts := s.currentManager().ListAlerts(10)
	if len(alerts) != 1 || alerts[0].Count != 1 || alerts[0].Severity.String() != "high" {
		t.Errorf("alerts = %+v, want one high-severity finding fired once", alerts)
	}

	// A good load ends the episode: the next failure reports again.
	if _, err := sqlDB.Exec(`ALTER TABLE blocked_users_gone RENAME TO blocked_users`); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	if _, err := sqlDB.Exec(`ALTER TABLE blocked_users RENAME TO blocked_users_gone`); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	if n := strings.Count(logs.String(), blockLoadFailedMsg); n != 2 {
		t.Errorf("%s logged %d times across two episodes, want 2", blockLoadFailedMsg, n)
	}
}

func TestBlockedUsers_LoadErrorWithoutPipeline(t *testing.T) {
	var logs syncBuffer
	s := blockServer(t, &logs, nil) // no AlertDBPath: the log line is the signal
	if _, err := s.cfg.State.SQL().Exec(`ALTER TABLE blocked_users RENAME TO blocked_users_gone`); err != nil {
		t.Fatal(err)
	}
	s.policy.Refresh()
	if n := strings.Count(logs.String(), blockLoadFailedMsg); n != 1 {
		t.Errorf("%s logged %d times, want 1", blockLoadFailedMsg, n)
	}
}

func TestBlockedUsers_Validation(t *testing.T) {
	s := blockServer(t, nil, nil)
	ctx := context.Background()
	add := func(e BlockEntry) error { _, err := s.blocks.Add(ctx, e, "cli:tester"); return err }

	if err := add(BlockEntry{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("neither field: %v, want ErrInvalid", err)
	}
	if err := add(BlockEntry{Email: "no-at-sign"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("email without @: %v, want ErrInvalid", err)
	}
	if err := add(BlockEntry{Sub: "u", Reason: strings.Repeat("x", 513)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long reason: %v, want ErrInvalid", err)
	}
	if _, err := s.blocks.Add(ctx, BlockEntry{Sub: "u"}, " "); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty actor: %v, want ErrInvalid", err)
	}
	if err := add(BlockEntry{Email: "Alice@Corp.com"}); err != nil {
		t.Fatal(err)
	}
	if err := add(BlockEntry{Email: " alice@CORP.com "}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("same email, other case: %v, want ErrDuplicate", err)
	}
	if err := add(BlockEntry{Sub: "s-1", Email: "other@corp.com"}); err != nil {
		t.Fatal(err)
	}
	if err := add(BlockEntry{Sub: "s-1"}); !errors.Is(err, ErrDuplicate) {
		t.Errorf("same sub: %v, want ErrDuplicate", err)
	}
	wire, err := s.blocks.Wire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []config.BlockedUser{{Email: "alice@corp.com"}, {Sub: "s-1", Email: "other@corp.com"}}
	if len(wire) != 2 || wire[0] != want[0] || wire[1] != want[1] {
		t.Errorf("Wire = %+v, want %+v (normalized, sorted)", wire, want)
	}

	t.Run("count", func(t *testing.T) {
		s := blockServer(t, nil, nil)
		fillBlocks(t, s, config.MaxBlockedUsers, 0)
		_, err := s.blocks.Add(context.Background(), BlockEntry{Sub: "one-too-many"}, "cli:tester")
		if !errors.Is(err, ErrTooMany) {
			t.Errorf("entry %d: %v, want ErrTooMany", config.MaxBlockedUsers+1, err)
		}
	})
	t.Run("bytes", func(t *testing.T) {
		s := blockServer(t, nil, nil)
		// About 2000 entries of ~270 bytes each fill MaxBlockedUsersBytes.
		fillBlocks(t, s, 2000, 250)
		_, err := s.blocks.Add(context.Background(), BlockEntry{Sub: strings.Repeat("z", 250)}, "cli:tester")
		if !errors.Is(err, ErrTooMany) {
			t.Errorf("list over MaxBlockedUsersBytes: %v, want ErrTooMany", err)
		}
	})
}

// fillBlocks inserts n rows straight into the table (bypassing Add's limits),
// each sub being its index plus subLen bytes of padding.
func fillBlocks(t *testing.T, s *Server, n, subLen int) {
	t.Helper()
	tx, err := s.cfg.State.SQL().Begin()
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("p", subLen)
	for i := range n {
		num := strconv.Itoa(i)
		id := "bu_" + strings.Repeat("0", 16-len(num)) + num
		if _, err := tx.Exec(`INSERT INTO blocked_users (id, sub, created_by, created_at) VALUES (?, ?, 'x', 0)`,
			id, num+pad); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestBlockedUsers_OutsidePolicyVersions(t *testing.T) {
	s := newVersionedServer(t, writePolicyFile(t, "api.openai.com"), nil)
	ctx := context.Background()
	if _, err := s.blocks.Add(ctx, BlockEntry{Email: "alice@corp.com", Reason: "r-secret-reason"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}

	doc1 := docWithAllow(baseDoc(t, s), "v1.example.com")
	// A doc that wrongly carries a list must still be stored without it.
	doc1.BlockedUsers = []config.BlockedUser{{Sub: "smuggled-sub"}}
	if _, changed, err := s.versions.Create(ctx, doc1, testAuthor, "v1", SourcePolicy, 0); err != nil || !changed {
		t.Fatalf("Create v1 = %v, %v", changed, err)
	}
	if _, changed, err := s.versions.Create(ctx, docWithAllow(baseDoc(t, s), "v2.example.com"), testAuthor, "v2", SourcePolicy, 1); err != nil || !changed {
		t.Fatalf("Create v2 = %v, %v", changed, err)
	}
	// Roll back to v1 (a new version carrying v1's doc).
	v1, err := s.versions.Get(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := s.versions.Create(ctx, v1.Doc, testAuthor, "rollback", SourceRollback, 2); err != nil || !changed {
		t.Fatalf("rollback = %v, %v", changed, err)
	}
	wire, _, _, _ := s.policy.snapshot()
	if got := wire.BlockedUsers; len(got) != 1 || got[0] != (config.BlockedUser{Email: "alice@corp.com"}) {
		t.Errorf("blockedUsers after versions and rollback = %+v, want alice only", got)
	}
	rows, err := s.cfg.State.SQL().Query(`SELECT doc_json FROM policy_versions`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var doc string
		if err := rows.Scan(&doc); err != nil {
			t.Fatal(err)
		}
		n++
		for _, bad := range []string{"blockedUsers", "alice@corp.com", "smuggled-sub", "r-secret-reason"} {
			if strings.Contains(doc, bad) {
				t.Errorf("doc_json holds %q: %s", bad, doc)
			}
		}
	}
	if n != 3 {
		t.Errorf("policy_versions rows = %d, want 3", n)
	}
}

func TestBlockedUsers_NoStateUnchanged(t *testing.T) {
	wantBody, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantETag, err := os.ReadFile(filepath.Join("testdata", "policy_overlay_none.golden.etag"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Config{PolicyPath: filepath.Join("testdata", "policy_overlay_none.yaml")})
	if s.blocks != nil {
		t.Error("a CP without State built a block store")
	}
	if fps := s.policy.overlayFingerprints(); len(fps) != 0 {
		t.Errorf("overlay fingerprints without State = %v, want none", fps)
	}
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	code, body, etag := getPolicy(t, ts.URL+"/policy", nil)
	if code != http.StatusOK || !bytes.Equal(body, wantBody) || etag != strings.TrimSpace(string(wantETag)) {
		t.Errorf("/policy without State differs from the golden: %d %s %s", code, body, etag)
	}
}

// TestBlockedUsers_Fingerprint: the overlay reports a 16-hex fingerprint of the
// list, empty when the list is empty.
func TestBlockedUsers_Fingerprint(t *testing.T) {
	s := blockServer(t, nil, nil)
	if fp := s.policy.overlayFingerprints()[blockedUsersOverlayName]; fp != "" {
		t.Errorf("empty list fingerprint = %q, want empty", fp)
	}
	if _, err := s.blocks.Add(context.Background(), BlockEntry{Sub: "u"}, "cli:tester"); err != nil {
		t.Fatal(err)
	}
	if fp := s.policy.overlayFingerprints()[blockedUsersOverlayName]; len(fp) != 16 {
		t.Errorf("fingerprint = %q, want 16 hex", fp)
	}
}

// TestBlockedUsers_StoreWithoutServer: the CLI builds a store over a DB it opened
// itself, with no policy refresh hook, and reads its own writes.
func TestBlockedUsers_StoreWithoutServer(t *testing.T) {
	db, err := cpstate.Open(context.Background(), filepath.Join(t.TempDir(), "warden-cp.db"), BlockMigrations())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	st := NewBlockStore(db, BlockStoreOptions{})
	ctx := context.Background()
	id, err := st.Add(ctx, BlockEntry{Sub: "u-1", Email: "A@b.co", Reason: "why"}, "system:offboarding")
	if err != nil {
		t.Fatal(err)
	}
	list, err := st.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	e := list[0]
	if e.ID != id || e.Sub != "u-1" || e.Email != "a@b.co" || e.Reason != "why" || e.CreatedBy != "system:offboarding" || e.CreatedAt.IsZero() {
		t.Errorf("entry = %+v", e)
	}
	if err := st.Remove(ctx, id, "cli:x"); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.List(ctx); len(list) != 0 {
		t.Errorf("List after Remove = %+v", list)
	}
}
