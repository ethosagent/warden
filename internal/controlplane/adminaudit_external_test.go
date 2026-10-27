package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethosagent/warden/internal/adminaudit"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/cpstate"
)

// fakeRecorder captures what the CP records; err, when set, fails every call.
type fakeRecorder struct {
	mu  sync.Mutex
	got []adminaudit.Input
	err error
}

func (f *fakeRecorder) Record(_ context.Context, in adminaudit.Input) (adminaudit.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return adminaudit.Entry{}, f.err
	}
	f.got = append(f.got, in)
	return adminaudit.Entry{}, nil
}

func (f *fakeRecorder) inputs() []adminaudit.Input {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]adminaudit.Input(nil), f.got...)
}

// newExternalAuditServer builds a file-mode CP whose admin audit records into
// rec, primed exactly as New primes it when console.adminAudit is enabled.
func newExternalAuditServer(t *testing.T, path string, rec adminaudit.Recorder, logs *syncBuffer) *Server {
	t.Helper()
	cfg := Config{PolicyPath: path, Logger: slog.New(slog.DiscardHandler)}
	if logs != nil {
		cfg.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	}
	srv := New(cfg)
	srv.auditRec = rec
	srv.primeExternalEdit()
	return srv
}

// editExternally replaces the served file the way an operator's tool would
// (temp file + rename), outside any CP writer, and returns its file: hash.
func editExternally(t *testing.T, path, body string) string {
	t.Helper()
	tmp := path + ".edit"
	if err := os.WriteFile(tmp, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(body))
	return "file:" + hex.EncodeToString(sum[:])
}

func allowOnlyBody(domain string) string {
	return "policy:\n  allowlist:\n    - domain: " + domain + "\n"
}

func TestAdminAuditExternalEditFileMode(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	start := "file:" + sha256Hex(readFile(t, path))
	rec := &fakeRecorder{}
	srv := newExternalAuditServer(t, path, rec, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	ctx := context.Background()

	srv.reloadPolicy(ctx) // nothing changed since start
	if got := rec.inputs(); len(got) != 0 {
		t.Fatalf("unchanged file recorded %d rows", len(got))
	}

	first := editExternally(t, path, allowOnlyBody("one.example.com"))
	srv.reloadPolicy(ctx)
	srv.reloadPolicy(ctx) // the same content seen again on the next tick
	got := rec.inputs()
	if len(got) != 1 {
		t.Fatalf("after one external edit: %d rows, want 1", len(got))
	}
	want := adminaudit.Input{
		Actor:      adminaudit.Actor{Sub: "system"},
		ActorRole:  "system",
		AuthMethod: adminaudit.AuthMethodSystem,
		Action:     "config.external_change",
		Target:     "policy",
		Outcome:    adminaudit.OutcomeOK,
		BeforeHash: start,
		AfterHash:  first,
	}
	if fmt.Sprint(got[0]) != fmt.Sprint(want) {
		t.Fatalf("row = %+v\nwant  %+v", got[0], want)
	}
	// The external change is served, not blocked.
	if d := fetchPolicyDomains(t, ts.URL); !contains(d, "one.example.com") {
		t.Fatalf("served policy = %v, want the external edit", d)
	}

	second := editExternally(t, path, allowOnlyBody("two.example.com"))
	srv.reloadPolicy(ctx)
	got = rec.inputs()
	if len(got) != 2 || got[1].BeforeHash != first || got[1].AfterHash != second {
		t.Fatalf("after a second edit: %+v, want a row %s -> %s", got, first, second)
	}

	// Going back to content already recorded writes nothing.
	editExternally(t, path, allowOnlyBody("one.example.com"))
	srv.reloadPolicy(ctx)
	if got := rec.inputs(); len(got) != 2 {
		t.Fatalf("content seen before recorded again: %d rows, want 2", len(got))
	}
}

func TestAdminAuditOwnWriteNotExternal(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	rec := &fakeRecorder{}
	srv := newExternalAuditServer(t, path, rec, nil)
	ctx := context.Background()

	if err := srv.writePolicy(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "saved.example.com", Port: 443}},
	}); err != nil {
		t.Fatalf("writePolicy: %v", err)
	}
	srv.reloadPolicy(ctx)
	if err := srv.writeSettings(config.SettingsWire{
		MCP: &config.MCPSettings{Enabled: true, Mode: "enforce"},
	}); err != nil {
		t.Fatalf("writeSettings: %v", err)
	}
	// Two CP writes between ticks: only the last written hash is the file's.
	if err := srv.writePolicy(config.Policy{
		Allowlist: []config.AllowlistEntry{{Domain: "saved2.example.com", Port: 443}},
	}); err != nil {
		t.Fatalf("writePolicy: %v", err)
	}
	srv.reloadPolicy(ctx)
	if got := rec.inputs(); len(got) != 0 {
		t.Fatalf("CP writes recorded as external changes: %+v", got)
	}

	// An external edit after a CP write is still caught, and so is reverting
	// it to the bytes the CP last wrote.
	cpBody := readFile(t, path)
	cpBytes := "file:" + sha256Hex(cpBody)
	ext := editExternally(t, path, allowOnlyBody("hand.example.com"))
	srv.reloadPolicy(ctx)
	editExternally(t, path, cpBody)
	srv.reloadPolicy(ctx)
	got := rec.inputs()
	if len(got) != 2 || got[0].AfterHash != ext || got[1].BeforeHash != ext || got[1].AfterHash != cpBytes {
		t.Fatalf("rows = %+v, want %s then a revert to %s", got, ext, cpBytes)
	}
}

func TestExternalChangeDisabled(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	srv := New(Config{PolicyPath: path}) // console.adminAudit off: AdminAudit nil
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	editExternally(t, path, allowOnlyBody("hand.example.com"))
	srv.reloadPolicy(context.Background())
	if srv.auditRec != nil {
		t.Fatal("a recorder is wired with admin audit disabled")
	}
	if srv.ext.lastLoaded != "" {
		t.Fatal("the external-edit check ran with admin audit disabled")
	}
	if d := fetchPolicyDomains(t, ts.URL); !contains(d, "hand.example.com") {
		t.Fatalf("served policy = %v, want the external edit (unchanged behaviour)", d)
	}
}

func TestExternalChangeNoContent(t *testing.T) {
	dir := t.TempDir()
	state, err := cpstate.Open(context.Background(), filepath.Join(dir, "warden-cp.db"), StateMigrations())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	store, err := adminaudit.Open(context.Background(), state, adminaudit.OpenOptions{KeyFile: filepath.Join(dir, "cp-audit.key")})
	if err != nil {
		t.Fatal(err)
	}
	path := writePolicyFile(t, "api.openai.com")
	var logs syncBuffer
	srv := New(Config{PolicyPath: path, AdminAudit: store, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})

	const marker = "content-marker-7f3a.example.com"
	after := editExternally(t, path, allowOnlyBody(marker)+"# a secret-looking comment sk-live-123\n")
	srv.reloadPolicy(context.Background())

	items, err := store.List(context.Background(), adminaudit.Filter{Action: "config.external_change"}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].AfterHash != after || items[0].Target != "policy" ||
		items[0].AuthMethod != adminaudit.AuthMethodSystem || items[0].Outcome != adminaudit.OutcomeOK ||
		!strings.HasPrefix(items[0].BeforeHash, "file:") {
		t.Fatalf("rows = %+v, want one config.external_change row with after %s", items, after)
	}
	if v, err := store.Verify(context.Background(), adminaudit.VerifyOptions{}); err != nil || !v.OK {
		t.Fatalf("chain does not verify after the row: %+v %v", v, err)
	}
	row := fmt.Sprintf("%+v", items[0])
	out := logs.String()
	for _, leak := range []string{marker, "sk-live-123", path, filepath.Base(path)} {
		if strings.Contains(row, leak) {
			t.Errorf("row contains %q: %s", leak, row)
		}
		if strings.Contains(out, leak) {
			t.Errorf("log contains %q: %s", leak, out)
		}
	}
	if !strings.Contains(out, after) {
		t.Errorf("log line does not carry the new hash: %s", out)
	}
}

func TestExternalChangeRecorderErrorStillServes(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	rec := &fakeRecorder{err: errors.New("disk full")}
	var logs syncBuffer
	srv := newExternalAuditServer(t, path, rec, &logs)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	editExternally(t, path, allowOnlyBody("hand.example.com"))
	srv.reloadPolicy(context.Background())
	if d := fetchPolicyDomains(t, ts.URL); !contains(d, "hand.example.com") {
		t.Fatalf("served policy = %v, want the external edit despite the audit failure", d)
	}
	if out := logs.String(); !strings.Contains(out, `"level":"ERROR"`) || !strings.Contains(out, "disk full") {
		t.Fatalf("recorder error not logged at ERROR: %s", out)
	}
}

func TestAuditExternalChangeDedupIsBounded(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	rec := &fakeRecorder{}
	srv := newExternalAuditServer(t, path, rec, nil)
	ctx := context.Background()
	hash := func(i int) string { return fmt.Sprintf("file:%064x", i) }

	for i := 0; i <= externalSeenMax; i++ { // 65 distinct hashes
		srv.auditExternalChange(ctx, "policy", "file:x", hash(i))
	}
	srv.auditExternalChange(ctx, "policy", "file:x", hash(externalSeenMax)) // still remembered
	if got := len(rec.inputs()); got != externalSeenMax+1 {
		t.Fatalf("rows = %d, want %d", got, externalSeenMax+1)
	}
	srv.auditExternalChange(ctx, "policy", "file:x", hash(0)) // evicted: recorded again
	if got := len(rec.inputs()); got != externalSeenMax+2 {
		t.Fatalf("evicted hash not recorded again: rows = %d", got)
	}

	// A failed record is not remembered, so a later call retries it.
	rec.err = errors.New("busy")
	srv.auditExternalChange(ctx, "policy", "file:x", "file:retry")
	rec.err = nil
	srv.auditExternalChange(ctx, "policy", "file:x", "file:retry")
	if got := rec.inputs(); got[len(got)-1].AfterHash != "file:retry" {
		t.Fatal("a failed record was remembered as done")
	}

	// Nil recorder: a no-op.
	srv.auditRec = nil
	srv.auditExternalChange(ctx, "policy", "file:x", "file:nil")
}

func TestExternalChangeUnreadableFileRecordsNothing(t *testing.T) {
	path := writePolicyFile(t, "api.openai.com")
	body := readFile(t, path)
	rec := &fakeRecorder{}
	srv := newExternalAuditServer(t, path, rec, nil)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	srv.reloadPolicy(context.Background())
	if got := rec.inputs(); len(got) != 0 {
		t.Fatalf("a missing file recorded %+v", got)
	}
	if d := fetchPolicyDomains(t, ts.URL); !contains(d, "api.openai.com") {
		t.Fatalf("served policy = %v, want last-known-good", d)
	}
	// The same bytes back in place are not a change either.
	editExternally(t, path, body)
	srv.reloadPolicy(context.Background())
	if got := rec.inputs(); len(got) != 0 {
		t.Fatalf("restoring the served bytes recorded %+v", got)
	}
}
