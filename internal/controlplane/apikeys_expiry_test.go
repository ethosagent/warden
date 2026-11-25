package controlplane

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/apikeys"
	"github.com/ethosagent/warden/internal/integration"
)

// mintTTL creates a key with the given lifetime and returns its id and plaintext.
func (e *keyEnv) mintTTL(sub string, ttl time.Duration, name string) (id, plaintext string) {
	e.t.Helper()
	tok, k, err := e.store.Create(context.Background(), apikeys.CreateParams{
		Name: name, OwnerIss: keyOwnerIss, OwnerSub: sub, OwnerEmail: sub + "@example.com",
		OwnerGroups: []string{groupEditor}, Scopes: []apikeys.Scope{"policy:read"},
		TTL: ttl, MaxTTL: 8760 * time.Hour, MaxActive: 25,
	})
	if err != nil {
		e.t.Fatalf("mint %s: %v", name, err)
	}
	return k.ID, tok
}

// TestAPIKeyExpiringFinding: with a fake clock 6 days before expiry the fake
// publisher gets exactly one api_key_expiring Finding, and none at 8 days; a
// revoked or already expired key is not reported, and the Finding names the key
// without any secret.
func TestAPIKeyExpiringFinding(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	pub := &recFindings{}
	e.srv.findings = pub
	ctx := context.Background()

	id, plaintext := e.mintTTL("alice", 30*24*time.Hour, "ci-deploy")
	revokedID, _ := e.mintTTL("bob", 30*24*time.Hour, "old")
	if err := e.store.Revoke(ctx, revokedID, "test"); err != nil {
		t.Fatal(err)
	}
	e.mintTTL("carol", 2*time.Hour, "short") // expires in 2h: reported once inside the window

	// 8 days before expiry of the 30-day keys: only the 2h key is inside 7 days.
	e.clk.Advance(22 * 24 * time.Hour)
	// carol's key expired long ago by now: not reported.
	n, err := e.srv.scanExpiringAPIKeys(ctx)
	if err != nil || n != 0 || len(pub.byRule(findingAPIKeyExpiring)) != 0 {
		t.Fatalf("scan at 8 days = %d, %v, findings %v; want none", n, err, pub.byRule(findingAPIKeyExpiring))
	}

	e.clk.Advance(2 * 24 * time.Hour) // 6 days left
	n, err = e.srv.scanExpiringAPIKeys(ctx)
	got := pub.byRule(findingAPIKeyExpiring)
	if err != nil || n != 1 || len(got) != 1 {
		t.Fatalf("scan at 6 days = %d, %v, findings %v; want exactly one", n, err, got)
	}
	f := got[0]
	if f.Severity != integration.SevMedium || f.DedupKey != findingAPIKeyExpiring+":"+id {
		t.Errorf("finding = %+v, want medium with dedup key api_key_expiring:%s", f, id)
	}
	for _, want := range []string{"key_id=" + id, `name="ci-deploy"`, `owner_email="alice@example.com"`, "expires_at="} {
		if !strings.Contains(string(f.Evidence), want) {
			t.Errorf("evidence %q lacks %q", f.Evidence, want)
		}
	}
	if f.Subject.User != "alice" {
		t.Errorf("subject user = %q, want the owner's sub", f.Subject.User)
	}
	secret := plaintext[strings.LastIndex(plaintext, "_")+1:]
	if all := f.Summary + string(f.Evidence) + f.DedupKey; strings.Contains(all, secret) || strings.Contains(all, "wak_") {
		t.Errorf("finding leaks key material: %q", all)
	}

	// Revoked inside the window: no longer reported.
	if err := e.store.Revoke(ctx, id, "test"); err != nil {
		t.Fatal(err)
	}
	if n, _ := e.srv.scanExpiringAPIKeys(ctx); n != 0 {
		t.Fatalf("scan after revoke = %d, want 0", n)
	}
}

// TestAPIKeyExpiryReportedOnce: a key already warned about is not published
// again by later scans, a new key is, a key whose expires_at moved is, and a key
// that left the window and came back is warned about again.
func TestAPIKeyExpiryReportedOnce(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	pub := &recFindings{}
	e.srv.findings = pub
	ctx := context.Background()
	scan := func(want int, why string) {
		t.Helper()
		n, err := e.srv.scanExpiringAPIKeys(ctx)
		if err != nil || n != want {
			t.Fatalf("%s: scan = %d, %v; want %d", why, n, err, want)
		}
	}
	id, _ := e.mintTTL("alice", 30*24*time.Hour, "ci")
	e.clk.Advance(24 * 24 * time.Hour)
	scan(1, "first scan inside the window")
	e.clk.Advance(apiKeyExpiryInterval)
	scan(0, "second hourly scan")
	scan(0, "third scan")

	e.mintTTL("bob", 30*24*time.Hour, "deploy")
	scan(0, "a key outside the window") // bob's key expires in 30 days
	e.mintTTL("carol", 3*24*time.Hour, "short")
	scan(1, "a new key inside the window")

	// expires_at moved (a database edit): reported again.
	if _, err := e.db.SQL().ExecContext(ctx, `UPDATE api_keys SET expires_at = expires_at + 3600 WHERE id = ?`, id); err != nil {
		t.Fatal(err)
	}
	scan(1, "a changed expires_at")
	scan(0, "after the change was reported")
	if got := len(pub.byRule(findingAPIKeyExpiring)); got != 3 {
		t.Fatalf("findings = %d, want 3", got)
	}

	// Left the window (expiry pushed out), then back in: warned again.
	if _, err := e.db.SQL().ExecContext(ctx, `UPDATE api_keys SET expires_at = expires_at + ? WHERE id = ?`, 30*24*3600, id); err != nil {
		t.Fatal(err)
	}
	scan(0, "pushed out of the window")
	if _, err := e.db.SQL().ExecContext(ctx, `UPDATE api_keys SET expires_at = expires_at - ? WHERE id = ?`, 30*24*3600, id); err != nil {
		t.Fatal(err)
	}
	scan(1, "back in the window")
}

// TestAPIKeyExpiryLoop: the job scans at start and then once an hour of the
// control plane's clock, publishing only what is new, and stops on cancel.
func TestAPIKeyExpiryLoop(t *testing.T) {
	e := newKeyEnv(t, keyEnvOpts{})
	pub := &recFindings{}
	e.srv.findings = pub
	e.mintTTL("alice", 30*24*time.Hour, "ci")
	e.clk.Advance(24 * 24 * time.Hour) // 6 days left

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go e.srv.runAPIKeyExpiry(ctx, done)
	waitFor := func(desc string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", desc)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitFor("the first scan", func() bool { return len(pub.byRule(findingAPIKeyExpiring)) == 1 })
	waitFor("the hourly timer", func() bool { return e.clk.PendingTimers() > 0 })
	e.mintTTL("bob", 2*24*time.Hour, "new")
	waitFor("the hourly tick to publish only the new key", func() bool {
		e.clk.Advance(apiKeyExpiryInterval)
		time.Sleep(5 * time.Millisecond)
		return len(pub.byRule(findingAPIKeyExpiring)) == 2
	})
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop on cancel")
	}
	if got := len(pub.byRule(findingAPIKeyExpiring)); got != 2 {
		t.Fatalf("findings = %d, want 2 (the old key is not republished)", got)
	}
}
