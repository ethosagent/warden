package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

const cacheMaxAge = 12 * time.Hour

// privateDir is a fresh state directory with mode 0700 (t.TempDir follows the
// umask, which the cache refuses when group-writable).
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// withCache turns the cache on for e's provider in a fresh state dir.
func (e *bundleEnv) withCache() string {
	e.t.Helper()
	dir := privateDir(e.t)
	if err := e.rp.SetBundleCache(dir, cacheMaxAge); err != nil {
		e.t.Fatal(err)
	}
	return dir
}

// restarted is a second provider, as after a process restart: same pins and
// clock, same state dir, no bundle applied.
func (e *bundleEnv) restarted(dir string, pins []keys.JWK) (*RemoteProvider, *bytes.Buffer) {
	e.t.Helper()
	rp, err := NewRemoteProvider(e.cp.srv.URL, "tok")
	if err != nil {
		e.t.Fatal(err)
	}
	rp.client, rp.longClient = e.cp.srv.Client(), e.cp.srv.Client()
	if pins == nil {
		pins = e.rp.trust.Pins
	}
	logs := &bytes.Buffer{}
	if err := rp.SetBundleTrust(BundleTrust{
		Pins: pins, Skew: 5 * time.Minute, Expiry: BundleExpiryKeep,
		Now: func() time.Time { return e.now }, Logger: slog.New(slog.NewTextHandler(logs, nil)),
	}); err != nil {
		e.t.Fatal(err)
	}
	if err := rp.SetBundleCache(dir, cacheMaxAge); err != nil {
		e.t.Fatal(err)
	}
	return rp, logs
}

func TestBundleCacheHasNoCredential(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cr3t-value"}
	pol := `{"allowlist":[{"domain":"a.example.com"}],"settings":{"secrets":{"backend":"aws","region":"us-east-1"}}}`
	e.cp.serve(e.sign(e.bundle(1, pol), creds), "c1")
	if err := e.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	path := BundleCachePath(dir)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"secretAccessKey", "SecretAccessKey", "s3cr3t-value", "AKIAEXAMPLE", `"credentials"`} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("the cache file contains %q", s)
		}
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file = %v, %v, want mode 0600", fi, err)
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir = %v, %v, want mode 0700", di, err)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".bundle-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}

	// The restart re-verifies without the sidecar: the policy is enforced, the
	// credential is not there (the worker falls back to env or IAM).
	rp, _ := e.restarted(dir, nil)
	if _, err := rp.LoadCache(); err != nil {
		t.Fatal(err)
	}
	s := rp.Settings()
	if s == nil || s.Secrets == nil || s.Secrets.Backend != "aws" || s.Secrets.AccessKeyID != "" || s.Secrets.SecretAccessKey != "" {
		t.Fatalf("settings after a cache load = %+v, want the aws selector without credentials", s)
	}
}

func TestBundleCacheLoadSeedsAppliedState(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}

	rp, logs := e.restarted(dir, nil)
	vb, err := rp.LoadCache()
	if err != nil || vb.Seq != 5 {
		t.Fatalf("LoadCache = %+v, %v, want seq 5", vb, err)
	}
	p, err := rp.GetPolicy()
	if err != nil || len(p.Allowlist) != 1 || p.Allowlist[0].Domain != "a.example.com" {
		t.Fatalf("policy = %+v, %v", p, err)
	}
	if st := rp.BundleStatus(); !st.Applied || st.Seq != 5 {
		t.Fatalf("status = %+v", st)
	}
	if b, ok := rp.Bundle(); !ok || b.Seq != 5 {
		t.Fatalf("Bundle() = %+v, %v", b, ok)
	}
	if strings.Contains(logs.String(), "a.example.com") {
		t.Fatalf("policy content in logs: %s", logs)
	}

	// A control plane that now serves an older seq is a rollback.
	e.cp.serve(e.sign(e.bundle(3, bundlePolicyB), nil), "e3")
	rp.endpoint = e.cp.srv.URL
	if err := rp.Pull(); !errors.Is(err, bundle.ErrRollback) {
		t.Fatalf("seq 3 after a seq 5 cache: %v, want rollback", err)
	}
	if got, _ := rp.GetPolicy(); got.Allowlist[0].Domain != "a.example.com" {
		t.Fatal("the cached policy was replaced by a rolled-back bundle")
	}
	// The same bundle is unchanged, a newer one applies.
	e.cp.serve(e.sign(e.bundle(5, bundlePolicyA), nil), "e5")
	if changed, err := rp.PollLong(t.Context(), time.Millisecond); err != nil || changed {
		t.Fatalf("same bundle after the cache = %v, %v, want unchanged", changed, err)
	}
	e.cp.serve(e.sign(e.bundle(6, bundlePolicyB), nil), "e6")
	if changed, err := rp.PollLong(t.Context(), time.Millisecond); err != nil || !changed {
		t.Fatalf("seq 6 after the cache = %v, %v, want applied", changed, err)
	}
}

func TestBundleCacheRefusals(t *testing.T) {
	other, err := keysPin(t)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(e *bundleEnv, path string) []keys.JWK // returns pins override
		want   string
	}{
		{"too old", func(e *bundleEnv, _ string) []keys.JWK { e.now = bundleT0.Add(cacheMaxAge + time.Hour); return nil }, "older than"},
		{"expired", func(e *bundleEnv, _ string) []keys.JWK { e.now = bundleT0.Add(25 * time.Hour); return nil }, "expired"},
		{"corrupt", func(_ *bundleEnv, p string) []keys.JWK { _ = os.WriteFile(p, []byte("not json"), 0o600); return nil }, "malformed"},
		{"tampered", func(e *bundleEnv, p string) []keys.JWK {
			raw, _ := os.ReadFile(p)
			_ = os.WriteFile(p, flipPayloadByte(e.t, raw), 0o600)
			return nil
		}, "bad_signature"},
		{"key no longer pinned", func(*bundleEnv, string) []keys.JWK { return []keys.JWK{other} }, "unknown_kid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newBundleEnv(t)
			dir := e.withCache()
			if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
				t.Fatal(err)
			}
			pins := tc.mutate(e, BundleCachePath(dir))
			rp, _ := e.restarted(dir, pins)
			_, err := rp.LoadCache()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadCache = %v, want an error containing %q", err, tc.want)
			}
			if _, gErr := rp.GetPolicy(); gErr == nil {
				t.Fatal("a refused cache installed a policy")
			}
			if _, ok := rp.Bundle(); ok {
				t.Fatal("a refused cache installed a bundle")
			}
			if strings.Contains(err.Error(), "a.example.com") {
				t.Fatalf("error leaks content: %v", err)
			}
		})
	}
}

// keysPin is a pin for a key that signed nothing.
func keysPin(t *testing.T) (keys.JWK, error) {
	t.Helper()
	sg, err := signer.GenerateLocal(keys.AlgEdDSA)
	if err != nil {
		return keys.JWK{}, err
	}
	return keys.PublicJWK(sg.Public(), keys.AlgEdDSA)
}

func TestBundleCacheLoadPreconditions(t *testing.T) {
	e := newBundleEnv(t)
	// Not enabled.
	if _, err := e.rp.LoadCache(); err == nil || errors.Is(err, ErrNoBundleCache) {
		t.Fatalf("LoadCache without a cache = %v", err)
	}
	dir := e.withCache()
	// No file yet.
	if _, err := e.rp.LoadCache(); !errors.Is(err, ErrNoBundleCache) {
		t.Fatalf("LoadCache with no file = %v, want ErrNoBundleCache", err)
	}
	// Boot only: refused once a bundle is applied.
	if err := e.pullSeq(1, bundlePolicyA, "e1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rp.LoadCache(); err == nil || !strings.Contains(err.Error(), "before a bundle is applied") {
		t.Fatalf("LoadCache after apply = %v, want a boot-only refusal", err)
	}
	// Without trust, SetBundleCache is refused; an empty dir or max age too.
	rp, _ := NewRemoteProvider(e.cp.srv.URL, "tok")
	if err := rp.SetBundleCache(dir, time.Hour); err == nil {
		t.Fatal("SetBundleCache without trust succeeded")
	}
	if err := e.rp.SetBundleCache("", time.Hour); err == nil {
		t.Fatal("SetBundleCache with no dir succeeded")
	}
	if err := e.rp.SetBundleCache(dir, 0); err == nil {
		t.Fatal("SetBundleCache with max age 0 succeeded")
	}
	// An oversized file is refused, not read whole.
	rp2, _ := e.restarted(privateDir(t), nil)
	big := BundleCachePath(rp2.cache.path[:len(rp2.cache.path)-len("/bundle/bundle.json")])
	if err := os.WriteFile(big, bytes.Repeat([]byte("x"), bundle.MaxEnvelopeBytes+10), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := rp2.LoadCache(); err == nil || !strings.Contains(err.Error(), "too_large") {
		t.Fatalf("oversized cache = %v", err)
	}
}

// A refresh (same content, newer issuedAt) rewrites the cache, or a restart
// would measure the max age from a stale issuedAt.
func TestBundleCacheRefreshMovesIssuedAt(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	nb := e.bundle(5, bundlePolicyA)
	nb.IssuedAt = bundleT0.Add(10 * time.Hour)
	nb.ExpiresAt = bundleT0.Add(34 * time.Hour)
	e.now = bundleT0.Add(11 * time.Hour)
	e.cp.serve(e.sign(nb, nil), "e5-refresh")
	if changed, err := e.rp.PollLong(t.Context(), time.Millisecond); err != nil || changed {
		t.Fatalf("refresh = %v, %v", changed, err)
	}
	// 13h after the first issuedAt: too old if the cache were stale, but the
	// refresh at +10h keeps it within 12h.
	e.now = bundleT0.Add(13 * time.Hour)
	rp, _ := e.restarted(dir, nil)
	vb, err := rp.LoadCache()
	if err != nil || !vb.IssuedAt.Equal(nb.IssuedAt) {
		t.Fatalf("LoadCache after a refresh = %+v, %v, want the refreshed issuedAt", vb, err)
	}
}

func TestBundleCacheRejectedBundleIsNotCached(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(BundleCachePath(dir))
	e.cp.serve(flipPayloadByte(t, e.sign(e.bundle(6, bundlePolicyB), nil)), "e6")
	if err := e.rp.Pull(); !IsBundleRejection(err) {
		t.Fatalf("tampered bundle = %v", err)
	}
	e.cp.serve(e.sign(e.bundle(4, bundlePolicyB), nil), "e4")
	if err := e.rp.Pull(); !IsBundleRejection(err) {
		t.Fatalf("rollback bundle = %v", err)
	}
	if after, _ := os.ReadFile(BundleCachePath(dir)); !bytes.Equal(before, after) {
		t.Fatal("a rejected bundle changed the cache")
	}
}

func TestBundleCacheWriteFailureLogsOnceAndKeepsPolicy(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	// Make the target a directory so the rename fails.
	path := BundleCachePath(dir)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := e.pullSeq(1, bundlePolicyA, "e1"); err != nil {
		t.Fatalf("a cache write failure failed the apply: %v", err)
	}
	if err := e.pullSeq(2, bundlePolicyB, "e2"); err != nil {
		t.Fatal(err)
	}
	if got := e.allowed(); len(got) != 1 || got[0] != "b.example.com" {
		t.Fatalf("policy = %v, want seq 2 applied despite the write failures", got)
	}
	if n := strings.Count(e.logs.String(), "bundle cache write failed"); n != 1 {
		t.Fatalf("write failure logged %d times, want once:\n%s", n, e.logs)
	}
	if strings.Contains(e.logs.String(), "a.example.com") {
		t.Fatalf("policy content in logs: %s", e.logs)
	}
}

func TestBundleCacheOffWritesNothing(t *testing.T) {
	e := newBundleEnv(t) // no SetBundleCache
	dir := privateDir(t)
	if err := e.pullSeq(1, bundlePolicyA, "e1"); err != nil {
		t.Fatal(err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("files written without a cache: %v", ents)
	}
	// The cache file holds the envelope: valid JSON with the signed members only.
	e2 := newBundleEnv(t)
	d2 := e2.withCache()
	if err := e2.pullSeq(1, bundlePolicyA, "e1"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(BundleCachePath(d2))
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m["payload"] == nil || m["signatures"] == nil {
		t.Fatalf("cache is not an envelope: %v %s", err, raw)
	}
}

func TestBundleCacheRefusesUnsafeFiles(t *testing.T) {
	prime := func(t *testing.T) (*bundleEnv, string) {
		e := newBundleEnv(t)
		dir := e.withCache()
		if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
			t.Fatal(err)
		}
		return e, dir
	}
	t.Run("fifo", func(t *testing.T) {
		e, dir := prime(t)
		path := BundleCachePath(dir)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		rp, _ := e.restarted(dir, nil)
		done := make(chan error, 1)
		go func() { _, err := rp.LoadCache(); done <- err }()
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("LoadCache on a FIFO = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("LoadCache blocked on a FIFO")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		e, dir := prime(t)
		path := BundleCachePath(dir)
		real := filepath.Join(t.TempDir(), "real.json")
		if err := os.Rename(path, real); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, path); err != nil {
			t.Fatal(err)
		}
		rp, _ := e.restarted(dir, nil)
		if _, err := rp.LoadCache(); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("LoadCache on a symlink = %v", err)
		}
	})
	t.Run("mode 0644", func(t *testing.T) {
		e, dir := prime(t)
		if err := os.Chmod(BundleCachePath(dir), 0o644); err != nil {
			t.Fatal(err)
		}
		rp, _ := e.restarted(dir, nil)
		if _, err := rp.LoadCache(); err == nil || !strings.Contains(err.Error(), "accessible by group or others") {
			t.Fatalf("LoadCache on a 0644 file = %v", err)
		}
	})
	t.Run("stateDir 0777", func(t *testing.T) {
		e := newBundleEnv(t)
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := e.rp.SetBundleCache(dir, time.Hour); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Fatalf("SetBundleCache on a 0777 dir = %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, BundleCacheDirName)); err == nil {
			t.Fatal("a bundle dir was created under an unsafe state dir")
		}
	})
	t.Run("bundle dir 0775", func(t *testing.T) {
		e := newBundleEnv(t)
		dir := privateDir(t)
		if err := os.Mkdir(filepath.Join(dir, BundleCacheDirName), 0o775); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(dir, BundleCacheDirName), 0o775)
		if err := e.rp.SetBundleCache(dir, time.Hour); err == nil {
			t.Fatal("SetBundleCache accepted a group-writable bundle dir")
		}
	})
	t.Run("symlinked stateDir", func(t *testing.T) {
		e := newBundleEnv(t)
		real := privateDir(t)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if err := e.rp.SetBundleCache(link, time.Hour); err == nil || !strings.Contains(err.Error(), "not a real directory") {
			t.Fatalf("SetBundleCache through a symlink = %v", err)
		}
	})
}

func TestBundleCacheFloorRejectsRollbackAndEquivocation(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	rp, _ := e.restarted(dir, nil)
	rp.SeedCacheFloor()

	e.cp.serve(e.sign(e.bundle(3, bundlePolicyB), nil), "e3")
	if err := rp.Pull(); !errors.Is(err, bundle.ErrRollback) {
		t.Fatalf("seq 3 against a seq 5 cache floor: %v, want rollback", err)
	}
	e.cp.serve(e.sign(e.bundle(5, bundlePolicyB), nil), "e5b")
	if err := rp.Pull(); !errors.Is(err, bundle.ErrEquivocation) {
		t.Fatalf("seq 5 with other content: %v, want equivocation", err)
	}
	if _, err := rp.GetPolicy(); err == nil {
		t.Fatal("a rejected boot pull installed a policy")
	}
	// The worker then falls back to the cache, and a newer bundle applies.
	if _, err := rp.LoadCache(); err != nil {
		t.Fatal(err)
	}
	e.cp.serve(e.sign(e.bundle(6, bundlePolicyB), nil), "e6")
	if changed, err := rp.PollLong(t.Context(), time.Millisecond); err != nil || !changed {
		t.Fatalf("seq 6 = %v, %v", changed, err)
	}
	// Boot-only: no cache load once the long-poll has started.
	if _, err := rp.LoadCache(); err == nil {
		t.Fatal("LoadCache succeeded after the long-poll started")
	}
}

// The control plane serving the cached bundle itself is applied (not
// "unchanged"), credentials sidecar included.
func TestBundleCacheFloorAppliesLiveBodyWithCredentials(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cr3t-value"}
	pol := `{"allowlist":[{"domain":"a.example.com"}],"settings":{"secrets":{"backend":"aws","region":"us-east-1"}}}`
	live := e.sign(e.bundle(5, pol), creds)
	e.cp.serve(live, "e5")
	if err := e.rp.Pull(); err != nil {
		t.Fatal(err)
	}
	rp, _ := e.restarted(dir, nil)
	rp.SeedCacheFloor()
	if err := rp.Pull(); err != nil {
		t.Fatalf("boot pull of the cached bundle itself: %v", err)
	}
	if s := rp.Settings(); s == nil || s.Secrets == nil || s.Secrets.SecretAccessKey != "s3cr3t-value" {
		t.Fatalf("settings = %+v, want the sidecar merged from the live body", s)
	}
	if b, ok := rp.Bundle(); !ok || b.Seq != 5 {
		t.Fatalf("bundle = %+v, %v", b, ok)
	}
}

func TestBundleCacheDirFsyncErrorIsAWriteFailure(t *testing.T) {
	if err := writeCacheFile(filepath.Join(t.TempDir(), "nodir", "bundle.json"), []byte(`{}`)); err == nil {
		t.Fatal("writing into a missing directory succeeded")
	}
}

// The floor is the cached bundle's seq only while that bundle could still be
// valid: past expiresAt plus the skew it is ignored (a CP restored from an old
// backup is accepted again).
func TestBundleCacheFloorExpires(t *testing.T) {
	e := newBundleEnv(t)
	dir := e.withCache()
	if err := e.pullSeq(5, bundlePolicyA, "e5"); err != nil {
		t.Fatal(err)
	}
	rp, _ := e.restarted(dir, nil)
	rp.SeedCacheFloor()
	// The bundle expires at T0+24h (+5m skew). A newer-looking but lower seq
	// bundle signed later is only acceptable once the floor has lapsed.
	e.now = bundleT0.Add(24*time.Hour + 6*time.Minute)
	nb := e.bundle(3, bundlePolicyB)
	nb.IssuedAt = e.now.Add(-time.Minute)
	nb.ExpiresAt = e.now.Add(time.Hour)
	e.cp.serve(e.sign(nb, nil), "e3")
	if err := rp.Pull(); err != nil {
		t.Fatalf("seq 3 after the floor expired: %v, want it accepted", err)
	}
}

// TestBundleCacheNeverHoldsCredentialForAnySpelling is the regression test for
// a parser differential: bundle.Verify matched the "credentials" member
// case-insensitively (encoding/json's rule) while the cache writer deleted
// only the exact key "credentials" from a map, so an envelope rewritten on the
// wire to spell it "Credentials" applied the secret and also wrote it to the
// last-known-good cache. Now a case variant or duplicate of an envelope
// member is malformed, and the cache is re-marshalled from what Verify parsed
// (payload and signatures only), so no spelling, escape or extra member can
// put a credential on disk.
func TestBundleCacheNeverHoldsCredentialForAnySpelling(t *testing.T) {
	creds := &bundle.Credentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "s3cr3t-value"}
	pol := `{"allowlist":[{"domain":"a.example.com"}],"settings":{"secrets":{"backend":"aws","region":"us-east-1"}}}`
	sidecar := `"credentials":{"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"s3cr3t-value"}`
	respell := func(name string) func(string) string {
		return func(env string) string { return strings.Replace(env, `"credentials"`, `"`+name+`"`, 1) }
	}
	tests := []struct {
		name   string
		edit   func(env string) string
		reject bool // Verify refuses it as malformed
	}{
		{"canonical", func(env string) string { return env }, false},
		{"Credentials", respell("Credentials"), true},
		{"CREDENTIALS", respell("CREDENTIALS"), true},
		{"credentialS", respell("credentialS"), true},
		{"long s fold", respell("credentiaL\u017f"), true},
		// An escape that decodes to exactly "credentials" is the canonical name.
		{"escaped exact name", respell(`cred\u0065ntials`), false},
		{"duplicate credentials", func(env string) string {
			return strings.Replace(env, `{"payload"`, `{`+sidecar+`,"payload"`, 1)
		}, true},
		{"case variant beside the sidecar", func(env string) string {
			return strings.Replace(env, `{"payload"`, `{"Credentials":{"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"s3cr3t-value"},"payload"`, 1)
		}, true},
		// An unknown member is ignored by Verify and must not be persisted.
		{"secret in an unknown member", func(env string) string {
			return strings.Replace(env, `{"payload"`, `{"x-credentials":{"accessKeyId":"AKIAEXAMPLE","secretAccessKey":"s3cr3t-value"},"payload"`, 1)
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newBundleEnv(t)
			dir := e.withCache()
			env := string(e.sign(e.bundle(1, pol), creds))
			edited := tt.edit(env)
			if tt.name != "canonical" && edited == env {
				t.Fatal("the edit changed nothing")
			}
			e.cp.serve([]byte(edited), "c1")
			err := e.rp.Pull()
			if tt.reject {
				var re *BundleRejectError
				if !errors.As(err, &re) || re.Reason != bundle.Reason(bundle.ErrMalformed) {
					t.Fatalf("pull = %v, want a malformed rejection", err)
				}
				if s := e.rp.Settings(); s != nil && s.Secrets != nil && s.Secrets.SecretAccessKey != "" {
					t.Fatal("a rejected envelope's secret was applied in memory")
				}
			} else if err != nil {
				t.Fatalf("pull: %v", err)
			}
			raw, err := os.ReadFile(BundleCachePath(dir))
			if errors.Is(err, os.ErrNotExist) {
				if !tt.reject {
					t.Fatal("an accepted bundle was not cached")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.reject {
				t.Fatal("a rejected envelope was cached")
			}
			for _, s := range []string{"s3cr3t-value", "AKIAEXAMPLE", "ccessKey"} {
				if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(s)) {
					t.Fatalf("the cache file contains %q", s)
				}
			}
			var members map[string]json.RawMessage
			if err := json.Unmarshal(raw, &members); err != nil {
				t.Fatal(err)
			}
			if len(members) != 2 || members["payload"] == nil || members["signatures"] == nil {
				t.Fatalf("cache members = %v, want exactly payload and signatures", keysOf(members))
			}
			rp, _ := e.restarted(dir, nil)
			if _, err := rp.LoadCache(); err != nil {
				t.Fatalf("the written cache does not load: %v", err)
			}
		})
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
