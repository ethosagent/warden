package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/internal/keys"
	"github.com/ethosagent/warden/internal/keys/adapters/signer"
)

const cacheMaxAge = 12 * time.Hour

// withCache turns the cache on for e's provider in a fresh state dir.
func (e *bundleEnv) withCache() string {
	e.t.Helper()
	dir := e.t.TempDir()
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
	rp2, _ := e.restarted(t.TempDir(), nil)
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
	dir := t.TempDir()
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
