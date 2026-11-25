package scenarios

import (
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ethosagent/warden/internal/bundle"
	"github.com/ethosagent/warden/test/harness"
)

// The last-known-good bundle cache (W-P2-SBND-06). A pinned worker with a
// state directory persists each bundle it verified. Restarted while the control
// plane is down, it enforces the cached policy; if the cache file was altered
// it enforces nothing (fail closed).

func bundleCacheOpts() []harness.Option { return pinnedWorkerOpts(harness.WithBundleCache()) }

// cacheHolds waits until worker 0's cache file verifies and its policy lists
// host, returning the file bytes. The file is written right after the
// snapshot swap, so the scenario waits for it instead of assuming.
func cacheHolds(t *testing.T, h *harness.H, host string) {
	t.Helper()
	h.Eventually("the worker caches a bundle that lists "+host, func() bool {
		raw, err := os.ReadFile(h.BundleCacheFile(0))
		if err != nil {
			return false
		}
		v := h.VerifyBundle(raw, bundle.State{})
		return strings.Contains(string(v.Bundle.Policy), host)
	})
}

// bundleCacheBootsFromCache: the worker applies two bundles, the control plane
// goes away, and the restarted worker enforces the cached policy (the host
// added by the second bundle is reachable, an unlisted one is not). The cache
// file is 0600 in a 0700 directory and holds no credential.
func bundleCacheBootsFromCache(t *testing.T, h *harness.H) {
	h.Upstream(rollbackHost)
	h.Eventually("the worker applies a verified bundle", func() bool {
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
	saveAllowing(t, h, rollbackHost, `"v1"`)
	h.Eventually("the worker enforces the next signed bundle", func() bool {
		return connectStatus(t, h, rollbackHost+":443") == http.StatusOK
	})
	cacheHolds(t, h, rollbackHost)

	path := h.BundleCacheFile(0)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("cache file = %v %v, want mode 0600", fi, err)
	}
	if fi, err := os.Stat(path[:strings.LastIndex(path, "/")]); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("cache dir = %v %v, want mode 0700", fi, err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "secretAccessKey") || strings.Contains(string(raw), `"credentials"`) {
		t.Fatal("the cache file holds a credential")
	}

	h.CP().Stop()
	h.RestartWorker(0)
	if got := connectStatus(t, h, rollbackHost+":443"); got != http.StatusOK {
		t.Fatalf("restarted worker with the control plane down: CONNECT %s = %d, want 200 from the cached policy", rollbackHost, got)
	}
	if got := connectStatus(t, h, "unlisted.example.net:443"); got != http.StatusForbidden {
		t.Fatalf("a host outside the cached policy = %d, want 403", got)
	}
	if !strings.Contains(h.Logs(), "enforcing the cached last-known-good signed bundle") {
		t.Error("the worker did not log that it booted from the cache")
	}
}

// bundleCacheTamperedFailsClosed: a byte of the cached payload is flipped while
// the worker is down. The restarted worker, with the control plane still down,
// rejects the cache and denies everything.
func bundleCacheTamperedFailsClosed(t *testing.T, h *harness.H) {
	h.Eventually("the worker applies a verified bundle", func() bool {
		return connectStatus(t, h, "api.example.com:443") == http.StatusOK
	})
	cacheHolds(t, h, "api.example.com")

	h.CP().Stop()
	path := h.BundleCacheFile(0)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// "payload":"<base64url>": change one character of the payload.
	i := strings.Index(string(raw), `"payload":"`) + len(`"payload":"`) + 40
	flipped := append([]byte(nil), raw...)
	if flipped[i] == 'A' {
		flipped[i] = 'B'
	} else {
		flipped[i] = 'A'
	}
	if err := os.WriteFile(path, flipped, 0o600); err != nil {
		t.Fatal(err)
	}

	h.RestartWorker(0)
	if got := connectStatus(t, h, "api.example.com:443"); got != http.StatusForbidden {
		t.Fatalf("restarted worker with a tampered cache: CONNECT = %d, want 403 (fail closed)", got)
	}
	logs := h.Logs()
	if !strings.Contains(logs, "starting FAIL-CLOSED") || !strings.Contains(logs, "cached bundle rejected") {
		t.Errorf("the worker did not log the rejected cache and the fail-closed boot:\n%s", logs)
	}
}
