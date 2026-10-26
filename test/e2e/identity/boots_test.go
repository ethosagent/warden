//go:build e2e

package identity

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ethosagent/warden/test/harness/compose"
)

// TestIdentityStackBoots is the stack's own proof: CP and worker-1 are healthy,
// Dex answers on its published port with the dev issuer, the worker proxies an
// allowed host and denies an unlisted one, and agent-1 has no direct route out
// (nor to Dex).
func TestIdentityStackBoots(t *testing.T) {
	requireStack(t)

	t.Run("control plane and worker-1 healthy", func(t *testing.T) {
		if code, _, err := compose.TryGet(compose.CPBase + "/healthz"); err != nil || code != http.StatusOK {
			t.Errorf("control plane healthz: status %d err %v", code, err)
		}
		if code, _, err := compose.PlainGet(compose.WorkerAdmin1 + "/healthz"); err != nil || code != http.StatusOK {
			t.Errorf("worker-1 healthz: status %d err %v", code, err)
		}
	})

	t.Run("dex discovery from the host", func(t *testing.T) {
		resp, err := hostClient.Get(dexURL + discoveryPath)
		if err != nil {
			t.Fatalf("GET %s%s: %v", dexURL, discoveryPath, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("discovery status = %d, want 200", resp.StatusCode)
		}
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatalf("decode discovery: %v", err)
		}
		if doc.Issuer != dexURL {
			t.Errorf("issuer = %q, want exactly %q", doc.Issuer, dexURL)
		}
	})

	t.Run("allowed host reachable through the worker", func(t *testing.T) {
		res := agentExec(t, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
			"--max-time", compose.AgentCurlMaxTime, "--cacert", compose.AgentCABundle, "https://api.example.test/")
		if got := strings.TrimSpace(res.Stdout); res.Exit != 0 || got != "200" {
			t.Errorf("allowed call: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, got, firstLine(res.Stderr))
		}
	})

	t.Run("non-allowlisted host denied", func(t *testing.T) {
		// Not on the allowlist, not on the denylist: default-deny. The worker
		// refuses the CONNECT itself, so curl reports the tunnel status.
		res := agentExec(t, "curl", "-s", "-o", "/dev/null", "-w", "%{http_connect}",
			"--max-time", compose.AgentCurlMaxTime, "--cacert", compose.AgentCABundle, "https://unlisted.example.test/")
		if got := strings.TrimSpace(res.Stdout); res.Exit == 0 || got != "403" {
			t.Errorf("unlisted host: exit %d, CONNECT status %q; want a non-zero exit and 403 from the worker", res.Exit, got)
		}
	})

	t.Run("direct egress from agent-1 fails", func(t *testing.T) {
		direct := func(u string) compose.Result {
			return agentExec(t, "curl", "-s", "-o", "/dev/null", "--noproxy", "*", "--max-time", "5", u)
		}
		if res := direct("https://1.1.1.1/"); res.Exit == 0 {
			t.Errorf("agent-1 reached a public IP with no proxy (exit 0)")
		}
		// Split horizon: Dex is not on agent-1's network, by name or by port.
		if res := direct("http://dex:5556/dex" + discoveryPath); res.Exit == 0 {
			t.Errorf("agent-1 reached Dex directly (exit 0); it must have no route to it")
		}
	})
}
