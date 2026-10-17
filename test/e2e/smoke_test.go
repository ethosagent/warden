//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestSmoke: the stack is up and an agent reaches an allowed host through its
// worker, verifying the worker's MITM leaf against the proxy CA.
func TestSmoke(t *testing.T) {
	out, exit := agentExec(t, svcAgent1, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
		"--cacert", "/etc/warden/certs/proxy-ca.crt", "https://api.example.test/")
	if exit != 0 || strings.TrimSpace(out) != "200" {
		t.Fatalf("allowed call: exit %d, status %q; want exit 0, 200", exit, out)
	}
}
