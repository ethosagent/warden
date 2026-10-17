package scenarios

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/test/harness"
)

// The transparent interception scenarios (#376): the SAME decisions the
// CONNECT proxy makes, reached with no proxy configuration at all — the
// agent's dials land on the worker's transparent listeners (SNI / Host = the
// destination) and must run the one pipeline: same swap, same deny reasons,
// same audit.

// transparentTLSServeAllowWithSwap is allow-with-swap over transparent
// interception: an SNI dial to the :443 listener for an allowlisted host runs
// the full pipeline — the upstream sees the real secret, the agent's response
// is canary-clean.
func transparentTLSServeAllowWithSwap(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")
	ph := h.Placeholder("openai")

	req, err := http.NewRequest(http.MethodGet, "https://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ph)
	resp, err := h.TransparentAgent().Do(req)
	if err != nil {
		t.Fatalf("GET through the transparent listener: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+swapValue {
		t.Errorf("upstream Authorization = %q, want the real value swapped in", got)
	}
	evs := eventsFor(h.Events(), "api.example.com", "allow")
	if len(evs) != 1 {
		t.Fatalf("allow events = %d, want 1", len(evs))
	}
	if !strings.HasPrefix(evs[0].SecretRef, "sha256:") {
		t.Errorf("SecretRef = %q, want a sha256: reference", evs[0].SecretRef)
	}
	h.AssertCanaryNeverLeaked()
}

// transparentTLSServeDeny: an SNI the allowlist does not name is refused at
// the hello — the client never completes a handshake — and the deny is
// audited with the SAME reason the CONNECT floor gives the same destination.
func transparentTLSServeDeny(t *testing.T, h *harness.H) {
	const denied = "sneaky.example.test"

	// The transparent leg: the handshake must not complete (refused before any
	// certificate is minted or bytes forwarded).
	if err := dialTransparentTLS(t, h, denied); err == nil {
		t.Fatal("TLS handshake for a non-allowlisted SNI succeeded; the gate did not refuse it")
	}

	// The forward leg of the SAME destination, for the parity half.
	if got := connectStatus(t, h, denied+":443"); got != http.StatusForbidden {
		t.Fatalf("CONNECT to the non-allowlisted %s = %d, want 403", denied, got)
	}

	evs := eventsFor(h.Events(), denied, "deny")
	if len(evs) != 2 {
		t.Fatalf("deny events for %s = %d, want 2 (CONNECT + transparent)", denied, len(evs))
	}
	if evs[0].Reason != evs[1].Reason {
		t.Errorf("deny reasons diverge: CONNECT %q vs transparent %q — the modes must decide alike",
			evs[0].Reason, evs[1].Reason)
	}
	if evs[0].Reason == "" {
		t.Error("deny event carries no reason")
	}
}

// transparentPlainHTTPAllowWithSwap is allow-with-swap over the plain :80
// listener: the Host header is the destination, the swap and audit are the
// CONNECT tunnel's.
func transparentPlainHTTPAllowWithSwap(t *testing.T, h *harness.H) {
	u := h.Upstream("api.example.com")
	ph := h.Placeholder("openai")

	req, err := http.NewRequest(http.MethodGet, "http://api.example.com/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+ph)
	resp, err := h.TransparentAgentPlain().Do(req)
	if err != nil {
		t.Fatalf("GET through the plain transparent listener: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d, want 200", resp.StatusCode)
	}

	if got := lastRequest(t, u).Header.Get("Authorization"); got != "Bearer "+swapValue {
		t.Errorf("upstream Authorization = %q, want the real value swapped in", got)
	}
	evs := eventsFor(h.Events(), "api.example.com", "allow")
	if len(evs) != 1 {
		t.Fatalf("allow events = %d, want 1", len(evs))
	}
	if evs[0].Protocol != "http" {
		t.Errorf("event protocol = %q, want %q (plain-HTTP admission)", evs[0].Protocol, "http")
	}
	h.AssertCanaryNeverLeaked()
}

// dialTransparentTLS performs one bare SNI handshake against the transparent
// listener, reporting only whether it completed.
func dialTransparentTLS(t *testing.T, h *harness.H, serverName string) error {
	t.Helper()
	addrs := h.TransparentAddrs()
	if len(addrs) == 0 || addrs[0][0] == "" {
		t.Fatal("the harness reports no transparent :443 address")
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addrs[0][0], &tls.Config{
		ServerName: serverName, RootCAs: h.AgentTLSConfig().RootCAs, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}
