package identityclient_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identityclient"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// TestForwarderRealWorker proves the forwarder interoperates with the real
// worker's identity capture: the worker verifies the token the forwarder puts
// in Proxy-Authorization on CONNECT and attributes the tunnel to that user,
// including after the forwarder's token changes (a refresh), and a policy deny
// from the worker reaches the client as a 403 that is still attributed.
func TestForwarderRealWorker(t *testing.T) {
	h := harness.New(t, harness.Local(), harness.WithIdentity(config.IdentityModeAttribute))
	const host, deniedHost = "api.example.com", "sneaky.example.test"
	h.Upstream(host)

	alice := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	bob := h.MintUserToken(fakes.Valid("bob", "bob@example.com", "ops"))
	var current atomic.Value
	current.Store(alice)

	fwd := &identityclient.Forwarder{
		WorkerAddr:       h.ProxyAddr(),
		Token:            func(context.Context) (string, error) { return current.Load().(string), nil },
		ClientCredential: fwdCred,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fwd.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	tunnel := func(target string) (net.Conn, *bufio.Reader, int) {
		t.Helper()
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = io.WriteString(c, connectReq(target, goodAuth()))
		br := bufio.NewReader(c)
		return c, br, statusOf(readHead(t, br))
	}
	// finish ends a raw tunnel (the bytes are not a TLS hello, so the worker
	// pipes them as an opaque tunnel) and waits for the worker to close it.
	finish := func(c net.Conn, br *bufio.Reader) {
		t.Helper()
		_, _ = io.WriteString(c, "plain bytes, not TLS\r\n\r\n")
		_, _ = io.Copy(io.Discard, br)
		_ = c.Close()
	}

	c1, br1, st := tunnel(host + ":443")
	if st != 200 {
		t.Fatalf("CONNECT as alice through the forwarder = %d, want 200", st)
	}
	finish(c1, br1)

	current.Store(bob) // the forwarder's token source rotated
	c2, br2, st := tunnel(host + ":443")
	if st != 200 {
		t.Fatalf("CONNECT as bob = %d, want 200", st)
	}
	finish(c2, br2)

	if _, _, st := tunnel(deniedHost + ":443"); st != 403 {
		t.Fatalf("CONNECT to a denied host = %d, want the worker's 403 relayed", st)
	}

	evs := h.Events()
	bySub := map[string]analytics.Event{}
	var denied *analytics.Event
	for i, e := range evs {
		if e.Domain == deniedHost {
			denied = &evs[i]
			continue
		}
		bySub[e.UserSub] = e
	}
	for sub, email := range map[string]string{"alice": "alice@example.com", "bob": "bob@example.com"} {
		e, ok := bySub[sub]
		if !ok {
			t.Fatalf("no tunnel event attributed to %s; events: %d", sub, len(evs))
		}
		if e.IdentityStatus != "valid" || e.UserEmail != email || e.Domain != host {
			t.Errorf("%s: event status %q email %q domain %q", sub, e.IdentityStatus, e.UserEmail, e.Domain)
		}
	}
	if denied == nil {
		t.Fatalf("no deny event for %s", deniedHost)
	}
	if denied.Decision != "deny" || denied.IdentityStatus != "valid" || denied.UserSub != "bob" {
		t.Errorf("denied CONNECT event = decision %q status %q sub %q, want deny/valid/bob",
			denied.Decision, denied.IdentityStatus, denied.UserSub)
	}

	// Neither the per-run credential nor the tokens appear in anything the
	// worker recorded.
	blob, _ := json.Marshal(evs)
	for _, secret := range []string{fwdCred, alice, bob} {
		if strings.Contains(string(blob), secret) {
			t.Errorf("a secret appears in the worker's recorded events")
		}
	}
}
