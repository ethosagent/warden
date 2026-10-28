package scenarios

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// The block-list worker-path scenarios (W-P1-BLOCK-09): a two-worker fleet, the
// in-process OIDC issuer as the IdP and the fake upstream as the recorder prove
// that an admin block made over the control plane's API reaches both workers
// within one long-poll cycle (new CONNECTs, with a valid or an expired token),
// cuts the user's open sessions (one deny event each, in-flight requests
// finish), and raises one Finding per user without her email. Survival across
// rollback, restart and outage is W-P1-BLOCK-12; the store and API have their
// own scenarios (block_list_served, block_api_*).

const (
	blockAliceEmail = "alice@example.com"
	blockHost       = "api.example.com"
	blockWorkers    = 2
)

func blockListFleetOpts() []harness.Option {
	return []harness.Option{
		harness.Fleet(blockWorkers),
		harness.WithIdentity(config.IdentityModeAttribute),
		harness.WithControlPlaneAdminToken(),
		harness.WithSecret("openai", harness.Canary(), blockHost), // so the canary sweep guards every output
		harness.WithAdminAudit(),                                  // the block store needs the control plane's state dir
	}
}

// blockListSessionHosts are the fake upstreams of the session scenario.
var blockListSessionHosts = []string{"keepalive.example.com", "tunnel.example.com", "slow.example.com", "bob.example.com"}

func blockListFindingOpts() []harness.Option {
	return append(blockListFleetOpts(), harness.WithCentralForwarding())
}

func blockListSessionsOpts() []harness.Option {
	return append(blockListFleetOpts(), harness.Allow(blockListSessionHosts...))
}

// blockUsers are the tokens a block-list scenario presents.
type blockUsers struct {
	alice, aliceExpired, bob string
}

func mintBlockUsers(h *harness.H) blockUsers {
	return blockUsers{
		alice:        h.MintUserToken(fakes.Valid("alice", blockAliceEmail)),
		aliceExpired: h.MintUserToken(fakes.Valid("alice", blockAliceEmail), fakes.Expired()),
		bob:          h.MintUserToken(fakes.Valid("bob", "bob@example.com")),
	}
}

func (u blockUsers) all() []string { return []string{u.alice, u.aliceExpired, u.bob} }

// userBlockedEvents are the deny events with Reason user_blocked on domain ("" =
// any domain) and, when sub is not "", that user sub.
func userBlockedEvents(evs []analytics.Event, domain, sub string) []analytics.Event {
	var out []analytics.Event
	for _, e := range evs {
		if e.Reason == string(denyreason.UserBlocked) && e.Decision == "deny" &&
			(domain == "" || e.Domain == domain) && (sub == "" || e.UserSub == sub) {
			out = append(out, e)
		}
	}
	return out
}

// awaitBlocked waits until worker i answers a CONNECT for hostPort presenting
// tok with 403 user_blocked: the worker has applied the block.
func awaitBlocked(t *testing.T, h *harness.H, i int, hostPort, tok string) {
	t.Helper()
	h.Eventually(fmt.Sprintf("worker-%d to deny the blocked user's CONNECT to %s", i+1, hostPort), func() bool {
		status, _ := h.ConnectReplyAt(i, hostPort, basicAuth("session", tok))
		return status == http.StatusForbidden
	})
	status, body := h.ConnectReplyAt(i, hostPort, basicAuth("session", tok))
	if status != http.StatusForbidden || !strings.Contains(body, string(denyreason.UserBlocked)) {
		t.Fatalf("worker-%d: CONNECT %s = %d %q, want 403 %s", i+1, hostPort, status, body, denyreason.UserBlocked)
	}
}

// blockListConnect: before the block both workers tunnel alice (a valid and an
// expired token: attribute mode never refuses a token). After
// POST /dashboard/api/blocked-users both answer her new CONNECTs 403
// user_blocked with either token, bob's requests still reach the upstream, and
// none of alice's does.
func blockListConnect(t *testing.T, h *harness.H) {
	up := h.Upstream(blockHost)
	users := mintBlockUsers(h)
	hostPort := blockHost + ":443"

	for i := 0; i < blockWorkers; i++ {
		for name, tok := range map[string]string{"valid": users.alice, "expired": users.aliceExpired} {
			if status, _ := h.ConnectReplyAt(i, hostPort, basicAuth("session", tok)); status != http.StatusOK {
				t.Fatalf("worker-%d: %s alice CONNECT before the block = %d, want 200", i+1, name, status)
			}
		}
	}

	h.BlockUser("alice", "")

	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hostPort, users.alice)
		awaitBlocked(t, h, i, hostPort, users.aliceExpired)
		resp, err := h.AgentWithProxyTokenAt(i, users.bob).Get(fmt.Sprintf("https://%s/bob-%d", blockHost, i))
		if err != nil {
			t.Fatalf("worker-%d: bob's GET: %v", i+1, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("worker-%d: bob's GET = %d, want 200", i+1, resp.StatusCode)
		}
	}
	// A client library turns the 403 into a transport error: alice's request must
	// fail, not reach the upstream.
	if resp, err := h.AgentWithProxyTokenAt(0, users.alice).Get("https://" + blockHost + "/alice"); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("alice's GET through the blocked tunnel succeeded with %d", resp.StatusCode)
	}

	reqs := up.Requests()
	if len(reqs) != blockWorkers {
		t.Fatalf("the upstream saw %d requests, want only bob's %d: %+v", len(reqs), blockWorkers, reqs)
	}
	for _, r := range reqs {
		if !strings.HasPrefix(r.Path, "/bob-") {
			t.Errorf("the upstream saw %s, want only bob's paths", r.Path)
		}
	}
	evs := h.Events()
	if len(userBlockedEvents(evs, blockHost, "alice")) < blockWorkers {
		t.Errorf("want a user_blocked deny event with alice's sub per worker, got %+v", userBlockedEvents(evs, "", ""))
	}
	for _, e := range userBlockedEvents(evs, "", "") {
		if e.UserSub == "bob" {
			t.Errorf("a user_blocked event names bob: %+v", e)
		}
	}
	assertNoLeakOf(t, h, users.all(), up)
	h.AssertCanaryNeverLeaked()
}

// openSession is a client connection of a user that stays open across the block.
type openSession struct {
	name   string
	worker int
	conn   net.Conn
	r      io.Reader // reads what the worker sends on conn (through TLS when terminated)
	tls    *tls.Conn
}

// openTLSSession opens a CONNECT to host on worker i with auth, handshakes TLS
// with the worker and sends one request; it returns the session and the
// response, ready to read. The CONNECT must succeed.
func openTLSSession(t *testing.T, h *harness.H, i int, host, auth, path string) *openSession {
	t.Helper()
	conn, _, status := h.DialConnectAt(i, host+":443", auth)
	if status != http.StatusOK {
		t.Fatalf("worker-%d: CONNECT %s = %d, want 200", i+1, host, status)
	}
	cfg := h.AgentTLSConfig()
	cfg.ServerName = host
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		t.Fatalf("worker-%d: TLS handshake for %s: %v", i+1, host, err)
	}
	s := &openSession{name: host, worker: i, conn: conn, r: bufio.NewReader(tc), tls: tc}
	s.send(t, path)
	return s
}

// send writes one keep-alive GET for path.
func (s *openSession) send(t *testing.T, path string) {
	t.Helper()
	if _, err := fmt.Fprintf(s.tls, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, s.name); err != nil {
		t.Fatalf("worker-%d: write the request to %s: %v", s.worker+1, s.name, err)
	}
}

// status reads one response and returns its status.
func (s *openSession) status(t *testing.T) int {
	t.Helper()
	resp, err := http.ReadResponse(s.r.(*bufio.Reader), nil)
	if err != nil {
		t.Fatalf("worker-%d: read the response from %s: %v", s.worker+1, s.name, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// expectClosed fails unless the worker closes the session promptly. The deadline
// is a backstop; a closed session returns at once.
func (s *openSession) expectClosed(t *testing.T) {
	t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err := io.Copy(io.Discard, s.r)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("worker-%d: the session to %s is still open after the block", s.worker+1, s.name)
	}
}

// blockListSessions: alice holds, on each worker, an idle HTTP/1 keep-alive
// session, a raw tunnel and a keep-alive session with a request in flight; bob
// holds a keep-alive session. After the block the idle keep-alive and the
// tunnel close, the in-flight request completes with its 200 and then its
// session closes, each of the six closures leaves exactly one user_blocked deny
// event with alice's sub, and bob's session keeps serving.
func blockListSessions(t *testing.T, h *harness.H) {
	const (
		kaHost   = "keepalive.example.com"
		tunHost  = "tunnel.example.com"
		slowHost = "slow.example.com"
		bobHost  = "bob.example.com"
		probe    = "probe.example.com"
		slowFor  = time.Minute
	)
	users := mintBlockUsers(h)
	ka, bobUp := h.Upstream(kaHost), h.Upstream(bobHost)
	slow := h.Upstream(slowHost)
	_ = h.Upstream(tunHost) // the tunnel dials it
	aliceAuth, bobAuth := basicAuth("session", users.alice), basicAuth("session", users.bob)

	var idle, tunnels, inflight, bobs []*openSession
	for i := 0; i < blockWorkers; i++ {
		s := openTLSSession(t, h, i, kaHost, aliceAuth, fmt.Sprintf("/idle-%d", i))
		if got := s.status(t); got != http.StatusOK {
			t.Fatalf("worker-%d: alice's keep-alive request = %d, want 200", i+1, got)
		}
		idle = append(idle, s)

		conn, br, status := h.DialConnectAt(i, tunHost+":443", aliceAuth)
		if status != http.StatusOK {
			t.Fatalf("worker-%d: alice's tunnel CONNECT = %d, want 200", i+1, status)
		}
		// One byte that is not a TLS hello: the worker pipes an opaque tunnel. The
		// TLS upstream waits for the rest of a record header and keeps it open.
		_, _ = fmt.Fprint(conn, "G")
		tunnels = append(tunnels, &openSession{name: tunHost, worker: i, conn: conn, r: br})

		b := openTLSSession(t, h, i, bobHost, bobAuth, fmt.Sprintf("/bob-%d-1", i))
		if got := b.status(t); got != http.StatusOK {
			t.Fatalf("worker-%d: bob's request = %d, want 200", i+1, got)
		}
		bobs = append(bobs, b)
	}
	h.Eventually("both tunnels to be dialled", func() bool {
		n := 0
		for _, e := range h.Events() {
			if e.Domain == tunHost && e.Protocol == "tcp" && e.Decision == "allow" {
				n++
			}
		}
		return n == blockWorkers
	})
	// The slow requests park on the upstream's fake-clock timer: in flight on
	// both workers when the block lands.
	slow.Delay(slowFor)
	for i := 0; i < blockWorkers; i++ {
		inflight = append(inflight, openTLSSession(t, h, i, slowHost, aliceAuth, fmt.Sprintf("/slow-%d", i)))
	}
	slow.WaitParked(blockWorkers)

	h.BlockUser("alice", "")
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, probe+":443", users.alice)
	}

	// The in-flight requests arrived under the old policy: they finish.
	h.Clock().Advance(slowFor)
	for _, s := range inflight {
		if got := s.status(t); got != http.StatusOK {
			t.Errorf("worker-%d: the in-flight request = %d, want it to complete with 200", s.worker+1, got)
		}
	}
	for _, group := range [][]*openSession{idle, tunnels, inflight} {
		for _, s := range group {
			s.expectClosed(t)
		}
	}
	for i, b := range bobs {
		b.send(t, fmt.Sprintf("/bob-%d-2", i))
		if got := b.status(t); got != http.StatusOK {
			t.Errorf("worker-%d: bob's request after the block = %d, want 200", i+1, got)
		}
	}

	closures := func() []analytics.Event {
		var out []analytics.Event
		for _, d := range []string{kaHost, tunHost, slowHost} {
			out = append(out, userBlockedEvents(h.Events(), d, "alice")...)
		}
		return out
	}
	h.Eventually("a user_blocked deny event for each of alice's six sessions", func() bool { return len(closures()) >= 3*blockWorkers })
	for _, d := range []string{kaHost, tunHost, slowHost} {
		if got := len(userBlockedEvents(h.Events(), d, "alice")); got != blockWorkers {
			t.Errorf("%s: %d user_blocked events with alice's sub, want %d (one per closed session)", d, got, blockWorkers)
		}
	}
	if got := len(userBlockedEvents(h.Events(), bobHost, "")); got != 0 {
		t.Errorf("%s: %d user_blocked events, want none for bob's sessions", bobHost, got)
	}
	// Alice's requests that arrived before the block were served; none after.
	if got := len(ka.Requests()); got != blockWorkers {
		t.Errorf("%s saw %d requests, want the %d pre-block ones", kaHost, got, blockWorkers)
	}
	assertNoLeakOf(t, h, users.all(), ka, slow, bobUp)
	h.AssertCanaryNeverLeaked()
}

// blockListFinding: alice, blocked by email, is denied on several domains on
// both workers. The control plane raises one security Finding for her, counting
// every denial, and neither it nor any log carries her email.
func blockListFinding(t *testing.T, h *harness.H) {
	users := mintBlockUsers(h)
	hosts := []string{"one.example.com", "two.example.com", "three.example.com"}

	h.BlockUser("", blockAliceEmail)
	for i := 0; i < blockWorkers; i++ {
		awaitBlocked(t, h, i, hosts[0]+":443", users.alice)
		for _, host := range hosts[1:] {
			if status, _ := h.ConnectReplyAt(i, host+":443", basicAuth("session", users.alice)); status != http.StatusForbidden {
				t.Fatalf("worker-%d: alice's CONNECT %s = %d, want 403", i+1, host, status)
			}
		}
		if status, _ := h.ConnectReplyAt(i, blockHost+":443", basicAuth("session", users.bob)); status != http.StatusOK {
			t.Fatalf("worker-%d: bob's CONNECT = %d, want 200", i+1, status)
		}
	}
	// Every host was denied on every worker at least once (the wait probes add
	// more); the workers forward their events, so the local store is no longer
	// the place to count them.
	denials := len(hosts) * blockWorkers

	admin := h.ControlPlaneAdminToken()
	type alert struct {
		DedupKey string `json:"dedupKey"`
		Category string `json:"category"`
		Severity string `json:"severity"`
		Summary  string `json:"summary"`
		Count    int    `json:"count"`
	}
	var body string
	var found []alert
	fetch := func() bool {
		code, resp, err := h.CP().Do(http.MethodGet, "/dashboard/api/alerts?limit=100", admin, nil)
		if err != nil || code != http.StatusOK {
			t.Fatalf("GET /dashboard/api/alerts = %d, %v", code, err)
		}
		var all []alert
		if err := json.Unmarshal([]byte(resp), &all); err != nil {
			t.Fatalf("decode the alerts: %v", err)
		}
		body, found = resp, nil
		for _, a := range all {
			if strings.HasPrefix(a.DedupKey, "user_blocked:") {
				found = append(found, a)
			}
		}
		return len(found) == 1 && found[0].Count >= denials
	}
	h.Eventually("one user_blocked Finding counting every denial", fetch)
	if len(found) != 1 || found[0].Category != "security" || found[0].Severity != "high" {
		t.Fatalf("user_blocked findings = %+v, want exactly one high security finding", found)
	}
	for _, needle := range []string{blockAliceEmail, "alice"} {
		if strings.Contains(body, needle) {
			t.Errorf("the alerts carry %q: %s", needle, body)
		}
	}
	if logs := h.Logs(); strings.Contains(logs, blockAliceEmail) {
		t.Error("a log line carries alice's email")
	}
	assertNoLeakOf(t, h, users.all())
	h.AssertCanaryNeverLeaked()
}
