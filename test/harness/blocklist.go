package harness

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Block-list levers (W-P1-BLOCK-09): block a user through the control plane's
// admin API and drive one specific worker of a Fleet, which the worker-1
// helpers (Agent, ConnectStatus) cannot.

const blockedUsersPath = "/dashboard/api/blocked-users"

// WithCentralForwarding makes every worker forward its analytics events to the
// control plane's /central/ingest every 100ms, the way a fleet does, so what the
// control plane derives from ingested events (alert Findings) can be asserted.
// In-process only: a supplied target wires its own forwarding.
func WithCentralForwarding() Option {
	return func(h *H) { h.wantCentral = true }
}

// BlockUser blocks a user through POST /dashboard/api/blocked-users with the
// control plane's admin bearer and returns the entry id. Give a sub, an email or
// both. It needs WithControlPlaneAdminToken and fails the test on any answer
// but 201. The reason is fixed text: it stays on the control plane.
func (h *H) BlockUser(sub, email string) string {
	h.tb.Helper()
	admin := h.ControlPlaneAdminToken()
	if admin == "" {
		h.tb.Fatal("harness: BlockUser needs the WithControlPlaneAdminToken option")
	}
	body, err := json.Marshal(map[string]string{"sub": sub, "email": email, "reason": "harness block"})
	if err != nil {
		h.tb.Fatalf("harness: encode the block request: %v", err)
	}
	code, resp, err := h.CP().Do(http.MethodPost, blockedUsersPath, admin, body)
	if err != nil || code != http.StatusCreated {
		h.tb.Fatalf("harness: POST %s = %d, %v; want 201", blockedUsersPath, code, err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(resp), &created); err != nil || created.ID == "" {
		h.tb.Fatalf("harness: the block response carries no id: %v", err)
	}
	return created.ID
}

// workerProxyAddr is worker i's proxy address (0-based: 0 is worker-1).
func (h *H) workerProxyAddr(i int) string {
	h.tb.Helper()
	addrs := h.ProxyAddrs()
	if i < 0 || i >= len(addrs) {
		h.tb.Fatalf("harness: worker index %d out of range (the fleet has %d workers)", i, len(addrs))
	}
	return addrs[i]
}

// AgentWithProxyTokenAt is AgentWithProxyToken against worker i (0-based).
func (h *H) AgentWithProxyTokenAt(i int, token string) *http.Client {
	h.tb.Helper()
	return h.proxyTokenClient(h.workerProxyAddr(i), token, false)
}

// ConnectReplyAt sends a CONNECT for hostPort to worker i (0-based) with a raw
// Proxy-Authorization value ("" sends none) and returns the reply's status and
// body: the decision itself, before a client library hides it. In-process only,
// like ConnectStatusWithAuth. The value is never logged.
func (h *H) ConnectReplyAt(i int, hostPort, proxyAuthorization string) (int, string) {
	h.tb.Helper()
	if _, ok := h.target.(ConnectProber); ok {
		h.tb.Fatalf("harness: ConnectReplyAt needs the in-process worker proxy")
	}
	return h.connectReply(h.workerProxyAddr(i), hostPort, proxyAuthorization)
}

// DialConnectAt opens a CONNECT to hostPort on worker i (0-based) presenting
// proxyAuthorization verbatim and returns the connection past the reply, a
// reader positioned after it and the reply's status. The connection closes at
// test cleanup. In-process only.
func (h *H) DialConnectAt(i int, hostPort, proxyAuthorization string) (net.Conn, *bufio.Reader, int) {
	h.tb.Helper()
	if _, ok := h.target.(ConnectProber); ok {
		h.tb.Fatalf("harness: DialConnectAt needs the in-process worker proxy")
	}
	conn, err := net.DialTimeout("tcp", h.workerProxyAddr(i), 5*time.Second)
	if err != nil {
		h.tb.Fatalf("dial the worker proxy: %v", err)
	}
	h.tb.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", hostPort, hostPort)
	if proxyAuthorization != "" {
		req += "Proxy-Authorization: " + proxyAuthorization + "\r\n"
	}
	if _, err := fmt.Fprint(conn, req+"\r\n"); err != nil {
		h.tb.Fatalf("send CONNECT %s: %v", hostPort, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		h.tb.Fatalf("read the CONNECT %s reply: %v", hostPort, err)
	}
	_ = resp.Body.Close()
	return conn, br, resp.StatusCode
}
