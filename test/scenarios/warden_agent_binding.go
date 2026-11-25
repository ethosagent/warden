package scenarios

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness"
)

// Agent binding of Warden tokens (W-P2-WBND-02). The worker serves one agent and
// takes the registered agents and their key thumbprints from the verified signed
// bundle. A Warden token whose signature verifies is still refused unless it was
// minted for this worker's agent (act), the agent is active, and the key it was
// minted for (cnf.jkt) is still registered. The check runs on every request
// against the bundle applied by the latest long-poll, so a tunnel opened with a
// good token loses the identity when its key is removed or its agent disabled,
// not when the token expires. Attribute mode never blocks: a refused token is an
// anonymous request, and what is checked is the identity recorded on the event.
// Tokens are never printed.

const bindingAgent = "bound-agent"

func wardenAgentBindingOpts() []harness.Option {
	return append(wardenTokenVerifyOpts(), harness.WithWorkerAgent(bindingAgent), harness.Allow(identityHost))
}

// bindingToken exchanges a user token for a Warden token minted for agent.
func bindingToken(t *testing.T, h *harness.H, agent *harness.TokenAgent, sub string) string {
	t.Helper()
	return decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, sub, "eng"), nil))).AccessToken
}

// requireBoundEvent checks the event of a request whose token bound.
func requireBoundEvent(t *testing.T, name string, e analytics.Event, sub string) {
	t.Helper()
	if e.IdentityStatus != "valid" || e.UserSub != sub || e.UserAct != bindingAgent || e.IdentityTokenType != "warden" {
		t.Errorf("%s: identity %s sub %q act %q type %q, want valid / %s / %s / warden",
			name, e.IdentityStatus, e.UserSub, e.UserAct, e.IdentityTokenType, sub, bindingAgent)
	}
}

// requireUnboundEvent checks a refused token attributed nothing, not even the act.
func requireUnboundEvent(t *testing.T, name string, e analytics.Event, reason string) {
	t.Helper()
	requireRefusedEvent(t, name, e, "invalid", reason)
	if e.UserAct != "" || e.IdentityTokenType != "" {
		t.Errorf("%s: a refused token recorded act %q type %q", name, e.UserAct, e.IdentityTokenType)
	}
}

// wardenAgentBinding: own agent accepted; another agent's token refused
// (agent_mismatch); a tunnel opened with a good token loses the identity on its
// next request once the agent's key is rotated away (cnf_mismatch), and so does
// a new connection presenting the same token.
func wardenAgentBinding(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	own := h.RegisterTokenAgent(bindingAgent, []string{"eng"}, []string{"read"})
	other := h.RegisterTokenAgent("other-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	ownTok := bindingToken(t, h, own, "user-1")
	otherTok := bindingToken(t, h, other, "user-2")
	p := &wardenProber{t: t, h: h}

	// The worker's own agent: accepted once it holds the bundle with the agent.
	var e analytics.Event
	h.Eventually("the worker binds a token minted for its own agent", func() bool {
		e = p.probe(ownTok)
		return e.IdentityStatus == "valid"
	})
	requireBoundEvent(t, "own agent's token", e, "user-1")

	// Probes made while the worker caught up were counted too: measure from here.
	base := map[string]float64{}
	for _, r := range []string{"agent_mismatch", "cnf_mismatch"} {
		base[r] = verifySeries(h, "invalid", r, "warden")
	}

	// Another registered agent's token: a valid signature, the wrong act.
	requireUnboundEvent(t, "another agent's token", p.probe(otherTok), "agent_mismatch")

	// A tunnel opened with the good token, then the agent's key is replaced.
	tun := openTLSSession(t, h, 0, identityHost, basicAuth("session", ownTok), "/tunnel-1")
	if got := tun.status(t); got != http.StatusOK {
		t.Fatalf("tunnel request = %d, want 200", got)
	}
	requireBoundEvent(t, "tunnel before the rotation", only(t, h.Events(), "https://"+identityHost+"/tunnel-1"), "user-1")

	h.RotateTokenAgentKey(bindingAgent)
	h.Eventually("a new connection with the rotated-away key's token is refused", func() bool {
		h.Clock().Advance(3 * time.Second)
		return p.probe(ownTok).IdentityReason == "cnf_mismatch"
	})
	requireUnboundEvent(t, "rotated-away key, new connection", p.probe(ownTok), "cnf_mismatch")

	// The open tunnel's next request is bound again, not carried over from CONNECT.
	tun.send(t, "/tunnel-2")
	if got := tun.status(t); got != http.StatusOK {
		t.Fatalf("tunnel request after the rotation = %d, want 200 (attribute mode never blocks)", got)
	}
	requireUnboundEvent(t, "open tunnel after the rotation", only(t, h.Events(), "https://"+identityHost+"/tunnel-2"), "cnf_mismatch")

	if h.MetricsAvailable() {
		if got := verifySeries(h, "invalid", "agent_mismatch", "warden") - base["agent_mismatch"]; got != 1 {
			t.Errorf("%s{invalid,agent_mismatch,warden} = %v, want 1", verifyMetric, got)
		}
		if got := verifySeries(h, "invalid", "cnf_mismatch", "warden") - base["cnf_mismatch"]; got < 2 {
			t.Errorf("%s{invalid,cnf_mismatch,warden} = %v, want at least 2", verifyMetric, got)
		}
	}
	requireNoCredentialsInLogs(t, h, ownTok, otherTok)
}

// wardenAgentBindingDisabled: a disabled agent is refused on the next request of
// a tunnel that was open when it was disabled, and on every new connection.
func wardenAgentBindingDisabled(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	own := h.RegisterTokenAgent(bindingAgent, []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	tok := bindingToken(t, h, own, "user-1")
	p := &wardenProber{t: t, h: h}
	h.Eventually("the worker binds a token minted for its own agent", func() bool {
		return p.probe(tok).IdentityStatus == "valid"
	})

	tun := openTLSSession(t, h, 0, identityHost, basicAuth("session", tok), "/tunnel-1")
	if got := tun.status(t); got != http.StatusOK {
		t.Fatalf("tunnel request = %d, want 200", got)
	}
	auth := basicAuth("session", tok)

	h.DisableTokenAgent(bindingAgent)
	h.Eventually("a new connection for the disabled agent is refused", func() bool {
		h.Clock().Advance(3 * time.Second)
		status, _ := h.ConnectReplyAt(0, identityHost+":443", auth)
		return status == http.StatusForbidden
	})
	if status, body := h.ConnectReplyAt(0, identityHost+":443", auth); status != http.StatusForbidden || !strings.Contains(body, "agent_disabled") {
		t.Fatalf("CONNECT for the disabled agent = %d %q, want 403 agent_disabled", status, body)
	}

	// The tunnel that was open is refused too: closed, or answered with a denial,
	// never served.
	_, _ = fmt.Fprintf(tun.tls, "GET /tunnel-2 HTTP/1.1\r\nHost: %s\r\n\r\n", identityHost)
	_ = tun.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if resp, err := http.ReadResponse(tun.r.(*bufio.Reader), nil); err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("the open tunnel served a request for a disabled agent")
		}
	}
	for _, ev := range h.Events() {
		if strings.HasSuffix(ev.URL, "/tunnel-2") && ev.Decision == "allow" {
			t.Errorf("the request on the open tunnel was allowed for a disabled agent: %+v", ev)
		}
	}
	requireNoCredentialsInLogs(t, h, tok)
}

func wardenAgentBindingChallengeOpts() []harness.Option {
	return append(wardenAgentBindingOpts(), harness.WithIdentity("challenge"))
}

// wardenAgentBindingChallenge: in challenge mode a tunnel opened with a good
// token does not drop to anonymous when its key is rotated away: the next request
// on it is answered 403 identity_required, and a new CONNECT with the same token
// is challenged (407).
func wardenAgentBindingChallenge(t *testing.T, h *harness.H) {
	h.Upstream(identityHost)
	own := h.RegisterTokenAgent(bindingAgent, []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	tok := bindingToken(t, h, own, "user-1")
	auth := basicAuth("session", tok)
	h.Eventually("the worker binds the token at CONNECT", func() bool {
		status, _ := h.ConnectReplyAt(0, identityHost+":443", auth)
		return status == http.StatusOK
	})
	tun := openTLSSession(t, h, 0, identityHost, auth, "/tunnel-1")
	if got := tun.status(t); got != http.StatusOK {
		t.Fatalf("tunnel request = %d, want 200", got)
	}

	h.RotateTokenAgentKey(bindingAgent)
	h.Eventually("a new CONNECT with the rotated-away key's token is challenged", func() bool {
		h.Clock().Advance(3 * time.Second)
		status, _ := h.ConnectReplyAt(0, identityHost+":443", auth)
		return status == http.StatusProxyAuthRequired
	})

	tun.send(t, "/tunnel-2")
	resp, err := http.ReadResponse(tun.r.(*bufio.Reader), nil)
	if err != nil {
		t.Fatalf("read the answer on the open tunnel: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := new(strings.Builder)
	_, _ = io.Copy(body, resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body.String(), "identity_required") || !resp.Close {
		t.Errorf("open tunnel after the rotation: %d %q close=%v, want 403 identity_required with Connection: close", resp.StatusCode, body.String(), resp.Close)
	}
	for _, ev := range h.Events() {
		if strings.HasSuffix(ev.URL, "/tunnel-2") && ev.Decision == "allow" {
			t.Errorf("the request after the rotation was allowed: %+v", ev)
		}
	}
	requireNoCredentialsInLogs(t, h, tok)
}
