package scenarios

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/test/fakes"
	"github.com/ethosagent/warden/test/harness"
)

// Identity require mode (W-P2-WBND-03). The control plane serves require for
// the worker's agent; the worker then admits only a Warden token minted for
// that agent. A CONNECT without one gets the 407 with no sign-in, before the
// block list, the policy and any dial; an IdP token is refused as unbound_token
// even though it verifies; and on terminated traffic a header naming another
// subject or agent is a 403 identity_conflict, never a 401.

// requireReply is one CONNECT answer, parsed.
type requireReply struct {
	status int
	raw    string
	body   struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
}

func requireConnect(t *testing.T, h *harness.H, auth string) requireReply {
	t.Helper()
	var r requireReply
	r.status, r.raw = h.ConnectReplyAt(0, challengeTarget, auth)
	_ = json.Unmarshal([]byte(r.raw), &r.body)
	return r
}

// assertRequire407 checks the 407 body is exactly {error, reason}: no sign_in.
func assertRequire407(t *testing.T, what string, r requireReply, reason string) {
	t.Helper()
	if r.status != http.StatusProxyAuthRequired {
		t.Fatalf("%s: status %d (%q), want 407", what, r.status, r.raw)
	}
	if r.body.Error != "identity_required" || r.body.Reason != reason {
		t.Errorf("%s: error %q reason %q, want identity_required / %s", what, r.body.Error, r.body.Reason, reason)
	}
	var generic map[string]any
	if err := json.Unmarshal([]byte(r.raw), &generic); err != nil || len(generic) != 2 {
		t.Errorf("%s: body %q must hold only error and reason (no sign_in)", what, r.raw)
	}
}

// enterRequire has the control plane serve require for this agent and waits
// until the running worker refuses an anonymous CONNECT with the 407.
func enterRequire(t *testing.T, h *harness.H) {
	t.Helper()
	editSettings(t, h, func(s *config.SettingsWire) {
		s.Agents = append(s.Agents, config.AgentSettings{ID: bootAgentID, Identity: config.IdentityModeRequire})
	})
	h.Eventually("the running worker to apply require mode", func() bool {
		return requireConnect(t, h, "").status == http.StatusProxyAuthRequired
	})
}

func requireDeny(h *harness.H, reason string) int {
	n := 0
	for _, e := range h.Events() {
		if e.Decision == "deny" && e.Reason == "identity_required" && (reason == "" || e.IdentityReason == reason) {
			n++
		}
	}
	return n
}

// identityRequireConnect: with a bundle applied, no token and a valid IdP token
// get the 407 (none, unbound_token), nothing is dialed, each is one deny event
// and one blocked count; the agent's Warden token is admitted and attributed.
func identityRequireConnect(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	up := h.Upstream(identityHost)
	enterRequire(t, h)
	before := len(up.Requests()) // the setup probe reached it under attribute mode

	none := requireConnect(t, h, "")
	assertRequire407(t, "no token", none, "none")
	dex := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	idp := requireConnect(t, h, basicAuth("session", dex))
	assertRequire407(t, "idp token", idp, "unbound_token")
	if strings.Contains(idp.raw, dex) {
		t.Error("the 407 echoes the credential")
	}
	h.Eventually("the refusals to be recorded", func() bool { return requireDeny(h, "") >= 2 })
	for _, e := range h.Events() {
		if e.Decision == "deny" && e.Reason == "identity_required" && e.UserSub != "" {
			t.Errorf("a refusal carries a user: %+v", e)
		}
	}
	if requireDeny(h, "unbound_token") != 1 {
		t.Errorf("want one deny event with identity_reason unbound_token, events %+v", h.Events())
	}
	if n := len(up.Requests()); n != before {
		t.Errorf("the upstream saw %d requests since require mode began; the 407 must come before any dial", n-before)
	}
	if h.MetricsAvailable() {
		key := harness.MetricKey("warden.blocked.total", map[string]string{"reason": "identity_required"})
		h.Eventually("warden.blocked.total{identity_required} to count both", func() bool { return h.Metrics()[key] >= 2 })
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+"/bound", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := h.AgentWithProxyTokenAt(0, good).Do(req)
	if err != nil {
		t.Fatalf("GET with the agent's Warden token: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET with the Warden token = %d, want 200", resp.StatusCode)
	}
	e := only(t, h.Events(), "https://"+identityHost+"/bound")
	if e.IdentityStatus != "valid" || e.IdentityTokenType != "warden" || e.UserSub != "user-1" || e.UserAct != bootAgentID {
		t.Errorf("bound request event = %s/%s type %q sub %q act %q", e.IdentityStatus, e.IdentityReason, e.IdentityTokenType, e.UserSub, e.UserAct)
	}
	requireNoCredentialsInLogs(t, h, good, dex)
}

// identityRequireHeaderConflict: on a terminated tunnel opened with the agent's
// token, an X-Warden-Identity naming another user, or the same user's token for
// another agent, is a 403 identity_conflict with Connection: close, never a 401.
func identityRequireHeaderConflict(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	other := h.RegisterTokenAgent("other-agent", []string{"eng"}, []string{"read"})
	otherAgentTok := decodeToken(t, exchangeForm(h, other.Form(tokenUser(h, "user-1", "eng"), nil))).AccessToken
	agent := h.RegisterTokenAgent("third-agent", []string{"eng"}, []string{"read"})
	user2Tok := decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-2", "eng"), nil))).AccessToken
	enterRequire(t, h)
	h.Upstream(identityHost)

	for name, hdr := range map[string]string{
		"another user":  user2Tok,
		"another agent": otherAgentTok,
	} {
		req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+"/conflict", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Warden-Identity", "Bearer "+hdr)
		resp, err := h.AgentWithProxyTokenAt(0, good).Do(req)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden || string(b) != `{"error":"identity_conflict"}` {
			t.Errorf("%s: status %d body %q, want 403 identity_conflict", name, resp.StatusCode, b)
		}
		if resp.Header.Get("WWW-Authenticate") != "" {
			t.Errorf("%s: WWW-Authenticate written", name)
		}
	}
	requireNoCredentialsInLogs(t, h, good, otherAgentTok, user2Tok)
}

// identityRequireBoot: a restarted worker enforces the control plane's require
// from its very first request: no Eventually, no policy change after boot.
func identityRequireBoot(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	enterRequire(t, h)
	h.RestartWorker(0)
	assertRequire407(t, "first CONNECT after restart", requireConnect(t, h, ""), "none")
	dex := h.MintUserToken(fakes.Valid("alice", "alice@example.com", "eng"))
	assertRequire407(t, "first idp CONNECT after restart", requireConnect(t, h, basicAuth("session", dex)), "unbound_token")
	if status, _ := h.ConnectReplyAt(0, challengeTarget, basicAuth("session", good)); status != http.StatusOK {
		t.Fatalf("first CONNECT with the agent's Warden token after restart = %d, want 200", status)
	}
}

// identityRequireSessionExpiry (W-P2-WBND-09): in require mode a held
// keep-alive session carrying the agent's Warden token is closed when the
// token's exp passes, with one identity_expired deny event per closed session, and a new
// request on the spent token is refused. The worker's session expiry loop runs
// on the harness clock (worker.Overrides.Clock), so the test drives it by
// condition: it advances the clock until the cut is observed, never by a fixed
// amount. The spent-token check then moves the clock past exp plus the
// verifier's skew, the point where a fresh CONNECT with it is refused.
func identityRequireSessionExpiry(t *testing.T, h *harness.H) {
	good := bootSetup(t, h)
	enterRequire(t, h)
	up := h.Upstream(identityHost)
	client := h.AgentWithProxyTokenAt(0, good)
	get := func(path string) (int, error) {
		req, err := http.NewRequest(http.MethodGet, "https://"+identityHost+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	if st, err := get("/held"); err != nil || st != http.StatusOK {
		t.Fatalf("GET with the agent's Warden token = %d %v, want 200", st, err)
	}
	served := len(up.Requests())
	expired := func() int {
		n := 0
		for _, e := range h.Events() {
			if e.Decision == "deny" && e.Reason == "identity_expired" {
				n++
			}
		}
		return n
	}
	h.Eventually("the held session to be closed at the token's exp", func() bool {
		h.Clock().Advance(time.Minute)
		return expired() > 0
	})
	// One event per closed session: the setup probe's keep-alive (opened under
	// attribute mode, armed by the flip's sweep) expires with the held one.
	if n := expired(); n < 1 || n > 2 {
		t.Errorf("%d identity_expired deny events, want 1 or 2 (the held session, plus the setup probe's keep-alive)", n)
	}
	if h.MetricsAvailable() {
		key := harness.MetricKey("warden.blocked.total", map[string]string{"reason": "identity_expired"})
		h.Eventually("warden.blocked.total{identity_expired} to count the cut", func() bool { return h.Metrics()[key] >= 1 })
	}
	// The cut lands at exp, but the verifier accepts the token for its clock
	// skew past exp, so a fresh CONNECT inside that window is admitted by design
	// (a "late" session). Where the clock stands now depends on which Eventually
	// iteration saw the cut: the one whose Advance crossed exp (clock under
	// exp+skew) or a later one. Move it past exp+skew so the token is spent on
	// every run. The CONNECT and the per-request check read the clock directly,
	// so no loop has to catch up after this Advance.
	_, claims := verifyWardenToken(t, h, good)
	spent := time.Unix(claims.Exp, 0).Add(identity.DefaultClockSkew)
	if d := spent.Sub(h.Clock().Now()); d >= 0 {
		h.Clock().Advance(d + time.Second)
	}
	if st, err := get("/spent"); err == nil && st == http.StatusOK {
		t.Errorf("a request with the spent token = %d, want it refused", st)
	}
	if n := len(up.Requests()); n != served {
		t.Errorf("the upstream saw %d requests after the cut, want none", n-served)
	}
	requireNoCredentialsInLogs(t, h, good)
}
