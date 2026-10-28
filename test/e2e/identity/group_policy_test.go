//go:build e2e

package identity

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness/compose"
)

// L2 group policy against real Dex (W-P1-GPOL-14): the core cases of the L1
// scenarios (test/scenarios, fake issuer) once more with a real Dex ID token
// and the seeded LDAP groups (deploy/compose/dex/seed.ldif): alice and dave are
// in eng, bob (warden-editors) and carol (warden-viewers) are not. The worker
// verifies a token minted for a host client by reaching Dex at its internal
// issuer URL (configs/config.e2e-identity-worker.yaml). No assertion prints a
// token; the stack is shared, so the policy edit is undone when the test ends.

const (
	// gatedHost is the host the test scopes to eng for its duration. No other
	// test in this package requests it.
	gatedHost   = "llm.example.test"
	gatedGroup  = "eng"
	mcpHost     = "mcp.example.test"
	engUser     = "dave" // eng only: not an admin, so no other role muddies the case
	engEmail    = "dave@example.org"
	nonMember   = "bob" // warden-editors, not eng
	nonMemEmail = "bob@example.org"
	policyWait  = 60 * time.Second
)

// policyDocMap is the dashboard policy document as the CP serves it, kept as
// generic JSON so a PUT of it back changes nothing but the allowlist.
type policyDocMap map[string]json.RawMessage

// scopeHost saves the fleet policy with host limited to group (replacing any
// entry for host) as admin alice and returns the document it replaced.
func scopeHost(t *testing.T, cs *consoleSession, host, group string) policyDocMap {
	t.Helper()
	code, body := cs.mustDo(t, http.MethodGet, "/dashboard/api/policy", nil, false)
	if code != http.StatusOK {
		t.Fatalf("GET /dashboard/api/policy: status %d", code)
	}
	var orig policyDocMap
	if err := json.Unmarshal(body, &orig); err != nil {
		t.Fatalf("decode the policy document: %v", err)
	}
	var entries []map[string]any
	if err := json.Unmarshal(orig["allowlist"], &entries); err != nil {
		t.Fatalf("decode the allowlist: %v", err)
	}
	next := entries[:0:0]
	for _, e := range entries {
		if e["domain"] != host {
			next = append(next, e)
		}
	}
	next = append(next, map[string]any{"domain": host, "groups": []string{group}})
	edited := policyDocMap{}
	for k, v := range orig {
		edited[k] = v
	}
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	edited["allowlist"] = raw
	putPolicyDoc(t, cs, edited)
	return orig
}

func putPolicyDoc(t *testing.T, cs *consoleSession, doc policyDocMap) {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if code, resp := cs.mustDo(t, http.MethodPut, "/dashboard/api/policy", b, true); code != http.StatusOK {
		t.Fatalf("PUT /dashboard/api/policy: status %d (body %.200s)", code, resp)
	}
}

// headerCurl requests url through worker-1 with the token in an
// X-Warden-Identity header and NO Proxy-Authorization, so the CONNECT carries
// no identity and the worker decides inside the tunnel. The header is read by
// curl from stdin (-H @-): the token is never on an argv. method POST sends
// body as JSON.
func headerCurl(t testing.TB, token, url, body string) (string, compose.Result) {
	t.Helper()
	args := []string{"curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}",
		"--max-time", compose.AgentCurlMaxTime, "-x", "http://" + compose.Proxy1,
		"--cacert", compose.AgentCABundle, "-H", "@-"}
	if body != "" {
		args = append(args, "-H", "Content-Type: application/json", "-d", body)
	}
	args = append(args, url)
	res, err := compose.AgentRunStdin(compose.SvcAgent1, []byte("X-Warden-Identity: Bearer "+token+"\n"), args...)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return strings.TrimSpace(res.Stdout), res
}

// refused reports a 403 at either point of "%{http_code} %{http_connect}": the
// CONNECT refused, or the request refused inside an open tunnel.
func refused(status string) bool {
	return strings.HasPrefix(status, "403 ") || strings.HasSuffix(status, " 403")
}

// upstreamCount is how many requests the fake upstream recorded for host.
func upstreamCount(t testing.TB, host string) int {
	t.Helper()
	recs, err := compose.RecorderRequests()
	if err != nil {
		t.Fatalf("identity: read the fake upstream recorder: %v", err)
	}
	return len(compose.FilterRecorded(recs, host))
}

// denyEvents returns the deny events on host with reason, from the event store.
func denyEvents(t testing.TB, host, reason string) []analytics.Event {
	t.Helper()
	var out []analytics.Event
	for _, e := range cpTraffic(t, "decision=deny&domain="+host+"&limit=1000") {
		if e.Reason == reason {
			out = append(out, e)
		}
	}
	return out
}

// waitDeny polls until host has more than before deny events with reason and
// returns the newest.
func waitDeny(t testing.TB, host, reason string, before int) analytics.Event {
	t.Helper()
	return waitEvent(t, "a new "+reason+" deny on "+host, func() (analytics.Event, bool) {
		if evs := denyEvents(t, host, reason); len(evs) > before {
			return evs[0], true
		}
		return analytics.Event{}, false
	})
}

func TestGroupPolicyDex(t *testing.T) {
	requireStack(t)
	engToken := dexToken(t, engUser)
	otherToken := dexToken(t, nonMember)
	tokens := []string{engToken, otherToken}
	var outputs []string
	keep := func(res compose.Result) { outputs = append(outputs, res.Stdout, res.Stderr) }

	admin := loginAs(t, "alice") // warden-admins: may edit the policy
	orig := scopeHost(t, admin, gatedHost, gatedGroup)
	t.Cleanup(func() { putPolicyDoc(t, admin, orig) })

	// The worker pulls the edit on its next long-poll turn. An anonymous
	// request to a scoped host is denied, so the first 403 shows the scoped
	// policy is live.
	err := compose.PollUntil(policyWait, func() (bool, string) {
		status, res := plainCurl(t, gatedHost)
		keep(res)
		return strings.HasPrefix(status, "403 "), "worker-1 still allows " + gatedHost + " to anyone"
	})
	if err != nil {
		t.Fatalf("identity: the scoped policy did not reach worker-1 within %s", policyWait)
	}

	t.Run("eng token allowed over Proxy-Authorization", func(t *testing.T) {
		before := upstreamCount(t, gatedHost)
		status, res := routedCurl(t, engToken, gatedHost)
		keep(res)
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("eng request: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
		if got := upstreamCount(t, gatedHost); got != before+1 {
			t.Errorf("fake upstream saw %d new requests, want 1", got-before)
		}
		e := waitEvent(t, "an allow event for "+engEmail, func() (analytics.Event, bool) {
			for _, e := range cpTraffic(t, "user="+engEmail+"&decision=allow&limit=1000") {
				if e.Domain == gatedHost {
					return e, true
				}
			}
			return analytics.Event{}, false
		})
		if e.IdentityStatus != "valid" || !contains(e.UserGroups, gatedGroup) {
			t.Errorf("allow event: identity_status %q, user_groups %v; want valid and %q", e.IdentityStatus, e.UserGroups, gatedGroup)
		}
	})

	t.Run("eng token allowed over X-Warden-Identity", func(t *testing.T) {
		before := upstreamCount(t, gatedHost)
		status, res := headerCurl(t, engToken, "https://"+gatedHost+"/", "")
		keep(res)
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("eng header request: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
		if got := upstreamCount(t, gatedHost); got != before+1 {
			t.Errorf("fake upstream saw %d new requests, want 1", got-before)
		}
	})

	t.Run("non-member denied group_not_allowed over both carriers", func(t *testing.T) {
		before := len(denyEvents(t, gatedHost, "group_not_allowed"))
		upBefore := upstreamCount(t, gatedHost)
		status, res := routedCurl(t, otherToken, gatedHost)
		keep(res)
		// The CONNECT already carries the subject, so the tunnel itself is
		// refused ("000 403"); the header carrier is decided inside the tunnel.
		if !refused(status) {
			t.Fatalf("non-member via Proxy-Authorization: exit %d, status %q; want a 403", res.Exit, status)
		}
		status, res = headerCurl(t, otherToken, "https://"+gatedHost+"/", "")
		keep(res)
		if !strings.HasPrefix(status, "403 ") {
			t.Fatalf("non-member via X-Warden-Identity: exit %d, status %q; want 403", res.Exit, status)
		}
		e := waitDeny(t, gatedHost, "group_not_allowed", before+1)
		if e.UserEmail != nonMemEmail || e.IdentityStatus != "valid" {
			t.Errorf("deny event: user_email %q, identity_status %q; want %q, valid", e.UserEmail, e.IdentityStatus, nonMemEmail)
		}
		if got := upstreamCount(t, gatedHost); got != upBefore {
			t.Errorf("a denied request reached the fake upstream (%d new)", got-upBefore)
		}
	})

	t.Run("no token denied identity_required", func(t *testing.T) {
		before := len(denyEvents(t, gatedHost, "identity_required"))
		upBefore := upstreamCount(t, gatedHost)
		status, res := plainCurl(t, gatedHost)
		keep(res)
		if !strings.HasPrefix(status, "403 ") {
			t.Fatalf("anonymous request: exit %d, status %q; want 403", res.Exit, status)
		}
		e := waitDeny(t, gatedHost, "identity_required", before)
		if e.UserEmail != "" || e.IdentityStatus != "none" {
			t.Errorf("deny event: user_email %q, identity_status %q; want none", e.UserEmail, e.IdentityStatus)
		}
		if got := upstreamCount(t, gatedHost); got != upBefore {
			t.Errorf("a denied request reached the fake upstream (%d new)", got-upBefore)
		}
	})

	t.Run("MCP tool gated to a group behaves the same", func(t *testing.T) {
		call := func(token, tool string) string {
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
			status, res := headerCurl(t, token, "https://"+mcpHost+"/mcp", body)
			keep(res)
			return status
		}
		upBefore := upstreamCount(t, mcpHost)
		if status := call(engToken, "deploy"); !strings.HasPrefix(status, "200 ") {
			t.Fatalf("eng calls deploy: status %q; want 200", status)
		}
		if status := call(otherToken, "list_files"); !strings.HasPrefix(status, "200 ") {
			t.Fatalf("non-member calls the ungated list_files: status %q; want 200", status)
		}
		if got := upstreamCount(t, mcpHost); got != upBefore+2 {
			t.Errorf("MCP upstream saw %d new requests after the two allowed calls, want 2", got-upBefore)
		}
		before := len(denyEvents(t, mcpHost, "mcp_tool_condition"))
		if status := call(otherToken, "deploy"); !strings.HasPrefix(status, "403 ") {
			t.Fatalf("non-member calls deploy: status %q; want 403", status)
		}
		if status := plainMCP(t, "deploy"); !strings.HasPrefix(status, "403 ") {
			t.Fatalf("anonymous calls deploy: status %q; want 403", status)
		}
		waitDeny(t, mcpHost, "mcp_tool_condition", before+1)
		if got := upstreamCount(t, mcpHost); got != upBefore+2 {
			t.Errorf("a denied tool call reached the MCP upstream (%d total new, want 2)", got-upBefore)
		}
	})

	t.Run("no token in agent output or logs", func(t *testing.T) {
		cp, err := compose.LogsOf(compose.SvcCP)
		if err != nil {
			t.Fatalf("control plane logs: %v", err)
		}
		surfaces := map[string]string{
			"agent command output": strings.Join(outputs, "\n"),
			"worker-1 logs":        workerLogs(t),
			"control plane logs":   cp,
		}
		for name, text := range surfaces {
			for _, tok := range tokens {
				if strings.Contains(text, tok) {
					t.Errorf("%s contain a Dex token", name)
				}
			}
			if m := jwtShaped.FindString(text); m != "" {
				t.Errorf("%s contain a JWT-shaped string (%d chars)", name, len(m))
			}
		}
	})
}

// plainMCP posts a tools/call with no identity at all.
func plainMCP(t testing.TB, tool string) string {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	res := agentExec(t, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}",
		"--max-time", compose.AgentCurlMaxTime, "--cacert", compose.AgentCABundle,
		"-H", "Content-Type: application/json", "-d", body, "https://"+mcpHost+"/mcp")
	return strings.TrimSpace(res.Stdout)
}
