//go:build e2e

package identity

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/test/harness/compose"
)

// L2 attribution smoke (W-P1-IDC-03): a plain curl container, no agent
// framework, is attributed to a seeded LDAP user through `warden identity env`
// and the identity contract. The test plays the harness: it gets alice's token
// from Dex on the host and hands it to the CLI inside agent-1 on stdin, never
// on argv and never echoed. Behaviour with a fake issuer is covered in process
// on L1; this test exists for real Dex, real LDAP and the internal-only agent
// network. No assertion prints a token.

const (
	smokeUser    = "alice"
	smokeEmail   = "alice@example.org"
	allowedHost  = "api.example.test"
	deniedHost   = "unlisted.example.test"
	attribWait   = 60 * time.Second
	envWorkerArg = compose.SvcWorker1 + ":" + compose.ProxyPort
)

// jwtShaped matches the start of any compact JWT (a base64url JSON header).
var jwtShaped = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{20,}`)

// routedCurl runs curl through the worker with the identity environment built
// by `warden identity env --token-stdin` from token (stdin only). host is
// requested over https and the HTTP status (or the CONNECT status for a
// refused tunnel) is returned with the raw result for leak sweeps.
func routedCurl(t testing.TB, token, host string) (status string, res compose.Result) {
	t.Helper()
	script := `eval "$(/opt/warden/warden identity env --worker ` + envWorkerArg +
		` --token-stdin --ca ` + compose.AgentCABundle + `)" && ` +
		`curl -sS -o /dev/null -w '%{http_code} %{http_connect}' --max-time ` + compose.AgentCurlMaxTime +
		` https://` + host + `/`
	res, err := compose.AgentRunStdin(compose.SvcAgent1, []byte(token), "sh", "-c", script)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	return strings.TrimSpace(res.Stdout), res
}

// plainCurl runs curl with the agent's own environment (the worker proxy with
// no credentials): the "no token" request.
func plainCurl(t testing.TB, host string) (string, compose.Result) {
	t.Helper()
	res := agentExec(t, "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{http_connect}",
		"--max-time", compose.AgentCurlMaxTime, "--cacert", compose.AgentCABundle, "https://"+host+"/")
	return strings.TrimSpace(res.Stdout), res
}

// statusEvents returns the allow events with the given identity_status for
// the host, newest data first as the API returns it.
func statusEvents(t testing.TB, host, status string) []analytics.Event {
	t.Helper()
	var out []analytics.Event
	for _, e := range cpTraffic(t, "decision=allow&domain="+host+"&limit=1000") {
		if e.IdentityStatus == status {
			out = append(out, e)
		}
	}
	return out
}

// waitEvent polls fn until it returns an event, up to attribWait. The worker
// forwards analytics to the control plane asynchronously.
func waitEvent(t testing.TB, what string, fn func() (analytics.Event, bool)) analytics.Event {
	t.Helper()
	var got analytics.Event
	err := compose.PollUntil(attribWait, func() (bool, string) {
		e, ok := fn()
		got = e
		return ok, "no matching event yet"
	})
	if err != nil {
		t.Fatalf("identity: %s: no matching event on the control plane within %s", what, attribWait)
	}
	return got
}

func TestIdentitySmoke(t *testing.T) {
	requireStack(t)

	var token string
	t.Run("1 token fetched from Dex", func(t *testing.T) {
		token = dexToken(t, smokeUser)
		if n := len(strings.Split(token, ".")); n != 3 {
			t.Fatalf("ID token has %d segments, want 3 (a JWT)", n)
		}
	})
	if token == "" {
		t.Fatalf("no token: the remaining checks cannot run")
	}
	// Every agent command result is swept for the token and for JWT shapes.
	var outputs []string
	keep := func(res compose.Result) { outputs = append(outputs, res.Stdout, res.Stderr) }

	t.Run("2 routed request to the allowed host returns 200", func(t *testing.T) {
		status, res := routedCurl(t, token, allowedHost)
		keep(res)
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("routed request: exit %d, status %q; want exit 0, 200 (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
	})

	t.Run("3 control plane attributes the request to alice", func(t *testing.T) {
		e := waitEvent(t, "valid event for "+smokeEmail, func() (analytics.Event, bool) {
			for _, e := range cpTraffic(t, "user="+smokeEmail+"&limit=1000") {
				if e.IdentityStatus == "valid" && e.Domain == allowedHost {
					return e, true
				}
			}
			return analytics.Event{}, false
		})
		if e.UserSub == "" {
			t.Errorf("user_sub is empty")
		}
		if e.UserEmail != smokeEmail {
			t.Errorf("user_email = %q, want %q", e.UserEmail, smokeEmail)
		}
		for _, g := range []string{"warden-admins", "eng"} {
			if !slices.Contains(e.UserGroups, g) {
				t.Errorf("user_groups = %v, want it to contain %q", e.UserGroups, g)
			}
		}
		if e.Decision != "allow" {
			t.Errorf("decision = %q, want allow", e.Decision)
		}
		sub := e.UserSub
		// The ?user= filter must not return anyone else's events.
		for _, o := range cpTraffic(t, "user="+smokeEmail+"&limit=1000") {
			if o.UserSub != sub || o.UserEmail != smokeEmail {
				t.Errorf("?user=%s returned an event for sub %q email %q", smokeEmail, o.UserSub, o.UserEmail)
			}
		}
	})

	t.Run("4 no token is allowed and recorded none", func(t *testing.T) {
		before := len(statusEvents(t, allowedHost, "none"))
		status, res := plainCurl(t, allowedHost)
		keep(res)
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("tokenless request was not allowed: exit %d, status %q (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
		waitEvent(t, "a new none event", func() (analytics.Event, bool) {
			evs := statusEvents(t, allowedHost, "none")
			if len(evs) > before {
				return evs[0], true
			}
			return analytics.Event{}, false
		})
	})

	t.Run("5 garbage token is allowed and recorded invalid", func(t *testing.T) {
		before := len(statusEvents(t, allowedHost, "invalid"))
		status, res := routedCurl(t, "not-a-real-token", allowedHost)
		keep(res)
		if res.Exit != 0 || !strings.HasPrefix(status, "200 ") {
			t.Fatalf("garbage-token request was not allowed: exit %d, status %q (stderr: %s)", res.Exit, status, firstLine(res.Stderr))
		}
		e := waitEvent(t, "a new invalid event", func() (analytics.Event, bool) {
			evs := statusEvents(t, allowedHost, "invalid")
			if len(evs) > before {
				return evs[0], true
			}
			return analytics.Event{}, false
		})
		if e.UserSub != "" || e.UserEmail != "" {
			t.Errorf("an invalid token must carry no user, got sub %q email %q", e.UserSub, e.UserEmail)
		}
	})

	t.Run("6 direct egress blocked and Dex unreachable from the agent", func(t *testing.T) {
		direct := func(u string) compose.Result {
			return agentExec(t, "curl", "-s", "-o", "/dev/null", "--noproxy", "*", "--max-time", "5", u)
		}
		if res := direct("https://" + allowedHost + "/"); res.Exit == 0 {
			t.Errorf("agent-1 reached %s with no proxy (exit 0)", allowedHost)
		}
		if res := direct("http://dex:5556/dex" + discoveryPath); res.Exit == 0 {
			t.Errorf("agent-1 reached dex:5556 directly (exit 0)")
		}
		// localhost inside the agent is the agent itself: nothing listens on 5556.
		if res := direct(dexURL + discoveryPath); res.Exit == 0 {
			t.Errorf("agent-1 reached %s (exit 0); localhost there is the agent", dexURL)
		}
	})

	t.Run("7 non-allowlisted host is denied and the deny carries alice", func(t *testing.T) {
		status, res := routedCurl(t, token, deniedHost)
		keep(res)
		if res.Exit == 0 || !strings.HasSuffix(status, " 403") {
			t.Fatalf("unlisted host: exit %d, status %q; want a failure with CONNECT 403", res.Exit, status)
		}
		e := waitEvent(t, "a deny event for "+smokeEmail, func() (analytics.Event, bool) {
			for _, e := range cpTraffic(t, "user="+smokeEmail+"&decision=deny&limit=1000") {
				if e.Domain == deniedHost {
					return e, true
				}
			}
			return analytics.Event{}, false
		})
		if e.UserEmail != smokeEmail || e.IdentityStatus != "valid" {
			t.Errorf("deny event: user_email %q, identity_status %q; want %q, valid", e.UserEmail, e.IdentityStatus, smokeEmail)
		}
	})

	t.Run("8 no token or JWT in agent output or logs", func(t *testing.T) {
		surfaces := map[string]string{
			"agent command output": strings.Join(outputs, "\n"),
			"worker-1 logs":        workerLogs(t),
		}
		cp, err := compose.LogsOf(compose.SvcCP)
		if err != nil {
			t.Fatalf("control plane logs: %v", err)
		}
		surfaces["control plane logs"] = cp
		for name, text := range surfaces {
			if strings.Contains(text, token) {
				t.Errorf("%s contain the alice token", name)
			}
			if m := jwtShaped.FindString(text); m != "" {
				t.Errorf("%s contain a JWT-shaped string (%s)", name, fmt.Sprintf("%d chars", len(m)))
			}
		}
	})
}
