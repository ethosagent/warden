package scenarios

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/tokensvc"
	"github.com/ethosagent/warden/test/harness"
)

// The token endpoint's limits, records and retention (W-P2-TOKX-04): a per-agent
// budget that only a verified agent can spend, a per-IP budget that stops a
// flood of forged assertions before it reaches any agent's budget, one
// token_events row and one warden.token.v1 line per authenticated outcome and
// none for the rest, no credential anywhere in them, and a retention ticker on
// the control plane's clock.

func tokenLimitsOpts(extra ...harness.Option) []harness.Option { return tokenServiceOpts(extra...) }

// forwarded makes the request look like it came from client through a reverse
// proxy the control plane trusts (WithTokenTrustedLoopbackProxy).
func forwarded(client string) http.Header { return http.Header{"X-Forwarded-For": {client}} }

// retryAfterSeconds checks a 429 carries a whole-second Retry-After >= 1.
func retryAfterSeconds(t *testing.T, name string, r harness.RawResponse) int {
	t.Helper()
	n, err := strconv.Atoi(r.Header.Get("Retry-After"))
	if err != nil || n < 1 {
		t.Fatalf("%s: Retry-After = %q, want an integer >= 1", name, r.Header.Get("Retry-After"))
	}
	return n
}

// tokenExchangeRateLimitedPerAgent: the verified agent's budget is spent by its
// own exchanges, the next one is a 429 rate_limited with Retry-After, another
// agent is unaffected, the budget refills with time, and the refusal is
// recorded because the agent had authenticated.
func tokenExchangeRateLimitedPerAgent(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	other := h.RegisterTokenAgent("other-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	for i := 0; i < 5; i++ {
		decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, fmt.Sprintf("user-%d", i), "eng"), nil)))
	}
	limited := exchangeForm(h, agent.Form(tokenUser(h, "user-5", "eng"), nil))
	requireRefusal(t, "sixth exchange in the minute", limited, 429, "rate_limited", "rate_limited")
	if got := retryAfterSeconds(t, "per-agent limit", limited); got != 12 {
		t.Errorf("Retry-After = %d, want 12 (5/minute refills one every 12s)", got)
	}
	decodeToken(t, exchangeForm(h, other.Form(tokenUser(h, "user-6", "eng"), nil)))

	h.Clock().Advance(13 * time.Second)
	decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-7", "eng"), nil)))

	var denied []harness.TokenEventRow
	for _, e := range h.TokenEvents() {
		if e.Outcome == tokensvc.OutcomeDenied {
			denied = append(denied, e)
		}
	}
	if len(denied) != 1 || denied[0].Reason != "rate_limited" || denied[0].AgentID != "harness-agent" {
		t.Errorf("denied rows = %+v, want one rate_limited row for harness-agent", denied)
	}
}

// tokenExchangeForgedAgentNoDoS: a flood of forged assertions that claim a real
// agent is stopped by the per-IP limit and never touches that agent's own
// budget, so a genuine request from another address still succeeds.
func tokenExchangeForgedAgentNoDoS(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	attacker, genuine := forwarded("203.0.113.9"), forwarded("198.51.100.7")
	var unauth, throttled int
	for i := 0; i < 50; i++ {
		forged := agent.Form("not-a-jwt", nil, harness.AssertionHeader("kid", "no-such-key"))
		switch r := h.CP().Exchange(forged.Encode(), attacker); r.Status {
		case http.StatusUnauthorized:
			unauth++
		case http.StatusTooManyRequests:
			throttled++
			requireNoStore(t, r)
			retryAfterSeconds(t, "per-IP limit", r)
		default:
			t.Fatalf("forged request %d = %d %s", i, r.Status, r.Body)
		}
	}
	if unauth != 20 || throttled != 30 {
		t.Errorf("forged flood: %d unauthorized and %d throttled, want 20 and 30 (perIP 20/minute)", unauth, throttled)
	}
	// The agent's own budget (5/minute) is whole: five genuine exchanges pass.
	for i := 0; i < 5; i++ {
		res := h.CP().Exchange(agent.Form(tokenUser(h, fmt.Sprintf("user-%d", i), "eng"), nil).Encode(), genuine)
		decodeToken(t, res)
	}
	requireRefusal(t, "the sixth genuine exchange",
		h.CP().Exchange(agent.Form(tokenUser(h, "user-9", "eng"), nil).Encode(), genuine), 429, "rate_limited", "rate_limited")
}

// logLine is one parsed JSON log line.
type logLine map[string]any

// tokenExchangeLines returns the warden.token.v1 lines of the control-plane log.
func tokenExchangeLines(t *testing.T, logs string) []logLine {
	t.Helper()
	var out []logLine
	for _, ln := range strings.Split(logs, "\n") {
		if !strings.Contains(ln, `"token_exchange"`) {
			continue
		}
		var l logLine
		if err := json.Unmarshal([]byte(ln), &l); err != nil || l["msg"] != "token_exchange" {
			continue
		}
		out = append(out, l)
	}
	return out
}

// tokenExchangeEventsRecorded: an issuance and a group_not_allowed denial each
// write exactly one token_events row and one warden.token.v1 line and no admin
// audit row; unauthenticated failures write none; no credential is in any row
// or line.
func tokenExchangeEventsRecorded(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	auditBefore := len(h.AdminAuditRows())

	user := tokenUser(h, "user-42", "eng")
	form := agent.Form(user, nil)
	assertion := form.Get("client_assertion")
	tr := decodeToken(t, exchangeForm(h, form))
	outsider := tokenUser(h, "user-43", "sales")
	denied := exchangeForm(h, agent.Form(outsider, nil))
	requireRefusal(t, "outside the agent's groups", denied, 400, "unauthorized_client", "group_not_allowed")

	for i := 0; i < 100; i++ {
		f := agent.Form(user, nil)
		a := f.Get("client_assertion")
		mid := len(a) - 20
		swap := "A"
		if a[mid:mid+1] == "A" {
			swap = "B"
		}
		f.Set("client_assertion", a[:mid]+swap+a[mid+1:])
		requireRefusal(t, "bad signature", exchangeForm(h, f), 401, "invalid_client", "client_authentication_failed")
	}

	rows := h.TokenEvents()
	if len(rows) != 2 {
		t.Fatalf("token_events has %d rows after 1 issuance, 1 denial and 100 bad signatures, want 2: %+v", len(rows), rows)
	}
	issued, refused := rows[0], rows[1]
	_, claims := verifyWardenToken(t, h, tr.AccessToken)
	switch {
	case issued.Outcome != "issued" || issued.Reason != "" || issued.AgentID != "harness-agent" ||
		issued.SID != claims.SID || issued.JTI != claims.JTI || issued.Exp != claims.Exp || issued.Scope != "read" || issued.KID == "":
		t.Errorf("issued row = %+v, want the token's sid %s jti %s exp %d", issued, claims.SID, claims.JTI, claims.Exp)
	case refused.Outcome != "denied" || refused.Reason != "group_not_allowed" || refused.AgentID != "harness-agent" || refused.SID != "" || refused.JTI != "":
		t.Errorf("denied row = %+v", refused)
	case len(issued.SubHMAC) != 64 || issued.SubHMAC == refused.SubHMAC || len(refused.SubHMAC) != 64:
		t.Errorf("sub_hmac = %q and %q, want two different 64-hex pseudonyms", issued.SubHMAC, refused.SubHMAC)
	}

	lines := tokenExchangeLines(t, h.Logs())
	if len(lines) != 2 {
		t.Fatalf("%d token_exchange lines, want 2: %v", len(lines), lines)
	}
	for i, want := range []harness.TokenEventRow{issued, refused} {
		l := lines[i]
		if l["schema"] != tokensvc.EventSchema || l["outcome"] != want.Outcome || l["reason"] != want.Reason ||
			l["agent"] != want.AgentID || l["sub"] != want.SubHMAC || l["sid"] != want.SID || l["jti"] != want.JTI || l["kid"] != want.KID {
			t.Errorf("line %d = %v, want it to mirror row %+v", i, l, want)
		}
	}

	if after := h.AdminAuditRows(); len(after) != auditBefore {
		t.Errorf("admin_audit grew from %d to %d rows: machine events stay out of the admin chain", auditBefore, len(after))
	}

	stored, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string]string{"subject token": user, "client assertion": assertion, "issued token": tr.AccessToken, "raw subject": "user-42"} {
		if strings.Contains(string(stored), secret) {
			t.Errorf("a token_events row holds the %s", name)
		}
		if strings.Contains(h.Logs(), secret) && name != "raw subject" {
			t.Errorf("the control-plane log holds the %s", name)
		}
	}
	for _, l := range lines {
		if strings.Contains(fmt.Sprint(l), "user-42") {
			t.Errorf("a token_exchange line holds the raw subject: %v", l)
		}
	}
}

// tokenRetentionPurges: the control plane's retention ticker, on its own clock,
// removes expired assertion records and issuance records past eventRetention.
func tokenRetentionPurges(t *testing.T, h *harness.H) {
	agent := h.RegisterTokenAgent("harness-agent", []string{"eng"}, []string{"read"})
	waitTokenKeyPublished(h)
	decodeToken(t, exchangeForm(h, agent.Form(tokenUser(h, "user-1", "eng"), nil)))
	if n := len(h.TokenEvents()); n != 1 {
		t.Fatalf("token_events has %d rows, want 1", n)
	}
	if h.TokenReplayRows() == 0 {
		t.Fatal("the used assertion left no replay record")
	}
	// The assertion record is past its expiry after the first tick.
	h.Eventually("the retention ticker purges the replay record", func() bool {
		h.Clock().Advance(time.Hour)
		return h.TokenReplayRows() == 0
	})
	// The issuance record outlives it until eventRetention (24h) has passed.
	h.Eventually("the retention ticker purges the issuance record", func() bool {
		h.Clock().Advance(time.Hour)
		return len(h.TokenEvents()) == 0
	})
}
