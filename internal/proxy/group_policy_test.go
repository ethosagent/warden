package proxy

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/config"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/policy"
)

// W-P1-GPOL-10: the policy stage decides identity-scoped allow entries on
// every request with that request's verified subject, on CONNECT, HTTP/1.1 and
// every h2 stream. Evaluators are built from a policy with a scoped entry; the
// fake verifier knows tok-alice and tok-bob (group eng), tok-expired, tok-bad,
// plus the sales/ops tokens each test adds.

const (
	hdrAlice = "X-Warden-Identity: Bearer tok-alice\r\n"
	hdrSales = "X-Warden-Identity: Bearer tok-sales\r\n"
)

// gpEnv is an idEnv whose policy allows idHost for group eng only.
func gpEnv(t *testing.T, edit func(*Config)) *idEnv {
	t.Helper()
	e := newIDEnvCfg(t, IdentityModeAttribute, scopedEdit(edit))
	e.v.Set("tok-sales", identity.Claims{Sub: "sam", Email: "sam@example.test", Groups: []string{"sales"}, Expiry: e.clk.now().Add(time.Hour)}, identity.StatusValid, "")
	return e
}

func (e *idEnv) lastDeny(t *testing.T, reason denyreason.Reason) analytics.Event {
	t.Helper()
	evs := e.waitDeny(t, reason, 1)
	return evs[len(evs)-1]
}

func TestGroupPolicy_ConnectIdentity(t *testing.T) {
	e := gpEnv(t, nil)

	// A member's token on Proxy-Authorization: the tunnel opens and each
	// request is decided with that subject.
	c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
	if got := c.get(""); got != http.StatusOK {
		t.Fatalf("eng token request = %d, want 200", got)
	}

	// A non-member's token is refused outright, with the group reason.
	_, _, status := e.connect("Proxy-Authorization: " + basicAuth("tok-sales") + "\r\n")
	if !strings.Contains(status, "403") {
		t.Fatalf("sales CONNECT = %q, want 403", status)
	}
	ev := e.lastDeny(t, denyreason.GroupNotAllowed)
	if ev.IdentityStatus != "valid" || ev.UserSub != "sam" {
		t.Errorf("deny event identity = %q/%q, want valid/sam", ev.IdentityStatus, ev.UserSub)
	}
	if got := e.m.scopedCount("allow"); got != 1 {
		t.Errorf("scoped allow = %d, want 1; %s", got, e.m.describe())
	}
}

func TestGroupPolicy_RequestIdentity(t *testing.T) {
	e := gpEnv(t, nil)
	c := e.h1("")
	if got := c.get(hdrAlice); got != http.StatusOK {
		t.Fatalf("eng request = %d, want 200", got)
	}
	if got := c.get(hdrSales); got != http.StatusForbidden {
		t.Fatalf("following sales request on the same tunnel = %d, want 403", got)
	}
	// A deny ends an h1 session (as any constraint deny does), so the next
	// caller opens a new tunnel.
	e.lastDeny(t, denyreason.GroupNotAllowed)
	if got := e.m.scopedCount("allow"); got != 1 {
		t.Errorf("scoped allow = %d, want 1", got)
	}
	if got := e.m.scopedCount("not_member"); got != 1 {
		t.Errorf("scoped not_member = %d, want 1", got)
	}
}

func TestGroupPolicy_H2PerStream(t *testing.T) {
	e := gpEnv(t, nil)
	cc := e.h2("")
	for i, tc := range []struct {
		tok  string
		want int
	}{{"tok-alice", 200}, {"tok-sales", 403}, {"tok-alice", 200}, {"", 403}} {
		hdr := map[string]string{}
		if tc.tok != "" {
			hdr["X-Warden-Identity"] = "Bearer " + tc.tok
		}
		if got := h2Get(t, cc, hdr); got != tc.want {
			t.Errorf("stream %d (%q) = %d, want %d", i, tc.tok, got, tc.want)
		}
	}
	e.waitDeny(t, denyreason.GroupNotAllowed, 1)
	e.waitDeny(t, denyreason.IdentityRequired, 1)
}

func TestGroupPolicy_NoIdentityReasons(t *testing.T) {
	e := gpEnv(t, nil)
	e.v.Set("tok-carol", identity.Claims{Sub: "carol", Groups: []string{"eng"}, Expiry: e.clk.now().Add(time.Hour)}, identity.StatusValid, "")

	cases := []struct {
		name   string
		hdr    string
		status string
	}{
		{"anonymous", "", "none"},
		{"invalid", "X-Warden-Identity: Bearer tok-bad\r\n", "invalid"},
		{"expired", "X-Warden-Identity: Bearer tok-expired\r\n", "expired"},
		{"conflict", "X-Warden-Identity: Bearer tok-carol\r\n", "conflict"},
	}
	// The conflict case needs a CONNECT identity that differs from the header.
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			connect := ""
			if tc.name == "conflict" {
				connect = "Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n"
			}
			before := len(e.waitDenyAll())
			c := e.h1(connect)
			if got := c.get(tc.hdr); got != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", got)
			}
			evs := e.waitDeny(t, denyreason.IdentityRequired, before+1)
			if got := evs[len(evs)-1].IdentityStatus; got != tc.status {
				t.Errorf("event identity_status = %q, want %q", got, tc.status)
			}
		})
	}
	if got := e.m.scopedCount("no_identity"); got != len(cases) {
		t.Errorf("scoped no_identity = %d, want %d; %s", got, len(cases), e.m.describe())
	}

	t.Run("token expires mid-session", func(t *testing.T) {
		c := e.h1("Proxy-Authorization: " + basicAuth("tok-alice") + "\r\n")
		if got := c.get(""); got != http.StatusOK {
			t.Fatalf("before expiry = %d, want 200", got)
		}
		e.clk.advance(2 * time.Hour)
		if got := c.get(""); got != http.StatusForbidden {
			t.Fatalf("after expiry = %d, want 403", got)
		}
		evs := e.waitDeny(t, denyreason.IdentityRequired, len(cases)+1)
		if got := evs[len(evs)-1].IdentityStatus; got != "expired" {
			t.Errorf("event identity_status = %q, want expired", got)
		}
	})
}

// waitDenyAll is the current identity_required deny events (no waiting).
func (e *idEnv) waitDenyAll() []analytics.Event {
	var out []analytics.Event
	for _, ev := range e.denyEvents() {
		if ev.Reason == string(denyreason.IdentityRequired) {
			out = append(out, ev)
		}
	}
	return out
}

func TestGroupPolicy_NeverJudged(t *testing.T) {
	j := &fakeJudge{verdict: Verdict{Decision: "allow"}}
	e := gpEnv(t, func(c *Config) { c.Judge = j })
	if got := e.h1("").get(hdrSales); got != http.StatusForbidden {
		t.Errorf("non-member = %d, want 403", got)
	}
	if got := e.h1("").get(""); got != http.StatusForbidden {
		t.Errorf("anonymous = %d, want 403", got)
	}
	if got := e.h1("").get(hdrAlice); got != http.StatusOK {
		t.Errorf("member = %d, want 200", got)
	}
	if n := j.callCount(); n != 0 {
		t.Errorf("judge calls = %d, want 0: a scoped destination never reaches the judge", n)
	}
}

func TestGroupPolicy_TruncatedGroups(t *testing.T) {
	e := gpEnv(t, nil)
	exp := e.clk.now().Add(time.Hour)
	e.v.Set("tok-trunc-member", identity.Claims{Sub: "tm", Groups: []string{"eng"}, GroupsTruncated: true, Expiry: exp}, identity.StatusValid, "")
	e.v.Set("tok-trunc-other", identity.Claims{Sub: "to", Groups: []string{"ops"}, GroupsTruncated: true, Expiry: exp}, identity.StatusValid, "")
	c := e.h1("")
	if got := c.get("X-Warden-Identity: Bearer tok-trunc-member\r\n"); got != http.StatusOK {
		t.Errorf("member found in the partial list = %d, want 200", got)
	}
	if got := c.get("X-Warden-Identity: Bearer tok-trunc-other\r\n"); got != http.StatusForbidden {
		t.Errorf("non-member with truncated groups = %d, want 403", got)
	}
	e.lastDeny(t, denyreason.IdentityGroupsTruncated)
	if got := e.m.scopedCount("not_member"); got != 1 {
		t.Errorf("scoped not_member = %d, want 1", got)
	}
}

func TestGroupPolicy_PolicySwapMidSession(t *testing.T) {
	e := gpEnv(t, nil)
	c := e.h1("")
	if got := c.get(hdrAlice); got != http.StatusOK {
		t.Fatalf("before the swap = %d, want 200", got)
	}
	e.p.cfg.Policy.Replace(config.Policy{Allowlist: []config.AllowlistEntry{
		{Domain: idHost, Port: 443, Groups: []string{"ops"}},
	}})
	if got := c.get(hdrAlice); got != http.StatusForbidden {
		t.Fatalf("after the group was removed = %d, want 403 on the same tunnel", got)
	}
	e.lastDeny(t, denyreason.GroupNotAllowed)
}

func TestGroupPolicy_RateChargedOnce(t *testing.T) {
	e := gpEnv(t, func(c *Config) {
		c.Policy = policy.NewEvaluator(config.Policy{Allowlist: []config.AllowlistEntry{
			{Domain: idHost, Port: 443, Groups: []string{"eng"}, RateLimit: "2/minute"},
		}})
	})
	// Non-members and anonymous callers do not consume the budget.
	for i := 0; i < 3; i++ {
		if got := e.h1("").get(hdrSales); got != http.StatusForbidden {
			t.Fatalf("sales %d = %d, want 403", i, got)
		}
		if got := e.h1("").get(""); got != http.StatusForbidden {
			t.Fatalf("anonymous %d = %d, want 403", i, got)
		}
	}
	// Two members' requests fit the budget of 2 (one charge each, not two).
	c := e.h1("")
	for i := 0; i < 2; i++ {
		if got := c.get(hdrAlice); got != http.StatusOK {
			t.Fatalf("member %d = %d, want 200", i, got)
		}
	}
	if got := c.get(hdrAlice); got != http.StatusForbidden {
		t.Fatalf("third member request = %d, want 403 rate_limited", got)
	}
	e.lastDeny(t, denyreason.RateLimited)
}

func TestRecordScoped(t *testing.T) {
	m := newFakeMetrics()
	p := &Proxy{cfg: Config{Metrics: m}}
	for _, v := range []policy.RequestVerdict{
		{Decision: policy.Allow, Scoped: true},
		{Decision: policy.Deny, Reason: denyreason.GroupNotAllowed, Scoped: true},
		{Decision: policy.Deny, Reason: denyreason.IdentityGroupsTruncated, Scoped: true},
		{Decision: policy.Conditional, Reason: denyreason.IdentityRequired, Scoped: true},
		{Decision: policy.Deny, Reason: denyreason.RateLimited, Scoped: true}, // not an identity outcome
		{Decision: policy.Allow}, // unscoped: nothing recorded
		{Decision: policy.NoMatch},
	} {
		p.recordScoped(v)
	}
	if m.scopedCount("allow") != 1 || m.scopedCount("not_member") != 2 || m.scopedCount("no_identity") != 1 {
		t.Errorf("scoped counts wrong: %s", m.describe())
	}
}

func TestGroupPolicy_ScopedMetricsNoLeak(t *testing.T) {
	e := gpEnv(t, nil)
	e.h1("").get(hdrAlice)
	e.h1("").get(hdrSales)
	for _, l := range e.m.log {
		for _, bad := range []string{"tok-", "sam", "alice@", "sales", "eng"} {
			if strings.Contains(l, bad) {
				t.Errorf("metric record %q leaks %q", l, bad)
			}
		}
	}
}
