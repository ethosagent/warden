package alertpipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/integration"
)

// containsAny reports whether s contains any of subs (case-insensitive), used to
// assert leaky fields never reach the bounded Summary/Evidence strings.
func containsAny(s string, subs ...string) string {
	low := strings.ToLower(s)
	for _, sub := range subs {
		if sub != "" && strings.Contains(low, strings.ToLower(sub)) {
			return sub
		}
	}
	return ""
}

func TestBridgeEvent_ReasonlessDeny(t *testing.T) {
	// The proxy writes Decision "deny" with no Reason for plain allowlist /
	// default-deny blocks — the bridge must turn these into egress_blocked.
	ts := time.Now()
	e := analytics.Event{
		Timestamp:   ts,
		Domain:      "evil.example.com",
		Method:      "POST",
		Decision:    "deny",
		Tool:        "shell",
		URL:         "https://evil.example.com/exfil?token=SECRET123&q=body",
		JudgeReason: "the model tried to leak the API key value abc123",
	}
	f, ok := bridgeEvent("worker-7", e)
	if !ok {
		t.Fatal("deny event should produce a finding")
	}
	if f.RuleID != "egress_blocked" {
		t.Errorf("RuleID = %q, want egress_blocked", f.RuleID)
	}
	if f.Category != "security" {
		t.Errorf("Category = %q, want security", f.Category)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "egress_blocked:evil.example.com" {
		t.Errorf("DedupKey = %q, want egress_blocked:evil.example.com (worker NOT in key)", f.DedupKey)
	}
	if f.Subject.Worker != "worker-7" || f.Subject.Domain != "evil.example.com" {
		t.Errorf("Subject = %+v, want worker-7 / evil.example.com", f.Subject)
	}
	if !f.Ts.Equal(ts) {
		t.Errorf("Ts = %v, want %v", f.Ts, ts)
	}
	// EGRESS HYGIENE: no url/query/body/judgeReason may reach the bounded strings.
	leak := "token=SECRET123 /exfil?q=body abc123 the model tried"
	if hit := containsAny(f.Summary, "SECRET123", "exfil", "abc123", "the model tried", "?"); hit != "" {
		t.Fatalf("Summary %q leaked %q (must contain only bounded enum fields); %s", f.Summary, hit, leak)
	}
	if hit := containsAny(string(f.Evidence), "SECRET123", "exfil", "abc123", "the model tried", "?"); hit != "" {
		t.Fatalf("Evidence %q leaked %q; %s", f.Evidence, hit, leak)
	}
}

func TestBridgeEvent_BlockCompat(t *testing.T) {
	// "block" is not what the proxy writes, but the bridge accepts it for
	// compatibility with external event producers.
	e := analytics.Event{Domain: "evil.example.com", Decision: "block", Method: "GET"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("block event should produce a finding")
	}
	if f.RuleID != "egress_blocked" {
		t.Errorf("RuleID = %q, want egress_blocked", f.RuleID)
	}
	if f.DedupKey != "egress_blocked:evil.example.com" {
		t.Errorf("DedupKey = %q", f.DedupKey)
	}
}

func TestBridgeEvent_ReasonCarryingDeny(t *testing.T) {
	// A deny that carries a bounded reason (dlp_*, mcp_*, scan reasons) keeps its
	// reason-based rule id so routing rules keyed on the reason still match.
	e := analytics.Event{Domain: "api.foo.com", Decision: "deny", Reason: "dlp_credit_card", Tool: "shell"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("reason-carrying deny should produce a finding")
	}
	if f.RuleID != "dlp_credit_card" {
		t.Errorf("RuleID = %q, want dlp_credit_card (reason wins over egress_blocked)", f.RuleID)
	}
	if f.DedupKey != "dlp_credit_card:api.foo.com" {
		t.Errorf("DedupKey = %q", f.DedupKey)
	}
}

// TestBridgeEvent_PolicyDenyReasons (#409): a CONNECT policy deny now carries
// its reason, so it routes as its OWN rule instead of the generic
// egress_blocked. The finding count per deny is unchanged (every deny alerted
// before as egress_blocked); only the rule id / dedup key is finer. All of the
// new reasons stay SevMedium — none contains the poison/exfil escalation
// substrings — so the alerts are neither noisier nor mis-escalated.
func TestBridgeEvent_PolicyDenyReasons(t *testing.T) {
	for _, reason := range []string{"policy_no_match", "policy_denylist", "rate_limited", "time_window"} {
		e := analytics.Event{Domain: "api.foo.com", Decision: "deny", Reason: reason, Method: "GET"}
		f, ok := bridgeEvent("w1", e)
		if !ok {
			t.Fatalf("%s: deny event should produce a finding", reason)
		}
		if f.RuleID != reason {
			t.Errorf("%s: RuleID = %q, want the reason itself", reason, f.RuleID)
		}
		if f.DedupKey != reason+":api.foo.com" {
			t.Errorf("%s: DedupKey = %q", reason, f.DedupKey)
		}
		if f.Severity != integration.SevMedium {
			t.Errorf("%s: Severity = %v, want medium (no escalation substring)", reason, f.Severity)
		}
		// EGRESS HYGIENE: the bounded summary/evidence carry the reason and the
		// domain, never more.
		if hit := containsAny(f.Summary, "?", "SECRET", "/"); hit != "" {
			t.Fatalf("%s: Summary %q leaked %q", reason, f.Summary, hit)
		}
	}
	// The same event without the reason (an old producer) still lands on
	// egress_blocked with the same per-domain dedup — the volume is identical.
	old, ok := bridgeEvent("w1", analytics.Event{Domain: "api.foo.com", Decision: "deny", Method: "GET"})
	if !ok || old.RuleID != "egress_blocked" || old.DedupKey != "egress_blocked:api.foo.com" {
		t.Fatalf("reason-less deny = %v ok=%v, want egress_blocked", old, ok)
	}
}

func TestBridgeEvent_ReasonMedium(t *testing.T) {
	e := analytics.Event{Domain: "api.foo.com", Reason: "mcp_schema_drift", Tool: "search"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("reason event should produce a finding")
	}
	if f.RuleID != "mcp_schema_drift" {
		t.Errorf("RuleID = %q, want mcp_schema_drift", f.RuleID)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("Severity = %v, want medium", f.Severity)
	}
	if f.DedupKey != "mcp_schema_drift:api.foo.com" {
		t.Errorf("DedupKey = %q", f.DedupKey)
	}
}

func TestBridgeEvent_ReasonPoisonHigh(t *testing.T) {
	// A poisoning/exfil reason escalates to SevHigh; tool-keyed when no domain.
	e := analytics.Event{Reason: "mcp_poisoning", Tool: "notes"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("poison event should produce a finding")
	}
	if f.Severity != integration.SevHigh {
		t.Errorf("Severity = %v, want high for a poisoning reason", f.Severity)
	}
	if f.DedupKey != "mcp_poisoning:notes" {
		t.Errorf("DedupKey = %q, want tool-keyed when domain is empty", f.DedupKey)
	}
}

func TestBridgeEvent_BenignAllow(t *testing.T) {
	e := analytics.Event{Domain: "api.openai.com", Decision: "allow", Method: "GET"}
	if _, ok := bridgeEvent("w1", e); ok {
		t.Fatal("a benign allow with no reason must NOT produce a finding")
	}
}

// TestBridgeEvent_MonitorDetectionOnAllowBridges: monitor mode exists to ALERT
// without blocking, so a monitor-mode detection riding an ALLOW event's bounded
// Reason — the #389 echo guard's secret_echo, an MCP gateway's monitor verdict
// reason — must still become a finding, exactly as before #409. The #409
// regression (every permitted MCP WebSocket session alerting mcp_ws) was fixed
// at its source in ws.go, which no longer writes a Reason on an allowed
// session; the bridge keeps keying on a non-empty Reason whatever the decision.
func TestBridgeEvent_MonitorDetectionOnAllowBridges(t *testing.T) {
	e := analytics.Event{Domain: "api.foo.com", Decision: "allow", Reason: "secret_echo"}
	f, ok := bridgeEvent("w1", e)
	if !ok {
		t.Fatal("a monitor-mode detection on an allow event must still become a finding")
	}
	if f.RuleID != "secret_echo" {
		t.Errorf("RuleID = %q, want secret_echo", f.RuleID)
	}
	if f.Severity != integration.SevMedium {
		t.Errorf("Severity = %v, want medium (no escalation substring)", f.Severity)
	}
	if f.DedupKey != "secret_echo:api.foo.com" {
		t.Errorf("DedupKey = %q", f.DedupKey)
	}
}

// TestBridgeEvent_AllowedMCPSessionNoFinding (#409, end to end): the session
// event ws.go now writes for an allowed MCP WebSocket upgrade — Decision allow
// and NO Reason — produces no finding. The regression is fixed at the source
// (the event simply carries nothing to key on), not by silencing allow events
// in the bridge; see TestWS_AllowedSessionEventCarriesNoReason.
func TestBridgeEvent_AllowedMCPSessionNoFinding(t *testing.T) {
	e := analytics.Event{
		Domain:         "mcp.example.com",
		Protocol:       "mcp",
		Method:         "GET",
		Decision:       "allow",
		ResponseStatus: 101,
	}
	if _, ok := bridgeEvent("w1", e); ok {
		t.Fatal("an allowed MCP WebSocket session (no Reason) must not produce a finding")
	}
}

func blockedEvent(sub, email, domain string) analytics.Event {
	return analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Decision:  "deny",
		Reason:    string(denyreason.UserBlocked),
		UserSub:   sub,
		UserEmail: email,
		URL:       "https://" + domain + "/x?token=SECRET123",
	}
}

func TestBridgeUserBlocked(t *testing.T) {
	a1, ok1 := bridgeEvent("w1", blockedEvent("sub-alice", "alice@corp.example", "a.example.com"))
	a2, ok2 := bridgeEvent("w1", blockedEvent("sub-alice", "alice@corp.example", "b.example.com"))
	b1, ok3 := bridgeEvent("w1", blockedEvent("sub-bob", "bob@corp.example", "a.example.com"))
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("user_blocked events must produce findings")
	}
	if a1.DedupKey != a2.DedupKey {
		t.Errorf("one user on two domains must share a key: %q vs %q", a1.DedupKey, a2.DedupKey)
	}
	if a1.DedupKey == b1.DedupKey {
		t.Errorf("two users on one domain must differ: %q", a1.DedupKey)
	}
	sum := sha256.Sum256([]byte("sub-alice"))
	if want := "user_blocked:" + hex.EncodeToString(sum[:])[:16]; a1.DedupKey != want {
		t.Errorf("DedupKey = %q, want %q", a1.DedupKey, want)
	}
	if a1.Severity != integration.SevHigh || a1.Category != "security" || a1.RuleID != "user_blocked" {
		t.Errorf("got severity=%v category=%q rule=%q", a1.Severity, a1.Category, a1.RuleID)
	}
	if a1.Subject.Domain != "" || a1.Subject.User != "sub-alice" || a1.Subject.Worker != "w1" {
		t.Errorf("Subject = %+v", a1.Subject)
	}
	if want := "user blocked: " + hex.EncodeToString(sum[:])[:8] + " denied"; a1.Summary != want {
		t.Errorf("Summary = %q, want %q", a1.Summary, want)
	}
	if a1.Evidence != "reason=user_blocked" {
		t.Errorf("Evidence = %q", a1.Evidence)
	}
}

func TestBridgeUserBlockedNoEmail(t *testing.T) {
	f, ok := bridgeEvent("w1", blockedEvent("sub-alice", "alice@corp.example", "secret.example.com"))
	if !ok {
		t.Fatal("expected finding")
	}
	raw, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, f.DedupKey) || !strings.Contains(s, `"User":"sub-alice"`) && !strings.Contains(s, `"user":"sub-alice"`) {
		t.Errorf("marshalled finding missing dedup key or Subject.User: %s", s)
	}
	if leak := containsAny(s, "alice@corp.example", "corp.example", "SECRET123", "secret.example.com"); leak != "" {
		t.Errorf("finding leaks %q: %s", leak, s)
	}
}

func TestBridgeUserBlockedNoSub(t *testing.T) {
	f, ok := bridgeEvent("w1", blockedEvent("", "", "a.example.com"))
	if !ok {
		t.Fatal("expected finding")
	}
	if f.DedupKey != "user_blocked:unknown" || f.Severity != integration.SevHigh {
		t.Errorf("DedupKey=%q severity=%v", f.DedupKey, f.Severity)
	}
	if f.Subject.User != "" || f.Subject.Domain != "" {
		t.Errorf("Subject = %+v", f.Subject)
	}
}
