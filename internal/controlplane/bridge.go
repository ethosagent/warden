package controlplane

import (
	"strings"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/integration"
)

// bridge.go is the M1 event→Finding bridge: a small, isolated, deliberately
// conservative stand-in for the future (M3) temporal-detection engine. Until the
// detection engine ships, we bridge already-observed, security-relevant analytics
// events into Findings so the alert pipeline (bus → alertmanager → store →
// router → integrations) is live end to end. Keep it small and bounded.
//
// EGRESS HYGIENE (invariant): a Finding crosses Warden's trust boundary when the
// router pushes the derived Alert to a third-party webhook/Slack. So Summary and
// Evidence here carry ONLY bounded enum fields — Domain, Tool, Decision, Reason,
// Method. They NEVER include e.URL (may carry query params), request/response
// bodies, or e.JudgeReason (free-text). This preserves Warden's egress-hygiene
// invariant; do not add free-text or value-bearing fields here.

// reasonSeverity escalates the most dangerous bounded MCP/scan reasons to
// SevHigh; every other reason stays SevMedium. It is a tiny, bounded escalation
// map (substring match on the bounded reason enum), NOT a general classifier.
func reasonSeverity(reason string) integration.Severity {
	r := strings.ToLower(reason)
	if strings.Contains(r, "poison") || strings.Contains(r, "exfil") {
		return integration.SevHigh
	}
	return integration.SevMedium
}

// bridgeEvent maps one analytics.Event to a Finding, returning ok=false for
// events that should not alert (the common case: a benign allow).
//
// proxyID is the worker that produced the event; it is recorded on
// Subject.Worker but — per the plan's per-rule dedup-scope decision — is NOT part
// of the egress_blocked DedupKey. So a blocked domain dedups fleet-wide (one
// alert per domain across the whole fleet) while Subject.Worker still records
// which worker last saw it. Reason-based findings key on domain-or-tool for the
// same fleet-wide dedup.
func bridgeEvent(proxyID string, e analytics.Event) (integration.Finding, bool) {
	switch {
	case strings.EqualFold(e.Decision, "block"):
		// A blocked egress: default-deny fired (or a rule denied). Bounded fields
		// only — domain + method for the summary, decision + bounded reason enum for
		// evidence.
		summary := "blocked egress to " + e.Domain
		if e.Method != "" {
			summary = "blocked " + e.Method + " egress to " + e.Domain
		}
		return integration.Finding{
			RuleID:   "egress_blocked",
			Category: "security",
			Severity: integration.SevMedium,
			Subject:  integration.Subject{Domain: e.Domain, Tool: e.Tool, Worker: proxyID},
			Summary:  summary,
			Evidence: integration.Evidence("decision=block reason=" + e.Reason),
			DedupKey: "egress_blocked:" + e.Domain,
			Ts:       e.Timestamp,
		}, true
	case e.Reason != "":
		// A bounded MCP/scan reason (e.g. "mcp_poisoning") on an allowed path. The
		// reason enum IS the rule id; subject keys on domain, falling back to tool
		// for MCP-only events that carry no domain.
		subject := e.Domain
		if subject == "" {
			subject = e.Tool
		}
		return integration.Finding{
			RuleID:   e.Reason,
			Category: "security",
			Severity: reasonSeverity(e.Reason),
			Subject:  integration.Subject{Domain: e.Domain, Tool: e.Tool, Worker: proxyID},
			Summary:  "detected " + e.Reason + " on " + subject,
			Evidence: integration.Evidence("reason=" + e.Reason),
			DedupKey: e.Reason + ":" + subject,
			Ts:       e.Timestamp,
		}, true
	default:
		return integration.Finding{}, false
	}
}
