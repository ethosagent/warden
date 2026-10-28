package alertpipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/integration"
)

// bridge.go is the event→Finding bridge: a small, isolated, deliberately
// conservative producer that runs alongside the temporal-detection engine. It
// bridges already-observed, security-relevant analytics events into Findings so
// the alert pipeline (bus → alertmanager → store → router → integrations) is live
// for block/reason events immediately, without waiting for a detection window.
// Keep it small and bounded. It is part of the pipeline assembly, so it lives
// here with Observe rather than in any host package.
//
// EGRESS HYGIENE (invariant): a Finding crosses Warden's trust boundary when the
// router pushes the derived Alert to a third-party webhook/Slack. So Summary and
// Evidence here carry ONLY bounded enum fields — Domain, Tool, Decision, Reason,
// Method. They NEVER include e.URL (may carry query params), request/response
// bodies, or e.JudgeReason (free-text). This preserves Warden's egress-hygiene
// invariant; do not add free-text or value-bearing fields here. The one
// identity exception is user_blocked, which carries the opaque UserSub (never
// the email) on Subject.User and only a hash of it in Summary and DedupKey.

// reasonSeverity escalates the most dangerous bounded MCP/scan reasons to
// SevHigh; every other reason stays SevMedium. It is a tiny, bounded escalation
// map (substring match on the bounded reason enum), NOT a general classifier.
func reasonSeverity(reason string) integration.Severity {
	r := strings.ToLower(reason)
	if r == string(denyreason.UserBlocked) {
		return integration.SevHigh
	}
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
	// The proxy writes Decision "deny" (internal/proxy: http.go, ws.go, serve.go);
	// "block" is accepted too for compatibility with external event producers.
	denied := strings.EqualFold(e.Decision, "deny") || strings.EqualFold(e.Decision, "block")
	switch {
	case e.Reason == string(denyreason.UserBlocked):
		// One Finding per blocked user across every domain: Domain is left empty
		// and the key hashes the sub, so the alert names a stable pseudonym, not
		// an email. With no sub the finding still alerts on one fleet-wide key.
		key := "user_blocked:unknown"
		summary := "user blocked: unknown denied"
		if e.UserSub != "" {
			h := sha256.Sum256([]byte(e.UserSub))
			full := hex.EncodeToString(h[:])
			key = "user_blocked:" + full[:16]
			summary = "user blocked: " + full[:8] + " denied"
		}
		return integration.Finding{
			RuleID:   e.Reason,
			Category: "security",
			Severity: reasonSeverity(e.Reason),
			Subject:  integration.Subject{Worker: proxyID, User: e.UserSub},
			Summary:  summary,
			Evidence: integration.Evidence("reason=" + e.Reason),
			DedupKey: key,
			Ts:       e.Timestamp,
		}, true
	case e.Reason != "":
		// A bounded MCP/scan reason (e.g. "mcp_poisoning", "dlp_credit_card"). The
		// reason enum IS the rule id — checked BEFORE the deny branch so
		// reason-carrying denies keep their reason-based rule ids for routing.
		// Subject keys on domain, falling back to tool for MCP-only events that
		// carry no domain.
		//
		// An ALLOW reaches this branch only when a monitor-mode detection rode it
		// (the #389 echo guard's secret_echo, an MCP gateway monitor verdict):
		// monitor mode alerts without blocking, so it must alert here. A benign
		// allow carries no Reason — informational allow metadata lives in
		// JudgeReason or dedicated fields (DLPAction, DLPRule, …), never here
		// (internal/proxy/ws.go documents the allowed-session contract).
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
	case denied:
		// A reason-less blocked egress. Since #409 every proxy-written deny
		// carries a bounded reason (internal/denyreason) and takes the branch
		// above; this remains for external event producers that do not.
		// Bounded fields only — domain + method for the summary, the decision enum
		// for evidence.
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
			Evidence: integration.Evidence("decision=" + strings.ToLower(e.Decision)),
			DedupKey: "egress_blocked:" + e.Domain,
			Ts:       e.Timestamp,
		}, true
	default:
		return integration.Finding{}, false
	}
}
