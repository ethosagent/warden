package proxy

import (
	"context"
	"log/slog"

	"github.com/ethosagent/warden/internal/identity"
	"github.com/ethosagent/warden/internal/mcp/gateway"
	"github.com/ethosagent/warden/internal/scan"
)

// decisionLog carries the bounded, log-safe fields for one decision record.
// It NEVER carries a raw secret value or a request/response body — SecretRef is
// the by-reference string (sha256/last4/len) only.
type decisionLog struct {
	Domain         string
	Port           int
	Protocol       string
	Method         string
	URL            string
	Decision       string
	ResponseStatus int
	SecretRef      string
	JudgeReason    string
	// Reason is the bounded decision reason from the ONE declared set
	// (internal/denyreason, rule X6 in #349): policy_no_match, the #371
	// constraint reasons, the edge/echo/MCP reasons, … A closed enum — metadata,
	// never content. Every deny carries it (#409). Detail, when non-empty, is a
	// bounded refinement of the reason (e.g. "request_line_too_long"); it never
	// carries request content.
	Reason string
	Detail string
	// AddrClass is the bounded address class behind an ssrf_* Reason (see
	// SSRFError). Empty unless Reason is one of the ssrf_* enums; it never
	// carries a resolved address.
	AddrClass string
	// ID is the caller's identity. While identity is on, logDecision logs its
	// status (none included) and reason, and the sub and group count only for
	// status valid. The email and the group list are logged at debug level only;
	// the token is never here.
	ID connIdentity
}

// logDecision emits one structured record next to the analytics StoreEvent.
// Allows log at info, denials at warn. The logger is never nil (proxy.New
// substitutes a discard logger), so callers need not guard.
func (p *Proxy) logDecision(d decisionLog) {
	attrs := []any{
		slog.String("domain", d.Domain),
		slog.Int("port", d.Port),
		slog.String("protocol", d.Protocol),
		slog.String("decision", d.Decision),
	}
	if d.Method != "" {
		attrs = append(attrs, slog.String("method", d.Method))
	}
	if d.URL != "" {
		attrs = append(attrs, slog.String("url", d.URL))
	}
	if d.ResponseStatus != 0 {
		attrs = append(attrs, slog.Int("response_status", d.ResponseStatus))
	}
	if d.SecretRef != "" {
		attrs = append(attrs, slog.String("secret_ref", d.SecretRef))
	}
	if d.JudgeReason != "" {
		attrs = append(attrs, slog.String("judge_reason", d.JudgeReason))
	}
	if d.Reason != "" {
		attrs = append(attrs, slog.String("reason", d.Reason))
	}
	if d.Detail != "" {
		attrs = append(attrs, slog.String("detail", d.Detail))
	}
	if d.AddrClass != "" {
		attrs = append(attrs, slog.String("addr_class", d.AddrClass))
	}
	// Identity off logs nothing identity-related, like the event. Identity on
	// always logs the status, none included.
	if p.identity() != nil {
		st := d.ID.status()
		attrs = append(attrs, slog.String("identity_status", string(st)))
		if d.ID.Reason != "" {
			attrs = append(attrs, slog.String("identity_reason", string(d.ID.Reason)))
		}
		if st == identity.StatusValid {
			attrs = append(attrs, slog.String("user_sub", d.ID.Claims.Sub), slog.Int("groups_count", len(d.ID.Claims.Groups)))
			if p.cfg.Logger.Enabled(context.Background(), slog.LevelDebug) {
				p.cfg.Logger.Debug("egress decision identity",
					slog.String("user_sub", d.ID.Claims.Sub),
					slog.String("user_email", d.ID.Claims.Email),
					slog.Any("user_groups", d.ID.Claims.Groups),
				)
			}
		}
	}
	if d.Decision == "deny" {
		p.cfg.Logger.Warn("egress decision", attrs...)
		return
	}
	p.cfg.Logger.Info("egress decision", attrs...)
}

// recordMCPFindings records each gateway finding as a bounded scan-finding
// metric and a debug log line. It NEVER logs any value/content — only the
// bounded kind/severity/tool/path. Metrics methods are nil-safe.
func (p *Proxy) recordMCPFindings(v gateway.Verdict) {
	for _, f := range v.Findings {
		p.cfg.Metrics.RecordScanFinding(f.Kind)
		p.cfg.Logger.Debug("mcp finding",
			slog.String("kind", f.Kind),
			slog.String("severity", f.Severity),
			slog.String("tool", f.Tool),
			slog.String("path", f.Path),
		)
	}
}

// recordResponseFindings records each non-MCP HTTP response-scan detection as a
// bounded scan-finding metric and a debug log line. It logs the MASKED evidence
// (last-4 + length, never the raw value) when present — never the body or a raw
// secret. Metrics methods are nil-safe. The metric kind is namespaced
// "http_response_<category>" so it never collides with the MCP finding kinds.
func (p *Proxy) recordResponseFindings(dets []scan.Detection) {
	for _, d := range dets {
		kind := "http_response_" + d.Category
		p.cfg.Metrics.RecordScanFinding(kind)
		p.cfg.Logger.Debug("http response finding",
			slog.String("kind", kind),
			slog.String("pattern", d.Pattern),
			slog.String("severity", d.Severity),
			slog.String("evidence", d.Evidence), // MASKED (opt-in); "" unless Evidence enabled
		)
	}
}

// recordDLPFindings records each outbound REQUEST-body DLP detection as a bounded
// scan-finding metric and a debug log line. The metric kind is namespaced
// "dlp_<category>" so it never collides with the MCP or response-scan finding
// kinds; category is a small closed set (safe as a metric label). The DESTINATION
// is deliberately NOT a label here (unbounded cardinality — it lives only on the
// event, same rule as Tool). It NEVER logs the body or a raw value — only the
// bounded kind/pattern/severity and the opt-in MASKED evidence. The DLP wiring
// builds the scanner WithEvidence(true), so d.Evidence is the value-free
// "••••<last4> (len N)" sample (never the raw match). Metrics methods are nil-safe.
func (p *Proxy) recordDLPFindings(dets []scan.Detection) {
	for _, d := range dets {
		kind := "dlp_" + d.Category
		p.cfg.Metrics.RecordScanFinding(kind)
		p.cfg.Logger.Debug("dlp finding",
			slog.String("kind", kind),
			slog.String("pattern", d.Pattern),
			slog.String("severity", d.Severity),
			slog.String("evidence", d.Evidence), // MASKED (opt-in); "" unless Evidence enabled
		)
	}
}
