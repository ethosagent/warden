package proxy

import (
	"log/slog"

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
// bounded kind/pattern/severity and the opt-in MASKED evidence (empty in Phase 1,
// which builds the scanner WithEvidence(false)). Metrics methods are nil-safe.
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
