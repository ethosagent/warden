package proxy

import (
	"log/slog"

	"github.com/ethosagent/warden/internal/mcp/gateway"
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
