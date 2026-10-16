package proxy

import (
	"log/slog"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
)

// denyExtra carries the per-site fields one deny adds on top of the scope's
// request identity. The zero value contributes nothing, so a call site passes
// exactly what its path records today (bounded enums, refs and counts only —
// never a body or a secret value). LatencyMs is per-site rather than implicit
// because the WebSocket session denies are recorded after a pump run of
// arbitrary length, where a session-lifetime figure would read as a mediation
// latency.
type denyExtra struct {
	Protocol       string // override for events audited as "mcp"
	Tool           string // MCP tool name
	JudgeReason    string // free-text judge rationale (judge denies only)
	ResponseStatus int
	SecretRef      string // by-reference secret list (echo-guard denies)
	DataClasses    []string
	DLPAction      string
	DLPRule        string
	DLPPartial     bool
	DLPEncoded     bool
	LatencyMs      int64
	SwappedRefs    []string
	Evidence       []string
}

// emitDeny records one request-scoped deny — the analytics event, the
// deny/request metrics, and the warn decision log — through ONE chokepoint, so
// a deny cannot be recorded without naming why (#409). reason is from the one
// declared set (internal/denyreason); MCP gateway verdict reasons pass through
// gatewayDenyReason. The caller writes the client response.
func (p *Proxy) emitDeny(s *requestScope, reason denyreason.Reason, extra ...denyExtra) {
	ev := analytics.Event{
		Timestamp: time.Now(),
		Domain:    s.domain,
		Port:      s.port,
		Protocol:  s.proto,
		Method:    s.req.Method,
		URL:       s.eventURL(),
		Decision:  "deny",
		Reason:    string(reason),
	}
	for _, x := range extra {
		if x.Protocol != "" {
			ev.Protocol = x.Protocol
		}
		ev.Tool = x.Tool
		ev.JudgeReason = x.JudgeReason
		ev.ResponseStatus = x.ResponseStatus
		ev.SecretRef = x.SecretRef
		ev.DataClasses = x.DataClasses
		ev.DLPAction = x.DLPAction
		ev.DLPRule = x.DLPRule
		ev.DLPPartial = x.DLPPartial
		ev.DLPEncoded = x.DLPEncoded
		ev.LatencyMs = x.LatencyMs
		ev.SwappedRefs = x.SwappedRefs
		ev.Evidence = x.Evidence
	}
	p.emitDenyEvent(ev)
}

// emitDenyEvent is the chokepoint every deny funnel reaches, including the
// pre-tunnel CONNECT denies in serve.go that have no requestScope yet. It
// enforces the reason contract on the finished event: an empty Reason is a bug
// in the deny path, so it is logged loudly and replaced with the declared
// unspecified fallback — an anonymous deny is made visible, never silent. The
// proxy test fakes go further and fail the run on one (test/fakes
// EnforceDenyReason).
func (p *Proxy) emitDenyEvent(ev analytics.Event) {
	if ev.Reason == "" {
		p.cfg.Logger.Error("deny event without a reason; recording the declared unspecified fallback — route the deny through emitDeny/emitDenyEvent with a declared reason",
			slog.String("domain", ev.Domain),
			slog.Int("port", ev.Port),
			slog.String("protocol", ev.Protocol),
		)
		ev.Reason = string(denyreason.Unspecified)
	}
	ev.Decision = "deny"
	_ = p.analyticsStore().StoreEvent(ev)
	p.cfg.Metrics.RecordRequest("deny", ev.Protocol)
	p.cfg.Metrics.RecordBlocked(ev.Reason)
	p.logDecision(decisionLog{
		Domain: ev.Domain, Port: ev.Port, Protocol: ev.Protocol,
		Method: ev.Method, URL: ev.URL, Decision: "deny",
		ResponseStatus: ev.ResponseStatus, SecretRef: ev.SecretRef,
		JudgeReason: ev.JudgeReason, Reason: ev.Reason,
	})
}

// gatewayDenyReason passes an MCP gateway verdict's reason through to the deny
// contract: the gateway's own bounded reasons (declared in
// internal/mcp/gateway) ride unchanged, and an empty one falls back to the
// declared mcp_gateway_deny so a gateway deny is never anonymous (#409).
func gatewayDenyReason(reason string) denyreason.Reason {
	if reason != "" {
		return denyreason.Reason(reason)
	}
	return denyreason.MCPGatewayDeny
}
