package proxy

import (
	"io"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/policy"
)

// Per-user rate limits (W-P3-PUL-09). The evaluator (internal/policy,
// userlimit.go) picks the one rule that applies and owns the buckets; this
// file decides WHEN to charge and how a refusal is answered.
//
// A limit is charged once per unit of work the proxy can see:
//   - every HTTP/1.1 request, HTTP/2 or gRPC stream and WebSocket upgrade, in
//     userLimitStage (each request carries its own subject, so one keep-alive
//     session carrying several users charges each of them);
//   - a raw tunnel (no CA) once at CONNECT, before the 200;
//   - an opaque passthrough on a TLS-terminating worker (non-TLS bytes, or
//     non-HTTP inside TLS) once, before the dial, since no request in it can
//     be seen.
//
// A TLS-terminated CONNECT only peeks (PeekUserLimit): the per-request charge
// is authoritative and a tunnel must not cost a request of its own.
//
// Limits are checked only when the policy verdict was Allow, after the
// identity, block-list and policy stages and before the judge: they can turn
// an allow into a deny, never anything into an allow, and they never see a
// secret (they run before the swap). The agent id is always the worker's
// bound agent (Config.AgentID), never a request or token value.

// userLimitKindRate is the kind label of warden.user_limit.denied.total for a
// rate refusal (W-P3-PUL-04 adds cost and unmeasurable).
const userLimitKindRate = "rate"

// userRateLimitedBody and userGroupsTruncatedBody are the JSON bodies of the two
// user-limit refusals, built from the declared reasons, never a second literal.
var (
	userRateLimitedBody     = `{"error":"` + string(denyreason.UserRateLimited) + `"}`
	userGroupsTruncatedBody = `{"error":"` + string(denyreason.IdentityGroupsTruncated) + `"}`
)

// retryAfterSeconds renders a bucket's time-to-reset as the integer seconds of
// a Retry-After header: rounded up, at least 1, so a client that honours it
// never retries into the same exhausted window.
func retryAfterSeconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	if s < 1 {
		return 1
	}
	return s
}

// userLimitResponse maps a user-limit deny verdict to the client answer: 429
// with Retry-After for user_rate_limited; 403 with no Retry-After for every
// other reason (identity_groups_truncated: waiting does not help, the IdP's
// group list is what is wrong).
func userLimitResponse(v policy.RequestVerdict) (status int, body string, retryAfter int) {
	switch v.Reason {
	case denyreason.UserRateLimited:
		return http.StatusTooManyRequests, userRateLimitedBody, retryAfterSeconds(v.RetryAfter)
	case denyreason.IdentityGroupsTruncated:
		return http.StatusForbidden, userGroupsTruncatedBody, 0
	default:
		// The evaluator declares no other user-limit reason; one added later
		// still refuses, under its own (declared) name.
		return http.StatusForbidden, `{"error":"` + string(v.Reason) + `"}`, 0
	}
}

// recordUserLimitDenied counts a user-limit refusal on the bounded kind label.
// A truncated-groups refusal is not a limit hit, so only the rate reason counts.
func (p *Proxy) recordUserLimitDenied(v policy.RequestVerdict) {
	if v.Reason == denyreason.UserRateLimited {
		p.cfg.Metrics.RecordUserLimitDenied(userLimitKindRate)
	}
}

// userLimitStage charges the request to the per-user limit rule that applies
// to its subject (nil for no, invalid or expired token: the anonymous rule)
// and refuses it when that rule is out of budget. It runs after constraintGate
// and only when that gate's verdict was Allow, so a NoMatch (judge), Deny or
// Conditional request is never charged and never allowed here. Over the
// limit the judge is not called, nothing is swapped and nothing is dialed.
// With no limits configured it is one read lock in the evaluator and changes
// nothing on the request or its events.
func (p *Proxy) userLimitStage(s *requestScope) (endSession bool) {
	if !s.policyAllowed {
		return false
	}
	v := p.cfg.Policy.ChargeUserLimit(policy.RequestContext{
		Domain: s.domain, Port: s.port, Scheme: s.scheme, Subject: s.subject,
	}, p.cfg.AgentID)
	// Set before any event of this request is recorded (the deny below and the
	// allow at the end both read it).
	s.limitRule = v.LimitRule
	if v.Decision != policy.Deny {
		return false
	}
	p.emitDeny(s, v.Reason, denyExtra{LatencyMs: s.latencyMs()})
	p.recordUserLimitDenied(v)
	status, body, retry := userLimitResponse(v)
	if retry > 0 {
		s.out.errorJSONRetry(status, body, retry)
	} else {
		s.out.errorJSON(status, body)
	}
	return true
}

// connUserLimit applies the per-user limit at a connection-level site (no
// request scope): charge consumes budget, otherwise it peeks. It returns the
// verdict; the caller refuses on Deny. Only a policy Allow is ever checked.
func (p *Proxy) connUserLimit(ci connIdentity, domain string, port int, charge bool) policy.RequestVerdict {
	rc := policy.RequestContext{Domain: domain, Port: port, Scheme: policy.SchemeHTTPS, Subject: p.connSubject(ci)}
	if charge {
		return p.cfg.Policy.ChargeUserLimit(rc, p.cfg.AgentID)
	}
	return p.cfg.Policy.PeekUserLimit(rc, p.cfg.AgentID)
}

// recordConnUserLimitDeny records a connection-level user-limit refusal: one
// deny event (with limit_rule) through the shared chokepoint and the kind
// counter. The caller answers the client.
func (p *Proxy) recordConnUserLimitDeny(ci connIdentity, domain string, port int, v policy.RequestVerdict) {
	p.emitDenyEvent(ci, analytics.Event{
		Timestamp: time.Now(),
		Domain:    domain,
		Port:      port,
		Protocol:  "tcp",
		Reason:    string(v.Reason),
		LimitRule: v.LimitRule,
	})
	p.recordUserLimitDenied(v)
}

// connectUserLimit is the CONNECT-time check, after the policy admitted the
// destination and before the 200: a raw tunnel (charge) is charged here once
// for its whole life; a TLS-terminated tunnel (peek) is refused only when the
// rule's bucket is already exhausted. A refusal answers the CONNECT with the
// same JSON as a request-level refusal (429 + Retry-After, or 403) and
// Connection: close. It returns the rule (for the tunnel's allow event) and
// whether the CONNECT was refused.
func (p *Proxy) connectUserLimit(w io.Writer, ci connIdentity, domain string, port int, charge bool) (rule string, denied bool) {
	v := p.connUserLimit(ci, domain, port, charge)
	if v.Decision != policy.Deny {
		return v.LimitRule, false
	}
	p.recordConnUserLimitDeny(ci, domain, port, v)
	status, body, retry := userLimitResponse(v)
	writeJSONResponseRetry(w, status, body, retry)
	return v.LimitRule, true
}

// passthroughUserLimit charges an opaque passthrough on a TLS-terminating
// worker (the client already has its 200, so there is no response to write:
// a refusal is the audited close). It returns the rule and whether it refused.
func (p *Proxy) passthroughUserLimit(ci connIdentity, domain string, port int) (rule string, denied bool) {
	v := p.connUserLimit(ci, domain, port, true)
	if v.Decision != policy.Deny {
		return v.LimitRule, false
	}
	p.recordConnUserLimitDeny(ci, domain, port, v)
	return v.LimitRule, true
}
