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
// A limit is charged once per unit of work the proxy forwards, at the last
// moment before it goes upstream, so a refused unit costs nothing:
//   - every HTTP/1.1 request, HTTP/2 or gRPC stream and WebSocket upgrade, in
//     forward (each request carries its own subject, so one keep-alive session
//     carrying several users charges each of them). userLimitStage peeks first,
//     before the judge, so an exhausted user skips the judge and every scan;
//   - a raw tunnel (no CA) or an opaque passthrough on a TLS-terminating worker
//     (non-TLS bytes, or non-HTTP inside TLS) once, after its session
//     registered and its dial succeeded, since no request in it can be seen.
//
// CONNECT only peeks, so an exhausted user is refused before the 200; a
// TLS-terminated CONNECT peeks only with a verified identity (a token-less one
// may carry several users' per-request identities).
//
// Limits apply only to a request the policy allowed or the judge allowed:
// they can turn an allow into a deny, never anything into an allow. The agent
// id is always the worker's bound agent (Config.AgentID), never a request or
// token value.

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

// userLimitStage is the pre-check: it runs after constraintGate and before
// judgeGate and only PEEKS (no budget is consumed), for a policy Allow and for
// a NoMatch the judge will decide. A user whose bucket is already exhausted is
// refused here, before the judge, the scans, the swap and any dial; otherwise
// the request is marked for the authoritative charge (chargeUserLimitNow),
// which runs just before the request is sent upstream, so a request refused
// by the judge, MCP, DLP, the swap or the SSRF dialer never consumes budget.
// A Deny or Conditional never reaches this stage (constraintGate ended it).
//
// A limit verdict can only deny; it never overrides the policy or judge
// verdict. With no limits configured it is one read lock in the evaluator and
// changes nothing on the request or its events.
func (p *Proxy) userLimitStage(s *requestScope) (endSession bool) {
	if !s.policyAllowed && s.deferred != deferJudge {
		return false
	}
	s.chargeLimit = true
	v := p.cfg.Policy.PeekUserLimit(p.userLimitRC(s), p.cfg.AgentID)
	if v.Decision != policy.Deny {
		// A peek is not a charge: limit_rule is set only once the request is
		// charged, so a request refused later carries none.
		return false
	}
	return p.denyUserLimit(s, v)
}

// chargeUserLimitNow is the authoritative charge, made once per request just
// before its first byte goes upstream (forward: after the upstream dial on
// HTTP/1.1; before the round trip on HTTP/2, whose transport dials inside it).
// It reports whether the request was refused (the response is written). A
// redial of a stale keep-alive conn re-sends the same request and is not
// charged again.
func (p *Proxy) chargeUserLimitNow(s *requestScope) (denied bool) {
	if !s.chargeLimit {
		return false
	}
	s.chargeLimit = false
	v := p.cfg.Policy.ChargeUserLimit(p.userLimitRC(s), p.cfg.AgentID)
	// Set before any event of this request is recorded (the deny below and the
	// allow at the end both read it).
	s.limitRule = v.LimitRule
	if v.Decision != policy.Deny {
		return false
	}
	return p.denyUserLimit(s, v)
}

func (p *Proxy) userLimitRC(s *requestScope) policy.RequestContext {
	return policy.RequestContext{Domain: s.domain, Port: s.port, Scheme: s.scheme, Subject: s.subject}
}

// denyUserLimit records and answers a user-limit refusal of a request.
func (p *Proxy) denyUserLimit(s *requestScope, v policy.RequestVerdict) bool {
	s.limitRule = v.LimitRule
	p.emitDeny(s, v.Reason, denyExtra{LatencyMs: s.latencyMs(), JudgeReason: s.judgeReason, SwappedRefs: s.swappedNames})
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

// connectUserLimitPeek is the CONNECT-time pre-check, after the policy
// admitted the destination and before the 200: a user whose bucket is already
// exhausted is refused with the same JSON as a request-level refusal (429 +
// Retry-After, or 403) and Connection: close. It consumes nothing; a tunnel is
// charged by tunnelUserLimitCharge once it is registered and dialed, and a
// terminated tunnel's requests are charged one by one.
func (p *Proxy) connectUserLimitPeek(w io.Writer, ci connIdentity, domain string, port int) (denied bool) {
	v := p.connUserLimit(ci, domain, port, false)
	if v.Decision != policy.Deny {
		return false
	}
	p.recordConnUserLimitDeny(ci, domain, port, v)
	status, body, retry := userLimitResponse(v)
	writeJSONResponseRetry(w, status, body, retry)
	return true
}

// tunnelUserLimitCharge charges an opaque tunnel (a raw tunnel without a CA,
// or a passthrough on a TLS-terminating worker) once for its whole life,
// after its session registered and its dial succeeded, so a refused tunnel
// costs nothing. The client already has its 200, so a refusal is the audited
// close. It returns the rule and whether it refused.
func (p *Proxy) tunnelUserLimitCharge(ci connIdentity, domain string, port int) (rule string, denied bool) {
	v := p.connUserLimit(ci, domain, port, true)
	if v.Decision != policy.Deny {
		return v.LimitRule, false
	}
	p.recordConnUserLimitDeny(ci, domain, port, v)
	return v.LimitRule, true
}
