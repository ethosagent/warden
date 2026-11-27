package proxy

import (
	"io"
	"net/http"
	"time"

	"github.com/ethosagent/warden/internal/analytics"
	"github.com/ethosagent/warden/internal/cost"
	"github.com/ethosagent/warden/internal/denyreason"
	"github.com/ethosagent/warden/internal/identity"
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

// The kind labels of warden.user_limit.denied.total: a rate refusal, a cost
// cap refusal and a refusal of unmeasurable traffic under a cost cap.
const (
	userLimitKindRate         = "rate"
	userLimitKindCost         = "cost"
	userLimitKindUnmeasurable = "unmeasurable"
)

// The JSON bodies of the user-limit refusals, built from the declared
// reasons, never a second literal.
var (
	userRateLimitedBody      = `{"error":"` + string(denyreason.UserRateLimited) + `"}`
	userGroupsTruncatedBody  = `{"error":"` + string(denyreason.IdentityGroupsTruncated) + `"}`
	userCostLimitedBody      = `{"error":"` + string(denyreason.UserCostLimited) + `"}`
	userCostUnmeasurableBody = `{"error":"` + string(denyreason.UserCostUnmeasurable) + `"}`
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
// with Retry-After for user_rate_limited; 403 with Retry-After to the next UTC
// midnight for user_cost_limited; 403 with no Retry-After for every other
// reason (identity_groups_truncated: waiting does not help, the IdP's group
// list is what is wrong; user_cost_unmeasurable: the session kind is what is
// refused).
func userLimitResponse(v policy.RequestVerdict) (status int, body string, retryAfter int) {
	switch v.Reason {
	case denyreason.UserRateLimited:
		return http.StatusTooManyRequests, userRateLimitedBody, retryAfterSeconds(v.RetryAfter)
	case denyreason.UserCostLimited:
		return http.StatusForbidden, userCostLimitedBody, retryAfterSeconds(v.RetryAfter)
	case denyreason.UserCostUnmeasurable:
		return http.StatusForbidden, userCostUnmeasurableBody, 0
	case denyreason.IdentityGroupsTruncated:
		return http.StatusForbidden, userGroupsTruncatedBody, 0
	default:
		// The evaluator declares no other user-limit reason; one added later
		// still refuses, under its own (declared) name.
		return http.StatusForbidden, `{"error":"` + string(v.Reason) + `"}`, 0
	}
}

// recordUserLimitDenied counts a user-limit refusal on the bounded kind label.
// A truncated-groups refusal is not a limit hit, so it is not counted.
func (p *Proxy) recordUserLimitDenied(v policy.RequestVerdict) {
	switch v.Reason {
	case denyreason.UserRateLimited:
		p.cfg.Metrics.RecordUserLimitDenied(userLimitKindRate)
	case denyreason.UserCostLimited:
		p.cfg.Metrics.RecordUserLimitDenied(userLimitKindCost)
	case denyreason.UserCostUnmeasurable:
		p.cfg.Metrics.RecordUserLimitDenied(userLimitKindUnmeasurable)
	}
}

// Per-user cost caps (W-P3-PUL-04). A rule with dailyCostUSD applies only to
// a destination the cost estimator tracks (an untracked one always prices at
// $0, so it is never denied for cost). It is checked at the same points as
// the rate limit: peeked in userLimitStage, checked again just before the
// request goes upstream (chargeUserLimitNow, before the rate charge, so a
// cost refusal never consumes rate budget) and, for a tunnel, at CONNECT and
// once it is dialed. A request is refused when the user's spend under the rule
// today (the worker's ledger) is at or over the cap, when the control plane
// lists the user as over it today, or when the ledger is full (fail closed).
// Traffic the worker cannot measure (raw tunnel, opaque passthrough,
// WebSocket) is refused under such a rule instead of passing unmetered. The
// ledger is charged after the response has been relayed, with the same
// estimate the event records (estimateCost), including when a deny cut the
// response after bytes reached the agent. The cap is soft: requests in flight
// are not yet counted. No log line carries a user's spend.

// userCostCheck is the result of checking a cost cap for one request.
type userCostCheck struct {
	// capped: a dailyCostUSD rule applies to this tracked destination; key is
	// the ledger key a forwarded request's estimate is added to.
	capped bool
	key    cost.LedgerKey
	// denied: refused, with v the deny verdict (reason, rule, Retry-After).
	denied bool
	v      policy.RequestVerdict
}

// costTracked reports whether a cost cap can apply on domain at all: the
// ledger is wired and the estimator prices the destination.
func (p *Proxy) costTracked(domain string) bool {
	if p.cfg.UserCost == nil || p.cfg.Cost == nil {
		return false
	}
	_, tracked := p.cfg.Cost.Tracks(domain)
	return tracked
}

// userCost checks the cost cap that applies to subj on domain at a
// connection-level site (no rate verdict to read the rule from), matching the
// rule itself. opaque says the traffic cannot be measured at all (a tunnel).
// With no ledger, or a destination the estimator does not track, it does
// nothing and allocates nothing.
func (p *Proxy) userCost(subj *identity.Subject, domain string, opaque bool) (c userCostCheck) {
	if !p.costTracked(domain) {
		return c
	}
	r, ok := p.cfg.Policy.MatchUserLimit(subj, p.cfg.AgentID, domain)
	if !ok {
		return c
	}
	return p.checkCostCap(subj, r.Name, r.DailyCostUSD, nil, opaque)
}

// userCostRule checks the cost cap of rule (capped at capUSD, the rate
// verdict's DailyCostUSD) for a request to domain: the request path reads the
// rule from its peek or charge, so the rule is matched once. req, when set, is
// unmeasurable when it is a WebSocket upgrade.
func (p *Proxy) userCostRule(subj *identity.Subject, domain, rule string, capUSD float64, req *http.Request) (c userCostCheck) {
	if capUSD <= 0 || !p.costTracked(domain) {
		return c
	}
	return p.checkCostCap(subj, rule, capUSD, req, false)
}

// noteLedgerFull warns once that the cost ledger is full: new users under a
// cost cap are refused until UTC midnight (warden.user_cost.ledger_refused
// counts them). No user is named.
func (p *Proxy) noteLedgerFull() {
	p.ledgerFullOnce.Do(func() {
		p.cfg.Logger.Warn("per-user cost ledger is full; new users under a cost cap are refused until UTC midnight",
			"max_keys", cost.MaxLedgerKeys)
	})
}

// checkCostCap is the cap check proper, for a tracked destination with the
// ledger wired.
func (p *Proxy) checkCostCap(subj *identity.Subject, rule string, capUSD float64, req *http.Request, opaque bool) (c userCostCheck) {
	if capUSD <= 0 {
		return c
	}
	var sub string
	if subj != nil {
		sub = subj.Sub
	}
	c.capped, c.key = true, cost.UserKey(sub, p.cfg.AgentID, rule)
	if opaque || (req != nil && isWebSocketUpgrade(req.Header)) {
		c.denied = true
		c.v = policy.RequestVerdict{Decision: policy.Deny, Reason: denyreason.UserCostUnmeasurable, LimitRule: rule}
		return c
	}
	l := p.cfg.UserCost
	now := l.Now()
	spent, known := l.Spent(c.key)
	if !known {
		p.noteLedgerFull()
	}
	if !known || spent >= capUSD || p.cfg.Policy.IsCostBlocked(sub, rule, now) {
		c.denied = true
		c.v = policy.RequestVerdict{
			Decision: policy.Deny, Reason: denyreason.UserCostLimited, LimitRule: rule,
			RetryAfter: cost.NextUTCMidnight(now).Sub(now),
		}
	}
	return c
}

// chargeUserCost adds usd, the estimate of a forwarded request, to its user's
// ledger key, once per request, when a cost-capped rule applied to it.
func (p *Proxy) chargeUserCost(s *requestScope, usd float64) {
	if !s.costCapped || s.costCharged {
		return
	}
	s.costCharged = true
	p.cfg.UserCost.Add(s.costKey, usd)
}

// cutCost charges a request whose response a deny refused or cut after the
// upstream answered (echo guard, MCP SSE gateway deny, response scanner
// block): the upstream did the work, so the user pays for what was read. It
// returns the charged estimate for the deny event, so the local reseed
// (CostByUserSince) and the fleet rollup count it too; zero when no cost cap
// applies or the request was already charged. Called on the relay goroutine
// once reading has stopped.
func (p *Proxy) cutCost(s *requestScope) (usd float64, provider string) {
	if !s.costCapped || s.costCharged || s.resp == nil {
		return 0, ""
	}
	usd, provider = p.estimateCost(s)
	p.chargeUserCost(s, usd)
	return usd, provider
}

// chargeUserCostCut charges a cut request whose deny event was recorded
// elsewhere: a gRPC frame refused after the headers, whose deny the body guard
// records on the transport goroutine while the response may still be
// relaying, so its event carries no cost. Known gap: that deny event (and so
// the local reseed and the fleet rollup) misses the charge; the live ledger
// still has it. A no-op when the deny already charged (cutCost).
func (p *Proxy) chargeUserCostCut(s *requestScope) {
	_, _ = p.cutCost(s)
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
	if v.Decision == policy.Deny {
		return p.denyUserLimit(s, v)
	}
	// The peeked rule's cost cap (none when no rule applies, always the case
	// with no limits configured). The charge re-checks it with this rule.
	s.peekRule, s.peekCostUSD = v.LimitRule, v.DailyCostUSD
	if c := p.userCostRule(s.subject, s.domain, v.LimitRule, v.DailyCostUSD, s.req); c.denied {
		return p.denyUserLimit(s, c.v)
	}
	// A peek is not a charge: limit_rule is set only once the request is
	// charged, so a request refused later carries none.
	return false
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
	// The cost cap first, under the peeked rule: a request it refuses
	// consumes no rate budget.
	if c := p.userCostRule(s.subject, s.domain, s.peekRule, s.peekCostUSD, s.req); c.denied {
		return p.denyUserLimit(s, c.v)
	}
	v := p.cfg.Policy.ChargeUserLimit(p.userLimitRC(s), p.cfg.AgentID)
	// Set before any event of this request is recorded (the deny below and the
	// allow at the end both read it).
	s.limitRule = v.LimitRule
	if v.Decision == policy.Deny {
		return p.denyUserLimit(s, v)
	}
	// A hot reload between the peek and the charge can change the rule that
	// applies: the charged rule's cost cap is then checked on this request too
	// (its rate budget is already consumed; the reload window is tiny).
	c := userCostCheck{}
	if v.LimitRule != s.peekRule || v.DailyCostUSD != s.peekCostUSD {
		if c = p.userCostRule(s.subject, s.domain, v.LimitRule, v.DailyCostUSD, s.req); c.denied {
			return p.denyUserLimit(s, c.v)
		}
	} else if v.DailyCostUSD > 0 && p.costTracked(s.domain) {
		var sub string
		if s.subject != nil {
			sub = s.subject.Sub
		}
		c.capped, c.key = true, cost.UserKey(sub, p.cfg.AgentID, v.LimitRule)
	}
	// The charged rule names the ledger key the estimate is added to.
	s.costCapped, s.costKey = c.capped, c.key
	return false
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
// request scope): charge consumes budget, otherwise it peeks. opaque says the
// tunnel's traffic cannot be measured, so a cost-capped rule refuses it
// (user_cost_unmeasurable); otherwise a user over a cost cap is refused. It
// returns the verdict; the caller refuses on Deny. Only a policy Allow is ever
// checked.
func (p *Proxy) connUserLimit(ci connIdentity, domain string, port int, charge, opaque bool) policy.RequestVerdict {
	subj := p.connSubject(ci)
	if c := p.userCost(subj, domain, opaque); c.denied {
		return c.v
	}
	rc := policy.RequestContext{Domain: domain, Port: port, Scheme: policy.SchemeHTTPS, Subject: subj}
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
// exhausted, or who is over a cost cap, is refused with the same JSON as a
// request-level refusal (429 + Retry-After, or 403) and Connection: close.
// opaque is true for a raw tunnel (no TLS termination), whose traffic cannot
// be priced: a cost-capped rule refuses it here (user_cost_unmeasurable). It
// consumes nothing; a tunnel is charged by tunnelUserLimitCharge once it is
// registered and dialed, and a terminated tunnel's requests are charged one by
// one.
func (p *Proxy) connectUserLimitPeek(w io.Writer, ci connIdentity, domain string, port int, opaque bool) (denied bool) {
	v := p.connUserLimit(ci, domain, port, false, opaque)
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
// close. Its traffic cannot be priced, so a cost-capped rule refuses it
// (user_cost_unmeasurable). It returns the rule and whether it refused.
func (p *Proxy) tunnelUserLimitCharge(ci connIdentity, domain string, port int) (rule string, denied bool) {
	v := p.connUserLimit(ci, domain, port, true, true)
	if v.Decision != policy.Deny {
		return v.LimitRule, false
	}
	p.recordConnUserLimitDeny(ci, domain, port, v)
	return v.LimitRule, true
}
