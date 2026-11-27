# Policy reference: per-user limits

Per-user limits (phase 3, "Act as the user") cap how fast and how much a
**verified user** can use the egress a shared agent has. They are rate limits
and daily **estimated** cost caps keyed by the user the worker verified, so one
user cannot use up a shared provider budget. The control plane side (the fleet
cost block list, the usage view, rollout) is in
[control-plane.md](control-plane.md#per-user-limits-rollout).

They are **off by default**. With no `policy.userLimits`, `policy.defaultUserLimit`
and `policy.anonymousLimit`, `/policy` and its ETag are byte-identical to a build
without the feature and the proxy adds no work to a request.

A limit never turns a deny into an allow. It is checked only for a request the
policy (or, for an unlisted destination, the LLM judge) would forward, so a
denied request is never charged and never gets a limit status instead of its
deny. It never touches secret swapping.

## Schema

```yaml
policy:
  userLimits:
    - name: eng-llm                    # required, unique, not "default" or "anonymous"
      match:
        users:   []                    # sub values; an email matches only when email_verified
        groups:  [eng]                 # IdP group claims
        agents:  []                    # worker agent ids
        domains: [api.openai.com]      # policy domain dialect; empty = every domain
      perAgent: false                  # one budget per (user, agent) instead of per user
      rateLimit: 60/minute             # N/second | N/minute | N/hour
      dailyCostUSD: 5                  # estimated spend per UTC day, at most 1e6
  defaultUserLimit: {rateLimit: 600/hour}   # no match block
  anonymousLimit:   {rateLimit: 5/minute}   # no match block
```

- A rule needs `rateLimit`, `dailyCostUSD` or both. `name` uses the agent-id
  character set; `default` and `anonymous` are reserved for the two single rules.
- At most 256 rules. Users, groups and agents are normalized like the group
  policy fields (see [group-policy.md](group-policy.md)).
- The worker and the control plane log a WARN (rule names only) for overlapping rules in one
  tier (the later one is partly unreachable), a `dailyCostUSD` with no CA
  configured (cost is only measured on terminated TLS), and agents whose
  identity mode is not `require`.

## Which rule applies

Exactly one rule applies to a request. The tiers, in order:

1. rules whose `match.users` matches the verified subject,
2. rules whose `match.groups` matches one of the subject's groups,
3. agents-only rules (no `users` and no `groups`),
4. `defaultUserLimit`.

Within a tier the first rule in list order whose match fields **and** domains
both match wins. A rule's budget is one bucket across all its domains, keyed by
the rule and the user (and the agent when `perAgent` is true).

A request with no valid token (none, invalid or expired) has no subject and uses
**only** `anonymousLimit`, keyed by the worker's resolved agent id. It is never
charged to a sub read from an unverified token. Dropping the token therefore
lands the request in the anonymous bucket, not in the user's. When the IdP is
down, new tokens fail verification and fall into the anonymous bucket.

A **strict** per-user guarantee needs identity mode `require` on the agent. In
`attribute` mode a client can simply send no token and take the anonymous budget
instead of its own, so set `anonymousLimit` to what you are willing to give an
unidentified caller.

If the user's group list was truncated by the group-claim cap, a rule that could
match by group fails closed (`identity_groups_truncated`) rather than guessing,
including a cost-only rule. Raise the IdP group cap (or keep groups short) for
users who must be metered.

## Rate limits

Over its rate the agent gets `429 {"error":"user_rate_limited"}` with an integer
`Retry-After` in seconds. The reason is `user_rate_limited` in the decision log.

- **Per worker.** Buckets live in each worker's memory. N workers allow a user up
  to N times the configured rate. There is no fleet-wide rate counter.
- **Windows survive unrelated changes.** A policy change that does not touch a
  rule (an allow or deny edit, a block-list change, a cost block update) does not
  reset its window. Changing a rule's definition, or removing it, drops that
  rule's buckets.
- **Restart.** A worker restart starts with empty buckets, so a user can spend
  one fresh window after it.
- **Bounds.** Expired buckets are swept about once a minute. The bucket table
  holds at most 100000 keys; at the limit a new key is denied (fail closed) and
  counted. Subs longer than 255 bytes are keyed by their SHA-256.
- **What is charged, and when.** Each forwarded HTTP request is charged
  individually, so a keep-alive connection carrying several users limits each
  correctly. An h2 stream is charged once per stream, a WebSocket upgrade once per
  upgrade, and a raw tunnel (no CA) once at CONNECT. A TLS-terminated CONNECT is
  only checked (not charged) at CONNECT; its requests are charged. The charge
  happens just before the request is forwarded, after DLP, MCP and SSRF refusals.

## Daily cost caps

`dailyCostUSD` caps the **estimated** spend of a user under a rule per UTC day.
It is not a billing figure: Warden prices the bytes it relays at about
bytes/4 tokens times the built-in provider prices, on the destinations the
cost estimator knows (`api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`, `api.cohere.com`). Other destinations are
never refused for cost. Compare it with your provider's invoice before relying on
a dollar value.

At or over the cap the agent gets `403 {"error":"user_cost_limited"}` with
`Retry-After` set to the seconds until the next UTC midnight.

- **Streamed responses are priced.** A chunked or SSE answer with no
  `Content-Length` is priced from the bytes actually relayed (request body and
  response copy, including the MCP SSE relay and gRPC streams). Before this
  change these responses were priced at $0.
- **UTC day.** The ledger is keyed by UTC day. At 00:00 UTC every cap starts
  again, and a published block whose day is over is ignored, even with the
  control plane down. Workers and the control plane need a correct clock (run
  NTP): a skewed worker resets, or fails to reset, at the wrong moment.
- **Soft cap.** A worker checks the ledger before a request and charges it after
  the response, so a user can overshoot by the requests in flight when the cap is
  reached (each can cost a whole answer).
- **Across workers.** Each worker has its own ledger, so before the fleet block
  list reaches a worker, the user can spend up to the cap on each of them. The
  control plane totals the fleet spend and publishes users at or over the cap as
  `costBlockedUsers` (see the control plane doc): the lag is the ingest batch
  interval plus the 30 s recompute debounce plus one policy long-poll. The
  worst-case overshoot is therefore roughly min(workers x cap, cap + what the
  user spends across the fleet during that lag) plus the requests in flight;
  workers x cap applies when the control plane is down. A deployment with one
  worker has only the in-flight overshoot. With the in-memory fleet store the control plane publishes
  nothing and the per-worker ledgers are the only cap.
- **Restart.** A worker rebuilds its ledger at boot from the day's cost in its
  local event store, so a restart keeps a user's spend. If the seed read fails,
  the worker starts with an empty ledger and logs a warning (fail open for that
  boot).
- **Unmeasurable traffic.** When a cost-capped rule applies to a destination the
  estimator tracks but the worker cannot measure (a raw tunnel without a CA, an
  opaque passthrough, a WebSocket upgrade), the request is refused with
  `user_cost_unmeasurable` instead of letting it through unmetered. Run the
  worker with a CA for capped users.
- **Ledger full.** The ledger holds at most 100000 keys; a new key past the limit
  is refused with `user_cost_limited` (fail closed).
- **Known gap: a gRPC call refused after response headers.** When a gRPC stream
  is refused after the upstream has already answered (a message that fails the
  frame guard), the bytes relayed before the refusal are charged to the worker's
  live ledger, but the deny event carries no cost. A worker restart (which
  reseeds from the event store) and the fleet rollup (`costBlockedUsers`, the
  usage view) therefore do not count them. Every other deny that fires after
  response bytes reached the agent (the echo guard, an MCP gateway deny, a
  scanner block) carries its cost on the deny event. A capped user can get a
  bounded amount of gRPC output that only the live ledger sees; a follow-up
  closes it.

## Observability

- Deny reasons `user_rate_limited`, `user_cost_limited` and
  `user_cost_unmeasurable` are in the decision log (`warden.decision.v1`,
  `schema_rev` 6 and 7) with `limit_rule` naming the rule, and in the
  `RecordBlocked` counters.
- The counter `warden.user_limit.denied.total{kind=rate|cost|unmeasurable}` and
  the gauge `warden.user_limit.buckets` never carry a sub, email or group label.
- The control plane Users usage view (`GET /dashboard/api/usage/users`, role
  viewer or a `traffic:read` API key) shows per-user requests, denies by reason,
  estimated cost and top agents from the fleet rollup.

## Rolling out

Add limits in this order: upgrade the control plane, then the workers; check the
fleet view (or `GET /dashboard/api/workers`) shows `userlimits/v1` and
`usercost/v1` on every worker; then save the rules. A save that introduces a rule
while a worker lacks the capability answers `409 workers_lack_capability` (an
admin can force it, audited). See the control plane doc.
