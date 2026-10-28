# Group-scoped policy

An allow entry or an MCP tool `allowWhen` can be limited to IdP groups or to named
users. The rule then applies only to a request that carries a **verified** user
token (see [the identity contract](identity-contract.md)) naming one of them.
Entries without `groups`/`users` behave exactly as before.

What you get, in one paragraph: a scoped rule never allows a request without a valid
verified identity; a verified user who is not named is denied outright and the
request never reaches the judge; and a worker that is too old to understand scoped
rules denies the destination instead of treating the rule as global.

Every statement below names the test that pins it. A drift test
(`internal/config/group_policy_doc_test.go`) keeps the reasons table and the config
example in step with the code.

## Quick start

1. Turn identity on for the worker: `identity.defaultMode: attribute` with an
   `issuer` and `audience` (see the [identity contract](identity-contract.md)).
2. Run the worker with a CA (`tls.caCert` and `tls.caKey`, or `--ca-cert`/`--ca-key`) so HTTPS requests can be inspected one by
   one. Without a CA only a narrow raw-tunnel case works, see
   [CONNECT and tunnels](#connect-and-tunnels).
3. Add `groups:` and/or `users:` to the allow entry:

```yaml
policy:
  allowlist:
    - domain: api.github.com
      groups: ["eng", "sre"]
```

A complete, loadable example is in
[`configs/config.example.yaml`](../configs/config.example.yaml) between the lines
`# --- group-policy example ---` and `# --- end group-policy example ---`.

## Where the fields go

| Where | Fields | Notes |
|---|---|---|
| `policy.allowlist[]` | `groups`, `users` | Scoped entry: admits only a named verified user. |
| `mcp.tools.constraints.<tool>.allowWhen` | `groups`, `users` | Narrows an already allowed tool. Clauses are ANDed with `agentId` and `timeWindow`. |
| `policy.denylist[]` | none | The denylist is global. A `groups` key there fails to load. |
| `mcp.scopes.list[].constraints` (task scopes) | none | Rejected at load: a task scope has no per-user meaning. |

Tests: `TestAllowlistGroupsAccepted`, `TestMCPAllowWhenGroupsAccepted`,
`TestDenylistGroupsRejected`, `TestScopeConstraintGroupsRejected` (internal/config).

The agent id `!identity-scoped` is reserved for the control-plane wire (see
[Old workers](#old-workers-and-the-fleet-view)) and is rejected as an `agentId`
(`TestReservedScopedSentinelRejected`).

### Normalisation

Values are normalised when the config is loaded (a worker's local YAML and the control plane's policy file):

- each value is trimmed; an empty value is an error;
- each list is de-duplicated and sorted;
- at most 256 values per list and 256 bytes per value;
- a `users` value containing `@` is an **email** and is lower-cased; any other
  `users` value is an exact IdP **`sub`** (case-sensitive);
- `groups` are exact, case-sensitive literals.

Errors name the field path, for example `policy.allowlist[2].groups[1]`
(`TestNormalizePrincipals`).

## Matching rules

A scoped entry admits a request when the verified subject is named by it:

- **group**: one of the subject's groups equals one of the entry's `groups`.
  Literal and case-sensitive: `Eng` does not match `eng`. There is no wildcard or
  prefix matching.
- **user by sub**: the subject's `sub` equals a non-email `users` value.
- **user by email**: the subject's email equals an email `users` value
  (case-insensitive) **and** the token's `email_verified` is true. An unverified
  email never matches.
- An entry with both lists matches when either does.

Tests: `TestEvaluateFor_Scoped`, `TestEvaluateFor_UsersAndVerifiedEmail`
(internal/policy); `TestConditionGroups` (MCP, same matcher).

Per entry the evaluator checks, in order: destination and port, **principal**, time
window, method, path, rate limit. So a non-member never consumes a scoped entry's
rate budget, and a method or path rule is only judged for a user the entry admits.
Each scoped entry has its own rate-limit bucket, never shared with an unscoped
entry for the same host (`TestEvaluateFor_ConstraintsAfterPrincipal`,
`TestEvaluateFor_ScopedRateBuckets`).

Matching across entries is any-match-wins, as for every allowlist. An unscoped entry
for the same destination therefore admits everyone and makes a scoped sibling
pointless; [the lint](#lint-warnings) warns about that
(`TestEvaluateFor_MixedScopedUnscoped`).

### What stays global

- **The denylist** is checked first and wins over every scoped entry
  (`TestEvaluateFor_DenylistWins`). It has no `groups`/`users`.
- **The user block list** (`policy.blockedUsers`) is checked before the policy and
  refuses the user with `user_blocked` on every destination.
- **A non-member is denied, not judged.** A destination that matches an entry by
  domain and port never falls through to the LLM judge, so a judge cannot talk its
  way past a scope (`TestGroupPolicy_NeverJudged`).

## Fail-closed cases

A scoped rule needs a verified subject. All of these get **403 `identity_required`**:

| Request carries | Why |
|---|---|
| no token (anonymous) | no subject |
| an invalid token (bad signature, wrong issuer or audience, malformed) | no subject |
| an expired token, including one that expires in the middle of a keep-alive session | the CONNECT identity is re-checked on every request |
| a CONNECT token and an `X-Warden-Identity` token for different users | conflict: no subject |
| a token while identity is off for the agent | nothing is verified |

Tests: `TestGroupPolicy_NoIdentityReasons` (anonymous, invalid, expired, conflict and
expiry mid-session).

The token travels in `Proxy-Authorization` on CONNECT, or per request in
`X-Warden-Identity`; the header is only used when CONNECT carried no token.

### Truncated group lists

A verified token carries at most 64 groups (a group over 256 bytes is dropped,
never cut). When anything was dropped the subject is marked `groupsTruncated`.

- A user found in the partial list is a member and is allowed.
- A user **not** found, on an entry that has `groups`, is denied with
  **`identity_groups_truncated`**, because the miss may be an artifact of the cut.
- An entry that lists only `users` is not affected by truncation: a miss is
  `group_not_allowed`.

Tests: `TestEvaluateFor_TruncatedGroups`, `TestGroupPolicy_TruncatedGroups`,
`TestConditionGroups_Truncated`.

## Deny reasons

The reasons are declared once, in `internal/denyreason`, and appear on the deny
event, the decision log and `warden_blocked_total{reason}`.

<!-- group-policy-reasons:start -->
| Reason | When |
|---|---|
| `identity_required` | The destination is only reachable with a verified identity and the request has none (anonymous, invalid, expired, conflicting), or the connection cannot be decided per request (see below). |
| `identity_expired` | Identity challenge mode only: the token that admitted a terminated tunnel expired while it was open (see [identity-contract.md](identity-contract.md)). |
| `identity_conflict` | Identity challenge mode only: an `X-Warden-Identity` header named a different subject than the tunnel's CONNECT token. |
| `group_not_allowed` | A verified subject reached the destination only through scoped entries that do not name it. |
| `identity_groups_truncated` | As `group_not_allowed`, but the subject's group list was truncated and the entry has `groups`. |
<!-- group-policy-reasons:end -->

The full reason set, with every other deny reason, is in [siem.md](siem.md#deny-reasons).
`TestGroupPolicyDocReasons` checks that this table equals the group-policy entries
of `denyreason.Declared()`.

Precedence when several entries match: an identity-less request gets
`identity_required` (identity could still satisfy it); otherwise the guard reason of
an entry that admitted the user but rejected the request (`path_not_allowed`,
`method_not_allowed`, `time_window`, `rate_limited`); otherwise
`identity_groups_truncated`, then `group_not_allowed`.

**MCP tools** use the gateway's own reason, `mcp_tool_condition`, for no identity
and for a non-member; the finding detail says `no verified identity` or
`user not permitted` and never names a group or user. Only a truncated-list miss
uses `identity_groups_truncated`. In `monitor` mode the gateway records the finding
and lets the call through, like every other `allowWhen` clause
(`TestConditionGroups_NoIdentityAndNonMember`, `TestConditionGroups_MonitorMode`).

## Protocol paths

Scoped rules are decided **per request**, with that request's subject.

- **HTTP/1.1**: each request on a keep-alive tunnel is decided separately, so two
  users on one tunnel are each handled correctly. A deny ends the session
  (`TestGroupPolicy_RequestIdentity`).
- **h2 and gRPC**: decided per stream (`TestGroupPolicy_H2PerStream`).
- **Policy swap**: a hot reload takes effect on the next request of an open
  session (`TestGroupPolicy_PolicySwapMidSession`).
- **MCP over HTTP and WebSocket** pass the subject to the gateway; **MCP over
  stdio has no verified identity, so group-gated tools are denied** and ungated
  tools still work (`TestMCPGroupCondition_StdioDenies`).

### CONNECT and tunnels

At CONNECT there is no method or path yet. A scoped destination is admitted
*conditionally* and the decision is deferred to each request:

- **With a CA**: the CONNECT is answered 200 and TLS is terminated; HTTP/1.1, h2 and
  gRPC are decided per request (`TestDeferredIdentity_ConnectWithCA`). A CONNECT
  whose token already names a non-member is refused at CONNECT with
  `group_not_allowed`.
- **Without a CA**, a conditional CONNECT cannot be inspected and is denied with
  `identity_required` (`TestDeferredIdentity_NoCA`).
- **Not TLS, or an unknown protocol inside TLS**: nothing can be decided per request,
  so the connection is denied (`identity_required`) and neither the judge nor the
  upstream is touched (`TestDeferredIdentity_FailClosedBranches`).
- **Scoped raw tunnel** (no CA): the one exception. A CONNECT whose token already
  names a member, with an expiry, is tunnelled opaquely **until the token expires**,
  when both ends are cut. A token with no expiry is denied. A policy swap does
  **not** cut an open scoped tunnel: removing a user from a group takes effect for
  new connections, not for the tunnel already open (`TestDeferredIdentity_RawTunnelExpiry`).
  Prefer a CA, or short-lived tokens, when this matters.

The transparent listeners use the same admission gate
(`TestTransparent_DeferredIdentity`).

## Old workers and the fleet view

The control plane serves one body per ETag to every worker. To keep a worker that
predates group policy from reading a scoped rule as a global one:

- scoped allow entries are moved out of `allowlist` into `scopedAllowlist`, which an
  old worker ignores, so it sees no entry for the host;
- a scoped MCP `allowWhen` is served as the reserved `agentId: "!identity-scoped"`,
  which no agent satisfies, with the real condition in a separate field.

A current worker merges both back. A pull whose sentinel has no matching scoped
condition is rejected and the worker keeps its last good policy. A policy with no
scoped rules produces the same bytes and ETag as before.

So an **old worker denies the scoped destination** (default-deny, `policy_no_match`)
and the gated tool. One caveat: if that old worker has an LLM judge enabled, an
unlisted host is judge-eligible like any other unlisted host. Upgrade the worker
rather than rely on this.

Tests: `TestProjectScoped_Allow`, `TestProjectScoped_MCP`,
`TestParseRemotePolicy_Scoped`, `TestParseRemotePolicy_DanglingSentinel`,
`TestOldWorkerDeniesScoped`.

**Capability `grouppolicy/v1`.** A current worker advertises `grouppolicy/v1` in its
heartbeat (`TestHeartbeat_AdvertisesGroupPolicy`). While the served policy has at
least one scoped rule (a scoped allow entry or a scoped MCP tool):

- the fleet view shows a **no groupPolicy** badge on every worker whose caps lack it,
  a worker that sends no caps included (`noGroupPolicy` in the dashboard worker
  view; `TestHeartbeat_FlagsWorkersWithoutGroupPolicy`, `TestFleetNoGroupPolicyBadge`);
- the control plane logs one WARN, `worker_lacks_grouppolicy`, per worker per policy
  ETag, with `proxy_id` and `scoped_entries` (a count, never group names;
  `TestWorkerLacksGroupPolicyLogOnce`).

Nothing is flagged while no scoped rule is served.

### Worker without identity

If scoped allow entries exist but identity is off for an agent, no request has a
subject, so every scoped destination is denied. The worker logs one WARN naming the
agent and the count of scoped entries, and repeats it only when that count changes
(`TestScopedEntriesIdentityOffWarns`).

## Previewing a change: `warden policy eval`

```sh
warden policy eval --candidate new.yaml --since 7d --db warden.db [--user alice@corp.example]
```

Recorded events are replayed against the candidate policy, each **with the user
recorded on it** (sub, email and the groups the token carried), so scoped entries are
evaluated for real.

- Each regression line (`Security Regressions`, `Availability Regressions`) is
  followed by `Affected users:`: the distinct users behind it, shown as email else
  `sub`, sorted, at most 20 with `(+N more)` after that. Never a token or a group
  list.
- Events with no valid recorded identity replay as anonymous and are counted on one
  line, `Anonymous events: N`, so pre-identity traffic is not read as user impact.
- `--user` limits the replay to one user, matched on `sub` or email
  (case-insensitive).
- Limits of replay: the recorded groups are a snapshot of what the token carried
  then, not the user's current membership; a recorded email replays as verified
  (the event does not record `email_verified`); rate limits and time windows are
  stripped, as before.

Tests: `TestEvaluate_AffectedUsers`, `TestEvaluate_AnonymousCount`,
`TestEvaluate_AffectedUsersCap` (internal/policyeval).

### Lint warnings

`policy eval` also prints `warning: ...` lines before the report for every scoped
allow entry that an unscoped entry already shadows: the unscoped entry admits
everyone for the same destination, so the scope never restricts anything. An
unscoped entry with a `timeWindow` or `rateLimit` is not treated as shadowing, and
when coverage cannot be proven (a regex against a wildcard) there is no warning.
Warnings carry entry indexes and domain patterns only, never a group or user. They
never fail the command. `config.LintScoped` covers allow entries, not MCP
conditions (`TestLintScoped`, `TestEvalCmd_LintWarnings`).

## Metrics

`warden_policy_scoped_total{result}` (OTel `warden.policy.scoped.total`) counts the
per-request decisions on destinations that have scoped entries:

| `result` | Meaning |
|---|---|
| `allow` | allowed (an upper bound: an unscoped sibling entry may have admitted it) |
| `not_member` | `group_not_allowed` or `identity_groups_truncated` |
| `no_identity` | `identity_required` |

There is no user, group, token or email label (`TestRecordScoped`,
`TestGroupPolicy_ScopedMetricsNoLeak`). It counts HTTP requests, not CONNECTs. The
three deny reasons also feed `warden_blocked_total{reason}`.

## Dashboard

What exists today: the fleet view's **no groupPolicy** badge (above). Editing
`groups`/`users` in the dashboard policy editor, with chip inputs and the shown lint
warnings, lands with W-P1-GPOL-08 (#597); until then set them in the YAML policy the
control plane serves; the policy editor does not show them.

## Limits and what is next

- Groups and users are matched as the issuer presents them. When more than one issuer
  is supported (P5, enterprise IdP adapters), groups will be namespaced as
  `<issuer>:<group>` so equal group names from different IdPs cannot be confused;
  today there is one issuer and plain names.
- Membership is the token's: a change in the IdP shows up when the user's next token
  is issued, and an open scoped raw tunnel lives until its token expires.
- A token with more than 64 groups is truncated (see above); give such users a
  `users` entry or a narrower group claim.
