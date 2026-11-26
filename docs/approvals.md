# Change approvals (`console.approvals`)

Change approvals hold every change that would widen what agents can reach, or where
credentials are sent, as a **draft** until a second person approves it. The reviewer
sees a structural diff, the reasons the change counts as widening, and (for policy
changes) a replay of recent fleet traffic under the base and the draft. A change that
only narrows access still applies at once.

It is off by default. With it off there is no table, migration or goroutine, and every
endpoint and the `/policy` bytes are the same as without the feature. The API tables
for the draft routes are in [control-plane.md](control-plane.md#change-drafts-and-the-two-person-rule-consoleapprovals);
this page is the operator guide.

Contents: [Enable it](#enable-it) · [What is held](#which-writes-are-held-and-which-are-direct) ·
[The two-person rule](#the-two-person-rule) · [Draft lifecycle](#the-draft-lifecycle-and-the-202-contract) ·
[Replay](#replay) · [Non-policy drafts](#non-policy-drafts-block-list-and-agents) ·
[Emergency apply](#emergency-apply-and-post-hoc-review) · [Offline CLI](#the-offline-cli) ·
[Storage](#the-fleet-database-and-the-state-dir) · [Known limits](#known-limits)

## Enable it

Prerequisites. Startup names the first one that is missing and refuses to start:

- `console.auth: oidc` (people sign in; a second person needs an identity).
- `--policy-store=versioned` and `--state-dir` (drafts apply as policy versions).
- `console.adminAudit.enabled: true` (every transition is a signed audit row).

```yaml
console:
  auth: oidc
  adminAudit:
    enabled: true
  approvals:
    enabled: true
```

Read from the control plane's own `--config` only: it is never sent to workers, so a
settings save cannot turn the gate off. Changing any value needs a control-plane
restart. Out-of-range values are startup errors even while the block is disabled.

| Key | Default | Meaning |
|---|---|---|
| `console.approvals.enabled` | `false` | Turns the gate on. |
| `console.approvals.minApprovals` | `1` | Distinct approvers a held change needs, `1..3`. |
| `console.approvals.allowSelfApproveNarrowing` | `true` | A narrowing change applies at submit with no second person. Set `false` to hold every change. |
| `console.approvals.allowEmergencyApply` | `false` | Allows the audited break-glass apply (see below). |
| `console.approvals.replayWindow` | `168h` | How far back a replay reads fleet events, `1h..720h`. |
| `console.approvals.replayMaxEvents` | `100000` | Most events one replay evaluates, `1..100000`. |
| `console.approvals.replayTimeout` | `60s` | Bounds one replay run; greater than `0`, at most `1h`. |
| `console.approvals.replayMaxAge` | `24h` | How old a done replay may be and still back an approval; greater than `0`, at most `720h`. |
| `console.approvals.draftTTL` | `168h` | An open draft expires after this; greater than `0`, at most `8760h`. |
| `console.approvals.maxOpenDrafts` | `200` | Cap on drafts in `draft`, `pending` or `needs_rebase`, `1..100000`. Past it, creating a draft is `429 too_many_drafts`. |

If approvals are enabled but the service cannot start, every gated write is refused
with `503 approvals_unavailable` (the gate fails closed).

## Which writes are held and which are direct

One clearance check guards every write that creates a policy version. A write that
widens (or, with `allowSelfApproveNarrowing: false`, any change) is stored as a pending
draft; head and the `/policy` ETag do not move.

| Write | Held when | Direct (applies at once) |
|---|---|---|
| Policy save: `POST`/`PUT /dashboard/api/policy` | An allow entry is added or loosened (scope, rate limit, time window, methods or paths); an allow entry removed so its explicit deny falls to the judge; a deny entry removed or changed | Narrowing edits: a deny added, an allow tightened or removed |
| Settings save: `POST`/`PUT /dashboard/api/settings` | Any field outside the small neutral or narrowing set. Admin approver needed for admin-only fields | `logging.*`, `cacheTTLSeconds`, and switching `dlp`, `compliance` or `advisory` on |
| `llmProviders` save: `POST`/`PUT /dashboard/api/llmproviders` | Always, and it needs an admin approver | Never |
| Rollback: `POST /dashboard/api/policy/versions/{v}/rollback` | The target version widens relative to head | A rollback that only narrows |
| `warden policy import` | Always (any file that differs from head), authored `cli:<os user>` | Never (a file equal to head is a no-op) |
| Block-list removal: `DELETE /dashboard/api/blocked-users/{id}`, `warden control-plane block remove` | Always (target `blocked_users`) | Adding a block (the incident kill switch) |
| Agent registry: register, add a key, add a group or scope, re-enable (`/dashboard/api/agents`) | Anything that widens the agent (target `agents`) | Disabling an agent; edits that only narrow |
| Integrations, detection, secret store and `/central/secrets`, worker tokens, signing keys, sessions, token sessions, worker cert revoke, enrollment tokens, API keys (`/dashboard/api/api-keys`), backups | Never held | Always direct |

The direct stores are not versioned policy. Note that creating an API key grants
admin-API access with no second person; see the not-gated list in
[control-plane.md](control-plane.md#which-writes-are-gated).

A held change keeps the `If-Match` rules: a stale `If-Match` is `409 policy_conflict`
and a missing one `428`, as before. Field-level role checks run at save time, so an
editor who saves an admin-only settings field is refused at once, not held.

Credential rotation. A settings save that carries a new raw secret (for example a cloud
`secretAccessKey`) is refused outright rather than held, because a draft holds only a
fingerprint, never the secret. Change the credential in the served config first.

A rollback keeps the credential the control plane serves now; it never brings back an
older one. The one exception: a rollback to a version with no secret store block, while
a credential is set, is refused. At apply time a pending draft whose credential
fingerprint differs from head's is refused with `422` and stays pending.

## The two-person rule

- **Author is not approver.** The approver's subject must differ from the author's
  (`403 self_approval_forbidden`). An API key acts as its owner, so a draft made with
  u1's key cannot be approved by u1's session.
- **The draft's required role.** An approver needs the role the draft needs now:
  `editor` for most policy changes, `admin` for settings fields that need it,
  `llmProviders`, the block list and agents. Otherwise `403 role_required`, naming the
  settings fields. Rejecting needs only `editor`, because it can only stop a change.
- **Break-glass cannot approve.** A break-glass session never approves
  (`403 breakglass_cannot_approve`). Its only route is the [emergency apply](#emergency-apply-and-post-hoc-review).
- **API keys cannot approve or reject** (`403 insufficient_scope`): the second person
  is always a signed-in human.
- **More than one.** With `minApprovals > 1` the approvers must be distinct people.
- Editing a draft makes a new revision and voids earlier approvals.

## The draft lifecycle and the 202 contract

States: `draft` (editable by its author), `pending` (submitted), `needs_rebase`
(head moved), `applied`, `applied_unreviewed` (emergency apply awaiting review),
`rejected`, `withdrawn`, `expired`. `applying` is the short in-flight state during the
publish.

A held save is answered `202` with a `Location` header naming the draft:

```json
{"draft_id": "<id>", "revision": 1, "state": "pending", "widening": true,
 "reasons": [{"code": "allow.added", "path": "allowlist"}]}
```

Nothing is published and workers see no change. The held save is one admin audit row
(the route's own action: `policy.write`, `settings.write`, `llmproviders.write` or
`policy.rollback`; `policy.import` on target `change_draft` for the CLI import; each
with `op=held` and target ref `draft:<id>@r1`); a draft made through
`POST /dashboard/api/changes` writes `change.draft.create` and `change.draft.submit`
rows instead. Submitting a widening draft raises an info Finding,
`policy_approval_requested`.

The approval that completes the set publishes in the same request: `200` with
`{state: applied, version}`, and workers get the new ETag within one long-poll cycle.
A moved head answers `409 rebase_required` (the draft becomes `needs_rebase`); a doc the
loader refuses is `422` and the draft stays pending. An expired draft cannot be
approved even before the sweeper retires it (`409 illegal_transition`, reason
`expired`). The audit shows `change.draft.approve` then a `policy.write` row (source
`approval`) with the hashes before and after.

## Replay

For a policy draft, the control plane queues a replay when it is submitted. The replay
reads recent fleet events (`replayWindow`, up to `replayMaxEvents`), evaluates each one
under the **base** version and under the **draft** with the same stateless evaluator,
and reports the destinations where the answer differs: `changed_to_allow` and
`changed_to_deny` groups keyed by domain, port and method, with a count, the affected
users (email, else subject) and no URL, path, query or header. Recorded judge, DLP,
block-list and rate-limit outcomes do not show up as noise, because both sides are
evaluated the same way. One replay runs at a time per control plane, and a draft can be
re-run once a minute.

What a replay does not model (stored on every result): rate limits and time windows
(events that match such an entry are counted as `limit_governed`); the judge (an event
that matches neither list is counted as judge, not as a plain deny); path and method
constraints, since replay events carry no URL; and identity-scoped entries, which use
the identity recorded on the event (an event with no valid identity is replayed as
anonymous). Read those reasons from the classification, not the replay. A window with
no events gives status `unavailable`.

Approve needs evidence. The request carries `revision`, `doc_sha256` and either:

- `replay_id`: a **done** replay of this revision no older than `replayMaxAge`; or
- `acknowledgeNoReplay: true`, accepted only when the latest replay of this revision
  `failed` or was `unavailable` (timeout, restart, an empty window, a failed queue).

Otherwise the answer is `409 replay_required`. A revision with no replay row at all
(for example one the offline CLI created) needs the sweep, which queues missing replays
within a minute, or `POST /dashboard/api/changes/{id}/replay`. A replay that outlives
`replayTimeout` is recorded `failed` with `error_code: timeout`; a replay interrupted
by a restart is failed as `interrupted`. Raise `replayTimeout` (up to `1h`) or lower
`replayWindow` or `replayMaxEvents` if timeouts are common. Approving with a changed
revision or digest is `409 revision_changed`.

Replay is run only for the `policy` target. For every other target see below.

## Non-policy drafts: block list and agents

Removing a block-list entry and widening an agent are held as drafts of their own
target (`blocked_users`, `agents`). They publish no policy version, so their approve
results carry no `version`.

- **Reason codes.** `blocklist.removed` (that user is unblocked); `agent.created`,
  `agent.enabled`, `agent.key_added` (a key the agent did not have, added or replaced),
  `agent.group_added` and `agent.scope_added`. Policy drafts use `allow.added`,
  `allow.scope_widened`, `allow.rate_relaxed`, `allow.time_relaxed`,
  `allow.constraint_widened`, `allow.removed_to_judge`, `deny.removed` and
  `settings.changed`.
- **The diff** of a non-policy draft is `{current, proposed}`: the entity as it is now
  and as the draft would leave it. `current` is `null` for something new.
- **No replay.** Nothing is queued for these targets, so the approve request must carry
  `acknowledgeNoReplay: true`. Sending a `replay_id` is not meaningful.
- **Withdraw and redo, not rebase.** A non-policy draft cannot be rebased. If the entity
  changed after the draft was made, withdraw the draft and make a new one from the
  current state.
- **A blocked person cannot approve their own unblock** (`403 self_unblock_forbidden`).
- **Redaction.** The block list is admin-only. A non-admin (a viewer, or an API key whose
  owner is not an admin) reading a block draft sees only `{id, has_sub, has_email}`,
  never who would be unblocked. An admin sees the entry.

## Emergency apply and post-hoc review

When the IdP is down and nobody can approve, `console.approvals.allowEmergencyApply:
true` lets **only a break-glass session** publish a pending draft with a stated reason. A
`needs_rebase` draft always gets `409 rebase_required`, so in practice only a pending or
freshly rebased draft can be emergency-applied:

```sh
# bg-cookies.txt is the cookie jar from the break-glass sign-in (see
# runbooks/break-glass.md), so the session cookie never lands in argv. The CSRF
# token is the one that sign-in returned.
curl --cacert ca.pem -X POST -b bg-cookies.txt \
  -H "X-Warden-CSRF: $CSRF_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"reason": "Identity provider is down and the payments vendor is blocked"}' \
  https://cp.example.internal:7070/dashboard/api/changes/DRAFT_ID/emergency-apply
```

- The reason is 10 to 512 characters. The expected head is still checked: a moved head is
  `409 rebase_required` and the draft needs a rebase first.
- At most 5 per 10 minutes; the counter resets when the control plane restarts.
- The audit row `change.draft.emergency_begin` is written before anything publishes (if
  it cannot be written nothing publishes). The decision row holds the reason.
- Every success raises one **critical** `approval_bypassed` Finding and one ERROR log
  line, and the draft becomes `applied_unreviewed`. Route that Finding to a channel
  somebody watches: startup WARNs if `allowEmergencyApply` is on but break-glass is off
  or no integration routes it. See [runbooks/break-glass.md](runbooks/break-glass.md).
- At every start the control plane raises the Finding again for each draft still
  `applied_unreviewed`.

**Post-hoc review.** `POST /dashboard/api/changes/{id}/review {"comment": "..."}` (at
least 10 characters) closes the draft as `applied`. It needs an OIDC admin who is not a
break-glass session, who is not the draft's author (`403 self_review_forbidden`) and who
has not already decided that revision. In a single-admin deployment the author's own
bypass therefore stays `applied_unreviewed`: the alert has gone out and the review is
meant to be independent. If the version published but the draft could not be updated,
the request fails `500 emergency_apply_unrecorded`, still alerts, and policy history
names the break-glass actor as the author (author kind `breakglass`).

## The offline CLI

Both commands open the state dir directly. They run as a host user, not as a signed-in
person, so what they can prove is limited.

- **`warden control-plane block remove`** is held. With approvals enabled on the state
  dir it creates a pending `blocked_users` draft (author `cli:<os user>`), prints its
  id, removes nothing and leaves the user blocked until a second admin approves it in
  the console. It exits `2` for an id not on the list. `block add` is always immediate.
- **`warden policy import`** creates a pending policy draft in the same way.
- **The offline `warden control-plane agent register|update|enable` commands are NOT
  held.** Each is a single-admin action on host access: anyone who can run the binary
  against the state dir can register an agent, add a key or re-enable an agent without a
  second person. Treat that as a **known limit**: guard host access to the state dir.
  The same is true of `restore`, which can move the policy head back.

A draft the CLI creates is authored `cli:<os user>` with no issuer, so the same human
can import offline and then approve through OIDC. Host access to the state database is
already full trust over the control plane; this is a limit of what the CLI can prove.
The control plane queues the replay of a CLI-created draft on its next sweep (within a
minute), and raises no `policy_approval_requested` Finding for a CLI-created block
draft (the CLI has no alert publisher).

## The fleet database and the state dir

Replays read the fleet analytics database, and drafts, replays and approvals live in
the control plane's state database. These are SQLite files in WAL mode, which need
shared memory and working file locks. **Keep the state dir and the fleet database on a
local disk, never on a network filesystem (NFS, SMB, and most shared volumes).** On
one the WAL can be corrupted or give wrong replay reads. The same applies to the lock
file; see the production-readiness checklist.

## The Changes tab

The console shows a **Changes** page only when approvals are enabled (the setup
response says `approvalsEnabled`). The server stays the only enforcement point: buttons
a role cannot use are hidden, but every refusal is shown with the code the server gave.

- **List and filters.** Drafts are listed by state (default `pending`; also `draft`,
  `needs rebase`, `applied, unreviewed`, `applied`, `rejected`, `withdrawn`, `expired`
  or all) and by target (all, policy, blocked users, agents). Rows key on the draft's
  target.
- **Diff by target.** A policy draft shows the structural diff (allow, deny, settings)
  and the reasons it is held. Block-list and agent drafts show the `{current, proposed}`
  diff field by field. Credentials show only as fingerprints and an agent's key
  material is never rendered. Everything from the server or a person is inserted as
  text, never as markup.
- **Replay status.** A pending replay is polled every 2 seconds, up to the replay
  timeout. A done replay shows the changed destinations; a failed or unavailable one,
  or a target with no replay, says so.
- **Approve.** Sends the revision, the digest and the done replay the reviewer saw.
  With no usable replay the **acknowledge** box must be ticked and
  `acknowledgeNoReplay` is sent. The author never sees Approve, and a break-glass
  session never does.
- **Other actions.** Reject (editor), Withdraw, and Rebase onto the head for a policy
  draft that needs it (non-policy drafts are withdrawn and redone). **Emergency apply**
  appears only for a break-glass session with admin rights, and **Mark reviewed**
  closes an `applied_unreviewed` draft for an admin who is not break-glass.
- **Deep link.** `#changes/<id>` opens a draft directly.
- **Held saves.** When a policy, settings or provider save is held, the console shows a
  notice with an "Open draft" link to `#changes/<id>`.

## Known limits

- **The draft list has no replay column.** `GET /dashboard/api/changes` does not show
  each draft's replay status; open the draft to see its replay. A `latest_replay_status`
  field on the list is a follow-up.
- **Replay covers allow and deny only.** Rate limits, time windows, the judge,
  path and method constraints and settings are judged from the classification reasons.
- **Replay only for the `policy` target.** Block-list and agent drafts have no replay
  and need `acknowledgeNoReplay`.
- **Non-policy drafts cannot be rebased.** Withdraw and redo.
- **The offline `agent` CLI is not held**, and `restore` is not held (host access).
- **The first-start import** of the served YAML as version 1 is not gated; it runs only
  on an empty store.
- **No metrics endpoint.** Findings, ERROR logs and the admin audit are the signals.
- **Replays and drafts are not pruned.** Old replay rows of closed drafts are kept; only
  `maxOpenDrafts` caps open drafts.
- **Emergency apply limits** reset on restart, as for break-glass.
- **A held draft expires** after `draftTTL`; re-create it if it lapses.

## End-to-end proof

`go test -race ./internal/controlplane -run TestApprovalsEndToEnd` runs the whole
flow in process with two editors, admins, a break-glass session and a long-polling
worker: an editor's widening change is held, the worker's ETag does not change for one
full wait, the author's own approval is refused, a second editor approves with a done
replay and the worker gets one new ETag, the break-glass emergency apply and its review,
a narrowing change that applies at once, a held `llmProviders` change that needs an
admin, and a clean `warden control-plane admin-audit verify --state-dir <dir>` over the
signed rows.
